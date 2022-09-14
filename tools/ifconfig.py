import argparse
import collections
import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
import timeit
import traceback
import xml.etree.ElementTree

from abc import abstractmethod, ABCMeta
from command import Command
from constants import LINK_SPEED_AUTO, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, \
    LINK_SPEED_NO_LINK, LINK_SPEED_10M
from constants import ATF_TOOLS_DIR, LINK_STATE_UP, LINK_STATE_DOWN, KNOWN_LINK_SPEEDS, INTERRUPT_TYPE_LEGACY, INTERRUPT_TYPE_MSI
from constants import VENDOR_AQUANTIA, OFFLOADS_STATE_DSBL, OFFLOADS_STATE_ENBL, OFFLOADS_STATE_TX, OFFLOADS_STATE_RX, OFFLOADS_STATE_TX_RX
from constants import MII_MODE_AUTO, MII_MODE_USX, MII_MODE_XFI, MII_MODE_XFI_DIV2, MII_MODE_OCSGMII, MII_MODE_SGMII
from constants import MII_MODE_USX_DIV2, MII_MODE_XFI_DIV2_OCSGMII_SGMII, MII_MODE_XFI_SGMII, MII_MODE_XFI_XSGMII, MII_MODE_2500BASE_X
from constants import OFFLOADS_STATE_OFF, OFFLOADS_STATE_ON
from constants import MTU_1500, MTU_2000, MTU_4000, MTU_9000, MTU_16000, MTU_MAP_WIN, MTU_MAP_LIN, MTUS

from debug import collect_debug_info
from drv_iface_cfg import FWStatistics, SettingsMemory, FWSettings
from ops import OpSystem
from utils import get_bus_dev_func, get_domain_bus_dev_func, remove_file, get_atf_logger

if sys.platform == "win32":
    import wmi
    from utils import get_wmi_pnp_devices, get_wmi_network_adapter, get_wmi_device_pnp_driver
elif "linux" in sys.platform:
    import yaml

AQUANTIA_SERVICE_NAMES_USB = ["AQC101", "aqnicusb"]
AQUANTIA_SERVICE_NAMES = ["AquantiaNDMP", "aqnic", "aqnic650", "aqnic640", "aqnic630", "aqnic620"] + \
                         AQUANTIA_SERVICE_NAMES_USB

STAT_NOT_SUPPORTED = "not supported"

SCRIPT_STATUS_SUCCESS = "[IF-CONFIG-SUCCESS]"
SCRIPT_STATUS_FAILED = "[IF-CONFIG-FAILED]"

log = get_atf_logger()
ops = OpSystem()


def get_linux_device_driver_name(port):
    bus, dev, func = get_bus_dev_func(port)
    port_str = "{bus:02d}:{dev}.{func}".format(
        bus=int(bus), dev=dev, func=func)
    log.info("Linux port for Aquantia: {}".format(port_str))

    try:
        cmd = "sudo lspci -v | grep '{}' -A 15".format(port_str)
        output = subprocess.check_output(cmd, shell=True,
                                         stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        log.error(e.output)
        raise e

    re_name = re.compile("Kernel driver in use: ([0-9a-zA-Z]+)")
    m = re_name.search(output)
    if m:
        return m.group(1)

    return "Not installed"


def get_conn_name(port):
    if ops.is_linux():
        return get_linux_network_adapter_name(port)
    elif ops.is_windows():
        return get_win_network_adapter_name(port)
    elif ops.is_freebsd():
        return get_freebsd_network_adapter_name(port)
    else:
        return get_macos_network_adapter_name(port)


def get_wmi_device_id(port):
    bus, _, __ = get_bus_dev_func(port)

    id = None
    if port.startswith("pci"):
        for device_bus in wmi.WMI().Win32_DeviceBus():
            if device_bus.Antecedent.DeviceID == "PCI_BUS_{}".format(bus):
                id = device_bus.Dependent.DeviceID
                break
    elif port.startswith("usb"):
        id = get_wmi_device_pnp_driver(port).DeviceID

    return id


def get_wmi_device_driver_name(port):
    bus, _, __ = get_bus_dev_func(port)

    if port.startswith("pci"):
        for device_bus in wmi.WMI().Win32_DeviceBus():
            if device_bus.Antecedent.DeviceID == "PCI_BUS_%s" % bus:
                name = device_bus.Dependent.Caption
                break
    elif port.startswith("usb"):
        name = get_wmi_device_pnp_driver(port).DeviceName

    return name


def get_wmi_device_driver_version(port):
    id = get_wmi_device_id(port)

    version = None
    for device in wmi.WMI().Win32_PnPSignedDriver():
        if device.DeviceID == id:
            version = device.DriverVersion
            break
    return version


def get_win_network_adapter_name(port):
    _id = get_wmi_device_id(port)
    name = None
    for device in wmi.WMI(namespace='StandardCimv2').MSFT_NetAdapter():
        if device.PnPDeviceID.lower() == _id.lower():
            name = device.Name
            break

    assert name is not None
    return name


def get_linux_network_adapter_name(port):
    domain, bus, dev, func = get_domain_bus_dev_func(port)
    bus_address = '{:04x}:{:02x}:{:02x}.{:01x}'.format(domain, bus, dev, func)

    if 'usb' not in port:
        cmd = "sudo lshw -c network -businfo | grep {} | awk '{{print $2}}'".format(bus_address)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            raise Exception("Interface for port {} was not found".format(port))
        out = res['output']
        name = None
        for n in out:
            name = n.strip()
            if not 'Resource temporarily unavailable' in name:
                break
        if name is None:
            raise Exception("Interface for port {} was not found".format(port))
    else:
        name = "enp{}s{}".format(bus, dev) if ops.is_centos() or ops.is_rhel() else "enx"
        res = Command(cmd="sudo ip a | grep {}".format(name)).run()

        if len(res["output"]) == 0:
            raise Exception("No interfaces found for USB")

        iface_str = res["output"][0]
        return iface_str.split(':')[1].strip()

    for i in range(10):
        log.info('try to run ip a #{}'.format(i))
        res = Command(cmd="sudo ip a | grep {}".format(name)).run()
        if any([name in line for line in res["output"]]):
            return name
        time.sleep(0.5)

    log.info("Tracing debug info before fail")
    Command(cmd="sudo lshw -c network -businfo").run()
    Command(cmd="sudo lspci -vvv").run()
    Command(cmd="dmesg").run()
    Command(cmd="ip a").run()
    raise Exception("Interface {} was not found".format(name))


def get_freebsd_network_adapter_name(port):
    domain, bus, dev, func = get_domain_bus_dev_func(port)
    bus_address = 'pci{}:{}:{}:{}:'.format(domain, bus, dev, func)

    if 'usb' not in port:
        cmd = "pciconf -l | grep {} | awk -F '@' '{{print $1}}' ".format(bus_address)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            raise Exception("Interface for port {} was not found".format(port))
        out = res['output']
        name = None
        for n in out:
            name = n.strip()
            if not 'Resource temporarily unavailable' in name:
                break
        if name is None:
            raise Exception("Interface for port {} was not found".format(port))
        return name
    else:
        raise NotImplementedError("The functionality is not implemented for usb")


def get_macos_network_adapter_name(port):
    cmd = Command(cmd="system_profiler SPEthernetDataType -xml > tmp.xml")
    cmd.run()
    res = cmd.join(1)
    if res["returncode"] != 0:
        raise Exception("Failed to run system_profiler")

    bus, _, __ = get_bus_dev_func(port)

    if "usb" not in port:
        cmd = "ioreg -c IOPCIDevice -x | grep -B30 -A5 {}:0:0 | " \
              "grep vendor-id".format(bus)
    else:
        # Additional sleep for imac setups
        time.sleep(5)
        cmd = "ioreg -c IOUSBDevice -x | grep -A5 -i {}".format(VENDOR_AQUANTIA)
    res = Command(cmd=cmd).run_join(30)
    if res["returncode"] != 0:
        raise Exception("Failed to obtain vendor id via ioreg")

    vendor_id = None
    re_vendor = re.compile(".*\"vendor-id\" = \<([0-9a-fA-F]+)\>", re.DOTALL)
    re_vendor_usb = re.compile(".*\"idVendor\" = (0x[0-9a-f]{4}).*", re.DOTALL)

    if "usb" not in port:
        for line in res["output"]:
            m = re_vendor.match(line)
            if m is not None:
                str_vend = "0x{}".format(m.group(1))
                int_vend = int(str_vend, 16) >> 16
                vendor_id = (int_vend & 0xff) << 8 | int_vend >> 8
                break
    else:
        for line in res["output"]:
            m = re_vendor_usb.match(line)
            if m is not None:
                vendor_id = int(m.group(1), 16)
                break

    if vendor_id is None:
        raise Exception("Failed to obtain vendor id")

    xmlroot = xml.etree.ElementTree.parse("tmp.xml")
    remove_file("tmp.xml")
    eth_entries = xmlroot.findall(".//array/dict/array/dict")
    for eth_entry in eth_entries:
        eth_info = {}
        for i in range(0, len(eth_entry), 2):
            k = eth_entry[i].text
            v = eth_entry[i + 1].text
            eth_info[k] = v

        if "usb" not in port:
            slot = eth_info.get("spethernet_slot_name", None)
            if slot is not None and slot == "Slot-{}".format(bus):
                return eth_info["spethernet_BSD_Name"]
            else:
                ven_id = eth_info.get("spethernet_vendor-id", None)
                if ven_id is not None:
                    if int(ven_id, 16) == vendor_id:
                        return eth_info["spethernet_BSD_Name"]
        else:
            vid = eth_info.get("spusbethernet_VID", None)
            if vid is not None and vid == str(vendor_id):
                return eth_info["spethernet_BSD_Name"]

    raise Exception("Interface is not initialized or driver is not loaded")


def get_expected_speed(speed, pci_port):
    if speed == LINK_SPEED_AUTO:
        supported_speeds = os.environ.get("SUPPORTED_SPEEDS", "").split(',')
        if len(supported_speeds) > 0:
            return supported_speeds[-1]
        else:
            lines = get_nof_pci_lines(pci_port)
            if lines == 4:
                return LINK_SPEED_10G
            elif lines == 1:
                return LINK_SPEED_5G
            else:
                raise Exception("Wrong number of PCI lines = {}".format(lines))
    else:
        return speed


def get_nof_pci_lines(port):
    bus, dev, func = get_bus_dev_func(port)
    slot = "{}:{}.{}".format(hex(int(bus)), dev, func)
    if sys.platform == "darwin":
        cmd = "ioreg -c IOPCIDevice -x | grep -B30 -A5 {}:0:0 | " \
              "grep IOPCIExpressLinkStatus".format(bus)
        re_status = re.compile(
            ".*\"IOPCIExpressLinkStatus\" = ([0-9a-fxA-F]+)", re.DOTALL)
        try:
            output = subprocess.check_output(
                cmd, stderr=subprocess.STDOUT, shell=True)
            m = re_status.match(output)
            if m is not None:
                status_val = int(m.group(1), 16)
                width = (status_val & 0x3f0) >> 4
                if width == 0x1:
                    return 1
                if width == 0x2:
                    return 2
                elif width == 0x4:
                    return 4
                raise Exception("Invalid link width 0x{:02x}".format(width))
            else:
                raise Exception("Failed to get number of PCI lines")
        except subprocess.CalledProcessError as e:
            log.exception(e.output)
            raise e
    else:
        # TODO: temporary before we compile lsusb for all platforms
        if port.startswith("usb"):
            return 1
        if sys.platform == 'win32':
            cmd = "lspci -s {} -vv | grep LnkSta".format(slot)
        else:
            cmd = "sudo lspci -s {} -vv | grep LnkSta".format(slot)

        res = Command(cmd=cmd).wait(10)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to run lspci")
        for line in res["output"]:
            if "Width x1" in line:
                return 1
            if "Width x2" in line:
                return 2
            if "Width x4" in line:
                return 4
        raise Exception("Failed to get number of PCI lines")


def get_mgmt_iface():
    mgmt_name, mgmt_mac, mgmt_ip, mgmt_gw = None, None, None, None

    if sys.platform == "win32":
        for c in wmi.WMI().Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if c.GatewayCostMetric is not None and len(c.GatewayCostMetric) >= 1 and c.GatewayCostMetric[0] == 0:
                mgmt_name = c.Description
                mgmt_mac = c.MACAddress
                mgmt_ip = c.IPAddress[0]
                mgmt_gw = c.DefaultIPGateway[0]
                break
    elif sys.platform == "darwin" or "freebsd" in sys.platform:
        cmd = "route -n get default | sort | awk '/gateway:/ || /interface:/ {print $2}'"
        res = Command(cmd=cmd, silent=True).run_join(3)
        mgmt_name = res["output"][1]
        mgmt_gw = res["output"][0]

        cmd = "ifconfig {} | sort | awk '/ether/ || /inet / {{print $2}}'".format(mgmt_name)
        res = Command(cmd=cmd, silent=True).run_join(3)
        mgmt_mac = res["output"][0]
        mgmt_ip = res["output"][1]
    else:
        cmd = "route -n | awk '/^0.0.0.0/ {printf \"%s\\n%s\\n\",$8,$2}'"
        res = Command(cmd=cmd, silent=True).run_join(3)
        mgmt_name = res["output"][0]
        mgmt_gw = res["output"][1]

        cmd = "ip address show {} | sort | awk '/inet / || /link\\/ether/ {{print $2}}'".format(mgmt_name)
        res = Command(cmd=cmd, silent=True).run_join(3)
        mgmt_mac = res["output"][1]
        mgmt_ip = res["output"][0].split("/")[0]

    return mgmt_name, mgmt_mac, mgmt_ip, mgmt_gw


def get_mgmt_mac():
    return get_mgmt_iface()[1]


def get_mgmt_gw():
    return get_mgmt_iface()[3]


class Ifconfig(object):
    __metaclass__ = ABCMeta

    RE_MAC = re.compile(".*\s([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]"
                        "([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]"
                        "([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})")
    LINK_UP_TIMEOUT = 25

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            if "phy_control" not in kwargs:
                return object.__new__(IfconfigLocal)
            else:
                return object.__new__(IfconfigLocalWithSeparatePhy)
        else:
            return object.__new__(IfconfigRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]
        self.__iface = None

    @property
    def iface(self):
        if self.__iface is None:
            self.__iface = self.get_conn_name()
        return self.__iface

    @abstractmethod
    def get_link_speed(self, vlan_id=None):
        pass

    @abstractmethod
    def set_link_speed(self, speed, half_duplex=False):
        pass

    @abstractmethod
    def set_link_state(self, state, vlan_id=None):
        pass

    @abstractmethod
    def set_ip_address(self, address, netmask, gateway, vlan_id=None):
        pass

    @abstractmethod
    def set_ipv6_address(self, address, prefix, gateway):
        pass

    @abstractmethod
    def get_mac_address(self, macvlan=None):
        pass

    @abstractmethod
    def get_management_mac_address(self):
        pass

    @abstractmethod
    def get_management_gateway(self):
        pass

    @abstractmethod
    def get_counters(self):
        pass

    @abstractmethod
    def get_nof_pci_lines(self):
        pass

    @abstractmethod
    def set_arp(self, ip, mac):
        pass

    @abstractmethod
    def del_arp(self, ip):
        pass

    @abstractmethod
    def get_guid_by_mac(self, mac_address, once=True):
        pass

    @abstractmethod
    def get_wmi_device_id(self):
        pass

    @abstractmethod
    def get_wmi_device_driver_name(self):
        pass

    @abstractmethod
    def get_wmi_device_driver_version(self):
        pass

    @abstractmethod
    def get_mtu(self):
        pass

    @abstractmethod
    def set_mtu(self, mtu):
        pass

    @abstractmethod
    def get_media_options(self, options_to_check=["flow-control", "full-duplex", "energy-efficient-ethernet"]):
        pass

    @abstractmethod
    def set_media_options(self, options_to_set=["flow-control", "full-duplex", "energy-efficient-ethernet"]):
        pass

    @abstractmethod
    def set_flow_control(self, value):
        pass

    @abstractmethod
    def get_flow_control(self):
        pass

    @abstractmethod
    def check_media_options(port, options):
        pass

    @abstractmethod
    def check_duplex(self):
        pass

    @abstractmethod
    def get_advanced_property(self, name):
        pass

    @abstractmethod
    def set_advanced_property(self, name, value):
        pass

    @abstractmethod
    def set_wol_settings(self, on_magic=False, on_pattern=False, on_ping=False, on_link=False, from_power_off=False):
        pass

    @abstractmethod
    def set_interrupt_type(self, int_type, number=1):
        pass

    @abstractmethod
    def set_power_mgmt_settings(self, only_magic_wake=False, allow_wake=False, allow_power_save=False):
        pass

    @abstractmethod
    def bind_ipv6(self):
        pass

    @abstractmethod
    def unbind_ipv6(self):
        pass

    @abstractmethod
    def get_conn_name(self):
        pass

    @abstractmethod
    def manage_offloads(self, offload, state):
        pass

    @abstractmethod
    def is_device_present(self):
        pass

    @abstractmethod
    def create_vlan_iface(self, vlan_id):
        pass

    @abstractmethod
    def delete_vlan_ifaces(self):
        pass

    @abstractmethod
    def delete_macvlan_ifaces(self):
        pass

    @abstractmethod
    def add_route(self, addr, mask_prefix, gw):
        pass

    @abstractmethod
    def del_ip_address(self, addr):
        pass

    @abstractmethod
    def get_ip_address(self, ipv=4):
        pass

    @abstractmethod
    def set_promisc_mode(self, state):
        pass

    @abstractmethod
    def set_buffer_size(self, rx_size=None, tx_size=None):
        pass

    def wait_link_up(self, timeout=LINK_UP_TIMEOUT, retry_interval=0.5, vlan_id=None):
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            time.sleep(retry_interval)
            speed = self.get_link_speed(vlan_id)
            if speed not in [None, LINK_SPEED_NO_LINK]:
                log.info("Link {} is UP".format(speed))
                return speed

        collect_debug_info()

        raise Exception('Link is NOT up after timeout = {} sec.'.format(timeout))

    def wait_link_down(self, timeout=LINK_UP_TIMEOUT, retry_interval=0.5, vlan_id=None):
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            time.sleep(retry_interval)
            speed = self.get_link_speed(vlan_id)
            if speed in [None, LINK_SPEED_NO_LINK]:
                log.info("Link {} is DOWN".format(speed))
                return speed
        raise Exception('Link is up after timeout = {} sec.'.format(timeout))


class IfconfigLocal(Ifconfig):
    def get_link_speed(self, vlan_id=None):
        if sys.platform == "win32":
            return self.get_link_speed_win(vlan_id)
        elif 'linux' in sys.platform.lower():
            return self.get_link_speed_linux(vlan_id)
        elif sys.platform == "darwin":
            return self.get_link_speed_macos(vlan_id)
        elif "freebsd" in sys.platform:
            return self.get_link_speed_freebsd(vlan_id)
        else:
            raise NotImplementedError("The functionality is not implemented")

    def get_link_speed_win(self, vlan_id=None):
        if vlan_id is not None:
            raise NotImplementedError()

        speed_map = {
            "10000000": LINK_SPEED_10M,
            "100000000": LINK_SPEED_100M,
            "1000000000": LINK_SPEED_1G,
            "2500000000": LINK_SPEED_2_5G,
            "5000000000": LINK_SPEED_5G,
            "10000000000": LINK_SPEED_10G,
        }
        network_adapter = get_wmi_network_adapter(self.port)
        try:
            if int(network_adapter.NetConnectionStatus) != 2:
                return LINK_SPEED_NO_LINK
            else:
                return speed_map[network_adapter.Speed]
        except KeyError:
            return LINK_SPEED_NO_LINK

    def get_link_speed_linux(self, vlan_id=None):
        speed_map = {
            "10": LINK_SPEED_10M,
            "100": LINK_SPEED_100M,
            "1000": LINK_SPEED_1G,
            "2500": LINK_SPEED_2_5G,
            "5000": LINK_SPEED_5G,
            "10000": LINK_SPEED_10G,
        }
        cmd = "sudo ethtool {}{} | grep -i speed: ".format(self.iface,
                                                           ".{}".format(vlan_id) if vlan_id is not None else "")
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)

        re_speed = re.compile(".*Speed: *([0-9]+)[a-zA-Z]*", re.DOTALL)
        m = re_speed.match(output.rstrip("\r\n"))
        if m is not None:
            try:
                return speed_map[m.group(1)]
            except KeyError:
                return LINK_SPEED_NO_LINK
        else:
            return LINK_SPEED_NO_LINK

    def get_link_speed_macos(self, vlan_id=None):
        if vlan_id is not None:
            iface = "vlan{}".format(vlan_id)
        else:
            iface = get_macos_network_adapter_name(self.port)

        media_type_map = {
            LINK_SPEED_100M: "100baseTX",
            LINK_SPEED_1G: "1000baseT",
            LINK_SPEED_2_5G: "2500Base-T",
            LINK_SPEED_5G: "5000Base-T",
            LINK_SPEED_10G: "10Gbase-T"
        }

        res = Command(cmd="ifconfig {} | grep status".format(iface)).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to get link speed")
        is_active = False
        for line in res["output"]:
            if "inactive" in line:
                return LINK_SPEED_NO_LINK
            if "active" in line:
                is_active = True
                break
        if is_active is False:
            raise Exception("Unknown link status")

        res = Command(cmd="ifconfig {} | grep media".format(iface)).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to get link speed")
        for line in res["output"]:
            for k, v in media_type_map.items():
                if v in line:
                    return k
        raise Exception("Unknown media type")

    def get_link_speed_freebsd(self, vlan_id=None):
        if vlan_id is not None:
            iface = "vlan{}".format(vlan_id)
        else:
            iface = get_freebsd_network_adapter_name(self.port)

        media_type_map = {
            LINK_SPEED_100M: "100baseTX",
            LINK_SPEED_1G: "1000baseT",
            LINK_SPEED_2_5G: "2500Base-T",
            LINK_SPEED_5G: "5000Base-T",
            LINK_SPEED_10G: "10Gbase-T",
        }

        res = Command(cmd="ifconfig {} | grep status".format(iface)).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to get link speed")
        is_active = False
        for line in res["output"]:
            if "no carrier" in line:
                return LINK_SPEED_NO_LINK
            if "active" in line:
                is_active = True
                break
        if is_active is False:
            raise Exception("Unknown link status")

        res = Command(cmd="ifconfig {} | grep media".format(iface)).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to get link speed")
        for line in res["output"]:
            for k, v in media_type_map.items():
                if v in line:
                    return k
        raise Exception("Unknown media type")

    def set_link_speed_win(self, speed, half_duplex):
        import _winreg
        network_adapter_id = get_wmi_device_id(self.port)
        network_adapter = get_wmi_network_adapter(self.port)
        subkey = "{:04d}".format(network_adapter.Index)

        internal_k = r"SYSTEM\ControlSet001\Control\Class"
        internal_k += r"\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{}".format(subkey)

        log.info("Trying to open key {}".format(internal_k))
        key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, internal_k, 0, _winreg.KEY_ALL_ACCESS)

        if network_adapter.ServiceName in AQUANTIA_SERVICE_NAMES_USB:
            if speed == LINK_SPEED_100M:
                val = "4"
            elif speed == LINK_SPEED_1G:
                val = "6"
            elif speed == LINK_SPEED_2_5G:
                val = "2500"
            elif speed == LINK_SPEED_5G:
                val = "5000"
            elif speed == LINK_SPEED_AUTO:
                val = "0"
            else:
                raise Exception("Invalid link speed {}".format(speed))
            log.info("Setting value {} to LinkSpeed in key {}".format(val, internal_k))
            _winreg.SetValueEx(key, "LinkSpeed", 0, _winreg.REG_SZ, val)
        elif network_adapter.ServiceName in AQUANTIA_SERVICE_NAMES:
            target_subkey = None
            try:
                _winreg.QueryValueEx(key, '*SpeedDuplex')
                target_subkey = '*SpeedDuplex'
            except Exception:
                pass
            try:
                _winreg.QueryValueEx(key, 'LinkSpeed')
                target_subkey = '*LinkSpeed'
            except Exception:
                pass

            assert target_subkey is not None, 'Link speed subkey is not found.'

            if target_subkey == '*SpeedDuplex':
                if speed == LINK_SPEED_100M:
                    val = "4"
                elif speed == LINK_SPEED_1G:
                    val = "6"
                elif speed == LINK_SPEED_2_5G:
                    val = "2500"
                elif speed == LINK_SPEED_5G:
                    val = "5000"
                elif speed == LINK_SPEED_10G:
                    val = "7"
                elif speed == LINK_SPEED_AUTO:
                    val = "0"
                else:
                    raise Exception("Invalid link speed {}".format(speed))
                log.info("Setting value {} to *SpeedDuplex in key {}".format(val, internal_k))
                _winreg.SetValueEx(key, "*SpeedDuplex", 0, _winreg.REG_SZ, val)
            else:
                if speed == LINK_SPEED_100M:
                    val = "32"
                elif speed == LINK_SPEED_1G:
                    val = "16"
                elif speed == LINK_SPEED_2_5G:
                    val = "8"
                elif speed == LINK_SPEED_5G:
                    val = "2"
                elif speed == LINK_SPEED_10G:
                    val = "1"
                elif speed == LINK_SPEED_AUTO:
                    lanes = get_nof_pci_lines(self.port)
                    if lanes == 1:
                        val = "58"
                    elif lanes in [2, 4]:
                        val = "59"
                else:
                    raise Exception("Invalid link speed {}".format(speed))
                log.info("Setting value {} to LinkSpeed in key {}".format(val, internal_k))
                _winreg.SetValueEx(key, "LinkSpeed", 0, _winreg.REG_SZ, val)
        elif network_adapter.ServiceName in ["ixgbt", "ixgbs"]:
            if speed == LINK_SPEED_100M:
                val = "4"
            elif speed == LINK_SPEED_1G:
                val = "6"
            elif speed == LINK_SPEED_10G:
                val = "7"
            elif speed == LINK_SPEED_AUTO:
                val = "0"
            else:
                raise Exception("Link speed {} is not supported by {}".format(speed, network_adapter.Name))
            log.info("Setting value {} to *SpeedDuplex in key {}".format(val, internal_k))
            _winreg.SetValueEx(key, "*SpeedDuplex", 0, _winreg.REG_SZ, val)
        elif network_adapter.ServiceName == "rt640x64":
            if speed == LINK_SPEED_100M:
                val = "4"
            elif speed == LINK_SPEED_1G:
                val = "6"
            elif speed == LINK_SPEED_AUTO:
                val = "0"
            else:
                raise Exception("Link speed {} is not supported by {}".format(speed, network_adapter.Name))
            log.info("Setting value {} to LinkSpeed in key {}".format(val, internal_k))
            _winreg.SetValueEx(key, "LinkSpeed", 0, _winreg.REG_SZ, val)
        elif network_adapter.ServiceName == "TN40xxmp":
            if speed == LINK_SPEED_100M:
                val = "3"
            elif speed == LINK_SPEED_1G:
                val = "2"
            elif speed == LINK_SPEED_2_5G:
                val = "4"
            elif speed == LINK_SPEED_5G:
                val = "5"
            elif speed == LINK_SPEED_10G:
                val = "1"
            elif speed == LINK_SPEED_AUTO:
                val = "0"
            else:
                raise Exception("Link speed {} is not supported by {}".format(speed, network_adapter.Name))
            log.info("Setting value {} to LinkSpeed in key {}".format(val, internal_k))
            _winreg.SetValueEx(key, "LinkSpeed", 0, _winreg.REG_SZ, val)
        elif network_adapter.ServiceName in AQUANTIA_SERVICE_NAMES:
            if "DEV_00C0" in network_adapter_id:
                if half_duplex:
                    if speed == LINK_SPEED_100M:
                        val = "3"
                    elif speed == LINK_SPEED_1G:
                        val = "5"
                    elif speed == LINK_SPEED_10M:
                        val = "1"
                    else:
                        raise Exception("Invalid link speed {}".format(speed))
                else:
                    if speed == LINK_SPEED_100M:
                        val = "4"
                    elif speed == LINK_SPEED_1G:
                        val = "6"
                    elif speed == LINK_SPEED_2_5G:
                        val = "2500"
                    elif speed == LINK_SPEED_5G:
                        val = "5000"
                    elif speed == LINK_SPEED_10G:
                        val = "7"
                    elif speed == LINK_SPEED_AUTO:
                        val = "0"
                    elif speed == LINK_SPEED_10M:
                        val = "2"
                    else:
                        raise Exception("Invalid link speed {}".format(speed))
            else:
                if speed == LINK_SPEED_100M:
                    val = "32"
                elif speed == LINK_SPEED_1G:
                    val = "16"
                elif speed == LINK_SPEED_2_5G:
                    val = "8"
                elif speed == LINK_SPEED_5G:
                    val = "2"
                elif speed == LINK_SPEED_10G:
                    val = "1"
                elif speed == LINK_SPEED_AUTO:
                    lanes = get_nof_pci_lines(self.port)
                    if lanes == 1:
                        val = "58"
                    elif lanes in [2, 4]:
                        val = "59"
                else:
                    raise Exception("Invalid link speed {}".format(speed))
            log.info("Setting value {} to LinkSpeed in key {}".format(val, internal_k))
            _winreg.SetValueEx(key, "LinkSpeed", 0, _winreg.REG_SZ, val)
        else:
            log.info("Adapter: {}".format(network_adapter))
            if speed == LINK_SPEED_100M:
                val = "4"
            elif speed == LINK_SPEED_1G:
                val = "6"
            elif speed == LINK_SPEED_AUTO:
                val = "0"
            try:
                _winreg.SetValueEx(key, "*SpeedDuplex", 0, _winreg.REG_SZ, val)
            except Exception:
                raise NotImplementedError(
                    "Something went wrong while appling link speed for unspecified network adapter")
        if key is not None:
            _winreg.CloseKey(key)

    def set_link_speed_linux(self, speed, half_duplex):
        if speed == "10M":
            val = "10"
        elif speed == "100M":
            val = "100"
        elif speed == "1G":
            val = "1000"
        elif speed == "2.5G":
            val = "2500"
        elif speed == "5G":
            val = "5000"
        elif speed == "10G":
            val = "10000"
        elif speed == "AUTO":
            val = "0"
        else:
            raise Exception("Invalid link speed %s" % speed)

        if half_duplex:
            duplex = "half"
        else:
            duplex = "full"
        if val == "0":
            cmd = "sudo ethtool -s %s autoneg on" % self.iface
        else:
            cmd = "sudo ethtool -s {} speed {} duplex {} autoneg off".format(self.iface, val, duplex)
        res = Command(cmd=cmd).wait(10)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to set link speed")

    def set_link_speed_macos(self, speed):
        media_type_map = {
            LINK_SPEED_100M: "100baseTX",
            LINK_SPEED_1G: "1000baseT",
            LINK_SPEED_2_5G: "2500base-T",
            LINK_SPEED_5G: "5000base-T",
            LINK_SPEED_10G: "10Gbase-T",
            LINK_SPEED_AUTO: "autoselect",
        }
        iface = get_macos_network_adapter_name(self.port)
        cmd = "sudo ifconfig {} media {}".format(iface, media_type_map[speed])
        res = Command(cmd=cmd).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to set link speed")

    def set_link_speed_freebsd(self, speed):
        media_type_map = {
            LINK_SPEED_100M: "100baseTX",
            LINK_SPEED_1G: "1000baseT",
            LINK_SPEED_2_5G: "2500Base-T",
            LINK_SPEED_5G: "5000Base-T",
            LINK_SPEED_10G: "10Gbase-T",
            LINK_SPEED_AUTO: "autoselect",
        }
        iface = get_freebsd_network_adapter_name(self.port)
        cmd = "sudo ifconfig {} media {} mediaopt full-duplex".format(iface, media_type_map[speed])
        res = Command(cmd=cmd).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to set link speed")

    def set_link_speed(self, speed, half_duplex=False):
        if sys.platform == 'win32':
            self.set_link_speed_win(speed, half_duplex)
            self.set_link_down()
            self.set_link_up()
        elif 'linux' in sys.platform.lower():
            self.set_link_speed_linux(speed, half_duplex)
            self.set_link_down()
            self.set_link_up()
        elif 'freebsd' in sys.platform.lower():
            self.set_link_down()
            self.set_link_speed_freebsd(speed)
            self.set_link_up()
        elif sys.platform == "darwin":
            self.set_link_speed_macos(speed)
            time.sleep(3)
        else:
            raise NotImplementedError("The functionality is not implemented")

    def set_link_state(self, state, vlan_id=None):
        log.info("Setting link state {} vlan_id {}".format(state, vlan_id))
        if state == LINK_STATE_UP:
            self.set_link_up(vlan_id)
        elif state == LINK_STATE_DOWN:
            self.set_link_down(vlan_id)
        else:
            raise Exception("Invalid link state '{}'".format(state))

    def set_link_down_win(self, vlan_id=None):
        if vlan_id is not None:
            raise NotImplementedError()

        def get_actual_adapter():
            if "usb" not in self.port:
                network_adapter = get_wmi_network_adapter(self.port)
            else:
                driver = get_wmi_device_pnp_driver(self.port)
                network_adapter = next(nic for nic in wmi.WMI(namespace='StandardCimv2').MSFT_NetAdapter() \
                                       if nic.PNPDeviceID == driver.DeviceID)
            return network_adapter

        network_adapter = get_actual_adapter()
        log.info("Disabling network adapter {}".format(network_adapter.Name))
        res = network_adapter.Disable()
        exp_res = (0 if "usb" not in self.port else None)
        if res[0] != exp_res:
            raise "Failed to disable network adapter with error %s" % res
        start = timeit.default_timer()
        while timeit.default_timer() - start < 10:
            network_adapter = get_actual_adapter()
            disable_state = (
                network_adapter.ConfigManagerErrorCode if "usb" not in self.port else network_adapter.State)
            exp_state = (22 if "usb" not in self.port else 3)
            if disable_state == exp_state:
                log.info("Device {} is disabled".format(self.port))
                break
            time.sleep(1)
        if int(disable_state) != exp_state:
            raise Exception('Failed to disable network adapter after 10 seconds')

    def set_link_down_linux(self, vlan_id=None):
        log.info("Disabling network adapter {}".format(self.iface))
        cmd = "sudo ip link set {}{} down".format(self.iface,
                                                  "" if vlan_id is None else ".{}".format(vlan_id))
        subprocess.check_output(cmd, shell=True)

    def set_link_down_macos(self, vlan_id=None):
        if vlan_id is not None:
            iface = "vlan{}".format(vlan_id)
        else:
            iface = get_macos_network_adapter_name(self.port)

        log.info("Disabling network adapter {}".format(iface))
        res = Command(cmd="sudo ifconfig {} down".format(iface)).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to down interface")

    def set_link_down_freebsd(self, vlan_id=None):
        if vlan_id is not None:
            iface = "vlan{}".format(vlan_id)
        else:
            iface = get_freebsd_network_adapter_name(self.port)

        log.info("Disabling network adapter {}".format(iface))
        res = Command(cmd="sudo ifconfig {} down".format(iface)).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to down interface")

    def set_link_down(self, vlan_id=None):
        if sys.platform == 'win32':
            self.set_link_down_win(vlan_id)
        elif 'linux' in sys.platform.lower():
            self.set_link_down_linux(vlan_id)
        elif sys.platform == "darwin":
            self.set_link_down_macos(vlan_id)
        elif "freebsd" in sys.platform:
            self.set_link_down_freebsd(vlan_id)
        else:
            raise NotImplementedError("The functionality is not implemented")

    def set_link_up_win(self, vlan_id=None):
        if vlan_id is not None:
            raise NotImplementedError()

        def get_actual_adapter():
            if "usb" not in self.port:
                network_adapter = get_wmi_network_adapter(self.port)
            else:
                driver = get_wmi_device_pnp_driver(self.port)
                network_adapter = next(nic for nic in wmi.WMI(namespace='StandardCimv2').MSFT_NetAdapter() \
                                       if nic.PNPDeviceID == driver.DeviceID)
            return network_adapter

        network_adapter = get_actual_adapter()
        log.info("Enabling network adapter {}".format(network_adapter.Name))
        res = network_adapter.Enable()
        exp_res = (0 if "usb" not in self.port else None)
        if res[0] != exp_res:
            raise Exception("Failed to enable network adapter with error {}".format(res))
        start = timeit.default_timer()
        while timeit.default_timer() - start < 10:
            network_adapter = get_actual_adapter()
            enable_state = (network_adapter.ConfigManagerErrorCode if "usb" not in self.port else network_adapter.State)
            exp_state = (0 if "usb" not in self.port else 2)
            if enable_state == exp_state:
                log.info("Device {} is enabled".format(self.port))
                break
            time.sleep(1)
        if enable_state != exp_state:
            raise Exception('Failed to enable network adapter after 10 seconds')

    def set_link_up_linux(self, vlan_id=None):
        log.info("Enabling network adapter {}".format(self.iface))
        cmd = "sudo ip link set {}{} up".format(self.iface, "" if vlan_id is None else ".{}".format(vlan_id))
        res = Command(cmd=cmd).wait(10)
        assert res["returncode"] == 0 and res["reason"] == Command.REASON_OK, "Failed to set link up"

    def set_link_up_macos(self, vlan_id=None):
        if vlan_id is not None:
            iface = "vlan{}".format(vlan_id)
        else:
            iface = get_macos_network_adapter_name(self.port)

        log.info("Enabling network adapter {}".format(iface))
        res = Command(cmd="sudo ifconfig {} up".format(iface)).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to down interface")

    def set_link_up_freebsd(self, vlan_id=None):
        if vlan_id is not None:
            iface = "vlan{}".format(vlan_id)
        else:
            iface = get_freebsd_network_adapter_name(self.port)

        log.info("Enabling network adapter {}".format(iface))
        res = Command(cmd="sudo ifconfig {} up".format(iface)).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to down interface")

    def set_link_up(self, vlan_id=None):
        if sys.platform == 'win32':
            self.set_link_up_win(vlan_id)
        elif 'linux' in sys.platform.lower():
            self.set_link_up_linux(vlan_id)
        elif sys.platform == "darwin":
            self.set_link_up_macos(vlan_id)
        elif "freebsd" in sys.platform:
            self.set_link_up_freebsd(vlan_id)
        else:
            raise NotImplementedError("The functionality is not implemented")

    def set_ip_address_win(self, address, netmask, gateway=None, vlan_id=None):
        if vlan_id is not None:
            raise NotImplementedError()

        for i in range(3)[::-1]:
            try:
                network_adapter = get_wmi_network_adapter(self.port)

                network_adapter_cfg = None
                nic_configs = wmi.WMI().Win32_NetworkAdapterConfiguration()
                for nic_config in nic_configs:
                    if nic_config.InterfaceIndex == network_adapter.InterfaceIndex:
                        network_adapter_cfg = nic_config

                if not network_adapter_cfg:
                    log.warning("No network adapter configuration found! Attempts left: {}".format(i))
                    for nic_config in nic_configs:
                        log.info(nic_config)
                    raise Exception("Could not find NetworkAdapterConfiguration for "
                                    "InterfaceIndex {}".format(network_adapter.InterfaceIndex))
            except Exception as exc:
                if i == 0:  # last attempt
                    log.exception(exc)
                    raise exc
                else:
                    log.info('Sleeping 10 seconds...')
                    time.sleep(10)
                    continue

        if network_adapter_cfg.IPAddress:
            ips = [ip for ip in network_adapter_cfg.IPAddress if ipaddress.ip_address(unicode(ip)).version == 4]
        else:
            ips = []
        if network_adapter_cfg.IPSubnet:
            RE_IPV4 = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")
            masks = [mask for mask in network_adapter_cfg.IPSubnet if RE_IPV4.match(mask) is not None]
        else:
            masks = []

        log.info("Setting {} IP address on adapter {}".format(address, network_adapter_cfg.Description))
        if address in ips:
            log.warning("Address {} is already set to adapter {}. "
                        "Will only update netmask".format(address, network_adapter_cfg.Description))
            ip_index = ips.index(address)
            masks[ip_index] = netmask
        else:
            ips.append(address)
            masks.append(netmask)
        res = network_adapter_cfg.EnableStatic(IPAddress=ips, SubnetMask=masks)
        if res[0] != 0:
            raise Exception("EnableStatic returned non zero code: {}".format(res[0]))

        if gateway:
            log.info("Setting gateway {} to adapter {}".format(gateway, network_adapter_cfg.Description))
            if network_adapter_cfg.DefaultIPGateway:
                gws = [gw for gw in network_adapter_cfg.DefaultIPGateway
                       if ipaddress.ip_address(unicode(gw)).version == 4 and gw != "0.0.0.0"]
            else:
                gws = []
            if gateway not in gws:
                gws.append(gateway)
                res = network_adapter_cfg.SetGateways(DefaultIPGateway=gws)
                if res[0] != 0:
                    raise Exception("SetGateways returned non zero code: {}".format(res[0]))

    def set_ip_address_linux(self, address, netmask, gateway=None, vlan_id=None):
        try:
            cmd = "sudo service NetworkManager stop"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            log.info(output)
        except subprocess.CalledProcessError as e:
            if "service not loaded" not in e.output:
                log.exception(e.output)
                raise e
        cidr = sum([bin(int(x)).count("1") for x in netmask.split(".")])

        # Flushing is commented because we need link-local IP address in FW sanity 2x tests
        # cmd = "sudo ip addr flush dev {}".format(nic_name)
        # try:
        #     output = subprocess.check_output(cmd, shell=True,
        #                                      stderr=subprocess.STDOUT)
        #     log.info(output)
        # except subprocess.CalledProcessError as e:
        #     log.exception(e.output)
        #     raise e

        cmd = "sudo ip addr add {}/{} dev {}{}".format(
            address, cidr, self.iface, "" if vlan_id is None else ".{}".format(vlan_id))
        res = Command(cmd=cmd).wait(5)
        if res["returncode"] != 0:
            for line in res["output"]:
                if "exists" in line:
                    log.info("IP address already exists")
                    return
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to set IP address")

        gateway = None
        if gateway:
            # TODO:
            # Not verified. Need to check that it works correctly
            cmd = "sudo ip route add default via {} dev {}{}".format(
                gateway, self.iface, "" if vlan_id is None else ".{}".format(vlan_id))
            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                log.info(output)
            except subprocess.CalledProcessError as e:
                log.exception(e.output)
                raise e

        self.set_link_up()
        time.sleep(2)

        cmd = "sudo ip addr show {}{}".format(self.iface, "" if vlan_id is None else ".{}".format(vlan_id))
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            log.info(output)
            if address not in output:
                raise Exception("Failed to set IP address on {}".format(self.iface))
        except subprocess.CalledProcessError as e:
            log.exception(e.output)
            raise e

    def set_ip_address_freebsd(self, address, netmask, gateway=None, vlan_id=None):
        if vlan_id:
            iface = "vlan{}".format(vlan_id)
        else:
            iface = get_freebsd_network_adapter_name(self.port)
        res = Command(cmd="sudo ifconfig {} inet {} netmask {}".format(iface, address, netmask)).run_join(5)

        if res["returncode"] != 0:
            raise Exception("Failed to set IPv4 address")

    def set_ip_address_macos(self, address, netmask, gateway=None, vlan_id=None):
        if vlan_id is not None:
            res = Command(cmd="sudo ifconfig vlan{} inet {} netmask {}". \
                          format(vlan_id, address, netmask)).run_join(5)

            if res["returncode"] != 0:
                raise Exception("Failed to set IPv4 address")

            return
        iface = get_macos_network_adapter_name(self.port)
        cmd = "sudo ipconfig set {} MANUAL {} {}".format(iface, address, netmask)
        res = Command(cmd=cmd).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to set IPv4 address")

        # Ip address check can be done only when link is up.
        # In case when setup is mac to mac ip address check can be performed only
        # after setting on both machines. That is why check is commented here.
        time.sleep(3)

        # # Try to check IP address 2 times
        # for i in range(2):
        #     time.sleep(5)  # sleep some time to make address visible
        #     res = Command(cmd="sudo ifconfig {}".format(iface)).run_join(1)
        #     if res["returncode"] != 0:
        #         raise Exception("Failed to check IPv6 address")

        #     for line in res["output"]:
        #         if "inet {}".format(address, netmask) in line:
        #             return

        # raise Exception("IP address was not set")

    def set_ip_address(self, address, netmask, gateway=None, vlan_id=None):
        log.info("Setting IPv4 address {}/{} gateway {} vlan_id {}".format(address, netmask, gateway, vlan_id))
        if sys.platform == 'win32':
            self.set_ip_address_win(address, netmask, gateway, vlan_id)
        elif 'linux' in sys.platform.lower():
            self.set_ip_address_linux(address, netmask, gateway, vlan_id)
        elif sys.platform == "darwin":
            self.set_ip_address_macos(address, netmask, gateway, vlan_id)
        elif "freebsd" in sys.platform:
            self.set_ip_address_freebsd(address, netmask, gateway, vlan_id)
        else:
            raise NotImplementedError("The functionality is not implemented")

    def set_ipv6_address_win(self, address, prefix, gateway=None):
        network_adapter = get_wmi_network_adapter(self.port)
        net_connection = network_adapter.NetConnectionID

        cmd = "netsh interface ipv6 add address interface=\"{conn}\" address={addr}/{prefix} type=unicast".format(
            conn=net_connection, addr=address, prefix=prefix)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            if any("The object already exists." in line for line in res["output"]):
                log.info("IPv6 adress already exists")
            else:
                raise Exception("Failed to set IPv6 address")

        if gateway:
            cmd = "netsh interface ipv6 add route ::/0 interface=\"{conn}\" {gw}".format(conn=net_connection,
                                                                                         gw=gateway)
            res = Command(cmd=cmd).run()
            if res["returncode"] != 0:
                raise Exception("Failed to set default gateway")

    def set_ipv6_address_linux(self, address, prefix, gateway=None):
        try:
            cmd = "sudo service NetworkManager stop"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            log.info(output)
        except subprocess.CalledProcessError as e:
            if "service not loaded" not in e.output:
                log.error(e.output)
                raise e

        # Flushing is commented because we need link-local IP address in FW sanity 2x tests
        # try:
        #     cmd = "sudo ip -6 addr flush dev {}".format(nic_name)
        #     output = subprocess.check_output(cmd, shell=True,
        #                                      stderr=subprocess.STDOUT)
        #     log.info(output)
        # except subprocess.CalledProcessError as e:
        #     log.error(e.output)
        #     raise e

        cmd = "sudo ip -6 addr add {}/{} dev {}".format(address, prefix, self.iface)
        res = Command(cmd=cmd).wait(5)
        if res["returncode"] != 0:
            for line in res["output"]:
                if "exists" in line:
                    log.info("IPv6 address already exists")
                    return
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to set IP address")

        self.set_link_up()
        time.sleep(2)

    def set_ipv6_address_freebsd(self, address, prefix, gateway=None):
        iface = get_freebsd_network_adapter_name(self.port)
        res = Command(cmd="sudo ifconfig {} inet6 {}/{}".format(iface, address, prefix)).run_join(5)

        if res["returncode"] != 0:
            raise Exception("Failed to set IPv6 address")

    def set_ipv6_address_macos(self, address, prefix, gateway=None):
        iface = get_macos_network_adapter_name(self.port)
        cmd = "sudo ipconfig set {} MANUAL-V6 {} {}".format(iface, address, prefix)
        res = Command(cmd=cmd).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to set IPv6 address")

        # Ip address check can be done only when link is up.
        # In case when setup is mac to mac ip address check can be performed only
        # after setting on both machines. That is why check is commented here.
        time.sleep(3)

        # # Try to check IP address 2 times
        # for i in range(2):
        #     time.sleep(5)  # sleep some time to make address visible
        #     res = Command(cmd="sudo ifconfig {}".format(iface)).run_join(1)
        #     if res["returncode"] != 0:
        #         raise Exception("Failed to check IPv6 address")

        #     for line in res["output"]:
        #         compr_ip = ipaddress.ip_address(unicode(address)).compressed
        #         if "inet6 {} prefixlen {}".format(compr_ip, prefix) in line:
        #             return

        # raise Exception("IPv6 address was not set")

    def set_ipv6_address(self, address, prefix, gateway=None):
        log.info("Setting IPv6 address {}/{} gateway {}".format(address, prefix, gateway))
        if sys.platform == 'win32':
            self.set_ipv6_address_win(address, prefix, gateway)
        elif sys.platform == "darwin":
            self.set_ipv6_address_macos(address, prefix, gateway)
        elif "linux" in sys.platform:
            self.set_ipv6_address_linux(address, prefix, gateway)
        elif "freebsd" in sys.platform:
            self.set_ipv6_address_freebsd(address, prefix, gateway)
        else:
            raise NotImplementedError()

    def get_mac_address_win(self):
        network_adapter = get_wmi_network_adapter(self.port)
        return network_adapter.MACAddress

    def get_mac_address_linux(self, macvlan):
        if macvlan == None:
            iface = self.iface
        else:
            iface = macvlan
        cmd = "ip a | grep -A 1 %s | grep ether | awk '{print $2}'" % iface
        try:
            output = subprocess.check_output(
                cmd, stderr=subprocess.STDOUT, shell=True)
            re_mac = re.compile("([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-]"
                                "[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-]"
                                "[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})", re.DOTALL)
            for line in output.split("\n"):
                m = re_mac.match(line)
                if m is not None:
                    return m.group(1)
        except subprocess.CalledProcessError as e:
            log.exception(e.output)
            raise e

    def get_mac_address_macos(self):
        iface = get_macos_network_adapter_name(self.port)
        cmd = "ifconfig | grep -A 3 {} | grep ether | awk '{{print $2}}'".format(iface)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            raise Exception("Couldn't get MAC addresses for interface: {}".format(iface))
        else:
            re_mac = re.compile("([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-]"
                                "[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-]"
                                "[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})", re.DOTALL)
            for line in res["output"]:
                m = re_mac.match(line)
                if m is not None:
                    return m.group(1)
            raise Exception("Couldn't get MAC address, regex not matched")

    def get_mac_address_freebsd(self):
        iface = get_freebsd_network_adapter_name(self.port)
        cmd = "ifconfig {} | grep ether | awk '{{print $2}}'".format(iface)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            raise Exception("Couldn't get MAC addresses for interface: {}".format(iface))
        else:
            re_mac = re.compile("([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-]"
                                "[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-]"
                                "[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})", re.DOTALL)
            for line in res["output"]:
                m = re_mac.match(line)
                if m is not None:
                    return m.group(1)
            raise Exception("Couldn't get MAC address, regex not matched")

    def get_mac_address(self, macvlan=None):
        if sys.platform == "win32":
            return self.get_mac_address_win()
        elif sys.platform == "darwin":
            return self.get_mac_address_macos()
        elif "freebsd" in sys.platform:
            return self.get_mac_address_freebsd()
        else:
            return self.get_mac_address_linux(macvlan)

    def get_management_mac_address(self):
        return get_mgmt_mac()

    def get_management_gateway(self):
        return get_mgmt_gw()

    def get_counters(self):
        return self.get_interface_stats()

    def get_nof_pci_lines(self):
        return get_nof_pci_lines(self.port)

    def get_interface_stats_win(self):
        internal_stats = collections.OrderedDict()
        internal_stats["transmit_ok"] = STAT_NOT_SUPPORTED
        internal_stats["transmit_error"] = STAT_NOT_SUPPORTED
        internal_stats["receive_ok"] = STAT_NOT_SUPPORTED
        internal_stats["receive_error"] = STAT_NOT_SUPPORTED

        bus, _, __ = get_bus_dev_func(self.port)

        pnp_entity = None
        for device_bus in wmi.WMI().Win32_DeviceBus():
            try:
                if device_bus.Antecedent.DeviceID == "PCI_BUS_%s" % bus:
                    pnp_entity = device_bus.Dependent
                    break
            except Exception:
                pass  # log.info('WARNING! WMI error: "{}"'.format(exc))

        for tr_ok in wmi.WMI(namespace="wmi").MSNdis_TransmitsOk():
            if tr_ok.InstanceName == pnp_entity.Name:
                internal_stats["transmit_ok"] = int(tr_ok.NdisTransmitsOk)

        for tr_err in wmi.WMI(namespace="wmi").MSNdis_TransmitsError():
            if tr_err.InstanceName == pnp_entity.Name:
                internal_stats["transmit_error"] = int(tr_err.NdisTransmitsError)

        for rec_ok in wmi.WMI(namespace="wmi").MSNdis_ReceivesOk():
            if rec_ok.InstanceName == pnp_entity.Name:
                internal_stats["receive_ok"] = int(rec_ok.NdisReceivesOk)

        for rec_err in wmi.WMI(namespace="wmi").MSNdis_ReceiveError():
            if rec_err.InstanceName == pnp_entity.Name:
                internal_stats["receive_error"] = int(rec_err.NdisReceiveError)

        return internal_stats

    def get_interface_stats_linux(self):
        internal_stats = dict(transmit_ok=STAT_NOT_SUPPORTED,
                              transmit_error=STAT_NOT_SUPPORTED,
                              receive_ok=STAT_NOT_SUPPORTED,
                              receive_error=STAT_NOT_SUPPORTED)
        cmd = "grep %s //proc//net//dev" % self.iface
        full_stats = subprocess.check_output(cmd,
                                             stderr=subprocess.STDOUT,
                                             shell=True).split()[1:]

        internal_stats["transmit_ok"] = int(full_stats[9])
        internal_stats["transmit_error"] = int(full_stats[10])
        internal_stats["receive_ok"] = int(full_stats[1])
        internal_stats["receive_error"] = int(full_stats[2])

        return internal_stats

    def get_interface_stats(self):
        if sys.platform == 'win32':
            return self.get_interface_stats_win()
        elif 'linux' in sys.platform.lower():
            return self.get_interface_stats_linux()
        else:
            raise NotImplementedError("The functionality is not implemented")

    def set_arp_win(self, address, mac, ipv=4):
        re_mac = re.compile("([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]"
                            "([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]"
                            "([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})")
        m = re_mac.match(mac)
        mac = "{}-{}-{}-{}-{}-{}".format(
            m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6))
        network_adapter = get_wmi_network_adapter(self.port)
        cmd = "netsh interface ip{} add neighbors \"{}\" {} {}".format(
            "v6" if ipv == 6 else "", network_adapter.NetConnectionId, address, mac)
        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
        except subprocess.CalledProcessError as e:
            if "exists" in e.output:
                self.del_arp(address)
                subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                        shell=True)
            else:
                log.error(e.output)
                raise Exception("Failed to set ARP entry")

    def set_arp_linux(self, address, mac, ipv=4):
        re_mac = re.compile("([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]"
                            "([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]"
                            "([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})")
        m = re_mac.match(mac)
        mac = "{}:{}:{}:{}:{}:{}".format(
            m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6))
        cmd = "sudo ip -{} neigh replace {} lladdr {} nud permanent dev {}".format(ipv, address, mac, self.iface)
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)

    def set_arp_macos(self, address, mac, ipv=4):
        # cmd = "ndp -a"
        raise NotImplementedError()

    def set_arp_freebsd(self, address, mac, ipv=4):
        # cmd = "ndp -a"
        raise NotImplementedError()

    def set_arp(self, address, mac):
        log.info("Setting static ARP entry {} -> {}".format(address, mac))
        ip_addr = ipaddress.ip_address(unicode(address))

        if sys.platform == "win32":
            self.set_arp_win(address, mac, ip_addr.version)
        elif "linux" in sys.platform.lower():
            self.set_arp_linux(address, mac, ip_addr.version)
        elif sys.platform == "darwin":
            self.set_arp_macos(address, mac, ip_addr.version)
        elif "freebsd" in sys.platform:
            self.set_arp_freebsd(address, mac, ip_addr.version)
        else:
            raise NotImplementedError("The functionality is not implemented")

    def del_arp_win(self, address, ipv=4):
        network_adapter = get_wmi_network_adapter(self.port)
        cmd = "netsh interface ip{} del neighbors \"{}\" {}".format(
            "v6" if ipv == 6 else "", network_adapter.NetConnectionId, address)
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)

    def del_arp_linux(self, address, ipv=4):
        cmd = "sudo ip -{} neigh del {} dev {}".format(ipv, address, self.iface)
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)

    def del_arp_macos(self, address, ipv=4):
        # cmd = "ndp -a"
        raise NotImplementedError()

    def del_arp_freebsd(self, address, ipv=4):
        # cmd = "ndp -a"
        raise NotImplementedError()

    def del_arp(self, address):
        ip_addr = ipaddress.ip_address(unicode(address))

        if sys.platform == "win32":
            self.del_arp_win(address, ip_addr.version)
        elif "linux" in sys.platform.lower()():
            self.del_arp_linux(address, ip_addr.version)
        elif sys.platform == "darwin":
            self.del_arp_macos(address, ip_addr.version)
        elif "freebsd" in sys.platform:
            self.del_arp_freebsd(address, mac, ip_addr.version)
        else:
            raise NotImplementedError("The functionality is not implemented")

    def get_guid_by_mac(self, mac_address, once=True):
        mac_original = mac_address
        mac_address = mac_address.replace(":", "-")

        prefix = "\\Device\\Tcpip_"
        if sys.platform == 'win32':
            cmd = "getmac"
        else:
            raise NotImplementedError(
                "The functionality is supported on Windows only")

        try:
            output = subprocess.check_output(
                cmd, stderr=subprocess.STDOUT, shell=True)
        except subprocess.CalledProcessError as e:
            log.error(e.output)
            raise e
        output = output.split("\n")

        for s in output:
            if s.find(mac_address) != -1:
                break

        guid = s.split()[1]

        if guid.lower().find("disconnected") != -1:
            log.error("Device with MAC {} is disconnected.".format(mac_original))
            raise Exception("Fix device with MAC {}!".format(mac_original))
        else:
            if guid.startswith(prefix) or once:
                return guid[len(prefix):]
            else:
                log.info("No GUID was found by MAC {}. Trying to get it "
                         "once more. Sleeping 10 seconds...".format(mac_original))
                time.sleep(10)
                return self.get_guid_by_mac(mac_original, True)

    def get_guid_by_port(self):
        dev = get_wmi_network_adapter(self.port)
        if dev.NetConnectionStatus == 2:
            return dev.GUID
        else:
            raise Exception("No GUID was found")

    def get_wmi_device_id(self):
        return get_wmi_device_id(self.port)

    def get_wmi_device_driver_name(self):
        return get_wmi_device_driver_name(self.port)

    def get_wmi_device_driver_version(self):
        return get_wmi_device_driver_version(self.port)

    def get_advanced_property(self, name):
        if sys.platform == 'win32':
            return self.get_advanced_prop_win(name)
        else:
            raise NotImplementedError("The functionality is not implemented")

    def check_duplex(self):
        if 'linux' in sys.platform.lower():
            ethtool_inf = Command(cmd="sudo ethtool {}".format(self.iface)).run_join()
            if ethtool_inf["returncode"] != 0:
                raise Exception("Failed to get duplex")
            for line in ethtool_inf["output"]:
                if "Duplex" in line:
                    if "Half" in line:
                        return "half"
                    elif "Duplex" in line:
                        return "duplex"
                    else:
                        raise Exception("Unknown duplex")
            else:
                raise Exception("Failed to get duplex")
        else:
            pass

    def get_advanced_prop_win(self, name):
        import _winreg
        network_adapter = get_wmi_network_adapter(self.port)
        subkey = "{0:04d}".format(network_adapter.Index)
        internal_k = r"SYSTEM\ControlSet001\Control\Class"
        internal_k += r"\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{}".format(subkey)
        log.info("Trying to open key {}".format(internal_k))
        key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, internal_k, 0, _winreg.KEY_ALL_ACCESS)
        if network_adapter.ServiceName in AQUANTIA_SERVICE_NAMES:
            log.info("Trying to obtain value {} from key {}".format(name, internal_k))
            value = _winreg.QueryValueEx(key, name)[0]
        else:
            raise ReferenceError("Wrong adapter type detected: {}".format(network_adapter.ServiceName))
        if key is not None:
            _winreg.CloseKey(key)
        return value

    def get_mtu(self):
        if sys.platform == "win32":
            return self.get_mtu_win()
        elif sys.platform == "darwin":
            return self.get_mtu_macos()
        elif "freebsd" in sys.platform:
            return self.get_mtu_freebsd()
        else:
            return self.get_mtu_linux()

    def get_mtu_win(self):
        import _winreg
        network_adapter = get_wmi_network_adapter(self.port)
        subkey = "{:04d}".format(network_adapter.Index)

        internal_k = r"SYSTEM\ControlSet001\Control\Class"
        internal_k += r"\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{}".format(subkey)

        log.info("Trying to open key {}".format(internal_k))
        key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, internal_k, 0, _winreg.KEY_ALL_ACCESS)

        try:
            if network_adapter.ServiceName in AQUANTIA_SERVICE_NAMES:
                val = _winreg.QueryValueEx(key, "*JumboPacket")[0]
                val = MTU_MAP_WIN.keys()[MTU_MAP_WIN.values().index(int(val))]
            else:
                raise Exception("Wrong adapter type detected: {}".format(network_adapter.ServiceName))
        finally:
            if key is not None:
                _winreg.CloseKey(key)

        return val

    def get_mtu_linux(self):
        cmd = "sudo ip link show {} | grep mtu".format(self.iface)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            raise Exception("Failed to get MTU")
        re_mtu = re.compile(".* mtu ([0-9]+).*", re.DOTALL)
        m = re_mtu.search(res["output"][0])
        if m is not None:
            current_mtu = int(m.group(1))
        else:
            raise Exception("Cannot find MTU")

        if current_mtu == 16334 and ops.is_linux():
            current_mtu = current_mtu + 14

        if current_mtu == 1500:
            return MTU_1500

        return MTU_MAP_LIN.keys()[MTU_MAP_LIN.values().index(int(current_mtu))]

    def set_mtu(self, mtu):
        log.info("Setting MTU {}".format(mtu))
        if sys.platform == "win32":
            self.set_mtu_win(mtu)
        elif sys.platform == "darwin":
            self.set_mtu_macos(mtu)
        elif "freebsd" in sys.platform:
            self.set_mtu_freebsd(mtu)
        else:
            self.set_mtu_linux(mtu)

    def set_mtu_win(self, mtu):
        import _winreg
        network_adapter = get_wmi_network_adapter(self.port)
        subkey = "{:04d}".format(network_adapter.Index)

        internal_k = r"SYSTEM\ControlSet001\Control\Class"
        internal_k += r"\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{}".format(subkey)

        log.info("Trying to open key {}".format(internal_k))
        key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, internal_k, 0, _winreg.KEY_ALL_ACCESS)

        try:
            if network_adapter.ServiceName in AQUANTIA_SERVICE_NAMES:
                val = str(MTU_MAP_WIN[mtu])
                log.info("Setting value {} to *JumboPacket in key {}".format(val, internal_k))
                _winreg.SetValueEx(key, "*JumboPacket", 0, _winreg.REG_SZ, val)
            else:
                raise Exception("Wrong adapter type detected: {}".format(network_adapter.ServiceName))
        finally:
            if key is not None:
                _winreg.CloseKey(key)

        self.set_link_down_win()
        self.set_link_up_win()
        # Workaround for Fiji
        # TODO: debut why need small timeout for Fiji between enable and next disable of device
        if "usb" in self.port:
            time.sleep(5)

    def set_mtu_linux(self, mtu):
        if mtu in MTUS:
            val = MTU_MAP_LIN[mtu]
        else:
            val = mtu

        if val == 16348:
            val = val - 14

        cmd = "sudo ip link set dev {} mtu {}".format(self.iface, val)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            raise Exception("Failed to set MTU {}".format(mtu))

    def set_mtu_freebsd(self, mtu):
        if mtu in MTUS:
            val = MTU_MAP_LIN[mtu]
        else:
            val = mtu
        if val == 16348:
            val = val - 14

        iface = get_freebsd_network_adapter_name(self.port)
        cmd = "sudo ifconfig {} mtu {}".format(iface, val)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            raise Exception("Failed to set MTU {}".format(mtu))

    def get_mtu_freebsd(self):
        iface = get_freebsd_network_adapter_name(self.port)
        cmd = "sudo ifconfig {} | grep mtu | awk '{print $6}'".format(iface)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            raise Exception("Failed to get MTU")

        re_mtu = re.compile("^Active MTU: ([0-9]+).*", re.DOTALL)
        m = re_mtu.search(res["output"][0])
        if m is not None:
            current_mtu = int(m.group(1))
        else:
            raise Exception("Cannot obtain MTU for iface {}".format(iface))

        if current_mtu == 16334:
            current_mtu = current_mtu + 14

        if current_mtu == 1500:
            return MTU_1500

        return MTU_MAP_LIN.keys()[MTU_MAP_LIN.values().index(int(current_mtu))]

    def set_mtu_macos(self, mtu):
        if mtu in MTUS:
            val = MTU_MAP_LIN[mtu]
        else:
            val = mtu
        if val == 16348:
            val = val - 14

        iface = get_macos_network_adapter_name(self.port)
        cmd = "sudo ifconfig {} mtu {}".format(iface, val)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            raise Exception("Failed to set MTU {}".format(mtu))

    def get_mtu_macos(self):
        iface = get_macos_network_adapter_name(self.port)
        cmd = "sudo networksetup -getMTU {}".format(iface)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            raise Exception("Failed to get MTU")

        re_mtu = re.compile("^Active MTU: ([0-9]+).*", re.DOTALL)
        m = re_mtu.search(res["output"][0])
        if m is not None:
            current_mtu = int(m.group(1))
        else:
            raise Exception("Cannot obtain MTU for iface {}".format(iface))

        if current_mtu == 16334:
            current_mtu = current_mtu + 14

        if current_mtu == 1500:
            return MTU_1500

        return MTU_MAP_LIN.keys()[MTU_MAP_LIN.values().index(int(current_mtu))]

    def set_media_options(self, options_to_set=["flow-control", "full-duplex", "energy-efficient-ethernet"]):
        log.info("Setting media options {}".format(options_to_set))
        if "freebsd" in sys.platform:
            if "flow-control" in options_to_set:
                options_to_set.remove("flow-control")
                options_to_set.extend(['rxpause', 'txpause'])
            known_media_opts = ["full-duplex", "half-duplex", "rxpause", "txpause"]
        else:
            known_media_opts = ["full-duplex", "half-duplex", "flow-control", "energy-efficient-ethernet"]

        for opt in options_to_set:
            assert opt in known_media_opts
        assert len(options_to_set) > 0

        if sys.platform == "win32":
            # "full-duplex" not implemented

            if "flow-control" in options_to_set:
                self.set_advanced_property("*FlowControl", OFFLOADS_STATE_TX_RX)
            else:
                self.set_advanced_property("*FlowControl", OFFLOADS_STATE_DSBL)

            if "energy-efficient-ethernet" in options_to_set:
                self.set_advanced_prop_win("*EEE", "1")
            else:
                self.set_advanced_prop_win("*EEE", "0")

            self.set_link_down()
            self.set_link_up()

        elif sys.platform == "darwin":
            iface = get_macos_network_adapter_name(self.port)

            cmd = "sudo ifconfig {}".format(iface)
            for opt in options_to_set:
                cmd += " mediaopt {}".format(opt)
            for opt in known_media_opts:
                if opt not in options_to_set:
                    cmd += " -mediaopt {}".format(opt)
            res = Command(cmd=cmd).run_join(5)
            if res["returncode"] != 0:
                raise Exception("Failed to set media options")
            time.sleep(5)  # TODO: is this sleep needed???
        elif "freebsd" in sys.platform:
            iface = get_freebsd_network_adapter_name(self.port)

            self.set_link_down()

            cmd = "sudo ifconfig {}".format(iface)
            for opt in options_to_set:
                if opt in known_media_opts:
                    cmd += " mediaopt {}".format(opt)
            for opt in known_media_opts:
                if opt not in options_to_set:
                    cmd += " -mediaopt {}".format(opt)
            res = Command(cmd=cmd).run_join(5)
            if res["returncode"] != 0:
                raise Exception("Failed to set media options")
            self.set_link_up()
            time.sleep(5)  # TODO: is this sleep needed???
        else:
            # duplex change is not supported

            if not self.port.startswith("usb"):
                val = "on" if "flow-control" in options_to_set else "off"
                cmd = "sudo ethtool --pause {} tx {} rx {}".format(self.iface, val, val)
                res = Command(cmd=cmd).wait(3)
                if res["returncode"] != 0:
                    if "no pause parameters changed, aborting" not in res["output"][-1]:
                        raise Exception("Failed to set media options")
                cmd = "sudo ethtool --set-eee {} eee {}".format(
                    self.iface, "on" if "energy-efficient-ethernet" in options_to_set else "off")
                res = Command(cmd=cmd).run_join(3)
                if res["returncode"] != 0:
                    raise Exception("Failed to set media options")

    def get_media_options(self, options_to_check=["flow-control", "full-duplex", "energy-efficient-ethernet"]):
        if sys.platform == "win32":
            pass
        elif "freebsd" in sys.platform:
            iface = get_freebsd_network_adapter_name(self.port)
            res = Command(cmd="ifconfig {} | grep media".format(iface)).run_join(5)
            if res["returncode"] != 0:
                raise Exception()

            re_media = re.compile(".*media: .*[bB]ase.* \<([a-z,\-]+)\>.*", re.DOTALL)
            for line in res["output"]:
                m = re_media.match(line)
                if m is not None:
                    medias = m.group(1)
                    return medias.split(",")
            raise Exception("Failed to obtain media information")
        elif sys.platform == "darwin":
            iface = get_macos_network_adapter_name(self.port)
            res = Command(cmd="ifconfig {} | grep media".format(iface)).run_join(5)
            if res["returncode"] != 0:
                raise Exception()

            re_media = re.compile(".*media: .*[Bb]ase.* \<([a-z,\-]+)\>.*", re.DOTALL)
            for line in res["output"]:
                m = re_media.match(line)
                if m is not None:
                    medias = m.group(1)
                    return medias.split(",")
            raise Exception("Failed to obtain media information")
        else:
            medias = []
            if "full-duplex" in options_to_check or "half-duplex" in options_to_check:
                res = Command(cmd="sudo ethtool {}".format(self.iface)).run_join(3)
                if res["returncode"] != 0:
                    raise Exception("Failed to check duplex")
                for line in res["output"]:
                    if "Duplex: Full" in line:
                        medias.append("full-duplex")
                    elif "Duplex: Half" in line:
                        medias.append("half-duplex")

            if "flow-control" in options_to_check:
                res = Command(cmd="sudo ethtool -a {}".format(self.iface)).run_join(3)
                if res["returncode"] != 0:
                    raise Exception("Failed to check flow-control")
                rx = False
                tx = False
                for line in res["output"]:
                    if "RX" in line and "on" in line:
                        rx = True
                    if "TX" in line and "on" in line:
                        tx = True
                if rx and tx:
                    medias.append("flow-control")

            if "energy-efficient-ethernet" in options_to_check:
                res = Command(cmd="sudo ethtool --show-eee {}".format(self.iface)).run_join(3)
                if res["returncode"] != 0:
                    raise Exception("Failed to check EEE options")
                for line in res["output"]:
                    if "EEE status: enabled - active" in line:
                        medias.append("energy-efficient-ethernet")

            return medias

    def check_media_options(self, options):
        log.info("Getting media options {}".format(options))
        known_media_opts = ["full-duplex", "half-duplex", "flow-control", "energy-efficient-ethernet"]

        if sys.platform == "win32":
            pass
        elif sys.platform == "darwin":
            iface = get_macos_network_adapter_name(self.port)
            res = Command(cmd="ifconfig {} | grep media".format(iface)).run_join(5)
            if res["returncode"] != 0:
                raise Exception()

            re_media = re.compile(".*media: .*[Bb]ase.* \<([a-z,\-]+)\>.*", re.DOTALL)
            for line in res["output"]:
                m = re_media.match(line)
                if m is not None:
                    medias = m.group(1)
                    for opt in options:
                        # TODO: bug in Frank's driver?!
                        if opt == "flow-control":
                            continue
                        if opt not in medias:
                            raise Exception("Media option {} is not set".format(opt))
                    for opt in known_media_opts:
                        if opt not in options:
                            if opt in medias:
                                raise Exception("Media option {} is set but not requested".format(opt))
                    return
            raise Exception("Failed to obtain media information")
        else:
            medias = self.get_media_options()
            for opt in options:
                if opt not in medias:
                    raise Exception("Media option {} is not set".format(opt))
            for opt in medias:
                if opt not in options:
                    raise Exception("Media option {} is set but not requested".format(opt))

    def set_advanced_property(self, name, value):
        log.info("Setting advanced property {} to {}".format(name, value))
        if sys.platform == 'win32':
            value_map = {
                "Enable": "1",
                "Disable": "0",
                "Forced": "2",
            }

            if name == "Downshift" and value != "Disable":
                if 0 <= int(value) <= 7:
                    value_index = str(value)
                else:
                    raise Exception("Invalid value, possible values 0 to 7")

            elif name == "ITR":
                value_map = {
                    "off": "0",
                    "low": "200",
                    "extreme": "2000",
                    "medium": "488",
                    "adaptive": "65535",
                    "high": "950"
                }
                value_index = value_map[value]
            elif name in ["*FlowControl", "*TCPUDPChecksumOffloadIPv4",
                          "*TCPUDPChecksumOffloadIPv6", "*IPChecksumOffloadIPv4",
                          "*TCPChecksumOffloadIPv4", "*UDPChecksumOffloadIPv4",
                          "*TCPChecksumOffloadIPv6", "*UDPChecksumOffloadIPv6"]:
                value_map = {OFFLOADS_STATE_DSBL: "0",
                             OFFLOADS_STATE_TX: "1",
                             OFFLOADS_STATE_RX: "2",
                             OFFLOADS_STATE_TX_RX: "3",
                             OFFLOADS_STATE_ENBL: "3"
                             }
                value_index = value_map[value]
            elif name in ["*TransmitBuffers", "*ReceiveBuffers"]:
                value_index = str(value)
            elif name in ["*PriorityVLANTag", "VlanID"]:
                # PriorityVLANTag
                # 0 - Priority & VLAN Disabled
                # 1 - Packet Priority Enabled
                # 2 - VLAN Enabled
                # 3 - Priority & VLAN Enabled
                value_index = value
            elif value.isdigit():
                value_index = value
            else:
                value_index = value_map[value]
            return self.set_advanced_prop_win(name, value_index)

        elif 'linux' in sys.platform.lower():
            pass
        else:
            if name == "*FlowControl":
                if value == OFFLOADS_STATE_TX_RX:
                    options = ["full-duplex", "flow-control", "energy-efficient-ethernet"]
                elif value == OFFLOADS_STATE_DSBL:
                    options = ["full-duplex", "energy-efficient-ethernet"]
            return self.set_media_options(options)

    def set_wol_settings(self, on_magic=False, on_pattern=False, on_ping=False, on_link=False, from_power_off=False):
        if sys.platform == 'win32':
            self.set_advanced_prop_win("*WakeOnMagicPacket", "1" if on_magic else "0")
            self.set_advanced_prop_win("*WakeOnPattern", "1" if on_pattern else "0")
            self.set_advanced_prop_win("WakeOnPing", "1" if on_ping else "0")
            if "usb" not in self.port:
                self.set_advanced_prop_win("WakeOnLink", "1" if on_link else "0")
            else:
                self.set_advanced_prop_win("WakeOnLink", "2" if on_link else "0")
            self.set_advanced_prop_win("WakeFromPowerOff", "1" if from_power_off else "0")

            self.set_link_state(LINK_STATE_DOWN)
            self.set_link_state(LINK_STATE_UP)
            self.wait_link_up()

        elif 'linux' in sys.platform.lower():
            val = ''
            if on_magic:
                val += "g"
            if on_link:
                val += "p"
            cmd = "sudo ethtool -s {} wol {}".format(self.iface, val if val is not '' else "d")
            res = Command(cmd=cmd).wait(3)
            if res["returncode"] != 0:
                if "not setting wol" not in res["output"][-1]:
                    raise Exception("Failed to set media options")
        else:
            raise NotImplementedError()

    def set_interrupt(self, int_type, number):
        log.info("Setting MSI Supported {}".format(int_type))
        if sys.platform == 'win32':
            if int(int_type) == int(INTERRUPT_TYPE_LEGACY):
                self.set_interrupt_win("MSISupported", INTERRUPT_TYPE_LEGACY)
                self.set_interrupt_win("MessageNumberLimit", number)
            elif int(int_type) == int(INTERRUPT_TYPE_MSI):
                self.set_interrupt_win("MSISupported", INTERRUPT_TYPE_MSI)
                self.set_interrupt_win("MessageNumberLimit", number)
        else:
            raise NotImplementedError("The functionality is not implemented")

    def set_interrupt_win(self, name, value):
        import _winreg
        network_adapter = get_wmi_network_adapter(self.port)
        ids = network_adapter.PNPDeviceID[4:]
        internal_k = r"SYSTEM\CurrentControlSet\Enum\PCI\{}\Device Parameters\Interrupt Management" \
                     r"\MessageSignaledInterruptProperties".format(ids)
        log.info("Trying to open key {}".format(internal_k))
        key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, internal_k, 0, _winreg.KEY_ALL_ACCESS)
        if network_adapter.ServiceName in AQUANTIA_SERVICE_NAMES:
            log.info("Setting value {} to {} in key {}".format(value, name, internal_k))
            _winreg.SetValueEx(key, name, 0, _winreg.REG_DWORD, int(value))
        else:
            raise ReferenceError("Wrong adapter type detected: {}".format(network_adapter.ServiceName))
        if key is not None:
            _winreg.CloseKey(key)

    def set_advanced_prop_win(self, name, value_index):
        import _winreg
        network_adapter = get_wmi_network_adapter(self.port)
        subkey = "{:04d}".format(network_adapter.Index)
        internal_k = r"SYSTEM\ControlSet001\Control\Class"
        internal_k += r"\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{}".format(subkey)
        log.info("Trying to open key {}".format(internal_k))
        key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, internal_k, 0, _winreg.KEY_ALL_ACCESS)
        if network_adapter.ServiceName in AQUANTIA_SERVICE_NAMES:
            log.info("Setting value {} to {} in key {}".format(value_index, name, internal_k))
            _winreg.SetValueEx(key, name, 0, _winreg.REG_SZ, value_index)
        else:
            raise ReferenceError("Wrong adapter type detected: {}".format(network_adapter.ServiceName))
        if key is not None:
            _winreg.CloseKey(key)

    def set_flow_control(self, direction):
        known_direction = [OFFLOADS_STATE_TX, OFFLOADS_STATE_RX, OFFLOADS_STATE_TX_RX, OFFLOADS_STATE_DSBL]
        if direction not in known_direction:
            raise Exception()

        if ops.is_windows():
            self.set_advanced_property("*FlowControl", direction)

        elif ops.is_linux():
            if direction == OFFLOADS_STATE_TX_RX:
                tx = "on"
                rx = "on"
            elif direction == OFFLOADS_STATE_TX:
                tx = "on"
                rx = "off"
            elif direction == OFFLOADS_STATE_RX:
                tx = "off"
                rx = "on"
            else:
                tx = "off"
                rx = "off"
            cmd = "sudo ethtool --pause {} tx {} rx {}".format(self.iface, tx, rx)
            res = Command(cmd=cmd).run_join(5)
            if res["returncode"] != 0:
                p = re.compile('(.*)no (.*)parameters changed, aborting(.*)')
                if not any(p.match(line) for line in res["output"]):
                    raise Exception("Failed to set flow control")

    def get_flow_control(self):
        if ops.is_linux():
            rx = None
            tx = None
            cmd = "sudo ethtool --show-pause {}".format(self.iface)
            res = Command(cmd=cmd).run_join(5)
            if res["returncode"] != 0:
                raise Exception("Failed to set flow control")
            for line in res["output"]:
                if "RX:" in line:
                    if "off" in line:
                        rx = "off"
                    else:
                        rx = "on"
                if "TX:" in line:
                    if "off" in line:
                        tx = "off"
                    else:
                        tx = "on"
            if rx is "off" and tx is "on":
                log.info("Flow Control: {}".format(OFFLOADS_STATE_TX))
                return OFFLOADS_STATE_TX
            elif tx is "off" and rx is "on":
                log.info("Flow Control: {}".format(OFFLOADS_STATE_RX))
                return OFFLOADS_STATE_RX
            elif tx is "on" and rx is "on":
                log.info("Flow Control: {}".format(OFFLOADS_STATE_TX_RX))
                return OFFLOADS_STATE_TX_RX
            else:
                log.info("Flow Control: {}".format(OFFLOADS_STATE_DSBL))
                return OFFLOADS_STATE_DSBL
        elif ops.is_windows():
            value_map = {0: OFFLOADS_STATE_DSBL,
                         1: OFFLOADS_STATE_TX,
                         2: OFFLOADS_STATE_RX,
                         3: OFFLOADS_STATE_TX_RX
                         }
            val = self.get_advanced_property("*FlowControl")
            value = value_map[int(val)]
            log.info("Flow Control: {}".format(value))
            return value
        else:
            raise NotImplemented()

    def set_interrupt_type(self, int_type, number=1):
        log.info("Setting MSI Supported {}".format(int_type))
        self.set_interrupt(int_type, number)

    def set_power_mgmt_settings(self, only_magic_wake=False, allow_wake=False, allow_power_save=False):
        log.info("Setting power management settings:")
        log.info("Only allow a magic packet to wake the computer = {}".format(only_magic_wake))
        log.info("Allow this device to wake the computer = {}".format(allow_wake))
        log.info("Allow the computer to turn off this device to save power = {}".format(allow_power_save))
        assert only_magic_wake in [False, True]
        assert allow_wake in [False, True]
        assert allow_power_save in [False, True]

        if sys.platform == 'win32':
            return self.set_power_mgmt_settings_win(only_magic_wake, allow_wake, allow_power_save)
        elif 'linux' in sys.platform.lower():
            # TODO: we need refactor this
            # TODO: only disable is supported
            if not allow_power_save:
                log.info("Disabling WOL on interface {}".format(self.iface))
                res = Command(cmd="sudo ethtool -s {} wol {}".format(self.iface, "d")).wait(10)
                if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                    raise Exception("Failed to disable WOL")
            elif only_magic_wake and allow_power_save:
                log.info("Enabling WOL by magic packet on interface {}".format(self.iface))
                res = Command(cmd="sudo ethtool -s {} wol {}".format(self.iface, "g")).wait(10)
                if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                    raise Exception("Failed to enable WOL")

        elif sys.platform == "darwin":
            log.info("Put WOL on macOS to {}".format(only_magic_wake))
            res = Command(cmd="sudo pmset womp {}".format(0 if not only_magic_wake else 1)).wait(10)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to put WOL on macOS to {}".format(only_magic_wake))
        else:
            raise NotImplementedError("The functionality is not implemented")

    def set_power_mgmt_settings_win(self, magic_packet_val, power_wake_val, power_enable_val):
        power_wake_enables = wmi.WMI(namespace='wmi').MSPower_DeviceWakeEnable()
        magic_packet_onlys = wmi.WMI(
            namespace='wmi').MSNdis_DeviceWakeOnMagicPacketOnly()
        power_enables = wmi.WMI(namespace='wmi').MSPower_DeviceEnable()

        # Workaround for Fiji
        if "usb" not in self.port:
            nic_id = get_wmi_pnp_devices(self.port)[0]
        else:
            nic_ids = get_wmi_pnp_devices(self.port)
            nic_id = [nic for nic in nic_ids if nic.Service in AQUANTIA_SERVICE_NAMES_USB][0]

        is_power_wake_set, is_magic_packet_set, is_power_enable_set = [False] * 3

        for pwr_wake_enable in power_wake_enables:
            if nic_id.PNPDeviceID.lower() in pwr_wake_enable.InstanceName.lower():
                pwr_wake_enable.Enable = power_wake_val
                pwr_wake_enable.Put_
                is_power_wake_set = True
                break

        for magic_pkt_only in magic_packet_onlys:
            if nic_id.PNPDeviceID.lower() in magic_pkt_only.InstanceName.lower():
                magic_pkt_only.EnableWakeOnMagicPacketOnly = magic_packet_val
                magic_pkt_only.Put_
                is_magic_packet_set = True
                break

        for power_enable in power_enables:
            if nic_id.PNPDeviceID.lower() in power_enable.InstanceName.lower():
                power_enable.Enable = power_enable_val
                power_enable.Put_
                is_power_enable_set = True
                break

        if not (is_power_wake_set and is_magic_packet_set and is_power_enable_set):
            raise Exception("Error while setting power management")

    def bind_ipv6(self):
        log.info("Binding IPv6 on port {}".format(self.port))
        if sys.platform != "win32":
            raise NotImplementedError()
        network_adapter = get_wmi_network_adapter(self.port)
        cmd = 'powershell "Enable-NetAdapterBinding -Name \'{}\' -DisplayName' \
              ' \'Internet Protocol Version 6 (TCP/IPv6)\''.format(network_adapter.NetConnectionID)
        res = Command(cmd=cmd).run_join(5)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to bind IPv6")

    def unbind_ipv6(self):
        log.info("Unbinding IPv6 from port {}".format(self.port))
        if sys.platform != "win32":
            raise NotImplementedError()

        network_adapter = get_wmi_network_adapter(self.port)
        cmd = 'powershell "Disable-NetAdapterBinding -Name \'{}\' -DisplayName' \
              ' \'Internet Protocol Version 6 (TCP/IPv6)\'"'.format(network_adapter.NetConnectionID)
        res = Command(cmd=cmd).run_join(5)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to unbind IPv6")

    def get_conn_name(self):
        log.info("Getting connection name for port {}".format(self.port))
        return get_conn_name(self.port)

    def manage_offload_linux(self, offload, state):
        m = {
            OFFLOADS_STATE_DSBL: OFFLOADS_STATE_OFF,
            OFFLOADS_STATE_ENBL: OFFLOADS_STATE_ON
        }

        if state in m:
            state = m[state]
        cmd = "sudo ethtool -K {} {} {}".format(self.iface, offload, state)
        res = Command(cmd=cmd).run_join(5)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to manage offloads")

    def manage_offload_mac(self, offload, state):
        log.info("There is no way to manage offloads on MAC, so skip it")

    def manage_offload_freebsd(self, offload, state):
        m = {
            OFFLOADS_STATE_DSBL: "-",
            OFFLOADS_STATE_ENBL: "",
            OFFLOADS_STATE_ON: "",
            OFFLOADS_STATE_OFF: "-"
        }

        if state in m:
            state = m[state]
        cmd = "sudo ifconfig {} {}{}".format(self.iface, state, offload)
        res = Command(cmd=cmd).run_join(5)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to manage offloads")

    def manage_offloads(self, offload, state):
        log.info("Setting offload {} for port {} to state {}".format(offload, self.port, state))
        if ops.is_linux():
            return self.manage_offload_linux(offload, state)
        elif ops.is_windows():
            return self.set_advanced_property(offload, state)
        elif ops.is_freebsd():
            return self.manage_offload_freebsd(offload, state)
        else:
            return self.manage_offload_mac(offload, state)

    def is_device_present(self):
        bus, dev, func = map(lambda x: int(x), get_bus_dev_func(self.port))
        if self.port.startswith("pci"):
            if sys.platform == "darwin":
                res = Command(cmd="ioreg -c IOPCIDevice -x | grep {}:0:0".format(bus)).run()
            else:
                res = Command(cmd="lspci | grep {:02x}:{:02x}".format(bus, dev)).run()
            if res["returncode"] not in [0, 1]:
                raise Exception("Failed to check PCI devices")
        elif self.port.startswith("usb"):
            if ops.is_windows():
                res = Command(cmd="listusb | grep \"path: {}\"".format(func)).run()
            elif ops.is_mac():
                # Workaround for pactool -l
                res = Command(cmd="sudo lsusb | grep -i {}".format("pacific")).run()
            else:
                res = Command(cmd="sudo pactool -l | grep -i {:X}:{:X}".format(dev, func)).run()
        else:
            raise Exception("Got wrong port format: {}".format(self.port))
        return len(res["output"]) > 0

    def create_vlan_iface(self, vlan_id):
        if sys.platform == "win32":
            raise NotImplementedError()
        elif sys.platform == "darwin" or "freebsd" in sys.platform:
            if "freebsd" in sys.platform:
                iface = get_freebsd_network_adapter_name(self.port)
            else:
                iface = get_macos_network_adapter_name(self.port)

            vlan_str = "vlan{}".format(vlan_id)
            res_create = Command(cmd="sudo ifconfig {} create".format(vlan_str)).wait(5)
            time.sleep(2)
            res_config = Command(cmd="sudo ifconfig {} vlan {} vlandev {}".format(vlan_str, vlan_id, iface)).wait(5)

            for res in [res_create, res_config]:
                if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                    raise Exception("Failed to create vlan interface")
        else:
            cmd = "sudo ip link add link {} name {}.{} type vlan id {}".format(self.iface, self.iface, vlan_id, vlan_id)
            res = Command(cmd=cmd).wait(5)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to create vlan interface")

    def delete_vlan_iface(self, vlan_id):
        if sys.platform == "win32":
            raise NotImplementedError()
        elif sys.platform == "darwin" or "freebsd" in sys.platform:
            res = Command(cmd="sudo ifconfig vlan{} destroy".format(vlan_id)).wait(5)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to destroy vlan interface")
        else:
            cmd = "sudo ip link del dev {}.{}".format(self.iface, vlan_id)
            res = Command(cmd=cmd).wait(5)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to destroy vlan interface")

    def delete_macvlan_iface(self, macvlan):
        if 'linux' not in sys.platform.lower():
            raise NotImplementedError()
        else:
            cmd = "sudo ip link del {} link {}".format(macvlan, self.iface)
            res = Command(cmd=cmd).wait(5)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to delete macvlan interface")

    def delete_vlan_ifaces(self):
        if sys.platform == "win32":
            raise NotImplementedError()
        elif sys.platform == "darwin" or "freebsd" in sys.platform:
            if "freebsd" in sys.platform:
                iface = get_freebsd_network_adapter_name(self.port)
            else:
                iface = get_macos_network_adapter_name(self.port)
            res = Command(cmd="ifconfig | grep {} | grep vlan".format(iface)).wait(5)
            re_vlan_id = re.compile(".*vlan: ([0-9]+).*parent interface: {}.*".format(iface), re.DOTALL)

            for line in res["output"]:
                m = re_vlan_id.match(line)
                if m is not None:
                    vlan_id = m.group(1)
                    self.delete_vlan_iface(vlan_id)
        else:
            cmd = "ip a | grep {}".format(self.iface)
            res = Command(cmd=cmd).wait(5)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to obtain list of vlan interfaces")
            re_vlan_iface = re.compile(".*{}\.([0-9]+)@{}.*".format(self.iface, self.iface), re.DOTALL)
            for line in res["output"]:
                m = re_vlan_iface.match(line)
                if m is not None:
                    vlan_id = m.group(1)
                    self.delete_vlan_iface(vlan_id)

    def delete_macvlan_ifaces(self):
        if 'linux' not in sys.platform.lower():
            raise NotImplementedError()
        else:
            cmd = "ip a | grep {}".format(self.iface)
            res = Command(cmd=cmd).wait(5)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to obtain list of vlan interfaces")
            re_macvlan_iface = re.compile(".*: ([A-Za-z0-9]+)@{}.*".format(self.iface), re.DOTALL)
            for line in res["output"]:
                m = re_macvlan_iface.match(line)
                if m is not None:
                    macvlan = m.group(1)
                    self.delete_macvlan_iface(macvlan)

    def add_route(self, addr, mask_prefix, gw):
        ip_addr = ipaddress.ip_address(unicode(addr))
        if ip_addr.version == 6:
            cidr = mask_prefix
        else:
            cidr = sum([bin(int(x)).count("1") for x in mask_prefix.split(".")])

        if sys.platform == "win32":
            network_adapter = get_wmi_network_adapter(self.port).NetConnectionID
            cmd = "netsh interface ipv{} add route {}/{} \"{}\" {}".format(ip_addr.version, addr, cidr, network_adapter,
                                                                           gw)
            res = Command(cmd=cmd).run_join(5)
            if res["returncode"] != 0:
                raise Exception("Failed to add route to {}/{} with {}".format(addr, cidr, gw))
        elif sys.platform == "darwin":
            raise NotImplementedError()
        else:
            cmd = "sudo ip -{} route add {}/{} via {} dev {}".format(ip_addr.version, addr, cidr, gw, self.iface)
            res = Command(cmd=cmd).run_join(5)
            if res["returncode"] != 0:
                raise Exception("Failed to add route to {}/{} via {}".format(addr, cidr, gw))

    def del_ip_address(self, addr):
        ip_addr = ipaddress.ip_address(unicode(addr))

        if sys.platform == "win32":
            network_adapter = get_wmi_network_adapter(self.port)
            cmd = "netsh interface ipv{} delete address \"{}\" {} {}".format(
                ip_addr.version, network_adapter.NetConnectionID, addr, "gateway=all" if ip_addr.version == 4 else "")
            res = Command(cmd=cmd).run_join(10)
            if res["returncode"] != 0 and not any("Element not found" in line for line in res["output"]):
                raise Exception("Failed to delete IP {} from interface".format(addr))

        elif sys.platform == "darwin":
            raise NotImplementedError()
        else:
            if ip_addr.version == 6 and ip_addr.is_link_local:
                return True
            cmd = "sudo ip -{} addr del {} dev {}".format(ip_addr.version, addr, self.iface)
            res = Command(cmd=cmd).wait(5)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to delete IP {} from interface".format(addr))

    def get_ip_address(self, ipv=4):
        if sys.platform == 'win32':
            return self.get_ip_address_win(ipv)
        elif 'linux' in sys.platform.lower():
            return self.get_ip_address_linux(ipv)
        else:
            raise NotImplementedError("The functionality is not implemented")

    def get_ip_address_win(self, ipv):
        for i in range(3)[::-1]:
            try:
                network_adapter = get_wmi_network_adapter(self.port)

                network_adapter_cfg = None
                nic_configs = wmi.WMI().Win32_NetworkAdapterConfiguration()
                for nic_config in nic_configs:
                    if nic_config.InterfaceIndex == network_adapter.InterfaceIndex:
                        network_adapter_cfg = nic_config

                if not network_adapter_cfg:
                    log.warning("No network adapter configuration found! Attempts left: {}".format(i))
                    for nic_config in nic_configs:
                        log.info(nic_config)
                    raise Exception("Could not find NetworkAdapterConfiguration for "
                                    "InterfaceIndex {}".format(network_adapter.InterfaceIndex))
            except Exception as exc:
                if i == 0:  # last attempt
                    log.exception(exc)
                    raise exc
                else:
                    log.info('Sleeping 10 seconds...')
                    time.sleep(10)
                    continue

        if network_adapter_cfg.IPAddress:
            if ipv == 4:
                return [ip for ip in network_adapter_cfg.IPAddress if
                        ipaddress.ip_address(unicode(ip)).version == 4]
            elif ipv == 6:
                return [ip for ip in network_adapter_cfg.IPAddress if
                        ipaddress.ip_address(unicode(ip)).version == 6]

    def get_ip_address_linux(self, ipv):
        cmd_ipv = "sudo ip addr show {} | grep '\<inet{}\>' | awk \'{{ print $2 }}\' | awk -F '/' \'{{ print $1 }}\'".format(
            self.iface, "6" if ipv == 6 else "")
        res = Command(cmd=cmd_ipv).run()
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to get IP")
        if len(res['output']) == 0:
            log.info("IP not found")
            return None
        ip = res['output']
        return ip

    def set_promisc_mode(self, state):
        if sys.platform == "win32":
            raise NotImplementedError()
        elif sys.platform == "darwin":
            raise NotImplementedError()
        else:
            cmd = "sudo ip link set {} promisc".format(self.iface)
            if state == "Enable":
                cmd += " on"
            else:
                cmd += " off"
            res = Command(cmd=cmd).run_join(5)
            if res["returncode"] != 0:
                raise Exception("Failed to set Promiscuous Mode")

    def set_buffer_size_linux(self, rx_size=None, tx_size=None):
        cmd = "sudo ethtool -G {}".format(self.iface)
        if rx_size is not None:
            cmd += " rx {}".format(rx_size)
            log.info("Setting rx buffers sieze {}".format(rx_size))
        if tx_size is not None:
            cmd += " tx {}".format(tx_size)
            log.info("Setting tx buffers sieze {}".format(tx_size))
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0:
            result = False
            for line in res["output"]:
                if "no ring parameters changed, aborting" in line:
                    result = True
            if not result:
                raise Exception("Failed to set buffers size")

    def set_buffer_size_windows(self, rx_size=None, tx_size=None):
        if rx_size is not None:
            self.set_advanced_property("*ReceiveBuffers", rx_size)
            log.info("Setting rx buffers sieze {}".format(rx_size))
        if tx_size is not None:
            self.set_advanced_property("*TransmitBuffers", tx_size)
            log.info("Setting tx buffers sieze {}".format(tx_size))

    def set_buffer_size(self, rx_size=None, tx_size=None):
        if rx_size is None and tx_size is None:
            raise Exception("At least one of the buffers must be specified")
        if sys.platform == 'win32':
            self.set_buffer_size_windows(rx_size, tx_size)
        elif 'linux' in sys.platform.lower():
            self.set_buffer_size_linux(rx_size, tx_size)
        else:
            raise NotImplementedError("The functionality is not implemented")

    def get_advertised_link_speeds_linux(self):
        speed_map = {
            "10": LINK_SPEED_10M,
            "100": LINK_SPEED_100M,
            "1000": LINK_SPEED_1G,
            "2500": LINK_SPEED_2_5G,
            "5000": LINK_SPEED_5G,
            "10000": LINK_SPEED_10G,
        }
        speeds = []
        cmd = "sudo ethtool %s" % self.iface
        internal_output = subprocess.check_output(cmd, shell=True).replace("\t",
                                                                           "    ")
        root_key = "Settings for {}".format(self.iface)
        child_key = "Advertised link modes"
        internal_speeds = yaml.load(internal_output)[root_key][child_key].split()
        for internal_speed in internal_speeds:
            internal_speed = re.sub("[^0-9]", "", internal_speed)
            speeds.append(speed_map[internal_speed])
        child_key = "Advertised auto-negotiation"
        autoneg = yaml.load(internal_output)[root_key][child_key]
        if autoneg:
            speeds.append(LINK_SPEED_AUTO)
        return speeds

    def get_advertised_link_speeds(self):
        if sys.platform == "win32":
            raise NotImplementedError("The functionality is not implemented")
        elif "linux" in sys.platform:
            return self.get_advertised_link_speeds_linux()


sif_mode_map = {
    # mask, shift
    LINK_SPEED_10G: (0x0000000f, 0),
    LINK_SPEED_5G: (0x000000f0, 4),
    LINK_SPEED_2_5G: (0x00000f00, 8),
    LINK_SPEED_1G: (0x0000f000, 12),
    LINK_SPEED_100M: (0x000f0000, 16)
}

sif_mode_to_mac_val_map = {
    MII_MODE_USX: 0x03,
    MII_MODE_USX_DIV2: 0xC,
    MII_MODE_XFI: 0x02,
    MII_MODE_XFI_DIV2: 0x0B,
    MII_MODE_OCSGMII: 0x0A,
    MII_MODE_SGMII: 0x06
}

mac_val_to_sif_mode_map = {
    0x03: MII_MODE_USX,
    0x0C: MII_MODE_USX_DIV2,
    0x02: MII_MODE_XFI,
    0x0B: MII_MODE_XFI_DIV2,
    0x0A: MII_MODE_OCSGMII,
    0x06: MII_MODE_SGMII
}


def get_sif_mode_prov_val_mac(tool):
    stats_addr = tool.readreg(0x360)
    settings_address = tool.readmem(stats_addr + FWStatistics.SETTINGS_ADDRESS_OFS, 4)[0]
    sif_mode = tool.readmem(settings_address + FWSettings.DAC_CABLE_SERDES_MODES_OFS, 4)[0]
    return sif_mode


def get_sif_mode_mac(tool, speed):
    sif_mode = get_sif_mode_prov_val_mac(tool)

    mask, shift = sif_mode_map[speed]
    prov_val = (sif_mode & mask) >> shift
    return mac_val_to_sif_mode_map[prov_val]


def set_sif_mode_mac(tool, speed, mode):
    sif_mode = get_sif_mode_prov_val_mac(tool)

    mask, shift = sif_mode_map[speed]
    sif_mode &= ~mask

    # for complicated mode
    if mode == MII_MODE_XFI_SGMII:
        mode = MII_MODE_SGMII if speed == LINK_SPEED_100M or speed == LINK_SPEED_1G else MII_MODE_XFI

    sif_mode |= sif_mode_to_mac_val_map[mode] << shift

    SettingsMemory.write_dword(tool, FWSettings.DAC_CABLE_SERDES_MODES_OFS, sif_mode)


class IfconfigLocalWithSeparatePhy(IfconfigLocal):
    LINK_SPEED_TO_PHY_CONTROL_SPEED_MAP = {
        LINK_SPEED_100M: "100 M",
        LINK_SPEED_1G: "1 G",
        LINK_SPEED_2_5G: "2.5G Base-T",
        LINK_SPEED_5G: "5G Base-T",
        LINK_SPEED_10G: "10 G"
    }

    def __init__(self, **kwargs):
        super(IfconfigLocalWithSeparatePhy, self).__init__(**kwargs)
        from atltoolper import AtlTool

        self.phy_control = kwargs["phy_control"]
        self.mii = kwargs.get("mii", MII_MODE_XFI)
        self.mac_atltool = AtlTool(port=self.port)

    def set_link_speed(self, speed, mac_sif_mode=MII_MODE_AUTO):
        # set mac speed
        super(IfconfigLocalWithSeparatePhy, self).set_link_speed(speed)
        time.sleep(5)

        if mac_sif_mode == MII_MODE_AUTO:
            mac_sif_mode = {
                LINK_SPEED_10G: MII_MODE_XFI,
                LINK_SPEED_5G: MII_MODE_XFI,
                LINK_SPEED_2_5G: MII_MODE_XFI,
                LINK_SPEED_1G: MII_MODE_SGMII,
                LINK_SPEED_100M: MII_MODE_SGMII
            }[speed]

        log.debug('link speed: {}    mode: {}'.format(speed, mac_sif_mode))
        set_sif_mode_mac(self.mac_atltool, speed, mac_sif_mode)

        log.debug('MAC SIF: {}'.format(get_sif_mode_mac(self.mac_atltool, speed)))
        log.debug('PHY SIF: {}'.format(self.phy_get_mii(speed)))

        if speed == LINK_SPEED_1G and self.phy_get_mii(speed) == MII_MODE_SGMII:
            self.phy_control.rmap.glb.GlobalSystemConfigurationFor1G().serdesMode.rmw(self.phy_control, 3)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_ReservedVendorProvisioning_3().systemSgmiiRxInvert.rmw(
                self.phy_control, 0)
            # self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_ReservedVendorProvisioning_3().systemSgmiiRxSerdes.rmw(self.phy_control, 2)
            log.info('PHY SGMII RX invert disable')

        reg = self.mac_atltool.readreg(0x368)
        self.mac_atltool.writereg(0x368, reg & ~0xf20)
        time.sleep(1)
        self.mac_atltool.writereg(0x368, reg)

        self.phy_control.setAutonegMasterMode("Automatic", self.LINK_SPEED_TO_PHY_CONTROL_SPEED_MAP[speed])
        self.phy_restart_autoneg()

    def set_link_state(self, state, vlan_id=None):
        super(IfconfigLocalWithSeparatePhy, self).set_link_state(state, vlan_id)
        if state == LINK_STATE_UP and vlan_id is None:
            self.phy_restart_autoneg()
        elif state == LINK_STATE_DOWN:
            pass

    def __mac_set_eee_sgmii(self, is_on):
        MAX_NOF_CONFIG_ATTEMPTS = 1

        def cfg():
            reg_4160 = self.mac_atltool.readreg(0x4160)
            if is_on:
                reg_4160 |= 0x1 << 0x1c
                reg_4160 &= 0xFFFFFFFB
            else:
                reg_4160 &= 0xdfffffff
                reg_4160 |= 0x4
            self.mac_atltool.writereg(0x4160, reg_4160)

            reg_41d0 = self.mac_atltool.readreg(0x41d0)
            if is_on:
                reg_41d0 |= 1 << 0x1b
            else:
                reg_41d0 &= 0xefffffff
            self.mac_atltool.writereg(0x41d0, reg_41d0)

            time.sleep(10)  # eee idle state simulation

            reg_8 = self.mac_atltool.readmsmreg(0x8)
            if is_on:
                reg_8 |= 1 << 0x17
            else:
                reg_8 &= 0xff7fffff
            self.mac_atltool.writemsmreg(0x8, reg_8)

        for i in range(MAX_NOF_CONFIG_ATTEMPTS):
            log.info("Attempt to configure RSI/TSI/MSM #{}".format(i + 1))
            cfg()
            time.sleep(3)
            self.wait_link_up()
            if is_on and not self.__is_mac_configured_eee_correctly_sgmii():
                log.warning("RSI/TSI lost detected, trying one more time")
            else:
                break
        else:
            raise Exception("Failed to configure EEE")

    def __mac_set_eee_xfi_usx(self, is_on, speed):
        reg_4000 = self.mac_atltool.readreg(0x4000)
        if is_on:
            reg_4000 |= 0x1 << 0x9
        else:
            reg_4000 &= 0xfffffdff
        self.mac_atltool.writereg(0x4000, reg_4000)

        if speed == LINK_SPEED_2_5G:
            self.mac_atltool.writemsmreg(0x18, 0x4000)
        elif speed == LINK_SPEED_5G:
            self.mac_atltool.writemsmreg(0x18, 0x2000)

        time.sleep(10)  # eee idle state simulation

        reg_8 = self.mac_atltool.readmsmreg(0x8)
        if is_on:
            reg_8 |= 1 << 0x17
        else:
            reg_8 &= 0xff7fffff
        self.mac_atltool.writemsmreg(0x8, reg_8)

    def phy_restart_autoneg(self):
        import gbecontrols
        gbecontrols.RestartAutoneg(self.phy_control)
        log.info('PHY renegotiation finished')

    def phy_hard_reset(self):
        # make hard reset to clear previous configuration
        self.phy_control.rmap.cmn.GlobalCommonPorControl_1().chipH_wReset.rmw(self.phy_control, 1)
        # sleep after hard reset
        time.sleep(5)
        self.phy_control.rmap.glb.GlobalReservedStatus_2().nearlySecondsLSW.readValue(self.phy_control)
        time.sleep(2)
        first_tick = self.phy_control.rmap.glb.GlobalReservedStatus_2().nearlySecondsLSW.readValue(self.phy_control)
        time.sleep(2)
        second_tick = self.phy_control.rmap.glb.GlobalReservedStatus_2().nearlySecondsLSW.readValue(self.phy_control)
        assert first_tick < second_tick, 'PHY is dead'
        log.info('PHY succesfully made hard reset')

    def phy_get_mii(self, speed):
        if speed == LINK_SPEED_1G:
            mii_register = self.phy_control.rmap.glb.GlobalSystemConfigurationFor1G()
        elif speed == LINK_SPEED_2_5G:
            mii_register = self.phy_control.rmap.glb.GlobalSystemConfigurationFor_2_5g()
        elif speed == LINK_SPEED_5G:
            mii_register = self.phy_control.rmap.glb.GlobalSystemConfigurationFor_5g()
        elif speed == LINK_SPEED_10G:
            mii_register = self.phy_control.rmap.glb.GlobalSystemConfigurationFor10G()
        elif speed == LINK_SPEED_100M:
            mii_register = self.phy_control.rmap.glb.GlobalSystemConfigurationFor100M()
        else:
            raise Exception("Failed ")
        if mii_register.rateAdaptationMethod.readValue(self.phy_control) == 1:
            return MII_MODE_USX
        else:
            if mii_register.serdesMode.readValue(self.phy_control) == 0:
                return MII_MODE_XFI
            elif mii_register.serdesMode.readValue(self.phy_control) == 3:
                return MII_MODE_SGMII
            elif mii_register.serdesMode.readValue(self.phy_control) == 4:
                return MII_MODE_OCSGMII
            elif mii_register.serdesMode.readValue(self.phy_control) == 6:
                return MII_MODE_XFI_DIV2

    def __phy_advertize_eee(self, is_on):
        assert is_on in [1, 0, True, False]
        if is_on is True:
            is_on = 1
        if is_on is False:
            is_on = 0

        # Apply EEE advertizement on PHY for all speeds
        self.phy_control.rmap.ang.AutonegotiationEeeAdvertisementRegister()._1000base_tEee.rmw(self.phy_control, is_on)
        self.phy_control.rmap.ang.AutonegotiationEeeAdvertisement_2Register()._2_5gbase_tEee.rmw(
            self.phy_control, is_on)
        self.phy_control.rmap.ang.AutonegotiationEeeAdvertisement_2Register()._5gbase_tEee.rmw(self.phy_control, is_on)
        self.phy_control.rmap.ang.AutonegotiationEeeAdvertisementRegister()._10gbase_tEee.rmw(self.phy_control, is_on)

    def __phy_enable_sec(self, speed):
        if speed == LINK_SPEED_1G:
            self.phy_control.rmap.glb.GlobalSystemConfigurationFor1G().securityEnable.rmw(self.phy_control, 1)
        elif speed == LINK_SPEED_2_5G:
            self.phy_control.rmap.glb.GlobalSystemConfigurationFor_2_5g().securityEnable.rmw(self.phy_control, 1)
        elif speed == LINK_SPEED_5G:
            self.phy_control.rmap.glb.GlobalSystemConfigurationFor_5g().securityEnable.rmw(self.phy_control, 1)
        elif speed == LINK_SPEED_10G:
            self.phy_control.rmap.glb.GlobalSystemConfigurationFor10G().securityEnable.rmw(self.phy_control, 1)
        elif speed == LINK_SPEED_100M:
            self.phy_control.rmap.glb.GlobalSystemConfigurationFor100M().securityEnable.rmw(self.phy_control, 1)
        else:
            raise Exception("Failed to enable SEC block")

        log.info('PHY security enabled')

    def __phy_internal_mode_set_eee_sgmii(self, speed):
        self.__phy_enable_sec(speed)
        self.phy_restart_autoneg()
        speed = self.wait_link_up()
        # Avoid problems with PHY fast retrain and others, sleep 3 seconds and wait one more time
        time.sleep(10)
        speed = self.wait_link_up()
        if speed == LINK_SPEED_1G:
            self.phy_control.rmap.secing.SecIngressControlRegister_2().secIngressEeeMode.rmw(self.phy_control, 0x2)
        self.phy_control.rmap.seceg.SecEgressControlRegister_2().secEgressEeeMode.rmw(self.phy_control, 0x2)
        log.info('PHY internal mode enabled')

    def __is_phy_negotiated_eee(self):
        status = self.phy_control.rmap.glb.GlobalEeeProvisioning_1().eeeMode.readValue(self.phy_control) == 1
        log.info("PHY {} EEE".format("negotiated" if status is True else "didn't negotiate"))
        return status

    def __is_mac_configured_eee_correctly_sgmii(self):
        reg_4160 = self.mac_atltool.readreg(0x4160)
        is_tsi_tx_err_suppression_enabled = reg_4160 & 0x4 == 0x4
        if is_tsi_tx_err_suppression_enabled is True:
            log.error("TSI TX_ERR suppression should be disabled for SGMII mode")
            return False
        is_tsi_eee_mode_enabled = reg_4160 & (0x1 << 0x1c) == (0x1 << 0x1c)
        if is_tsi_eee_mode_enabled is False:
            log.error("TSI EEE mode should be enabled for SGMII mode")
            return False
        reg_41d0 = self.mac_atltool.readreg(0x41d0)
        is_rsi_eee_mode_enabled = reg_41d0 & (0x1 << 0x1b) == 0x1 << 0x1b
        if is_rsi_eee_mode_enabled is False:
            log.error("RSI EEE mode should be enabled for SGMII mode")
            return False
        return True

    def __is_mac_configured_eee_correctly_xfi_usx(self):
        reg_4000 = self.mac_atltool.readreg(0x4000)
        is_mpi_eee_mode_enabled = reg_4000 & (0x1 << 0x9) == 0x1 << 0x9
        if is_mpi_eee_mode_enabled is False:
            log.error("MPI EEE mode should be enabled for XFI mode")
            return False
        return True

    def __is_mac_configured_eee_correctly_msm(self):
        reg_8 = self.mac_atltool.readmsmreg(0x8)
        is_msm_tx_lpi_enabled = reg_8 & (0x1 << 0x17) == 0x1 << 0x17
        if is_msm_tx_lpi_enabled is False:
            log.error("MSM Tx Low Power IDLE should be enabled")
            return False
        return True

    def __is_mac_configured_eee_correctly(self, speed):
        status = True
        if self.mii == MII_MODE_XFI_SGMII:
            if speed in [LINK_SPEED_1G]:  # 2.5G is also here because OCSGMII
                status &= self.__is_mac_configured_eee_correctly_sgmii()
            elif speed in [LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_2_5G]:
                status &= self.__is_mac_configured_eee_correctly_xfi_usx()
            else:
                status = False  # for 100M link speed
                # raise NotImplementedError()
        else:
            if speed in [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]:
                status &= self.__is_mac_configured_eee_correctly_xfi_usx()
            else:
                raise NotImplementedError()

        status &= self.__is_mac_configured_eee_correctly_msm()
        return status

    def __is_phy_internal_configured_eee_correctly(self, speed):
        status = True
        if speed == LINK_SPEED_2_5G or speed == LINK_SPEED_5G or speed == LINK_SPEED_10G:
            status &= self.phy_control.rmap.pcs.PcsStandardStatus_1().txLpiIndication.readValue(self.phy_control)
        elif speed == LINK_SPEED_1G:
            status &= self.phy_control.rmap.gbe.GbePhyTgeStatus_4().tgeEeeTxLpiIndication.readValue(self.phy_control)
        return status

    def set_media_options(self, options, eee_mode=''):
        log.info("Setting media options {}".format(options))

        # TODO: add full duplex and flow control

        eee_is_on = "energy-efficient-ethernet" in options
        self.__phy_advertize_eee(eee_is_on)
        self.phy_restart_autoneg()
        speed = self.wait_link_up()
        # Avoid problems with PHY fast retrain and others, sleep 3 seconds and wait one more time
        # time.sleep(3)
        # speed = self.wait_link_up()
        current_phy_mii = self.phy_get_mii(speed)
        if eee_mode == 'external':
            if current_phy_mii in [MII_MODE_SGMII, MII_MODE_OCSGMII]:
                self.__mac_set_eee_sgmii(eee_is_on)
            elif current_phy_mii in [MII_MODE_USX, MII_MODE_XFI, MII_MODE_XFI_DIV2]:
                self.__mac_set_eee_xfi_usx(eee_is_on, speed)
            else:
                raise NotImplementedError()
        else:
            self.__phy_internal_mode_set_eee_sgmii(speed=speed)

    def check_media_options(self, options, eee_mode=''):
        # TODO: only EEE is supported

        speed = self.wait_link_up(timeout=1)  # at this moment link should be up

        should_be_eee_enabled = "energy-efficient-ethernet" in options

        # First of all check whether PHY negotiated EEE
        is_phy_negotiated_eee = self.__is_phy_negotiated_eee()
        if should_be_eee_enabled is True and is_phy_negotiated_eee is False:
            raise Exception("Media option energy-efficient-ethernet is not set")
        elif should_be_eee_enabled is False and is_phy_negotiated_eee is True:
            raise Exception("Media option energy-efficient-ethernet is set but not requested")

        # Now check EEE configuration on MAC if external mode or PHY side if it is intarnal
        if eee_mode == 'internal':
            is_phy_internal_configured_eee_correctly = self.__is_phy_internal_configured_eee_correctly(speed)
            if should_be_eee_enabled is True and is_phy_internal_configured_eee_correctly is False:
                raise Exception("Media option energy-efficient-ethernet is not set")
            elif should_be_eee_enabled is False and is_phy_internal_configured_eee_correctly is True:
                raise Exception("Media option energy-efficient-ethernet is set but not requested")
        else:
            is_mac_configured_eee_correctly = self.__is_mac_configured_eee_correctly(speed)
            if should_be_eee_enabled is True and is_mac_configured_eee_correctly is False:
                raise Exception("Media option energy-efficient-ethernet is not set")
            elif should_be_eee_enabled is False and is_mac_configured_eee_correctly is True:
                raise Exception("Media option energy-efficient-ethernet is set but not requested")


class IfconfigRemote(Ifconfig):
    def __init__(self, **kwargs):
        super(IfconfigRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.cmd_start = "cd {} && sudo python ifconfig.py -p {} ".format(ATF_TOOLS_DIR, self.port)

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).wait(60)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to execute remote command")
        if not any(SCRIPT_STATUS_SUCCESS in line for line in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote ifconfig operation")
        return res["output"], None

    def get_link_speed(self, vlan_id=None):
        cmd = self.cmd_start + "-c getspeed"
        if vlan_id is not None:
            cmd += " --vid {}".format(vlan_id)
        stdout, _ = self.remote_exec(cmd)

        re_speed = re.compile(".*\s(10M|100M|1G|2\.5G|5G|10G)$")
        for line in stdout:
            m = re_speed.match(line.rstrip())
            if m is not None:
                val = m.group(1)
                if val in KNOWN_LINK_SPEEDS:
                    return val
        return LINK_SPEED_NO_LINK

    def set_link_speed(self, speed, half_duplex=False):
        log.info("Setting link speed {} on host {}".format(speed, self.host))
        cmd = self.cmd_start + "-c setspeed -s {}".format(speed)
        if half_duplex:
            cmd += " --half_duplex"
        self.remote_exec(cmd)

    def set_link_state(self, state, vlan_id=None):
        log.info("Setting link state {} on host {}".format(state, self.host))
        if state == LINK_STATE_UP:
            cmd = self.cmd_start + "-c linkup"
        else:
            cmd = self.cmd_start + "-c linkdown"
        if vlan_id is not None:
            cmd += " --vid {}".format(vlan_id)
        self.remote_exec(cmd)

    def set_ip_address(self, address, netmask, gateway, vlan_id=None):
        log.info("Setting IP address {}/{} gateway {} vlan_id {} on host {}".format(
            address, netmask, gateway, vlan_id, self.host))
        cmd = self.cmd_start + "-c setip -a {} -n {} -g {}".format(address, netmask, gateway)
        if vlan_id is not None:
            cmd += " --vid {}".format(vlan_id)
        self.remote_exec(cmd)

    def set_ipv6_address(self, address, prefix, gateway):
        log.info("Setting IPv6 address {}/{} gw {} on host {}".format(
            address, prefix, gateway, self.host))
        cmd = self.cmd_start + "-c setipv6 -a {} -n {} -g {}".format(address, prefix, gateway)
        self.remote_exec(cmd)

    def get_mac_address(self, macvlan=None):
        cmd = self.cmd_start + "-c getmac"
        if macvlan is not None:
            cmd = cmd + " --macvlan {}".format(macvlan)
        stdout, _ = self.remote_exec(cmd)
        for line in stdout:
            m = self.RE_MAC.match(line)
            if m is not None:
                mac = "{}:{}:{}:{}:{}:{}".format(m.group(1), m.group(2),
                                                 m.group(3), m.group(4),
                                                 m.group(5), m.group(6))
                return mac
        return None

    def get_management_mac_address(self):
        cmd = self.cmd_start + "-c getmgmtmac"
        stdout, _ = self.remote_exec(cmd)
        for line in stdout:
            m = self.RE_MAC.match(line)
            if m is not None:
                mac = "{}:{}:{}:{}:{}:{}".format(m.group(1), m.group(2),
                                                 m.group(3), m.group(4),
                                                 m.group(5), m.group(6))
                return mac
        return None

    def get_management_gateway(self):
        raise NotImplementedError()

    def get_counters(self):
        cmd = self.cmd_start + "-c stats"
        stdout, _ = self.remote_exec(cmd)

        res = {
            "transmit_ok": re.compile(" *transmit_ok = ([0-9]+)"),
            "transmit_error": re.compile(" *transmit_error = ([0-9]+)"),
            "receive_ok": re.compile(" *receive_ok = ([0-9]+)"),
            "receive_error": re.compile(" *receive_error = ([0-9]+)")
        }

        stats = {}
        for line in stdout:
            for cname, _re in res.items():
                m = _re.match(line)
                if m is not None:
                    stats[cname] = int(m.group(1))
        return stats

    def get_nof_pci_lines(self):
        cmd = self.cmd_start + "-c getnofpcilines"
        stdout, _ = self.remote_exec(cmd)
        re_pci_lines = re.compile(".*Number of PCI lines = ([0-9]+)$", re.DOTALL)
        for line in stdout:
            m = re_pci_lines.match(line.rstrip())
            if m is not None:
                return int(m.group(1))
        return None

    def set_arp(self, ip, mac):
        log.info("Setting static ARP entry {} -> {} on host".format(ip, mac, self.host))
        cmd = self.cmd_start + "-c setarp -a {} -m {}".format(ip, mac)
        self.remote_exec(cmd)

    def del_arp(self, ip):
        cmd = self.cmd_start + "-c delarp -a {}".format(ip)
        self.remote_exec(cmd)

    def get_guid_by_mac(self, mac_address, once=True):
        cmd = self.cmd_start + "-c getguidbymac -m {}".format(mac_address)
        stdout, _ = self.remote_exec(cmd)
        re_guid = re.compile(".*({[A-Z0-9-]+}).*", re.DOTALL)
        for line in stdout:
            m = re_guid.match(line.rstrip())
            if m is not None:
                return m.group(1)
        return None

    def get_guid_by_port(self):
        cmd = self.cmd_start + "-c getguidbyport"
        stdout, _ = self.remote_exec(cmd)
        re_guid = re.compile(".*({[A-Z0-9-]+}).*", re.DOTALL)
        for line in stdout:
            m = re_guid.match(line.rstrip())
            if m is not None:
                return m.group(1)
        return None

    def get_wmi_device_id(self):
        cmd = self.cmd_start + "-c getwmideviceid"
        stdout, _ = self.remote_exec(cmd)
        return stdout[0].rstrip("\r\n")

    def get_wmi_device_driver_name(self):
        cmd = self.cmd_start + "-c getwmidevicedrivername"
        stdout, _ = self.remote_exec(cmd)
        return stdout[0].rstrip("\r\n")

    def get_wmi_device_driver_version(self):
        cmd = self.cmd_start + "-c getwmidevicedriverversion"
        stdout, _ = self.remote_exec(cmd)
        return stdout[0].rstrip("\r\n")

    def get_mtu(self):
        cmd = self.cmd_start + "-c getmtu"
        stdout, _ = self.remote_exec(cmd)
        re_mtu = re.compile(r".*MTU = ([0-9]+)", re.DOTALL)
        for line in stdout:
            m = re_mtu.match(line)
            if m is not None:
                return int(m.group(1))
        return None

    def set_mtu(self, mtu):
        log.info("Setting MTU {} on host {}".format(mtu, self.host))
        cmd = self.cmd_start + "-c setmtu --mtu {}".format(mtu)
        self.remote_exec(cmd)

    def get_media_options(self, options_to_check=["flow-control", "full-duplex", "energy-efficient-ethernet"]):
        log.info("Getting media options on host {}".format(self.host))
        opt = ",".join(options_to_check)
        cmd = self.cmd_start + "-c getmediaoptions -o {}".format(opt)
        stdout, _ = self.remote_exec(cmd)

        opts = []
        for line in stdout:
            if "flow-control" in line:
                opts.append("flow-control")
            elif "full-duplex" in line:
                opts.append("full-duplex")
            elif "energy-efficient-ethernet" in line:
                opts.append("energy-efficient-ethernet")

        return opts

    def set_media_options(self, options_to_set=["flow-control", "full-duplex", "energy-efficient-ethernet"]):
        log.info("Setting media options {} on host {}".format(options_to_set, self.host))
        opt = ",".join(options_to_set)
        cmd = self.cmd_start + "-c setmediaoptions -o {}".format(opt)
        self.remote_exec(cmd)

    def set_flow_control(self, value):
        log.info("Setting FlowControl {} on host {}".format(value, self.host))
        cmd = self.cmd_start + "-c setflowcontrol -d {}".format(value)
        self.remote_exec(cmd)

    def get_flow_control(self):
        log.info("Getting FlowControl on host {}".format(self.host))
        cmd = self.cmd_start + "-c getflowcontrol"
        stdout, _ = self.remote_exec(cmd)

        for line in stdout:
            if "Flow Control:" in line:
                if OFFLOADS_STATE_TX_RX in line:
                    return OFFLOADS_STATE_TX_RX
                elif OFFLOADS_STATE_TX in line:
                    return OFFLOADS_STATE_TX
                elif OFFLOADS_STATE_RX in line:
                    return OFFLOADS_STATE_RX
                elif OFFLOADS_STATE_DSBL in line:
                    return OFFLOADS_STATE_DSBL

    def check_media_options(self, options):
        log.info("Getting media options {} on host {}".format(options, self.host))
        opt = ",".join(options)
        cmd = self.cmd_start + "-c checkmediaoptions -o {}".format(opt)
        self.remote_exec(cmd)

    def get_advanced_property(self, name):
        cmd = self.cmd_start + "-c getadvprop --propname {}".format(name)
        stdout, _ = self.remote_exec(cmd)
        re_adv_prop = re.compile(r".*Advanced property = (.*)", re.DOTALL)
        for line in stdout:
            m = re_adv_prop.match(line)
            if m is not None:
                return m.group(1)
        return None

    def check_duplex(self):
        cmd = self.cmd_start + "-c checkduplex"
        stdout, _ = self.remote_exec(cmd)
        re_mtu = re.compile(r".*Duplex = ([a-z]+)", re.DOTALL)
        for line in stdout:
            m = re_mtu.match(line)
            if m is not None:
                return str(m.group(1))
        return None

    def set_advanced_property(self, name, value):
        log.info("Setting advanced property {} to {} on host {}".format(name, value, self.host))
        cmd = self.cmd_start + "-c setadvprop --propname {} --propvalue {}".format(name, value)
        self.remote_exec(cmd)

    def set_wol_settings(self, on_magic=False, on_pattern=False, on_ping=False, on_link=False, from_power_off=False):
        log.info("Set wol settings on host {}".format(self.host))
        cmd = self.cmd_start + "-c setwol "
        if on_magic:
            cmd = cmd + "--on_magic "
        if on_pattern:
            cmd = cmd + "--on_pattern "
        if on_ping:
            cmd = cmd + "--on_ping "
        if on_link:
            cmd = cmd + "--on_link "
        if from_power_off:
            cmd = cmd + "--from_power_off "
        self.remote_exec(cmd)

    def set_interrupt_type(self, int_type, number=1):
        log.info("Setting MSI Supported interrupt {} on host {}".format(int_type, self.host))
        cmd = self.cmd_start + "-c setinter --int_type {} --propvalue {}".format(int_type, number)
        self.remote_exec(cmd)

    def set_power_mgmt_settings(self, only_magic_wake=False, allow_wake=False, allow_power_save=False):
        log.info("Setting power management settings on host {}:".format(self.host))
        log.info("Only allow a magic packet to wake the computer = {}".format(only_magic_wake))
        log.info("Allow this device to wake the computer = {}".format(allow_wake))
        log.info("Allow the computer to turn off this device to save power = {}".format(allow_power_save))
        cmd = self.cmd_start + "-c setpwroptions --onlymagicpkt {} --enablewake {} " \
                               "--enablepwrsave {}".format(only_magic_wake, allow_wake, allow_power_save)
        self.remote_exec(cmd)

    def bind_ipv6(self):
        cmd = self.cmd_start + "-c bindipv6"
        self.remote_exec(cmd)

    def unbind_ipv6(self):
        cmd = self.cmd_start + "-c unbindipv6"
        self.remote_exec(cmd)

    def get_conn_name(self):
        cmd = self.cmd_start + "-c getconnname"
        stdout, _ = self.remote_exec(cmd)
        re_iface = re.compile(".*Adapter name: ([0-9a-zA-Z\s]+)")
        for line in stdout:
            m = re_iface.match(line)
            if m is not None:
                return m.group(1)
        return None

    def manage_offloads(self, offload, state):
        log.info("Setting offload {} for port {} to state {} on host {}".format(offload, self.port, state, self.host))
        cmd = self.cmd_start + "-c manageoffloads --offload {} --state {}".format(offload, state)
        self.remote_exec(cmd)

    def is_device_present(self):
        cmd = self.cmd_start + "-c isdevicepresent"
        stdout, _ = self.remote_exec(cmd)
        re_device_present = re.compile(r".*Device is present.*", re.DOTALL)
        re_device_not_present = re.compile(r".*Device is not present.*", re.DOTALL)
        for line in stdout:
            m = re_device_present.match(line)
            if m is not None:
                return True
            m = re_device_not_present.match(line)
            if m is not None:
                return False
        raise Exception("Failed to parse device presense")

    def create_vlan_iface(self, vlan_id):
        cmd = self.cmd_start + "-c createvlaniface --vid {}".format(vlan_id)
        self.remote_exec(cmd)

    def delete_vlan_ifaces(self):
        cmd = self.cmd_start + "-c deletevlanifaces"
        self.remote_exec(cmd)

    def delete_macvlan_ifaces(self):
        cmd = self.cmd_start + "-c deletemacvlanifaces"
        self.remote_exec(cmd)

    def delete_vlan_iface(self, vlan_id):
        cmd = self.cmd_start + "-c deletevlaniface --vid {}".format(vlan_id)
        self.remote_exec(cmd)

    def add_route(self, addr, mask_prefix, gw):
        raise NotImplementedError()

    def del_ip_address(self, addr):
        cmd = self.cmd_start + "-c delipaddress -a {}".format(addr)
        self.remote_exec(cmd)

    def get_ip_address(self, ipv=4):
        cmd = self.cmd_start + "-c getipaddress --ipv {}".format(ipv)
        stdout, _ = self.remote_exec(cmd)
        re_ip_v4 = re.compile(r"IP_FOUND:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
        re_ip_v6 = re.compile(r"IP_FOUND:([0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}))")

        ips = []
        for line in stdout:
            if ipv == 4:
                m = re_ip_v4.finditer(line)
                if m is not None:
                    for match in m:
                        ips.append(match.group(1))
            elif ipv == 6:
                m = re_ip_v6.finditer(line)
                if m is not None:
                    for match in m:
                        ips.append(match.group(1))

        return ips

    def set_promisc_mode(self, state):
        if state == "Enable":
            cmd = self.cmd_start + "-c promiscon"
        else:
            cmd = self.cmd_start + "-c promiscoff"
        self.remote_exec(cmd)

    def set_buffer_size(self, rx_size=None, tx_size=None):
        cmd = self.cmd_start + "-c buffer_size"
        if rx_size is not None:
            cmd = cmd + " --rx_size {}".format(rx_size)
        if tx_size is not None:
            cmd = cmd + " --tx_size {}".format(tx_size)
        self.remote_exec(cmd)


class IfconfigArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("\n{}\n".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "%s: error: %s\n" % (self.prog, message))


if __name__ == "__main__":
    parser = IfconfigArgumentParser()
    parser.add_argument("-c", "--command", help="Command to be performed",
                        choices=["checkduplex",
                                 "setip",
                                 "setipv6",
                                 "stats",
                                 "setspeed",
                                 "getspeed",
                                 "linkdown",
                                 "linkup",
                                 "getmgmtmac",
                                 "getmac",
                                 "getifacename",
                                 "getadvspeeds",
                                 "getadvprop",
                                 "setarp",
                                 "delarp",
                                 "getnofpcilines",
                                 "setpwroptions",
                                 "setadvprop",
                                 "getguidbymac",
                                 "getguidbyport",
                                 "getwmideviceid",
                                 "getwmidevicedrivername",
                                 "getwmidevicedriverversion",
                                 "getmtu",
                                 "setmtu",
                                 "setmediaoptions",
                                 "getmediaoptions",
                                 "checkmediaoptions",
                                 "bindipv6",
                                 "unbindipv6",
                                 "getconnname",
                                 "manageoffloads",
                                 "isdevicepresent",
                                 "createvlaniface",
                                 "deletevlanifaces",
                                 "deletemacvlanifaces",
                                 "deletevlaniface",
                                 "delipaddress",
                                 "getipaddress",
                                 "promiscon",
                                 "promiscoff",
                                 "setinter",
                                 "buffer_size",
                                 "setflowcontrol",
                                 "getflowcontroladv",
                                 "getflowcontrol",
                                 "setwol"], type=str, required=True)

    parser.add_argument("-a", "--address", type=str, help="IPv4 or IPv6 address to be set on interface")
    parser.add_argument("-p", "--port", help="PCI port, i.e. pci0.00.0, ...", type=str)
    parser.add_argument("-n", "--netmask", help="Netmask/Prefix for IP interface", type=str)
    parser.add_argument("-g", "--gateway", help="Default gateway for IP interface")
    parser.add_argument("-s", "--speed", help="Default gateway for IP interface",
                        choices=["10M", "100M", "1G", "2.5G", "5G", "10G", "AUTO"])
    parser.add_argument("-m", "--mac", help="Default gateway for IP interface")
    parser.add_argument("--enablepwrsave", help="Allow the computer to turn off this device to save power", type=str)
    parser.add_argument("--enablewake", help="Allow this device to wake the computer", type=str)
    parser.add_argument("--half_duplex", help="Set half duplex link", action='store_true', default=False)
    parser.add_argument("--onlymagicpkt", help="Only allow a magic packet to wake the computer", type=str)
    parser.add_argument("--propname", help="Name of property in Advanced")
    parser.add_argument("--propvalue", help="Value of property in Advanced")
    parser.add_argument("--on_magic", help="Value of wol settings", action='store_true', default=False)
    parser.add_argument("--on_pattern", help="Value of wol settings", action='store_true', default=False)
    parser.add_argument("--on_ping", help="Value of wol settings", action='store_true', default=False)
    parser.add_argument("--on_link", help="Value of wol settings", action='store_true', default=False)
    parser.add_argument("--from_power_off", help="Value of wol settings", action='store_true', default=False)
    parser.add_argument("--int_type", help="Interrupt type")
    parser.add_argument("--macvlan", type=str, help="macvlan interface")
    parser.add_argument("--mtu", help="MTU value, i.e. 1500, 4000, ...", type=int)
    parser.add_argument("-o", "--options", help="The comma separated list of media options")
    parser.add_argument("--state", help="State for managing offloads")
    parser.add_argument("--offload", help="Offload name for managing")
    parser.add_argument("--vid", help="Vlan id", type=int)
    parser.add_argument("--ipv", help="IP version", type=int)
    parser.add_argument("--rx_size", help="RX buffer size", type=int)
    parser.add_argument("--tx_size", help="TX buffer size", type=int)
    parser.add_argument("-d", "--direction", help="Direction", type=str,
                        choices=[OFFLOADS_STATE_RX, OFFLOADS_STATE_TX, OFFLOADS_STATE_TX_RX, OFFLOADS_STATE_DSBL])

    args = parser.parse_args()
    if args.gateway == 'None':
        args.gateway = None

    try:
        ifconfig_obj = IfconfigLocal(port=args.port)

        if args.command == "setip":
            if not args.port or not args.netmask:
                log.error("To set IP address port and netmask must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_ip_address(args.address, args.netmask, args.gateway, args.vid)
        elif args.command == "setflowcontrol":
            if args.port is None or args.direction is None:
                log.error("To set flow control, port and value must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_flow_control(args.direction)
        elif args.command == "checkduplex":
            if args.port is None:
                log.error("To set port")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            duplex = ifconfig_obj.check_duplex()
            log.info("Duplex = {}".format(duplex))
        elif args.command == "getflowcontrol":
            if args.port is None:
                log.error("To get flow control, port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.get_flow_control()
        elif args.command == "setinter":
            if args.port is None or args.int_type is None:
                log.error("To set advanced property port, name and value must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_interrupt(args.int_type, args.propvalue)
        elif args.command == "setipv6":
            if not args.port or not args.netmask:
                log.error("To set IP address port and netmask must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_ipv6_address(args.address, args.netmask, args.gateway)
        elif args.command == "stats":
            if not args.port:
                log.error("To get counters port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            stats = ifconfig_obj.get_interface_stats()
            log.info("Interface statistic counters:")
            for k, v in stats.items():
                log.info("  {} = {}".format(k, v))
        elif args.command == "setspeed":
            if args.port is None or args.speed is None:
                log.error("To set link speed port and speed must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            if args.half_duplex:
                ifconfig_obj.set_link_speed(args.speed, args.half_duplex)
            else:
                ifconfig_obj.set_link_speed(args.speed)
        elif args.command == "getspeed":
            if args.port is None:
                log.error("To get link down port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            speed = ifconfig_obj.get_link_speed(args.vid)
            log.info(speed)
        elif args.command == "linkdown":
            if args.port is None:
                log.error("To set link down port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_link_down(args.vid)
        elif args.command == "linkup":
            if args.port is None:
                log.error("To set link up port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_link_up(args.vid)
        elif args.command == "getmac":
            if args.port is None:
                log.error("To get mac address port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            if args.macvlan is not None:
                mac = ifconfig_obj.get_mac_address(args.macvlan)
            else:
                mac = ifconfig_obj.get_mac_address()
            log.info(mac)
        elif args.command == "getmgmtmac":
            mac = ifconfig_obj.get_management_mac_address()
            log.info(mac)
        elif args.command == "getadvspeeds":
            if args.port is None:
                log.error("To get mac address port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            advspeeds = ifconfig_obj.get_advertised_link_speeds()
            log.info(advspeeds)
        elif args.command == "getadvprop":
            if args.port is None or args.propname is None:
                log.error("To get advanced property port and name must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            value = ifconfig_obj.get_advanced_property(args.propname)
            log.info("Advanced property = {}".format(value))
        elif args.command == "setarp":
            if args.address is None or args.mac is None or args.port is None:
                log.error("To set static ARP entry ip, mac and port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_arp(args.address, args.mac)
        elif args.command == "delarp":
            if args.address is None:
                log.error("To delete static ARP entry IP must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.del_arp(args.address)
        elif args.command == "getnofpcilines":
            if args.port is None:
                log.error("To get number of PCI lines port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            nof_lines = ifconfig_obj.get_nof_pci_lines()
            log.info("Number of PCI lines = {}".format(nof_lines))
        elif args.command == "setpwroptions":
            if args.port is None or args.enablepwrsave is None or args.enablewake is None or args.onlymagicpkt is None:
                log.error("To set Power Management, port and power options must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_power_mgmt_settings(args.onlymagicpkt in ["True"], args.enablewake in ["True"],
                                                 args.enablepwrsave in ["True"])
        elif args.command == "setadvprop":
            if args.port is None or args.propname is None or args.propvalue is None:
                log.error("To set advanced property port, name and value must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_advanced_property(args.propname, args.propvalue)
        elif args.command == "setwol":
            if args.port is None:
                log.error("To set wol settings, port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_wol_settings(args.on_magic, args.on_pattern, args.on_ping, args.on_link,
                                          args.from_power_off)
        elif args.command == "getguidbymac":
            if args.mac is None:
                log.error("MAC address must be specified to get device GUID")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            guid = ifconfig_obj.get_guid_by_mac(args.mac)
            log.info(guid)
        elif args.command == "getguidbyport":
            if args.port is None:
                log.error("PCI port must be specified to get device GUID")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            guid = ifconfig_obj.get_guid_by_port()
            log.info(guid)
        elif args.command == "getwmideviceid":
            if args.port is None:
                log.error("PCI port must be specified to get device Hardware ID")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            hwid = ifconfig_obj.get_wmi_device_id()
            log.info(hwid)
        elif args.command == "getwmidevicedrivername":
            if args.port is None:
                log.error("PCI port must be specified to get device driver name")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            name = ifconfig_obj.get_wmi_device_driver_name()
            log.info(name)
        elif args.command == "getwmidevicedriverversion":
            if args.port is None:
                log.error("PCI port must be specified to get device driver version")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            version = ifconfig_obj.get_wmi_device_driver_version()
            log.info(version)
        elif args.command == "getmtu":
            if args.port is None:
                log.error("PCI port must be specified to get MTU")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            mtu = ifconfig_obj.get_mtu()
            log.info("MTU = {}".format(mtu))
        elif args.command == "setmtu":
            if args.port is None or args.mtu is None:
                log.error("To set MTU port and MTU value must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_mtu(int(args.mtu))
        elif args.command == "setmediaoptions":
            if args.port is None or args.options is None:
                log.error("To set media options port and options must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_media_options(args.options.split(","))
        elif args.command == "checkmediaoptions":
            if args.port is None or args.options is None:
                log.error("To get media options port and options must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.check_media_options(args.options.split(","))
        elif args.command == "bindipv6":
            if args.port is None:
                log.error("To bind IPv6 port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.bind_ipv6()
        elif args.command == "unbindipv6":
            if args.port is None:
                log.error("To unbind IPv6 port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.unbind_ipv6()
        elif args.command == "getconnname":
            if args.port is None:
                log.error("To get connection name port must be specified")
            iface = ifconfig_obj.get_conn_name()
            log.info("Adapter name: {}".format(iface))
        elif args.command == "manageoffloads":
            if args.port is None or args.state is None:
                log.error("To set offloads status port and state must be specified")
            ifconfig_obj.manage_offloads(args.offload, args.state)
        elif args.command == "isdevicepresent":
            if args.port is None:
                log.error("To check device port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            pres = ifconfig_obj.is_device_present()
            log.info("Device is{} present".format("" if pres else " not"))
        elif args.command == "createvlaniface":
            if args.port is None or args.vid is None:
                log.error("To create vlan interface port and vlan id must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.create_vlan_iface(args.vid)
        elif args.command == "deletevlanifaces":
            if args.port is None:
                log.error("To delete all vlan interfaces port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.delete_vlan_ifaces()
        elif args.command == "deletemacvlanifaces":
            if args.port is None:
                log.error("To delete all macvlan interfaces port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.delete_macvlan_ifaces()

        elif args.command == "deletevlaniface":
            if args.port is None or args.vid is None:
                log.error("To delete vlan interface port and vlan id must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.delete_vlan_iface(args.vid)

        elif args.command == "getipaddress":
            if args.port is None or args.ipv is None:
                log.error("To get adress port and type must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ips = ifconfig_obj.get_ip_address(args.ipv)
            log.info("\n".join('IP_FOUND:' + ip for ip in ips))
        elif args.command == "delipaddress":
            if args.port is None or args.address is None:
                log.error("To del adress port and address must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.del_ip_address(args.address)
        elif args.command == "promiscon":
            if args.port is None:
                log.error("To enable Promiscuous Mode port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_promisc_mode("Enable")
        elif args.command == "promiscoff":
            if args.port is None:
                log.error("To disable Promiscuous Mode port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_promisc_mode("Disable")
        elif args.command == "getmediaoptions":
            if args.port is None or args.options is None:
                log.error("To get media options port and options to check must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            opts = ifconfig_obj.get_media_options(args.options.split(","))
            log.info("\n".join(opt for opt in opts))
        elif args.command == "buffer_size":
            if args.port is None or (args.rx_size is None and args.tx_size is None):
                log.error("To set buffer size port and at least one rx or tx bufsize must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ifconfig_obj.set_buffer_size(args.rx_size, args.tx_size)

    except Exception:
        traceback.print_exc(limit=10, file=sys.stderr)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
