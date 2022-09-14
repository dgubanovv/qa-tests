import argparse
import glob
import io
import json
import os
import re
import socket
import subprocess
import sys
import time
import urlparse
import zipfile

import constants
import ops

from abc import abstractmethod, ABCMeta
from atltoolper import AtlTool
from command import Command
from utils import get_bus_dev_func, get_domain_bus_dev_func, remove_file, remove_directory, get_url_response, \
    get_atf_logger, SpacedArgAction, download_file


if sys.platform == "win32":
    import wmi
    from utils import get_wmi_pnp_devices, get_wmi_device_pnp_driver, get_win_usb_hw_ids

SCRIPT_STATUS_SUCCESS = "[DRIVER-SUCCESS]"
SCRIPT_STATUS_FAILED = "[DRIVER-FAILED]"

DRV_TYPE_GENERIC_WIN = "genericwin"
DRV_TYPE_NDIS = "ndis"
DRV_TYPE_DIAG = "diag"
DRV_TYPE_DIAG_LIN = "diag_lin"
DRV_TYPE_DIAG_WIN = "diag_win"
DRV_TYPE_DIAG_MAC = "diag_mac"
DRV_TYPE_DIAG_WIN_USB = "diag_win_usb"
DRV_TYPE_SRC_DIAG_LIN = "diag_lin_src"
DRV_TYPE_MSI = "msi"
DRV_TYPE_KO = "ko"
DRV_TYPE_RPM = "rpm"
DRV_TYPE_DEB = "deb"
DRV_TYPE_KEXT = "kext"
DRV_TYPE_FREEBSD_SRC = "freebsd"
DRV_TYPE_LINUX_SRC = "linuxsrc"
DRV_TYPE_T6 = "t6"
DRV_TYPE_MAC_CDC = "mac_cdc"
DRV_TYPE_LIN_CDC = "linux_cdc"
DRV_TYPE_CDC = "cdc"
NAME_LIN_DRV_TYPE_PROD = "atlantic"
NAME_LIN_DRV_TYPE_DIAG = "aqdiag"
NAME_LIN_DRV_TYPE_CDC = "cdc"
NUMBER_OF_UNINSTALLING_ATTEMPS = 10

log = get_atf_logger()


class DriverMeta(ABCMeta):
    drv_classes = {}

    def __init__(cls, name, bases, attrs):
        if hasattr(cls, "drv_type") and cls.drv_type:
            DriverMeta.drv_classes[cls.drv_type] = cls

    @staticmethod
    def find_driver(drv_type):
        op_sys = ops.OpSystem()
        if drv_type == DRV_TYPE_DIAG:
            if op_sys.is_windows():
                return DriverMeta.drv_classes[DRV_TYPE_DIAG_WIN]
            elif op_sys.is_linux():
                return DriverMeta.drv_classes[DRV_TYPE_SRC_DIAG_LIN]
            elif op_sys.is_mac():
                return DriverMeta.drv_classes[DRV_TYPE_DIAG_MAC]
            elif op_sys.is_freebsd():
                return DriverMeta.drv_classes[DRV_TYPE_FREEBSD_SRC]
            else:
                raise Exception("Unknown operating system")
        elif drv_type == DRV_TYPE_CDC:
            if op_sys.is_linux():
                return DriverMeta.drv_classes[DRV_TYPE_LIN_CDC]
            elif op_sys.is_mac():
                return DriverMeta.drv_classes[DRV_TYPE_MAC_CDC]
            else:
                raise Exception("No CDC driver supported")
        else:
            return DriverMeta.drv_classes[drv_type]


class Driver(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)

        if host is None or host == "localhost" or host == socket.gethostname():
            return DriverLocal.__new__(DriverLocal, **kwargs)
        else:
            return object.__new__(DriverRemote)

    def __init__(self, **kwargs):
        self.insmod_args = kwargs.get("insmod_args", None)
        self.make_args = kwargs.get("make_args", None)
        self.port = kwargs["port"]
        self.version = kwargs["version"]
        self.vendor = "aquantia"
        self.flashless_fw = kwargs.get("flashless_fw", None)

    @staticmethod
    def get_default_drv_type(host):
        # IF user doesn't spicify driver type it means that user doesn't care which driver will be created.
        # The user just wants it to be installed => traffic works; and so on...
        log.warning("Driver type is not specified, KO, KEXT or NDIS will be used")
        host_os_name = ops.OpSystem(host=host).get_name()
        if host_os_name in constants.LINUX_OSES:
            if host_os_name not in constants.UBUNTU_OSES:
                log.info("This is Linux OS, creating LINUX SRC RPM driver")
                drv_type = DRV_TYPE_RPM
            else:
                log.info("This is Linux OS, creating LINUX SRC DEB driver")
                drv_type = DRV_TYPE_DEB
        elif host_os_name in constants.FREEBSD_OSES:
            log.info("This is FreeBSD OS, creating FREEBSD SRC driver")
            drv_type = DRV_TYPE_FREEBSD_SRC
        elif host_os_name in constants.MAC_OSES:
            log.info("This is MAC OS, creating KEXT driver")
            drv_type = DRV_TYPE_KEXT
        else:
            log.info("This is Windows OS, creating NDIS driver")
            drv_type = DRV_TYPE_NDIS

        return drv_type

    @abstractmethod
    def install(self):
        pass

    @abstractmethod
    def uninstall(self, ignore_remove_errors=False):
        pass

    @property
    def release_version(self):
        content = self.version
        if not self.drv_type:
            return content
        if self.drv_type == DRV_TYPE_KO:
            suburl = "driver/{}/{}/{}/{}/version.txt".format(self.drv_type, self.ops, self.vendor, self.version)
        if self.drv_type == DRV_TYPE_LINUX_SRC or self.drv_type == DRV_TYPE_FREEBSD_SRC:
            suburl = "driver/linux/{}/{}/version.txt".format(self.vendor, self.version)
        elif self.drv_type == DRV_TYPE_DIAG:
            op_sys = ops.OpSystem()
            if op_sys.is_windows():
                suburl = "driver/diag/win/{}/version.txt".format(self.version)
            elif op_sys.is_linux():
                raise NotImplementedError()
            elif op_sys.is_mac():
                suburl = "driver/diag/mac/{}/version.txt".format(self.version)
        elif self.drv_type in [DRV_TYPE_DIAG_WIN, DRV_TYPE_DIAG_MAC, DRV_TYPE_DIAG_LIN]:
            suburl = "driver/{}/{}/version.txt".format(self.drv_type.replace("_", "/"), self.version)
        elif self.drv_type == DRV_TYPE_NDIS and self.version.startswith('3x'):
            suburl = "driver/{}/{}/atlantic2/builds/{}/version.txt".format(self.drv_type, self.vendor, self.version.split('/')[1])
        else:
            if self.vendor == constants.VENDOR_QNAP:
                vendor_for_work = constants.VENDOR_AQUANTIA
            else:
                vendor_for_work = self.vendor
            suburl = "driver/{}/{}/{}/version.txt".format(self.drv_type, vendor_for_work, self.version)
        if not suburl:
            return content
        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Getting release version from {}".format(url))
        try:
            content = get_url_response(url)
        except Exception as e:
            log.exception(e)

        return content.rstrip("\r\n")


class DriverLocal(Driver):
    __metaclass__ = DriverMeta

    def __new__(cls, **kwargs):
        if kwargs.get("drv_type"):
            drv_type = kwargs.get("drv_type")
        else:
            cls.flashless_fw = kwargs.get("flashless_fw", None)
            host_os_name = ops.OpSystem()
            if 'usb' in kwargs["port"] and host_os_name.is_linux():
                log.info("This is Fiji, creating LINUX SRC driver")
                drv_type = DRV_TYPE_LINUX_SRC
            elif "freebsd" in kwargs["version"]:
                drv_type = DRV_TYPE_FREEBSD_SRC
            elif cls.flashless_fw is not None:
                drv_type = DRV_TYPE_LINUX_SRC
            elif "forwarding" in kwargs["version"]:
                drv_type = DRV_TYPE_LINUX_SRC
            else:
                drv_type = cls.get_default_drv_type(None)

        obj_cls = cls.find_driver(drv_type)
        obj = object.__new__(obj_cls)
        return obj

    def __init__(self, **kwargs):
        super(DriverLocal, self).__init__(**kwargs)
        self.arch = self.get_arch()
        self.vendor = self.get_nic_vendor()
        self.ops = ops.OpSystem().get_name()

    def get_arch(self):
        cmd = "arch"
        op_sys = ops.OpSystem()
        if op_sys.is_freebsd():
            return "x86_64"
        try:
            log.info("Running command '{}'".format(cmd))
            output = subprocess.check_output(cmd, shell=True,
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            log.error(e.output)
            raise e
        output = output.rstrip("\r\n")
        if output not in constants.KNOWN_ARCHES:
            raise Exception("Unknown system architecture '{}'".format(output))
        return output

    @abstractmethod
    def get_nic_vendor(self):
        pass


class DriverRemote(Driver):
    def __init__(self, **kwargs):
        super(DriverRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.ops = ops.OpSystem(host=self.host)
        if self.flashless_fw is not None:
            self.drv_type = DRV_TYPE_LINUX_SRC
        if kwargs.get("drv_type"):
            self.drv_type = kwargs["drv_type"]
        elif "forwarding" in kwargs["version"]:
            self.drv_type = DRV_TYPE_LINUX_SRC
        elif "freebds" in kwargs["version"]:
            self.drv_type = DRV_TYPE_FREEBSD_SRC
        elif 'usb' in kwargs["port"] and self.ops.is_linux():
            log.info("This is Fiji, creating LINUX SRC driver")
            self.drv_type = DRV_TYPE_LINUX_SRC
        else:
            self.drv_type = self.get_default_drv_type(self.host)
        self.cmd_start = "cd {} && sudo python driver.py -d {} -p {} ".format(
            constants.ATF_TOOLS_DIR, self.drv_type, self.port)

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).wait(300)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to execute remote command")
        if not any(SCRIPT_STATUS_SUCCESS in line for line in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote driver operation")
        return res["output"]

    def install(self):
        cmd = self.cmd_start + "-c install"
        if self.version is not None:
            cmd += " -v {}".format(self.version)
        if self.insmod_args:
            cmd += " -a \"{}\"".format(self.insmod_args)
        if self.make_args:
            cmd += " -m \"{}\"".format(self.make_args)
        if self.flashless_fw:
            cmd += " -f \"{}\"".format(self.flashless_fw)
        self.remote_exec(cmd)

    def uninstall(self, ignore_remove_errors=False):
        cmd = self.cmd_start + "-c uninstall"
        self.remote_exec(cmd)

    def download(self):
        cmd = self.cmd_start + "-c download"
        if self.version is not None:
            cmd += " -v {}".format(self.version)
        res = self.remote_exec(cmd)
        for line in res:
            m = re.match(".*Downloaded\sfile:\s(.+)", line)
            if m is not None:
                return m.groups()[0]
        raise Exception

    def bind(self):
        cmd = self.cmd_start + "-c bind"
        self.remote_exec(cmd)

    def unbind(self):
        cmd = self.cmd_start + "-c unbind"
        self.remote_exec(cmd)

    def is_installed(self):
        cmd = self.cmd_start + "-c isinstalled"
        res = self.remote_exec(cmd)

        not_found_str = "Installed driver was not found"
        another_drv_str = "Another installed driver was found"

        if any(not_found_str in line for line in res):
            return False

        if self.drv_type == DRV_TYPE_DIAG_WIN_USB:
            if any("Installed USB auxiliary driver was found" in line for line in res):
                return True
        if self.drv_type == DRV_TYPE_GENERIC_WIN:
            if any(another_drv_str in line for line in res):
                return True
        if self.drv_type == DRV_TYPE_NDIS:
            if any("Installed NDIS driver was found" in line for line in res):
                return True
        if self.drv_type == DRV_TYPE_DIAG_WIN:
            if any("Installed diag driver was found" in line for line in res):
                return True

        if any(another_drv_str in line for line in res):
            return False


class WindowsDriver(DriverLocal):
    drv_type = DRV_TYPE_GENERIC_WIN
    DEVCON_RESTART_WAIT = 30

    def get_nic_vendor(self):
        pnps = get_wmi_pnp_devices(self.port)
        if len(pnps) == 0:
            error_msg = "PNP devices are not found for port '{}'".format(self.port)
            log.error(error_msg)
            raise Exception(error_msg)
        if self.port.startswith("pci"):
            devid = pnps[0].DeviceID.lower()
            log.debug("Vendor id is {}".format(devid))
            if "ven_1d6a" in devid:
                return constants.VENDOR_AQUANTIA
            elif "ven_8086" in devid:
                return constants.VENDOR_INTEL
            elif "ven_1fc9" in devid:
                return constants.VENDOR_TEHUTI
            return constants.VENDOR_UNKNOWN
        elif self.port.startswith("usb"):
            vid, _ = get_win_usb_hw_ids(self.port)
            log.debug("Vendor id is {}".format(vid))
            vid = vid.lower()
            if vid == "1d6a":
                return constants.VENDOR_AQUANTIA
            elif vid == "05ac":
                return constants.VENDOR_APPLE
            elif vid == "2001":
                return constants.VENDOR_DLINK
            elif vid == "0bda":
                return constants.VENDOR_REALTEK
            elif vid == "2357":
                return constants.VENDOR_TPLINK
            elif vid == "2eca":
                return constants.VENDOR_PACIFIC
            elif vid == "1c04":
                return constants.VENDOR_QNAP

    def devcon_disable(self, hwid):
        cmd = "devcon -r disable \"{}\"".format(hwid)
        RETRY_COUNT = 2
        for i in range(RETRY_COUNT):
            log.info("Attempt #{}".format(i + 1))
            res = Command(cmd=cmd).run()
            if res["returncode"] != 0:
                output = "".join(res["output"])
                if "restart" in output.lower() or "reboot" in output.lower():
                    log.warning("Devcon requested restart. "
                                "Sleeping {} sec while system is going to restart".format(self.DEVCON_RESTART_WAIT))
                    # We expect that system will be restarted automatically during sleep
                    time.sleep(self.DEVCON_RESTART_WAIT)
                    raise Exception("The system was not restarted in time")

                if i == RETRY_COUNT - 1:
                    raise Exception("Failed to disable device {}".format(hwid))
                else:
                    log.warning("Failed to disable device {}".format(hwid))
                    time.sleep(3)
            else:
                break

    def devcon_enable(self, hwid):
        res = Command(cmd="devcon -r enable \"{}\"".format(hwid)).run()
        if res["returncode"] != 0:
            output = "".join(res["output"])
            if "restart" in output.lower() or "reboot" in output.lower():
                log.warning("Devcon requested restart. "
                            "Sleeping {} seconds while system is going to restart".format(self.DEVCON_RESTART_WAIT))
                # We expect that system will be restarted automatically during sleep
                time.sleep(self.DEVCON_RESTART_WAIT)
                raise Exception("The system was not restarted in time")
            else:
                raise Exception("Failed to enable device {}".format(hwid))

    def trace_devcon_installation_log(self, hwid):
        cmd = "tac \"C:\\\\Windows\\\\INF\\\\setupapi.dev.log\" | " \
              "grep -m1 -B 300 \"Device Install (UpdateDriverForPlugAndPlayDevices) - {}\" | " \
              "tac".format(hwid.replace("\\", "\\\\\\\\").replace("&", "\\&"))
        setup_log = Command(cmd=cmd, silent=True).run()["output"]
        end_setup_log = -1
        for i, line in enumerate(setup_log):
            if "<<<" in line:
                end_setup_log = i
                break
        log.debug("\n{0}\nInstallation log:\n{1}\n{0}".format(
            "-" * 120, "\n".join(setup_log[:end_setup_log + 2])))

    def devcon_update(self, hwid, inf):
        res = Command(cmd="devcon -r updateni \"{}\" \"{}\"".format(inf, hwid)).run()
        if res["returncode"] != 0:
            log.error("Devcon failed. Trying to get installation log")
            self.trace_devcon_installation_log(hwid)
            output = "".join(res["output"])
            if "restart" in output.lower() or "reboot" in output.lower():
                log.warning("Devcon requested restart. "
                            "Sleeping {} seconds while system is going to restart".format(self.DEVCON_RESTART_WAIT))
                # We expect that system will be restarted automatically during sleep
                time.sleep(self.DEVCON_RESTART_WAIT)
                raise Exception("The system was not restarted in time")
            else:
                if "Failed to copy driver package" in output:
                    log.info("Driver copying is failed, trying one more time after delay")
                    time.sleep(5)
                    res = Command(cmd="devcon -r updateni \"{}\" \"{}\"".format(inf, hwid)).run()
                    if res["returncode"] != 0:
                        log.error("Devcon failed. Trying to get installation log")
                        self.trace_devcon_installation_log(hwid)
                        raise Exception("Failed to update driver package {} for device {}".format(inf, hwid))

    def devcon_update_and_confirm(self, hwid, inf):
        try:
            from pywinauto import Application, timings
            app = Application()

            cmd = "devcon /r update \"{}\" \"{}\"".format(inf, hwid)
            log.info("Running command '{}'".format(cmd))
            p = subprocess.Popen(cmd, shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)

            # wait and confirm Windows Security dialog
            def connect_to_security_dlg():
                app.connect(path='rundll32.exe', title='Windows Security')
                app.window(title='Windows Security').wrapper_object()

            try:
                timings.wait_until_passes(
                    timeout=10,
                    retry_interval=0.1,
                    func=connect_to_security_dlg)
                security_warning = True
            except Exception as e:
                security_warning = False

            if security_warning:
                log.warning("Found Windows Security dialog")
                msg = "&Install this driver software anyway"
                if app.WindowsSecurity[msg].exists():
                    app.WindowsSecurity[msg].click()
                    log.info("Clicked 'Install this driver software anyway'")
                else:
                    app.window(title='Windows Security').InstallButton.click()
                    log.info("Clicked 'Install'")
                app.window(title='Windows Security').wait_not('visible')
                log.info('The dialog is closed')

            stdout, stderr = p.communicate()
            if "Drivers updated successfully" not in stdout:
                raise Exception("Failed to update driver package, output:\n{}".
                                format(stdout))
        except subprocess.CalledProcessError as e:
            if "restart" in e.output.lower() or "reboot" in e.output.lower():
                log.warning("Devcon requested restart, sleeping {} seconds "
                            "until system is restarting".format(self.DEVCON_RESTART_WAIT))
                # We expect that system will be restarted automatically
                # during sleep
                time.sleep(self.DEVCON_RESTART_WAIT)
                log.error("The system was not restarted in time")
            log.error(e.output)
            raise e

    def devcon_update_driver(self, port, inf):
        if port.startswith("pci"):
            hwid_long = get_wmi_pnp_devices(port)[0].DeviceID
            re_hwid = re.compile(r"PCI\\VEN_[0-9A-F]{4}&DEV_([0-9A-F]{4})&SUBSYS_[0-9A-F]{8}", re.DOTALL)
            hwid_short = re_hwid.search(hwid_long)

            if hwid_short:
                hwid_short = hwid_short.group(0)
            else:
                raise Exception("Could not find device id for port {}".format(port))
        elif port.startswith("usb"):
            hwid_short = get_wmi_pnp_devices(port)[0].HardwareID[0]

        self.devcon_disable(hwid_short)
        try:
            self.devcon_update(hwid_short, inf)
        finally:
            # If we failed to update driver, enable device back (otherwise next test might not find card on PCI)
            self.devcon_enable(hwid_short)

    @staticmethod
    def devcon_rescan():
        res = Command(cmd="devcon rescan").run()
        if res["returncode"] != 0:
            raise Exception("Failed to update device list")

    def install(self):
        raise NotImplementedError

    def uninstall(self, ignore_remove_errors=False):
        self.uninstall_inf_driver(ignore_remove_errors=ignore_remove_errors)

    def is_installed(self):
        log.info("Checking any NDIS or Sample driver for port {}".format(self.port))

        self.restart_wmi()
        pnp_driver = get_wmi_device_pnp_driver(self.port)
        if pnp_driver is None or pnp_driver.DeviceName is None or pnp_driver.DeviceClass is None:
            log.info("Installed driver was not found")
            return False
        elif pnp_driver.DeviceClass in ["NET", "SAMPLE", "LIBUSBK USB DEVICES", "USB", "LIBUSBK DEVICES"]:
            log.info("Installed driver was found")
            return True
        else:
            raise RuntimeError('Driver of incompatible type "{}" was found!'.format(pnp_driver.DeviceClass))

    def uninstall_inf_driver(self, ignore_remove_errors=False):
        for attempt in range(NUMBER_OF_UNINSTALLING_ATTEMPS):
            if WindowsDriver.is_installed(self):
                pnp_driver = get_wmi_device_pnp_driver(self.port)
                if pnp_driver.DeviceClass == "USB":
                    log.info("Skip uninstall for USB Mass Storage")
                    return
                log.info("Driver is still installed, attempt of trying to remove driver #{}".format(attempt + 1))
                res = Command(cmd="devcon -r remove \"{}\"".format(pnp_driver.HardWareID)).run()
                if res["returncode"] != 0:
                    output = "".join(res["output"])
                    if "restart" in output.lower() or "reboot" in output.lower():
                        log.warning(
                            "Devcon requested restart. Sleeping {} seconds while system is going to restart".format(
                                self.DEVCON_RESTART_WAIT))
                        # We expect that system will be restarted automatically during sleep
                        time.sleep(self.DEVCON_RESTART_WAIT)
                        log.error("The system was not restarted in time")
                    if not ignore_remove_errors:
                        raise Exception("Failed to remove driver for device {}".format(pnp_driver.HardWareID))

                inf_file = pnp_driver.InfName
                if pnp_driver.InfName is None:
                    log.info("INF file name field is empty in PNP device. Enumerating all devices")
                    res = Command(cmd="pnputil -e", silent=True).run()
                    if res["returncode"] != 0:
                        raise Exception("Failed to enumerate drivers")
                    re_inf = re.compile("Published name : *(oem[0-9]+.inf).*", re.DOTALL)
                    for line in res["output"]:
                        m = re_inf.match(line)
                        if m is not None:
                            inf = m.group(1)
                            if self.vendor.lower() in line.lower():
                                log.info("INF file has been found in: '{}'".format(line))
                                inf_file = inf
                                break

                if inf_file is not None:
                    res = Command(cmd="pnputil -f -d {}".format(inf_file)).run()
                    # TODO: This code sometimes fails but I think it's not a problem for tests
                    # if res["returncode"] != 0:
                    #     raise Exception("Failed to delete INF file {}".format(inf_file))

                self.devcon_rescan()
            else:
                log.info("Driver has been uninstalled")
                break
        if self.is_installed():
            raise Exception("Can't uninstall driver")

    def reset_pci_root_port(self):
        if sys.platform != 'win32':
            raise NotImplementedError()

        vendor = self.get_nic_vendor()
        if vendor == constants.VENDOR_AQUANTIA:
            dev = "Device 1d6a:"
        else:
            raise NotImplementedError()

        try:
            output = subprocess.check_output("lspci -t -v", shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            log.error(e.output)
            raise e

        target = None
        for line in output.splitlines():
            if dev in line:
                # TODO: extend this approach for multiple cards
                target = line.rstrip()
        if target is None:
            log.error(output)
            raise Exception("Device not found in lspci output")

        exp = re.compile('^\s+\+\-(.*)\-\[\d+\]\-+\d+\.\d+\s+Device\s(.*)$')
        m = exp.match(target)
        bridge_hex = m.group(1)
        device_vendor, device_num = m.group(2).split(':')

        try:
            output = subprocess.check_output("lspci -n", shell=True,
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            log.error(e.output)
            raise e

        bridge_line = None
        for line in output.splitlines():
            if bridge_hex in line:
                bridge_line = line.rstrip()
        if bridge_line is None:
            log.error(output)
            raise Exception("{} not found in lspci output".format(bridge_hex))

        [_, cc, vendor_devid, _, revision] = bridge_line.split()
        [vendor, device_id] = vendor_devid.split(':')
        revision = 'REV_' + revision.rstrip(')').upper()
        vendor = 'VEN_' + vendor.upper()
        device_id = 'DEV_' + device_id.upper()
        hwid_part1 = 'PCI\\{0}&{1}'.format(vendor, device_id)

        hwid = None
        for pnp in wmi.WMI().Win32_PnPEntity():
            if pnp.HardwareID is not None and \
                    hwid_part1 in ",".join(pnp.HardwareID):
                hwid = pnp.HardwareID[0]
                break
        if hwid is None:
            raise Exception(
                "There is no hardware ID like {}".format(hwid_part1))

        self.devcon_disable(hwid)
        self.devcon_enable(hwid)

    def install_trusted_certificate(self, cer_file):
        res = Command(cmd="certutil -addstore \"TrustedPublisher\" {}".format(cer_file)).run()
        if res["returncode"] != 0:
            raise Exception("Failed to install certificate {}".format(cer_file))

        res = Command(cmd="certutil -addstore \"Root\" {}".format(cer_file)).run()
        if res["returncode"] != 0:
            if "Cannot add a non-root certificate" in "".join(res["output"]):
                log.warning("Certificate {} was not installed to Root store".format(cer_file))
                return
            raise Exception("Failed to install certificate {}".format(cer_file))

    def check_driver_status(self):
        drv = get_wmi_pnp_devices(self.port)
        if drv[0].Status != "OK":
            msg = 'Driver installation failed: {}'.format(drv[0].Status)
            log.error(msg)
            raise RuntimeError(msg)
        elif drv[0].ConfigManagerErrorCode != 0:
            msg = "Driver installation failed! Config Manager Error Code: {}".format(drv[0].ConfigManagerErrorCode)
            log.error(msg)
            raise RuntimeError(msg)

    @staticmethod
    def remove_all_hidden_devices():
        cmd_all = "devcon findall * | grep -i aqua"
        cmd_present = "devcon find * | grep -i aqua"

        res_all = Command(cmd=cmd_all).run()
        cmd_present = Command(cmd=cmd_present).run()

        hidden_devices = res_all["output"]
        for device in cmd_present["output"]:
            try:
                hidden_devices.remove(device)
            except IndexError as exc:
                log.error("Unexpected IndexError: {}".format(device))
                raise exc

        log.info("Devices to be removed:\n{}".format("\n".join(hidden_devices)))

        RE_DEVCON_FIND = re.compile(r"(.*): .*")
        hw_ids = []
        for device in hidden_devices:
            re_match = RE_DEVCON_FIND.match(device)
            if re_match is not None:
                hw_ids.append(re_match.group(1))

        cmd_remove_tmpl = "devcon /r remove \"@{}\""
        for hw_id in hw_ids:
            res = Command(cmd=cmd_remove_tmpl.format(hw_id)).run()
            if res["returncode"] != 0:
                log.error("Failed to completely remove device {}".format(hw_id))

        WindowsDriver.devcon_rescan()

    def get_aq_firmware_version(self):
        if not self.release_version.startswith("2"):
            raise Exception("Can't get FW version without 2x driver")

        RE_MAJOR = re.compile(r"major\s+:\s+(\d+)")
        RE_MINOR = re.compile(r"minor\s+:\s+(\d+)")
        RE_REVISION = re.compile(r"revision\s+:\s+(\d+)")

        res = Command(cmd="powershell \"Get-WmiObject -Namespace root\\wmi -Class Aq_FirmwareVersion\"").run()
        if res["returncode"] != 0:
            raise Exception("Failed to get FW version using Windows driver")
        major = None
        minor = None
        revision = None
        for line in res["output"]:
            m1 = RE_MAJOR.match(line)
            if m1 is not None:
                major = m1.group(1)
            m2 = RE_MINOR.match(line)
            if m2 is not None:
                minor = m2.group(1)
            m3 = RE_REVISION.match(line)
            if m3 is not None:
                revision = m3.group(1)
        if all([major, minor, revision]):
            return major + "." + minor + "." + revision
        else:
            raise Exception("Couldn't extract FW version from command output")

    def get_aq_diagnostics_data(self):
        if not self.release_version.startswith("2"):
            raise Exception("Can't get FW version without 2x driver")

        res = Command(
            cmd="powershell \"Get-WmiObject -Namespace root\\wmi -Class Aq_DiagnosticsData | ConvertTo-Json -Depth 3\"",
            silent=True
        ).run()
        if res["returncode"] != 0:
            raise Exception("Failed to get Diagnostics Data using Windows driver")

        j = json.loads("\n".join(res["output"]))

        d = {
            "cableLength": j["cableLength"],
            "mpiControl": j["mpiControl"],
            "mpiState": j["mpiState"],
            "macTemperature": next(
                prop["Value"] for prop in j["thermalInfo"]["Properties"] if prop["Name"] == "macTemperature"),
            "phyTemperature": next(
                prop["Value"] for prop in j["thermalInfo"]["Properties"] if prop["Name"] == "phyTemperature"),
            "txPathResetCount": j["txPathResetCount"],
            "txWatchdogEventCount": j["txWatchdogEventCount"]
        }

        return d

    def restart_wmi(self):
        Command(cmd="net stop winmgmt /Y").run()
        Command(cmd="net start winmgmt").run()


class LinuxDriver(DriverLocal):
    ALL_AQUANTIA_KO_NAMES = ["aqdiag", "atlantic", "atlantic_fwd", "aqc111", "if_atlantic", "atl_tsn"]
    vendor_to_module_map = {
        constants.VENDOR_AQUANTIA: "atlantic",
        constants.VENDOR_INTEL: "ixgbe",
        constants.VENDOR_TEHUTI: "tn40xx"
    }

    def __init__(self, **kwargs):
        super(LinuxDriver, self).__init__(**kwargs)
        self.module = self.vendor_to_module_map[self.vendor]
        self.pci_bus_dir = '/sys/bus/pci/drivers/'
        self.driver_dir = os.path.join(self.pci_bus_dir, self.sysfs_name)
        domain, bus, dev, func = get_domain_bus_dev_func(self.port)
        self.pci_port = '{:04x}:{:02x}:{:02x}.{:01x}'.format(domain, bus, dev, func)
        if "usb" not in self.port:
            self.atltool = AtlTool(port=self.port)

    def get_nic_vendor(self):
        for i in range(3):
            if "usb" in self.port:
                cmd = "sudo lsusb"
                log.info("Running command '{}'".format(cmd))
                output = Command(cmd=cmd).run()["output"]
                for line in output:
                    if "2eca" in line:
                        return constants.VENDOR_AQUANTIA
            else:
                domain, bus, dev, func = get_domain_bus_dev_func(self.port)
                bus_address = '{:04x}:{:02x}:{:02x}.{:01x}'.format(domain, bus, dev, func)
                cmd = "sudo lspci -Dmm -s {}".format(bus_address)
                output = "\n".join(Command(cmd=cmd).run()["output"])

                if "1d6a" in output.lower() or "aquantia" in output.lower():
                    return constants.VENDOR_AQUANTIA
                if "intel" in output.lower():
                    return constants.VENDOR_INTEL
                if "tehuti" in output.lower():
                    return constants.VENDOR_TEHUTI

                time.sleep(1)

        log.error('Device not found, checking current device list')
        if "usb" in self.port:
            Command(cmd="sudo lsusb").run()
        else:
            Command(cmd="sudo lspci -mm").run()

        return constants.VENDOR_UNKNOWN

    def rmmod(self, module=None):
        if module is None:
            module = self.module
        log.info("Uninstalling module {}".format(module))
        cmd = "sudo rmmod {}".format(module)
        try:
            log.info("Running command '{}'".format(cmd))
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            log.info("Module has been uninstalled")
        except subprocess.CalledProcessError as e:
            if "not currently loaded" not in e.output:
                log.error(e.output)
                raise e
            log.info("Module is not loaded, nothing to uninstall")

    def insmod(self, _file):
        log.info("Installing module {}".format(_file))

        Command(cmd="sudo modprobe ptp").wait(30)
        Command(cmd="sudo modprobe crc_itu_t").wait(30)

        cmd = "sudo insmod {}".format(_file)
        if "usb" in self.port:
            Command(cmd="sudo modprobe usbnet").wait(30)

        try:
            log.info("Running command '{}'".format(cmd))
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            log.error(e.output)
            raise e
        log.info("Module has been installed")

    def download_fw(self):
        hostload_dir = "/storage/export/builds/firmware/{}/Customers_AqSign/hostload/*.fw".format(self.flashless_fw)
        firmware_dir = "/lib/firmware/mrvl"
        Command(cmd="sudo rm /lib/firmware/mrvl/*.fw").run_join()
        Command(cmd="sudo mkdir {}/".format(firmware_dir)).run_join()
        res = download_file("qa-nfs01", "{}".format(hostload_dir), "{}".format(firmware_dir))

    def get_kernel_release(self):
        try:
            output = subprocess.check_output("uname -r", shell=True,
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            log.error(e.output)
            raise e
        return output.rstrip("\r\n")

    @staticmethod
    def list_aq_devices():
        pci_devices_dir = '/sys/bus/pci/devices/'
        ports = os.listdir(pci_devices_dir)
        pci_aq_devices = []
        for port in ports:
            with open(os.path.join(pci_devices_dir, port, 'vendor')) as f:
                vendor_id = f.read().strip()
            if vendor_id == '0x1d6a':
                # convert from "0000:01:00.0" to "pci1.0.0"
                # TODO: PCIe domains are not supported
                pointed_digits = '.'.join([i for i in port.split(':')[1:]])
                port = 'pci' + '.'.join([str(int(i, 16)) for i in pointed_digits.split('.')])

                pci_aq_devices.append(port)
        return pci_aq_devices

    def is_loaded(self):
        with open('/proc/modules') as f:
            return self.sysfs_name in f.read()

    def load(self, os_driver_file_path):
        try:
            output = subprocess.check_output('insmod  {}/{}.ko'.format(os_driver_file_path, self.sysfs_name), shell=True)
            if any(output.splitlines()):
                raise RuntimeError("Failed to load driver: {}/{}.ko".format(os_driver_file_path, self.sysfs_name))
            print '"{}" driver has been loaded'.format(self.sysfs_name)
        except subprocess.CalledProcessError:
            raise RuntimeError("Cannot load driver: {}/{}.ko".format(os_driver_file_path, self.sysfs_name))

    def unload(self):
        try:
            output = subprocess.check_output('rmmod {}'.format(self.sysfs_name), shell=True)
            if any(output.splitlines()):
                raise RuntimeError('Failed to unload "{}" driver'.format(self.sysfs_name))
            print '"{}" driver has been unloaded'.format(self.sysfs_name)
        except (subprocess.CalledProcessError, OSError):
            raise RuntimeError('Cannot unload "{}" driver'.format(self.sysfs_name))

    def is_bound(self):
        if self.pci_port is None:
            return False  # can't bind to unknown device
        return os.path.exists(self.driver_dir) and self.pci_port in os.listdir(self.driver_dir)

    def bind(self):
        err_msg = 'Failed to bind "{}" driver from PCIe port {}'.format(self.sysfs_name, self.pci_port)
        cmd = "echo -n {} | sudo tee -a {}/bind".format(self.pci_port, self.driver_dir)
        res = Command(cmd=cmd).run()
        assert res["returncode"] == 0, err_msg
        if not self.is_bound():
            raise Exception(err_msg)
        log.info('"{}" driver has been enabled'.format(self.sysfs_name))

    def unbind(self):
        err_msg = 'Failed to unbind "{}" driver from PCIe port {}'.format(self.sysfs_name, self.pci_port)
        cmd = "echo -n {} | sudo tee -a {}/unbind".format(self.pci_port, self.driver_dir)
        res = Command(cmd=cmd).run()
        assert res["returncode"] == 0, err_msg
        if self.is_bound():
            raise Exception(err_msg)
        log.info('"{}" driver has been disabled'.format(self.sysfs_name))

    def check_ko_loaded(self, name):
        if name not in self.ALL_AQUANTIA_KO_NAMES:
            raise Exception("Unknown KO name")
        re_c = re.compile("([a-z0-9_]+) *[0-9]+ *[0-9]")
        for ko_name in self.ALL_AQUANTIA_KO_NAMES:
            res = Command(cmd="lsmod | grep ^{}".format(ko_name)).run()
            if ko_name == name:
                assert res["returncode"] == 0
                for str in res["output"]:
                    if name != re_c.match(str).group(1):
                        raise Exception("Invalid KO found: {}".format(re_c.match(str).group(1)))
            else:
                for str in res["output"]:
                    if ko_name == re_c.match(str).group(1):
                        raise Exception("Invalid KO found: {}".format(ko_name))

    def add_blacklist(self, blacklist_name):
        if blacklist_name not in ["atlantic", "atlantic_fwd"]:
            Exception()
        if not os.path.exists("/etc/modprobe.d/blacklist-module-{}.conf".format(blacklist_name)):
            Command(cmd="echo 'blacklist {}' | sudo tee /etc/modprobe.d/blacklist-module-{}.conf ; "
                        "sync".format(blacklist_name, blacklist_name)).run()
            Command(cmd="sudo update-initramfs -u").run()

    def remove_blacklist(self, blacklist_name):
        if blacklist_name not in ["atlantic", "atlantic_fwd"]:
            Exception()
        if os.path.exists("/etc/modprobe.d/blacklist-module-{}.conf".format(blacklist_name)):
            Command(cmd="sudo rm /etc/modprobe.d/blacklist-module-{}.conf".format(blacklist_name)).run()
            Command(cmd="sudo update-initramfs -u").run()


class MacDriver(DriverLocal):
    KNOWN_BUNDLE_IDS = ["com.aquantia.driver.atl01x",
                        "com.apple.driver.AppleEthernetAquantiaAqtion",
                        "com.aquantia.simple",
                        "com.aquantia.driver.usb.pacific",
                        "com.apple.driver.usb.cdc.ecm",
                        "com.apple.driver.usb.cdc.acm",
                        "com.apple.driver.usb.cdc.ncm",
                        "com.apple.driver.usb.cdc"]

    BUNDLE_ID_TO_DARWIN_PKG_NAME = {
        "com.apple.driver.AppleEthernetAquantiaAqtion": "AppleEthernetAquantiaAqtion"
    }

    def __init__(self, **kwargs):
        super(MacDriver, self).__init__(**kwargs)

    def get_nic_vendor(self):
        bus, _, __ = get_bus_dev_func(self.port)
        if "usb" in self.port:
            cmd = "ioreg -c IOUSBDevice -x | grep -A5 -i {}".format(constants.VENDOR_AQUANTIA)
        else:
            cmd = "ioreg -c IOPCIDevice -x | grep -B30 -A5 {}:0:0 | grep vendor-id".format(bus)
        res = Command(cmd=cmd).run_join(30)
        if res["returncode"] != 0:
            raise Exception("Failed to obtain vendor id via ioreg")
        for line in res["output"]:
            if "1d6a" in line or "6a1d" in line or "0x2eca" in line:
                return constants.VENDOR_AQUANTIA
        return constants.VENDOR_UNKNOWN

    def list_kext_drivers(self):
        re_bundle_id = re.compile("com\.[a-zA-Z0-9]+\.driver\.([a-zA-Z0-9]+)")

        cmd = Command(cmd="sudo kextstat")
        cmd.run_async()
        res = cmd.join(1)
        if res["returncode"] != 0:
            raise Exception("Failed to run kextstat")

        for line in res["output"]:
            m = re_bundle_id.match(line)
            if m is not None:
                yield m.group(1)

    def kextload(self, bundle):
        subdirs = os.listdir(bundle)
        if len(subdirs) != 1:
            log.debug("Subdirs: {}".format(subdirs))
            raise Exception("Driver bundle should contain only one dir in zip")

        kext_dir = subdirs[0]
        kext_path = os.path.join(bundle, kext_dir)
        cmd = Command(cmd="sudo chown -R root:wheel {}".format(kext_path))
        res = cmd.run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to change KEXT ownership")

        cmd = "sudo kextload {}".format(kext_path)
        res = Command(cmd=cmd).run_join(60)
        if res["returncode"] != 0:
            raise Exception("Failed to load bundle")

        res = Command(cmd="kextstat", silent=True).run_join(5)
        if res["returncode"] != 0:
            raise Exception("Failed to get list of loaded bundles")

        for line in res["output"]:
            if any([b in line for b in self.KNOWN_BUNDLE_IDS]):
                log.info("Bundle is loaded successfully")
                #if "usb" in self.port:
                #    usb_control = USBControl(device=constants.USB_CONNECT_CSWITCH)
                #    usb_control.disable(0)
                #    time.sleep(20)
                #    usb_control.enable(0)
                return
        raise Exception("Failed to load bundle")

    def kextunload(self, bundle_id):
        res = Command(cmd="kextstat | grep {}".format(bundle_id)).run_join(30)
        if len(res["output"]) > 0 and bundle_id in res["output"][0]:
            res = Command(cmd="sudo kextunload -b {}".format(bundle_id)).run_join(60)
            if res["returncode"] != 0:
                cmd1 = "sudo kill `ps -ax | grep 'coreaudiod' | grep 'sbin' |awk '{print $1}'`"
                cmd2 = "sudo kextunload -b com.apple.AppleEthernetAquantiaAqtionFirmware"
                cmd3 = "sudo kextunload -b {}".format(bundle_id)
                Command(cmd=cmd1).run_join(60)
                Command(cmd=cmd2).run_join(60)
                res = Command(cmd=cmd3).run_join(60)
                if res["returncode"] != 0:
                    raise Exception("Failed to unload bundle {}".format(bundle_id))

    def uninstall(self, ignore_remove_errors=False):
        for bundle_id in self.KNOWN_BUNDLE_IDS:
            self.kextunload(bundle_id)

            pkg = self.BUNDLE_ID_TO_DARWIN_PKG_NAME.get(bundle_id, None)
            if pkg is not None:
                res = Command(cmd="darwinup list | grep {} | awk '{{print $7}}'".format(pkg)).run_join(30)
                if len(res["output"]) > 0 and pkg in res["output"][0]:
                    res = Command(cmd="sudo darwinup -f uninstall {}".format(res["output"][0])).run_join(180)
                name_pkg = Command(cmd="darwinup list | grep {} | awk '{{print $7}}'".format(pkg)).run_join(30)
                if len(name_pkg["output"]) > 0 and pkg in name_pkg["output"][0]:
                    res = Command(cmd="sudo darwinup -f uninstall {}".format(name_pkg["output"][0])).run_join(180)
                    if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                        res = Command(cmd="sudo rm /usr/local/bin/aeaa_util /usr/local/bin/aeaa_script.d; sudo darwinup -f uninstall {}".format(name_pkg["output"][0])).run_join(180)
                        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                            raise Exception("Failed to uninstall package {}".format(pkg))
        res = Command(cmd="sudo kextcache -invalidate /").run_join(1800)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to clear kext cache")

    def get_macos_device_bundle_name(self):
        cmd = Command(cmd="kextstat", silent=True)
        res = cmd.run_join(3)
        if res["returncode"] != 0:
            raise Exception("Failed to run kextstat")

        for line in res["output"]:
            for bundle in self.KNOWN_BUNDLE_IDS:
                if bundle in line:
                    return bundle

        return None


class NdisDriver(WindowsDriver):
    drv_type = DRV_TYPE_NDIS

    def __init__(self, **kwargs):
        super(NdisDriver, self).__init__(**kwargs)

    def install(self):
        release_version = self.release_version
        log.info("Installing NDIS driver")
        # log.info("Checking driver for port {}".format(self.port))
        # pnp_driver = get_wmi_device_pnp_driver(self.port)
        # if pnp_driver and pnp_driver.DriverVersion:
        #     log.info("Found installed driver: '{}', Version: {}".format(pnp_driver.FriendlyName,
        #                                                                 pnp_driver.DriverVersion))
        #     # Convert release version to windows driver version (remove leading zeros)
        #     rel_ver_conv = ".".join(str(int(val)) for val in release_version.split("."))
        #     if pnp_driver.DriverVersion == rel_ver_conv:
        #         log.info("Installed driver and requested driver versions are the same, skipping installation")
        #         return
        #     else:
        #         log.info("Current driver will be removed")

        OS_TO_INF_MAP_X1_STYLE = {
            constants.OS_WIN7_32: "Win7/atlantic620.inf",
            constants.OS_WIN7_64: "Win7/atlantic620.inf",
            constants.OS_WIN8_32: "Win8/atlantic630.inf",
            constants.OS_WIN8_64: "Win8/atlantic630.inf",
            constants.OS_WIN8_1_32: "Win8.1/atlantic640.inf",
            constants.OS_WIN8_1_64: "Win8.1/atlantic640.inf",
            constants.OS_WIN10_32: "Win10/atlantic650.inf",
            constants.OS_WIN10_64: "Win10/atlantic650.inf",
            constants.OS_WIN10_1_32: "Win10/atlantic650.inf",
            constants.OS_WIN10_1_64: "Win10/atlantic650.inf",
            constants.OS_WIN10_2_32: "Win10/atlantic650.inf",
            constants.OS_WIN10_2_64: "Win10/atlantic650.inf",
            constants.OS_WIN10_3_32: "Win10/atlantic650.inf",
            constants.OS_WIN10_3_64: "Win10/atlantic650.inf",
            constants.OS_WIN10_4_32: "Win10/atlantic650.inf",
            constants.OS_WIN10_4_64: "Win10/atlantic650.inf",
            constants.OS_WIN10_5_32: "Win10/atlantic650.inf",
            constants.OS_WIN10_5_64: "Win10/atlantic650.inf",
            constants.OS_WIN10_6_32: "Win10/atlantic650.inf",
            constants.OS_WIN10_6_64: "Win10/atlantic650.inf",
        }
        OS_TO_INF_MAP_X2_STYLE = {
            constants.OS_WIN7_32: "win7/drv/aqnic620.inf",
            constants.OS_WIN7_64: "win7/drv/aqnic620.inf",
            constants.OS_WIN8_32: "win8/drv/aqnic630.inf",
            constants.OS_WIN8_64: "win8/drv/aqnic630.inf",
            constants.OS_WIN8_1_32: "win8.1/drv/aqnic640.inf",
            constants.OS_WIN8_1_64: "win8.1/drv/aqnic640.inf",
            constants.OS_WIN10_32: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_64: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_1_32: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_1_64: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_2_32: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_2_64: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_3_32: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_3_64: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_4_32: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_4_64: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_5_32: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_5_64: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_6_32: "win10/drv/aqnic650.inf",
            constants.OS_WIN10_6_64: "win10/drv/aqnic650.inf",
            constants.OS_WINSRV_2019: "win10/drv/aqnic650.inf",
        }
        OS_TO_INF_MAP_X3_STYLE = {
            constants.OS_WIN7_32: None,
            constants.OS_WIN7_64: None,
            constants.OS_WIN8_32: None,
            constants.OS_WIN8_64: None,
            constants.OS_WIN8_1_32: None,
            constants.OS_WIN8_1_64: None,
            constants.OS_WIN10_32: "win10/aqnic650.inf",
            constants.OS_WIN10_64: "win10/aqnic650.inf",
            constants.OS_WIN10_1_32: "win10/aqnic650.inf",
            constants.OS_WIN10_1_64: "win10/aqnic650.inf",
            constants.OS_WIN10_2_32: "win10/aqnic650.inf",
            constants.OS_WIN10_2_64: "win10/aqnic650.inf",
            constants.OS_WIN10_3_32: "win10/aqnic650.inf",
            constants.OS_WIN10_3_64: "win10/aqnic650.inf",
            constants.OS_WIN10_4_32: "win10/aqnic650.inf",
            constants.OS_WIN10_4_64: "win10/aqnic650.inf",
            constants.OS_WIN10_5_32: "win10/aqnic650.inf",
            constants.OS_WIN10_5_64: "win10/aqnic650.inf",
            constants.OS_WIN10_6_32: "win10/aqnic650.inf",
            constants.OS_WIN10_6_64: "win10/aqnic650.inf",
            constants.OS_WINSRV_2019: "win10/aqnic650.inf",
        }
        OS_TO_INF_MAP_X2_INBOX_STYLE = {
            constants.OS_WIN7_32: "win7/drv/aqnic620_Inbox.inf",
            constants.OS_WIN7_64: "win7/drv/aqnic620_Inbox.inf",
            constants.OS_WIN8_32: "win8/drv/aqnic630_Inbox.inf",
            constants.OS_WIN8_64: "win8/drv/aqnic630_Inbox.inf",
            constants.OS_WIN8_1_32: "win8.1/drv/aqnic640_Inbox.inf",
            constants.OS_WIN8_1_64: "win8.1/drv/aqnic640_Inbox.inf",
            constants.OS_WIN10_32: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_64: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_1_32: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_1_64: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_2_32: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_2_64: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_3_32: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_3_64: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_4_32: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_4_64: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_5_32: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_5_64: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_6_32: "win10/drv/aqnic650_Inbox.inf",
            constants.OS_WIN10_6_64: "win10/drv/aqnic650_Inbox.inf",
        }
        OS_TO_INF_MAP_PACIFIC = {
            constants.OS_WIN7_32: None,
            constants.OS_WIN7_64: None,
            constants.OS_WIN8_32: "driver/NETAQC101.inf",
            constants.OS_WIN8_64: "driver/NETAQC101.inf",
            constants.OS_WIN8_1_32: "driver/NETAQC101.inf",
            constants.OS_WIN8_1_64: "driver/NETAQC101.inf",
            constants.OS_WIN10_32: "driver/NETAQC101.inf",
            constants.OS_WIN10_64: "driver/NETAQC101.inf",
            constants.OS_WIN10_1_32: "driver/NETAQC101.inf",
            constants.OS_WIN10_1_64: "driver/NETAQC101.inf",
            constants.OS_WIN10_2_32: "driver/NETAQC101.inf",
            constants.OS_WIN10_2_64: "driver/NETAQC101.inf",
            constants.OS_WIN10_3_32: "driver/NETAQC101.inf",
            constants.OS_WIN10_3_64: "driver/NETAQC101.inf",
            constants.OS_WIN10_4_32: "driver/NETAQC101.inf",
            constants.OS_WIN10_4_64: "driver/NETAQC101.inf",
            constants.OS_WIN10_5_32: "driver/NETAQC101.inf",
            constants.OS_WIN10_5_64: "driver/NETAQC101.inf",
            constants.OS_WIN10_6_32: "driver/NETAQC101.inf",
            constants.OS_WIN10_6_64: "driver/NETAQC101.inf",
        }

        OS_TO_INF_MAP_AQ_PACIFIC = {
            constants.OS_WIN7_32: None,
            constants.OS_WIN7_64: None,
            constants.OS_WIN8_32: "aqnicusb.inf",
            constants.OS_WIN8_64: "aqnicusb.inf",
            constants.OS_WIN8_1_32: "aqnicusb.inf",
            constants.OS_WIN8_1_64: "aqnicusb.inf",
            constants.OS_WIN10_32: "aqnicusb.inf",
            constants.OS_WIN10_64: "aqnicusb.inf",
            constants.OS_WIN10_1_32: "aqnicusb.inf",
            constants.OS_WIN10_1_64: "aqnicusb.inf",
            constants.OS_WIN10_2_32: "aqnicusb.inf",
            constants.OS_WIN10_2_64: "aqnicusb.inf",
            constants.OS_WIN10_3_32: "aqnicusb.inf",
            constants.OS_WIN10_3_64: "aqnicusb.inf",
            constants.OS_WIN10_4_32: "aqnicusb.inf",
            constants.OS_WIN10_4_64: "aqnicusb.inf",
            constants.OS_WIN10_5_32: "aqnicusb.inf",
            constants.OS_WIN10_5_64: "aqnicusb.inf",
            constants.OS_WIN10_6_32: "aqnicusb.inf",
            constants.OS_WIN10_6_64: "aqnicusb.inf",
        }

        OS_TO_INF_MAP_LIBUSBK = {
            constants.OS_WIN7_32: None,
            constants.OS_WIN7_64: None,
            constants.OS_WIN8_32: "pacific.inf",
            constants.OS_WIN8_64: "pacific.inf",
            constants.OS_WIN8_1_32: "pacific.inf",
            constants.OS_WIN8_1_64: "pacific.inf",
            constants.OS_WIN10_32: "pacific.inf",
            constants.OS_WIN10_64: "pacific.inf",
            constants.OS_WIN10_1_32: "pacific.inf",
            constants.OS_WIN10_1_64: "pacific.inf",
            constants.OS_WIN10_2_32: "pacific.inf",
            constants.OS_WIN10_2_64: "pacific.inf",
            constants.OS_WIN10_3_32: "pacific.inf",
            constants.OS_WIN10_3_64: "pacific.inf",
            constants.OS_WIN10_4_32: "pacific.inf",
            constants.OS_WIN10_4_64: "pacific.inf",
            constants.OS_WIN10_5_32: "pacific.inf",
            constants.OS_WIN10_5_64: "pacific.inf",
            constants.OS_WIN10_6_32: "pacific.inf",
            constants.OS_WIN10_6_64: "pacific.inf",
        }

        arch = self.arch
        if arch in constants.KNOWN_X86_ARCHES:
            arch = "x86"
        zip_file = "{}.zip".format(arch)

        if self.vendor == constants.VENDOR_AQUANTIA:
            if not self.version.startswith('atlantic2/builds'):
                suburl = "driver/ndis/{}/{}/{}".format(self.vendor, self.version, zip_file)
            else:
                if 'x86_64' == arch:
                    arch = "x64"
                zip_file = "Aquantia_AQtion_{}_Win_ver{}.zip".format(arch, release_version)
                suburl = "driver/ndis/{}/{}/bin/{}".format(self.vendor, self.version, zip_file)
        elif self.vendor == constants.VENDOR_QNAP:
            suburl = "driver/ndis/{}/{}/{}".format(constants.VENDOR_AQUANTIA, self.version, zip_file)
        elif self.vendor == constants.VENDOR_PACIFIC:
            suburl = "driver/ndis/{}/{}/{}".format(self.vendor, self.version, zip_file)
        elif self.vendor == constants.VENDOR_APPLE:
            suburl = "driver/ndis/{}/{}/{}".format(self.vendor, "latest", zip_file)
        elif self.vendor == constants.VENDOR_DLINK:
            suburl = "driver/ndis/{}/{}/{}".format(self.vendor, "latest", zip_file)
        elif self.vendor == constants.VENDOR_REALTEK:
            suburl = "driver/ndis/{}/{}/{}".format(self.vendor, "latest", zip_file)
        elif self.vendor == constants.VENDOR_TEHUTI:
            suburl = "driver/ndis/{}/{}/{}".format(self.vendor, "latest", zip_file)
        elif self.vendor == constants.VENDOR_TPLINK:
            suburl = "driver/ndis/{}/{}/{}".format(self.vendor, "latest", zip_file)
        else:
            log.debug("Device vendor is '{}'".format(self.vendor))
            raise NotImplementedError()

        if self.vendor in [constants.VENDOR_AQUANTIA, constants.VENDOR_QNAP]:
            log.info("Version of the driver is {}".format(release_version))
            if release_version.startswith("1"):
                if self.version.startswith("pacific"):
                    log.info("This is pacific driver by Aquantia")
                    os_to_inf_map = OS_TO_INF_MAP_AQ_PACIFIC
                else:
                    log.info("This is 1x driver")
                    os_to_inf_map = OS_TO_INF_MAP_X1_STYLE
            elif release_version.startswith("2"):
                log.info("This is 2x driver")
                os_to_inf_map = OS_TO_INF_MAP_X2_STYLE
            elif release_version.startswith("3"):
                log.info("This is 3x driver")
                os_to_inf_map = OS_TO_INF_MAP_X3_STYLE
            elif release_version.startswith("0.1") and self.version.startswith("pacific"):
                log.info("This is pacific driver by ASIX")
                os_to_inf_map = OS_TO_INF_MAP_PACIFIC
            elif release_version.startswith("0.2") and self.version.startswith("pacific"):
                log.info("This is pacific driver by Aquantia")
                os_to_inf_map = OS_TO_INF_MAP_AQ_PACIFIC
            elif release_version.startswith("libusbk") and self.version.startswith("pacific"):
                log.info("This is pacific driver by libusbk")
                os_to_inf_map = OS_TO_INF_MAP_LIBUSBK
            else:
                raise NotImplementedError()

        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Downloading NDIS driver from {}".format(url))
        content = get_url_response(url)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            archive.extractall(arch)

        log.info("Uninstalling old package if exists")
        self.uninstall()

        log.info("Additionally try to uninstall INF driver if it exists")
        self.uninstall_inf_driver()

        if self.vendor in [constants.VENDOR_AQUANTIA, constants.VENDOR_QNAP]:
            inf_file = os.path.join(arch, os_to_inf_map[self.ops])

            # TODO: in case of pure Apple IDs use specific inf file
            if self.port.startswith("pci"):
                hwid = get_wmi_pnp_devices(self.port)[0].DeviceID
                if "PCI\\VEN_1D6A&DEV_07B1&SUBSYS_0187106B" in hwid:
                    inf_file = inf_file[0:-4] + "_Apple.inf"

            # TODO: remove this code in the future for 2x driver
            if not os.path.exists(inf_file) and release_version.startswith("2"):
                log.info("Normal INF file {} doesn't exist, checking inbox variant".format(inf_file))
                inf_file = os.path.join(arch, OS_TO_INF_MAP_X2_INBOX_STYLE[self.ops])
                if not os.path.exists(inf_file):
                    log.warning("INF file {} doesn't exist, switching to X1 variant".format(inf_file))
                    inf_file = os.path.join(arch, OS_TO_INF_MAP_X1_STYLE[self.ops])
                else:
                    log.info("Inbox INF file {} was found".format(inf_file))

            drv_folder = os.path.dirname(os.path.abspath(inf_file))
            cer_files = glob.glob(os.path.join(drv_folder, "*.cer"))
            if len(cer_files) > 1:
                raise Exception("Too many CER files: {}".format(cer_files))
            elif len(cer_files) == 1:
                cer_file = cer_files[0]
            else:
                log.info("Generating CER file")

                cmd_ps = "powershell.exe -command \"{}\""
                cmd_cer = "[System.IO.File]::WriteAllBytes('{}.cer', (Get-AuthenticodeSignature .\{}.sys)." \
                          "SignerCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))"
                if self.version.startswith("pacific"):
                    if release_version.startswith("0.2") or release_version.startswith("1"):
                        name = "aqnicusb"
                    elif release_version.startswith("0.9"):
                        name = "aqc101"
                    else:
                        name = r"driver\aqc101"
                if self.version.startswith("atlantic2/builds"):
                    if ops.OpSystem().is_win10():
                        name = r"win10\aqnic650"
                    path = os.path.join(arch, name + ".inf")
                    if not os.path.exists(path):
                        raise Exception(path)
                if self.version.startswith("2x"):
                    if ops.OpSystem().is_win10():
                        name = r"win10\drv\aqnic650"
                    elif ops.OpSystem().is_win8():
                        name = r"win8\drv\aqnic630"
                    elif ops.OpSystem().is_win81():
                        name = r"win8.1\drv\aqnic640"
                    elif ops.OpSystem().is_win7():
                        name = r"win7\drv\aqnic620"
                    path = os.path.join(arch, name + ".inf")
                    if not os.path.exists(path):
                        raise Exception(path)
                cmd_cer = cmd_cer.format(os.path.join(arch, name), os.path.join(arch, name))

                Command(cmd=cmd_ps.format(cmd_cer)).run_join(30)
                time.sleep(1)
                cer_file = os.path.join(arch, "{}.cer".format(name))

            if os.path.exists(cer_file):
                self.install_trusted_certificate(cer_file)
            else:
                log.warning("CER file {} doesn't exists".format(cer_file))
        elif self.vendor == constants.VENDOR_APPLE:
            inf_file = os.path.join(arch, "AppleUSBEthernet.inf")
        elif self.vendor == constants.VENDOR_DLINK:
            inf_file = os.path.join(arch, "DUB-13X2.inf")
        elif self.vendor == constants.VENDOR_REALTEK:
            inf_file = os.path.join(arch, "rtux64w10.INF")
        elif self.vendor == constants.VENDOR_TEHUTI:
            inf_file = os.path.join(arch, "TN40xxmp_.inf")
        elif self.vendor == constants.VENDOR_TPLINK:
            inf_file = os.path.join(arch, "rtux64w10.INF")
        else:
            raise NotImplementedError()

        log.info("Installing driver {}".format(inf_file))
        self.devcon_update_driver(self.port, inf_file)
        self.devcon_rescan()
        remove_directory(arch)
        self.check_driver_status()
        log.info("Driver has been installed successfully")

    def uninstall(self, ignore_remove_errors=False):
        self.uninstall_inf_driver(ignore_remove_errors=ignore_remove_errors)

    def is_installed(self):
        log.info("Checking NDIS driver for port {}".format(self.port))
        self.restart_wmi()
        pnp_driver = get_wmi_device_pnp_driver(self.port)
        if pnp_driver is None or pnp_driver.DeviceName is None:
            log.info("Installed driver was not found")
            return False
        elif pnp_driver.DeviceClass == "NET":
            log.info("Installed NDIS driver was found")
            return True
        else:
            log.info("Another installed driver was found")
            return False


class WindowsDiagDriver(WindowsDriver):
    drv_type = DRV_TYPE_DIAG_WIN

    def __init__(self, **kwargs):
        super(WindowsDiagDriver, self).__init__(**kwargs)

    def install(self):
        log.info("Installing diag driver")
        arch = self.arch
        if arch in constants.KNOWN_X86_ARCHES:
            arch = "x86"
        _file = "{}.zip".format(arch)
        suburl = "driver/diag/win/stable/{}".format(_file)
        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Downloading WIN DIAG driver from {}".format(url))
        content = get_url_response(url)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            archive.extractall(arch)

        log.info("Uninstalling old package if exists")
        self.uninstall()
        log.info("Additionally try to uninstall INF driver if it exists")
        self.uninstall_inf_driver()

        cer_file = os.path.join(arch, "aquantiaDiagPack.cer")
        inf_file = os.path.join(arch, "aquantiaDiagPack/aquantiaDiag.inf")

        if os.path.exists(cer_file):
            self.install_trusted_certificate(cer_file)
        else:
            log.warning("CER file {} doesn't exists".format(cer_file))

        log.info("Installing driver {}".format(inf_file))
        self.devcon_update_driver(self.port, inf_file)
        self.devcon_rescan()
        remove_directory(arch)
        self.check_driver_status()
        log.info("Driver has been installed successfully")

    def uninstall(self, ignore_remove_errors=False):
        self.uninstall_inf_driver(ignore_remove_errors=ignore_remove_errors)

    def is_installed(self):
        log.info("Checking diag driver for port {}".format(self.port))
        self.restart_wmi()
        pnp_driver = get_wmi_device_pnp_driver(self.port)
        if pnp_driver is None or pnp_driver.DeviceName is None:
            log.info("Installed driver was not found")
            return False
        elif pnp_driver.DeviceClass == "SAMPLE":
            log.info("Installed diag driver was found")
            return True
        else:
            log.info("Another installed driver was found")
            return False


class WindowsDiagDriverUSB(WindowsDriver):
    drv_type = DRV_TYPE_DIAG_WIN_USB

    def __init__(self, **kwargs):
        super(WindowsDiagDriverUSB, self).__init__(**kwargs)

    def install(self):
        arch = self.arch
        if arch in constants.KNOWN_X86_ARCHES:
            arch = "x86"
        _file = "{}.zip".format(arch)
        suburl = "driver/ndis/aquantia/pacific/pacific_diag/{}".format(_file)
        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Downloading WIN DIAG driver for USB from {}".format(url))
        content = get_url_response(url)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            archive.extractall(arch)

        log.info("Uninstalling old package if exists")
        self.uninstall()

        # TODO: Separate method in base class WindowsDriver for future use with this command
        cmd_cer = os.path.join(arch, "dpscat.exe /PATH {}".format(arch))
        Command(cmd=cmd_cer).run_join(30)
        inf_file = os.path.join(arch, "pacific.inf")

        log.info("Installing driver {}".format(inf_file))
        self.devcon_update_driver(self.port, inf_file)
        self.devcon_rescan()
        remove_directory(arch)
        self.check_driver_status()
        log.info("Driver has been installed successfully")

    def uninstall(self, ignore_remove_errors=False):
        self.uninstall_inf_driver(ignore_remove_errors=ignore_remove_errors)

    def is_installed(self):
        log.info("Checking USB auxiliary driver for port {}".format(self.port))
        self.restart_wmi()
        pnp_driver = get_wmi_device_pnp_driver(self.port)
        if pnp_driver is None or pnp_driver.DeviceName is None:
            log.info("Installed driver was not found")
            return False
        elif pnp_driver.DeviceClass == "LIBUSBK USB DEVICES":
            log.info("Installed USB auxiliary driver was found")
            return True
        else:
            log.info("Another installed driver was found")
            return False


class MsiDriver(WindowsDriver):
    drv_type = DRV_TYPE_MSI

    def __init__(self, **kwargs):
        super(MsiDriver, self).__init__(**kwargs)

    def install(self, ignore_remove_errors=False):
        _file = "Aquantia_AQtion_x{}_Win_ver{}.msi".format(self.arch[-2:],
                                                           self.release_version)
        suburl = "driver/msi/aquantia/{}/{}".format(self.version, _file)
        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Downloading MSI driver from {}".format(url))
        content = get_url_response(url)
        with open(_file, "wb") as f:
            f.write(content)

        log.info("Uninstalling old driver if exists")
        self.uninstall()
        log.info("Additionally try to uninstall INF driver if it exists")
        self.uninstall_inf_driver(ignore_remove_errors=ignore_remove_errors)

        cmd = "{} /q".format(_file)
        try:
            log.info("Running command '{}'".format(cmd))
            output = subprocess.check_output(cmd, shell=True,
                                             stderr=subprocess.STDOUT)
            log.debug("Command output:")
            log.debug(output.rstrip("\r\n"))
        except subprocess.CalledProcessError as e:
            log.error(e.output)
            raise e

        remove_file(_file)
        self.devcon_rescan()
        log.info("Driver has been installed successfully")

    def uninstall(self, ignore_remove_errors=False):
        log.info("Uninstalling MSI driver")

        name = None
        for product in wmi.WMI().Win32_Product():
            if "Atlantic driver" in product.Name:
                name = product.Name
                break

        if name is None:
            log.info("MSI driver is not installed, nothing to uninstall")
            return

        for product in wmi.WMI().Win32_Product(name=name):
            product.Uninstall()

        for product in wmi.WMI().Win32_Product():
            if "Atlantic driver" in product.Name:
                raise Exception("Failed to uninstall MSI driver")

        log.info("MSI driver has been uninstalled")

    def is_present(self):
        for product in wmi.WMI().Win32_Product():
            if "Atlantic driver" in product.Name:
                return True
        return False


class KoDriver(LinuxDriver):
    drv_type = DRV_TYPE_KO

    def __init__(self, **kwargs):
        self.sysfs_name = NAME_LIN_DRV_TYPE_PROD
        super(KoDriver, self).__init__(**kwargs)

    def download(self):
        _file = "{}.ko".format(self.module)
        suburl = "driver/ko/{}/{}/{}/{}".format(self.ops, self.vendor,
                                                self.version, _file)
        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Downloading KO module from {}".format(url))
        content = get_url_response(url)
        with open(_file, "wb") as f:
            f.write(content)
        log.info("Downloaded file: {}".format(_file))

        return _file

    def install(self):
        self.remove_blacklist("atlantic")
        self.add_blacklist("atlantic_fwd")
        _file = self.download()
        log.info("Uninstalling old module if exists")
        self.uninstall()

        Command(cmd="sudo modprobe crc_itu_t").wait(30)

        self.insmod(_file)
        remove_file(_file)
        self.check_ko_loaded("atlantic")

    def uninstall(self, ignore_remove_errors=False):
        # TODO: implement one general method in base class for all driver types
        if self.vendor == constants.VENDOR_AQUANTIA:
            known_modules = [self.vendor_to_module_map[constants.VENDOR_AQUANTIA], "aqdiag", "atlantic_fwd", "atl_tsn"]
            for module in known_modules:
                self.rmmod(module)
        else:
            self.rmmod()


class RpmDriver(LinuxDriver):
    drv_type = DRV_TYPE_RPM

    def __init__(self, **kwargs):
        self.sysfs_name = NAME_LIN_DRV_TYPE_PROD
        super(RpmDriver, self).__init__(**kwargs)

    def install(self):
        self.remove_blacklist("atlantic")
        self.add_blacklist("atlantic_fwd")
        # Search for RPM file name
        res = Command(cmd="ls /storage/export/builds/driver/rpm/{}/{} | grep rpm".format(self.vendor, self.version),
                      host=constants.NFS_SERVER).wait(60)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to find RPM package")
        if len(res["output"]) > 1:
            raise Exception("Too many RPM files in the folder")

        _file = res["output"][0].strip()
        suburl = "driver/rpm/{}/{}/{}".format(self.vendor, self.version, _file)
        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Downloading RPM package from {}".format(url))
        content = get_url_response(url)
        with open(_file, "wb") as f:
            f.write(content)

        log.info("Uninstalling old package if exists")
        self.uninstall()

        Command(cmd="sudo modprobe ptp").wait(30)
        Command(cmd="sudo modprobe crc_itu_t").wait(30)
        Command(cmd="sudo modprobe usbnet").wait(30)

        log.info("Installing RPM package")
        res = Command(cmd="sudo rpm -i {}".format(os.path.abspath(_file))).wait(180)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed install RPM package")
        self.check_ko_loaded("atlantic")

    def uninstall(self, ignore_remove_errors=False):
        # TODO: implement one general method in base class for all driver types
        log.info("Removing KO objects")
        if self.vendor == constants.VENDOR_AQUANTIA:
            known_modules = [self.vendor_to_module_map[constants.VENDOR_AQUANTIA], "aqdiag", "atlantic_fwd", "atl_tsn"]
            for module in known_modules:
                self.rmmod(module)
        else:
            self.rmmod()

        log.info("Uninstalling RPM package")
        res = Command(cmd="sudo rpm -e `rpm -qa | grep -i tlantic`").wait(60)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            if not any("rpm: no packages given for erase" in line for line in res["output"]):
                raise Exception("Failed uninstall RPM package")


class DebDriver(LinuxDriver):
    drv_type = DRV_TYPE_DEB

    def __init__(self, **kwargs):
        self.sysfs_name = NAME_LIN_DRV_TYPE_PROD
        super(DebDriver, self).__init__(**kwargs)

    def install(self):
        self.remove_blacklist("atlantic")
        self.add_blacklist("atlantic_fwd")
        # Search for DEB file name
        res = Command(cmd="ls /storage/export/builds/driver/deb/{}/{} | grep deb".format(self.vendor, self.version),
                      host=constants.NFS_SERVER).wait(60)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to find DEB package")
        if len(res["output"]) > 1:
            raise Exception("Too many DEB files in the folder")

        _file = res["output"][0].strip()
        suburl = "driver/deb/{}/{}/{}".format(self.vendor, self.version, _file)
        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Downloading DEB package from {}".format(url))
        content = get_url_response(url)
        with open(_file, "wb") as f:
            f.write(content)

        log.info("Uninstalling old package if exists")
        self.uninstall()

        Command(cmd="sudo modprobe ptp").wait(30)
        Command(cmd="sudo modprobe crc_itu_t").wait(30)

        log.info("Installing DEB package")
        res = Command(cmd="sudo dpkg -i {}".format(os.path.abspath(_file))).wait(180)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to install DEB package")

        remove_file(_file)
        self.check_ko_loaded("atlantic")

    def uninstall(self, ignore_remove_errors=False):
        if self.vendor != constants.VENDOR_AQUANTIA:
            raise NotImplementedError()

        log.info("Removing KO objects")
        known_modules = [self.vendor_to_module_map[constants.VENDOR_AQUANTIA], "aqdiag", "atlantic_fwd", "atl_tsn"]
        for module in known_modules:
            self.rmmod(module)

        log.info("Uninstalling DEB package")
        res = Command(cmd="sudo dpkg --purge atlantic").wait(180)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to install DEB package")


class LinuxSrcDriver(LinuxDriver):
    drv_type = DRV_TYPE_LINUX_SRC

    def __init__(self, **kwargs):
        self.sysfs_name = NAME_LIN_DRV_TYPE_DIAG
        super(LinuxSrcDriver, self).__init__(**kwargs)

    def install(self):
        if self.flashless_fw != None:
            self.download_fw()
            res = Command(cmd="sudo flashErase -d {}".format(self.atltool.pciutil_port[5:])).run()
            if res["returncode"] != 0:
                raise Exception("FlashErase is fail")
            res = Command(cmd="sudo kickstart").run()
            if res["returncode"] == 0:
                raise Exception("Kickstart should be failed")
            Command(cmd="sudo dmesg -C").run_join()

        if "usb" in self.port:
            _file = "fiji.tar.gz"
        else:
            _file = "atlantic.tar.gz"
        sub_url = "driver/linux/{}/{}/{}".format(self.vendor, self.version, _file)
        url = urlparse.urljoin(constants.BUILDS_SERVER, sub_url)
        log.info("Downloading LINUX SRC driver from {}".format(url))
        content = get_url_response(url)
        with open(_file, "wb") as f:
            f.write(content)

        log.info("Uninstalling old package if exists")
        self.uninstall()

        log.info("Compiling driver from source code")

        drv_string = ("fiji" if 'usb' in self.port else "atlantic")

        # Do not care about return codes, just check that KO file exists later
        Command(cmd="rm -rf Linux; tar zxf {}.tar.gz".format(drv_string)).run_join(3)
        Command(cmd="cd Linux; make {}".format(self.make_args if self.make_args else "")).run_join(30)

        if "forwarding" in self.version:
            self.remove_blacklist("atlantic_fwd")
            Command(cmd="sudo mkdir -p /lib/modules/$(uname -r)/updates/drivers/net/ethernet/aquantia/atlantic/").run()
            Command(cmd="cd Linux; sudo cp atlantic-fwd.ko /lib/modules/$(uname -r)/updates/drivers/net/ethernet/"
                        "aquantia/atlantic").run()
            Command(cmd="cd /lib/modules/$(uname -r)/updates/drivers/net/ethernet/aquantia/atlantic; "
                        "sudo chmod 644 atlantic-fwd.ko").run()
            Command(cmd="sudo depmod -a $(uname -r)").run()
            self.add_blacklist("atlantic")
            self.remove_blacklist("atlantic_fwd")
            Command(cmd="cd Linux; mv atlantic-fwd.ko atlantic.ko").run_join(15)
        else:
            self.remove_blacklist("atlantic")
            self.add_blacklist("atlantic_fwd")
            Command(cmd="cd Linux; sudo make install").run_join(30)
        ko_file = "Linux/{}.ko".format("aqc111" if "usb" in self.port else "atlantic")

        if not os.path.isfile(ko_file):
            Command(cmd="rm -rf Linux; rm {}.tar.gz".format(drv_string)).run_join(3)
            raise Exception("Driver was not compiled")

        if self.insmod_args:
            ko_file += " {}".format(self.insmod_args)

        self.insmod(ko_file)
        Command(cmd="rm -rf Linux; rm {}.tar.gz".format(drv_string)).run_join(3)
        if self.flashless_fw != None:
            res = Command(cmd="sudo dmesg").run_join()
            successfully = False
            for line in res["output"]:
                if "Host load completed successfully" in line:
                    successfully = True
            assert successfully, "Host load fail"
        if "usb" in self.port:
            Command(cmd="sudo usb_modeswitch -v 0x2eca -p 0xc101 -u 1").run_join(10)
            time.sleep(2)
        if "forwarding" in self.version:
            self.check_ko_loaded("atlantic_fwd")
        elif "usb" in self.port:
            self.check_ko_loaded("aqc111")
        elif "atlantic2" in self.version:
            self.check_ko_loaded("atlantic")
        else:
            self.check_ko_loaded("atlantic")

    def uninstall(self):
        # TODO: implement one general method in base class for all driver types
        if self.vendor == constants.VENDOR_AQUANTIA:
            known_modules = [self.vendor_to_module_map[constants.VENDOR_AQUANTIA], "aqdiag", "atlantic_fwd", "aqc111", "atl_tsn"]
            if self.version == "for_install":
                known_modules.extend(["cdc_ether"])

            for module in known_modules:
                self.rmmod(module)
        else:
            self.rmmod()


class LinuxCDCDriver(LinuxDriver):
    drv_type = DRV_TYPE_LIN_CDC

    def __init__(self, **kwargs):
        self.sysfs_name = NAME_LIN_DRV_TYPE_CDC
        super(LinuxCDCDriver, self).__init__(**kwargs)

    def install(self):
        log.info("Installing CDC driver")
        res = Command(cmd="lsmod | grep cdc").run_join(15)
        is_cdc_loaded = all("cdc_ether" in line for line in res["output"])

        if is_cdc_loaded:
            log.info("CDC driver is active, exiting")
            return
        else:
            Command(cmd=\
                "sudo insmod /lib/modules/4.15.0-45-generic/kernel/drivers/net/usb/usbnet.ko").run_join(15)
            Command(cmd=\
                "sudo insmod /lib/modules/4.15.0-45-generic/kernel/drivers/net/usb/cdc_ether.ko").run_join(15)

            time.sleep(3)
            cdc = Command(cmd="lsmod | grep cdc_ether").run_join(3)
            usb_net = Command(cmd="lsmod | grep usb_net").run_join(3)

            assert all(len(res["output"]) > 0 for res in [cdc, usb_net])

    def uninstall(self):
        self.rmmod("cdc_ether")


class LinuxFreeBSDDriver(LinuxSrcDriver):
    drv_type = DRV_TYPE_FREEBSD_SRC

    def __init__(self, **kwargs):
        self.sysfs_name = NAME_LIN_DRV_TYPE_DIAG
        super(LinuxFreeBSDDriver, self).__init__(**kwargs)

    def install(self):
        log.info("Installing FreeBSD driver")
        _file = "atlantic.tar.gz"
        log.info("version: {}".format(self.version))
        sub_url = "driver/linux/{}/{}/{}".format(self.vendor, self.version, _file)
        url = urlparse.urljoin(constants.BUILDS_SERVER, sub_url)
        log.info("Downloading FreeBSD SRC driver from {}".format(url))
        content = get_url_response(url)
        with open(_file, "wb") as f:
            f.write(content)

        log.info("Uninstalling old package if exists")
        self.uninstall()

        drv_string = "atlantic"

        log.info("Compiling driver from source code")
        Command(cmd="rm -rf Linux; tar zxf atlantic.tar.gz").run_join(3)
        Command(cmd="cd Linux; make").run_join(30)

        ko_file = "Linux/if_atlantic.ko"

        if not os.path.isfile(ko_file):
            Command(cmd="rm -rf Linux; rm {}.tar.gz".format(drv_string)).run_join(3)
            raise Exception("Driver was not compiled")

        self.kldload(ko_file)
        Command(cmd="rm -rf Linux; rm {}.tar.gz".format(drv_string)).run_join(3)
        self.check_bsd_ko_loaded("if_atlantic")

    def uninstall(self):
        self.kldunload("if_atlantic")

    def check_bsd_ko_loaded(self, name):
        if name not in self.ALL_AQUANTIA_KO_NAMES:
            raise Exception("Unknown KO name")
        for ko_name in self.ALL_AQUANTIA_KO_NAMES:
            res = Command(cmd="kldstat | awk '{{print $5}}' | grep {}".format(ko_name)).run()
            if ko_name == name:
                assert res["returncode"] == 0
            else:
                for str in res["output"]:
                    if ko_name == str:
                        raise Exception("Invalid KO found: {}".format(ko_name))

    def kldload(self, module):
        log.info("Installing module {}".format(module))
        cmd = "sudo kldload {}".format(module)

        log.info("Running command '{}'".format(cmd))
        res = Command(cmd=cmd).run_join(5)
        log.info("Module has been installed")
        if res['returncode'] != 0:
            output = "\n".join(res["output"])
            if "not currently loaded" not in output:
                log.error(output)
                raise output
            log.info("Module is not loaded, nothing to uninstall")

    def kldunload(self, module):
        log.info("Uninstalling module {}".format(module))
        cmd = "sudo kldunload {}".format(module)

        log.info("Running command '{}'".format(cmd))
        res = Command(cmd=cmd).run_join(5)
        log.info("Module has been uninstalled")
        if res['returncode'] != 0:
            output = "\n".join(res["output"])
            if "can't find file" not in output:
                log.error(output)
                raise output
            log.info("Module is not loaded, nothing to uninstall")


class LinuxDiagDriver(KoDriver):
    drv_type = DRV_TYPE_DIAG_LIN

    def __init__(self, **kwargs):
        self.sysfs_name = NAME_LIN_DRV_TYPE_DIAG
        super(LinuxDiagDriver, self).__init__(**kwargs)

    def install(self):
        self.add_blacklist("atlantic")
        self.add_blacklist("atlantic_fwd")
        if self.vendor != constants.VENDOR_AQUANTIA:
            raise NotImplementedError()
        _file = "{}.ko".format(self.module)
        if self.ops in [constants.OS_UBUNTU_16_04_64, constants.OS_UBUNTU_18_04_64]:
            kernel_ver = self.get_kernel_release()
            suburl = "driver/diag/lin/{}/{}/{}/{}".format(self.ops, self.version, kernel_ver, _file)
        else:
            suburl = "driver/diag/lin/{}/{}/{}".format(self.ops, self.version, _file)
        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Downloading LIN DIAG driver from {}".format(url))
        content = get_url_response(url)
        with open(_file, "wb") as f:
            f.write(content)

        log.info("Uninstalling old module if exists")
        self.uninstall()

        self.insmod(_file)
        remove_file(_file)
        self.check_ko_loaded("aqdiag")


class LinuxSrcDiagDriver(LinuxDriver):
    drv_type = DRV_TYPE_SRC_DIAG_LIN

    def __init__(self, **kwargs):
        self.sysfs_name = NAME_LIN_DRV_TYPE_DIAG
        super(LinuxSrcDiagDriver, self).__init__(**kwargs)

    def install(self):
        self.add_blacklist("atlantic")
        self.add_blacklist("atlantic_fwd")
        if self.vendor != constants.VENDOR_AQUANTIA:
            raise NotImplementedError()
        _unpacked_folder = "aqdiag-src"
        _file = "aqdiag-src.tar.gz"
        suburl = "driver/diag/lin/{}/{}".format(self.version, _file)
        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Downloading LIN DIAG driver from {}".format(url))
        content = get_url_response(url)
        with open(_file, "wb") as f:
            f.write(content)

        log.info("Uninstalling old module if exists")
        self.uninstall()

        log.info("Compiling driver from source code")

        # Do not care about return codes, just check that KO file exists later
        Command(cmd="rm -rf {}; tar zxf {}".format(_unpacked_folder, _file)).run_join(3)
        Command(cmd='cd {}; make'.format(_unpacked_folder)).run_join(15)

        ko_file = "{}/aqdiag.ko".format(_unpacked_folder)
        if not os.path.isfile(ko_file):
            Command(cmd="rm -rf {}; rm {}".format(_unpacked_folder, _file)).run_join(3)
            raise Exception("Driver was not compiled")

        Command(cmd='cd {}; make load'.format(_unpacked_folder)).run_join(15)
        Command(cmd="rm -rf {}; rm {}".format(_unpacked_folder, _file)).run_join(3)

        self.check_ko_loaded("aqdiag")

    def uninstall(self, ignore_remove_errors=False):
        # TODO: implement one general method in base class for all driver types
        if self.vendor == constants.VENDOR_AQUANTIA:
            known_modules = [self.vendor_to_module_map[constants.VENDOR_AQUANTIA], "aqdiag", "atlantic_fwd", "atl_tsn"]
            for module in known_modules:
                self.rmmod(module)
        else:
            self.rmmod()


class KextDriver(MacDriver):
    drv_type = DRV_TYPE_KEXT

    def __init__(self, **kwargs):
        super(KextDriver, self).__init__(**kwargs)

    def install(self):
        if self.vendor != constants.VENDOR_AQUANTIA:
            raise NotImplementedError()

        if 'usb' not in self.port:
            drv_loaded = False
            driver_version = False
            for i in range(3):
                if drv_loaded:
                    break
                time.sleep(5)
                res = Command(cmd="kextstat | grep com.apple.driver.AppleEthernetAquantiaAqtion").run_join(5)
                for line in res["output"]:
                    if "com.apple.driver.AppleEthernetAquantiaAqtion" in line:
                        drv_loaded = True
                    log.info('Need release driver version {}'.format(self.release_version))
                    if self.release_version in line:
                        driver_version = True
                        break
        tgz_is_found = True
        suburl = "driver/kext/{}/{}/Shared_AppleEthernetAquantiaAqtion_DSTROOT_osx.tar.gz".format(self.vendor,
                                                                                                  self.version)
        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        try:
            log.info("Downloading KEXT driver from {}".format(url))
            content = get_url_response(url)
        except Exception:
            log.warning("TGZ KEXT driver was not found, trying bundle.zip")
            tgz_is_found = False
        if tgz_is_found:
            with open("Shared_AppleEthernetAquantiaAqtion_DSTROOT_osx.tar.gz", "wb") as f:
                f.write(content)
        if not tgz_is_found:
            suburl = "driver/kext/{}/{}/bundle.zip".format(self.vendor, self.version)
            url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
            log.info("Downloading KEXT driver from {}".format(url))
            content = get_url_response(url)

        log.info("Uninstalling old package if exists")
        self.uninstall()

        if tgz_is_found:
            Command(cmd="sudo darwinup list").run_join(10)
            Command(cmd="sudo darwinup install Shared_AppleEthernetAquantiaAqtion_DSTROOT_osx.tar.gz").run_join(180)
            Command(cmd="sudo rm Shared_AppleEthernetAquantiaAqtion_DSTROOT_osx.tar.gz").run_join(3)
            drv_loaded = False
            for i in range(3):
                if drv_loaded:
                    break
                time.sleep(5)
                res = Command(cmd="kextstat | grep com.apple.driver.AppleEthernetAquantiaAqtion").run_join(5)
                for line in res["output"]:
                    if "com.apple.driver.AppleEthernetAquantiaAqtion" in line:
                        drv_loaded = True
                        break
            if not drv_loaded:
                res = Command(cmd="sudo kextload /System/Library/Extensions/IONetworkingFamily.kext/Contents/"
                                  "PlugIns/AppleEthernetAquantiaAqtion.kext").run_join(30)
                if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                    raise Exception("Failed to kextload")
        else:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                archive.extractall("bundle")
            self.kextload("bundle")
            Command(cmd="sudo rm -rf bundle").run_join(3)
            Command(cmd="sudo rm bundle.zip").run_join(3)


class MacCDCDriver(MacDriver):
    drv_type = DRV_TYPE_MAC_CDC

    def __init__(self, **kwargs):
        super(MacCDCDriver, self).__init__(**kwargs)

    def install(self):
        if self.vendor != constants.VENDOR_AQUANTIA:
            raise NotImplementedError()

        log.info("Installing CDC driver")

        self.uninstall()
        time.sleep(3)
        res_cdc = Command(cmd="sudo kextload -b com.apple.driver.usb.cdc").run_join(60)
        time.sleep(3)
        res_ecm = Command(cmd="sudo kextload -b com.apple.driver.usb.cdc.ecm").run_join(60)

        if res_cdc["returncode"] != 0 or res_ecm["returncode"] != 0:
            raise Exception("Failed to load CDC bundle")

        cdc = Command(cmd="sudo kextstat | grep com.apple.driver.usb.cdc").run_join(2)
        cdc_ecm = Command(cmd="sudo kextstat | grep com.apple.driver.usb.cdc.ecm").run_join(2)

        assert all(len(res["output"]) > 0 for res in [cdc, cdc_ecm])

        from usb_control import USBControl
        usb_control = USBControl(device=constants.USB_CONNECT_CSWITCH)
        usb_control.disable(0)
        time.sleep(5)
        usb_control.enable(0)


class MacDiagDriver(MacDriver):
    drv_type = DRV_TYPE_DIAG_MAC

    def __init__(self, **kwargs):
        super(MacDiagDriver, self).__init__(**kwargs)

    def install(self):
        if self.vendor != constants.VENDOR_AQUANTIA:
            raise NotImplementedError()
        suburl = "driver/diag/mac/{}/bundle.zip".format(self.version)
        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Downloading MAC DIAG driver from {}".format(url))
        content = get_url_response(url)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            archive.extractall("bundle")

        log.info("Uninstalling old package if exists")
        self.uninstall()

        self.kextload("bundle")
        remove_directory("bundle")


class DriverArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error("\n{}\n".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


class T6Driver(WindowsDriver):
    drv_type = DRV_TYPE_T6

    def __init__(self, **kwargs):
        super(T6Driver, self).__init__(**kwargs)

    def install(self):
        arch = ops.OpSystem().get_arch()
        zip_name = "CDM v2.12.28 WHQL Certified.zip"
        suburl = "tools/windows/fwtools/{}/{}".format(arch, zip_name)

        url = urlparse.urljoin("http://" + constants.NFS_SERVER, suburl)
        log.info("Downloading T6 driver from {}".format(url))
        content = get_url_response(url)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            archive.extractall(arch)

        inf_file = os.path.join(arch, "ftdibus.inf")

        # log.info("Uninstalling old package if exists")
        # self.uninstall_inf_driver()

        log.info("Installing T6 driver")
        self.devcon_update("USB\\VID_0403&PID_6014", inf_file)
        self.devcon_rescan()
        self.devcon_enable("USB\\VID_0403&PID_6014")

    def get_nic_vendor(self):
        return None

    def uninstall_inf_driver(self, ignore_remove_errors=False):
        def get_inf():
            Command(cmd="pnputil -e", silent=False).run()
            for d in wmi.WMI().Win32_PnPSignedDriver():
                if "VID_0403&PID_6014" in d.DeviceID:
                    return d.InfName
            return None

        Command(cmd="devcon -r remove \"USB\\VID_0403&PID_6014\"").run()

        inf_file = get_inf()
        while inf_file is not None:
            Command(cmd="pnputil -d {}".format(inf_file)).run()
        self.devcon_rescan()


if __name__ == "__main__":
    parser = DriverArgumentParser()
    parser.add_argument("-c", "--command", help="Command to be performed", type=str, required=True,
                        choices=["download", "install", "uninstall", "getvendor", "bind", "unbind", "isinstalled"])
    parser.add_argument("-d", "--driver", help="Driver type", type=str,
                        choices=[DRV_TYPE_NDIS, DRV_TYPE_DIAG, DRV_TYPE_KO, DRV_TYPE_RPM, DRV_TYPE_DEB, DRV_TYPE_MSI,
                                 DRV_TYPE_KEXT, DRV_TYPE_LINUX_SRC, DRV_TYPE_SRC_DIAG_LIN, DRV_TYPE_DIAG_WIN_USB,
                                 DRV_TYPE_T6, DRV_TYPE_FREEBSD_SRC])
    parser.add_argument("-v", "--version", help="Driver version", type=str)
    parser.add_argument("-p", "--port", help="PCI port, i.e. pci0, pci1, ...", type=str)
    parser.add_argument("-a", "--insmod_args", help="Additional insmod arguments", type=str, action=SpacedArgAction,
                        nargs="+")
    parser.add_argument("-m", "--make_args", help="Additional make arguments", type=str, action=SpacedArgAction,
                        nargs="+")
    parser.add_argument("-f", "--flashless_fw", help="Firmware version for flashless", type=str)

    args = parser.parse_args()

    try:
        if args.command == "getvendor":
            drv = Driver(version=None, port=args.port)
            log.info("Vendor = {}".format(drv.vendor))
        elif args.command == "download":
            if not args.version:
                log.error("To download driver version must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            drv = Driver(drv_type=args.driver, version=args.version, port=args.port)
            drv.download()
        elif args.command == "install":
            if not args.version:
                log.error("To install driver version must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            drv = Driver(drv_type=args.driver, version=args.version, port=args.port, insmod_args=args.insmod_args,
                         make_args=args.make_args, flashless_fw=args.flashless_fw)
            drv.install()
        elif args.command == "uninstall":
            drv = Driver(drv_type=args.driver, version=None, port=args.port)
            drv.uninstall()
        elif args.command == "bind":
            drv = Driver(drv_type=args.driver, version=None, port=args.port)
            drv.bind()
        elif args.command == "unbind":
            drv = Driver(drv_type=args.driver, version=None, port=args.port)
            drv.unbind()
        elif args.command == "isinstalled":
            drv = Driver(drv_type=args.driver, version=None, port=args.port)
            drv.is_installed()

    except Exception:
        log.exception("Driver failed")
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
