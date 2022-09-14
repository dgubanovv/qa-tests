import argparse
import tempfile

import constants
import os
import re
import sys
import subprocess
import time
import timeit
import urllib2
import zipfile

import ipaddress
import requests
import shutil
from command import Command
from log import get_atf_logger
from ops import OpSystem


log = get_atf_logger()
ON_POSIX = 'posix' in sys.builtin_module_names

PCI_PORT_RE = re.compile("pci(?:\d+\.)?(\d+)\.(\d{2})\.(\d)")
USB_PORT_RE = re.compile(r"usb(?P<LIN_BUS_FLAG>(?P<LIN_BUS>\d+)\.)?(?P<LIN_PORT>\d+)\."
                         "(?P<WIN_BUS>\d+)\.(?P<WIN_PORT>\d+)(?P<WIN_SUBPORT_FLAG>,(?P<WIN_SUBPORT>\d+))*")


def _enqueue_output(out, err, queue_out, queue_err):
    try:
        for line in iter(out.readline, ''):
            queue_out.put(line)
    except Exception:
        pass
    try:
        for line in iter(err.readline, ''):
            queue_err.put(line)
    except Exception:
        pass


def remove_file(path):
    log.info("Removing file {}".format(path))
    if not os.path.isfile(path):
        log.info("File doesn't exist")
        return
    try:
        os.remove(path)
    except WindowsError as e:
        log.error("Exception while removing file: {}, {}".format(e.errno, e.message))


def remove_directory(path):
    log.info("Removing directory {}".format(path))
    if not os.path.isdir(path):
        log.info("Directory doesn't exist")
        return
    try:
        shutil.rmtree(path)
    except Exception:
        os.system('rm -rf {}'.format(path))


def normalize_remote_windows_path_for_scp(host, path):
    if host.startswith("nn-") or host.startswith("qa-"):
        return path
    if OpSystem(host=host).is_windows():
        if path.lower().startswith("c:/"):
            path = "/c" + path[2:]
        if path.lower().startswith("d:/"):
            path = "/d" + path[2:]
    return path


def upload_file(hostname, local_file, remote_path):
    remote_path = remote_path.replace("\\", "/")
    local_file = local_file.replace("\\", "/")
    remote_path = normalize_remote_windows_path_for_scp(hostname, remote_path)
    log.info("Uploading {0} to {1}:{2}".format(local_file, hostname, remote_path))
    Command(cmd="scp {} aqtest@{}:{}".format(local_file, hostname, remote_path)).run()


def download_file(hostname, remote_file, local_file):
    remote_file = remote_file.replace("\\", "/")
    local_file = local_file.replace("\\", "/")
    remote_file = normalize_remote_windows_path_for_scp(hostname, remote_file)

    log.info("Downloading {0}: {1} to {2}".format(hostname, remote_file, local_file))
    return Command(cmd="scp aqtest@{}:{} {}".format(hostname, remote_file, local_file)).run()


def upload_directory(hostname, local_dir, remote_path):
    local_dir = local_dir.replace("\\", "/")
    remote_path = remote_path.replace("\\", "/")
    if not local_dir.endswith("/"):
        local_dir += "/"
    remote_path = normalize_remote_windows_path_for_scp(hostname, remote_path)
    log.info("Uploading {0} to {1}:{2}".format(local_dir, hostname, remote_path))
    Command(cmd="scp -r {} aqtest@{}:{}".format(local_dir, hostname, remote_path)).run()


def download_directory(hostname, remote_dir, local_dir):
    local_dir = local_dir.replace("\\", "/")
    remote_dir = remote_dir.replace("\\", "/")
    if not local_dir.endswith("/"):
        local_dir += "/"
    if not remote_dir.endswith("/"):
        remote_dir += "/"
    remote_dir = normalize_remote_windows_path_for_scp(hostname, remote_dir)
    log.info("Downloading {0}:{1} to {2}".format(hostname, remote_dir, local_dir))
    Command(cmd="scp -r aqtest@{}:{} {}".format(hostname, remote_dir, local_dir)).run()


def compress_dir(dir_path, zip_file_path):
    log.info("Compressing {0} directory into {1} file".format(dir_path, zip_file_path))
    zipf = zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED)
    for root, dirs, files in os.walk(dir_path):
        for f in files:
            zipf.write(os.path.join(root, f), os.path.join(os.path.basename(zip_file_path)[:-4], f))
    zipf.close()


def normalize_as_file_name(string):
    string = string.replace(" ", "_").replace("<", "_")
    string = string.replace(",", "_").replace(">", "_")
    string = string.replace("%", "_").replace("?", "_")
    string = string.replace(",", "_").replace("*", "_")
    string = string.replace(":", "_").replace("|", "_")
    string = string.replace("/", "_").replace("\\", "_")
    string = string.replace("\"", "_").replace(";", "_")
    return string.lower()


def get_bus_dev_func(port):
    if port.startswith("pci"):
        # Format:
        # pci(?:<DOMAIN>).<BUS>.<DEV>.<FUNC>
        iface = "pci"
        m = PCI_PORT_RE.match(port)
        if m is not None:
            return m.group(1), m.group(2), m.group(3)
    elif port.startswith("usb"):
        # Format:
        # usb<LIN_BUS>.<LIN_PORT>.<WIN_BUS>.<WIN_PORT>[,<WIN_SUBPORT>]
        iface = "usb"
        m = USB_PORT_RE.match(port)
        if m is not None:
            if m.group("LIN_BUS_FLAG") is None:
                return m.group("LIN_PORT"), m.group("WIN_BUS"), m.group("WIN_PORT")
            else:
                if OpSystem().is_windows():
                    return 0, m.group("WIN_BUS"), m.group("WIN_PORT")
                else:
                    return 0, m.group("LIN_BUS"), m.group("LIN_PORT")
    else:
        iface = "unknown"
    raise Exception("Failed to parse port for {} interface: '{}'".format(iface, port))


def get_domain_bus_dev_func(port):  # port is string 'pci2.1.00.0' or 'pci5.00.1' or 'usb0.0004.0007'
    res = None
    if port.startswith("pci"):
        iface = "pci"
        re_port = re.compile("pci(?:(\d+)(?:\.))?(\d+)\.(\d{2})\.(\d)")
        m = re_port.match(port)
        if m is not None:
            res = map(lambda x: 0 if x is None else x, m.groups())
    elif port.startswith("usb"):
        res = (0,) + get_bus_dev_func(port)
    if res is not None:
        return map(int, res)
    raise Exception("Failed to parse {} '{}'".format(iface, port))


if sys.platform == 'win32':
    import wmi


    def get_win_usb_hw_ids(port):
        if not port.startswith("usb"):
            raise Exception()

        m = USB_PORT_RE.match(port)
        if m is None:
            raise Exception("Failed to parse USB port: {}".format(port))

        usb_bus, usb_port = int(m.group("WIN_BUS")), int(m.group("WIN_PORT"))
        re_vid_did_str = r"Device ([\da-fA-F]{{4}}):([\da-fA-F]{{4}}).*bus {}.*path: {}.*".format(usb_bus, usb_port)
        if m.group("WIN_SUBPORT_FLAG"):
            re_vid_did_str += r"\.{}".format(int(m.group("WIN_SUBPORT")))
        re_vid_did = re.compile(re_vid_did_str)

        res = Command(cmd="listusb | grep \"path: {}\"".format(usb_port)).run_join(10)
        if res["returncode"] != 0:
            raise Exception("Failed to get VID:DID for device {}".format(port))

        for line in res["output"]:
            m = re_vid_did.match(line)
            if m is not None:
                return m.group(1), m.group(2)

        raise Exception("Failed to get VID:DID for device {}".format(port))

    def get_wmi_pnp_devices(port):

        def lookup_wmi_pnp_devices(port):
            bus, _, __ = get_bus_dev_func(port)

            pnps = []
            if port.startswith("pci"):
                for device_bus in wmi.WMI().Win32_DeviceBus():
                    try:
                        if device_bus.Antecedent.DeviceID == "PCI_BUS_{}".format(bus):
                            pnps.append(device_bus.Dependent)
                    except Exception:
                        pass
            elif port.startswith("usb"):
                vid, pid = get_win_usb_hw_ids(port)
                hw_id_line = r"USB\VID_{}&PID_{}".format(vid, pid).lower()
                for usb_controller_device in wmi.WMI().Win32_USBControllerDevice():
                    usb_device = usb_controller_device.Dependent
                    if hw_id_line in usb_device.DeviceID.lower():
                        pnps.append(usb_device)

            return pnps

        pnps = lookup_wmi_pnp_devices(port)
        if len(pnps) == 0:
            log.warning("PNP devices were not found, retrying after devcon rescan")
            res = Command(cmd="devcon rescan").run()
            if res["returncode"] != 0:
                raise Exception("Failed to update device list")
            pnps = lookup_wmi_pnp_devices(port)
        return pnps

    def get_wmi_device_pnp_driver(port):
        bus, dev, func = get_bus_dev_func(port)
        if port.startswith("pci"):
            iface = "pci"
            location = "PCI bus {}, device {}, function {}".format(bus, int(dev), func)
            drivers = wmi.WMI().Win32_PnPSignedDriver(Location=location)
        elif port.startswith("usb"):
            iface = "usb"
            vid, pid = get_win_usb_hw_ids(port)
            hw_id_line = r"USB\VID_{}&PID_{}".format(vid, pid).lower()
            drivers = []
            for drv in wmi.WMI().Win32_PnPSignedDriver():
                if drv.HardWareID and hw_id_line in drv.HardWareID.lower():
                    drivers.append(drv)
        if len(drivers) == 0:
            return None
        if len(drivers) != 1:
            for drv in drivers:
                log.warn(drv)
            raise Exception("Found multiple devices for interface {}: {}".format(iface, port))
        return drivers[0]

    def get_wmi_network_adapter(port):
        bus, portn, hubn = get_bus_dev_func(port)

        if port.startswith("pci"):
            iface = "pci"
            deviceID = "PCI_BUS_{}".format(bus)
        elif port.startswith("usb"):
            iface = "usb"

        network_adapter = None
        if iface == "pci":
            pnp_entity = None
            for device_bus in wmi.WMI().Win32_DeviceBus():
                try:
                    if device_bus.Antecedent.DeviceID == deviceID:
                        pnp_entity = device_bus.Dependent
                        break
                except Exception:
                    pass

            if not pnp_entity:
                raise Exception("Could not find PNPEntity for port {}".format(
                    port))

            for nic in wmi.WMI().Win32_NetworkAdapter():
                if nic.PNPDeviceID == pnp_entity.PNPDeviceID:
                    network_adapter = nic
                    break
        elif iface == "usb":
            driver = get_wmi_device_pnp_driver(port)
            hardwareID = driver.DeviceID

            # for nic in wmi.WMI(namespace='StandardCimv2').MSFT_NetAdapter():
            for nic in wmi.WMI().Win32_NetworkAdapter():
                if nic.PNPDeviceID == hardwareID:
                    network_adapter = nic
                    break

        if not network_adapter:
            raise Exception("Could not find NetworkAdapter for PNPDeviceID {}".format(pnp_entity.PNPDeviceID))

        return network_adapter


def str_to_bool(_str):
    assert _str.lower() in ["yes", "no", "y", "n", "yep", "nope", "true", "false"]
    return _str.lower() in ["yes", "y", "yep", "true"]


def is_linux(os_name):
    return os_name in constants.LINUX_OSES


def check_output_ex(cmd, ignores=[]):
    try:
        log.info("Running command '%s'", cmd)
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return [line.rstrip("\r\n") for line in output]
    except subprocess.CalledProcessError as e:
        for i in ignores:
            if i in e.output:
                return
            log.error(e.output)
            raise e


def url_file_exists(url):
    request = urllib2.Request(url)
    request.get_method = lambda: 'HEAD'
    try:
        urllib2.urlopen(request)
        return True
    except Exception:
        return False


def get_url_response(url):
    timeout = 1
    start = timeit.default_timer()
    while True:
        curr_time = timeit.default_timer()
        if curr_time - start >= 40:  # 31 sec max retrying time + some overhead
            raise Exception("Server didn't respond after {} seconds retrying".format(curr_time - start))

        log.info("GET request for URL {}".format(url))
        response = requests.get(url)

        if response.status_code == 502:
            log.warning("Response code is 502, retrying after {} sec".format(timeout))
            time.sleep(timeout)
            timeout *= 2  # 1 + 2 + 4 + 8 + 16 = 31 max retrying time
            continue

        if response.status_code == 200:
            break

        # If response code not in [200, 502] raise immediatelly
        raise Exception("Failed to request the URL, response code {}".format(response.status_code))

    if response.status_code != 200:
        raise Exception("Failed to request the URL, response code {}".format(response.status_code))

    return response.content


def get_compressed_ipv6(ipv6):
    return ipaddress.IPv6Address(unicode(ipv6)).compressed


def get_host_number(host):
    macpro_reg = re.compile('.*macpro(\d+).*')
    j137_reg = re.compile('.*J137-(\d+).*')
    drv_reg = re.compile('.*drv(\d+).*')
    try:
        for reg in (macpro_reg, j137_reg, drv_reg):
            match = reg.match(host)
            if match:
                host_number = int(match.group(1))
                if reg == drv_reg:
                    host_number += 1000
                break
        if not match:
            try:
                host_number = int(host[2:5])
            except ValueError:
                host_number = abs(hash(host))

    except Exception:
        raise Exception("Failed to extract host number from name {}".format(host))
    return host_number


class SpacedArgAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, " ".join(values))


def get_macos_version():
    output = subprocess.check_output("sw_vers", shell=True, stderr=subprocess.STDOUT)
    re_ver = re.compile(".*ProductVersion:\s+([0-9]+)\.([0-9]+).*", re.DOTALL)
    for line in output.split("\n"):
        m = re_ver.match(line)
        if m is not None:
            major_ver = int(m.group(1))
            minor_ver = int(m.group(2))
            return major_ver, minor_ver
    raise Exception("MacOS version was not matched")


def check_digital_signature(file, expected_signatures):
    def _download_signtool(destination):
        if os.path.exists(destination):
            return
        signtool_url = "http://qa-nfs01.rdc-lab.marvell.com/qa/testing/signtool.exe"
        content = get_url_response(signtool_url)
        with open(destination, "wb") as f:
            f.write(content)

    signtool_path = os.path.join(tempfile.gettempdir(), "signtool.exe")
    _download_signtool(signtool_path)

    cmd = '{} verify /v /pa /all "{}"'.format(signtool_path, file)
    res = Command(cmd=cmd).run_join(5)["output"]

    for signature in expected_signatures:
        assert '            Issued to: {}'.format(signature) in res, \
            '"{}" does not have expected digital signature'.format(file)

    assert 'Number of signatures successfully Verified: {}'.format(len(expected_signatures)) in res, \
        '"{}" has some problems with digital signature'.format(file)
    assert 'Number of warnings: 0' in res, '"{}" has some problems with digital signature'.format(file)
    assert 'Number of errors: 0' in res, '"{}" has some problems with digital signature'.format(file)
