import contextlib
import copy
import io
import ntpath
import os
import re
import subprocess
import tempfile
import traceback
import urlparse
import zipfile
import time
import timeit
import Queue
import threading

import requests
import yaml

import ops
from constants import BUILDS_SERVER, OS_CENTOS7_2_64, OS_CENTOS6_8_64, OS_MAC_10_12
from constants import OS_UBUNTU_16_04_64, OS_UBUNTU_18_04_64
from constants import OS_RHEL7_3_64, OS_RHEL7_4_64, OS_RHEL7_5_64
from utils import get_atf_logger, remove_directory, get_url_response
from command import Command

# Set AQ_DEVICEREV environment variable to B1 to be able to override B1 device ID's on B0 chip
os.environ["AQ_DEVICEREV"] = "B1"

log = get_atf_logger()
OS_MAC_DIAG_NAME = "Mac_OS_10_13"
DEFAULT_LINUX_DIAG_INSTALL_PATH = "/opt/aquantia/diag"

def download_from_url(suburl):
    url = urlparse.urljoin(BUILDS_SERVER, suburl)
    log.debug("Downloading Diag from {}".format(url))
    content = get_url_response(url)
    fname = ntpath.basename(suburl)
    with open(fname, "wb") as f:
        f.write(content)
    return os.path.abspath(fname).replace("\\", "/")


def uninstall_diag():
    op_sys = ops.OpSystem()
    os_name = op_sys.get_name()
    installed = False
    if os_name in [OS_CENTOS7_2_64, OS_CENTOS6_8_64]:
        installed_list = Command(cmd="sudo yum list diag").run()
        if "installed" in "\n".join(installed_list["output"]):
            installed = True
    elif os_name in (OS_UBUNTU_16_04_64, OS_UBUNTU_18_04_64):
        installed_list = Command(cmd="sudo dpkg -l diag").run()
        if "no packages found matching diag" not in "\n".join(installed_list["output"]):
            installed = True
    else:
        log.info("Os is not Linux not needed to uninstall diag")
        return

    if not installed:
        log.info("diag is not installed")
        return

    if os_name in [OS_CENTOS7_2_64, OS_CENTOS6_8_64]:
        cmd = Command(cmd="sudo yum -y remove diag")
    elif os_name in (OS_UBUNTU_16_04_64, OS_UBUNTU_18_04_64):
        cmd = Command(cmd="sudo dpkg -P diag")

    log.info("Remove currently installed diag")
    res = cmd.run()
    if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
        raise Exception("Failed to uninstall diag returncode: {}, reason: {}, output: {}".format(res["returncode"],
                                                                                                 res["reason"],
                                                                                                 res["output"]))

def download_and_install_linux(version, base_dir=None):
    op_sys = ops.OpSystem()
    arch = ops.get_arch()
    os_name = op_sys.get_name()
    # diag_version = get_actual_diag_version(version)

    if os_name in (OS_CENTOS7_2_64, OS_CENTOS6_8_64):
        suburl = "diag/{}/diag_{}.rpm".format(version, arch)
    elif os_name in (OS_UBUNTU_16_04_64, OS_UBUNTU_18_04_64):
        suburl = "diag/{}/diag_{}.deb".format(version, arch)
    elif os_name in (OS_RHEL7_3_64, OS_RHEL7_4_64, OS_RHEL7_5_64):
        suburl = "diag/{}/diag_linux_x86_64.zip".format(version)
    else:
        raise Exception("Unknown Linux distribution")

    downloaded_path = download_from_url(suburl)
    if os_name in [OS_CENTOS7_2_64, OS_CENTOS6_8_64]:
        cmd = Command(cmd="sudo yum install -y {}".format(downloaded_path))
        default_path = DEFAULT_LINUX_DIAG_INSTALL_PATH
    elif os_name in (OS_UBUNTU_16_04_64, OS_UBUNTU_18_04_64):
        cmd = Command(cmd="sudo apt -f -y install {}".format(downloaded_path))
        default_path = DEFAULT_LINUX_DIAG_INSTALL_PATH
    else:
        if base_dir is None:
            directory = tempfile.mkdtemp()
        else:
            directory = os.path.join(base_dir, "diag")
            remove_directory(directory)
            os.mkdir(directory)

        cmd = Command(cmd="sudo unzip {} -d {}".format(downloaded_path, directory))
        default_path = directory
    res = cmd.run()

    if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
        raise Exception("Failed to unpack diag returncode: {}, reason: {}, output: {}".format(res["returncode"],
                                                                                              res["reason"],
                                                                                              res["output"]))
    return default_path


def download_and_install_windows(version, base_dir=None):
    arch = ops.get_arch()
    suburl = "diag/{}/diag_windows_x86{}.zip".format(version, '_64' if arch == '64' else '')
    downloaded_path = download_from_url(suburl)
    if base_dir is None:
        directory = tempfile.mkdtemp()
    else:
        directory = os.path.join(base_dir, "diag")
        remove_directory(directory)
        os.mkdir(directory)

    with zipfile.ZipFile(downloaded_path) as archive:
        archive.extractall(directory)
    return directory


def download_and_install_macos(version, base_dir=None):
    suburl = "diag/{}/{}.zip".format(version, OS_MAC_DIAG_NAME)
    downloaded_path = download_from_url(suburl)
    if base_dir is None:
        directory = tempfile.mkdtemp()
    else:
        directory = os.path.join(base_dir, "diag")
        remove_directory(directory)
        os.mkdir(directory)

    with zipfile.ZipFile(downloaded_path) as archive:
        archive.extractall(directory)

    cmd = "chmod 777 {}".format(os.path.join(directory, "DIAG"))
    res = Command(cmd=cmd).run()
    if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
        raise Exception("Failed to set permissions returncode: {}, reason: {}, output: {}".format(res["returncode"],
                                                                                                  res["reason"],
                                                                                                  res["output"]))
    return directory


def download_diag(version, base_dir=None):
    log.info("Downloading Diag...")
    op_sys = ops.OpSystem()

    if op_sys.is_windows():
        directory = download_and_install_windows(version, base_dir)
    elif op_sys.is_linux():
        directory = download_and_install_linux(version, base_dir)
    elif op_sys.get_name() == OS_MAC_10_12:
        directory = download_and_install_macos(version, base_dir)
    else:
        raise Exception("Unknown operating system")

    log.debug("Diag has been downloaded and extracted to {}".format(directory))
    return directory


def get_actual_diag_version(version):
    suburl = "diag/{}/version.txt".format(version)
    url = urlparse.urljoin(BUILDS_SERVER, suburl)
    log.info("Fetching URL {}".format(url))
    response = requests.get(url=url)
    if response.status_code != 200:
        raise Exception("Cannot get actual DIAG tool version for '{}', "
                        "status {}".format(version, response.status_code))
    return response.content.rstrip("\r\n")


class RunAsync():
    REASON_NONE = -1
    REASON_OK = 0
    REASON_TIMEOUT = 1
    REASON_FAIL = 2

    def __init__(self, **kwargs):
        self.opened_proc = kwargs["opened_proc"]
        self.input = kwargs["input"]
        self.output = Queue.Queue()
        self.result = {
            "output": None,
            "returncode": None,
            "reason": self.REASON_NONE
        }

    def _enqueue_output(self, stdout, stderr):
            for line in iter(stdout.readline, ''):
                try:
                    self.output.put(line.rstrip("\r\n"))
                except Exception:
                    pass

    def run_async(self):
        log_thread = threading.Thread(target=self._enqueue_output,
                                      args=(self.opened_proc.stdout,
                                            self.opened_proc.stderr))
        log_thread.daemon = True
        log_thread.start()
        self.opened_proc.stdin.write(self.input)
        time.sleep(5)
        self.opened_proc.communicate()

    def join(self, timeout=None):
        if self.opened_proc is None:
            return self.result
        else:
            start_time = timeit.default_timer()
            killed = False
            while self.opened_proc.poll() is None:
                if timeout is not None and \
                        timeit.default_timer() - start_time > timeout:
                    self.opened_proc.kill()
                    killed = True
                    log.warning("Process timeout, killing it")
                time.sleep(0.5)

            self.result["returncode"] = self.opened_proc.returncode
            if killed is False:
                self.result["reason"] = self.REASON_OK
            else:
                self.result["reason"] = self.REASON_TIMEOUT

            self.result["output"] = []
            while not self.output.empty():
                self.result["output"].append(self.output.get())
            self.opened_proc = None
            log.info("Process is ended, return code {}, reason {}".format(
                self.result["returncode"], self.result["reason"]))

            return self.result


class DiagWrapper(object):
    BEFORE_KILL_TMO = int(os.environ.get("BEFORE_KILL_TMO", 600))
    INIT_TIMEOUT = 10

    AQC_TEMPLATE = {
        'Count': 0,
        'FW_FILE': None,
        'PCI Max Lane Width': None,
        'PCI Subsystem ID': None,
        'MAC OUI': None,
        'PCI Device ID': None,
        'MAC End': None,
        'MAC Begin': None,
        'VPD': {
            'read_only': {
                'LC': 'AquantiaLocation',
                'MN': 'AquantiaManufacturingId',
                'EC': 'AquantiaEngineeringChangeLevel',
                'key_order': ['PN', 'EC', 'FG', 'LC', 'MN', 'PG', 'SN'],
                'PG': 'AquantiaPciGeography',
                'FG': 'AquantiaFabricGeography',
                'vendor_specific': ['AquantiaVendorSpecificReadOnlyItem0',
                                    'AquantiaVendorSpecificReadOnlyItem1'],
                'PN': 'AquantiaPartNumber',
                'SN': 'AquantiaSerialNumber'
            },
            'write': {
                'system_specific': ['AquantiaSystemSpecificWritableItem0',
                                    'AquantiaSystemSpecificWritableItem1'],
                'vendor_specific': ['AquantiaVendorSpecificWritableItem0',
                                    'AquantiaVendorSpecificWritableItem1'],
                'asset_tag_identifier': 'AquantiaAssetTagIdentifier'
            },
            'product_name': 'AQtion'
        },
        'PCI Subsystem Vendor ID': None
    }
    # TODO: add all possible options and check timelimits for all option
    CMD_DICT = {
        "Select device": {
            "command": "1\n",
            "pause": 10
        },
        "Datapath Tests": {
            "command": "2\n",
            "pause": 10
        },
        "Flash": {
            "command": "3\n",
            "pause": 10
        },
        "Offloads": {
            "command": "4\n",
            "pause": 10
        },
        "Mics Tests": {
            "command": "5\n",
            "pause": 10
        },
        "Device Info": {
            "command": "6\n",
            "pause": 10
        },
        "Enable/Disable Logging": {
            "command": "7\n",
            "pause": 5
        },
        "Exit": {
            "command": "0\n",
            "pause": 5
        },
        "Help": {
            "command": "h\n",
            "pause": 2
        },
        "Select 1 device": {
            "command": "1\n",
            "pause": 10
        },
        "Select 2 device": {
            "command": "2\n",
            "pause": 10
        },
        "Enter": {
            "command": "\n",
            "pause": 10
        },
        "Go back to main menu": {
            "command": "0\n",
            "pause": 3
        },
        "Run Mac Loopback": {
            "command": "1\n",
            "pause": 60
        },
        "Run Phy Loopback": {
            "command": "2\n",
            "pause": 5
        },
        "10G": {
            "command": "1\n",
            "pause": 300
        },
        "5G": {
            "command": "2\n",
            "pause": 300
        },
        "2.5G": {
            "command": "3\n",
            "pause": 300
        },
        "1G": {
            "command": "4\n",
            "pause": 300
        },
        "100M": {
            "command": "5\n",
            "pause": 300
        },
        "Run External Loopback": {
            "command": "3\n",
            "pause": 5
        },
        "Read Flash NCB Block": {
            "command": "1\n",
            "pause": 5
        },
        "Update Flash Image": {
            "command": "2\n",
            "pause": 5
        },
        "Save Flash Contents To File": {
            "command": "3\n",
            "pause": 5
        },
        "Compare Flash Contents To CLX File": {
            "command": "4\n",
            "pause": 5
        },
        "Run Large Segment Offload Test": {
            "command": "1\n",
            "pause": 5
        },
        "LED Tests": {
            "command": "1\n",
            "pause": 100
        },
        "Toggle Bottom Green LED": {
            "command": "1\n",
            "pause": 100
        },
        "Toggle Top Yellow LED": {
            "command": "1\n",
            "pause": 100
        },
        "Toggle Top Green LED": {
            "command": "1\n",
            "pause": 100
        },
        "MAC Register Test": {
            "command": "0\n",
            "pause": 30
        },
        "PHY Link Test": {
            "command": "0\n",
            "pause": 5
        },
        "SERDES Tests": {
            "command": "0\n",
            "pause": 5
        },
        "Read VPD": {
            "command": "0\n",
            "pause": 5
        },
        "PHY flash clx": {
            "command": "2\n",
            "pause": 15 
        },
        "Q": {
            "command": "q\n",
            "pause": 3 
        },
        "Special configuration": {
            "command": "s\n",
            "pause": 5 
        },
        "Config File": {
            "command": "1\n",
            "pause": 5 
        },
        "Select New FW and OpROM Driver": {
            "command": "2\n",
            "pause": 3 
        },
        "Apply New Settings": {
            "command": "6\n",
            "pause": 10 
        },
        "Board Dependent Provisioning": {
            "command": "5\n",
            "pause": 3 
        },
        "MAC clx/bin File": {
            "command": "1\n",
            "pause": 3 
        },
        "PHY clx/bin file": {
            "command": "2\n",
            "pause": 3 
        },
        "Program Mirror Image of CLX File To Flash": {
            "command": "5\n",
            "pause": 3 
        },
        "Choose device to test:1": {
            "command": "1\n",
            "pause": 3 
        },
        "Choose device to test:2": {
            "command": "2\n",
            "pause": 3 
        },
        "y": {
            "command": "y\n",
            "pause": 5
        },

    }
    MENU_MAP = {
        1: {'Select device': {
                1: 'pci1.0.0'
                }
            },                
        2: {'Datapath Tests': {
                1: {'Change Loopback Settings': {
                    1: 'System DMA (Run now)',
                    2: 'System Packet (Run now)',
                    3: 'Ethernet Plug (Run now)'
                    }
                   },
                2: 'Start Datapath Tests'
                }
            },
        3: {'Flash': {
                1: 'Read Flash NCB Block',
                2: 'Update Flash Image',
                3: 'Verify Flash Against Firmware File',
                4: 'Save Flash contents to file'
                }
            },
        4: {'Memory': {
                1: {'Change Memory Tests': {
                    1: 'IRAM Memory (Run now)',
                    2: 'DRAM Memory (Run now)',
                    3: 'TPB/RPB Memory (Run now)'
                    }
                   },
                2: 'Run Memory Tests'
                }
            },
        5: {'Offloads': {
                1: 'Run Large Segment Offload Test'
                }
           },
        6: {'Fast Datapath Tests': {
                1: 'Run Fast Mac Loopback',
                2: 'Run Fast Ethernet Plug Loopback'
                }
           },
        7: {'Misc Tests': {
                1: 'Read VPD',
                2: 'LED Tests',
                3: 'MAC Register Test'
                }
           },
        8: 'Device Info',
        9: 'Enable/Disable Logging',
        0: 'Exit',
        "h" : 'Help'
    }

    class MenuMapper(object):
        def __init__(self):
            self.curr_sub_menu = DiagWrapper.MENU_MAP

        def get_sub(self, index):
            if index == "h":
                return "Help"
            elif index == "0":
                return 'Exit'
            elif index == "y":
                return 'Yes'

            self.curr_sub_menu = self.curr_sub_menu[int(index)]
            if type(self.curr_sub_menu) is dict:
                self.curr_sub_menu_name = self.curr_sub_menu.keys()[0]
                self.curr_sub_menu = self.curr_sub_menu[self.curr_sub_menu_name]
            else:
                self.curr_sub_menu_name = self.curr_sub_menu

            return self.curr_sub_menu_name

    def __init__(self, diag_dir, params=None):
        if ops.OpSystem().is_windows():
            self.cmd = os.path.join(diag_dir, "diag ")
        else:
            self.cmd = os.path.join(diag_dir, "DIAG ")
        if params is not None:
            self.cmd += params
        self.cmd_buf = ''

    @staticmethod
    def create_aqc_file(aqc):
        dev_id = aqc["dev_id"]
        if "lanes" in aqc:
            lanes = aqc["lanes"]
        else:
            if dev_id in [0x1, 0xd107, 0xd100, 0x7b1, 0x11b1]:
                lanes = 0x4
            elif dev_id in [0xd108, 0xd109]:
                lanes = 0x1
            else:
                # Default value
                lanes = 0x4

        aqc_data = copy.deepcopy(DiagWrapper.AQC_TEMPLATE)
        if dev_id == 0xd100:
            aqc_data["PCI Subsystem ID"] = aqc.get("subsys_id", 0x4)
        else:
            aqc_data["PCI Subsystem ID"] = aqc.get("subsys_id", 1)
        aqc_data["FW_FILE"] = aqc["clx"]
        aqc_data["PCI Device ID"] = dev_id
        aqc_data["PCI Max Lane Width"] = lanes
        re_mac = re.compile("([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]"
                            "([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]"
                            "([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})",
                            re.DOTALL)
        m = re_mac.match(aqc["mac"])
        mac_high = "{}-{}-{}".format(m.group(1), m.group(2), m.group(3))
        mac_low = "{}-{}-{}".format(m.group(4), m.group(5), m.group(6))
        mac_low_end = "{}-{}-FF".format(m.group(4), m.group(5))
        aqc_data["MAC OUI"] = mac_high
        aqc_data["MAC Begin"] = mac_low
        aqc_data["MAC End"] = mac_low_end
        aqc_data["PCI Subsystem Vendor ID"] = aqc.get("subven_id", 0x1d6a)

        aqc_file = "tmp.aqc"
        aqc_content=["AQC file ({}) content:".format(aqc_file)]

        for k, v in aqc_data.items():
            if k == "VPD":
                continue
            if type(v) is int:
                aqc_content.append("{}: '0x{:02x}'".format(k, v))
            else:
                aqc_content.append("{}: '{}'".format(k, v))

        log.info('\n'.join(aqc_content))

        with open(aqc_file, "w") as f:
            yaml.dump(aqc_data, f)
        return aqc_file

    @staticmethod
    def exec_aqc(aqc, base_dir=None, kickstart=False):
        if type(aqc) is str:
            if os.path.exists(aqc) is False:
                raise Exception("File {} doesn't exist".format(aqc))
            op_sys = ops.OpSystem()
            if op_sys.is_windows():
                if base_dir is not None:
                    log.info("Diagtool directory: {}".format(base_dir))
                    cmd = "{} --password !h:ahT8uW6 --aqc {} --raise -v 2".format(os.path.join(base_dir, "diag"), aqc)
                else:
                    cmd = "diag --password !h:ahT8uW6 --aqc {} --raise -v 2".format(aqc)
            elif op_sys.is_linux():
                if base_dir is not None:
                    log.info("Diagtool directory: {}".format(base_dir))
                    diag = os.path.join(base_dir, "DIAG")
                else:
                    diag = os.path.join(os.environ["ATF_TOOLS"], "diag", os.environ["ATF_OS"], "DIAG")
                cmd = "sudo {} --password !h:ahT8uW6 --aqc {} --raise -v 2".format(diag, aqc)
            elif op_sys.is_mac():
                if base_dir is not None:
                    raise NotImplementedError()
                else:
                    diag = os.path.join(os.environ["ATF_TOOLS"], "diag")
                    diag = os.path.join(diag, os.environ["ATF_OS"])
                    diag = os.path.join(diag, "DIAG")
                    cmd = "sudo {} --password !h:ahT8uW6 --aqc {} --raise".format(diag, aqc)
            else:
                raise Exception("Unknown OS")
            if not kickstart:
                cmd += " --no_kickstart"
            res = Command(cmd=cmd).run_join(240)
            if res["reason"] != Command.REASON_OK or res["returncode"] != 0:
                raise Exception("Failed to burn firmware")
        elif type(aqc) is dict:
            aqc_file = DiagWrapper.create_aqc_file(aqc)
            DiagWrapper.exec_aqc(aqc_file, base_dir=base_dir)

            try:
                os.remove(aqc_file)
            except Exception as exc:
                log.warning('Cannot delete file "{}". Exception:\n{}'.format(aqc_file, traceback.format_exc(exc)))

    @staticmethod
    def exec_single(params, diag_dir=None):
        op_sys = ops.OpSystem()
        if op_sys.is_windows():
            if diag_dir is not None:
                log.info("Diagtool directory: {}".format(diag_dir))
                cmd = "{} {}".format(os.path.join(diag_dir, "diag"), params)
            else:
                cmd = "diag {}".format(params)

        else:
            if diag_dir is not None:
                log.info("Diagtool directory: {}".format(diag_dir))
                diag = diag_dir
            else:
                diag = os.path.join(os.environ["ATF_TOOLS"], "diag")
            diag = os.path.join(diag, "DIAG")
            cmd = "{} {}".format(diag, params)

        return Command(cmd=cmd).wait(DiagWrapper.BEFORE_KILL_TMO)

    def init(self):
        log.info("Starting Diag tool...")
        try:
            self.p = subprocess.Popen(
                            self.cmd,
                            shell=True,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            )  
            
            time.sleep(DiagWrapper.INIT_TIMEOUT)
        except subprocess.CalledProcessError as e:
            log.error(e.output)
            raise e

    def append(self, cmd):
        if cmd == "":
            log.warning("Empty command provided")
            return
        else:    
            log.info("Appending command: {} ".format(cmd))
            self.cmd_buf = cmd

    def _route_builder(self):
        line = ""
        m = DiagWrapper.MenuMapper()
        
        for x in self.cmd_buf.rstrip():
            line += m.get_sub(x) + "==> "
        
        return line

    def commit(self):
        log.info("Route: \n\n{}\n\n".format(self._route_builder()))
        log.info("Executing Diag now...")
        cmd = ''.join((x + '\n') for x in self.cmd_buf)  
        
        proc = RunAsync(opened_proc=self.p, input=cmd)
        proc.run_async()
        res = proc.join(DiagWrapper.BEFORE_KILL_TMO)
        # log.info("OUTPUT:")
        # log.info("\n".join(res["output"]))
        
        return '\n'.join(res["output"])
    
    def read_flash(self):
        log.info("Reading flash now...")
        self.append("31y00")
        out = self.commit()
        re_bytes = re.compile(".*[0-9a-f]{4}", re.DOTALL)
        flash_bytes = []
        for line in out.split("\n"):
            if re_bytes.match(line):
                line_bytes = line.split(':')[-1].strip().split()
                flash_bytes.extend(line_bytes)
        
        return flash_bytes
