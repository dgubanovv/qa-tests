import copy
import os
import sys
import random
import re
import subprocess
import time
from collections import namedtuple
import tempfile
import pytest
import yaml

from tools.diagper import DiagWrapper, download_diag, get_actual_diag_version, uninstall_diag
from tools import driver, ifconfig, utils, firmware, constants
from tools.atltoolper import AtlTool
# from tools.ifconfig import get_advanced_prop, get_nof_pci_lines
from tools.utils import remove_file, remove_directory, get_atf_logger, get_bus_dev_func
from infra.test_base import TestBase, idparametrize
from tools.ops import get_arch, OpSystem
from tools.constants import CHIP_REV_B0, CHIP_REV_B1, LINK_SPEED_5G, LINK_SPEED_10G, FELICITY_CARDS, BERMUDA_CARDS, \
    CARDS_FELICITY_BERMUDA
from tools.mbuper import MbuWrapper, download_mbu
from tools.command import Command


log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "diag_sanity"


class TestDiag(TestBase):
    menu_items_B0 = ["1) Select device",
                     "2) Datapath Tests",
                     "3) Flash",
                     "4) Memory",
                     "5) Offloads",
                     "6) Misc Tests",
                     "7) Device Info",
                     "8) Enable/Disable Logging",
                     "0) Exit",
                     "h) Help"]

    menu_items_B1 = ["1) Select device",
                     "2) Datapath Tests",
                     "3) Flash",
                     "4) Offloads",
                     "5) Misc Tests",
                     "6) Device Info",
                     "7) Enable/Disable Logging",
                     "0) Exit",
                     "h) Help"]

    HELP = """
    usage: diag [-h] [-?] [/?]
                [-i | -a AUTOMATED_TEST_FILE [AUTOMATED_TEST_FILE ...] | -f
                FLASH_UPDATE_FILE [FLASH_UPDATE_FILE ...] | -p] [-c] [-r] [-s]
                [-k] [-v {0,1,2}] [-d DVC_NUM] [-t [RUN_TEST [RUN_TEST ...]]]

    Vendor = Aquantia
    Revision = 0.0.0
    Purpose = To test hardware
    
    optional arguments:
    -h, --help            show this help message and exit
    -?                    show this help message and exit
    /?                    show this help message and exit
    -i                    Run diagnostic software in interactive mode. (Can't be
                            combined with -a)
    -a AUTOMATED_TEST_FILE [AUTOMATED_TEST_FILE ...]
                            Run tests automatically with configuration file (Can't
                            be combined with -i)
    -f FLASH_UPDATE_FILE [FLASH_UPDATE_FILE ...]
                            Burn flash with specified file and then exit. (Can't
                            be combined with -a, -i, -p)
    -p                    Print device and program information
    -c                    Continue running tests even on failure (for automated
                            mode (-a), default is to exit on first failure; for
                            interactive mode (-i), this is ignored and it never
                            exits automatically.)
    -r                    Print results at the end of diag program.
    -s                    At the start of diag, install diagnostic driver on all
                            Aquantia devices. (Location automatically detected).
                            Diagnostic driver is uninstalled and replaced with
                            device driver after the program terminates.
    -k                    At the start of diag, install diagnostic driver on all
                            Aquantia devices. Keeps diagnostic driver installed
                            after exiting(Location automatically detected)
    -v {0,1,2}            Set verbosity level of standard output
                                    0 = Print nothing
                                    1 = Print test name + status (default)
                                    2 = Print detailed info
    -d DVC_NUM            The device number (an integer index) to run tests on.
                            For N Aquantia devices, starts from index 0 and goes
                            up to N-1. This software detects devices using
                            pciX.Y.Z notation (where X is bus, Y is device, and Z
                            is function), and sorts the list using this notation.
                            So if a device is in slot pci1.0.0 and another is in
                            slot pci4.0.0, pci1.0.0 will be referenced with
                            integer index 0 and pci4.0.0 with 1. (default is 0)
    -t [RUN_TEST [RUN_TEST ...]]
                            Run specified tests by supplying the test type and
                            test name. ie: datapath:System_DMA Use commas between
                            each test name and spaces between each test type list
                            of acceptable tests:
                            fast_datapath:Mac,Phy,External_Loopback
                            mem:IRAM_Memory,DRAM_Memory,TPB/RPB_Memory (not
                            available for B1) offload:LSO flash:Flash_Write_Read
                            misc:VPD_Read,MAC_Registers,LED_Test
    """

    HELP_LIN = """
    usage: DIAG [-h] [-?] [-i | -a AUTOMATED_TEST_FILE [AUTOMATED_TEST_FILE ...] |
            -f FLASH_UPDATE_FILE [FLASH_UPDATE_FILE ...] | -p] [-c] [-r] [-s]
            [-k] [-v {0,1,2}] [-d DVC_NUM] [-t [RUN_TEST [RUN_TEST ...]]]

    Vendor = Aquantia
    Revision = 0.0.0
    Purpose = To test hardware
    
    optional arguments:
    -h, --help            show this help message and exit
    -?                    show this help message and exit
    -i                    Run diagnostic software in interactive mode. (Can't be
                            combined with -a)
    -a AUTOMATED_TEST_FILE [AUTOMATED_TEST_FILE ...]
                            Run tests automatically with configuration file (Can't
                            be combined with -i)
    -f FLASH_UPDATE_FILE [FLASH_UPDATE_FILE ...]
                            Burn flash with specified file and then exit. (Can't
                            be combined with -a, -i, -p)
    -p                    Print device and program information
    -c                    Continue running tests even on failure (for automated
                            mode (-a), default is to exit on first failure; for
                            interactive mode (-i), this is ignored and it never
                            exits automatically.)
    -r                    Print results at the end of diag program.
    -s                    At the start of diag, install diagnostic driver on all
                            Aquantia devices. (Location automatically detected).
                            Diagnostic driver is uninstalled and replaced with
                            device driver after the program terminates.
    -k                    At the start of diag, install diagnostic driver on all
                            Aquantia devices. Keeps diagnostic driver installed
                            after exiting(Location automatically detected)
    -v {0,1,2}            Set verbosity level of standard output
                                    0 = Print nothing
                                    1 = Print test name + status (default)
                                    2 = Print detailed info
    -d DVC_NUM            The device number (an integer index) to run tests on.
                            For N Aquantia devices, starts from index 0 and goes
                            up to N-1. This software detects devices using
                            pciX.Y.Z notation (where X is bus, Y is device, and Z
                            is function), and sorts the list using this notation.
                            So if a device is in slot pci1.0.0 and another is in
                            slot pci4.0.0, pci1.0.0 will be referenced with
                            integer index 0 and pci4.0.0 with 1. (default is 0)
    -t [RUN_TEST [RUN_TEST ...]]
                            Run specified tests by supplying the test type and
                            test name. ie: datapath:System_DMA Use commas between
                            each test name and spaces between each test type list
                            of acceptable tests:
                            fast_datapath:Mac,Phy,External_Loopback
                            mem:IRAM_Memory,DRAM_Memory,TPB/RPB_Memory (not
                            available for B1) offload:LSO flash:Flash_Write_Read
                            misc:VPD_Read,MAC_Registers,LED_Test
    """

    AFTER_BURN_DELAY = 5
    BOUNDARY_DIAG_VER = "1.3.13"

    RE_WIN_DRV = re.compile(r"Aquantia AQtion \d+Gbit Network Adapter ?(\(NDIS 6\.\d+ Miniport\))?")

    RE_DIAG = re.compile(".*aquantiaDiag.*", re.DOTALL)
    RE_DIAG_LINUX = re.compile(".*aqdiag.*", re.DOTALL)
    RE_DIAG_MACOS = "com.aquantia.simple"

    FW_1X_TEST_VERSION = "x1/stable"
    FW_1X_FELICITY_TEST_VERSION = "felicity/stable"
    FW_2X_TEST_VERSION = "x2/stable/bin_forCustomers"
    FW_3X_PREVIOUS_VERSION = "3x/3.1.46"
    FW_3X_TEST_VERSION = "3x/stable"

    DEFAULT_SELFTEST_CONFIG = {
        "version": 1,
        "tests": {
            "datapath_tests": [],
            "memory_tests": [],
            "offload_tests": [],
            "flash_tests": [],
            "misc_tests": []
        },
        "Ethernet_Speed": []
        }

    DeviceInfo = namedtuple("DeviceInfo", ["mac", "fw_version", "phy_fw_version", "vendor_id", "device_id",
                                           "subsystem_vendor_id", "subsystem_device_id", "max_playload",
                                           "pcie_link_speed", "pcie_link_width", "mac_temperature", "eth_link_status",
                                           "tx_status", "rx_status"])

    @classmethod
    def add_diag_drv_cert(cls, path):
        arch = get_arch()
        cert_dir = "win32" if arch == "32" else "x64"
        cert = os.path.join(path, "mbu/Os/{}/aquantiaDiagPack.cer".format(cert_dir))

        cls.diag_drv.install_trusted_certificate(cert)

    @classmethod
    def adapter_speed(cls):
        speed = cls.atltool.get_adapter_speed()
        if speed == '5G':
            return LINK_SPEED_5G
        elif speed == '10G':
            return LINK_SPEED_10G

        raise Exception("Cannot obtain adapter speed")

    @classmethod
    def setup_class(cls):
        # set DUT_PORT before TestBase.setup_class() because it's needed inside
        dut_felicity = os.environ.get('DUT_FELICITY', None)
        if dut_felicity is not None:
            os.environ['DUT_PORT'] = dut_felicity
            os.environ['DUT_FW_CARD'] = 'Felicity'

        # init from base class
        super(TestDiag, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.os = OpSystem()

            cls.install_firmwares()

            # uninstall previously installed diag on linux to be able to install rpm or deb
            if cls.os.is_centos() or cls.os.is_ubuntu():
                uninstall_diag()
            cls.diag_dir = download_diag(cls.diag_version)
            cls.diag_ver = get_actual_diag_version(cls.diag_version)

            # First diag test burns firmware so skip FW installation here
            # cls.install_firmwares()

            # TODO: refactor getting chip revision
            # cls.chip_rev = cls.get_chip_revision(cls.dut_port)
            # if os.environ.get("AQ_DEVICEREV") == CHIP_REV_B1:
            #     cls.chip_rev = CHIP_REV_B1
            # log.info("Chip revision: {}".format(cls.chip_rev))

            cls.diag_drv = driver.Driver(port=cls.dut_port, drv_type="diag", version=cls.dut_drv_version)

            if cls.os.is_windows():
                cls.add_diag_drv_cert(cls.diag_dir)

            if cls.os.is_linux():
                if cls.os.is_rhel():
                    cls.diag_drv_path = '{}/mbu/Os/linux/driver/src'.format(cls.diag_dir)
                    Command(cmd='cd {}; make'.format(cls.diag_drv_path)).run_join(15)
                    Command(cmd='insmod {}/aqdiag.ko'.format(cls.diag_drv_path)).run_join(15)
                else:
                    Command(cmd='insmod /opt/aquantia/diag/mbu/Os/linux/driver/src/aqdiag.ko').run_join(15)
            else:
                cls.diag_drv.install()
            cls.atltool = AtlTool(port=cls.dut_port)
            # cls.efused_adapter_speed = cls.adapter_speed()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestDiag, cls).teardown_class()

        # DiagWrapper.exec_single("--password !h:ahT8uW6 --flash_erase")
        if cls.os.is_linux():
            uninstall_diag()
        else:
            remove_directory(cls.diag_dir)

        # if cls.os.is_windows():
        #     try:
        #         cls.diag_drv.remove_all_hidden_devices()
        #     except Exception as e:
        #         log.error(e)

    def setup_method(self, method):
        super(TestDiag, self).setup_method(method)

        # Check if diag driver is installed
        if self.os.is_windows():
            curr_drv = ifconfig.get_wmi_device_driver_name(self.dut_port)
            m = self.RE_DIAG.search(curr_drv)
            if not m:
                self.diag_drv.install()
        elif self.os.is_linux():
            curr_drv = ifconfig.get_linux_device_driver_name(self.dut_port)
            m = self.RE_DIAG_LINUX.search(curr_drv)
            if not m:
                self.diag_drv.install()
        else:
            curr_drv = self.diag_drv.get_macos_device_bundle_name()
            log.info("Current MAC OS bundle: {}".format(curr_drv))
            if self.RE_DIAG_MACOS not in curr_drv:
                self.diag_drv.install()

    def update_flash_aqc(self):
        fw = firmware.Firmware(port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
                               version=self.dut_fw_version, mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
                               pause=self.dut_fw_pause, pcirom=self.dut_fw_pcirom, dirtywake=self.dut_fw_dirtywake)

        log.info("Installing firmware {}".format(self.dut_fw_version))

        try:
            fw.install()
        except ValueError as e:
            log.error(e)

        time.sleep(self.AFTER_BURN_DELAY)
        self.diag_drv.install()

    @staticmethod
    def _get_string_contains(strings, item):
        return next(obj for obj in strings if item in obj)

    @staticmethod
    def _get_value_from_regex(regex, string):
        matches = re.search(regex, string)
        if matches is None:
            return None
        else:
            return matches.group()

    def _get_actual_device_data(self):
        if self.os.is_windows():
            return self._get_actual_device_data_win()
        else:
            return self._get_actual_device_data_linux()

    def _get_actual_device_data_linux(self):
        bus, dev, func = get_bus_dev_func(self.dut_port)
        port_str = "0{}:{}.{}".format(bus, dev, func)
        log.info("Linux port for Aquantia: {}".format(port_str))

        try:
            cmd = "lspci -v | grep '{}' -A 1".format(port_str)
            output = subprocess.check_output(cmd, shell=True,
                                             stderr=subprocess.STDOUT)
            log.info(output)
        except subprocess.CalledProcessError as e:
            log.error(e.output)
            raise e

        re_ven_dev = re.compile(r"Ethernet controller: Device ([0-9a-z]{4}:d?[0-9a-z]{3,4}) \(rev [0-9]{2}\)",
                                re.DOTALL)

        re_sub_ven_sys = re.compile(r"Subsystem: Device ([0-9a-z]{4}:[0-9a-z]{4})", re.DOTALL)

        ven_dev = re_ven_dev.search(output)
        sub_ven_sys = re_sub_ven_sys.search(output)

        if ven_dev is None or sub_ven_sys is None:
            raise Exception("Cannot obtain device data")

        ven_id = ven_dev.group(1).split(":")[0]
        dev_id = ven_dev.group(1).split(":")[1]
        subsys_ven_id = sub_ven_sys.group(1).split(":")[0]
        subsys_dev_id = sub_ven_sys.group(1).split(":")[1]

        actual_device_data = {
            "ven_id": "0x{}".format(ven_id.lower()),
            "dev_id": "0x{}".format(dev_id.lower()),
            "subsys_dev_id": int(subsys_dev_id, 16),
            "subsys_ven_id": "0x{}".format(subsys_ven_id.lower())
        }

        return actual_device_data

    def _get_actual_device_data_win(self):
        pci_dev = utils.get_wmi_pnp_devices(self.dut_port)[0].DeviceID

        re_ven = re.compile(r".*VEN_([0-9A-Z]{4})", re.DOTALL)
        re_dev = re.compile(r".*DEV_(D?[A-Z0-9]{3,4})", re.DOTALL)
        re_subsys_ven_id = re.compile(r".*SUBSYS_([0-9]{4})([0-9A-Z]{4})", re.DOTALL)

        ven_id = re_ven.match(pci_dev).group(1)
        dev_id = re_dev.match(pci_dev).group(1)
        subsys_dev_id = re_subsys_ven_id.match(pci_dev).group(1)
        subsys_ven_id = re_subsys_ven_id.match(pci_dev).group(2)

        actual_device_data = {
            "ven_id": "0x{}".format(ven_id.lower()),
            "dev_id": "0x{}".format(dev_id.lower()),
            "subsys_dev_id": int(subsys_dev_id, 16),
            "subsys_ven_id": "0x{}".format(subsys_ven_id.lower())
        }

        return actual_device_data

    def verify_diag_driver_name(self, wrapper):
        pnp_driver_name = ifconfig.get_wmi_device_driver_name(self.dut_port)
        m = self.RE_DIAG.match(pnp_driver_name)
        assert m is not None, "No match to regexp: \n {}\n in: {}".format(self.RE_DIAG.pattern, pnp_driver_name)

        wrapper.append("0")
        wrapper.commit()
        time.sleep(self.AFTER_BURN_DELAY)

    def verify_filled_flash(self, diag):
        diag.init()
        flash_data = diag.read_flash()

        # add regexp here after rework
        assert len(set(flash_data)) > 1
        return flash_data

    def get_tests_from_autoconf(self, conf):
        test_types = ["misc_tests", "flash_tests", "offload_tests", "memory_tests", "datapath_tests"]
        auto_tests = []
        with open(conf, "r") as f:
            conf = [line for line in f.read().split("\n") if len(line) > 0 and line[0] != "#"]
            for test in test_types:
                auto_tests.extend(re.findall('\'([^\']*)\'', self._get_string_contains(conf, test)))
                auto_tests.extend(re.findall('"([^"]*)"', self._get_string_contains(conf, test)))
        return auto_tests

    @classmethod
    def get_device_info(cls):
        # mac
        output = DiagWrapper.exec_single("-p", cls.diag_dir)
        assert output["reason"] == Command.REASON_OK
        assert output["returncode"] == 0
        output_lines = output.split("\n")
        mac_regex = r"([0-9A-Fa-f]{2}[-]){5}([0-9A-Fa-f]{2})"
        mac_str = cls._get_string_contains(output_lines, "MAC Address")
        mac = cls._get_value_from_regex(mac_regex, mac_str)
        mac = mac.replace("-", ":")

        # firmware version
        fw_version_regex = r"([123]\.[0-9]\.[0-9]{1,3})"
        fw_version_str = cls._get_string_contains(output_lines, "Firmware Version")
        fw_version = cls._get_value_from_regex(fw_version_regex, fw_version_str)

        # PHY Firmware Version
        phy_fw_version_regex = r"(VerStr: [0-9a-zA-Z\s.-]+)"
        phy_fw_version_str = cls._get_string_contains(output_lines, "PHY Firmware Version")
        phy_fw_version = cls._get_value_from_regex(phy_fw_version_regex, phy_fw_version_str)

        # Vendor ID
        id_regex = r"0x[0-9a-z]{1,4}"
        vendor_id_str = cls._get_string_contains(output_lines, "Vendor ID")
        vendor_id = cls._get_value_from_regex(id_regex, vendor_id_str)

        # Device ID
        device_id_str = cls._get_string_contains(output_lines, "Device ID")
        device_id = cls._get_value_from_regex(id_regex, device_id_str)

        # Subsystem Vendor ID
        subsystem_vendor_id_str = cls._get_string_contains(output_lines, "Subsystem Vendor ID")
        subsystem_vendor_id = cls._get_value_from_regex(id_regex, subsystem_vendor_id_str)

        # Subsystem Device ID
        subsystem_device_id_str = cls._get_string_contains(output_lines, "Subsystem Device ID")
        subsystem_device_id = cls._get_value_from_regex(id_regex, subsystem_device_id_str)

        # Max Payload Supported
        max_playload_regex = r"[1-9][0-9]{1,3}"
        max_playload_str = cls._get_string_contains(output_lines, "Max Payload Supported")
        max_playload = cls._get_value_from_regex(max_playload_regex, max_playload_str)

        # PCIe Link Speed = Gen
        pcie_link_speed_regex = r"(Gen [1-4])"
        pcie_link_speed_str = cls._get_string_contains(output_lines, "PCIe Link Speed")
        pcie_link_speed = cls._get_value_from_regex(pcie_link_speed_regex, pcie_link_speed_str)

        # PCIe Link Width
        pcie_link_width_regex = r"([14]{1})\s*$"
        pcie_link_width_str = cls._get_string_contains(output_lines, "PCIe Link Width")
        pcie_link_width = cls._get_value_from_regex(pcie_link_width_regex, pcie_link_width_str)

        # Reading MAC Temperature...
        mac_temperature_regex = r"([0-9]{1,}\.[0-9]{1,})"

        # TODO: implement smart logic
        line = ("Temperature" if cls.diag_ver >= TestDiag.BOUNDARY_DIAG_VER else "Reading MAC Temperature...")
        mac_temperature_str = cls._get_string_contains(output_lines, line)
        mac_temperature = float(cls._get_value_from_regex(mac_temperature_regex, mac_temperature_str))

        # Ethernet Link Status assert Down in
        eth_link_status = cls._get_string_contains(output_lines, "Ethernet Link Status")

        # System TX: Down | System RX: Down
        rx_tx_str = cls._get_string_contains(output_lines, "System TX")
        tx_status = None
        rx_status = None
        if rx_tx_str is not None:
            tx_status, rx_status = rx_tx_str.split("|")

        return cls.DeviceInfo(mac, fw_version, phy_fw_version, vendor_id, device_id, subsystem_vendor_id,
                              subsystem_device_id, max_playload, pcie_link_speed, pcie_link_width, mac_temperature,
                              eth_link_status, tx_status, rx_status)

    @classmethod
    def get_fw_branch(cls):
        fw_version = cls.get_actual_firmware_version(cls.dut_fw_version)
        fw_x = fw_version.split(".")[0]
        return fw_x

    if sys.platform == "win32" and 'darwin' not in sys.platform:
        params = ["-h", "/?", "-?"]
    else:
        params = ["-h", "-?"]

    # def test_dev_info(self):
    #     dev_inf = self.get_device_info()
    #     actual_dev_data = self._get_actual_device_data()

    #     assert dev_inf.mac == self.get_flash_override()[0]["mac"], "wrong mac address"
    #     assert dev_inf.fw_version == self.get_actual_firmware_version(self.dut_fw_version), "wrong firmware version"
    #     assert dev_inf.phy_fw_version is not None, "no phy firmware version info"

    #     assert dev_inf.vendor_id == actual_dev_data["ven_id"], "vendor id are different"
    #     assert int(dev_inf.device_id, 16) == int(actual_dev_data["dev_id"], 16), "device id are different"
    #     assert dev_inf.subsystem_vendor_id == actual_dev_data["subsys_ven_id"], "subsystem vendor id are different"
    #     assert int(dev_inf.subsystem_device_id, 16) == actual_dev_data["subsys_dev_id"], \
    #         "subsystem vendor id are different"

    #     assert dev_inf.max_playload == "512", "max playload is not 512"
    #     assert dev_inf.pcie_link_speed is not None, "no pcie link speed info"
    #     assert int(dev_inf.pcie_link_width) == get_nof_pci_lines(self.dut_port), "pcie link width different"
    #     assert dev_inf.mac_temperature > 0, "incorrect temperature"
    #     assert "Down" in dev_inf.eth_link_status or "Up" in dev_inf.eth_link_status, "wrong link status"
    #     assert "Down" in dev_inf.tx_status or "Up" in dev_inf.tx_status, "wrong tx status"
    #     assert "Down" in dev_inf.rx_status or "Up" in dev_inf.rx_status, "wrong rx status"

    # @idparametrize("flag", params)
    # def test_help_file(self, flag):
    #     if self.os.is_linux() or self.os.is_mac():
    #         help = TestDiag.HELP_LIN
    #     else:
    #         help = TestDiag.HELP

    #     expected_version = get_actual_diag_version(self.diag_version)
    #     log.info("Expected Diag version: {}".format(expected_version))
    #     out = DiagWrapper.exec_single(flag, self.diag_dir).split()
    #     exp = [expected_version if x == '0.0.0' else x for x in help.split()]

    #     assert out == exp, "wrong diag help expected:\n {}".format(help)

    # @pytest.mark.skipif('win32' not in sys.platform, reason="Does not run on linux")
    # def test_temp_drv_install_win(self):
    #     if self.get_fw_branch() == "2":
    #         pytest.skip("Does not run on 2.x")

    #     log.info("Installing Win driver now")

    #     driver_win = driver.Driver(port=self.dut_port, version=self.dut_drv_version)
    #     driver_win.install()

    #     log.info("Running Diag with '-s' option")
    #     d = DiagWrapper(self.diag_dir, "-s")
    #     d.init()

    #     # Check Diag driver now
    #     self.verify_diag_driver_name(d)

    #     # Check Win driver now
    #     pnp_driver_name = ifconfig.get_wmi_device_driver_name(self.dut_port)
    #     pnp_driver_ver = get_advanced_prop(self.dut_port, "DriverVersion")

    #     dut_drv_version = ".".join([str(int(v)) for v in driver_win.release_version.split(".")])

    #     m = self.RE_WIN_DRV.match(pnp_driver_name)

    #     # pnp_driver_ver = (pnp_driver_ver if pnp_driver_ver.split('.')[-1] != '0' else
    #     #                   '.'.join(k for k in pnp_driver_ver.split('.')[:-1]))
    #     pnp_driver_ver = pnp_driver_ver.rstrip(".0")
    #     dut_drv_version = dut_drv_version.rstrip(".0")

    #     assert m is not None, "No match to regexp: \n {}\n in: {}".format(self.RE_WIN_DRV.pattern, pnp_driver_name)
    #     assert pnp_driver_ver == dut_drv_version, "driver version are different"

    #     driver_win.uninstall()

    # @pytest.mark.skipif('win32' not in sys.platform, reason="Does not run on linux")
    # def test_temp_drv_install_msi(self):
    #     if self.get_fw_branch() == "2":
    #         pytest.skip("Does not run on 2.x")

    #     log.info("Installing MSI driver now")
    #     driver_msi = driver.Driver(port=self.dut_port, version="stable", drv_type=driver.DRV_TYPE_MSI)
    #     driver_msi.install()

    #     log.info("Running Diag with -s option")
    #     d = DiagWrapper(self.diag_dir, "-s")
    #     d.init()

    #     # Check Diag driver now
    #     self.verify_diag_driver_name(d)

    #     # Check MSI driver now
    #     pnp_driver_name = ifconfig.get_wmi_device_driver_name(self.dut_port)
    #     log.info("pnp driver name: {}".format(pnp_driver_name))
    #     pnp_driver_ver = get_advanced_prop(self.dut_port, "DriverVersion")
    #     log.info("pnp driver version: {}".format(pnp_driver_ver))

    #     dut_msi_version = ".".join([str(int(v)) for v in driver_msi.release_version.split(".")])
    #     log.info("msi drver version: {}".format(dut_msi_version))

    #     m = self.RE_WIN_DRV.match(pnp_driver_name)

    #     assert m is not None, "no match to regex: {} in pnp driver name:\n {}".format(self.RE_WIN_DRV, pnp_driver_name)
    #     assert pnp_driver_ver == dut_msi_version, "msi driver version are different"

    #     driver_msi.uninstall()

    # @pytest.mark.skipif('win32' not in sys.platform, reason="Does not run on linux")
    # def test_permanent_drv_install(self):
    #     if self.get_fw_branch() == "2":
    #         pytest.skip("Does not run on 2.x")

    #     driver_win = driver.Driver(port=self.dut_port, version=self.dut_drv_version)
    #     driver_win.install()

    #     pnp_driver_name = ifconfig.get_wmi_device_driver_name(self.dut_port)
    #     m = self.RE_WIN_DRV.match(pnp_driver_name)
    #     assert m is not None, "No match to regexp: \n {}\n in: {}".format(self.RE_WIN_DRV.pattern, pnp_driver_name)

    #     log.info("Running Diag with '-k' option")
    #     d = DiagWrapper(self.diag_dir, "-k")
    #     d.init()

    #     # Check Diag driver now
    #     self.verify_diag_driver_name(d)


    def run_test_flash_update_aqc(self, fw_version, kickstart):
        prev_version = self.atltool.get_fw_version()
        log.info("Previous firmware version is {0[0]}.{0[1]}.{0[2]}".format(prev_version))

        fw = firmware.Firmware(port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
                               version=fw_version, mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
                               pause=self.dut_fw_pause, pcirom=self.dut_fw_pcirom, dirtywake=self.dut_fw_dirtywake)
        clx_path = fw.download()

        aqc_data = {
            "clx": clx_path,
            "mac": "11:22:33:22:11:22",
            "dev_id": fw.default_overrides["dev_id"],
            "subsys_id": fw.default_overrides["subsys_id"],
            "subven_id": fw.default_overrides["subven_id"]
        }

        aqc_path = DiagWrapper.create_aqc_file(aqc_data)

        params = "--password !h:ahT8uW6 --aqc {} --raise -v 2".format(aqc_path)
        if not kickstart:
            params += " --no_kickstart"
        res = DiagWrapper.exec_single(params, self.diag_dir)
        assert res["reason"] == Command.REASON_OK
        assert res["returncode"] == 0

        remove_file(aqc_path)
        remove_file(clx_path)

        if kickstart:
            assert any("Kickstart" in line for line in res["output"])
        else:
            assert not any("kickstart" in line.lower() for line in res["output"])

        if kickstart:
            new_version = self.atltool.get_fw_version()
            log.info("New firmware version is {0[0]}.{0[1]}.{0[2]}".format(new_version))
            assert prev_version != new_version
        else:
            new_version = self.atltool.get_fw_version()
            # Firmware was not kickstarted yet, so version is not updated
            assert prev_version == new_version
            self.atltool.kickstart(reload_phy_fw=(self.dut_fw_card not in CARDS_FELICITY_BERMUDA))

    def run_test_flash_erase(self):
        params = "--password !h:ahT8uW6 --flash_erase --raise"
        res = DiagWrapper.exec_single(params, self.diag_dir)
        assert res["reason"] == Command.REASON_OK
        assert res["returncode"] == 0
        re_pass = re.compile(r".*Pass.*", re.DOTALL)
        assert any(re_pass.match(line) for line in res["output"] \
            if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line)
        try:
            self.atltool.kickstart(reload_phy_fw=(self.dut_fw_card not in CARDS_FELICITY_BERMUDA))
        except Exception as exc:
            log.info("Kickstart has been failed as expected. Exception: {}".format(str(exc)))
        else:
            raise Exception("Kickstart should not pass after erase")

    def run_flash_burn(self, clx_path):
        bus, dev, func = map(lambda x: int(x), get_bus_dev_func(self.dut_port))
        lspci_port = "{:02x}:{:02x}.{:x}".format(bus, dev, func)
        cmd = "" if OpSystem().is_windows() else "sudo "
        cmd += "flashBurn -d {} {}".format(lspci_port, clx_path)
        res = Command(cmd=cmd).wait(180)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to burn firmware")
        if "Device burned and verified" not in res["output"][-1]:
            raise Exception("Failed to burn firmware")

    def run_test_flash_update_aqc_after_flash_burn(self, fw_version_flashburn, fw_version_diag):
        fw = firmware.Firmware(port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
                               version=fw_version_flashburn, mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
                               pause=self.dut_fw_pause, pcirom=self.dut_fw_pcirom, dirtywake=self.dut_fw_dirtywake)
        clx_path = fw.download()

        self.run_flash_burn(clx_path)
        self.atltool.kickstart(reload_phy_fw=(self.dut_fw_card not in CARDS_FELICITY_BERMUDA))

        remove_file(clx_path)

        self.run_test_flash_update_aqc(fw_version_diag, False)


    def run_test_selftest(self, config, speed = None):
        config_path = "tmp.cfg"
        tmp_content = ["tmp.cfg file content:"]

        with open(config_path, "w") as f:
            yaml.dump(config, f)
            tmp_content.append(yaml.dump(config))
        log.info('\n'.join(tmp_content))

        params = "-a {} -r --raise".format(config_path)
        res = DiagWrapper.exec_single(params, self.diag_dir)
        assert res["reason"] == Command.REASON_OK
        assert res["returncode"] == 0
        log.info('Exit code: {}, reason: {}'.format(res["returncode"], res["reason"]))
        re_pass = re.compile(r"^(\w*\s*)+=\s*\d*[a-z ]*\d* passed \(100.00%\)?")
        assert any(re_pass.match(line) for line in res["output"] \
            if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line)
        log.info('tests are 100% passed')

        re_pass_subtest = re.compile(r"^(\w*\s*)+\(*\d*\.*\d*\w*\)*(\s*\.*)+\s*Pass?")
        assert any(re_pass_subtest.match(line) for line in res["output"] \
            if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line)
        log.info('subtests have been passed at least once')

        if speed is not None:
            itr = 0
            re_pass_speed = re.compile(r"^(\w*\s*)+\(*(\d+\.*\d*\w)\)(\s*\.*)+\s*Pass?")
            for line in res["output"]:
                if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line:
                    m = re_pass_speed.match(line)
                    if m is not None:
                        assert m.group(2) == speed
                        log.info('subtest iteration #{} have been passed with speed "{}"'.format(itr, speed))
                        itr += 1
            assert itr == 1

    def test_flash_update_aqc_fw_1x_no_kickstart(self):
        if self.dut_fw_card in FELICITY_CARDS:
            self.run_test_flash_update_aqc(self.FW_1X_FELICITY_TEST_VERSION, False)
        elif self.dut_fw_card in BERMUDA_CARDS:
            pytest.skip("FW 1.X doesn't support Bermuda")
        else:
            self.run_test_flash_update_aqc(self.FW_1X_TEST_VERSION, False)

    def test_flash_erase(self):
        self.run_test_flash_erase()

    def test_flash_update_aqc_fw_2x_no_kickstart(self):
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip("FW 2.X doesn't support Felicity")
        elif self.dut_fw_card in BERMUDA_CARDS:
            pytest.skip("FW 2.X doesn't support Bermuda")
        else:
            self.run_test_flash_update_aqc(self.FW_2X_TEST_VERSION, False)

    def test_double_flash_erase(self):
        self.run_test_flash_erase()
        self.run_test_flash_erase()

    def test_flash_update_aqc_fw_3x_no_kickstart(self):
        self.run_test_flash_update_aqc(self.FW_3X_TEST_VERSION, False)

    def test_flash_update_aqc_fw_1x_with_kickstart(self):
        if self.dut_fw_card in FELICITY_CARDS:
            self.run_test_flash_update_aqc(self.FW_1X_FELICITY_TEST_VERSION, True)
        elif self.dut_fw_card in BERMUDA_CARDS:
            pytest.skip("FW 2.X doesn't support Bermuda")
        else:
            self.run_test_flash_update_aqc(self.FW_1X_TEST_VERSION, True)

    def test_flash_update_aqc_fw_2x_with_kickstart(self):
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip("FW 2.X doesn't support Felicity")
        elif self.dut_fw_card in BERMUDA_CARDS:
            pytest.skip("FW 2.X doesn't support Bermuda")
        else:
            self.run_test_flash_update_aqc(self.FW_2X_TEST_VERSION, True)

    def test_flash_update_aqc_fw_3x_with_kickstart(self):
        if self.dut_fw_card in BERMUDA_CARDS:
            fw = firmware.Firmware(port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
                                   version=self.FW_3X_PREVIOUS_VERSION, mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
                                   pause=self.dut_fw_pause, pcirom=self.dut_fw_pcirom, dirtywake=self.dut_fw_dirtywake)
            clx_path = fw.download()
            self.run_flash_burn(clx_path)
            self.atltool.kickstart(reload_phy_fw=(self.dut_fw_card not in CARDS_FELICITY_BERMUDA))
            remove_file(clx_path)

        self.run_test_flash_update_aqc(self.FW_3X_TEST_VERSION, True)

    def test_flash_update_aqc_after_flash_burn_1x(self):
        if self.dut_fw_card in FELICITY_CARDS:
            self.run_test_flash_update_aqc_after_flash_burn(self.FW_3X_TEST_VERSION, self.FW_1X_FELICITY_TEST_VERSION)
        elif self.dut_fw_card in BERMUDA_CARDS:
            pytest.skip("FW 1.X doesn't support Bermuda")
        else:
            self.run_test_flash_update_aqc_after_flash_burn(self.FW_3X_TEST_VERSION, self.FW_1X_TEST_VERSION)

    def test_flash_update_aqc_after_flash_burn_2x(self):
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip("FW 2.X doesn't support Felicity")
        elif self.dut_fw_card in BERMUDA_CARDS:
            pytest.skip("FW 2.X doesn't support Bermuda")
        else:
            self.run_test_flash_update_aqc_after_flash_burn(self.FW_1X_TEST_VERSION, self.FW_2X_TEST_VERSION)

    def test_flash_update_aqc_after_flash_burn_3x(self):
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip("FW 2.X doesn't support Felicity")
        elif self.dut_fw_card in BERMUDA_CARDS:
            pytest.skip("FW 2.X doesn't support Bermuda")
        else:
            self.run_test_flash_update_aqc_after_flash_burn(self.FW_2X_TEST_VERSION, self.FW_3X_TEST_VERSION)

    def test_selftest_mac(self):
        config = copy.deepcopy(self.DEFAULT_SELFTEST_CONFIG)
        config["tests"]["datapath_tests"] = ["Mac"]
        self.run_test_selftest(config)

    def test_selftest_phy_loopback(self):
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip("Felicity has no PHY")
        else:
            config = copy.deepcopy(self.DEFAULT_SELFTEST_CONFIG)
            config["tests"]["datapath_tests"] = ["Phy Loopback"]
            self.run_test_selftest(config)

    @idparametrize("speed", ['100M', '2.5G', '5G', '10G'])
    def test_selftest_extloopback(self, speed):
        if self.dut_fw_card in BERMUDA_CARDS and speed == '10G':
            pytest.skip("Bermuda max 5G")
        else:
            config = copy.deepcopy(self.DEFAULT_SELFTEST_CONFIG)
            config["tests"]["datapath_tests"] = ["External Loopback"]
            config["Ethernet_Speed"] = [speed]
            self.run_test_selftest(config, speed)


    def test_selftest_lso(self):
        config = copy.deepcopy(self.DEFAULT_SELFTEST_CONFIG)
        config["tests"]["offload_tests"] = ["LSO"]
        self.run_test_selftest(config)

    # def create_config_for_automated_test(self):
    #     cfg_location = os.path.join(os.path.join(self.diag_dir, "config"), "test.cfg")
    #     with open(cfg_location, "w") as f:
    #         f.write('tests:\n\
    #                 datapath_tests: ["External Loopback"]\n\
    #                 memory_tests: []\n\
    #                 offload_tests: ["LSO"]\n\
    #                 flash_tests: []')
    #     return cfg_location

    # def test_stop_automated_mode_after_fail(self):
    #     cfg = self.create_config_for_automated_test()
    #     params = "-a {} -r".format(cfg)
    #     out = DiagWrapper.exec_single(params, self.diag_dir)

    #     if self.diag_ver >= TestDiag.BOUNDARY_DIAG_VER:
    #         assert "Starting External Loopback ({})".format(self.efused_adapter_speed) in out
    #         assert "Fail" in out
    #         assert "LSO" not in out, "LSO test has run"
    #     else:
    #         assert "Ending Ethernet Plug... RESULT = FAIL" in out, "Ethernet Plug test is not fail"
    #         assert "LSO" not in out, "LSO test has run"

    # def test_continue_automated_mode_after_fail(self):
    #     cfg = self.create_config_for_automated_test()
    #     params = "-a {} -r -c".format(cfg)
    #     out = DiagWrapper.exec_single(params, self.diag_dir)
    #     if self.diag_ver >= TestDiag.BOUNDARY_DIAG_VER:
    #         assert "Starting External Loopback ({})".format(self.efused_adapter_speed) in out, \
    #                                                 "External Loopback test not started"
    #         assert "Starting LSO " in out, "LSO test not run"
    #     else:
    #         assert "Ending Ethernet Plug... RESULT = FAIL" in out, "Ethernet Plug test is not fail"
    #         # ensure that LSO test starts
    #         assert "Starting LSO..." in out, "LSO test not run"
    #     # ensure that LSO test pass
    #     regexp_lso = "^.*{}.*passed.*$".format("LSO")
    #     regexp_eth_plug = "^.*{}.*passed.*$".format("External Loopback")
    #     matches_lso = re.findall(regexp_lso, out, re.MULTILINE)
    #     matches_eth_plug = re.findall(regexp_eth_plug, out, re.MULTILINE)
    #     assert "1 out of  1 passed (100.00%)" in matches_lso[-1], "LSO test not passed"
    #     assert "0 out of  1 passed (0.00%)" in matches_eth_plug[-1], "Eth Plug test is passed"

    # @idparametrize("argument", ["", "-i"])
    # def test_interactive_mode(self, argument):
    #     d = DiagWrapper(self.diag_dir, argument)
    #     d.init()
    #     d.append("0")
    #     out = d.commit()
    #     log.info("\n{}".format(out))
    #     welcome_msg = "Welcome to Aquantia NIC Diagnostics (Version {})"\
    #         .format(get_actual_diag_version(self.diag_version))
    #     assert welcome_msg in out, "Incorrect welcome msg"

    #     menu = (TestDiag.menu_items_B0 if self.chip_rev == CHIP_REV_B0 else TestDiag.menu_items_B1)
    #     for item in menu:
    #         assert item in out, "error item: {} not in menu".format(item)

    # @idparametrize("test_name", ["Mac", "Phy"])
    # def test_datapath(self, test_name):
    #     def get_packet_num(strings, packet_type):
    #         packet_num_regex = r"(\d+\,?)+"
    #         packet = self._get_string_contains(strings, packet_type)
    #         assert packet is not None, "No {} packets found".format(packet_type)
    #         packet_num = re.search(packet_num_regex, packet)
    #         assert packet_num is not None, "No packet len in: {}".format(packet)
    #         packet_num = packet_num.group().replace(",", "")
    #         return packet_num

    #     log.info("Start {} datapath test".format(test_name))
    #     params = "-t fast_datapath:{}".format(test_name)
    #     out = DiagWrapper.exec_single(params, self.diag_dir)

    #     if self.diag_ver >= TestDiag.BOUNDARY_DIAG_VER:
    #         assert "Starting {}".format(test_name) in out
    #         assert "Pass" in out
    #     else:
    #         assert "Starting {}...".format(test_name), "{} test not started".format(test_name)
    #         assert "Ending {}... RESULT = PASS".format(test_name) in out, "{} test not passed".format(test_name)
    #         out = out.split("\n")
    #         assert get_packet_num(out, "Transmitted") > 0, "Transmitted packets len = 0"
    #         assert get_packet_num(out, "Received") > 0, "Transmitted packets len = 0"
    #         assert get_packet_num(out, "Total Transmitted") == get_packet_num(out, "Total Received"), "" \
    #                                     "Total trasmitted packet len not equal Total Received packet len"

    # def test_lso(self):
    #     params = "-t offload:LSO"
    #     out = DiagWrapper.exec_single(params, self.diag_dir)

    #     if self.diag_ver >= TestDiag.BOUNDARY_DIAG_VER:
    #         assert "Starting LSO" in out, "LSO test not started"
    #         assert "Pass" in out, "LSO test not passed"
    #     else:
    #         assert "Ending LSO... RESULT = PASS" in out, "LSO test not passed"
    #         out = out.split("\n")
    #         iter_count = 0
    #         for line in out:
    #             if "Itr" in line:
    #                 iter_count += 1
    #                 assert "PASS" in line, "{} not passed".format(line)
    #                 items = line.split(',')
    #                 rdm = self._get_string_contains(items, "RDM")
    #                 expected_rdm = self._get_string_contains(items, "Expected RDM")
    #                 regexp = r"(\d+)"
    #                 rdm = int(re.search(regexp, rdm).group())
    #                 expected_rdm = int(re.search(regexp, expected_rdm).group())
    #                 assert rdm == expected_rdm, "RDM != Expected RDM in: {}".format(line)
    #         assert iter_count > 0, "No iteration were run"

    # @pytest.mark.skipif('win' not in sys.platform,
    #                      reason="Skip for linux due it requare cold reboot")
    # def test_flash_fields_mac(self):
    #     mac = rand_mac()
    #     params = "--password !h:ahT8uW6 --flash_fields mac_addr={}".format(mac.replace(":", "-"))
    #     out = DiagWrapper.exec_single(params, self.diag_dir)
    #     time.sleep(self.AFTER_BURN_DELAY)
    #     dev_inf = self.get_device_info()
    #     assert mac == dev_inf.mac, "mac is different, expected mac: {}, current mac: {}".format(mac, dev_inf.mac)

    # @pytest.mark.skipif('win' not in sys.platform,
    #                      reason="Skip for linux due it requare cold reboot")
    # def test_flash_fields_subsys(self):
    #     subsis = "{0:#0{1}x}".format(random.randint(0, 2**32-1), 10)
    #     params = "--password !h:ahT8uW6 --flash_fields subsys={}".format(subsis)
    #     out = DiagWrapper.exec_single(params, self.diag_dir)
    #     time.sleep(self.AFTER_BURN_DELAY)

    #     re_erased_flash = re.compile("Starting Read Whole Flash\s+\.\s+Pass", re.DOTALL)

    #     assert  re_erased_flash.search(out) != None, "Flash update failed"
    #     assert "NCB pointers were updated" in out, "Flash update failed"

    #     dev_inf = self.get_device_info()
    #     sub_sys_dev = int(dev_inf.subsystem_device_id, 16)
    #     sub_sys_ven = int(dev_inf.subsystem_vendor_id, 16)
    #     current_subsis = sub_sys_dev << 16 | sub_sys_ven

    #     # Assert as int() due internal Python issues
    #     assert int(subsis, 16) == current_subsis, "subsis is different, expected subsis: {}, current subsis: {}"\
    #         .format(subsis, current_subsis)

    # @idparametrize("password", ["!h:ahT8uW6", "12345"])
    # def test_password(self, password):
    #     menu = (copy.deepcopy(TestDiag.menu_items_B0) if self.chip_rev == CHIP_REV_B0 \
    #             else copy.deepcopy(TestDiag.menu_items_B1))

    #     not_allowed_items = ["e) Efuse",
    #                          "f) Flash edit",
    #                          "k) Kickstart MCP",
    #                          "x) Special Firmware"]

    #     if password == "!h:ahT8uW6":
    #         menu.append("s) Special configuration")
    #     else:
    #         not_allowed_items.append("s) Special configuration")

    #     params = "--password {}".format(password)
    #     d = DiagWrapper(self.diag_dir, params)
    #     d.init()
    #     d.append("0")
    #     out = d.commit()

    #     for item in menu:
    #         assert item in out, "error item: {} not in menu".format(item)

    #     for item in not_allowed_items:
    #         assert item not in out, "error item: {} in menu".format(item)

    # def test_vpd(self):
    #     params = "-v 2 -t misc:VPD_Read"
    #     out = DiagWrapper.exec_single(params, self.diag_dir)
    #     assert "Ending VPD Read... RESULT = PASS" in out, "VPD failed"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
