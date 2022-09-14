import os
import time

import pytest

from tools.firmware import Firmware
from tools.ops import OpSystem
from tools.driver import Driver
from tools.command import Command
from tools.firmware import list_files
from tools.constants import USB_CONNECT_CSWITCH, \
                            OS_WIN7_32, OS_WIN7_64, OS_WIN10_64, OS_WIN10_32, OS_WIN8_1_32, OS_WIN8_1_64

from tools.usb_control import USBControl
from tools.utils import get_atf_logger, upload_file
from infra.test_base import TestBase

log = get_atf_logger()

def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fiji_cdrom"

class TestFijiCDROM(TestBase):
    CDROM_TOTAL_SIZE = 991232

    @classmethod
    def setup_class(cls):
        super(TestFijiCDROM, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.dut_usb_control = USBControl(host=cls.dut_hostname, device=USB_CONNECT_CSWITCH)
            cls.dut_driver = Driver(port=cls.dut_port, version="pacific/stable", host=cls.dut_hostname)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_method(cls):
        super(TestFijiCDROM, cls).teardown_class()
        cls.install_normal_fw()

    @classmethod
    def install_normal_fw(cls):
         # Workaround for FW with CDROM (restore back the FW without CDROM)
        cls.dut_usb_control.enable(0)
        time.sleep(30)
        cls.dut_driver.install()
        time.sleep(3)

        dut_firmware = Firmware(host=cls.dut_hostname, port=cls.dut_port, card=cls.dut_fw_card, speed=cls.dut_fw_speed,
                                     version=cls.dut_fw_version)
        file_path = os.path.basename(dut_firmware.download())
        cmd = "cd qa-tests/tools && sudo aqusb-flash write {} -v".format(file_path)
        res = Command(cmd=cmd, host=cls.dut_hostname, silent=True).run()

        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to burn a FW")

        cls.dut_usb_control.disable(0)
        time.sleep(20)
        cls.dut_usb_control.enable(0)

    @classmethod
    def install_fw_with_cdrom(cls):
        cls.dut_usb_control.enable(0)
        time.sleep(30)
        dut_firmware = Firmware(host=cls.dut_hostname, port=cls.dut_port, card=cls.dut_fw_card, speed=cls.dut_fw_speed,
                                     version=cls.dut_fw_version, cdrom=True)

        dut_firmware.install()
        cls.dut_usb_control.disable(0)
        time.sleep(20)
        cls.dut_usb_control.enable(0)

    def restore_target_os(self, os):
        self.restore_os(os, self.dut_hostname)

    def check_cdrom_is_present(self):
        cmd_cdrom = 'python -c "import psutil; dps = psutil.disk_partitions(); \
               found = next(dps[i] for i in range(len(dps)) if \'cdrom\' in dps[i].opts); print found" '

        res = Command(cmd=cmd_cdrom, host=self.dut_hostname).run()

        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to check CDROM")

        assert len(res["output"]) == 1, "No CDROM was detected on host {}".format(self.dut_hostname)

        aq_mass_storage_name = "AQ Mass Storage USB Device"
        aq_mass_storage_id = "AQ______Mass_Storage____1"
        cmd_mass_storage = "devcon status {} | grep Name".format(aq_mass_storage_id)

        res = Command(cmd=cmd_mass_storage, host=self.dut_hostname).run()

        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to check device name")

        assert aq_mass_storage_name in res["output"][0], "Wrong device name in device manager"

        code = """
import wmi
disk = wmi.WMI().Win32_LogicalDisk(VolumeName="CDROM")[0]
name= "\\\\\\.\\\{}".format(disk.Name)

try:
    file(name, "r").read()
except Exception:
    print "FAIL"
else:
    print "PASS"
"""

        file = "tmp.py"
        with open(file, "w") as f:
            f.write(code)

        upload_file(self.dut_hostname, file, file)
        res = Command(cmd="sudo python {}".format(file), host=self.dut_hostname).run()
        time.sleep(5)

        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK or "PASS" not in res["output"][0]:
            raise Exception("Failed to check device name")

    def run_test_cdrom(self, os):
        self.install_fw_with_cdrom()
        self.dut_usb_control.disable(0)
        self.restore_target_os(os)
        self.dut_usb_control.enable(0)
        time.sleep(30)

        self.check_cdrom_is_present()

    def test_cdrom_win10_x64(self):
        """
        @description: This subtest performs check of CDROM functionality for Win10 x64.

        @steps:
        1. Install Win10 x64 on host.
        2. Plug Fiji dongle.
        3. Check if CDROM is available and DVD/CDROM string contains correct name in Dev manager.

        @result: CDROM is available and DVD/CDROM string contains correct name in Dev manager
        @duration: 10 minutes.
        @requirements: FIJI_CDROM_WIN_10_X64
        """
        self.run_test_cdrom(OS_WIN10_64)

    def test_cdrom_win10_x32(self):
        """
        @description: This subtest performs check of CDROM functionality for Win10 x32.

        @steps:
        1. Install Win10 x32 on host.
        2. Plug Fiji dongle.
        3. Check if CDROM is available and DVD/CDROM string contains correct name in Dev manager.

        @result: CDROM is available and DVD/CDROM string contains correct name in Dev manager
        @duration: 10 minutes.
        @requirements: FIJI_CDROM_WIN_10_X32
        """
        self.run_test_cdrom(OS_WIN10_32)

    def test_cdrom_win8_1_x32(self):
        """
        @description: This subtest performs check of CDROM functionality for Win8.1 x32.

        @steps:
        1. Install Win8.1 x32 on host.
        2. Plug Fiji dongle.
        3. Check if CDROM is available and DVD/CDROM string contains correct name in Dev manager.

        @result: CDROM is available and DVD/CDROM string contains correct name in Dev manager
        @duration: 10 minutes.
        @requirements: FIJI_CDROM_WIN_8_1_X32
        """
        self.run_test_cdrom(OS_WIN8_1_32)

    def test_cdrom_win8_1_x64(self):
        """
        @description: This subtest performs check of CDROM functionality for Win8.1 x64.

        @steps:
        1. Install Win8.1 x64 on host.
        2. Plug Fiji dongle.
        3. Check if CDROM is available and DVD/CDROM string contains correct name in Dev manager.

        @result: CDROM is available and DVD/CDROM string contains correct name in Dev manager
        @duration: 10 minutes.
        @requirements: FIJI_CDROM_WIN_8_1_X64
        """
        self.run_test_cdrom(OS_WIN8_1_64)

if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
