import os
import io
import time
import urlparse
import ntpath
import zipfile
import re
import shutil

import pytest

from tools.firmware import Firmware
from tools.driver import Driver
from tools.command import Command
from tools.constants import USB_CONNECT_CSWITCH, BUILDS_SERVER
from tools.usb_control import USBControl
from tools.utils import get_atf_logger, get_url_response, remove_directory, remove_file
from tools.aq_wmi import Aq_UsbNetAdapter
from infra.test_base import TestBase


log = get_atf_logger()

path_to_zip = "tools/usb-flash-update/{}/bin/aqusbupdate_ver{}.zip"
bdp_qnap = "Qnap"
fw_for_check_before = "pacific/3.1.4_FW_RELEASE-563"
fw_for_check_after = "pacific/3.1.2_FW_RELEASE-540"

path_to_logs = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

def download_from_url(suburl):
    usb_tool_ver = os.environ.get("USB_TOOLS", "1.0.0")
    url = urlparse.urljoin(BUILDS_SERVER, suburl.format(usb_tool_ver, usb_tool_ver))
    fname = ntpath.basename(suburl)
    log.debug("Downloading {} from {}".format(fname, url))
    content = get_url_response(url)
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        archive.extractall(os.path.dirname(os.path.abspath(__file__)))

def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "usb_flash_update"

class TestUsbFlashUpdate(TestBase):
    MAC_IRAM_POINTER = 0x2c, 3
    AFTER_BURN_TIMEOUT = 4
    EXEC_PATH = "cd qa-tests/ && sudo ./aqusbupdate -q "

    @classmethod
    def setup_class(cls):
        super(TestUsbFlashUpdate, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.dut_usb_control = USBControl(host=cls.dut_hostname, device=USB_CONNECT_CSWITCH)
            cls.dut_driver = Driver(port=cls.dut_port, version="pacific/stable", host=cls.dut_hostname)
            cls.dut_driver.install()

            download_from_url(path_to_zip)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def teardown_method(self, method):
        super(TestUsbFlashUpdate, self).teardown_method(method)

        if os.path.exists(path_to_logs):
            remove_directory(path_to_logs)

    def burn_device(self, version, bdp=None, aq_update_tool=False, skip_fails=False):
        dut_firmware = Firmware(host=self.dut_hostname, port=self.dut_port, card=self.dut_fw_card,
                                    speed=self.dut_fw_speed, version=version, bdp=bdp)

        self.file_path = os.path.basename(dut_firmware.download())
        if not aq_update_tool:
            cmd = "cd qa-tests/ && sudo aqusb-flash write {} -v".format(self.file_path)
        else:
            cmd = self.EXEC_PATH + "{}".format(self.file_path)
        res = Command(cmd=cmd, host=self.dut_hostname, silent=True).wait(timeout=60)

        if not skip_fails:
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to burn a FW")

        self.dut_usb_control.disable(0)
        time.sleep(self.AFTER_BURN_TIMEOUT)
        self.dut_usb_control.enable(0)
        time.sleep(self.AFTER_BURN_TIMEOUT)
        return res["output"]

    def check_fw_version(self):
        expected_version = self.get_actual_firmware_version(fw_for_check_after)
        log.info("Expected FW version: {}".format(expected_version))
        re_fw_ver = re.compile(".*((\d+)\.(\d+)\.(\d+)).*")
        m = re_fw_ver.match(expected_version)
        if m is None:
            raise Exception("Invalid expected version: {}".format(expected_version))
        ver_high = int(m.group(2))
        ver_mid = int(m.group(3))
        ver_low = int(m.group(4))

        aq_wmi = Aq_UsbNetAdapter()
        ver_major = int(aq_wmi.ReadReg8(0xda) & 0x7f)
        ver_minor = int(aq_wmi.ReadReg8(0xdb))
        ver_release = int(aq_wmi.ReadReg8(0xdc))

        log.info("Actual FW version in registers 0xda:0xdc: {}.{}.{}".format(ver_major, ver_minor, ver_release))
        assert ver_high == ver_major and ver_mid == ver_minor and ver_low == ver_release

    def check_logs(self):
        assert os.path.exists(path_to_logs)
        sub_log = os.listdir(path_to_logs)[0]
        assert os.path.exists(os.path.join(path_to_logs, sub_log, "trace.etl"))

    def corrupt_clx(self, clx_file, ncb_num, ptr, shift_offset=0):
        ptr_addr = ptr[0]
        ptr_size = ptr[1]

        if ncb_num == 1:
            ptr_addr += 0x4000

        # Read Pointer
        cmd = "cd qa-tests/; xxd -s {} -l {} -e {} | awk '{{print $2}}'".format(ptr_addr, ptr_size, clx_file)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        offset = int(res["output"][0], 16)
        offset += shift_offset

        # Corrupt block
        crptd_clx = 'ncb{}_block_0x{:02x}_corrupted.clx'.format(ncb_num, ptr_addr)
        cmd = "cd qa-tests/; cp {} {}".format(clx_file, crptd_clx)
        Command(cmd=cmd, host=self.dut_hostname).run()
        # cmd = "dd if=/dev/urandom of={} bs=1 count=20 seek={} conv=notrunc".format(crptd_clx, offset)
        cmd = "tr '\\0' '\\377' < /dev/zero | dd of={} bs=1 count=20 seek={} conv=notrunc".format(crptd_clx, offset)
        Command(cmd=cmd, host=self.dut_hostname).run()

        return crptd_clx

    def test_update_workflow(self):
        """
        @description: This test validates direct workflow for update tool

        @steps:
        1. Burn initial QNAP firmware to the dongle
        2. Burn next QNAP firmware to the dongle with QNAP update tool
        3. Check if firmware successfully updated
        4. Check if device was started with no errors

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.burn_device(fw_for_check_before, bdp=bdp_qnap)
        output = self.burn_device(fw_for_check_after, bdp=bdp_qnap, aq_update_tool=True)

        assert any("Firmware successfully updated" in line for line in output)

        fail = False
        try:
            self.dut_driver.check_driver_status()
        except RuntimeError as e:
            fail = True

        assert not fail
        self.check_fw_version()

    def test_no_qnap_dev(self):
        """
        @description: This test validates impossibility of burning to the non QNAP device

        @steps:
        1. Burn initial non QNAP firmware to the dongle
        2. Burn next QNAP firmware to the dongle with QNAP update tool
        3. Check if firmware have not been updated

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.burn_device(fw_for_check_before)
        output = self.burn_device(fw_for_check_after, bdp=bdp_qnap, aq_update_tool=True, skip_fails=True)

        assert any("No devices found" in line for line in output)

    def test_logs(self):
        """
        @description: This test validates logging of update tool

        @steps:
        1. Burn initial QNAP firmware to the dongle
        2. Burn next QNAP firmware to the dongle with QNAP update tool
        3. Check if logs folder is present

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.burn_device(fw_for_check_before, bdp=bdp_qnap)
        self.burn_device(fw_for_check_after, bdp=bdp_qnap, aq_update_tool=True)

        self.check_logs()

    def test_no_qnap_fw(self):
        """
        @description: This test validates impossibility of burning non QNAP firmware

        @steps:
        1. Burn initial QNAP firmware to the dongle
        2. Burn next non QNAP firmware to the dongle with QNAP update tool
        3. Check if firmware have not been updated

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.burn_device(fw_for_check_before, bdp=bdp_qnap)
        output = self.burn_device(fw_for_check_after, aq_update_tool=True, skip_fails=True)

        assert any("The device cannot be updated. Reason: not compatible with this firmware" in line for line in output)

    def test_coprrupted_fw_ncb0(self):
        """
        @description: This test validates impossibility of burning QNAP firmware corrupted ncb0

        @steps:
        1. Burn initial QNAP firmware to the dongle
        2. Burn corrupted QNAP firmware to the dongle with QNAP update tool
        3. Check if firmware have not been updated

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.burn_device(fw_for_check_before, bdp=bdp_qnap)
        crptd_clx = self.corrupt_clx(self.file_path, ncb_num=0, ptr=self.MAC_IRAM_POINTER)

        cmd = self.EXEC_PATH + "{}".format(crptd_clx)
        output = Command(cmd=cmd, host=self.dut_hostname).run()["output"]
        assert any("Firmware image for writing is not valid" in line for line in output)

    def test_coprrupted_fw_ncb1(self):
        """
        @description: This test validates impossibility of burning QNAP firmware corrupted ncb1

        @steps:
        1. Burn initial QNAP firmware to the dongle
        2. Burn corrupted QNAP firmware to the dongle with QNAP update tool
        3. Check if firmware have not been updated

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.burn_device(fw_for_check_before, bdp=bdp_qnap)
        crptd_clx = self.corrupt_clx(self.file_path, ncb_num=1, ptr=self.MAC_IRAM_POINTER)

        cmd = self.EXEC_PATH + "{}".format(crptd_clx)
        output = Command(cmd=cmd, host=self.dut_hostname).run()["output"]
        assert any("Firmware image for writing is not valid" in line for line in output)

    def test_backup(self):
        """
        @description: This test validates backuping with QNAP tool

        @steps:
        1. Burn initial QNAP firmware to the dongle with QNAP update tool
        2. Burn next QNAP firmware to the dongle with QNAP update tool
        3. Check if firmware have been updated
        4. Burn device with layout.bin located in log dir
        5. Check if firmware have been updated, and its version coincides the initial one

        @result: All checks are passed.
        @duration: 3 minutes.
        """

        # Burn QNAP with regular tool before test
        if os.path.exists("layout.bin"):
            remove_file("layout.bin")

        self.burn_device(fw_for_check_before, bdp=bdp_qnap)
        self.burn_device(fw_for_check_after, bdp=bdp_qnap, aq_update_tool=True)
        remove_directory(path_to_logs)
        self.burn_device(fw_for_check_before, bdp=bdp_qnap, aq_update_tool=True)

        sub_log = os.listdir(path_to_logs)[0]
        # Hack for 'No file found error'
        shutil.move(os.path.join("logs", sub_log, "layout.bin"), ".")
        cmd = self.EXEC_PATH + "layout.bin"

        res = Command(cmd=cmd, host=self.dut_hostname).run()
        assert res["returncode"] == 0
        assert any("Firmware successfully updated" in line for line in res["output"])

        self.dut_usb_control.disable(0)
        time.sleep(self.AFTER_BURN_TIMEOUT)
        self.dut_usb_control.enable(0)
        time.sleep(self.AFTER_BURN_TIMEOUT)

        self.check_fw_version()


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])