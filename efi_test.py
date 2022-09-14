import contextlib
import os
import io
import tempfile
import time
import urlparse
import zipfile

import pytest
import re

from tools.constants import BUILDS_SERVER
from tools.command import Command
from tools.power import Power
from tools.utils import get_atf_logger, upload_file, upload_directory, remove_directory, \
    get_url_response, download_directory, download_file

from infra.test_base import TestBase

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "efi_test"


class TestEFITools(TestBase):
    TIMEOUT = 30
    EFI_RUN_TIMEOUT = 40
    POWER_UP_TIMEOUT = 100
    EFI_TOOL_DIR = "tools"
    USB_PATH = "/media/usb/EFI/BOOT"
    OUTPUT = "TEST_OUTPUT"

    @classmethod
    def setup_class(cls):
        super(TestEFITools, cls).setup_class()
        cls.log_server_dir = cls.create_logs_dir_on_log_server()

        try:
            cmd = "rm -rf {}/{}".format(cls.USB_PATH, cls.EFI_TOOL_DIR)
            Command(host=cls.dut_hostname, cmd=cmd).run()
            cmd = "rm -rf {}/efi_test.nsh".format(cls.USB_PATH)
            Command(host=cls.dut_hostname, cmd=cmd).run()
            cmd = "rm -rf {}/{}".format(cls.USB_PATH, cls.OUTPUT)
            Command(host=cls.dut_hostname, cmd=cmd).run()

            cls.mount_flash("/media/usb", host=cls.dut_hostname)

            dir_tool = cls.download_efi_tool(cls.efi_version, cls.working_dir)
            download_file("nn-nfs01", "/storage/export/qa/testing/sha256.bin", os.path.join(dir_tool, "sha256.bin"))
            download_file("nn-nfs01", "/storage/export/qa/testing/pcicfg.bin", os.path.join(dir_tool, "pcicfg.bin"))

            upload_directory(cls.dut_hostname, dir_tool, cls.USB_PATH)
            upload_file(cls.dut_hostname, "efi_test.nsh", cls.USB_PATH + "/efi_test.nsh")
            cls.launch_efi_tests()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def download_efi_tool(cls, version, base_dir=None):
        log.info("Downloading efi...")
        if base_dir is None:
            directory = tempfile.mkdtemp()
        else:
            directory = os.path.join(base_dir, cls.EFI_TOOL_DIR)
            remove_directory(directory)
            os.mkdir(directory)

        url = urlparse.urljoin(BUILDS_SERVER, "tools/efi/{}/efi.zip".format(version))
        log.debug("Downloading EFI from {}".format(url))
        content = get_url_response(url)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            archive.extractall(directory)
        log.debug("EFI has been downloaded and extracted to {}".
                  format(directory))

        return directory

    @staticmethod
    def mount_flash(usb_dir="/media/usb", host='localhost'):
        cmd = "sudo fdisk -l | grep FAT16 | awk '{print $1}'"
        out = Command(host=host, cmd=cmd).run()["output"]
        if out:
            device = out[0]
        else:
            raise Exception("Not USB Flash(FAT16) in machine")
        cmd = "mkdir -p {}".format(usb_dir)
        Command(host=host, cmd=cmd).run()
        cmd = "sudo umount {}".format(usb_dir)
        Command(host=host, cmd=cmd).run()
        cmd = "sudo mount {} {} -o umask=000".format(device, usb_dir)
        Command(host=host, cmd=cmd).run()

    def read_output(self, test):
        log.info("Analyze {} output".format(test))
        path_to_out = os.path.join(self.working_dir, self.OUTPUT, test)
        if not os.path.exists(path_to_out):
            raise Exception("Output '{}' from AtlSwitchNcb.efi not found ".format(path_to_out))
        res = ""
        log.info("file name os -> {}".format(path_to_out))
        with io.open(path_to_out, mode='r', encoding='utf16') as f:
            res = f.read()
            log.info(res)
        return res

    @staticmethod
    def get_actual_efi_tool_version(version):
        suburl = "tools/efi/{}/version.txt".format(version)
        url = urlparse.urljoin(BUILDS_SERVER, suburl)
        response = get_url_response(url)
        return response.rstrip("\r\n")

    @classmethod
    def launch_efi_tests(cls):
        Power(host=cls.dut_hostname).reboot()
        time.sleep(cls.TIMEOUT)
        # if not self.is_host_powered_on(self.dut_hostname):
        #    raise Exception("DUT didn't light up power LED after magic packet")
        log.info("EFI shell tests are running")
        time.sleep(cls.EFI_RUN_TIMEOUT)

        if not cls.poll_host_alive(cls.dut_hostname, cls.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back after reboot".format())

        cls.mount_flash("/media/usb", host=cls.dut_hostname)
        download_directory(cls.dut_hostname, "{}/{}".format(cls.USB_PATH, cls.OUTPUT), cls.working_dir)

    ######################################## switch_ncb ##############################################################

    def test_switch_ncb(self):
        output = self.read_output("switchNCB.txt")

        ncb = re.findall("CURRENT NCB IS (.+) \*\*", output, re.MULTILINE)
        if len(ncb) != 3:
            raise Exception("Not launched all getNCB.efi")
        switch_ncb = re.findall("SUCCESS \((.+) is now valid, (.+) is now invalid", output, re.MULTILINE)
        if len(switch_ncb) != 2:
            raise Exception("Not launched all switchNCB.efi with SUCCESS")
        switch_ncb = [switch_ncb[0][1], switch_ncb[0][0], switch_ncb[1][0]]
        if ncb != switch_ncb:
            raise Exception("Not correct switch NCB get: {} != switch: {}".format(ncb, switch_ncb))

    def test_switch_ncb_dev_num_0(self):
        output = self.read_output("switchNCB_dev_num_0.txt")
        if "SUCCESS" not in output:
            raise Exception("Not Success in <tool>.efi -dev_num 0")

    def test_switch_ncb_dev_num_20(self):
        output = self.read_output("switchNCB_dev_num_20.txt")
        if "Error! Was only able to find" not in output:
            raise Exception("should be error. We don't have dev 20 <tool>.efi -dev_num 20")

    def test_switch_ncb_dev_num_21(self):
        output = self.read_output("switchNCB_dev_num_21.txt")
        if not "Error! Flag -dev_num only allows values up to 32" in output:
            raise Exception("should be error. <tool>.efi -dev_num 21")

    ######################################## help ##############################################################

    def test_switch_help(self):
        output = self.read_output("switchNCB_help.txt")
        if not "AtlSwitchNcb.efi" in output:
            raise Exception("Not help usage")
        if not "switch current NCB" in output:
            raise Exception("Not help info")

    def test_chip_reset_help(self):
        output = self.read_output("ChipReset_help.txt")
        if not "AtlChipReset.efi" in output:
            raise Exception("Not help usage")
        if not "This utility will perform a chip reset" in output:
            raise Exception("Not help info")

    def test_dump_flash_help(self):
        output = self.read_output("DumpFlash_help.txt")
        if not "AtlDumpFlash.efi" in output:
            raise Exception("Not help usage")
        if not "This utility will always dump out" in output:
            raise Exception("Not help info")

    def test_efuse_burnB1_help(self):
        output = self.read_output("EfuseBurnB1_help.txt")
        if "AtlEfuseBurnB1.efi" not in output:
            raise Exception("Not help usage")
        if "Will burn flashless configuration, using clx file to burn efuse" not in output:
            raise Exception("Not help info")

    def test_efuse_read_help(self):
        output = self.read_output("EfuseRead_help.txt")
        if not "AtlEfuseRead.efi" in output:
            raise Exception("Not help usage")
        if not "This utility will always dump" in output:
            raise Exception("Not help info")

    def test_get_NCB_help(self):
        output = self.read_output("getNCB_help.txt")
        if not "AtlGetNcb.efi" in output:
            raise Exception("Not help usage")
        if not "This utility will print out current NCB" in output:
            raise Exception("Not help info")

    def test_read_reg_help(self):
        output = self.read_output("ReadReg_help.txt")
        if not "AtlReadReg.efi" in output:
            raise Exception("Not help usage")
        if not "This utility will read 1 Atlantic register" in output:
            raise Exception("Not help info")

    def test_reset_done_help(self):
        output = self.read_output("ResetDone_help.txt")
        if not "AtlResetDone.efi" in output:
            raise Exception("Not help usage")
        if not "This utility will check if HW reset" in output:
            raise Exception("Not help info")

    ######################################## version ##############################################################

    def test_switch_version(self):
        current_version = self.get_current_version_efi(self.efi_version)
        output = self.read_output("switchNCB_version.txt")
        if current_version not in output and "Version" not in output:
            raise Exception("Version incorrect")

    def test_chip_reset_version(self):
        current_version = self.get_current_version_efi(self.efi_version)
        output = self.read_output("ChipReset_version.txt")
        if current_version not in output and "Version" not in output:
            raise Exception("Version incorrect")

    def test_dump_flash_version(self):
        current_version = self.get_current_version_efi(self.efi_version)
        output = self.read_output("DumpFlash_version.txt")
        if current_version not in output and "Version" not in output:
            raise Exception("Version incorrect")

    def test_efuse_burnB1_version(self):
        current_version = self.get_current_version_efi(self.efi_version)
        output = self.read_output("EfuseBurnB1_version.txt")
        if current_version not in output and "Version" not in output:
            raise Exception("Version incorrect")

    def test_efuse_read_version(self):
        current_version = self.get_current_version_efi(self.efi_version)
        output = self.read_output("EfuseRead_version.txt")
        if current_version not in output and "Version" not in output:
            raise Exception("Version incorrect")

    def test_getNCB_version(self):
        current_version = self.get_current_version_efi(self.efi_version)
        output = self.read_output("getNCB_version.txt")
        if current_version not in output and "Version" not in output:
            raise Exception("Version incorrect")

    def test_read_reg_version(self):
        current_version = self.get_current_version_efi(self.efi_version)
        output = self.read_output("ReadReg_version.txt")
        if current_version not in output and "Version" not in output:
            raise Exception("Version incorrect")

    def test_reset_done_version(self):
        current_version = self.get_current_version_efi(self.efi_version)
        output = self.read_output("ResetDone_version.txt")
        if current_version not in output and "Version" not in output:
            raise Exception("Version incorrect")

    ######################################## chip_reset ##############################################################

    def test_chip_reset(self):
        output = self.read_output("ChipReset.txt")
        if not "MAC kickstart complete" in output:
            raise Exception("MAC kickstart failed")
        if not "PHY kickstart complete" in output:
            raise Exception("PHY kickstart failed")
        if not "CHIP RESET DONE" in output:
            raise Exception("Not Success in <tool>.efi")

    def test_chip_reset_phy_0(self):
        output = self.read_output("ChipReset_phy_0.txt")
        if not "CHIP RESET DONE" in output:
            raise Exception("Not Success in <tool>.efi -phy 0")

    def test_chip_reset_phy_1(self):
        output = self.read_output("ChipReset_phy_1.txt")
        if not "MAC kickstart complete" in output:
            raise Exception("MAC kickstart failed")
        if not "PHY kickstart failed " in output:
            raise Exception("PHY kickstart complete, should be fail with phy id 1")

    def test_chip_reset_skip(self):
        output = self.read_output("ChipReset_skip.txt")
        if "PHY kickstart" in output:
            raise Exception("Found PHY kickstart, should be skip phy kickstart")
        if not "CHIP RESET DONE" in output:
            raise Exception("Not Success in AtlChipReset.efi -phy_id 1 -skip_phy_kickstart")

    def test_chip_reset_dev_num_0(self):
        output = self.read_output("ChipReset_dev_num_0.txt")
        if not "CHIP RESET DONE" in output:
            raise Exception("Not Success in <tool>.efi -dev_num 0")

    def test_chip_reset_dev_num_20(self):
        output = self.read_output("ChipReset_dev_num_20.txt")
        if not "Error! Was only able to find" in output:
            raise Exception("should be error. We don't have dev 20 <tool>.efi -dev_num 20")

    def test_chip_reset_dev_num_21(self):
        output = self.read_output("ChipReset_dev_num_21.txt")
        if not "Error! Flag -dev_num only allows values up to 32" in output:
            raise Exception("should be error. <tool>.efi -dev_num 21")

    ######################################## dump_flash ##############################################################

    def test_dump_flash(self):
        output = self.read_output("DumpFlash.txt")
        if "SUCCESS" not in output and "Successfully" not in output:
            raise Exception("Failed flash dump")

    def test_dump_flash_dev_num_0(self):
        output = self.read_output("DumpFlash_dev_num_0.txt")
        if not "SUCCESS" in output:
            raise Exception("Not Success in <tool>.efi -dev_num 0")

    def test_dump_flash_dev_num_20(self):
        output = self.read_output("DumpFlash_dev_num_20.txt")
        if not "Error! Was only able to find" in output:
            raise Exception("should be error. We don't have dev 20 <tool>.efi -dev_num 20")

    def test_dump_flash_dev_num_21(self):
        output = self.read_output("DumpFlash_dev_num_21.txt")
        if not "Error! Flag -dev_num only allows values up to 32" in output:
            raise Exception("should be error. <tool>.efi -dev_num 21")

    ############################################## efuse_burn ########################################################

    def test_efuse_burn_ncbstart_0(self):
        output = self.read_output("EfuseBurnB1_ncbstart_0.txt")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_ncbstart_1(self):
        output = self.read_output("EfuseBurnB1_ncbstart_1.txt")
        if "Checking if RMW is supported...Flash supports it" not in output:
            raise Exception("Flash not support")
        if "Error! The current NCB is" not in output:
            raise Exception("Flash not support")

    def test_efuse_burn_ncbstart_10(self):
        output = self.read_output("EfuseBurnB1_ncbstart_10.txt")
        if "Error! Flag -ncbstart only allows values up to 1" not in output:
            raise Exception("Works, But should not error. Flag -ncbstart only allows values up to 1")

    def test_efuse_burn_ncbstart(self):
        output = self.read_output("EfuseBurnB1_ncbstart.txt")
        if "Error! Flag -ncbstart requires a value!" not in output:
            raise Exception("Not in output: Error! Flag -ncbstart requires a value!")

    def test_efuse_burn_ncbend_0(self):
        output = self.read_output("EfuseBurnB1_ncbend_0.txt")
        if "Checking if RMW is supported...Flash supports it" not in output:
            raise Exception("Flash not support")
        if "Error! The current NCB is" not in output:
            raise Exception("Flash not support")

    def test_efuse_burn_ncbend_1(self):
        output = self.read_output("EfuseBurnB1_ncbend_1.txt")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_ncbend_10(self):
        output = self.read_output("EfuseBurnB1_ncbend_10.txt")
        if "Error! Flag -ncbend only allows values up to 1" not in output:
            raise Exception("Works, But should not error. Flag -ncbend only allows values up to 1")

    def test_efuse_burn_ncbend(self):
        output = self.read_output("EfuseBurnB1_ncbend.txt")
        if "Error! Flag -ncbend requires a value!" not in output:
            raise Exception("Not in output: Error! Flag -ncbend requires a value!")

    def test_efuse_burn_flashless_0(self):
        output = self.read_output("EfuseBurnB1_flashless_0.txt")
        if "[62]0x27020" not in output:
            raise Exception("Error: Not burn 62 dword to 27020")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_flashless_1(self):
        output = self.read_output("EfuseBurnB1_flashless_1.txt")
        if "[62]0x27000" not in output:
            raise Exception("Error: Not burn 62 dword to 0x27000")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_flashless_not_val(self):
        output = self.read_output("EfuseBurnB1_flashless.txt")
        if not "Flag -flashless requires a value" in output:
            raise Exception("Works, But should not work")

    def test_efuse_burn_pcicfg_0(self):
        output = self.read_output("EfuseBurnB1_pcicfg_0.txt")
        if "[62]0x27400" not in output:
            raise Exception("Error: Not burn 62 dword to 0x27400")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_pcicfg_1(self):
        output = self.read_output("EfuseBurnB1_pcicfg_1.txt")
        if "[62]0x27600" not in output:
            raise Exception("Error: Not burn 62 dword to 0x27600")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_lock_bit_0(self):
        output = self.read_output("EfuseBurnB1_lock_bit_0.txt")
        if "[127]0x0" not in output:
            raise Exception("Error: Not burn 127 dword to 0x0")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_lock_bit_1(self):
        output = self.read_output("EfuseBurnB1_pcicfg_1.txt")
        if "[127]0x0" not in output:
            raise Exception("Error: Not burn 127 dword to 0x0")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_lock_bit_sha(self):
        output = self.read_output("EfuseBurnB1_lock_bit_sha.txt")
        if "[121]0x61393177 [122]0xDCB4449F [123]0xF865057 [124]0x8C74398D [125]0xE5D3DAE7" not in output:
            raise Exception("Error: No Hash")
        if "[127]0x80000000" not in output:
            raise Exception("Error: Not burn 127 dword to 0x8")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_lock_bit_10(self):
        output = self.read_output("EfuseBurnB1_lock_bit_10.txt")
        if "Error! Flag -lock_bit only allows values up to 1" not in output:
            raise Exception("Error! Flag -lock_bit only allows values up to 1, but you entered 16!")

    def test_efuse_burn_lock_bit(self):
        output = self.read_output("EfuseBurnB1_lock_bit.txt")
        if "Error! Flag -lock_bit requires a value" not in output:
            raise Exception("Error! Flag -lock_bit requires a value")

    def test_efuse_burn_mac(self):
        output = self.read_output("EfuseBurnB1_mac.txt")
        if "[40]0x11223344 [41]0x55660000" not in output:
            raise Exception("Error: Not burn MAC dword to 11-22-33-44-55-66")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_mac_incorrect(self):
        output = self.read_output("EfuseBurnB1_mac_incorrect.txt")
        if "Invalid MAC Address format" not in output:
            raise Exception("Error: Invalid MAC Address format")

    def test_efuse_burn_pcicfg_bin(self):
        output = self.read_output("EfuseBurnB1_pcicfg_bin.txt")
        if "[64]0xEFDA0001 [65]0x7B11D6A [66]0x2000002 [67]0x187106B [68]0x0 [69]0x40001 [70]0xFFFFFFFF [71]0xF004FFFF [72]0xFFFFFFFF [73]0x4FFFF [74]0xFFFFFFC0" not in output:
            raise Exception("Error: PCICONFIG setting error")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_pcicfg_bin_incorrect(self):
        output = self.read_output("EfuseBurnB1_pcicfg_bin_incorrect.txt")
        if "PCI Cfg bin file was not the valid marker default" not in output:
            raise Exception("Error: PCI Cfg bin file was not the valid marker default")

    def test_efuse_burn_sha_bin(self):
        output = self.read_output("EfuseBurnB1_sha_bin.txt")
        if "[121]0x61393177 [122]0xDCB4449F [123]0xF865057 [124]0x8C74398D [125]0xE5D3DAE7" not in output:
            raise Exception("Error: No Hash")
        if "[127]0x80000000" not in output:
            raise Exception("Error: Not burn 127 dword to 0x8")
        if "Correct CRC for loaded" not in output:
            raise Exception("Incorrect CRC")
        if "Sample of efuseBufFilled" not in output:
            raise Exception("Not efuse")
        if "Efusing agent didn't start successfully" not in output:
            raise Exception("Efusing agent start successfully")
        if "FAILURE!!! EFUSE BURNING FAILED" not in output:
            raise Exception("Efusing passing - fail!!!")

    def test_efuse_burn_sha_bin_incorrect(self):
        output = self.read_output("EfuseBurnB1_sha_bin_incorrect.txt")
        if "File size is 96 bytes, but should be 32 bytes" not in output:
            raise Exception("Error: File size is 96 bytes, but should be 32 bytes")

    def test_efuse_burn_dev_num_0(self):
        output = self.read_output("EfuseBurnB1_dev_num_0.txt")
        if not "Sample of efuseBufFilled" in output:
            raise Exception("Not Success in <tool>.efi -dev_num 0")

    def test_efuse_burn_dev_num_20(self):
        output = self.read_output("EfuseBurnB1_dev_num_20.txt")
        if not "Error! Was only able to find" in output:
            raise Exception("should be error. We don't have dev 20 <tool>.efi -dev_num 20")

    def test_efuse_burn_dev_num_21(self):
        output = self.read_output("EfuseBurnB1_dev_num_21.txt")
        if not "Error! Flag -dev_num only allows values up to 32" in output:
            raise Exception("should be error. <tool>.efi -dev_num 21")

    ######################################## get_ncb ##############################################################

    def test_get_ncb_dev_num_0(self):
        output = self.read_output("getNCB_dev_num_0.txt")
        if not "CURRENT NCB IS" in output:
            raise Exception("Not Success in <tool>.efi -dev_num 0")

    def test_get_ncb_dev_num_20(self):
        output = self.read_output("getNCB_dev_num_20.txt")
        if not "Error! Was only able to find" in output:
            raise Exception("should be error. We don't have dev 20 <tool>.efi -dev_num 20")

    def test_get_ncb_dev_num_21(self):
        output = self.read_output("getNCB_dev_num_21.txt")
        if not "Error! Flag -dev_num only allows values up to 32" in output:
            raise Exception("should be error. <tool>.efi -dev_num 21")

    ######################################## read_reg ##############################################################

    def test_read_reg_18(self):
        output = self.read_output("ReadReg_18.txt")
        if not "Value for register" in output:
            raise Exception("Cannot read register")
        if not "0x18: 0x30" in output:
            raise Exception("Incorrect value")

    def test_read_reg_dev_num_0(self):
        output = self.read_output("ReadReg_dev_num_0.txt")
        if not "Wrong number of commands" in output:
            raise Exception("Not Success in <tool>.efi -dev_num 0")

    def test_read_reg_dev_num_20(self):
        output = self.read_output("ReadReg_dev_num_20.txt")
        if not "Error! Was only able to find" in output:
            raise Exception("should be error. We don't have dev 20 <tool>.efi -dev_num 20")

    def test_read_reg_dev_num_21(self):
        output = self.read_output("ReadReg_dev_num_21.txt")
        if not "Error! Flag -dev_num only allows values up to 32" in output:
            raise Exception("should be error. <tool>.efi -dev_num 21")

    ######################################## efuse_read ##############################################################

    def test_efuse_read(self):
        output = self.read_output("EfuseRead.txt")
        if not "Efuse contents" in output:
            raise Exception("Not Efuse contents")
        if not "Writing efuse contents to efuse_read.bin" in output:
            raise Exception("Cannot write to bin file")
        if not "Successfully" in output:
            raise Exception("Not Success in <tool>.efi -dev_num 0")

    def test_efuse_read_dev_num_0(self):
        output = self.read_output("EfuseRead_dev_num_0.txt")
        if not "Successfully " in output:
            raise Exception("Not Success in <tool>.efi -dev_num 0")

    def test_efuse_read_dev_num_20(self):
        output = self.read_output("EfuseRead_dev_num_20.txt")
        if not "Error! Was only able to find" in output:
            raise Exception("should be error. We don't have dev 20 <tool>.efi -dev_num 20")

    def test_efuse_read_dev_num_21(self):
        output = self.read_output("EfuseRead_dev_num_21.txt")
        if not "Error! Flag -dev_num only allows values up to 32" in output:
            raise Exception("should be error. <tool>.efi -dev_num 21")

    ######################################## reset_done ##############################################################

    def test_reset_done(self):
        output = self.read_output("ResetDone.txt")
        if not "RESET CHECK PASSED" in output:
            raise Exception("Not Success in <tool>.efi -dev_num 0")

    def test_reset_done_dev_num_0(self):
        output = self.read_output("ResetDone_dev_num_0.txt")
        if not "RESET CHECK PASSED" in output:
            raise Exception("Not Success in <tool>.efi")

    def test_reset_done_dev_num_20(self):
        output = self.read_output("ResetDone_dev_num_20.txt")
        if not "Error! Was only able to find" in output:
            raise Exception("should be error. We don't have dev 20 <tool>.efi -dev_num 20")

    def test_reset_done_dev_num_21(self):
        output = self.read_output("ResetDone_dev_num_21.txt")
        if not "Error! Flag -dev_num only allows values up to 32" in output:
            raise Exception("should be error. <tool>.efi -dev_num 21")


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
