import collections
import os
import shutil
import time

import pytest

from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import FELICITY_CARDS
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.firmware import Firmware
from tools.ops import OpSystem
from tools.utils import get_atf_logger, get_bus_dev_func, get_url_response

from infra.test_base import TestBase

# Import atltool module after importing atltoolper
import atltool

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    # Define this variable to test locally built firmware
    # os.environ["CLX_FILE"] = r"C:\Users\aqtest\Desktop\ATL-3.0.119.clx"
    os.environ["TEST"] = "fw_3x_flashless"


class TestFw3xFlashless(TestBase):
    """
    Test Plan - https://sites.google.com/s/10ZpXHZNCbqZsUispNuAIjq885NweZ89u/p/1U2RbiYS-PU37QBIdzcWbckvF3O-37TYI/edit?pli=1&authuser=1
    """

    PROV_HEADER = "PartNumber = AQR107\n"

    PHY_PROV_TMPL = """
ProvisioningBlock
{{
  Type Power Up
  PHY_List {{ Common }}
  ChangeList
  {{
{REGISTERS}
  }}
}}
"""
    PHY_PROV_REG_TMPL = "    {MMD:02X}.{ADDR:04X} = 0x{VALUE:04X}"

    MAC_PROV_TMPL = """
ProvisioningBlockMac
{{
  Type Power Up
  MAC_List {{ Common }}
  ChangeList
  {{
{REGISTERS}
  }}
}}
"""
    MAC_PROV_REG_TMPL = "    0B.{REG:04X} = 0x{VALUE:08X}"

    PROVISIONING_TOOL_URL = "http://qa-nfs01.rdc-lab.marvell.com/builds/tools/fw/latest/ProvisioningTool_default.exe"
    PROVISIONING_TOOL_NAME = "ProvisioningTool_default.exe"
    NCB_TEMPLATE_URL = "http://qa-nfs01.rdc-lab.marvell.com/qa/testing/ncb_template.clx"
    NCB_TEMPLATE_NAME = "ncb_template.clx"

    CLX_FLASH_NAME = "clx_flash.clx"
    CLX_HOST_NAME = "clx_host.clx"

    BDP_FLASH_NAME = "bdp_flash.txt"
    BDP_HOST_NAME = "bdp_host.txt"

    CLX_FILE = None

    BDP_INSTR_FLASH_ONLY = "FLASH_ONLY"
    BDP_INSTR_HOST_ONLY = "HOST_ONLY"
    BDP_INSTR_FLASH_HOST = "FLASH_AND_HOST"

    FLASH_MAC_REGS_TMPL = [
        (0x10C, 0x11111111),
        (0x118, 0x22222222),
        (0x124, 0x33333333),
    ]
    FLASH_PHY_REGS_TMPL = [
        (0x1e, 0x300, 0x1111),
        (0x1e, 0x301, 0x2222),
        (0x1e, 0x302, 0x3333),
    ]
    HOST_MAC_REGS_TMPL = [
        (0x20C, 0x44444444),
        (0x40C, 0x5555),
    ]
    HOST_PHY_REGS_TMPL = [
        (0x1e, 0x303, 0x4444),
        (0x1e, 0x304, 0x5555),
        (0x1e, 0x305, 0x6666),
    ]

    @classmethod
    def setup_class(cls):
        super(TestFw3xFlashless, cls).setup_class()

        cls.log_server_dir = cls.create_logs_dir_on_log_server()

        cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest")
        cls.dut_driver.install()

        cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
        cls.dut_ops = OpSystem()

        # Check that DUT card is RBL
        dw62 = cls.dut_atltool_wrapper.get_efuse(63 * 4)[-1]
        if dw62 & 0x27000 == 0:
            raise Exception("Can't execute flashless test on non-RBL card")

        # Skip Felicity cards for now
        if cls.dut_fw_card in FELICITY_CARDS:
            raise Exception("Can't execute flashless test on Felicity card")

        if not all([cls.dut_fw_version, cls.dut_fw_card]):
            raise Exception("Information about DUT FW is not filled")
        cls.dut_firmware = Firmware(port=cls.dut_port, card=cls.dut_fw_card, speed=cls.dut_fw_speed,
                                    version=cls.dut_fw_version, mdi=cls.dut_fw_mdi, mii=cls.dut_fw_mii,
                                    pause=cls.dut_fw_pause, pcirom=cls.dut_fw_pcirom, dirtywake=cls.dut_fw_dirtywake,
                                    host=cls.dut_hostname, bdp=cls.dut_bdp, sign=cls.dut_sign, se_enable=cls.dut_se)

        # Download necessary assets
        cls.download_test_assets()

    @classmethod
    def teardown_class(cls):
        super(TestFw3xFlashless, cls).teardown_class()
        if os.path.exists(cls.PROVISIONING_TOOL_NAME):
            os.remove(cls.PROVISIONING_TOOL_NAME)
        if os.path.exists(cls.NCB_TEMPLATE_NAME):
            os.remove(cls.NCB_TEMPLATE_NAME)
        if cls.CLX_FILE and os.path.exists(cls.CLX_FILE) and "CLX_FILE" not in os.environ:
            os.remove(cls.CLX_FILE)

    def setup_method(self, method):
        super(TestFw3xFlashless, self).setup_method(method)

    def teardown_method(self, method):
        super(TestFw3xFlashless, self).teardown_method(method)
        if os.path.exists(self.CLX_FLASH_NAME):
            os.remove(self.CLX_FLASH_NAME)
        if os.path.exists(self.CLX_HOST_NAME):
            os.remove(self.CLX_HOST_NAME)
        if os.path.exists(self.BDP_FLASH_NAME):
            os.remove(self.BDP_FLASH_NAME)
        if os.path.exists(self.BDP_HOST_NAME):
            os.remove(self.BDP_HOST_NAME)

    @classmethod
    def download_test_assets(cls):
        log.info("Downloading Provisioning Tool from '{}'".format(cls.PROVISIONING_TOOL_URL))
        content = get_url_response(cls.PROVISIONING_TOOL_URL)
        with open(cls.PROVISIONING_TOOL_NAME, "wb") as f:
            f.write(content)
        log.info("Downloading NCB template from '{}'".format(cls.NCB_TEMPLATE_URL))
        content = get_url_response(cls.NCB_TEMPLATE_URL)
        with open(cls.NCB_TEMPLATE_NAME, "wb") as f:
            f.write(content)
        log.info("Downloading firmware that will be used in hostboot procedure")
        cls.CLX_FILE = os.environ.get("CLX_FILE", cls.dut_firmware.download())

    @classmethod
    def create_prov_file(cls, filename, mac_regs=None, phy_regs=None):
        """
        Create provisioning file with specified settings.

        :param filename: Provisioning file name.
        :param mac_regs: list of tuples (REG, VALUE)
        :param phy_regs: list of tuples (MMD, ADDR, VALUE)
        """
        with open(filename, "w") as f:
            f.write(cls.PROV_HEADER)
            if mac_regs:
                f.write(cls.MAC_PROV_TMPL.format(
                    REGISTERS="\n".join(cls.MAC_PROV_REG_TMPL.format(REG=reg, VALUE=value) for reg, value in mac_regs)))
            if phy_regs:
                f.write(cls.PHY_PROV_TMPL.format(REGISTERS="\n".join(
                    cls.PHY_PROV_REG_TMPL.format(MMD=mmd, ADDR=addr, VALUE=value) for mmd, addr, value in phy_regs)))

    def dut_burn_clx(self, filename):
        bus, dev, func = map(lambda x: int(x), get_bus_dev_func(self.dut_port))
        lspci_port = "{:02x}:{:02x}.{:x}".format(bus, dev, func)
        cmd = "{}flashBurn -d {} {}".format("" if self.dut_ops.is_windows() else "sudo ", lspci_port, filename)
        res = Command(cmd=cmd).run_join(180)
        if res["returncode"] != 0:
            raise Exception("Failed to burn CLX on DUT card")

    @classmethod
    def apply_provisioning(cls, prov_file, clx_in_file, clx_out_file):
        cmd = "{} -i {} -t {} -s {} -lu -ncb0".format(cls.PROVISIONING_TOOL_NAME, clx_in_file, clx_out_file, prov_file)
        res = Command(cmd=cmd).run_join(30)
        if res["returncode"] != 0:
            raise Exception("Failed to apply provisioning from file '{}' to CLX '{}'".format(prov_file, clx_in_file))

    def verify_mac_regs(self, flash_mac_regs, host_mac_regs):
        regs = collections.OrderedDict()
        for reg, value in flash_mac_regs + host_mac_regs:
            regs[reg] = value
        for reg, value in regs.items():
            mif_value = self.dut_atltool_wrapper.readreg(reg)
            assert mif_value == value, \
                "Incorrect value in provisioned MAC register 0x{:x}: (MIF) 0x{:x} != (FILE) 0x{:x}".format(
                    reg, mif_value, value)

    def verify_phy_regs(self, flash_phy_regs, host_phy_regs):
        regs = collections.OrderedDict()
        for mmd, addr, value in flash_phy_regs + host_phy_regs:
            regs[(mmd, addr)] = value
        for reg, value in regs.items():
            mmd, addr = reg
            mif_value = self.dut_atltool_wrapper.readphyreg(mmd, addr)
            assert mif_value == value, \
                "Incorrect value in provisioned PHY register 0x{:x}.0x{:x}: (MIF) 0x{:x} != (FILE) 0x{:x}".format(
                    mmd, addr, mif_value, value)

    def run_flashless_test(self, flash_mac_regs, flash_phy_regs, host_mac_regs, host_phy_regs, bdp_instruction):
        assert isinstance(flash_mac_regs, collections.Iterable)
        assert isinstance(host_mac_regs, collections.Iterable)
        assert isinstance(flash_phy_regs, collections.Iterable)
        assert isinstance(host_phy_regs, collections.Iterable)
        assert bdp_instruction in [self.BDP_INSTR_FLASH_ONLY, self.BDP_INSTR_HOST_ONLY, self.BDP_INSTR_FLASH_HOST]

        # Prepare CLX file for flash
        self.create_prov_file(self.BDP_FLASH_NAME, flash_mac_regs, flash_phy_regs)
        shutil.copy(self.BDP_FLASH_NAME, self.test_log_dir)
        self.apply_provisioning(self.BDP_FLASH_NAME, self.NCB_TEMPLATE_NAME, self.CLX_FLASH_NAME)

        # Prepare CLX file for host upload
        self.create_prov_file(self.BDP_HOST_NAME, host_mac_regs, host_phy_regs)
        shutil.copy(self.BDP_HOST_NAME, self.test_log_dir)
        self.apply_provisioning(self.BDP_HOST_NAME, self.CLX_FILE, self.CLX_HOST_NAME)

        # Burn CLX_FLASH to flash
        self.dut_burn_clx(self.CLX_FLASH_NAME)

        # Upload FW from host
        log.info("Initiating reset sequence")
        restart_completed = self.dut_atltool_wrapper.kickstart_rbl(reload_phy_fw=True, force_flashless=True)
        if restart_completed != 0xF1A7:
            raise Exception("RBL didn't enter upload from host mode as expected")
        log.info("Loading FW '{}' from host with instruction {}".format(self.CLX_HOST_NAME, bdp_instruction))
        if bdp_instruction == self.BDP_INSTR_FLASH_ONLY:
            loadfw_flags = atltool.LOADFW_BDP_FLASH_ONLY
        elif bdp_instruction == self.BDP_INSTR_HOST_ONLY:
            loadfw_flags = atltool.LOADFW_BDP_HOST_ONLY
        else:  # self.BDP_INSTR_FLASH_HOST
            loadfw_flags = 0
        macUploaded, phyUploaded, macBdpUploaded, phyBdpUploaded = atltool.load_firmware(
            self.dut_atltool_wrapper.device_number, self.CLX_HOST_NAME, loadfw_flags)
        # Check what's been done by load_firmware function
        if bdp_instruction == self.BDP_INSTR_FLASH_ONLY:
            assert not macBdpUploaded, "FW requested MAC BDP upload from host with instruction FLASH_ONLY"
            assert not phyBdpUploaded, "FW requested PHY BDP upload from host with instruction FLASH_ONLY"
        else:
            if host_mac_regs:
                assert macBdpUploaded, "FW didn't request MAC BDP upload from host with instruction {}".format(
                    bdp_instruction)
            if host_mac_regs:
                assert phyBdpUploaded, "FW didn't request PHY BDP upload from host with instruction {}".format(
                    bdp_instruction)

        # Check that FW is loaded
        for k in range(1000):
            ver_maj, ver_min, ver_rev = self.dut_atltool_wrapper.get_fw_version()
            if any([ver_maj, ver_min, ver_rev]):
                break
            time.sleep(0.010)  # pause 10 ms

        fw_ver = "{}.{}.{}".format(ver_maj, ver_min, ver_rev)
        if "CLX_FILE" not in os.environ:
            assert fw_ver == self.dut_firmware.actual_version, \
                "Loaded FW version is incorrect: {}, expected: {}".format(fw_ver, self.dut_firmware.actual_version)
        log.info("Successfully loaded FW {}".format(fw_ver))

        # Check that all BDP settings were applied correctly
        if bdp_instruction == self.BDP_INSTR_FLASH_ONLY:
            self.verify_mac_regs(flash_mac_regs, [])
            self.verify_phy_regs(flash_phy_regs, [])
        elif bdp_instruction == self.BDP_INSTR_HOST_ONLY:
            self.verify_mac_regs([], host_mac_regs)
            self.verify_phy_regs([], host_phy_regs)
        else:
            self.verify_mac_regs(flash_mac_regs, host_mac_regs)
            self.verify_phy_regs(flash_phy_regs, host_phy_regs)
        log.info("Provisioned MAC and PHY registers checked out")

    def test_bdp_flash_instr_flash_only(self):
        """Check that FW applies BDP from FLASH and doesn't request to upload BDP from HOST with FLASH_ONLY
        instruction."""
        self.run_flashless_test(self.FLASH_MAC_REGS_TMPL, self.FLASH_PHY_REGS_TMPL, self.HOST_MAC_REGS_TMPL,
                                self.HOST_PHY_REGS_TMPL, self.BDP_INSTR_FLASH_ONLY)

    def test_bdp_none_instr_flash_only(self):
        """Check that FW loads without BDP in FLASH and doesn't request to upload BDP from HOST with FLASH_ONLY
        instruction."""
        self.run_flashless_test([], [], self.HOST_MAC_REGS_TMPL, self.HOST_PHY_REGS_TMPL, self.BDP_INSTR_FLASH_ONLY)

    def test_bdp_host_instr_host_only(self):
        """Check that FW applies BDP from HOST and ignores BDP in FLASH with HOST_ONLY instruction."""
        self.run_flashless_test(self.FLASH_MAC_REGS_TMPL, self.FLASH_PHY_REGS_TMPL, self.HOST_MAC_REGS_TMPL,
                                self.HOST_PHY_REGS_TMPL, self.BDP_INSTR_HOST_ONLY)

    def test_bdp_none_instr_host_only(self):
        """Check that FW loads without BDP in CLX_HOST and ignores BDP in FLASH with HOST_ONLY instruction."""
        self.run_flashless_test(self.FLASH_MAC_REGS_TMPL, self.FLASH_PHY_REGS_TMPL, [], [], self.BDP_INSTR_HOST_ONLY)

    def test_bdp_none_instr_flash_host(self):
        """Check that FW loads without BDP in FLASH and CLX_HOST with FLASH_HOST instruction."""
        self.run_flashless_test([], [], [], [], self.BDP_INSTR_FLASH_HOST)

    def test_bdp_flash_instr_flash_host(self):
        """Check that FW applies BDP from FLASH and loads without BDP in CLX_HOST with FLASH_HOST instruction."""
        self.run_flashless_test(self.FLASH_MAC_REGS_TMPL, self.FLASH_PHY_REGS_TMPL, [], [], self.BDP_INSTR_FLASH_HOST)

    def test_bdp_host_instr_flash_host(self):
        """Check that FW applies BDP from HOST and loads without BDP in FLASH with FLASH_HOST instruction."""
        self.run_flashless_test([], [], self.HOST_MAC_REGS_TMPL, self.HOST_PHY_REGS_TMPL, self.BDP_INSTR_FLASH_HOST)

    def test_bdp_flash_host_extend_instr_flash_host(self):
        """Check that FW applies BDP from FLASH and HOST with FLASH_HOST instruction. BDPs extend each over."""
        self.run_flashless_test(self.FLASH_MAC_REGS_TMPL, self.FLASH_PHY_REGS_TMPL, self.HOST_MAC_REGS_TMPL,
                                self.HOST_PHY_REGS_TMPL, self.BDP_INSTR_FLASH_HOST)

    def test_bdp_flash_host_overlap_instr_flash_host(self):
        """Check that FW applies BDP from FLASH and HOST with FLASH_HOST instruction. BDPs overlap each over."""
        host_mac_regs = [(0x118, 0x77777777), (0x124, 0x88888888)] + self.HOST_MAC_REGS_TMPL
        host_phy_regs = [(0x1E, 0x301, 0x7777), (0x1E, 0x302, 0x8888)] + self.HOST_PHY_REGS_TMPL
        self.run_flashless_test(self.FLASH_MAC_REGS_TMPL, self.FLASH_PHY_REGS_TMPL, host_mac_regs, host_phy_regs,
                                self.BDP_INSTR_FLASH_HOST)

    def check_phy_prov_term(self):
        prov_term_off = self.dut_atltool_wrapper.readphymem(0x3FFE028C, 4)[0]
        log.info("Provisioning terminator offset = {:#010x}".format(prov_term_off))
        assert prov_term_off % 2 == 0, "PHY provisioning is not aligned to 2 bytes"
        if prov_term_off % 4 == 0:
            last_prov_dw = self.dut_atltool_wrapper.readphymem(0x3FFE0000 + prov_term_off - 4, 4)[0]
            log.info("Last provisioning dword [{:#06x}] = {:#010x}".format(prov_term_off - 4, last_prov_dw))
            prov_term_dw = self.dut_atltool_wrapper.readphymem(0x3FFE0000 + prov_term_off, 4)[0]
            log.info("Provisioning dword with terminator [{:#06x}] = {:#010x}".format(prov_term_off, prov_term_dw))
            assert last_prov_dw & 0xFFFF != 0, "FW set prov term 4 bytes too far"
            assert (last_prov_dw >> 16) & 0xFFFF != 0, "FW set prov term 2 bytes too far"
            assert prov_term_dw == 0, "FW set prov term too short"
        else:
            last_prov_dw = self.dut_atltool_wrapper.readphymem(0x3FFE0000 + prov_term_off - 2, 4)[0]
            log.info("Provisioning dword with terminator [{:#06x}] = {:#010x}".format(prov_term_off - 2, last_prov_dw))
            assert last_prov_dw & 0xFFFF != 0, "FW set prov term 2 bytes too far"
            assert (last_prov_dw >> 16) & 0xFFFF == 0, "FW set prov term 2 bytes too short"

    def test_phy_prov_term_host_phy_bdp_not_aligned(self):
        """Check that FW sets correct PHY provisioning terminator after uploading PHY BDP from host with size not
        aligned to 4 bytes
        """
        self.run_flashless_test([], [], self.HOST_MAC_REGS_TMPL, self.HOST_PHY_REGS_TMPL + [(0x1E, 0x306, 0x7777)],
                                self.BDP_INSTR_FLASH_HOST)
        self.check_phy_prov_term()

    def test_phy_prov_term_host_phy_bdp_aligned(self):
        """Check that FW sets correct PHY provisioning terminator after uploading PHY BDP from host with size aligned
        to 4 bytes
        """
        self.run_flashless_test([], [], self.HOST_MAC_REGS_TMPL, self.HOST_PHY_REGS_TMPL, self.BDP_INSTR_FLASH_HOST)
        self.check_phy_prov_term()

    def test_mac_bdp_longer_than_32_dwords(self):
        """Check that FW applies correct MAC BDP from HOST. MAC BDP length is more that 0x80"""
        self.run_flashless_test([], [], (self.FLASH_MAC_REGS_TMPL + self.HOST_MAC_REGS_TMPL) * 3, [],
                                self.BDP_INSTR_HOST_ONLY)

    def test_phy_bdp_longer_than_16_dwords_not_aligned(self):
        """Check that FW applies correct PHY BDP from HOST. PHY BDP length is more that 0x40. Total PHY BDP length is
        not aligned to 4 bytes
        """
        self.run_flashless_test([], [], [], (self.FLASH_PHY_REGS_TMPL + self.HOST_PHY_REGS_TMPL) * 3,
                                self.BDP_INSTR_HOST_ONLY)

    def test_phy_bdp_longer_than_16_dwords_aligned(self):
        """Check that FW applies correct PHY BDP from HOST. PHY BDP length is more that 0x40. Total PHY BDP length is
        aligned to 4 bytes
        """
        self.run_flashless_test([], [], [],
                                (self.FLASH_PHY_REGS_TMPL + self.HOST_PHY_REGS_TMPL) * 3 + [(0x1E, 0x300, 0x1111)],
                                self.BDP_INSTR_HOST_ONLY)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
