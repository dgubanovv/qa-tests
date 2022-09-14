import os
import pytest


from tools.driver import Driver
from tools import command
from tools import firmware
from tools.constants import FELICITY_CARDS
from tools.atltoolper import AtlTool
from infra.test_base import TestBase, idparametrize
from tools.ops import OpSystem
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_fw_compatibility"


class TestCompatibilityBase(TestBase):
    VERSION_FW_1_5_44 = "x1/1.5.44/bin_forCustomers"
    VERSION_FW_1_5_58 = "x1/1.5.58/bin_forCustomers"
    VERSION_FW_1_5_89 = "x1/1.5.89_master__293/bin_forCustomers"
    VERSION_FW_3_0_6 = "3x/3.0.6"
    VERSION_FW_3_0_33 = "3x/3.0.33"
    VERSION_FW_3_1_21 = "3x/3.1.21"
    VERSION_FW_3_1_28 = "3x/3.1.28"
    VERSION_FW_3_1_30 = "3x/3.1.30"
    VERSION_FW_3_1_31 = "3x/3.1.31"
    VERSION_FW_3_1_32 = "3x/3.1.32"
    VERSION_FW_3_1_43 = "3x/3.1.43"
    VERSION_FW_3_1_44 = "3x/3.1.44"
    VERSION_FW = [VERSION_FW_1_5_44, VERSION_FW_1_5_58, VERSION_FW_1_5_89, VERSION_FW_3_0_6, VERSION_FW_3_0_33,
                  VERSION_FW_3_1_21, VERSION_FW_3_1_28, VERSION_FW_3_1_30, VERSION_FW_3_1_31, VERSION_FW_3_1_32,
                  VERSION_FW_3_1_43, VERSION_FW_3_1_44]

    VERSION_WDRV_2_0_026 = "2x/2.0.026.0"
    VERSION_WDRV_2_1_001 = "2x/2.1.001.0"
    VERSION_WDRV_2_1_005 = "2x/2.1.005.0"
    VERSION_WDRV_2_1_009 = "2x/2.1.009.0"
    VERSION_WDRV = [VERSION_WDRV_2_0_026, VERSION_WDRV_2_1_001, VERSION_WDRV_2_1_005,
                    VERSION_WDRV_2_1_009]

    VERSION_LDRV_2_0_7 = "2x/2.0.7.0_21"
    VERSION_LDRV_2_0_9 = "2x/2.0.9.0_23"
    VERSION_LDRV_2_0_10 = "2x/2.0.10.0_25"
    VERSION_LDRV_2_0_15 = "2x/2.0.15.0_48"
    VERSION_LDRV = [VERSION_LDRV_2_0_7, VERSION_LDRV_2_0_9, VERSION_LDRV_2_0_10,
                    VERSION_LDRV_2_0_15]

    @classmethod
    def setup_class(cls):
        super(TestCompatibilityBase, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)

            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port)
            cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)

            cls.dut_ifconfig.wait_link_up()

            cls.dut_ops = OpSystem()
            cls.lkp_ops = OpSystem(host=cls.lkp_hostname)

            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        cls.state.test_cleanup_cold_restart = True

    def install_fw(self, version):
        if version == "x1/1.5.44/bin_forCustomers":
            pciroom = "2.5.13"
        elif version == "x1/1.5.58/bin_forCustomers":
            pciroom = "2.5.17"
        else:
            pciroom = self.dut_fw_pcirom

        self.dut_flash_override, _ = self.get_flash_override()
        if all([self.dut_fw_version, self.dut_fw_card]):
            self.dut_firmware = firmware.Firmware(port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
                                                  version=version, mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
                                                  pause=self.dut_fw_pause, pcirom=pciroom,
                                                  dirtywake=self.dut_fw_dirtywake, host=self.dut_hostname, bdp=self.dut_bdp,
                                                  sign=self.dut_sign,
                                                  se_enable=self.dut_se)

            if self.state.fw_install_cold_restart is True and self.is_local_host(self.dut_hostname):
                log.info("FW installation has been done before reboot")
                self.state.fw_install_cold_restart = False
                self.state.update()
            else:
                postinstall_action = self.dut_firmware.install(overrides=self.dut_flash_override)
                if postinstall_action == firmware.Firmware.POSTINSTALL_RESTART:
                    self.restart(self.dut_hostname)
                if postinstall_action == firmware.Firmware.POSTINSTALL_COLD_RESTART:
                    if self.is_local_host(self.dut_hostname):
                        self.state.fw_install_cold_restart = True
                        self.state.update()
                    self.cold_restart(self.dut_hostname)

    def check_compatibility(self, version_fw, version_drv):
        self.install_fw(version_fw)
        command.Command(cmd="readstat", host=self.dut_hostname).wait(60)
        res = command.Command(cmd="readstat | grep address", host=self.dut_hostname).wait(60)
        if res["returncode"] != 0:
            raise Exception("Failed")
        addr = res["output"]
        for num in range(2):
            self.atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)
            res = command.Command(cmd="readstat | grep address", host=self.dut_hostname).wait(60)
            if res["returncode"] != 0:
                raise Exception("Failed")
            addr_1 = res["output"]
            assert addr == addr_1
        self.driver = Driver(port=self.dut_port, version=version_drv)
        self.driver.install()
        self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, None)
        self.dut_ifconfig.wait_link_up()
        ping_res = self.ping(self.LKP_IPV4_ADDR, "localhost", 3)
        assert ping_res

    @idparametrize("version_fw", VERSION_FW)
    @idparametrize("version_drv", VERSION_WDRV)
    def test_compatibility_win(self, version_fw, version_drv):
        if self.dut_ops.is_linux():
            pytest.skip("Skip for Linux")
        self.check_compatibility(version_fw, version_drv)

    @idparametrize("version_fw", VERSION_FW)
    @idparametrize("version_drv", VERSION_LDRV)
    def test_compatibility_linux(self, version_fw, version_drv):
        if self.dut_ops.is_windows():
            pytest.skip("Skip for Windows")
        self.check_compatibility(version_fw, version_drv)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])