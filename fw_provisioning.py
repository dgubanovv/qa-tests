import os
import tempfile
import time
import random

import pytest
import shutil

from tools.atltoolper import AtlTool
from tools.constants import CARD_NIKKI, CARD_BERMUDA_B0, CARD_BERMUDA_A0, LINK_SPEED_AUTO, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_10G, FELICITY_CARDS, LINK_SPEED_NO_LINK
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.firmware import Firmware
from tools.utils import get_atf_logger

from infra.test_base import TestBase

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_provisioning"


class TestProvisioning(TestBase):
    @classmethod
    def setup_class(cls):
        super(TestProvisioning, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.dut_flash_override, cls.lkp_flash_override = cls.get_flash_override()
            cls.lkp_firmware = Firmware(port=cls.lkp_port, card=cls.lkp_fw_card, speed=cls.lkp_fw_speed,
                                        version=cls.lkp_fw_version, mdi=cls.lkp_fw_mdi, mii=cls.lkp_fw_mii,
                                        pause=cls.lkp_fw_pause, pcirom=cls.lkp_fw_pcirom,
                                        dirtywake=cls.lkp_fw_dirtywake, host=cls.lkp_hostname, bdp=cls.lkp_bdp,
                                        sign=cls.lkp_sign,
                                        se_enable=cls.lkp_se, hsd=cls.lkp_hsd)

            postinstall_action = cls.lkp_firmware.install(overrides=cls.lkp_flash_override)
            if postinstall_action == Firmware.POSTINSTALL_RESTART:
                cls.restart(cls.lkp_hostname)
            if postinstall_action == Firmware.POSTINSTALL_COLD_RESTART:
                if cls.is_local_host(cls.lkp_hostname):
                    cls.state.fw_install_cold_restart = True
                    cls.state.update()
                cls.cold_restart(cls.lkp_hostname)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def install_fw(self, bdp, install_lkp=False, bdp_lkp=""):
        self.dut_firmware = Firmware(port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
                                     version=self.dut_fw_version, mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
                                     pause=self.dut_fw_pause, pcirom=self.dut_fw_pcirom,
                                     dirtywake=self.dut_fw_dirtywake, host=self.dut_hostname, bdp=bdp,
                                     sign=self.dut_sign,
                                     se_enable=self.dut_se, hsd=self.dut_hsd)

        if self.state.fw_install_cold_restart is True and self.is_local_host(self.dut_hostname):
            log.info("FW installation has been done before reboot")
            self.state.fw_install_cold_restart = False
            self.state.update()
        else:
            postinstall_action = self.dut_firmware.install(overrides=self.dut_flash_override)
            if postinstall_action == Firmware.POSTINSTALL_RESTART:
                self.restart(self.dut_hostname)
            if postinstall_action == Firmware.POSTINSTALL_COLD_RESTART:
                if self.is_local_host(self.dut_hostname):
                    self.state.fw_install_cold_restart = True
                    self.state.update()
                self.cold_restart(self.dut_hostname)
        if install_lkp:
            self.lkp_firmware = Firmware(port=self.lkp_port, card=self.lkp_fw_card, speed=self.lkp_fw_speed,
                                         version=self.lkp_fw_version, mdi=self.lkp_fw_mdi, mii=self.lkp_fw_mii,
                                         pause=self.lkp_fw_pause, pcirom=self.lkp_fw_pcirom,
                                         dirtywake=self.lkp_fw_dirtywake, host=self.lkp_hostname,
                                         bdp=bdp_lkp,
                                         sign=self.lkp_sign,
                                         se_enable=self.lkp_se, hsd=self.lkp_hsd)

            if self.state.fw_install_cold_restart is True and self.is_local_host(self.dut_hostname):
                log.info("FW installation has been done before reboot")
                self.state.fw_install_cold_restart = False
                self.state.update()
            else:
                postinstall_action = self.lkp_firmware.install(overrides=self.lkp_flash_override)
                if postinstall_action == Firmware.POSTINSTALL_RESTART:
                    self.restart(self.lkp_hostname)
                if postinstall_action == Firmware.POSTINSTALL_COLD_RESTART:
                    if self.is_local_host(self.lkp_hostname):
                        self.state.fw_install_cold_restart = True
                        self.state.update()
                    self.cold_restart(self.lkp_hostname)

    def test_media_detect_qualcomm(self):
        """
        @description: Check media detect for Qualcomm.

        @steps:
        1. Install firmware with provisioning for Qalcom.
        2. Check that media detect is Enabled(in 1E.C478 register the value is 0x180).

        @result: media detect is Enabled.
        @duration: 60 seconds.
        @requirements: FW_PROVISIONING_MEDIA_DETECT_1
        """
        if self.dut_fw_card != CARD_NIKKI:
            pytest.skip()
        self.install_fw(bdp="Qcom-")
        assert self.dut_atltool_wrapper.readphyreg(0x1E, 0xC478) & 0x180 == 0x180, "Media detect disabled"

    def test_media_detect_peroni(self):
        """
        @description: Check media detect for Peroni.

        @steps:
        1. Install firmware with provisioning for Peroni.
        2. Check that media detect is Enabled(in 1E.C478 register the value is 0x180).

        @result: media detect is Enabled.
        @duration: 60 seconds.
        @requirements: FW_PROVISIONING_MEDIA_DETECT_1
        """
        if self.dut_fw_card not in [CARD_BERMUDA_A0, CARD_BERMUDA_B0]:
            pytest.skip()
        self.install_fw(bdp="Peroni")
        assert self.dut_atltool_wrapper.readphyreg(0x1E, 0xC478) & 0x180 == 0x180, "Media detect disabled"

    def test_media_detect(self):
        """
        @description: Check, that media detect is disable.

        @steps:
        1. Install firmware.
        2. Check that media detect is Disabled(in 1E.C478 register the value is 0x0).

        @result: media detect is Disabled.
        @duration: 60 seconds.
        @requirements: FW_PROVISIONING_MEDIA_DETECT_1
        """
        self.install_fw(bdp=self.dut_bdp)
        assert self.dut_atltool_wrapper.readphyreg(0x1E, 0xC478) & 0x180 == 0x0, "Media detect enabled"

    def test_media_detect_link_up(self):
        """
        @description: Check link up with media detect.

        @steps:
        1. Install firmware with provisioning for Peroni or Qalcom.
        2. Check that media detect is Enabled(in 1E.C478 register the value is 0x180).
        3. Link down.
        4. Link up on DUT.
        5. Time sleep.
        6. Link up on LKP.
        7. Check that link is up

        @result: Link is up.
        @duration: 5 minutes.
        @requirements: FW_MEDIA_DETECT_1
        """
        if self.dut_fw_card not in [CARD_BERMUDA_A0, CARD_BERMUDA_B0, CARD_NIKKI] or \
                self.lkp_fw_card not in [CARD_BERMUDA_A0, CARD_BERMUDA_B0, CARD_NIKKI]:
            pytest.skip()

        self.install_fw(bdp="Qcom-" if self.dut_fw_card == CARD_NIKKI else "Peroni", install_lkp=True,
                        bdp_lkp="Qcom-" if self.lkp_fw_card == CARD_NIKKI else "Peroni")
        assert self.dut_atltool_wrapper.readphyreg(0x1E, 0xC478) & 0x180 == 0x180, "Media detect disabled"
        assert self.lkp_atltool_wrapper.readphyreg(0x1E, 0xC478) & 0x180 == 0x180, "Media detect disabled"
        self.dut_driver = Driver(port=self.dut_port, drv_type=DRV_TYPE_DIAG, version="latest")
        self.lkp_driver = Driver(port=self.lkp_port, drv_type=DRV_TYPE_DIAG, version="latest", host=self.lkp_hostname)
        self.dut_driver.install()
        self.lkp_driver.install()
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=True)
        self.lkp_atltool_wrapper.kickstart(reload_phy_fw=True)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_100M)
        self.lkp_atltool_wrapper.set_link_params_2x(LINK_SPEED_100M)
        self.dut_atltool_wrapper.wait_link_up()
        for i in range(10):
            self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_NO_LINK)
            self.lkp_atltool_wrapper.set_link_params_2x(LINK_SPEED_NO_LINK)
            self.dut_atltool_wrapper.wait_link_down()
            time.sleep(random.randint(1, 5))
            self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_100M)
            time.sleep(random.uniform(0.5, 5))
            self.lkp_atltool_wrapper.set_link_params_2x(LINK_SPEED_100M)
            self.dut_atltool_wrapper.wait_link_up()

    def test_media_detect_link_up_time(self):
        """
        @description: Check link up with media detect.

        @steps:
        1. Install firmware with provisioning for Peroni or Qalcom.
        2. Check that media detect is Enabled(in 1E.C478 register the value is 0x180).
        3. Link up.
        4. Check that the link is up no longer than 17 seconds

        @result: Link is up no longer than 17 seconds.
        @duration: 3 minutes.
        @requirements: FW_MEDIA_DETECT_2
        """
        if self.dut_fw_card not in [CARD_BERMUDA_A0, CARD_BERMUDA_B0, CARD_NIKKI] or \
                self.lkp_fw_card not in [CARD_BERMUDA_A0, CARD_BERMUDA_B0, CARD_NIKKI]:
            pytest.skip()
        self.install_fw(bdp="Qcom-" if self.dut_fw_card == CARD_NIKKI else "Peroni", install_lkp=True,
                        bdp_lkp="Qcom-" if self.lkp_fw_card == CARD_NIKKI else "Peroni")
        assert self.lkp_atltool_wrapper.readphyreg(0x1E, 0xC478) & 0x180 == 0x180, "Media detect disabled"
        self.dut_driver = Driver(port=self.dut_port, drv_type=DRV_TYPE_DIAG, version="latest")
        self.lkp_driver = Driver(port=self.lkp_port, drv_type=DRV_TYPE_DIAG, version="latest", host=self.lkp_hostname)
        self.dut_driver.install()
        self.lkp_driver.install()
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=True)
        self.lkp_atltool_wrapper.kickstart(reload_phy_fw=True)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_100M)
        self.lkp_atltool_wrapper.set_link_params_2x(LINK_SPEED_100M)
        self.dut_atltool_wrapper.wait_link_up(timeout=17)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
