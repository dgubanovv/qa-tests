import os
import time

import pytest
import re

from tools.pactoolper import PacTool, CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, CAPS_AQ_USB_VENDOR_CMD_SLEEP_PROXY
from tools.constants import LINK_STATE_UP, LINK_STATE_DOWN, FELICITY_CARDS, LINK_SPEED_100M, LINK_SPEED_1G, \
    LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_NO_LINK, LINK_SPEED_AUTO
from tools.driver import Driver, DRV_TYPE_DIAG_WIN_USB
from tools.ifconfig import get_expected_speed
from infra.test_base import TestBase
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "usb_fw_sanity"


class TestUsbSanity(TestBase):
    DEFAULT_LINK_CHECKS = 3

    @classmethod
    def setup_class(cls):
        super(TestUsbSanity, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG_WIN_USB, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()
            cls.dut_pactool = PacTool(port=cls.dut_port)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestUsbSanity, self).setup_method(method)

    def teardown_method(self, method):
        super(TestUsbSanity, self).teardown_method(method)

    def test_fw_version(self):
        """
        @description: This subtest performs fw version check.

        @steps:
        1. Get expected fw version.
        2. Get actual fw version.

        @result: Expected and actual versions should be equal.
        """
        expected_version = self.get_actual_firmware_version(self.dut_fw_version)
        log.info("Expected FW version: {}".format(expected_version))
        re_fw_ver = re.compile(".*((\d+)\.(\d+)\.(\d+)).*")
        m = re_fw_ver.match(expected_version)
        if m is None:
            raise Exception("Invalid expected version: {}".format(expected_version))
        ver_high = int(m.group(2))
        ver_mid = int(m.group(3))
        ver_low = int(m.group(4))

        ver_major = int(self.dut_pactool.readreg(0xda) & 0x7f)
        ver_minor = int(self.dut_pactool.readreg(0xdb))
        ver_release = int(self.dut_pactool.readreg(0xdc))
        log.info("Actual FW version in registers 0xda:0xdc: {}.{}.{}".format(ver_major, ver_minor, ver_release))

        assert ver_high == ver_major and ver_mid == ver_minor and ver_low == ver_release

    def run_test_speed_switch(self, speed_from, speed_to):
        if self.obtain_real_speed(speed_from) not in self.supported_speeds or \
                self.obtain_real_speed(speed_to) not in self.supported_speeds:
            pytest.xfail()

        exp_from_speed = get_expected_speed(speed_from, self.dut_port)
        exp_to_speed = get_expected_speed(speed_to, self.dut_port)

        if self.lkp_fw_card not in FELICITY_CARDS:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

        link_check_attempts = int(os.environ.get('LINK_CHECKS', self.DEFAULT_LINK_CHECKS))
        for i in range(link_check_attempts):
            log.info('Link check #{}...'.format(i + 1))
            if self.lkp_fw_card in FELICITY_CARDS:
                self.lkp_ifconfig.set_link_speed(speed_from)
            self.dut_pactool.set_link_speed(speed_from)
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            pspeed = self.lkp_ifconfig.wait_link_up()
            assert pspeed is not None
            assert pspeed == exp_from_speed

            if self.lkp_fw_card in FELICITY_CARDS:
                self.lkp_ifconfig.set_link_speed(speed_to)

            if speed_to == LINK_SPEED_AUTO and self.usb_2_0:
                data = self.dut_pactool.control_transfer_in(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, size=4)
                data[0] = 0x3
                self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, data=data, size=4)
            else:
                self.dut_pactool.set_link_speed(speed_to)
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            pspeed = self.lkp_ifconfig.wait_link_up()
            assert pspeed is not None
            assert pspeed == exp_to_speed

    def run_test_link_speed_dut_auto_partner_x(self, speed):
        """
        @description: This subtest performs check link speed with autoneg link speed enabled on dut.

        @steps:
        1. Set autoneg speed on dut.
        2. Set needded link speed on link partner.

        @result: No link.
        """

        if self.obtain_real_speed(speed) not in (self.supported_speeds or []):
            pytest.xfail()

        exp_speed = get_expected_speed(speed, self.dut_port)

        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_pactool.set_link_speed(LINK_SPEED_AUTO)
        link_check_attempts = int(os.environ.get('LINK_CHECKS', self.DEFAULT_LINK_CHECKS))
        for i in range(link_check_attempts):
            log.info('Link check #{}...'.format(i + 1))
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            dspeed = self.lkp_ifconfig.wait_link_up()
            assert dspeed is not None
            assert dspeed == exp_speed

    def run_test_link_speed_dut_x_partner_auto(self, speed):
        """
        @description: This subtest performs check link speed with autoneg link speed enabled on link partner.

        @steps:
        1. Set autoneg speed on link partner.
        2. Set needded link speed on dut.

        @result: No link.
        """

        if self.obtain_real_speed(speed) not in (self.supported_speeds or []):
            pytest.xfail()

        exp_speed = get_expected_speed(speed, self.dut_port)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        if speed == LINK_SPEED_AUTO and self.usb_2_0:
            data = self.dut_pactool.control_transfer_in(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, size=4)
            data[0] = 0x3
            self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, data=data, size=4)
        else:
            self.dut_pactool.set_link_speed(speed)

        link_check_attempts = int(os.environ.get('LINK_CHECKS', self.DEFAULT_LINK_CHECKS))
        for i in range(link_check_attempts):
            log.info('Link check #{}...'.format(i + 1))
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            pspeed = self.lkp_ifconfig.wait_link_up()
            assert pspeed is not None
            assert pspeed == exp_speed

    def obtain_real_speed(self, speed):
        return speed if speed != LINK_SPEED_AUTO else self.supported_speeds[-1]

    def test_link_speed_dut_100m_partner_auto(self):
        self.run_test_link_speed_dut_x_partner_auto(LINK_SPEED_100M)

    def test_link_speed_dut_1g_partner_auto(self):
        self.run_test_link_speed_dut_x_partner_auto(LINK_SPEED_1G)

    def test_link_speed_dut_2_5g_partner_auto(self):
        self.run_test_link_speed_dut_x_partner_auto(LINK_SPEED_2_5G)

    def test_link_speed_dut_5g_partner_auto(self):
        self.run_test_link_speed_dut_x_partner_auto(LINK_SPEED_5G)

    def test_link_speed_dut_auto_partner_auto(self):
        self.run_test_link_speed_dut_x_partner_auto(LINK_SPEED_AUTO)

    def test_link_speed_dut_auto_partner_100m(self):
        self.run_test_link_speed_dut_auto_partner_x(LINK_SPEED_100M)

    def test_link_speed_dut_auto_partner_1g(self):
        self.run_test_link_speed_dut_auto_partner_x(LINK_SPEED_1G)

    def test_link_speed_dut_auto_partner_2_5g(self):
        self.run_test_link_speed_dut_auto_partner_x(LINK_SPEED_2_5G)

    def test_link_speed_dut_auto_partner_5g(self):
        self.run_test_link_speed_dut_auto_partner_x(LINK_SPEED_5G)

    def test_speed_switch_from_100m_to_1g(self):
        self.run_test_speed_switch(LINK_SPEED_100M, LINK_SPEED_1G)

    def test_speed_switch_from_100m_to_2_5g(self):
        self.run_test_speed_switch(LINK_SPEED_100M, LINK_SPEED_2_5G)

    def test_speed_switch_from_100m_to_5g(self):
        self.run_test_speed_switch(LINK_SPEED_100M, LINK_SPEED_5G)

    def test_speed_switch_from_100m_to_auto(self):
        self.run_test_speed_switch(LINK_SPEED_100M, LINK_SPEED_AUTO)

    def test_speed_switch_from_1g_to_2_5g(self):
        self.run_test_speed_switch(LINK_SPEED_1G, LINK_SPEED_2_5G)

    def test_speed_switch_from_1g_to_5g(self):
        self.run_test_speed_switch(LINK_SPEED_1G, LINK_SPEED_5G)

    def test_speed_switch_from_1g_to_auto(self):
        self.run_test_speed_switch(LINK_SPEED_1G, LINK_SPEED_AUTO)

    def test_speed_switch_from_2_5g_to_5g(self):
        self.run_test_speed_switch(LINK_SPEED_2_5G, LINK_SPEED_5G)

    def test_speed_switch_from_2_5g_to_auto(self):
        self.run_test_speed_switch(LINK_SPEED_2_5G, LINK_SPEED_AUTO)

    def test_speed_switch_from_5g_to_auto(self):
        self.run_test_speed_switch(LINK_SPEED_5G, LINK_SPEED_AUTO)

    def test_speed_switch_from_5g_to_1g(self):
        self.run_test_speed_switch(LINK_SPEED_5G, LINK_SPEED_1G)

    def test_control_link_linkdrop(self):
        """
        @description: This subtest performs check link speed after low power bit was enabled.

        @steps:
        1. Set autoneg speed and check that correct link speed was up.
        2. Set low power bit.

        @result: No link.
        """
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_pactool.set_link_speed(LINK_SPEED_AUTO)
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed != LINK_SPEED_NO_LINK
        # put bit for wake on magic packet enabled, to up 100M in sleep proxy mode
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, data=[15,0,12,0], size=4)
        log.info('Drop link bit was set')
        # Link should be UP on link partner
        speed = self.lkp_ifconfig.wait_link_down()
        assert speed == LINK_SPEED_NO_LINK
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, data=[15,0,8,0], size=4)
        log.info('Drop link bit was cleared')
        # Link should be UP on link partner
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed != LINK_SPEED_NO_LINK

    def test_control_link_sleep_proxy(self):
        """
        @description: This subtest performs check link speed after sleep proxy bit was enabled.

        @steps:
        1. Set autoneg speed and check that correct link speed was up.
        2. Set speed proxy bit.

        @result: 100M link speed is up.
        """
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_pactool.set_link_speed(LINK_SPEED_AUTO)
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed != LINK_SPEED_NO_LINK
        # put bit for wake on magic packet enabled, to up 100M in sleep proxy mode
        sleep_proxy_cfg = [00, 00, 00, 00, 00, 00, 02] + [00] * 283
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_SLEEP_PROXY,
                                              data=sleep_proxy_cfg, size=290)
        time.sleep(5)
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, data=[0,0,24,0], size=4)
        log.info('Sleep proxy bit was set')
        # Link should be UP on link partner
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed == self.supported_speeds[0]


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
