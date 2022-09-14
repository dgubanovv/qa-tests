import os
import time
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import pytest

from hlh.register import Register
from infra.test_base import TestBase, idparametrize
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.atltoolper import AtlTool
from tools.constants import CARD_NIKKI
from tools.fw_a2_drv_iface_cfg import HOST_MODE_ACTIVE, FirmwareA2Config
from tools.ifconfig import LINK_SPEED_10M, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_10G, LINK_SPEED_AUTO, LINK_SPEED_NO_LINK, LINK_STATE_UP, LINK_STATE_DOWN, get_expected_speed, \
    KNOWN_LINK_SPEEDS
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_link_sanity"


class TestA2FWLinkSanity(TestBase):
    NOF_LINK_CHECKS = 20

    LKP_IP4_ADDR = "192.168.0.2"
    NETMASK_IPV4 = "255.255.255.0"

    LKP_IP6_ADDR = "4000:0000:0000:0000:1601:bd17:0c02:2402"
    PREFIX_IPV6 = "64"

    @classmethod
    def setup_class(cls):
        super(TestA2FWLinkSanity, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", host=cls.dut_hostname,
                                    drv_type=DRV_TYPE_DIAG)
            cls.dut_driver.install()
            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.fw_config = FirmwareA2Config(cls.atltool_wrapper)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6_ADDR, cls.PREFIX_IPV6, None)
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestA2FWLinkSanity, self).setup_method(method)
        self.atltool_wrapper.kickstart2()

    def run_eee_link_speed(self, speed):
        if speed not in self.supported_speeds:
            pytest.skip()
        if self.lkp_fw_card == CARD_NIKKI and speed in [LINK_SPEED_1G]:
            # 1G EEE is disabled on Lil Nikki
            pytest.skip()
        exp_eee_map = {
            LINK_SPEED_100M: (0x7, 0x3c, 0x2),
            LINK_SPEED_1G: (0x7, 0x3c, 0x4),
            LINK_SPEED_2_5G: (0x7, 0x3e, 0x1),
            LINK_SPEED_5G: (0x7, 0x3e, 0x2),
            LINK_SPEED_10G: (0x7, 0x3c, 0x8)
        }
        for i in range(self.NOF_LINK_CHECKS):
            log.info('Link check #{}...'.format(i + 1))
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            self.lkp_ifconfig.set_media_options(options_to_set=["energy-efficient-ethernet"])
            self.fw_config.set_link_state(LINK_STATE_UP)
            self.fw_config.set_link_speed(speed=speed, eee=True)
            self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
            lkpspeed = self.lkp_ifconfig.wait_link_up()
            dutspeed = self.fw_config.wait_link_up()
            exp_speed = get_expected_speed(speed, self.dut_port)
            dut_eee_status = self.fw_config.get_fw_eee_status()

            assert dutspeed == exp_speed, "Firmware up {} link speed.  But expected {}".format(dutspeed, speed)
            assert lkpspeed == exp_speed
            log.info("Link {} is up".format(dutspeed))
            assert dut_eee_status == 1, "FW did not enable EEE mode"
            eee_phy_reg = self.atltool_wrapper.readphyreg(exp_eee_map[speed][0], exp_eee_map[speed][1])
            assert eee_phy_reg == exp_eee_map[speed][2], "PHY reports wrong EEE state"

    @idparametrize("speed", [LINK_SPEED_10M, LINK_SPEED_100M, LINK_SPEED_1G])
    def test_link_up_half_duplex(self, speed):
        """"
        @description: Test Half duplex link up.

        @steps:
        1. Select speed.
        2. Set link speed half duplex on DUT and LKP.
        3. Check that link half duplex is up.

        @result: Link half duplex is up.
        @duration: 15 sec.
        """

        if self.dut_fw_card != "Antigua" or self.lkp_fw_card != "Antigua":
            pytest.skip()
        if speed not in self.supported_speeds:
            pytest.skip()
        self.lkp_ifconfig.set_link_speed(speed, half_duplex=True)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(speed, half_duplex=True)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()
        if speed == LINK_SPEED_1G:
            sp_1g = Register(self.atltool_wrapper.readphyreg(0x7, 0xc400))
            assert sp_1g[0xe] == 1, "Half Duplex not enabled for 1G"
        elif speed == LINK_SPEED_100M:
            sp_100m = Register(self.atltool_wrapper.readphyreg(0x7, 0x10))
            assert sp_100m[0x7] == 1, "Half Duplex not enabled for 100M"
        elif speed == LINK_SPEED_10M:
            sp_10m = Register(self.atltool_wrapper.readphyreg(0x7, 0x10))
            assert sp_10m[0x5] == 1, "Half Duplex not enabled for 10M"
        assert self.lkp_ifconfig.check_duplex() == "half"

    def run_test_link_speed_dut_x_lkp_auto(self, link_speed):
        if link_speed not in self.supported_speeds:
            pytest.skip()
        for i in range(self.NOF_LINK_CHECKS):
            log.info('Link check #{}...'.format(i + 1))
            self.fw_config.set_link_state(LINK_STATE_UP)
            self.fw_config.set_link_speed(link_speed)
            self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            lkpspeed = self.lkp_ifconfig.wait_link_up()
            dutspeed = self.fw_config.wait_link_up()
            exp_speed = get_expected_speed(link_speed, self.dut_port)

            assert dutspeed == exp_speed, "Firmware up {} link speed.  But expected {}".format(dutspeed, link_speed)
            assert lkpspeed == exp_speed
            log.info("Link {} is up".format(dutspeed))

    def run_test_link_speed_dut_auto_lkp_x(self, link_speed):
        if link_speed not in self.supported_speeds:
            pytest.skip()
        for i in range(self.NOF_LINK_CHECKS):
            log.info('Link check #{}...'.format(i + 1))
            self.fw_config.set_link_state(LINK_STATE_UP)
            self.fw_config.set_link_speed(LINK_SPEED_AUTO)
            self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
            self.lkp_ifconfig.set_link_speed(link_speed)
            lkpspeed = self.lkp_ifconfig.wait_link_up()
            dutspeed = self.fw_config.wait_link_up()
            exp_speed = get_expected_speed(link_speed, self.dut_port)
            assert dutspeed == exp_speed, "Firmware up {} link speed.  But expected {}".format(dutspeed, link_speed)
            assert lkpspeed == exp_speed
            log.info("Link {} is up".format(dutspeed))

    def run_test_speed_switch(self, speed_from, speed_to):
        if speed_from not in self.supported_speeds or speed_to not in self.supported_speeds:
            pytest.skip()
        link_check_attempts = int(os.environ.get('LINK_CHECKS', self.NOF_LINK_CHECKS))
        for i in range(link_check_attempts):
            log.info('Link check #{}...'.format(i + 1))
            self.lkp_ifconfig.set_link_speed(speed_from)

            exp_from_speed = get_expected_speed(speed_from, self.dut_port)
            exp_to_speed = get_expected_speed(speed_to, self.dut_port)

            self.fw_config.set_link_state(LINK_STATE_UP)
            self.fw_config.set_link_speed(speed_from)
            self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
            self.lkp_ifconfig.set_link_speed(speed_from)
            lkpspeed = self.lkp_ifconfig.wait_link_up()

            new_link_up = self.fw_config.wait_link_up()
            assert new_link_up == exp_from_speed, "Firmware up {}. Expected {}".format(new_link_up, exp_from_speed)
            assert lkpspeed is not None
            assert lkpspeed == exp_from_speed

            self.fw_config.set_link_state(LINK_STATE_UP)
            self.fw_config.set_link_speed(speed_to)
            self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
            self.lkp_ifconfig.set_link_speed(speed_to)
            lkpspeed = self.lkp_ifconfig.wait_link_up()

            new_link_up = self.fw_config.wait_link_up()
            assert new_link_up == exp_to_speed, "Firmware up {}. Expected {}".format(new_link_up, exp_to_speed)
            log.info("Link {} is up".format(new_link_up))
            assert lkpspeed is not None
            assert lkpspeed == exp_to_speed

    def run_test_speed_switch_to_no_link(self, speed_from):
        if speed_from not in self.supported_speeds:
            pytest.skip()
        for i in range(self.NOF_LINK_CHECKS):
            log.info('Link check #{}...'.format(i + 1))
            self.fw_config.set_link_state(LINK_STATE_UP)
            self.fw_config.set_link_speed(speed_from)
            self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            lkpspeed = self.lkp_ifconfig.wait_link_up()
            dutspeed = self.fw_config.wait_link_up()
            exp_speed = get_expected_speed(speed_from, self.dut_port)

            assert dutspeed == exp_speed, "Firmware up {} link speed.  But expected {}".format(dutspeed, speed_from)
            assert lkpspeed == exp_speed
            log.info("Link {} is up".format(dutspeed))

            self.fw_config.set_link_speed(LINK_SPEED_NO_LINK)
            self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
            self.lkp_ifconfig.wait_link_down()

            new_link_up = self.fw_config.get_fw_link_speed()
            assert new_link_up == LINK_SPEED_NO_LINK, "Firmware up {}. Expected: no link".format(new_link_up)
            log.info("Link is down")

    # LKP auto
    @idparametrize("dut_speed", KNOWN_LINK_SPEEDS)
    def test_link_speed_lkp_auto(self, dut_speed):
        self.run_test_link_speed_dut_x_lkp_auto(link_speed=dut_speed)

    # # DUT auto
    @idparametrize("lkp_speed", [LINK_SPEED_AUTO] + KNOWN_LINK_SPEEDS)
    def test_link_speed_dut_auto(self, lkp_speed):
        self.run_test_link_speed_dut_auto_lkp_x(lkp_speed)

    # Link switch
    @idparametrize("from_speed", KNOWN_LINK_SPEEDS)
    @idparametrize("to_speed", KNOWN_LINK_SPEEDS)
    def test_speed_switch(self, from_speed, to_speed):
        self.run_test_speed_switch(from_speed, to_speed)

    @idparametrize("from_speed", KNOWN_LINK_SPEEDS)
    def test_speed_switch_to_no_link(self, from_speed):
        self.run_test_speed_switch_to_no_link(from_speed)

    def test_control_link_linkdrop(self):
        """
        @description: Check FW link drop.

        @steps:
        1. Set autoneg link speed on DUT and LKP.
        2. Ckeck that link is up.
        3. Set link to down state on DUT.
        4. Ckeck link state.
        5. Set link to up state on DUT.
        6. Ckeck link speed and link state.

        @result: All ckecks are passed.
        @duration: 2 minutes.
        """
        self.atltool_wrapper.kickstart2()
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(LINK_SPEED_AUTO)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()

        cur_speed = self.fw_config.wait_link_up()
        dut_link_speed = get_expected_speed(LINK_SPEED_AUTO, self.dut_port)

        assert cur_speed == dut_link_speed, "Firmware up {} link speed.  \
                                            But expected {}".format(cur_speed, LINK_SPEED_AUTO)
        log.info("Link {} is up".format(cur_speed))

        self.fw_config.set_link_state(LINK_STATE_DOWN)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        time.sleep(3)
        # self.lkp_ifconfig.wait_link_down()
        dut_link_state = self.fw_config.get_fw_link_state()
        assert dut_link_state == 0, "Firmware should put link to down state"
        log.info("Link is down")

        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()
        cur_speed_new = self.fw_config.wait_link_up()

        assert cur_speed_new == dut_link_speed, "Firmware up {} link speed.  \
                                            But expected {}".format(cur_speed_new, LINK_SPEED_AUTO)
        log.info("Link {} is up".format(cur_speed_new))

        assert cur_speed_new == cur_speed

    # EEE link
    @idparametrize("speed", [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_eee_link(self, speed):
        """
        @description: Check EEE link speed.

        @steps:
        1. In loop for each speed in KNOWN_LINK_SPEEDS:
            a. Set link speed and enable EEE in FW link options for DUT.
            b. Set link speed and enable EEE via drv settings for LKP.

        @result: EEE is enable for current link speed.
        @duration: 1 minute.
        """
        self.run_eee_link_speed(speed=speed)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
