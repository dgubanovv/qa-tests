import itertools
import os
import time
import sys
qa_tests = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(qa_tests)

import pytest

from hlh.register import Register
from infra.test_base import TestBase, idparametrize
from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_1G, LINK_SPEED_5G, KNOWN_LINK_SPEEDS, LINK_SPEED_AUTO, \
    LINK_SPEED_NO_LINK, LINK_STATE_UP, LINK_STATE_DOWN, LINK_SPEED_NO_LINK, FELICITY_CARDS, CARD_FIJI
from tools.driver import Driver, DRV_TYPE_MAC_CDC, DRV_TYPE_LIN_CDC
from tools.mbuper import LINK_SPEED_TO_REG_VAL_MAP_2X, LINK_SPEED_TO_REG_VAL_MAP_2X_ALL_AUTO
from tools.ops import OpSystem
import tools.ping
from tools.utils import get_atf_logger
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config, LINK_SPEED_TO_LINKOPTION_VAL_A2_MAP

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_link_test"


class TestDriverLink(TestBase):
    """
    @description: The TestDriverLink test is dedicated to verify driver link up on different link speeds.

    @setup: Two Aquantia NIC connected to any link partner.
    """
    LINK_CONFIG_DELAY = 20
    AFTER_LINK_UP_DELAY = 15
    PING_COUNT = 4
    NUMBER_OF_CHECKS = 5

    @classmethod
    def setup_class(cls):
        super(TestDriverLink, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.install_firmwares()

            cls.dut_fw_is_a2 = cls.dut_firmware.is_atlantic2()
            if cls.dut_fw_card != CARD_FIJI:
                cls.atltool_wrapper = AtlTool(port=cls.dut_port)
                if cls.dut_fw_is_a2:
                    cls.fw_config = FirmwareA2Config(cls.atltool_wrapper)

            if cls.dut_drv_cdc:
                if cls.dut_ops.is_mac():
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, drv_type=DRV_TYPE_MAC_CDC)
                elif cls.dut_ops.is_linux():
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, drv_type=DRV_TYPE_LIN_CDC)
                else:
                    raise Exception("CDC driver is not supported")
            else:
                if cls.dut_fw_card not in CARD_FIJI and cls.atltool_wrapper.is_secure_chips() and cls.dut_ops.is_linux():
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version,
                                            flashless_fw=cls.dut_fw_version)
                else:
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)

            if not (cls.skip_drv_install or cls.skip_dut_drv_install):
                cls.dut_driver.install()
            if not (cls.skip_drv_install or cls.skip_lkp_drv_install):
                cls.lkp_driver.install()



            if cls.dut_ops.is_windows():
                cls.dut_ifconfig.set_advanced_property("Downshift", "Disable")

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            if cls.dut_fw_card != CARD_FIJI:
                cls.dut_nof_pci_lines = cls.dut_ifconfig.get_nof_pci_lines()
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)

            if cls.lkp_fw_card != CARD_FIJI:
                cls.lkp_nof_pci_lines = cls.lkp_ifconfig.get_nof_pci_lines()

            # Disable WOL on LKP to avoid problem with link down on Linux
            cls.lkp_ifconfig.set_power_mgmt_settings(False, False, False)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def run_test_link_speed(self, dut_speed, lkp_speed):
        if dut_speed not in self.supported_speeds + [LINK_SPEED_AUTO]:
            pytest.skip("Unsupported link speed {} on DUT".format(dut_speed))
        if lkp_speed not in self.supported_speeds + [LINK_SPEED_AUTO]:
            pytest.skip("Unsupported link speed {} on LKP".format(lkp_speed))
        if (self.dut_fw_card in FELICITY_CARDS or self.lkp_fw_card in FELICITY_CARDS) and \
                (LINK_SPEED_AUTO in [dut_speed, lkp_speed]):
            pytest.skip()
        if self.dut_drv_cdc:
            if lkp_speed == LINK_SPEED_AUTO and dut_speed in self.supported_speeds:
                pytest.skip("Unsupported link speed change on CDC driver")
        if dut_speed == LINK_SPEED_AUTO and lkp_speed == LINK_SPEED_AUTO:
            if self.dut_fw_card != CARD_FIJI:
                expected_speed = self.supported_speeds[-1]
            else:
                expected_speed = (LINK_SPEED_5G if not self.usb_2_0 else LINK_SPEED_1G)
        elif dut_speed == LINK_SPEED_AUTO and lkp_speed != LINK_SPEED_AUTO:
            expected_speed = lkp_speed
        elif dut_speed != LINK_SPEED_AUTO and lkp_speed == LINK_SPEED_AUTO:
            expected_speed = dut_speed
        elif dut_speed != LINK_SPEED_AUTO and lkp_speed != LINK_SPEED_AUTO:
            if dut_speed == lkp_speed:
                expected_speed = dut_speed
            else:
                expected_speed = LINK_SPEED_NO_LINK
        else:
            raise Exception("Invalid test parameters")

        for i in range(self.NUMBER_OF_CHECKS):
            if i == 0:
                self.dut_ifconfig.set_link_speed(dut_speed)
                self.lkp_ifconfig.set_link_speed(lkp_speed)
            else:
                self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
                self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
                self.dut_ifconfig.set_link_state(LINK_STATE_UP)
                self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

            max_link_up_time = 18
            if LINK_SPEED_AUTO not in [dut_speed, lkp_speed] and dut_speed != lkp_speed:
                # If link speeds are different wait for 18 seconds (max link up time)
                # Then make sure that link is down
                log.info("Waiting {} seconds to make sure that link is down".format(max_link_up_time))
                time.sleep(max_link_up_time)
                self.dut_ifconfig.wait_link_down(timeout=1)
            else:
                log.info("Waiting maximum {} seconds to make sure that link is up".format(max_link_up_time))
                if self.dut_drv_cdc:
                    actual_speed = self.lkp_ifconfig.wait_link_up(timeout=max_link_up_time)
                else:
                    actual_speed = self.dut_ifconfig.wait_link_up(timeout=max_link_up_time)
                assert actual_speed == expected_speed, \
                    "Invalid link speed negotiated: expected {}, actual {}".format(expected_speed, actual_speed)

                log.info("Sleeping {} seconds before checking datapath".format(self.AFTER_LINK_UP_DELAY))
                time.sleep(self.AFTER_LINK_UP_DELAY)
                assert tools.ping.ping(self.PING_COUNT, self.LKP_IPV4_ADDR, src_addr=self.DUT_IPV4_ADDR), 'Ping is failed'

    def test_link_down_timeout(self):
        """
        @description: Check that link down after 15 sec waiting.

        @steps:
        1. Set max link speed on DUT and LKP.
        2. Check that link up.
        3. Set link down.
        4. Wait link down.
        5. Wait 15 sec.
        6. Check that link down.

        @result: All checks are passed.
        @duration: 30 sec.
        """

        speed = self.supported_speeds[-1]
        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        link_speed = self.dut_ifconfig.wait_link_up()
        assert speed == link_speed, "Unexpected speed"
        log.info("Link speed {} is up".format(link_speed))
        self.dut_ifconfig.set_link_down()
        self.dut_ifconfig.wait_link_down()
        time.sleep(15)
        link_speed = self.lkp_ifconfig.get_link_speed()
        assert link_speed == LINK_SPEED_NO_LINK, "Unexpected speed"

    @idparametrize("dut_speed", KNOWN_LINK_SPEEDS + [LINK_SPEED_AUTO])
    def test_link_speed_lkp_auto(self, dut_speed):
        """
        @description: Check link up on specified speed with auteneg link speed on LKP.

        @steps:
        1. Set autoneg link speed on LKP.
        2. In loop for 10G/5G/2,5G/1G/100M/autoneg link speed:
            a. Set specified link speed on DUT.
            c. Run ping from DUT to LKP.
            d. Make sure all pings are answered.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_test_link_speed(dut_speed=dut_speed, lkp_speed=LINK_SPEED_AUTO)

    @idparametrize("lkp_speed", KNOWN_LINK_SPEEDS + [LINK_SPEED_AUTO])
    def test_link_speed_dut_auto(self, lkp_speed):
        """
        @description: Check link up on specified speed with auteneg link speed on DUT.

        @steps:
        1. Set autoneg link speed on DUT.
        2. In loop for 10G/5G/2,5G/1G/100M/autoneg link speed:
            a. Set specified link speed on LKP.
            c. Run ping from DUT to LKP.
            d. Make sure all pings are answered.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_test_link_speed(dut_speed=LINK_SPEED_AUTO, lkp_speed=lkp_speed)

    @idparametrize("speed", KNOWN_LINK_SPEEDS + [LINK_SPEED_AUTO])
    def test_link_speed(self, speed):
        """
        @description: Check link up on specified speed.

        @steps:
        1. In loop for 10G/5G/2,5G/1G/100M/autoneg link speed:
            a. Set specified link speed on DUT and LKP.
            c. Run ping from DUT to LKP.
            d. Make sure all pings are answered.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_test_link_speed(dut_speed=speed, lkp_speed=speed)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_link_switch_to_auto(self, speed):
        """
        @description: Check that firmware set up correct value of 0x370 register after switch from various speed to
        auto negotiation.

        @steps:
        1. Set 10G/5G/2,5G/1G/100M link speed on DUT through driver.
        2. Set autoneg on DUT.
        3. Compare values of 0x368 and 0x370 registers.

        @result: The values of the registers are the same.
        @duration: 3 minutes.
        """
        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Fiji does not support atltool readreg command")

        if self.dut_fw_card in FELICITY_CARDS or self.lkp_fw_card in FELICITY_CARDS:
            pytest.skip()

        if speed not in self.supported_speeds + [LINK_SPEED_AUTO]:
            pytest.skip("Unsupported link speed {} on DUT".format(speed))
        self.dut_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()
        self.dut_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_ifconfig.wait_link_up()

        if self.dut_fw_is_a2:
            link_option = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions")
            speed_bits = LINK_SPEED_TO_LINKOPTION_VAL_A2_MAP.values()
            for option_speed in speed_bits:
                if option_speed not in ["rate_N2P5G", "rate_N5G"]:
                    log.info("{}".format(option_speed))
                    assert getattr(link_option, option_speed) == 1
        else:
            adv_reg = self.dut_atltool_wrapper.readreg(0x368) & 0xFFFF
            cap_reg = self.dut_atltool_wrapper.readreg(0x370) & 0xFFFF
            assert adv_reg == cap_reg, "0x368: {:b} != 0x370: {:b}".format(adv_reg, cap_reg)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_link_speed_reg(self, speed):
        """
        @description: Check that firmware set up correct value of 0x370 register for various speed.

        @steps:
        1. Set 10G/5G/2,5G/1G/100M link speed on DUT through driver.
        2. Check value of 0x370 reg.

        @result: The value of register 0x370 is equal to the expected value.
        @duration: 3 minutes.
        """
        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Fiji does not support atltool readreg command")
        if speed not in self.supported_speeds + [LINK_SPEED_AUTO]:
            pytest.skip("Unsupported link speed {} on DUT".format(speed))

        exp_values = LINK_SPEED_TO_REG_VAL_MAP_2X_ALL_AUTO if OpSystem().is_mac() else LINK_SPEED_TO_REG_VAL_MAP_2X

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()

        if self.dut_fw_is_a2:
            link_speed = self.fw_config.get_fw_link_speed()
            assert link_speed == speed
        else:
            val = self.dut_atltool_wrapper.readreg(0x370) & 0xFFFF
            exp = exp_values[speed]

            if self.dut_fw_card in FELICITY_CARDS:
                for not_supported_speed in set(KNOWN_LINK_SPEEDS) ^ set(self.supported_speeds):
                    if not_supported_speed in LINK_SPEED_TO_REG_VAL_MAP_2X:
                        exp = exp & ~LINK_SPEED_TO_REG_VAL_MAP_2X[not_supported_speed]

            assert val == exp, "0x370: {:b} != expected: {:b}".format(val, exp)

    @idparametrize("_from,_to", list(itertools.permutations(KNOWN_LINK_SPEEDS, 2)))
    def test_link_switch_speed(self, _from, _to):
        """
        @description: Check link switch from 10G/5G/2,5G/1G/100M link speed to another speed.

        @steps:
        1. In loop for 10G/5G/2,5G/1G/100M link speed:
            a. Set autoneg link speed on LKP.
            b. Set 10G/5G/2,5G/1G/100M link speed on DUT through driver.
            c. Run ping from DUT to LKP.
            d. Make sure all pings are answered.
            e. Change link speed to another one from 10G/5G/2,5G/1G/100M link speed.
            f. Run ping from DUT to LKP.
            g. Make sure all pings are answered.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        if self.dut_fw_card in FELICITY_CARDS or self.lkp_fw_card in FELICITY_CARDS:
            pytest.skip()

        if _from not in self.supported_speeds or _to not in self.supported_speeds:
            pytest.skip()

        if self.dut_drv_cdc:
            pytest.skip("N/A for CDC driver")

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_ifconfig.set_link_speed(_from)
        self.dut_ifconfig.wait_link_up()
        time.sleep(5)

        assert self.ping(from_host="localhost", to_host=self.LKP_IPV4_ADDR)

        self.dut_ifconfig.set_link_speed(_to)
        self.dut_ifconfig.wait_link_up()
        time.sleep(5)

        assert self.ping(from_host="localhost", to_host=self.LKP_IPV4_ADDR)

    def test_downshift_attempts_config(self):
        """
        @description: Check downshift configuration.

        @steps:
        1. In loop for different downshift retry counter:
            a. Set Downshift retry counter via driver settings.
            b. Check that retry counter is configured correctly in PHY register.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        if not OpSystem().is_windows():
            pytest.skip()
        if self.dut_fw_card in FELICITY_CARDS or self.dut_fw_card == CARD_FIJI:
            pytest.skip()

        max_retry_count = 7
        for retry_count in range(max_retry_count + 1):
            self.dut_ifconfig.set_advanced_property("Downshift", retry_count)
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.dut_ifconfig.wait_link_up()

            phy_downshift = Register(self.dut_atltool_wrapper.readphyreg(0x7, 0xc400))
            assert phy_downshift[0x4] == 0 if retry_count == 0 else 1, "Downshift is disable"
            assert phy_downshift[:0x3] == retry_count, "Wrong retry count in PHY: {}"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
