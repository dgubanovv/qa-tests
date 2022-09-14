"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import sys
import shutil
import time
import tempfile

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, \
    LINK_SPEED_AUTO, LINK_SPEED_NO_LINK
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvEthConfig, OffloadIpInfo
from tools.mbuper import LINK_SPEED_TO_REG_VAL_MAP, LINK_SPEED_TO_REG_VAL_MAP_2X, LINK_STATE_UP
from tools.utils import get_atf_logger
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config, SleepProxyOffload
from infra.test_base import TestBase

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_proxy_speed"


class TestFw2xProxySpeed(TestBase):
    """
    @description: The proxy speed test is dedicated to verify minimal link speed feature. In sleep proxy mode firmware
    should negotiate minimal possible link speed. The test is running on LKP. Precondition: DUT is configured for
    sleep proxy mode.

    @setup: Antigua device as dut and Atlantic as LKP connected back to back.
    """

    @classmethod
    def setup_class(cls):
        super(TestFw2xProxySpeed, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", drv_type=DRV_TYPE_DIAG, host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version="latest", drv_type=DRV_TYPE_DIAG)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.setup_sleep_proxy_on_dut()

            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port)

            cls.dut_nof_pci_lanes = cls.dut_ifconfig.get_nof_pci_lines()
            cls.lkp_nof_pci_lanes = cls.lkp_ifconfig.get_nof_pci_lines()

            cls.lkp_fw_is_1x = cls.lkp_firmware.is_1x()
            cls.lkp_fw_is_a2 = cls.lkp_firmware.is_atlantic2()
            if cls.lkp_fw_is_a2:
                cls.lkp_fw_config = FirmwareA2Config(cls.lkp_atltool_wrapper)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestFw2xProxySpeed, self).setup_method(method)

    def teardown_method(self, method):
        super(TestFw2xProxySpeed, self).teardown_method(method)

    @classmethod
    def setup_sleep_proxy_on_dut(cls):
        log.info("Configuring sleep proxy on DUT")
        cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
        cls.dut_fw_config = FirmwareA2Config(cls.dut_atltool_wrapper)
        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4[0] = "192.168.0.2"
        cls.dut_fw_config.configure_sleep_proxy(sp_cfg, cls.suggest_test_mac_address(cls.dut_port, cls.dut_hostname))
        log.info("Sleep proxy has been configured")

    def set_link_speed_on_lkp(self, speed):
        if self.lkp_fw_is_1x:
            self.lkp_atltool_wrapper.writereg(0x368, speed << 16 | LINK_STATE_UP)
        elif self.lkp_fw_is_a2:
            self.lkp_fw_config.set_link_speed(speed)
        else:
            self.lkp_atltool_wrapper.writereg(0x368, speed)
        time.sleep(0.1)  # give firmware a chance to write zero to 0x36c

    def set_and_verify_lkp_link_a1(self, speed_array, expected_speed):
        speed = 0
        for s in speed_array:
            if self.lkp_fw_is_1x:
                speed |= LINK_SPEED_TO_REG_VAL_MAP[s]
            else:
                speed |= LINK_SPEED_TO_REG_VAL_MAP_2X[s]
        self.set_link_speed_on_lkp(speed)
        actual_speed = self.lkp_atltool_wrapper.wait_link_up(timeout=20)
        assert actual_speed == expected_speed

    def set_and_verify_lkp_link_a2(self, speed_array, expected_speed):
        self.lkp_fw_config.set_link_speed(speed_array)
        self.lkp_fw_config.set_link_state(LINK_STATE_UP)
        actual_speed = self.lkp_fw_config.wait_link_up(timeout=20)
        assert actual_speed == expected_speed

    def link_speed_test(self, speed_array, expected_speed):
        if self.lkp_fw_is_a2:
            self.set_and_verify_lkp_link_a2(speed_array, expected_speed)
        else:
            self.set_and_verify_lkp_link_a1(speed_array, expected_speed)

    def link_switch_test(self, speed_array):
        for speed in speed_array:
            assert speed != LINK_SPEED_NO_LINK  # logic check

            if self.lkp_fw_is_1x:
                s = LINK_SPEED_TO_REG_VAL_MAP[LINK_SPEED_NO_LINK]
            elif self.lkp_fw_is_a2:
                s = LINK_SPEED_NO_LINK
            else:
                s = LINK_SPEED_TO_REG_VAL_MAP_2X[LINK_SPEED_NO_LINK]
            self.set_link_speed_on_lkp(s)

            if self.lkp_fw_is_1x:
                _, s, __ = self.lkp_atltool_wrapper.get_link_params()
            elif self.lkp_fw_is_a2:
                s = self.lkp_fw_config.get_fw_link_speed()
            else:
                s = self.lkp_atltool_wrapper.get_link_speed_2x()
            assert s == LINK_SPEED_NO_LINK

            if speed == LINK_SPEED_AUTO:
                expected_speed = LINK_SPEED_100M
            else:
                expected_speed = speed

            if self.lkp_fw_is_1x:
                self.set_link_speed_on_lkp(LINK_SPEED_TO_REG_VAL_MAP[speed])
            elif self.lkp_fw_is_a2:
                self.set_link_speed_on_lkp(speed)
            else:
                self.set_link_speed_on_lkp(LINK_SPEED_TO_REG_VAL_MAP_2X[speed])

            if self.lkp_fw_is_a2:
                self.lkp_fw_config.wait_link_up(timeout=20)
            else:
                actual_speed = self.lkp_atltool_wrapper.wait_link_up(timeout=20)
            assert actual_speed == expected_speed

    # List set up tests
    # Tests are mixed to make sure that link switch happens every time from test to test, i. e.
    # expected link speed always differs from previous test run
    # Please keep them mixed

    def test_single_speed_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes only 100M.

        @steps:
        1. Set link speed 100M on LKP.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_100M], LINK_SPEED_100M)

    def test_single_speed_1g(self):
        """
        @description: This subtest checks that DUT will negotiate 1G if LKP advertizes only 1G.

        @steps:
        1. Set link speed 1G on LKP.
        2. Wait for link up.
        3. Make sure that link 1G is negotiated on LKP.

        @result: 1G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_1G], LINK_SPEED_1G)

    def test_multiple_speed_10g_1g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes 10G, 1G and 100M link speeds.

        @steps:
        1. Let LKP advertize 10G, 1G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_1G, LINK_SPEED_100M], LINK_SPEED_100M)

    def test_single_speed_2_5g(self):
        """
        @description: This subtest checks that DUT will negotiate 2.5G if LKP advertizes only 2.5G.

        @steps:
        1. Set link speed 2.5G on LKP.
        2. Wait for link up.
        3. Make sure that link 2.5G is negotiated on LKP.

        @result: 2.5G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_2_5G], LINK_SPEED_2_5G)

    def test_multiple_speed_10g_5g_2_5g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes 10G, 5G, 2.5G and
        100M link speeds.

        @steps:
        1. Let LKP advertize 10G, 5G, 2.5G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_100M], LINK_SPEED_100M)

    def test_single_speed_5g(self):
        """
        @description: This subtest checks that DUT will negotiate 5G if LKP advertizes only 5G.

        @steps:
        1. Set link speed 5G on LKP.
        2. Wait for link up.
        3. Make sure that link 5G is negotiated on LKP.

        @result: 5G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_5G], LINK_SPEED_5G)

    def test_multiple_speed_10g_2_5g_1g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes 10G, 2.5G, 1G and
        100M link speeds.

        @steps:
        1. Let LKP advertize 10G, 2.5G, 1G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M], LINK_SPEED_100M)

    def test_single_speed_10g(self):
        """
        @description: This subtest checks that DUT will negotiate 10G if LKP advertizes only 10G.

        @steps:
        1. Set link speed 10G on LKP.
        2. Wait for link up.
        3. Make sure that link 10G is negotiated on LKP.

        @result: 10G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G], LINK_SPEED_10G)

    def test_single_speed_auto(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes all link speeds.

        @steps:
        1. Set autoneg on LKP.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_AUTO], LINK_SPEED_100M)

    def test_multiple_speed_2_5g_1g(self):
        """
        @description: This subtest checks that DUT will negotiate 1G if LKP advertizes 2.5G and 1G link speeds.

        @steps:
        1. Let LKP advertize 2.5G and 1G link speeds.
        2. Wait for link up.
        3. Make sure that link 1G is negotiated on LKP.

        @result: 1G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_2_5G, LINK_SPEED_1G], LINK_SPEED_1G)

    def test_multiple_speed_1g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes 1G and 100M link speeds.

        @steps:
        1. Let LKP advertize 1G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_1G, LINK_SPEED_100M], LINK_SPEED_100M)

    def test_multiple_speed_5g_1g(self):
        """
        @description: This subtest checks that DUT will negotiate 1G if LKP advertizes 5G and 1G link speeds.

        @steps:
        1. Let LKP advertize 5G and 1G link speeds.
        2. Wait for link up.
        3. Make sure that link 1G is negotiated on LKP.

        @result: 1G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_5G, LINK_SPEED_1G], LINK_SPEED_1G)

    def test_multiple_speed_2_5g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes 2.5G and 100M link speeds.

        @steps:
        1. Let LKP advertize 2.5G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_2_5G, LINK_SPEED_100M], LINK_SPEED_100M)

    def test_multiple_speed_10g_1g(self):
        """
        @description: This subtest checks that DUT will negotiate 1G if LKP advertizes 10G and 1G link speeds.

        @steps:
        1. Let LKP advertize 10G and 1G link speeds.
        2. Wait for link up.
        3. Make sure that link 1G is negotiated on LKP.

        @result: 1G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_1G], LINK_SPEED_1G)

    def test_multiple_speed_5g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes 5G and 100M link speeds.

        @steps:
        1. Let LKP advertize 5G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_5G, LINK_SPEED_100M], LINK_SPEED_100M)

    def test_multiple_speed_5g_2_5g(self):
        """
        @description: This subtest checks that DUT will negotiate 2.5G if LKP advertizes 5G and 2.5G link speeds.

        @steps:
        1. Let LKP advertize 5G and 2.5G link speeds.
        2. Wait for link up.
        3. Make sure that link 2.5G is negotiated on LKP.

        @result: 2.5G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_5G, LINK_SPEED_2_5G], LINK_SPEED_2_5G)

    def test_multiple_speed_10g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes 10G and 100M link speeds.

        @steps:
        1. Let LKP advertize 10G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_100M], LINK_SPEED_100M)

    def test_multiple_speed_10g_2_5g(self):
        """
        @description: This subtest checks that DUT will negotiate 2.5G if LKP advertizes 10G and 2.5G link speeds.

        @steps:
        1. Let LKP advertize 10G and 2.5G link speeds.
        2. Wait for link up.
        3. Make sure that link 2.5G is negotiated on LKP.

        @result: 2.5G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_2_5G], LINK_SPEED_2_5G)

    def test_multiple_speed_10g_5g(self):
        """
        @description: This subtest checks that DUT will negotiate 5G if LKP advertizes 10G and 5G link speeds.

        @steps:
        1. Let LKP advertize 10G and 5G link speeds.
        2. Wait for link up.
        3. Make sure that link 5G is negotiated on LKP.

        @result: 5G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_5G], LINK_SPEED_5G)

    def test_multiple_speed_2_5g_1g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes 2.5G, 1G and 100M link speeds.

        @steps:
        1. Let LKP advertize 2.5G, 1G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M], LINK_SPEED_100M)

    def test_multiple_speed_5g_2_5g_1g(self):
        """
        @description: This subtest checks that DUT will negotiate 1G if LKP advertizes 5G, 2.5G and 1G link speeds.

        @steps:
        1. Let LKP advertize 5G, 2.5G and 1G link speeds.
        2. Wait for link up.
        3. Make sure that link 1G is negotiated on LKP.

        @result: 1G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G], LINK_SPEED_1G)

    def test_multiple_speed_5g_2_5g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes 5G, 2.5G and 100M link speeds.

        @steps:
        1. Let LKP advertize 5G, 2.5G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_100M], LINK_SPEED_100M)

    def test_multiple_speed_10g_5g_2_5g(self):
        """
        @description: This subtest checks that DUT will negotiate 2.5G if LKP advertizes 10G, 5G and 2.5G link speeds.

        @steps:
        1. Let LKP advertize 10G, 5G and 2.5G link speeds.
        2. Wait for link up.
        3. Make sure that link 2.5G is negotiated on LKP.

        @result: 2.5G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G], LINK_SPEED_2_5G)

    def test_multiple_speed_10g_5g_1g(self):
        """
        @description: This subtest checks that DUT will negotiate 1G if LKP advertizes 10G, 5G and 1G link speeds.

        @steps:
        1. Let LKP advertize 10G, 5G and 1G link speeds.
        2. Wait for link up.
        3. Make sure that link 1G is negotiated on LKP.

        @result: 1G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_1G], LINK_SPEED_1G)

    def test_multiple_speed_10g_5g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes 10G, 5G and 100M link speeds.

        @steps:
        1. Let LKP advertize 10G, 5G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_100M], LINK_SPEED_100M)

    def test_multiple_speed_10g_2_5g_1g(self):
        """
        @description: This subtest checks that DUT will negotiate 1G if LKP advertizes 10G, 2.5G and 1G link speeds.

        @steps:
        1. Let LKP advertize 10G, 2.5G and 1G link speeds.
        2. Wait for link up.
        3. Make sure that link 1G is negotiated on LKP.

        @result: 1G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_2_5G, LINK_SPEED_1G], LINK_SPEED_1G)

    def test_multiple_speed_10g_2_5g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes
        10G, 2.5G and 100M link speeds.

        @steps:
        1. Let LKP advertize 10G, 2.5G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_2_5G, LINK_SPEED_100M], LINK_SPEED_100M)

    def test_multiple_speed_10g_5g_2_5g_1g(self):
        """
        @description: This subtest checks that DUT will negotiate 1G if LKP advertizes
        10G, 5G, 2.5G and 1G link speeds.

        @steps:
        1. Let LKP advertize 10G, 5G, 2.5G and 1G link speeds.
        2. Wait for link up.
        3. Make sure that link 1G is negotiated on LKP.

        @result: 1G link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G], LINK_SPEED_1G)

    def test_multiple_speed_10g_5g_1g_100m(self):
        """
        @description: This subtest checks that DUT will negotiate 100M if LKP advertizes
        10G, 5G, 1G and 100M link speeds.

        @steps:
        1. Let LKP advertize 10G, 5G, 1G and 100M link speeds.
        2. Wait for link up.
        3. Make sure that link 100M is negotiated on LKP.

        @result: 100M link is up on LKP.
        @duration: 20 seconds.
        """
        self.link_speed_test([LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_1G, LINK_SPEED_100M], LINK_SPEED_100M)

    # Link switch tests

    def test_switch_5g_100m_1g_auto_10g_2_5g_100m_2_5g_100m(self):
        """
        @description: This subtest checks ability of firmware change link speed in sleep proxy mode.

        @steps:
        1. In the loop change link partner speeds and make sure that link is up: 5G, 100M, 1G, AUTO, 10G, 2.5G,
        100M, 2.5G, 100M.

        @result: All link switches are success.
        @duration: 2 minutes seconds.
        """

        self.link_switch_test([LINK_SPEED_5G, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_AUTO,
                               LINK_SPEED_10G, LINK_SPEED_2_5G, LINK_SPEED_100M, LINK_SPEED_2_5G, LINK_SPEED_100M])

    def test_switch_1g_100m_10g_5g_100m_5g_auto_10g(self):
        """
        @description: This subtest checks ability of firmware change link speed in sleep proxy mode.

        @steps:
        1. In the loop change link partner speeds and make sure that link is up: 1G, 100M, 10G, 5G, 100M,
        5G, AUTO, 10G.

        @result: All link switches are success.
        @duration: 2 minutes seconds.
        """

        self.link_switch_test([LINK_SPEED_1G, LINK_SPEED_100M, LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_100M,
                               LINK_SPEED_5G, LINK_SPEED_AUTO, LINK_SPEED_10G])


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
