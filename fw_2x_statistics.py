import os
import shutil
import time

import pytest

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_AUTO, LINK_STATE_DOWN, \
    LINK_STATE_UP
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvEEEStateMachineConfig
from tools.ifconfig import get_expected_speed
from tools.utils import get_atf_logger

from infra.test_base import TestBase
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_statistics"


class TestFw2xStatistics(TestBase):
    """
    @description: The statistics test is dedicated to verify statistics counters. Next counters are to be verified:
    LINK_DROPS_DURING_STABILITY_TIMER, LINK_DROPS_AFTER_STABILITY_TIMER, EEE_FAILURES, EEE_STATE_LINK_DOWN.

    @setup: Two Aquantia devices connected back to back.
    """

    EEE_STATEMACHINE_MASK = {
        LINK_SPEED_2_5G: 0x8,
        LINK_SPEED_5G: 0x2,
        LINK_SPEED_10G: 0x1
    }
    EEE_FROM_SILENT_TO_ACTIVE_DELAY = 12

    @classmethod
    def setup_class(cls):
        super(TestFw2xStatistics, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest")
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.atltool_wrapper = AtlTool(port=cls.dut_port)

            # Disable WOL on LKP to avoid problem with link down on Linux
            cls.lkp_ifconfig.set_power_mgmt_settings(False, False, False)

            cls.enable_eee_on_lkp()
            cls.auto_speed = get_expected_speed(LINK_SPEED_AUTO, cls.dut_port)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestFw2xStatistics, cls).teardown_class()

    def setup_method(self, method):
        super(TestFw2xStatistics, self).setup_method(method)
        self.atltool_wrapper.kickstart()
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        time.sleep(5)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestFw2xStatistics, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        if self.MCP_LOG:
            self.atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

    @classmethod
    def enable_eee_on_lkp(cls):
        cls.lkp_ifconfig.set_media_options(["energy-efficient-ethernet"])
        cls.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)

    def read_statistics(self):
        data = {}
        statistics_base_addr = self.atltool_wrapper.readreg(0x360)
        data["LINK_DROPS_DURING_STABILITY_TIMER"] = self.atltool_wrapper.readmem(statistics_base_addr + 0xd8, 4)[0]
        data["LINK_DROPS_AFTER_STABILITY_TIMER"] = self.atltool_wrapper.readmem(statistics_base_addr + 0xdc, 4)[0]
        data["EEE_FAILURES"] = self.atltool_wrapper.readmem(statistics_base_addr + 0xe0, 4)[0]
        # GAP!
        data["EEE_STATE_LINK_DOWN"] = self.atltool_wrapper.readmem(statistics_base_addr + 0xe8, 4)[0]
        log.info("Statistics: {}".format(data))
        return data

    def configure_eee_state_machine(self, link_down_timeout, link_up_timeout, max_link_drops, feature_mask, caps):
        cfg = DrvEEEStateMachineConfig()
        cfg.link_down_timeout = link_down_timeout
        cfg.link_up_timeout = link_up_timeout
        cfg.max_link_drops = max_link_drops
        cfg.feature_mask = feature_mask
        cfg.caps = caps

        beton_file = os.path.join(self.test_log_dir, "eee_state_machine.txt")
        cfg.apply(self.atltool_wrapper, beton_file)

    def check_test_is_applicable(self, speeds):
        for speed in speeds:
            if speed not in self.supported_speeds:
                pytest.xfail()

    def test_counter_link_drops_during_stability_timer_1(self):
        """
        @description: This subtest performs counters check related to stability timer (aka link up timeout).

        @steps:
        1. Set DUT and LKP link speed 5G.
        2. Configure EEE autodisable feature with 45s link down timeout, 120s link up timeout, 10 max link drops,
        feature mask for 5G link speed.
        3. Wait for 5G link up.
        4. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        5. Read and remember statistics counters.
        6. Set link down on LKP.
        7. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is not increased
            c. EEE_STATE_LINK_DOWN is increased
        8. Set link up on LKP, wait for link up.
        9. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        10. Set link down on LKP.
        11. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is not increased
            c. EEE_STATE_LINK_DOWN is increased
        12. Set link up on LKP, wait for link up.

        @result: Counters are incrementing correctly, there are no problems with link up.
        @duration: 1 minute.
        """

        self.check_test_is_applicable([LINK_SPEED_5G])

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_5G)

        self.atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_5G)
        self.configure_eee_state_machine(
            45000, 120000, 10, self.EEE_STATEMACHINE_MASK[LINK_SPEED_5G],
            DrvEEEStateMachineConfig.CAPS_HI_5GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        statictics = self.read_statistics()
        start_eee_state_link_down_val = statictics["EEE_STATE_LINK_DOWN"]
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 1
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 1

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 2
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 2

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_5G

    def test_counter_link_drops_during_stability_timer_2(self):
        """
        @description: This subtest performs counters check related to stability timer (aka link up timeout), but
        without delay for EEE from SILENT to ACTIVE transition.

        @steps:
        1. Set DUT and LKP link speed 2.5G.
        2. Configure EEE autodisable feature with 45s link down timeout, 120s link up timeout, 10 max link drops,
        feature mask for 2.5G link speed.
        3. Wait for 2.5G link up.
        4. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        5. Read and remember statistics counters.
        6. Set link down on LKP.
        7. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is not increased
            c. EEE_STATE_LINK_DOWN is increased
        8. Set link up on LKP, wait for link up.
        9. Immediate link down on LKP (no delay).
        10. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is not(!) increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is not increased
            c. EEE_STATE_LINK_DOWN is increased
        11. Set link up on LKP, wait for link up.
        12. Immediate link down on LKP (no delay).
        13. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is not(!) increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is not increased
            c. EEE_STATE_LINK_DOWN is increased
        14. Set link up on LKP, wait for link up.

        @result: Counters are incrementing correctly, there are no problems with link up.
        @duration: 2 minutes.
        """

        self.check_test_is_applicable([LINK_SPEED_2_5G])

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_2_5G)

        self.atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_2_5G)
        self.configure_eee_state_machine(
            45000, 120000, 10, self.EEE_STATEMACHINE_MASK[LINK_SPEED_2_5G],
            DrvEEEStateMachineConfig.CAPS_HI_2P5GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        statictics = self.read_statistics()
        start_eee_state_link_down_val = statictics["EEE_STATE_LINK_DOWN"]
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 1
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 1

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G

        # Perform immediate link down (when silent EEE)
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        # Counter should not increase
        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 1
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 2

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G

        # Perform immediate link down (when silent EEE)
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        # Counter should not increase
        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 1
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 3

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G

    def test_counter_link_drops_during_stability_timer_3(self):
        """
        @description: This subtest performs counters check when EEE autodisable feature is configured for not
        negotiated speed.

        @steps:
        1. Set DUT and LKP link speed 2.5G.
        2. Configure EEE autodisable feature with 45s link down timeout, 120s link up timeout, 10 max link drops,
        feature mask for 5G link speed.
        3. Wait for 2.5G link up.
        4. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        5. Read and remember statistics counters.
        6. Set link down on LKP.
        7. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is not increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is not increased
            c. EEE_STATE_LINK_DOWN is increased
        8. Set link up on LKP, wait for link up.

        @result: Counters are incrementing correctly, there are no problems with link up.
        @duration: 1 minute.
        """

        self.check_test_is_applicable([LINK_SPEED_2_5G])

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_2_5G)

        self.atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_2_5G)
        self.configure_eee_state_machine(
            45000, 120000, 10, self.EEE_STATEMACHINE_MASK[LINK_SPEED_2_5G],
            DrvEEEStateMachineConfig.CAPS_HI_5GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        statictics = self.read_statistics()
        start_eee_state_link_down_val = statictics["EEE_STATE_LINK_DOWN"]
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 1

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G

    def test_counter_link_drops_after_stability_timer_1(self):  # link_up_timeout is small
        """
        @description: This subtest performs counters check related to stability timer (aka link up timeout) when
        link up timeout is small.

        @steps:
        1. Set DUT and LKP link speed 5G.
        2. Configure EEE autodisable feature with 45s link down timeout, 1s link up timeout, 10 max link drops,
        feature mask for 5G link speed.
        3. Wait for 5G link up.
        4. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        5. Read and remember statistics counters.
        6. Set link down on LKP.
        7. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is not increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is increased
            c. EEE_STATE_LINK_DOWN is increased
        8. Set link up on LKP, wait for link up.
        9. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        10. Set link down on LKP.
        11. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is not increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is increased
            c. EEE_STATE_LINK_DOWN is increased
        12. Set link up on LKP, wait for link up.

        @result: Counters are incrementing correctly, there are no problems with link up.
        @duration: 1 minute.
        """

        self.check_test_is_applicable([LINK_SPEED_5G])

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_5G)

        self.atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_5G)
        self.configure_eee_state_machine(
            45000, 1000, 10, self.EEE_STATEMACHINE_MASK[LINK_SPEED_5G],
            DrvEEEStateMachineConfig.CAPS_HI_5GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        statictics = self.read_statistics()
        start_eee_state_link_down_val = statictics["EEE_STATE_LINK_DOWN"]
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 1
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 1

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 2
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 2

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_5G

    def test_counter_link_drops_after_stability_timer_2(self):  # link_up_timeout is small
        """
        @description: This subtest performs counters check related to stability timer (aka link up timeout) when
        link up timeout is small, but without delay for EEE from SILENT to ACTIVE transition.

        @steps:
        1. Set DUT and LKP link speed 10G.
        2. Configure EEE autodisable feature with 45s link down timeout, 1s link up timeout, 10 max link drops,
        feature mask for 10G link speed.
        3. Wait for 10G link up.
        4. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        5. Read and remember statistics counters.
        6. Set link down on LKP.
        7. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is not increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is increased
            c. EEE_STATE_LINK_DOWN is increased
        8. Set link up on LKP, wait for link up.
        9. Immediate link down on LKP (no delay).
        10. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is not increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is not(!) increased
            c. EEE_STATE_LINK_DOWN is increased
        11. Set link up on LKP, wait for link up.
        12. Immediate link down on LKP (no delay).
        13. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is not increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is not(!) increased
            c. EEE_STATE_LINK_DOWN is increased
        14. Set link up on LKP, wait for link up.

        @result: Counters are incrementing correctly, there are no problems with link up.
        @duration: 2 minutes.
        """

        self.check_test_is_applicable([LINK_SPEED_10G])

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_10G)

        self.atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_10G)
        self.configure_eee_state_machine(
            45000, 1000, 10, self.EEE_STATEMACHINE_MASK[LINK_SPEED_10G],
            DrvEEEStateMachineConfig.CAPS_HI_10GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        statictics = self.read_statistics()
        start_eee_state_link_down_val = statictics["EEE_STATE_LINK_DOWN"]
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 1
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 1

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_10G

        # Perform immediate link down (when silent EEE)
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        # Counter should not increase
        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 1
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 2

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_10G

        # Perform immediate link down (when silent EEE)
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        # Counter should not increase
        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 1
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 3

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_10G

    def test_counter_link_drops_after_stability_timer_3(self):  # link_up_timeout is small
        """
        @description: This subtest performs counters check when EEE autodisable feature is configured for not
        negotiated speed and link up timeout is small.

        @steps:
        1. Set DUT and LKP link speed 2.5G.
        2. Configure EEE autodisable feature with 45s link down timeout, 120s link up timeout, 10 max link drops,
        feature mask for 10G link speed.
        3. Wait for 2.5G link up.
        4. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        5. Read and remember statistics counters.
        6. Set link down on LKP.
        7. Read statictics counters, make sure that:
            a. LINK_DROPS_DURING_STABILITY_TIMER is not increased
            b. LINK_DROPS_AFTER_STABILITY_TIMER is not increased
            c. EEE_STATE_LINK_DOWN is increased
        8. Set link up on LKP, wait for link up.

        @result: Counters are incrementing correctly, there are no problems with link up.
        @duration: 1 minute.
        """

        self.check_test_is_applicable([LINK_SPEED_2_5G])

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_2_5G)

        self.atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_2_5G)
        self.configure_eee_state_machine(
            45000, 1000, 10, self.EEE_STATEMACHINE_MASK[LINK_SPEED_2_5G],
            DrvEEEStateMachineConfig.CAPS_HI_10GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        statictics = self.read_statistics()
        start_eee_state_link_down_val = statictics["EEE_STATE_LINK_DOWN"]
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["LINK_DROPS_DURING_STABILITY_TIMER"] == 0
        assert statictics["LINK_DROPS_AFTER_STABILITY_TIMER"] == 0
        assert statictics["EEE_STATE_LINK_DOWN"] == start_eee_state_link_down_val + 1

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G

    def test_counter_eee_failures(self):
        """
        @description: This subtest performs EEE_FAILURES counter check in different conditions.

        @steps:
        1. Set DUT and LKP link speed 2.5G.
        2. Configure EEE autodisable feature with 22s link down timeout, 22s link up timeout, 1 max link drops,
        feature mask for 2.5G link speed.
        3. Wait for 2.5G link up.
        4. Sleep 30 seconds.
        5. Read and remember statistics counters.
        6. Set link down on LKP.
        7. Read statictics counters, make sure that EEE_FAILURES is not incremented (due to link up timeout is passed).
        8. Set link up on LKP, wait for link up.
        9. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        10. Set link down on LKP.
        11. Make sure that EEE_FAILURES is incremented (because link up timeout is not passed).
        12. Sleep 30 seconds.
        13. Make sure that EEE_FAILURES counter is not changed (i.e. not affected by passed link down timeout).
        14. Set link up on LKP, wait for link up.
        15. Sleep 30 seconds.
        16. Set link down on LKP.
        17. Make sure that EEE_FAILURES is not incremented (due to link up timeout is passed).
        18. Set link up on LKP, wait for link up.
        19. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        20. Set link down on LKP.
        21. Make sure that EEE_FAILURES is incremented (because link up timeout is not passed).
        22. Set link up on LKP, wait for link up.
        23. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        24. Set link down on LKP.
        25. Sleep 30 seconds.
        26. Make sure that EEE_FAILURES is not incremented (due to link down timeout is passed).
        27. Set link up on LKP, wait for link up.
        28. Make sure that EEE_FAILURES is not changed.

        @result: Counters are incrementing correctly, there are no problems with link up.
        @duration: 5 minutes.
        """

        self.check_test_is_applicable([LINK_SPEED_2_5G])

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_2_5G)

        self.atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_2_5G)
        self.configure_eee_state_machine(
            22000, 22000, 1, self.EEE_STATEMACHINE_MASK[LINK_SPEED_2_5G],
            DrvEEEStateMachineConfig.CAPS_HI_2P5GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(30)

        statictics = self.read_statistics()
        assert statictics["EEE_FAILURES"] == 0

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["EEE_FAILURES"] == 0

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["EEE_FAILURES"] == 1

        time.sleep(30)

        statictics = self.read_statistics()
        assert statictics["EEE_FAILURES"] == 1

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.atltool_wrapper.wait_link_up()
        time.sleep(30)

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["EEE_FAILURES"] == 1

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.atltool_wrapper.wait_link_down()

        statictics = self.read_statistics()
        assert statictics["EEE_FAILURES"] == 2

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        time.sleep(30)

        statictics = self.read_statistics()
        assert statictics["EEE_FAILURES"] == 2

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        assert self.atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G

        statictics = self.read_statistics()
        assert statictics["EEE_FAILURES"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
