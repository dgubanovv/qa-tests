import os
import re
import shutil
import tempfile
import time
from sets import Set

import pytest

from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_AUTO, \
    FELICITY_CARDS, CARDS_FELICITY_BERMUDA
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvEEEStateMachineConfig, DrvMessage
from tools.ifconfig import get_expected_speed
from tools.mbuper import LINK_SPEED_TO_REG_VAL_MAP_2X
from tools.utils import get_atf_logger, upload_directory, remove_directory

from infra.test_base import TestBase
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_eee_state_machine_mbu"


class TestEEEStateMachineMbu(TestBase):
    """
    @description: The EEE state machine test is dedicated to verify EEE autodisable feature.

    @setup: Two Aquantia devices connected back to back.
    """

    EEE_STATEMACHINE_MASK = {LINK_SPEED_1G: 0x10, LINK_SPEED_2_5G: 0x8, LINK_SPEED_5G: 0x2, LINK_SPEED_10G: 0x1}
    EEE_CAPS_BITS = {
        LINK_SPEED_1G: DrvEEEStateMachineConfig.CAPS_HI_1000BASET_FD_EEE,
        LINK_SPEED_2_5G: DrvEEEStateMachineConfig.CAPS_HI_2P5GBASET_FD_EEE,
        LINK_SPEED_5G: DrvEEEStateMachineConfig.CAPS_HI_5GBASET_FD_EEE,
        LINK_SPEED_10G: DrvEEEStateMachineConfig.CAPS_HI_10GBASET_FD_EEE,
    }
    EEE_STATEMACHINE_CAPS_BITS = 0x4000
    EEE_FROM_SILENT_TO_ACTIVE_DELAY = 12
    ALL_EEE_SPEEDS = [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]

    @classmethod
    def setup_class(cls):
        super(TestEEEStateMachineMbu, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest")
            cls.lkp_driver = Driver(port=cls.lkp_port, drv_type=DRV_TYPE_DIAG, version="latest", host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            # Prepare link-partner, i.e. disable auto-disable feature on it
            cls.lkp_atltool_wrapper.kickstart(reload_phy_fw=cls.lkp_fw_card not in CARDS_FELICITY_BERMUDA)
            # Now toggle 0x4000 bit, by 2-step update
            beton = ["writereg 0x36c 0x00004000", "pause 1 s", "writereg 0x36c 0x00000000"]
            cls.lkp_atltool_wrapper.exec_beton(beton)

            cls.auto_speed = get_expected_speed(LINK_SPEED_AUTO, cls.dut_port)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestEEEStateMachineMbu, cls).teardown_class()

    def set_lkp_speed_and_eee(self, speed, eee_speeds):
        self.current_lkp_speed = speed
        beton = ["writereg 0x368 0x0", "pause 1 s"]
        caps = 0
        for eee_speed in eee_speeds:
            caps |= self.EEE_CAPS_BITS[eee_speed]

        beton.append("writereg 0x36c 0x{:08x}".format(caps))
        beton.append("writereg 0x368 0x{:08x}".format(LINK_SPEED_TO_REG_VAL_MAP_2X[speed]))
        self.lkp_atltool_wrapper.exec_beton(beton)

    def self_lkp_link_down_up(self, delay=5):
        beton = [
            "writereg 0x368 0x0",
            "pause {} s".format(delay),
            "writereg 0x368 0x{:08x}".format(LINK_SPEED_TO_REG_VAL_MAP_2X[self.current_lkp_speed])
        ]
        self.lkp_atltool_wrapper.exec_beton(beton)

    def setup_method(self, method):
        super(TestEEEStateMachineMbu, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.dut_atltool_wrapper = AtlTool(port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)
        # self.bin_log_file, self.txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)
        # self.lkp_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestEEEStateMachineMbu, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()

        beton = ["rr 0x368", "rr 0x36c", "rr 0x370", "rr 0x374", "rpr 0x7.0x3c", "rpr 0x7.0x3d", "rpr 0x7.0x3e",
                 "rpr 0x7.0x3f"]
        log.info("Debug info after test from DUT:")
        self.dut_atltool_wrapper.exec_beton(beton)

        log.info("Debug info after test from LKP:")
        self.lkp_atltool_wrapper.exec_beton(beton)

        # # Disable FW logging and copy log files to output test directory
        # self.dut_atltool_wrapper.debug_buffer_enable(False)
        # shutil.copy(self.bin_log_file, self.test_log_dir)
        # shutil.copy(self.txt_log_file, self.test_log_dir)

        # self.lkp_bin_log_file, self.lkp_txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(False)
        # shutil.copy(self.lkp_bin_log_file, self.test_log_dir)
        # shutil.copy(self.lkp_txt_log_file, self.test_log_dir)

    def configure_eee_state_machine(self, link_down_timeout, link_up_timeout, max_link_drops, feature_mask, caps):
        cfg = DrvEEEStateMachineConfig()
        cfg.link_down_timeout = link_down_timeout
        cfg.link_up_timeout = link_up_timeout
        cfg.max_link_drops = max_link_drops
        cfg.feature_mask = feature_mask
        cfg.caps = caps

        beton_file = os.path.join(self.test_log_dir, "eee_state_machine.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

    def verify_mac_advertized_eee(self, enabled_speeds=None, disabled_speeds=None):
        if enabled_speeds is not None and disabled_speeds is None:
            disabled_speeds = Set(self.ALL_EEE_SPEEDS) - Set(enabled_speeds)
        elif enabled_speeds is None and disabled_speeds is not None:
            enabled_speeds = Set(self.ALL_EEE_SPEEDS) - Set(disabled_speeds)
        elif enabled_speeds is None and disabled_speeds is None:
            raise Exception("Both enabled_speeds and disabled_speeds are None")

        val = self.dut_atltool_wrapper.readreg(0x36c)
        for speed in enabled_speeds:
            assert val & self.EEE_CAPS_BITS[speed] == self.EEE_CAPS_BITS[speed]
        for speed in disabled_speeds:
            assert val & self.EEE_CAPS_BITS[speed] == 0

    def verify_phy_advertized_eee(self, enabled_speeds=None, disabled_speeds=None):
        if enabled_speeds is not None and disabled_speeds is None:
            disabled_speeds = Set(self.ALL_EEE_SPEEDS) - Set(enabled_speeds)
        elif enabled_speeds is None and disabled_speeds is not None:
            enabled_speeds = Set(self.ALL_EEE_SPEEDS) - Set(disabled_speeds)
        elif enabled_speeds is None and disabled_speeds is None:
            raise Exception("Both enabled_speeds and disabled_speeds are None")

        # PHY register values for enabled EEE
        phy_0x7_0x3c_eee_1g = 0x4
        phy_0x7_0x3e_eee_2_5g = 0x1
        phy_0x7_0x3e_eee_5g = 0x2
        phy_0x7_0x3c_eee_10g = 0x8
        phy_0x7_0x3c_val = self.dut_atltool_wrapper.readphyreg(0x7, 0x3c)
        phy_0x7_0x3e_val = self.dut_atltool_wrapper.readphyreg(0x7, 0x3e)

        for speed in enabled_speeds:
            if speed == LINK_SPEED_1G:
                assert phy_0x7_0x3c_val & phy_0x7_0x3c_eee_1g == phy_0x7_0x3c_eee_1g
            if speed == LINK_SPEED_2_5G:
                assert phy_0x7_0x3e_val & phy_0x7_0x3e_eee_2_5g == phy_0x7_0x3e_eee_2_5g
            if speed == LINK_SPEED_5G:
                assert phy_0x7_0x3e_val & phy_0x7_0x3e_eee_5g == phy_0x7_0x3e_eee_5g
            if speed == LINK_SPEED_10G:
                assert phy_0x7_0x3c_val & phy_0x7_0x3c_eee_10g == phy_0x7_0x3c_eee_10g
        for speed in disabled_speeds:
            if speed == LINK_SPEED_1G:
                assert phy_0x7_0x3c_val & phy_0x7_0x3c_eee_1g == 0
            if speed == LINK_SPEED_2_5G:
                assert phy_0x7_0x3e_val & phy_0x7_0x3e_eee_2_5g == 0
            if speed == LINK_SPEED_5G:
                assert phy_0x7_0x3e_val & phy_0x7_0x3e_eee_5g == 0
            if speed == LINK_SPEED_10G:
                assert phy_0x7_0x3c_val & phy_0x7_0x3c_eee_10g == 0

    def verify_mac_negotiated_eee(self, enabled_speeds=None, disabled_speeds=None):
        if enabled_speeds is not None and disabled_speeds is None:
            disabled_speeds = Set(self.ALL_EEE_SPEEDS) - Set(enabled_speeds)
        elif enabled_speeds is None and disabled_speeds is not None:
            enabled_speeds = Set(self.ALL_EEE_SPEEDS) - Set(disabled_speeds)
        elif enabled_speeds is None and disabled_speeds is None:
            raise Exception("Both enabled_speeds and disabled_speeds are None")

        val = self.dut_atltool_wrapper.readreg(0x374)
        for speed in enabled_speeds:
            assert val & self.EEE_CAPS_BITS[speed] == self.EEE_CAPS_BITS[speed]
        for speed in disabled_speeds:
            assert val & self.EEE_CAPS_BITS[speed] == 0

    def check_test_is_applicable(self, speeds):
        if self.dut_fw_card in FELICITY_CARDS:
            if self.supported_speeds is None:
                raise Exception("Do not know supported speeds on Felicity")
            for speed in speeds:
                if speed not in self.supported_speeds:
                    pytest.xfail()
        else:
            if LINK_SPEED_10G in speeds and self.auto_speed != LINK_SPEED_10G:
                pytest.xfail()

    @pytest.mark.skip("Firmware logs are encoded, so this test will not pass anymore")
    def test_default_settings(self):
        """
        @description: This subtest checks default feature settings.

        @steps:
        1. Kickstart DUT.
        2. Collect default deature settings.
        3. Make sure that link down timeout is 10 seconds.
        4. Make sure that link up timeout is 8 hours.
        5. Make sure that max link drops is 1.
        6. Make sure that feature is enabled for 1G, 2.5G, 5G and 10G link speeds.

        @result: Default settings are correct.
        @duration: 1 minute.
        """

        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

        with open(self.txt_log_file, "r") as log_file:
            mcp_log = log_file.readlines()

            if len(mcp_log) <= 1:
                pytest.skip("Log is empty. This is probably 2.x production release")

            re_def_settings = re.compile(".*eee configure, linkDownTimeout: ([0-9]+), linkUpTimeout: "
                                         "([0-9]+), maxLinkDrops: ([0-9]+), ratesMask: ([a-fA-Fx0-9]+).*")

            def_setting_found = False
            for line in mcp_log[::-1]:
                m = re_def_settings.match(line)
                if m is not None:
                    log.info(line)

                    link_down_timeout = int(m.group(1))
                    link_up_timeout = int(m.group(2))
                    max_link_drops = int(m.group(3))
                    rates_mask = int(m.group(4), 16)

                    assert link_down_timeout == DrvEEEStateMachineConfig.DEFAULT_LINK_DOWN_TIMEOUT
                    assert link_up_timeout == DrvEEEStateMachineConfig.DEFAULT_LINK_UP_TIMEOUT
                    assert max_link_drops == DrvEEEStateMachineConfig.DEFAULT_MAX_LINK_DROPS
                    ver_major, ver_minor, ver_release = self.dut_atltool_wrapper.get_fw_version()
                    if ver_major == 2 and ver_minor >= 11:
                        assert rates_mask == 0x0  # Not enabled
                    elif ver_major == 2 and ver_minor < 11:
                        assert rates_mask == 0x20 | 0x10 | 0x8 | 0x2 | 0x1  # 100M, 1G, 2.5G, 5G and 10G
                    else:
                        assert rates_mask == 0x10 | 0x8 | 0x2 | 0x1  # 1G, 2.5G, 5G and 10G
                    def_setting_found = True
                    break
            if not def_setting_found:
                raise Exception("Failed to find default feature settings")

    def test_link_down_timeout_on_10g(self):
        """
        @description: This subtest verifies link down timeout on 10G link speed.

        @steps:
        1. Set 10G link speed on LKP, set EEE advertizment for 2.5G, 5G and 10G on LKP.
        2. Kickstart DUT.
        3. Set link speed 10G on DUT.
        4. Configure EEE autodisable feature with 20s link down timeout, 120s link up timeout, 1 max link drops,
        feature mask for 10G link speed.
        5. Configure DUT to advertize EEE on 10G.
        6. Wait for link up.
        7. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        8. Verify that MAC advertizes only 10G EEE, PHY advertizes only 10G EEE, MAC negotiated only 10G EEE.
        9. Link down/up on LKP.
        10. Wait for link up.
        11. Verify that MAC advertizes only 10G EEE, PHY doesn't advertize EEE, MAC didn't negotiate EEE on all speeds.
        12. Link down on LKP for (link down timeout + 2) sec, then link up.
        13. Wait for link up.
        14. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        15. Verify that MAC advertizes only 10G EEE, PHY advertizes only 10G EEE, MAC negotiated only 10G EEE.

        @result: Fast link down disables EEE, long link down enables EEE.
        @duration: 2 minutes.
        """

        self.check_test_is_applicable(speeds=[LINK_SPEED_10G])

        link_down_timeout = 20

        self.set_lkp_speed_and_eee(LINK_SPEED_10G, [LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

        self.dut_atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_10G)
        self.configure_eee_state_machine(
            link_down_timeout * 1000, 120000, 1, self.EEE_STATEMACHINE_MASK[LINK_SPEED_10G],
            DrvEEEStateMachineConfig.CAPS_HI_10GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_10G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_phy_advertized_eee(disabled_speeds=self.ALL_EEE_SPEEDS)
        self.verify_mac_negotiated_eee(disabled_speeds=self.ALL_EEE_SPEEDS)

        self.self_lkp_link_down_up(delay=link_down_timeout + 2)
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_10G])

    def test_link_down_timeout_on_2_5g_and_5g(self):
        """
        @description: This subtest verifies link down timeout 2.5G and 5G link speeds with link switch.

        @steps:
        1. Set 2.5G link speed on LKP, set EEE advertizment for 1G, 2.5G, 5G and 10G on LKP.
        2. Kickstart DUT.
        3. Set autoneg on DUT.
        4. Configure EEE autodisable feature with 20s link down timeout, 120s link up timeout, 2 max link drops,
        feature mask for 2.5G and 5G link speeds.
        5. Configure DUT to advertize EEE on 2.5G and 5G.
        6. Wait for link 2.5G up.
        7. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        8. Verify that MAC advertizes 2.5G and 5G EEE, PHY advertizes 2.5G and 5G EEE, MAC negotiated only 2.5G EEE.
        9. Link down/up on LKP.
        10. Wait for link up.
        11. Verify that first link down didn't change anything because max link drops is 2; MAC advertizes 2.5G and 5G
        EEE, PHY advertizes 2.5G and 5G EEE, MAC negotiated only 2.5G EEE.
        12. Set 5G link speed on LKP, set EEE advertizment for 1G, 2.5G, 5G and 10G on LKP.
        13. Wait for link 5G up.
        14. Verify that MAC advertizes 2.5G and 5G EEE, PHY advertizes 2.5G and 5G EEE, MAC negotiated only 5G EEE.
        15. Link down/up on LKP.
        16. Wait for link up.
        17. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        18. Verify that max link drops counter was reset after link speed change; MAC advertizes 2.5G and 5G
        EEE, PHY advertizes 2.5G and 5G EEE, MAC negotiated only 5G EEE.
        19. Link down/up on LKP.
        20. Wait for link up.
        21. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        22. Verify that 5G EEE is disabled due to second link down; MAC advertizes 2.5G and 5G
        EEE, PHY advertizes 2.5G EEE only, MAC didn't negotiate EEE.
        23. Link down on LKP for (link down timeout + 2) sec, then link up.
        24. Wait for link up.
        25. Verify that EEE is enabled back on 5G; MAC advertizes 2.5G and 5G EEE, MAC negotiated only 5G EEE.
        26. Set 2.5G link speed on LKP, set EEE advertizment for 1G, 2.5G, 5G and 10G on LKP.
        27. Wait for link 2.5G up.
        28. Verify that MAC advertizes 2.5G and 5G EEE, MAC negotiated only 2.5G EEE.

        @result: All checks are passed.
        @duration: 5 minutes.
        """

        self.check_test_is_applicable(speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])

        link_down_timeout = 20

        self.set_lkp_speed_and_eee(LINK_SPEED_2_5G, [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

        self.dut_atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_AUTO)
        self.configure_eee_state_machine(
            link_down_timeout * 1000, 120000, 2,
            self.EEE_STATEMACHINE_MASK[LINK_SPEED_2_5G] | self.EEE_STATEMACHINE_MASK[LINK_SPEED_5G],
            DrvEEEStateMachineConfig.CAPS_HI_2P5GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_5GBASET_FD_EEE |
            DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_2_5G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_2_5G])

        # Second link down will disable EEE on 2.5G
        self.set_lkp_speed_and_eee(LINK_SPEED_5G, [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_5G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_5G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G])
        self.verify_mac_negotiated_eee(disabled_speeds=self.ALL_EEE_SPEEDS)

        self.self_lkp_link_down_up(delay=link_down_timeout + 2)
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_5G])

        self.set_lkp_speed_and_eee(LINK_SPEED_2_5G, [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_2_5G])

    def test_long_link_down_during_active_state(self):
        """
        @description: This subtest verifies that long link down resets max link drops counter.

        @steps:
        1. Set 10G link speed on LKP, set EEE advertizment for 2.5G, 5G and 10G on LKP.
        2. Kickstart DUT.
        3. Set link speed 10G on DUT.
        4. Configure EEE autodisable feature with 20s link down timeout, 45s link up timeout, 2 max link drops,
        feature mask for 10G link speed.
        5. Configure DUT to advertize EEE on 10G.
        6. Wait for link up.
        7. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        8. Verify that MAC advertizes only 10G EEE, PHY advertizes only 10G EEE, MAC negotiated only 10G EEE.
        9. Link down/up on LKP.
        10. Wait for link up.
        11. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        12. Verify that MAC advertizes only 10G EEE, PHY advertizes only 10G EEE, MAC negotiated only 10G EEE.
        13. Link down on LKP for (link down timeout + 2) sec, then link up.
        14. Wait for link up.
        15. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        16. Verify that MAC advertizes only 10G EEE, PHY advertizes only 10G EEE, MAC negotiated only 10G EEE.
        17. Link down/up on LKP.
        18. Wait for link up.
        19. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        20. Verify that MAC advertizes only 10G EEE, PHY advertizes only 10G EEE, MAC negotiated only 10G EEE.
        21. Link down/up on LKP.
        22. Wait for link up.
        23. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        24. Verify that MAC advertizes only 10G EEE, PHY doesn't advertize EEE, MAC didn't negotiate EEE.

        @result: Long link down reset max link drops counter.
        @duration: 4 minutes.
        """

        self.check_test_is_applicable(speeds=[LINK_SPEED_10G])

        link_down_timeout = 20
        link_up_timeout = 45

        self.set_lkp_speed_and_eee(LINK_SPEED_10G, [LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

        self.dut_atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_AUTO)
        self.configure_eee_state_machine(
            link_down_timeout * 1000, link_up_timeout * 1000, 2,
            self.EEE_STATEMACHINE_MASK[LINK_SPEED_10G],
            DrvEEEStateMachineConfig.CAPS_HI_10GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_10G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_10G])

        self.self_lkp_link_down_up(delay=link_down_timeout + 2)
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_10G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_10G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_phy_advertized_eee(disabled_speeds=self.ALL_EEE_SPEEDS)
        self.verify_mac_negotiated_eee(disabled_speeds=self.ALL_EEE_SPEEDS)

    def test_link_up_timeout_2_5g_10g(self):
        """
        @description: This subtest verifies link up timeout.

        @steps:
        1. Set 10G link speed on LKP, set EEE advertizment for 2.5G, 5G and 10G on LKP.
        2. Kickstart DUT.
        3. Set autoneg on DUT.
        4. Configure EEE autodisable feature with 20s link down timeout, 120s link up timeout, 2 max link drops,
        feature mask for 2.5G and 10G link speeds.
        5. Configure DUT to advertize EEE on 2.5G and 10G.
        6. Wait for link 10G up.
        7. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        8. Verify that MAC advertizes 2.5G and 10G EEE, PHY advertizes 2.5G and 10G EEE,
        MAC negotiated 2.5G and 10G EEE.
        9. Sleep (link up timeout + 2 - 12) seconds to pass link up tomeout.
        10. Verify that MAC advertizes 2.5G and 10G EEE, PHY advertizes 2.5G and 10G EEE,
        MAC negotiated 2.5G and 10G EEE.
        15. Link down/up on LKP.
        16. Wait for link up.
        17. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        18. Verify that MAC advertizes 2.5G and 10G EEE, PHY advertizes 2.5G & 10G EEE,
        MAC negotiated 2.5G and 10G EEE because link up timeout is passed.
        19. Link down/up on LKP.
        20. Wait for link up.
        21. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        22. Verify that 10G EEE is disabled; MAC advertizes 2.5G and 10G EEE, PHY advertizes 2.5G EEE,
        MAC negotiated 2.5G EEE.

        @result: All checks are passed.
        @duration: 3 minutes.
        """

        self.check_test_is_applicable(speeds=[LINK_SPEED_2_5G, LINK_SPEED_10G])

        link_down_timeout = 20
        link_up_timeout = 45

        self.set_lkp_speed_and_eee(LINK_SPEED_10G, [LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

        self.dut_atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_AUTO)
        self.configure_eee_state_machine(
            link_down_timeout * 1000, link_up_timeout * 1000, 1,
            self.EEE_STATEMACHINE_MASK[LINK_SPEED_2_5G] | self.EEE_STATEMACHINE_MASK[LINK_SPEED_10G],
            DrvEEEStateMachineConfig.CAPS_HI_2P5GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_10GBASET_FD_EEE |
            DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_10G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_10G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_10G])

        time.sleep(link_up_timeout + 2 - self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_10G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_10G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_10G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_10G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_10G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_10G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G, LINK_SPEED_10G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_2_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[])

    def test_link_speed_switch_during_inactive_state(self):
        """
        @description: This subtest verifies link switch after EEE failure.

        @steps:
        1. Set 5G link speed on LKP, set EEE advertizment for 2.5G, 5G and 10G on LKP.
        2. Kickstart DUT.
        3. Set autoneg on DUT.
        4. Configure EEE autodisable feature with 20s link down timeout, 45s link up timeout, 1 max link drops,
        feature mask for 10G and 5G link speeds.
        5. Configure DUT to advertize EEE on 10G and 5G.
        6. Wait for link 5G up.
        7. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        8. Verify that MAC advertizes 10G and 5G EEE, PHY advertizes 10G and 5G EEE, MAC negotiated 10G and 5G EEE.
        9. Link down/up on LKP.
        10. Wait for link up.
        11. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        12. Verify that 5G EEE is disabled; MAC advertizes 10G and 5G EEE, PHY advertizes 10G EEE,
        MAC negotiated 10G EEE.
        13. Set 10G link speed on LKP, set EEE advertizment for 10G, 2.5G, 5G and 10G on LKP.
        14. Wait for link 10G up.
        15. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        16. MAC advertizes 10G and 5G EEE, PHY advertizes 10G and 5G EEE, MAC negotiated 10G EEE.
        17. Set 5G link speed on LKP, set EEE advertizment for 10G, 2.5G, 5G and 10G on LKP.
        18. Wait for link 5G up.
        19. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        20. MAC advertizes 10G and 5G EEE, PHY advertizes 10G and 5G EEE, MAC negotiated 10G and 5G EEE.

        @result: All checks are passed.
        @duration: 4 minutes.
        """

        self.check_test_is_applicable(speeds=[LINK_SPEED_10G, LINK_SPEED_5G])

        link_down_timeout = 20
        link_up_timeout = 45

        self.set_lkp_speed_and_eee(LINK_SPEED_5G, [LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

        self.dut_atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_AUTO)
        self.configure_eee_state_machine(
            link_down_timeout * 1000, link_up_timeout * 1000, 1,
            self.EEE_STATEMACHINE_MASK[LINK_SPEED_10G] | self.EEE_STATEMACHINE_MASK[LINK_SPEED_5G],
            DrvEEEStateMachineConfig.CAPS_HI_10GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_5GBASET_FD_EEE |
            DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_5G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_mac_negotiated_eee(enabled_speeds=[])

        self.set_lkp_speed_and_eee(LINK_SPEED_10G, [LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_10G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_10G])

        self.set_lkp_speed_and_eee(LINK_SPEED_5G, [LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_5G])

    def test_disable_feature(self):
        """
        @description: This subtest verifies disable of the feature.

        @steps:
        1. Set 2.5G link speed on LKP, set EEE advertizment for 2.5G, 5G and 10G on LKP.
        2. Kickstart DUT.
        3. Set autoneg on DUT.
        4. Toggle 0x4000 bit to disable feature.
        7. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        8. Verify that MAC advertizes 10G and 2.5G EEE, PHY advertizes 10G and 2.5G EEE, MAC negotiated 10G and 2.5G EEE.
        9. Link down/up on LKP.
        10. Wait for link up.
        11. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        12. Verify that MAC advertizes 10G and 2.5G EEE, PHY advertizes 10G and 2.5G EEE, MAC negotiated 10G and 2.5G EEE.
        13. Link down/up on LKP.
        14. Wait for link up.
        15. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        16. Verify that MAC advertizes 10G and 2.5G EEE, PHY advertizes 10G and 2.5G EEE, MAC negotiated 10G and 2.5G EEE.
        17. Configure EEE autodisable feature with 45s link down timeout, 45s link up timeout, 1 max link drops,
        feature mask for 10G and 2.5G link speeds.
        18. Wait for link up.
        19. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        13. Link down/up on LKP.
        14. Wait for link up.
        15. Sleep 12 seconds (EEE transition from SILENT to ACTIVE state).
        16. MAC advertizes 10G and 2.5G EEE, PHY advertizes 10G EEE only, MAC negotiated 10G EEE only.

        @result: All checks are passed.
        @duration: 4 minutes.
        """

        self.check_test_is_applicable(speeds=[LINK_SPEED_2_5G, LINK_SPEED_10G])

        self.set_lkp_speed_and_eee(LINK_SPEED_2_5G, [LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

        self.dut_atltool_wrapper.set_link_params_2x(speed=LINK_SPEED_AUTO)
        # Toggle 0x4000 bit to disable feature
        beton = ["wr 0x36c 0x4000", "pause 1 s", "wr 0x36c 0x{:08x}".format(
            DrvEEEStateMachineConfig.CAPS_HI_10GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_2P5GBASET_FD_EEE)]
        self.dut_atltool_wrapper.exec_beton(beton)
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_2_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_2_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_2_5G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_2_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_2_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_2_5G])

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_2_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_2_5G])
        self.verify_mac_negotiated_eee(enabled_speeds=[LINK_SPEED_2_5G])

        self.configure_eee_state_machine(
            45000, 45000, 1,
            self.EEE_STATEMACHINE_MASK[LINK_SPEED_10G] | self.EEE_STATEMACHINE_MASK[LINK_SPEED_2_5G],
            DrvEEEStateMachineConfig.CAPS_HI_10GBASET_FD_EEE | DrvEEEStateMachineConfig.CAPS_HI_2P5GBASET_FD_EEE |
            DrvEEEStateMachineConfig.CAPS_HI_EEE_AUTO_DISABLE)
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.self_lkp_link_down_up()
        assert self.dut_atltool_wrapper.wait_link_up() == LINK_SPEED_2_5G
        time.sleep(self.EEE_FROM_SILENT_TO_ACTIVE_DELAY)

        self.verify_mac_advertized_eee(enabled_speeds=[LINK_SPEED_10G, LINK_SPEED_2_5G])
        self.verify_phy_advertized_eee(enabled_speeds=[LINK_SPEED_10G])
        self.verify_mac_negotiated_eee(enabled_speeds=[])


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
