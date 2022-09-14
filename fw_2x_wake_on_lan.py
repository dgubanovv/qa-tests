"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import time
import timeit

import pytest
import shutil

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_NO_LINK, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_10G, LINK_SPEED_AUTO, LINK_STATE_UP, LINK_STATE_DOWN, FELICITY_CARDS
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvEthConfig, OffloadIpInfo, DrvWakeByTimerConfig, DrvMessage, FWSettings, \
    SettingsMemory
from tools.mbuper import LINK_SPEED_TO_REG_VAL_MAP_2X
from tools.power import Power
from tools.samba import Samba
from tools.scapy_tools import ScapyTools
from tools.utils import get_atf_logger

from infra.test_base import TestBase, idparametrize
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_wake_on_lan"


class TestWakeOnLan(TestBase):
    AFTER_TURNOFF_DELAY = 30
    WAKE_ON_LINK_DELAY = 15

    DUT_IP = "192.168.0.3"
    DUT_MAC = "00:17:b6:00:07:82"

    LKP_IP = "192.168.0.2"
    NETMASK = "255.255.255.0"
    GATEWAY = "192.168.0.1"

    @classmethod
    def setup_class(cls):
        super(TestWakeOnLan, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest", host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, cls.GATEWAY)

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port)

            cls.dut_fw_ver_maj = cls.dut_atltool_wrapper.get_fw_version()[0]

            cls.dut_power = Power(host=cls.dut_hostname)
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port)

            # Disable WOL on LKP to avoid problem with link down on Linux
            cls.lkp_ifconfig.set_power_mgmt_settings(False, False, False)

            # Disable Samba to remove background multicast traffic which affects SerDes
            Samba(host=cls.lkp_hostname).stop()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestWakeOnLan, cls).teardown_class()

    def setup_method(self, method):
        super(TestWakeOnLan, self).setup_method(method)
        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(True)
            self.bin_log_file, self.txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(True)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)
        for i in range(3):
            if self.is_host_alive_and_ready(self.dut_hostname):
                break
            time.sleep(5)
        else:
            raise Exception("DUT is not online, can't perform test")

        # FW 3X requires kickstart after each configuration
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)

        self.get_wake_counter()
        self.get_wake_reason()

    def teardown_method(self, method):
        super(TestWakeOnLan, self).teardown_method(method)

        self.bring_host_online(self.dut_hostname)
        self.dut_power.hibernate_off()

        self.get_wake_counter()
        self.get_wake_reason()

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()

        if self.MCP_LOG:
            self.dut_bin_log_file, self.dut_txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.dut_bin_log_file, self.test_log_dir)
            shutil.copy(self.dut_txt_log_file, self.test_log_dir)

            self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

    def hibernate_dut(self, retry_interval=15, check_early_wake=True):
        log.info("Hibernating DUT")
        self.dut_power.hibernate()
        if not self.poll_host_powered_off(self.dut_hostname, retry_interval=retry_interval):
            raise Exception("Couldn't hibernate DUT")
        log.info("DUT is hibernated")

        if check_early_wake:
            time.sleep(self.AFTER_TURNOFF_DELAY)
            if self.is_host_powered_on(self.dut_hostname):
                raise Exception("DUT came back online spuriously before test")
            log.info("DUT is still hibernated after {} seconds of sleeping".format(self.AFTER_TURNOFF_DELAY))

    def perform_after_wake_up_checks(self):
        log.info("Waiting until agent on DUT is started")
        if not self.poll_host_alive_and_ready(self.dut_hostname, self.POWER_UP_TIMEOUT):
            log.warning("Agent on DUT is not started after WoL test")

    def get_wake_counter(self):
        wake_counter = self.dut_atltool_wrapper.get_wake_counter_2x()
        log.info("Current wake counter: {}".format(wake_counter))
        return wake_counter

    def get_wake_reason(self):
        wake_reason = self.dut_atltool_wrapper.get_wake_reason_2x()
        log.info("Wake reason: {}".format(hex(wake_reason)))
        return wake_reason

    @idparametrize("sleep_proxy", [
        pytest.param(False, marks=pytest.mark.xfail(reason="MAC not available without sleep proxy being configured")),
        True
    ])
    def test_wake_by_magic_packet(self, sleep_proxy):
        """Test for wake on LAN by magic packet"""
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407
        cfg.mac = TestWakeOnLan.DUT_MAC
        cfg.caps = DrvEthConfig.CAPS_HI_WOL
        if sleep_proxy:
            cfg.caps |= DrvEthConfig.CAPS_HI_SLEEP_PROXY

        cfg.ips = OffloadIpInfo()

        beton_file = os.path.join(self.test_log_dir,
                                  "offload_wol_magic_proxy.txt" if sleep_proxy else "offload_wol_magic_no_proxy.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Sleep proxy link {} is up".format(link_speed))

        self.hibernate_dut()

        assert self.lkp_ifconfig.wait_link_up() != LINK_SPEED_NO_LINK, "DUT dropped link after hibernation"

        log.info("Sending magic packet")
        self.lkp_scapy_tools.send_raw_magic_packet(self.DUT_MAC)

        time.sleep(self.LED_TIMEOUT)
        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after magic packet")
        log.info("DUT turned on after magic packet")

        self.perform_after_wake_up_checks()

    @idparametrize("timeout", [30, 60])
    def test_wake_by_timer(self, timeout):
        """Test for wake by timer"""
        cfg = DrvWakeByTimerConfig()
        cfg.timeout = timeout * 1000

        beton_file = os.path.join(self.test_log_dir, "cfg_wake_by_timer.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        self.hibernate_dut(retry_interval=2, check_early_wake=False)  # Timing is important in this test

        timestamp_before = timeit.default_timer()

        log.info("Sleeping {} seconds".format(timeout - 10))
        time.sleep(timeout - 10)
        if self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online too early: {} sec".format(timeit.default_timer() - timestamp_before))
        log.info("DUT didn't wake up too early. Waiting for DUT to power on for 20 seconds")

        if not self.poll_host_powered_on(self.dut_hostname, timeout=20, retry_interval=2):
            raise Exception("DUT didn't come online after expected timeout {} sec".format(timeout))
        log.info("DUT woke up after {} seconds".format(timeit.default_timer() - timestamp_before))

        self.perform_after_wake_up_checks()

    def test_wake_on_link_no_link(self):
        """Test for wake on link when host is going to sleep without set link"""
        log.info("Setting link DOWN on LKP")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)

        beton = [
            "writereg 0x36c 0x00000000",
            "pause 3 s",
            "writereg 0x36c 0x{:08x}".format(DrvMessage.CAPS_HI_WAKE_ON_LINK)
        ]
        self.dut_atltool_wrapper.exec_beton(beton)

        self.hibernate_dut()

        log.info("Setting link UP on LKP")
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

        log.info("Sleeping {} seconds".format(self.WAKE_ON_LINK_DELAY))
        time.sleep(self.WAKE_ON_LINK_DELAY)

        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link UP")
        log.info("DUT turned on after link UP")

        self.perform_after_wake_up_checks()

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_AUTO])
    def test_wake_on_link_with_link(self, speed):
        """Test for wake on link when host is going to sleep without set link"""
        if self.dut_fw_card in FELICITY_CARDS:
            if speed == LINK_SPEED_AUTO:
                speed = self.supported_speeds[-1]

        if speed != LINK_SPEED_AUTO and speed not in self.supported_speeds:
            pytest.xfail()

        # Set link speed on LKP
        self.lkp_ifconfig.set_link_speed(speed)

        # Before turning on Wake on Link feature we need to make sure that link is up
        log.info("Setting link speed {} on DUT".format(speed))
        beton = [
            "writereg 0x36c 0x00000000",
            "pause 3 s",
            "writereg 0x368 0x{:08x}".format(LINK_SPEED_TO_REG_VAL_MAP_2X[speed])
        ]
        self.dut_atltool_wrapper.exec_beton(beton)

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        log.info("Turning on Wake on Link feature (set LINK_DROP + WAKE_ON_LINK)")
        beton = [
            "writereg 0x036c 0x{:08x}".format(DrvMessage.CAPS_HI_LINK_DROP),
            "pause 2 s",
            "writereg 0x0368 0x00000000",
            "pause 2 s",
            "writereg 0x036c 0x{:08x}".format(DrvMessage.CAPS_HI_WAKE_ON_LINK)
        ]
        self.dut_atltool_wrapper.exec_beton(beton)
        time.sleep(5)  # Let FW detect feature and set sleep proxy speed

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Sleep proxy link {} is up".format(link_speed))

        self.hibernate_dut()

        link_speed = self.lkp_ifconfig.get_link_speed()
        log.info("Sleep proxy link {} is up".format(link_speed))

        log.info("Setting link DOWN - UP on LKP")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        time.sleep(3)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

        log.info("Sleeping {} seconds".format(self.WAKE_ON_LINK_DELAY))
        time.sleep(self.WAKE_ON_LINK_DELAY)

        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link UP")
        log.info("DUT turned on after link UP")

        self.perform_after_wake_up_checks()

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_10G])
    def test_no_link_in_sleep_without_sleep_proxy(self, speed):
        """Verify that FW doesn't set link while host is asleep when sleep proxy is not configured.
        Not applicable for Dirtywake firmware
        """

        # Check for Dirtywake feature
        prov_off = self.dut_atltool_wrapper.readmem(0x1FB10024, 4)[0]
        prov_dw_1 = self.dut_atltool_wrapper.readmem(0x1FB10000 + prov_off, 4)[0]
        if prov_dw_1 & 0x1:
            pytest.skip("Skipping test for Dirtywake firmware")

        if self.dut_fw_card in FELICITY_CARDS:
            if speed == LINK_SPEED_AUTO:
                speed = self.supported_speeds[-1]

        if speed not in self.supported_speeds:
            pytest.xfail()

        # Set link speed on LKP
        self.lkp_ifconfig.set_link_speed(speed)

        log.info("Setting link speed {} on DUT")
        beton = [
            "writereg 0x36c 0x00000000",
            "pause 3 s",
            "writereg 0x0368 0x{:08x}".format(LINK_SPEED_TO_REG_VAL_MAP_2X[speed])
        ]
        self.dut_atltool_wrapper.exec_beton(beton)

        lkp_speed = self.lkp_ifconfig.wait_link_up()
        assert lkp_speed == speed, "DUT didn't set correct link speed. Actual: {}".format(lkp_speed)
        log.info("Link {} is up".format(lkp_speed))

        self.hibernate_dut()

        lkp_speed = self.lkp_ifconfig.get_link_speed()
        assert lkp_speed == LINK_SPEED_NO_LINK, "DUT set {} link in sleep mode without sleep proxy".format(lkp_speed)

        log.info("Turning DUT back on")
        self.bring_host_online(self.dut_hostname)

    def test_empty_offload(self):
        """Test for wake on link when host is going to sleep without set link"""
        if self.dut_fw_card in FELICITY_CARDS:
            speed = self.supported_speeds[-1]
        else:
            speed = LINK_SPEED_AUTO

        # Set link speed on LKP
        self.lkp_ifconfig.set_link_speed(speed)

        # Before turning on Wake on Link feature we need to make sure that link is up
        log.info("Setting link speed {} on DUT".format(speed))
        beton = [
            "writereg 0x36c 0x00000000",
            "pause 3 s",
            "writereg 0x0368 0x{:08x}".format(LINK_SPEED_TO_REG_VAL_MAP_2X[speed])
        ]
        self.dut_atltool_wrapper.exec_beton(beton)

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        log.info("Applying empty offload structure to FW and turning on Wake on Link")
        # Prepare offload structure where all offsets are 0 (empty structure)
        # Can't use DrvMessage from drv_iface_cfg.py since DrvMessage automatically sets correct offsets
        data = [
            0x00000005, 0x00000000, 0x00000054, 0x00b61700, 0x00008207, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
        ]
        beton = [
            "writereg 0x36c 0x{:08x}".format(DrvMessage.CAPS_HI_LINK_DROP),
            "pause 3 s",
            "writereg 0x368 0x00000000"
        ]
        self.dut_atltool_wrapper.exec_beton(beton)
        self.dut_atltool_wrapper.dump_to_config_memory(data)
        beton = [
            "writereg 0x36c 0x{:08x}".format(DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WAKE_ON_LINK)
        ]
        self.dut_atltool_wrapper.exec_beton(beton)
        time.sleep(5)  # Let FW detect feature and set sleep proxy speed

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Sleep proxy link {} is up".format(link_speed))

        self.hibernate_dut()

        link_speed = self.lkp_ifconfig.get_link_speed()
        log.info("Sleep proxy link {} is up".format(link_speed))

        log.info("Setting link DOWN - UP on LKP")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        time.sleep(3)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

        log.info("Sleeping {} seconds".format(self.WAKE_ON_LINK_DELAY))
        time.sleep(self.WAKE_ON_LINK_DELAY)

        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link UP")
        log.info("DUT turned on after link UP")

        self.perform_after_wake_up_checks()

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_link_reset_after_wake_on_link(self, speed):
        """
        @description: Verify that FW restores link speed that was set before enabling WoL. Applicable for FW 3.x only.

        @steps:
        1. Enable WOL_EX_WAKE_ON_LINK_KEEP_RATE FW setting.
        2. Set link speed to *speed*. Wait for it to go up.
        3. Configure WoL (link up) via FW high caps. Check that link speed is preserved.
        4. Do link down-up on LKP.
        5. Check link speed.

        @result: FW restores original link speed upon waking the PC.
        @duration: 1 minute.
        """
        if self.dut_fw_ver_maj != 3:
            pytest.skip()

        if speed not in self.supported_speeds:
            pytest.skip()

        # Enable WOL_EX_WAKE_ON_LINK_KEEP_RATE setting
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.WOL_EX_OFS,
                                   FWSettings.WolEx.WAKE_ON_LINK_KEEP_RATE)

        # Set link speed
        if self.lkp_fw_card not in FELICITY_CARDS:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        else:
            self.lkp_ifconfig.set_link_speed(speed)

        self.dut_atltool_wrapper.writereg(0x368, LINK_SPEED_TO_REG_VAL_MAP_2X[speed])

        link_speed = self.lkp_ifconfig.wait_link_up()
        assert link_speed == speed, "Wrong link speed at the beginning of the test: {}".format(link_speed)

        # Configure Wake on Link
        self.dut_atltool_wrapper.set_link_control_2x(DrvMessage.CAPS_HI_LINK_DROP)
        self.lkp_ifconfig.wait_link_down()
        self.dut_atltool_wrapper.set_link_control_2x(DrvMessage.CAPS_HI_WAKE_ON_LINK)

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Sleep proxy link {} is up".format(link_speed))

        self.hibernate_dut()

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Sleep proxy link {} is up".format(link_speed))

        log.info("Setting link DOWN - UP on LKP")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        time.sleep(3)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

        link_speed = self.lkp_ifconfig.wait_link_up()
        assert link_speed == speed, "FW didn't restore original link speed before waking the PC"

        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link UP")
        log.info("DUT turned on after link UP")

        self.perform_after_wake_up_checks()

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_link_reset_after_wol_magic_and_on_link(self, speed):
        """
        @description: Verify that FW restores link speed before waking the PC that was set before enabling WoL.
        Wake on magic packet and wake on link are enabled at the same time. Applicable for FW 3.x only.

        @steps:
        1. Enable WOL_EX_WAKE_ON_MAGIC_RESTORE_RATE and WOL_EX_WAKE_ON_LINK_KEEP_RATE FW setting.
        2. Set link speed to *speed*. Wait for it to go up.
        3. Configure WoL (magic packet + link up). Check that link speed is minimal available (because wake on magic
        packet is enabled).
        4. Send magic packet
        5. Check link speed.

        @result: FW restores original link speed upon waking the PC.
        @duration: 1 minute.
        """
        if self.dut_fw_ver_maj != 3:
            pytest.skip()

        if speed not in self.supported_speeds:
            pytest.skip()

        # Enable WOL_EX_WAKE_ON_MAGIC_RESTORE_RATE and WOL_EX_WAKE_ON_LINK_KEEP_RATE settings
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.WOL_EX_OFS,
                                   FWSettings.WolEx.WAKE_ON_MAGIC_RESTORE_RATE |
                                   FWSettings.WolEx.WAKE_ON_LINK_KEEP_RATE)

        # Set link speed
        if self.lkp_fw_card not in FELICITY_CARDS:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        else:
            self.lkp_ifconfig.set_link_speed(speed)

        self.dut_atltool_wrapper.writereg(0x368, LINK_SPEED_TO_REG_VAL_MAP_2X[speed])

        link_speed = self.lkp_ifconfig.wait_link_up()
        assert link_speed == speed, "Wrong link speed at the beginning of the test: {}".format(link_speed)

        # Configure WoL
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407
        cfg.mac = TestWakeOnLan.DUT_MAC
        cfg.ips = OffloadIpInfo()
        cfg.caps = DrvEthConfig.CAPS_HI_LINK_DROP
        cfg.apply(self.dut_atltool_wrapper)

        self.lkp_ifconfig.wait_link_down()

        self.dut_atltool_wrapper.set_link_control_2x(DrvMessage.CAPS_HI_WAKE_ON_LINK | DrvMessage.CAPS_HI_WOL |
                                                     DrvMessage.CAPS_HI_SLEEP_PROXY)

        link_speed = self.lkp_ifconfig.wait_link_up()
        if self.dut_fw_card not in FELICITY_CARDS:
            assert link_speed == LINK_SPEED_100M, "DUT didn't setup 100 Mb/s. Current link speed is {}".format(
                link_speed)
            log.info("DUT set up 100 Mb/s link speed")

        self.hibernate_dut()

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Sleep proxy link {} is up".format(link_speed))

        log.info("Setting magic packet from LKP")
        self.lkp_scapy_tools.send_raw_magic_packet(self.DUT_MAC)

        link_speed = self.lkp_ifconfig.wait_link_up()
        assert link_speed == speed, "FW didn't restore original link speed before waking the PC"

        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link UP")
        log.info("DUT turned on after link UP")

        self.perform_after_wake_up_checks()


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
