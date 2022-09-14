"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import time
import sys
import timeit

import pytest
import shutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.atltoolper import AtlTool
from tools.constants import LINK_STATE_UP
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.scapy_tools import ScapyTools
from tools.power import Power
from tools.utils import get_atf_logger
from tools.ifconfig import LINK_SPEED_NO_LINK, LINK_STATE_DOWN, LINK_SPEED_AUTO, LINK_SPEED_100M, \
    LINK_SPEED_1G, LINK_SPEED_10G, LINK_SPEED_2_5G, LINK_SPEED_5G
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config, SleepProxyOffload, WAKE_REASON_MAGIC_PACKET, \
    WAKE_REASON_TIMER, WAKE_REASON_LINK
from tools.fw_a2_drv_iface_structures import HOST_MODE_ACTIVE
from infra.test_base import TestBase, idparametrize

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_wake_on_lan"


class TestWakeOnLan(TestBase):
    AFTER_TURNOFF_DELAY = 30
    WAKE_ON_LINK_DELAY = 15
    WOL_LINK_DELAY = 10
    WAKE_COUNTER_DELAY = 1
    DUT_MAC_ADDR = "00:17:B6:01:02:03"

    LKP_IP4_ADDR = "192.168.0.2"
    NETMASK_IPV4 = "255.255.255.0"
    MULTICAST_IPV4 = "192.168.0.255"

    LKP_IP6_ADDR = "4000:0000:0000:0000:1601:bd17:0c02:2402"
    PREFIX_IPV6 = "64"

    @classmethod
    def setup_class(cls):
        super(TestWakeOnLan, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", drv_type=DRV_TYPE_DIAG, host=cls.dut_hostname)
            cls.dut_driver.install()
            cls.dut_power = Power(host=cls.dut_hostname)
            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.dut_fw_config = FirmwareA2Config(cls.dut_atltool_wrapper)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.lkp_driver.install()
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6_ADDR, cls.PREFIX_IPV6, None)
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            cls.lkp_mac_addr = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestWakeOnLan, self).setup_method(method)
        for i in range(3):
            if self.is_host_alive_and_ready(self.dut_hostname):
                break
            time.sleep(5)
        else:
            raise Exception("DUT is not online, can't perform test")
        self.dut_atltool_wrapper.kickstart2()

    def teardown_method(self, method):
        super(TestWakeOnLan, self).teardown_method(method)
        self.bring_host_online(self.dut_hostname)
        self.dut_power.hibernate_off()
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

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

    def test_wake_by_magic_packet(self):
        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_magic_packet = True
        self.dut_fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        log.info("Sleep proxy has been configured")

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Sleep proxy link {} is up".format(link_speed))

        wol_status = self.dut_fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        log.info(wol_status.wakeCount)
        self.hibernate_dut()

        assert self.lkp_ifconfig.wait_link_up() != LINK_SPEED_NO_LINK, "DUT dropped link after hibernation"

        log.info("Sending magic packet")
        self.lkp_scapy_tools.send_raw_magic_packet(self.DUT_MAC_ADDR)

        time.sleep(self.LED_TIMEOUT)
        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after magic packet")
        log.info("DUT turned on after magic packet")

        self.perform_after_wake_up_checks()

    @idparametrize("timeout", [30, 60])
    def test_wake_by_timer(self, timeout):
        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_timer = True
        sp_cfg.wake_on_lan.timer = timeout * 1000
        self.dut_fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        log.info("Sleep proxy has been configured")

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Sleep proxy link {} is up".format(link_speed))

        wol_status = self.dut_fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        log.info(wol_status.wakeCount)
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

    def test_wake_on_link_up_no_link(self):
        log.info("Setting link DOWN on LKP")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)

        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_link_up = True
        sp_cfg.wake_on_lan.link_up_timeout = self.WOL_LINK_DELAY * 1000
        self.dut_fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        log.info("Sleep proxy has been configured")

        self.hibernate_dut()

        # Wait 20 second. It is link up stabilization timeout in Sleep mode.
        log.info("Sleeping {} seconds".format(20))
        time.sleep(20)
        log.info("Setting link UP on LKP")
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.wait_link_up()

        log.info("Sleeping {} seconds".format(self.WAKE_ON_LINK_DELAY))
        time.sleep(self.WAKE_ON_LINK_DELAY)

        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link UP")
        log.info("DUT turned on after link UP")

        self.perform_after_wake_up_checks()

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_AUTO])
    def test_wake_on_link_down_with_link(self, speed):
        log.info("Setting link {} on LKP".format(speed))
        self.lkp_ifconfig.set_link_speed(speed)

        self.dut_fw_config.set_link_state(LINK_STATE_UP)
        self.dut_fw_config.set_link_speed(speed)
        self.dut_fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()

        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_link_down = True
        sp_cfg.wake_on_lan.link_down_timeout = self.WOL_LINK_DELAY * 1000
        self.dut_fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        log.info("Sleep proxy has been configured")

        self.hibernate_dut()

        self.lkp_ifconfig.wait_link_up()
        # Wait 20 second. It is link up stabilization timeout in Sleep mode.
        log.info("Sleeping {} seconds".format(20))
        time.sleep(20)
        log.info("Setting link DOWN - UP on LKP")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)

        log.info("Sleeping {} seconds".format(self.WAKE_ON_LINK_DELAY))
        time.sleep(self.WAKE_ON_LINK_DELAY - 3)

        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link UP")
        log.info("DUT turned on after link UP")

        self.perform_after_wake_up_checks()

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_10G])
    def test_no_link_in_sleep_without_sleep_proxy(self, speed):
        """Verify that FW doesn't set link while host is asleep when sleep proxy is not configured.
        Not applicable for Dirtywake firmware
        """

        # TODO: Add check for Dirtywake feature. Not applicable for Dirtywake firmware

        log.info("Setting link {} on LKP".format(speed))
        self.lkp_ifconfig.set_link_speed(speed)

        self.dut_fw_config.set_link_state(LINK_STATE_UP)
        self.dut_fw_config.set_link_speed(LINK_SPEED_AUTO)
        self.dut_fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()

        self.hibernate_dut()

        lkp_speed = self.lkp_ifconfig.get_link_speed()
        assert lkp_speed == LINK_SPEED_NO_LINK, "DUT set {} link in sleep mode without sleep proxy".format(lkp_speed)

        log.info("Turning DUT back on")
        self.bring_host_online(self.dut_hostname)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
