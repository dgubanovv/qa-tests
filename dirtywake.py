"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import tempfile
import time

import pytest
import shutil

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_100M, LINK_SPEED_AUTO, LINK_STATE_UP, LINK_STATE_DOWN, \
    CARD_FELICITY_KR, CARD_FELICITY_EUROPA, CARD_FELICITY, LINK_SPEED_10G, LINK_SPEED_NO_LINK
from tools.command import Command
from tools.driver import Driver
from tools.ops import OpSystem
from tools.power import Power
from tools.scapy_tools import ScapyTools
from tools.utils import get_atf_logger

from infra.test_base import TestBase, idparametrize

log = get_atf_logger()


def setup_module(module):
    #import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "wol_dirtywake"


class TestDirtyWake(TestBase):
    """
    @description: The dirty wake test is dedicated to check wol from cold shutdown.

    @setup: Two AQC devices connected back to back.
    """

    AFTER_TURNOFF_DELAY = 30
    BEFORE_PING_DELAY = 10

    WAKE_ON_LINK_DELAY = 20  # set in driver
    PING_COUNT = 4
    WOL_SPEED = LINK_SPEED_100M

    PRVT_NW_CMD = "powershell -command \"& {&'Set-NetConnectionProfile' -NetworkCategory Private}\""

    @classmethod
    def setup_class(cls):
        super(TestDirtyWake, cls).setup_class()
        if cls.dut_fw_card in [CARD_FELICITY_KR, CARD_FELICITY_EUROPA, CARD_FELICITY]:
            cls.WOL_SPEED = LINK_SPEED_10G
            log.info("Setting WOL speed to 10G for Felicity")
        else:
            log.info("Leave WOL speed as 100M")

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port, cls.dut_hostname)
            cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port)
            cls.NETMASK_IPV4 = "255.255.0.0"

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            cls.dut_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.normal_speed = cls.lkp_ifconfig.wait_link_up()

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port)

            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.dut_power = Power(host=cls.dut_hostname)
            cls.dut_ops = OpSystem(host=cls.dut_hostname)

            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestDirtyWake, self).setup_method(method)
        if not self.is_host_alive_and_ready(self.dut_hostname):
            raise Exception("DUT is not online, can't perform test")

        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(True, 'remote_mcp.bin')
            self.bin_log_file, self.txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestDirtyWake, self).teardown_method(method)

        self.bring_host_online(self.dut_hostname)

        if self.MCP_LOG:
            if hasattr(self, 'wol_state') and self.wol_state == 'shutdown':
                self.dut_atltool_wrapper.debug_buffer_enable(True, 'remote_mcp.bin')
                time.sleep(5)
                self.dut_atltool_wrapper.debug_buffer_enable(True, 'remote_mcp.bin')
                time.sleep(5)

            self.dut_bin_log_file, self.dut_txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.dut_bin_log_file, self.test_log_dir)
            shutil.copy(self.dut_txt_log_file, self.test_log_dir)

            self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

    def dirty_shutdown_dut(self):
        self.power_off(host=self.dut_hostname)
        if not self.poll_host_powered_off(self.dut_hostname):
            raise Exception("Couldn't turn off DUT")

    def dut_check_wol_speed(self):
        speed = self.lkp_ifconfig.get_link_speed()
        if self.dut_fw_card in [CARD_FELICITY_KR, CARD_FELICITY_EUROPA, CARD_FELICITY]:
            assert speed != LINK_SPEED_NO_LINK, "DUT didn't setup any link"
            log.info("DUT card is Felicity. {} link speed is set".format(speed))
        else:
            assert speed == self.WOL_SPEED, "DUT didn't setup 100 Mb/s. Current link speed is {}".format(speed)
            log.info("DUT set up 100 Mb/s link speed")

    def perform_after_wake_up_checks(self):
        if self.dut_ops.is_linux():
            self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.NETMASK_IPV4, None)
            self.dut_ifconfig.set_link_speed(LINK_SPEED_AUTO)

        actual_speed = self.lkp_ifconfig.wait_link_up()
        assert self.normal_speed == actual_speed, "DUT didn't set up expected link after wake up"
        log.info("Link speed is correct: {}".format(actual_speed))

        log.info("Waiting until agent on DUT is started")
        if not self.poll_host_alive_and_ready(self.dut_hostname, self.POWER_UP_TIMEOUT):
            log.warning("Agent on DUT is not started after WoL DirtyWake test")

        time.sleep(self.BEFORE_PING_DELAY)
        if not self.ping("localhost", self.DUT_IPV4_ADDR, self.PING_COUNT):
            raise Exception("DUT didn't answer on ping after test")

    def test_dirtywake_on_magic_packet(self):
        """
        @description: Check that pc wakes from magic packet after cold shutdown (dirty wake).
        """
        self.dirty_shutdown_dut()

        # Make sure DUT didn't come online after turning off
        time.sleep(self.AFTER_TURNOFF_DELAY)
        if self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")

        self.dut_check_wol_speed()

        log.info("Sending magic packet")
        self.lkp_ifconfig.set_arp(self.DUT_IPV4_ADDR, self.dut_mac)
        self.lkp_scapy_tools.send_raw_magic_packet(self.dut_mac)

        time.sleep(self.LED_TIMEOUT)
        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after magic packet")

        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back from cold shutdown state after magic packet")
        log.info("DUT woke up after magic packet")

        self.perform_after_wake_up_checks()


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
