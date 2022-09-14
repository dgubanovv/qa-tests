"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import sys
import time

import pytest
import shutil
import random

from tools.atltoolper import AtlTool
from tools.aq_wmi import Aq_UsbNetAdapter
from tools.constants import LINK_SPEED_100M, LINK_SPEED_AUTO, LINK_STATE_UP, LINK_STATE_DOWN, \
    FELICITY_CARDS, CARD_FIJI, LINK_SPEED_10G, LINK_SPEED_NO_LINK, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_1G
from tools.command import Command
from tools.driver import Driver
from tools.ops import OpSystem
from tools.power import Power
from tools.scapy_tools import ScapyTools
from tools.utils import get_atf_logger, upload_file, download_file
from tools.uart import Uart
from infra.test_base import TestBase, idparametrize

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "wol"


class WoLTestBase(TestBase):
    AFTER_TURNOFF_DELAY = 30
    BEFORE_PING_DELAY = 10

    WAKE_ON_LINK_DELAY = 20  # set in driver
    PING_COUNT = 4
    WOL_SPEED = LINK_SPEED_100M

    DUT_IP = "192.168.0.3"
    LKP_IP = "192.168.0.2"
    NETMASK = "255.255.255.0"
    GATEWAY = "192.168.0.1"

    PRVT_NW_CMD = "powershell -command \"& {&'Set-NetConnectionProfile' -NetworkCategory Private}\""

    UBUNTU_IFACE_CFG = r"auto {0}\niface {0} inet static\naddress {1}\nnetmask {2}\n"
    RHEL_IFACE_CFG = r"DEVICE={}\nONBOOT=yes\nIPADDR={}\nNETMASK={}\n"
    DHCP_LEASE_RENEW_SCRIPT = r"#!/bin/bash\nsudo ifdown {0}; sudo ifup {0}\n"

    @classmethod
    def setup_class(cls):
        super(WoLTestBase, cls).setup_class()
        if cls.dut_fw_card in FELICITY_CARDS:
            cls.WOL_SPEED = LINK_SPEED_10G
            log.info("Setting WOL speed to 10G for Felicity")
        else:
            log.info("Leave WOL speed as 100M")

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.dut_power = Power(host=cls.dut_hostname)
            cls.dut_ops = OpSystem(host=cls.dut_hostname)

            cls.install_firmwares()

            if cls.dut_fw_card == CARD_FIJI:
                if cls.dut_ops.is_centos() or cls.dut_ops.is_rhel():
                    log.info("Configuring CDC interface on DUT")
                    cls.cfg_dut_iface_rhel()
            if cls.dut_fw_card not in CARD_FIJI:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            if cls.lkp_fw_card not in CARD_FIJI:
                cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            if cls.dut_fw_card not in CARD_FIJI and cls.dut_atltool_wrapper.is_secure_chips() and cls.dut_ops.is_linux():
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, flashless_fw=cls.dut_fw_version, host=cls.dut_hostname)
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            if cls.dut_ops.is_linux():
                log.info("Rebooting DUT to apply DHCP lease settings")
                cls.dut_power.reboot()
                time.sleep(30)
                if not cls.poll_host_alive_and_ready(cls.dut_hostname, 120):
                    raise Exception("Failed to reboot DUT")
                log.info("Creating script on DUT to update DHCP lease on DUT after hibernate")
                cls.create_dhcp_script_on_dut()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IP, cls.NETMASK, cls.LKP_IP)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, cls.GATEWAY)

            if cls.dut_fw_card == CARD_FIJI and cls.dut_ops.is_linux():
                log.info("Changing module from CDC to AQC111 on DUT")
                Command(cmd="sudo usb_modeswitch -v 0x2eca -p 0xc101 -u 1", host=cls.dut_hostname).run_join(10)

            cls.dut_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.normal_speed = cls.lkp_ifconfig.wait_link_up()

            if cls.MCP_LOG and cls.dut_fw_card == CARD_FIJI:
                # Create UART always on LKP
                cls.dut_uart = Uart()

            # Upload files to up interface on DUT
            if cls.dut_ops.is_ubuntu():
                cls.cfg_dut_iface_ubuntu()
            elif cls.dut_ops.is_centos() or cls.dut_ops.is_rhel():
                cls.cfg_dut_iface_rhel()

            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port)

            # Disable WOL on LKP to avoid problem with link down on Linux
            cls.lkp_ifconfig.set_power_mgmt_settings(False, False, False)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(WoLTestBase, cls).teardown_class()
        # Delete created files from DUT and LKP
        if cls.dut_ops.is_linux():
            Command(cmd="sudo rm -rf /lib/systemd/system-sleep/renew_dhcp_lease", host=cls.dut_hostname).run_join(10)

            if cls.dut_ops.is_ubuntu():
                Command(cmd="sudo cp ~/original_iface_file.txt /etc/network/interfaces",
                        host=cls.dut_hostname).run_join(10)
            elif cls.dut_ops.is_centos() or cls.dut_ops.is_rhel():
                Command(cmd="sudo rm -rf /etc/sysconfig/network-scripts/ifcfg-{}".format(
                    cls.dut_ifconfig.get_conn_name()), host=cls.dut_hostname).run_join(10)

    def setup_method(self, method):
        super(WoLTestBase, self).setup_method(method)
        if not self.is_host_alive_and_ready(self.dut_hostname):
            raise Exception("DUT is not online, can't perform test")

        if self.MCP_LOG:
            if self.dut_fw_card == CARD_FIJI:
                self.dut_uart.run_async()
            else:
                self.dut_atltool_wrapper.debug_buffer_enable(True, 'remote_mcp.bin')

        # Enable on_magic=True by default for Fiji driver
        if self.dut_fw_card == CARD_FIJI:
            self.cable_plug()
            self.dut_set_wol_settings(on_magic=True)

    def teardown_method(self, method):
        super(WoLTestBase, self).teardown_method(method)

        self.bring_host_online(self.dut_hostname)
        if not self.dut_ops.is_linux():
            self.dut_power.hibernate_off()

        if self.MCP_LOG:
            if self.dut_fw_card == CARD_FIJI:
                log = self.dut_uart.join()
                if len(log) > 0:
                    log_file = "uart.txt"
                    with open(log_file, "w") as f:
                        f.write("\n".join(line for line in log))

                    shutil.move(log_file, self.test_log_dir)
            else:
                if hasattr(self, 'wol_state') and self.wol_state == 'shutdown':
                    self.dut_atltool_wrapper.debug_buffer_enable(True, 'remote_mcp.bin')
                    time.sleep(5)
                    self.dut_atltool_wrapper.debug_buffer_enable(True, 'remote_mcp.bin')
                    time.sleep(5)

                self.dut_bin_log_file, self.dut_txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(False)
                shutil.copy(self.dut_bin_log_file, self.test_log_dir)
                shutil.copy(self.dut_txt_log_file, self.test_log_dir)

    @classmethod
    def cfg_dut_iface_ubuntu(cls):
        Command(cmd="sudo cp /etc/network/interfaces ~/original_iface_file.txt", host=cls.dut_hostname).run_join(10)
        Command(cmd="sudo sh -c 'printf \"{}\" >> /etc/network/interfaces'".format(
            cls.UBUNTU_IFACE_CFG.format(cls.dut_ifconfig.get_conn_name(), cls.DUT_IP, cls.NETMASK)),
            host=cls.dut_hostname).run_join(10)

    @classmethod
    def cfg_dut_iface_rhel(cls):
        conn_name = cls.dut_ifconfig.get_conn_name()
        Command(cmd="sudo sh -c 'printf \"{}\" > /etc/sysconfig/network-scripts/ifcfg-{}'".format(
            cls.RHEL_IFACE_CFG.format(conn_name, cls.DUT_IP, cls.NETMASK), conn_name),
            host=cls.dut_hostname).run_join(10)

    @classmethod
    def create_dhcp_script_on_dut(cls):
        res = Command(cmd="sudo route | grep default | awk '{print $8}'", host=cls.dut_hostname).run_join(10)
        Command(cmd="sudo printf \"{}\" > /tmp/renew_dhcp_lease".format(
            cls.DHCP_LEASE_RENEW_SCRIPT.format(res["output"][0])), host=cls.dut_hostname).run_join(10)
        Command(cmd="sudo install -m 777 -T /tmp/renew_dhcp_lease /lib/systemd/system-sleep/renew_dhcp_lease",
                host=cls.dut_hostname).run_join(10)

    def cable_unplug(self):
        log.info("Unplugging cable by setting link state DOWN on LKP")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        log.info("Cable has been unplugged")

    def cable_plug(self):
        log.info("Plugging cable by setting link state UP on LKP")
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        log.info("Cable has been plugged")

    def turn_off_dut(self, action):
        if action == "hibernate":
            self.dut_power.hibernate()
        elif action == "shutdown":
            self.dut_power.shutdown()
        elif action == "suspend":
            self.dut_power.suspend()
        else:
            raise Exception("Got wrong action type: {}".format(action))
        if not self.poll_host_powered_off(self.dut_hostname):
            raise Exception("Couldn't turn off DUT")

    def dut_check_wol_speed(self):
        speed = self.lkp_ifconfig.get_link_speed()
        if self.dut_fw_card in FELICITY_CARDS + [CARD_FIJI]:
            assert speed != LINK_SPEED_NO_LINK, "DUT didn't setup any link"
            log.info("DUT card is Felicity or Fiji. {} link speed is set".format(speed))
        else:
            assert speed == self.WOL_SPEED, "DUT didn't setup 100 Mb/s. Current link speed is {}".format(speed)
            log.info("DUT set up 100 Mb/s link speed")

    def dut_set_wol_settings(self, on_magic=False, on_pattern=False, on_ping=False, on_link=False,
                             from_power_off=False):

        self.dut_ifconfig.set_wol_settings(on_magic=on_magic, on_pattern=on_pattern, on_ping=on_ping, on_link=on_link,
                             from_power_off=from_power_off)

        if self.dut_ops.is_windows():
            self.dut_ifconfig.set_advanced_property("Downshift", "Disable")
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.lkp_ifconfig.wait_link_up(retry_interval=2)

        if "win7" not in self.dut_ops.get_name().lower() and not self.dut_ops.is_linux():
            res = Command(cmd=self.PRVT_NW_CMD, host=self.dut_hostname).run()
            assert res["returncode"] == 0, "Couldn't set network to private on DUT"

    def perform_after_wake_up_checks(self, state=None):
        if self.dut_ops.is_linux() and self.dut_fw_card == CARD_FIJI:
            # This modeswitch is need to apply aqc111 back instead of cdc_ether driver
            Command(cmd="sudo usb_modeswitch -v 0x2eca -p 0xc101 -u 1", host=self.dut_hostname).run_join(10)
            self.normal_speed = LINK_SPEED_5G
        if (self.dut_ops.is_centos() | self.dut_ops.is_rhel()) and self.dut_fw_card == CARD_FIJI:
            # TODO: Fix it via linux kernel files for USB
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.dut_ifconfig.set_ip_address(self.DUT_IP, self.NETMASK, self.LKP_IP)
        actual_speed = self.lkp_ifconfig.wait_link_up()

        # linux no network configure files after reboot on, so after reboot speed = AUTO speed
        if not self.dut_ops.is_linux() or ("forwarding" in self.dut_drv_version and state != "shutdown"):
            assert self.normal_speed == actual_speed, "DUT didn't set up expected link after wake up"
            log.info("Link speed is correct: {}".format(actual_speed))

        log.info("Waiting until agent on DUT is started")
        if not self.poll_host_alive_and_ready(self.dut_hostname, self.POWER_UP_TIMEOUT):
            log.warning("Agent on DUT is not started after WoL test")

        time.sleep(self.BEFORE_PING_DELAY)
        if not self.ping("localhost", self.DUT_IP, self.PING_COUNT):
            if self.dut_fw_card == CARD_FIJI:
                def retry_ping():
                    time.sleep(2)
                    self.lkp_ifconfig.wait_link_up()
                    return self.ping("localhost", self.DUT_IP, self.PING_COUNT)

                log.info("Datapath stuck detected, trying soft datapath reset")
                aq_usb = Aq_UsbNetAdapter(host=self.dut_hostname)
                aq_usb.datapath_soft_reset()
                if retry_ping():
                    raise AssertionError("Soft datapath helped to restore datapath stuck")
                else:
                    log.info("Soft datapath reset didn't help, trying hard reset")
                    aq_usb.datapath_hard_reset()
                    if retry_ping():
                        raise AssertionError("Hard datapath helped to restore datapath stuck")
                    else:
                        log.info("Neither soft nor hard datapath reset helped, trying serdes restart")
                        aq_usb.RestartSerdes()
                        if retry_ping():
                            raise AssertionError("Serdes restart helped to restore datapath")
            raise Exception("DUT didn't answer on ping after test")


class TestWolStressRandom(WoLTestBase):
    def test_wake_on_lan_stress(self):
        for i in range(50):
            action = random.choice(["on_magic_packet", "on_pattern", "on_link"])
            log.info("{:#<78}".format(""))
            log.info("{:#<78}".format("Iteration: {} ".format(i)))
            log.info("{:#<78}".format("Action for wake: {} ".format(action)))
            log.info("{:#<78}".format(""))

            if action == "on_magic_packet":
                self.dut_set_wol_settings(True, False, False)
                self.dut_ifconfig.set_power_mgmt_settings(True, True, True)

                time.sleep(2)
                self.dut_power.hibernate()
                time.sleep(self.AFTER_TURNOFF_DELAY)

                log.info("Check if DUT is sleeping")
                if self.is_host_powered_on(self.dut_hostname):
                    raise Exception("DUT came back online spuriously before test")

                self.dut_check_wol_speed()

                log.info("Sending magic packet")
                self.lkp_ifconfig.set_arp(self.DUT_IPV4_ADDR, self.dut_mac)
                self.lkp_scapy_tools.send_raw_magic_packet(self.dut_mac)
            elif action == "on_pattern":
                self.dut_set_wol_settings(False, True, False)
                self.dut_ifconfig.set_power_mgmt_settings(False, True, True)

                time.sleep(2)
                self.dut_power.hibernate()
                time.sleep(self.AFTER_TURNOFF_DELAY)

                log.info("Check if DUT is sleeping")
                if self.is_host_powered_on(self.dut_hostname):
                    raise Exception("DUT came back online spuriously before test")

                self.dut_check_wol_speed()

                log.info("Sending TCP SYN from LKP (port 22)")
                self.lkp_scapy_tools.wake_on_port(self.DUT_IP, self.LKP_IP, self.dut_mac, 22, "tcp")
            else:
                self.dut_set_wol_settings(on_magic=True, on_link=True)
                self.dut_ifconfig.set_power_mgmt_settings(False, True, True)
                self.cable_unplug()

                time.sleep(2)
                self.dut_power.hibernate()
                time.sleep(self.AFTER_TURNOFF_DELAY)

                log.info("Check if DUT is sleeping")
                if self.is_host_powered_on(self.dut_hostname):
                    raise Exception("DUT came back online spuriously before test")

                self.cable_plug()
                log.info("DUT should start waking up in {} seconds after link plug".format(self.WAKE_ON_LINK_DELAY))
                log.info("Sleeping {} seconds".format(self.WAKE_ON_LINK_DELAY))
                time.sleep(self.WAKE_ON_LINK_DELAY)

            time.sleep(self.LED_TIMEOUT)
            if not self.is_host_powered_on(self.dut_hostname):
                raise Exception("DUT didn't light up power LED wake action '{}'".format(action))

            if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
                raise Exception("DUT didn't come back from sleep after action '{}'".format(action))
            log.info("DUT woke up after wake action")

            self.perform_after_wake_up_checks()


class TestWoLStressMPOnly(WoLTestBase):
    def test_wake_on_magic_only_stress(self):
        for i in range(50):
            log.info("{:#<78}".format(""))
            log.info("{:#<78}".format("Iteration: {} ".format(i)))
            log.info("{:#<78}".format(""))

            if self.dut_ops.is_rhel():
                pytest.skip("RHEL could not be hibernated with LOM connected")

            self.dut_ifconfig.set_power_mgmt_settings(True, True, True)
            self.dut_set_wol_settings(on_magic=True, from_power_off=True)

            time.sleep(2)
            self.dut_power.hibernate()

            # Make sure DUT didn't come online after turning off
            time.sleep(self.AFTER_TURNOFF_DELAY)
            log.info("Check if DUT is sleeping")
            if self.is_host_powered_on(self.dut_hostname):
                raise Exception("DUT came back online spuriously before test")

            self.dut_check_wol_speed()

            log.info("Sending magic packet")
            self.lkp_ifconfig.set_arp(self.DUT_IPV4_ADDR, self.dut_mac)
            self.lkp_scapy_tools.send_raw_magic_packet(self.dut_mac)

            time.sleep(self.LED_TIMEOUT)
            if not self.is_host_powered_on(self.dut_hostname):
                raise Exception("DUT didn't light up power LED wake action '{}'".format('on_magic_packet'))

            if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
                raise Exception("DUT didn't come back from sleep after action '{}'".format('on_magic_packet'))
            log.info("DUT woke up after wake action")

            self.perform_after_wake_up_checks()


class TestWoLBasic(WoLTestBase):
    """
    @description: The TestWoLBasic test is dedicated to verify wake on lan.

    @setup: Two Aquantia devices connected back to back.
    """
    @idparametrize("state", ["hibernate", "shutdown", "suspend"])
    def test_check_wol_with_link_down(self, state):
        """
        @description: Check wake on link from different states ("hibernate", "shutdown", "suspend").
        Condition: link is down before shutting down DUT.

        @steps:
        1. For each action in ["hibernate", "shutdown", "suspend"]:
            a. Configure power management setting.
            b. Configure wol settings: wake on lan enabled, from power off state enabled, wake on magic packet enabled.
            c. Set link down on LKP.
            d. Execute action on DUT.
            e. Set link UP on LKP.
            f. Make sure that DUT wake up.

        @result: DUT wakes up due to link up.
        @duration: 5 minutes.
        """
        if state == "hibernate" and self.dut_ops.is_rhel():
            pytest.skip("RHEL could not be hibernated with LOM connected")
        if self.dut_ops.is_freebsd():
            pytest.skip("Free bsd driver doesn't support wake on plug")

        if state == "suspend" and not self.suspend_enabled:
            pytest.skip("Skip test due suspend is not support by motherboard")

        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Skip for Fiji ")

        assert state in ["hibernate", "shutdown", "suspend"]
        self.wol_state = state

        self.dut_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.wait_link_up()

        self.dut_ifconfig.set_power_mgmt_settings(False, True, True)
        self.dut_set_wol_settings(on_link=True, from_power_off=True, on_magic=True)
        self.lkp_ifconfig.set_link_down()

        self.turn_off_dut(state)

        # Make sure DUT didn't come online after turning off
        time.sleep(self.AFTER_TURNOFF_DELAY)
        if state != "suspend" and self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        if state == "suspend" and self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.wait_link_up()
        # Need it to add here self.perform_after_wake_up_checks(state=state)?

    @idparametrize("state", ["hibernate", "shutdown", "suspend"])
    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_wake_on_link_with_wake_on_mp_from_state(self, state, speed):
        """
        @description: Check wake on link from different states ("hibernate", "shutdown", "suspend").
        Condition: wake on magic packet enabled.

        @steps:
        1. For each action in ["hibernate", "shutdown", "suspend"] and for link speed in
        [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]:
            a. Configure power management setting.
            b. Configure wol settings: wake on lan enabled, from power off state enabled, wake on magic packet enabled.
            c. Execute action on DUT.
            d. Make link down and then link up on LKP.
            e. Make sure that DUT wake up.
            f. Run ping from DUT to LKP.

        @result: DUT wakes up due to link flapping, datapath is OK after wake up.
        @duration: 20 minutes.
        """
        if state == "hibernate" and self.dut_ops.is_rhel():
            pytest.skip("RHEL could not be hibernated with LOM connected")
        if self.dut_ops.is_freebsd():
            pytest.skip("Free bsd driver doesn't support wake on plug")

        if state == "suspend" and not self.suspend_enabled:
            pytest.skip("Skip test due suspend is not support by motherboard")

        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Skip for Fiji ")

        if self.dut_fw_card in FELICITY_CARDS:
            if "DAC" in self.sfp and speed in [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G] and self.supported_speeds[-1] == LINK_SPEED_10G:
                pytest.skip("Skip for Dac cable can not 2.5G and 5G link up when autoneg on LKP")

        if speed not in self.supported_speeds:
            pytest.skip("Skip 10G connection test")

        assert state in ["hibernate", "shutdown", "suspend"]
        self.wol_state = state

        self.dut_ifconfig.set_link_speed(speed)
        self.normal_speed = self.lkp_ifconfig.wait_link_up()

        self.dut_ifconfig.set_power_mgmt_settings(False, True, True)
        self.dut_set_wol_settings(on_link=True, from_power_off=True, on_magic=True)

        self.turn_off_dut(state)

        # Make sure DUT didn't come online after turning off
        time.sleep(self.AFTER_TURNOFF_DELAY)
        if state != "suspend" and self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        if state == "suspend" and self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")

        self.dut_check_wol_speed()

        self.cable_unplug()
        time.sleep(5)
        self.cable_plug()
        if "forwarding" in self.dut_drv_version and state != "shutdown":
            assert self.lkp_ifconfig.wait_link_up(retry_interval=2) == speed
        else:
            self.lkp_ifconfig.wait_link_up(retry_interval=2)
        log.info("DUT should start waking up in {} seconds after link plug".format(self.WAKE_ON_LINK_DELAY))
        log.info("Sleeping {} seconds".format(self.WAKE_ON_LINK_DELAY))
        time.sleep(self.WAKE_ON_LINK_DELAY)

        time.sleep(self.LED_TIMEOUT)
        if state != "suspend" and not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link up")
        if state == "suspend":
            for i in range(10):
                if self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
                    break
            else:
                raise Exception("DUT didn't light up power LED after link up")

        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back from {} state after cable plug".format(state))
        log.info("DUT woke up after cable plug")

        self.perform_after_wake_up_checks(state=state)

    @idparametrize("state", ["hibernate", "shutdown", "suspend"])
    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_wake_on_magic_packet_with_wake_on_link_from_state(self, state, speed):
        """
        @description: Check wake on magic packet from different states ("hibernate", "shutdown", "suspend").
        Condition: wake on link enabled.

        @steps:
        1. In loop for action from ["hibernate", "shutdown", "suspend"] and different link speeds from
        [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]:
            a. Configure power management setting.
            b. Configure wol settings: wake on link enabled, from power off state enabled, wake on magic packet enabled.
            c. Execute action on DUT.
            d. Send magic packet from LKP to DUT.
            e. Make sure that DUT wake up.
            f. Run ping from DUT to LKP.

        @result: All ckecks are passed.
        @duration: 20 minutes.
        """
        if speed not in self.supported_speeds:
            pytest.xfail()

        if state == "hibernate" and self.dut_ops.is_rhel():
            pytest.skip("RHEL could not be hibernated with LOM connected")

        if self.dut_fw_card == CARD_FIJI and (state == "shutdown" or speed == LINK_SPEED_10G):
            pytest.skip("Skip for Fiji ")

        if self.dut_fw_card in FELICITY_CARDS:
            if "DAC" in self.sfp and speed in [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G] and self.supported_speeds[-1] == LINK_SPEED_10G:
                pytest.skip("Skip for Dac cable can not 2.5G and 5G link up when autoneg on LKP")

        if speed not in self.supported_speeds:
            pytest.skip("Skip 10G connection test")

        if state == "suspend" and not self.suspend_enabled:
            pytest.skip("Skip test due suspend is not support by motherboard")

        assert state in ["hibernate", "shutdown", "suspend"]

        self.wol_state = state

        self.dut_ifconfig.set_link_speed(speed)
        self.normal_speed = self.lkp_ifconfig.wait_link_up()

        self.dut_ifconfig.set_power_mgmt_settings(True, True, True)
        self.dut_set_wol_settings(on_magic=True, from_power_off=True, on_link=True)

        self.turn_off_dut(state)

        # Make sure DUT didn't come online after turning off
        time.sleep(self.AFTER_TURNOFF_DELAY)
        if state != "suspend" and self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        if state == "suspend" and self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")

        self.dut_check_wol_speed()

        log.info("Sending magic packet")
        self.lkp_ifconfig.set_arp(self.DUT_IP, self.dut_mac)
        self.lkp_scapy_tools.send_raw_magic_packet(self.dut_mac)

        time.sleep(self.LED_TIMEOUT)
        if state != "suspend" and not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after magic packet")
        if state == "suspend":
            for i in range(10):
                if self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
                    break
            else:
                raise Exception("DUT didn't light up power LED after magic packet")

        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back from {} state after magic packet".format(state))
        log.info("DUT woke up after magic packet")

        self.perform_after_wake_up_checks(state=state)

    @idparametrize("state", ["hibernate", "shutdown", "suspend"])
    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_wake_on_magic_packet_from_state(self, state, speed):
        """
        @description: Check wake on magic packet from different states ("hibernate", "shutdown", "suspend").
        Condition: wake on link disabled.

        @steps:
        1. For each action in ["hibernate", "shutdown", "suspend"] and for speed in
        [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]:
            a. Configure power management setting.
            b. Configure wol settings: wake on link disabled, from power off state enabled, wake on magic packet enabled.
            c. Execute action on DUT.
            d. Send magic packet from LKP to DUT.
            e. Make sure that DUT wake up.
            f. Run ping from DUT to LKP.

        @result: All ckecks are passed.
        @duration: 20 minutes.
        """
        if speed not in self.supported_speeds:
            pytest.xfail()

        if state == "hibernate" and self.dut_ops.is_rhel():
            pytest.skip("RHEL could not be hibernated with LOM connected")

        if self.dut_fw_card == CARD_FIJI and (state == "shutdown" or speed == LINK_SPEED_10G):
            pytest.skip("Skip for Fiji ")

        if self.dut_fw_card in FELICITY_CARDS:
            if "DAC" in self.sfp and speed in [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G] and self.supported_speeds[-1] == LINK_SPEED_10G:
                pytest.skip("Skip for Dac cable can not 2.5G and 5G link up when autoneg on LKP")

        if speed not in self.supported_speeds:
            pytest.skip("Skip 10G connection test")

        if state == "suspend" and not self.suspend_enabled:
            pytest.skip("Skip test due suspend is not support by motherboard")

        assert state in ["hibernate", "shutdown", "suspend"]

        self.wol_state = state

        self.dut_ifconfig.set_link_speed(speed)
        self.normal_speed = self.lkp_ifconfig.wait_link_up()

        self.dut_ifconfig.set_power_mgmt_settings(True, True, True)
        self.dut_set_wol_settings(on_magic=True, from_power_off=True)

        self.turn_off_dut(state)

        # Make sure DUT didn't come online after turning off
        time.sleep(self.AFTER_TURNOFF_DELAY)
        if state != "suspend" and self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        if state == "suspend" and self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")

        self.dut_check_wol_speed()

        log.info("Sending magic packet")
        self.lkp_ifconfig.set_arp(self.DUT_IP, self.dut_mac)
        self.lkp_scapy_tools.send_raw_magic_packet(self.dut_mac)

        time.sleep(self.LED_TIMEOUT)
        if state != "suspend" and not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after magic packet")
        if state == "suspend":
            for i in range(10):
                if self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
                    break
            else:
                raise Exception("DUT didn't light up power LED after magic packet")

        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back from {} state after magic packet".format(state))
        log.info("DUT woke up after magic packet")

        self.perform_after_wake_up_checks()

    @idparametrize("state", ["hibernate", "shutdown", "suspend"])
    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_wake_on_pattern_from_state(self, state, speed):
        """
        @description: Check wake on pattern from different states ("hibernate", "shutdown", "suspend").
        Condition: wake on link disabled, wake on magic packet disabled.

        @steps:
        1. In loop for action from ["hibernate", "shutdown", "suspend"] and different link speeds from
        [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]:
            a. Configure power management setting.
            b. Configure wol settings: wake on lan disabled, from power off state enabled,
            wake on magic packet disabled, wake on pattern enabled.
            c. Execute action on DUT.
            d. Send TCP SYN packet from LKP to DUT.
            e. Make sure that DUT wake up.
            f. Run ping from DUT to LKP.

        @result: All ckecks are passed.
        @duration: 20 minutes.
        """
        if state == "hibernate" and self.dut_ops.is_rhel():
            pytest.skip("RHEL could not be hibernated with LOM connected")
        if self.dut_ops.is_linux() or self.dut_ops.is_freebsd():
            pytest.skip("Linux driver doesn't support wake on pattern")
        if self.dut_firmware.is_2x():
            pytest.skip("Firmware 2x doesn't support wake by ping")

        if self.dut_fw_card == CARD_FIJI and (state == "shutdown" or speed == LINK_SPEED_10G):
            pytest.skip("Skip for Fiji ")

        if self.dut_fw_card in FELICITY_CARDS:
            if "DAC" in self.sfp and speed in [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G] and self.supported_speeds[-1] == LINK_SPEED_10G:
                pytest.skip("Skip for Dac cable can not 2.5G and 5G link up when autoneg on LKP")

        if speed not in self.supported_speeds:
            pytest.skip("Skip 10G connection test")

        if state == "suspend" and not self.suspend_enabled:
            pytest.skip("Skip test due suspend is not support by motherboard")

        assert state in ["hibernate", "shutdown", "suspend"]
        self.wol_state = state

        self.dut_ifconfig.set_link_speed(speed)
        self.normal_speed = self.lkp_ifconfig.wait_link_up()

        self.dut_ifconfig.set_power_mgmt_settings(False, True, True)
        self.dut_set_wol_settings(on_pattern=True, from_power_off=True)

        self.turn_off_dut(state)

        # Make sure DUT didn't come online after turning off
        time.sleep(self.AFTER_TURNOFF_DELAY)
        if state != "suspend" and self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        if state == "suspend" and self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")

        self.dut_check_wol_speed()

        log.info("Sending TCP SYN from LKP (port 22)")
        self.lkp_scapy_tools.wake_on_port(self.DUT_IP, self.LKP_IP, self.dut_mac, 22, "tcp")

        time.sleep(self.LED_TIMEOUT)
        if state != "suspend" and not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after TCP SYN")
        if state == "suspend":
            for i in range(10):
                if self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
                    break
            else:
                raise Exception("DUT didn't light up power LED after TCP SYN")

        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back from {} state TCP SYN".format(state))
        log.info("DUT woke up after TCP SYN")

        self.perform_after_wake_up_checks(state=state)

    @idparametrize("state", ["hibernate", "shutdown", "suspend"])
    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_wake_on_ping_from_state(self, state, speed):
        """
        @description: Check wake on ping from different states ("hibernate", "shutdown", "suspend").
        Condition: wake on link disabled, wake on magic packet disabled.

        @steps:
        1. For each action in ["hibernate", "shutdown", "suspend"] and for speed in
        [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]:
            a. Configure power management setting.
            b. Configure wol settings: wake on link disabled, from power off state enabled,
            wake on magic packet disabled, wake on ping enabled.
            c. Execute action on DUT.
            d. Wake DUT via ping from LKP.
            e. Make sure that DUT wake up.
            f. Run ping from DUT to LKP.

        @result: All ckecks are passed.
        @duration: 20 minutes.
        """
        if state == "hibernate" and self.dut_ops.is_rhel():
            pytest.skip("RHEL could not be hibernated with LOM connected")
        if self.dut_ops.is_linux() or self.dut_ops.is_freebsd():
            pytest.skip("Linux driver doesn't support wake on ping")

        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Skip for Fiji ")

        if self.dut_fw_card in FELICITY_CARDS:
            if "DAC" in self.sfp and speed in [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G] and self.supported_speeds[-1] == LINK_SPEED_10G:
                pytest.skip("Skip for Dac cable can not 2.5G and 5G link up when autoneg on LKP")

        if speed not in self.supported_speeds:
            pytest.skip("Skip 10G connection test")

        if state == "suspend" and not self.suspend_enabled:
            pytest.skip("Skip test due suspend is not support by motherboard")

        assert state in ["hibernate", "shutdown", "suspend"]
        self.wol_state = state

        self.dut_ifconfig.set_link_speed(speed)
        self.normal_speed = self.lkp_ifconfig.wait_link_up()

        self.dut_ifconfig.set_power_mgmt_settings(False, True, True)
        self.dut_set_wol_settings(on_ping=True, from_power_off=True)

        self.turn_off_dut(state)

        # Make sure DUT didn't come online after turning off
        time.sleep(self.AFTER_TURNOFF_DELAY)
        if state != "suspend" and self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        if state == "suspend" and self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")

        self.dut_check_wol_speed()

        log.info("Pinging host {}".format(self.dut_hostname))
        self.lkp_ifconfig.set_arp(self.DUT_IP, self.dut_mac)
        self.ping("localhost", self.DUT_IP, 1)

        time.sleep(self.LED_TIMEOUT)
        if state != "suspend" and not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after ping")
        if state == "suspend":
            for i in range(10):
                if self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
                    break
            else:
                raise Exception("DUT didn't light up power LED after ping")

        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back from {} state after ping".format(state))
        log.info("DUT woke up after ping")

        self.perform_after_wake_up_checks()

    @idparametrize("state", ["hibernate", "shutdown", "suspend"])
    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_wake_on_plug_from_state(self, state, speed):
        """
        @description: Check wake on link from different states ("hibernate", "shutdown", "suspend").
        Condition: wake on magic packet disabled.

        @steps:
        1. For each action in ["hibernate", "shutdown", "suspend"] and for speed in
        [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]:
            a. Configure power management setting.
            b. Configure wol settings: wake on link enabled, from power off state enabled, wake on magic packet disabled.
            c. Execute action on DUT.
            d. Set link down and then link up on LKP.
            e. Make sure that DUT wake up.
            f. Run ping from DUT to LKP.

        @result: All ckecks are passed.
        @duration: 20 minutes.
        """
        if state == "hibernate" and self.dut_ops.is_rhel():
            pytest.skip("RHEL could not be hibernated with LOM connected")
        if self.dut_ops.is_freebsd():
            pytest.skip("Free bsd driver doesn't support wake on plug")

        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Skip for Fiji ")

        if self.dut_fw_card in FELICITY_CARDS:
            if "DAC" in self.sfp and speed in [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G] and self.supported_speeds[-1] == LINK_SPEED_10G:
                pytest.skip("Skip for Dac cable can not 2.5G and 5G link up when autoneg on LKP")

        if speed not in self.supported_speeds:
            pytest.skip("Skip 10G connection test")

        if state == "suspend" and not self.suspend_enabled:
            pytest.skip("Skip test due suspend is not support by motherboard")

        assert state in ["hibernate", "shutdown", "suspend"]
        self.wol_state = state

        self.dut_ifconfig.set_link_speed(speed)
        self.normal_speed = self.lkp_ifconfig.wait_link_up()

        self.dut_ifconfig.set_power_mgmt_settings(False, True, True)
        self.dut_set_wol_settings(on_link=True, from_power_off=True)

        self.turn_off_dut(state)

        # Make sure DUT didn't come online after turning off
        time.sleep(self.AFTER_TURNOFF_DELAY)
        if state != "suspend" and self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        if state == "suspend" and self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")

        self.dut_check_wol_speed()

        self.cable_unplug()
        time.sleep(5)
        self.cable_plug()
        if "forwarding" in self.dut_drv_version and state != "shutdown":
            assert self.lkp_ifconfig.wait_link_up(retry_interval=2) == speed
        else:
            self.lkp_ifconfig.wait_link_up(retry_interval=2)

        log.info("DUT should start waking up in {} seconds after link plug".format(self.WAKE_ON_LINK_DELAY))
        log.info("Sleeping {} seconds".format(self.WAKE_ON_LINK_DELAY))
        time.sleep(self.WAKE_ON_LINK_DELAY)

        time.sleep(self.LED_TIMEOUT)
        if state != "suspend" and not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link up")
        if state == "suspend":
            for i in range(10):
                if self.ping(from_host=self.lkp_hostname, to_host=self.dut_hostname):
                    break
            else:
                raise Exception("DUT didn't light up power LED after link up")

        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back from {} state after cable plug".format(state))
        log.info("DUT woke up after cable plug")

        self.perform_after_wake_up_checks(state=state)

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_wake_on_double_plug_from_hibernate(self, speed):
        """
        @description: Check wake on link from hibernate with double plug.
        Condition: wake on link enabled, wake on magic packet disabled.

        @steps:
        1. For each speed in
        [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]:
            a. Configure power management setting.
            b. Configure wol settings: wake on link enabled, from power off state enabled,
            wake on magic packet disabled.
            c. Hibernate DUT.
            d. 2 times perform link down => up on LKP.
            e. Make sure that DUT wake up.
            f. Run ping from DUT to LKP.

        @result: All ckecks are passed.
        @duration: 20 minutes.
        """
        if self.dut_ops.is_rhel():
            pytest.skip("RHEL could not be hibernated with LOM connected")
        if self.dut_ops.is_linux() or self.dut_ops.is_freebsd():
            pytest.skip("Linux driver doesn't support wake on plug")

        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Skip for Fiji ")

        if self.dut_fw_card in FELICITY_CARDS:
            if "DAC" in self.sfp and speed in [LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G] and self.supported_speeds[-1] == LINK_SPEED_10G:
                pytest.skip("Skip for Dac cable can not 2.5G and 5G link up when autoneg on LKP")

        if speed not in self.supported_speeds:
            pytest.skip("Skip 10G connection test")

        self.wol_state = "hibernate"

        self.dut_ifconfig.set_link_speed(speed)
        self.normal_speed = self.lkp_ifconfig.wait_link_up()

        self.dut_ifconfig.set_power_mgmt_settings(False, True, True)
        self.dut_set_wol_settings(on_link=True, from_power_off=True)

        self.turn_off_dut("hibernate")

        # Make sure DUT didn't come online after turning off
        time.sleep(self.AFTER_TURNOFF_DELAY)
        if self.is_host_alive(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")

        self.cable_unplug()
        time.sleep(5)
        self.cable_plug()
        self.lkp_ifconfig.wait_link_up(timeout=10, retry_interval=2)

        self.dut_check_wol_speed()

        self.cable_unplug()

        log.info("Sleeping {} seconds".format(self.POWER_UP_TIMEOUT))
        time.sleep(self.POWER_UP_TIMEOUT)

        if self.is_host_alive(self.dut_hostname):
            raise Exception("DUT woke up after second cable unplug")
        else:
            log.info("DUT didn't wake up after second cable unplug")

        self.cable_plug()
        self.lkp_ifconfig.wait_link_up(timeout=10, retry_interval=2)

        self.dut_check_wol_speed()
        log.info("DUT should start waking up in {} seconds after link plug".format(self.WAKE_ON_LINK_DELAY))
        log.info("Sleeping {} seconds".format(self.WAKE_ON_LINK_DELAY))
        time.sleep(self.WAKE_ON_LINK_DELAY)

        time.sleep(self.LED_TIMEOUT)
        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link up")

        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back after second cable plug")
        log.info("DUT woke up after second cable plug")

        self.perform_after_wake_up_checks()

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_5G, LINK_SPEED_2_5G])
    def test_wake_on_plug_usb(self, speed):
        """
        @description: Check wake on link up from hibernate state.
        Condition: wake on link enabled.

        @steps:
        1. For link speed in
        [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]:
            a. Configure power management setting.
            b. Configure wol settings: wake on link enabled, from power off state enabled,
            wake on magic packet disabled.
            c. Set link down on LKP.
            d. Hibernate DUT.
            e. Set link up on LKP.
            f. Make sure that DUT wake up.

        @result: All ckecks are passed.
        @duration: 20 minutes.
        """
        if self.dut_fw_card != CARD_FIJI:
            pytest.skip("Skip for all cards except Fiji")
        if self.dut_ops.is_linux() or self.dut_ops.is_freebsd():
            pytest.skip("Linux driver doesn't support wake on plug")

        if speed not in self.supported_speeds:
            pytest.xfail()

        self.wol_state = "hibernate"

        self.dut_ifconfig.set_link_speed(speed)
        self.normal_speed = self.lkp_ifconfig.wait_link_up()

        self.dut_ifconfig.set_power_mgmt_settings(False, True, True)
        self.dut_set_wol_settings(on_magic=True, on_link=True)

        self.cable_unplug()
        self.turn_off_dut("hibernate")

        time.sleep(self.AFTER_TURNOFF_DELAY)
        if self.is_host_alive(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")

        self.cable_plug()
        self.lkp_ifconfig.wait_link_up(timeout=10, retry_interval=2)
        self.dut_check_wol_speed()

        time.sleep(self.LED_TIMEOUT)
        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link up")

        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back after cable plug")
        log.info("DUT woke up after cable plug")

        self.perform_after_wake_up_checks()

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G])
    def test_wake_on_unplug_usb(self, speed):
        """
        @description: Check wake on link down from hibernate state.
        Condition: wake on link enabled.

        @steps:
        1. For link speed in
        [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]:
            a. Configure power management setting.
            b. Configure wol settings: wake on link enabled, from power off state enabled,
            wake on magic packet disabled.
            c. Hibernate DUT.
            d. Set link down on LKP.
            e. Make sure that DUT wake up.

        @result: All ckecks are passed.
        @duration: 20 minutes.
        """
        if self.dut_fw_card != CARD_FIJI:
            pytest.skip("Skip for all cards except Fiji")
        if self.dut_ops.is_linux() or self.dut_ops.is_freebsd():
            pytest.skip("Linux driver doesn't support wake on plug")

        if speed not in self.supported_speeds:
            pytest.xfail()

        self.wol_state = "hibernate"

        self.dut_ifconfig.set_link_speed(speed)
        self.normal_speed = self.lkp_ifconfig.wait_link_up()

        self.dut_ifconfig.set_power_mgmt_settings(False, True, True)
        self.dut_set_wol_settings(on_magic=True, on_link=True)

        self.turn_off_dut("hibernate")

        time.sleep(self.AFTER_TURNOFF_DELAY)
        if self.is_host_alive(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")

        self.cable_unplug()

        time.sleep(self.LED_TIMEOUT)
        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after link up")

        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back after cable plug")
        log.info("DUT woke up after cable plug")


if __name__ == "__main__":
    args = [__file__, "-s", "-v"]
    if len(sys.argv) > 1:
        args.extend(["-k", sys.argv[-1]])
    pytest.main(args)
