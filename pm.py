"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""

import re
import os
import time

import pytest
import shutil

from tools import pcontrol
from tools.atltoolper import AtlTool
from tools.command import Command
from tools.driver import Driver
from tools.ifconfig import get_expected_speed
from tools.power import Power
from tools.utils import get_atf_logger, upload_file, download_file, get_bus_dev_func
from tools.ops import OpSystem
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_NO_LINK, FELICITY_CARDS, DIRECTION_RX, CARD_FIJI

from infra.test_base import TestBase, idparametrize

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "pm"


class TestPM(TestBase):
    """
    @description: The TestPM test is dedicated to verify power management.

    @setup: Two Aquantia devices connected back to back.
    """
    """
    DUT - remote machine
    LKP - local machine
    """
    AFTER_TURNOFF_DELAY = 30
    PING_COUNT = 10
    BEFORE_PING_DELAY = 20
    IPERF_TIME = int(os.environ.get("IPERF_TIME", 30))

    DUT_IP = "192.168.0.3"
    LKP_IP = "192.168.0.2"
    NETMASK = "255.255.255.0"
    GATEWAY = "192.168.0.1"

    IFACE_UBUNTU = """auto {}
iface {} inet static
address {}
netmask {}
"""
    IFACE = """DEVICE={}
ONBOOT=yes
IPADDR={}
NETMASK={}
"""
    SCRIPT_FOR_RENEW_DHCP_LEASE = """#!/bin/bash
sudo ifdown eth0; sudo ifup eth0
"""

    @classmethod
    def setup_class(cls):
        super(TestPM, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            if cls.dut_fw_card not in CARD_FIJI:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            if cls.lkp_fw_card not in CARD_FIJI:
                cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            if cls.dut_fw_card not in CARD_FIJI and cls.dut_atltool_wrapper.is_secure_chips() and cls.dut_ops.is_linux():
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, flashless_fw=cls.dut_fw_version,
                                        host=cls.dut_hostname)
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
            cls.dut_driver.install()
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.lkp_driver.install()

            cls.dut_ops = OpSystem(host=cls.dut_hostname)
            cls.lkp_ops = OpSystem()

            # Upload file to renew DHCP lease on DUT after hibernate
            if cls.dut_ops.is_linux():
                with open('/tmp/renew_dhcp_lease', 'w') as f:
                    f.write(cls.SCRIPT_FOR_RENEW_DHCP_LEASE)
                upload_file(cls.dut_hostname, '/tmp/renew_dhcp_lease', '~/renew_dhcp_lease')
                command_cp = 'sudo cp ~/renew_dhcp_lease /lib/systemd/system-sleep/renew_dhcp_lease'
                command_dut_cp = Command(cmd=command_cp, host=cls.dut_hostname)
                command_dut_cp.run_join(5)
                command_cp = 'sudo chmod 777 /lib/systemd/system-sleep/renew_dhcp_lease'
                command_dut_cp = Command(cmd=command_cp, host=cls.dut_hostname)
                command_dut_cp.run_join(5)

            # Upload files to up interface on DUT
            if cls.dut_ops.is_ubuntu():
                # Save original file in home dirictory
                command_cp = 'sudo cp /etc/network/interfaces ~/original_iface_file.txt'
                command_dut_cp = Command(cmd=command_cp, host=cls.dut_hostname)
                command_dut_cp.run_join(5)

                download_file(cls.dut_hostname, '/etc/network/interfaces', '/tmp/iface_file.txt')
                with open('/tmp/iface_file.txt', 'a') as f:
                    f.write(cls.IFACE_UBUNTU.format(cls.dut_ifconfig.get_conn_name(),
                                                    cls.dut_ifconfig.get_conn_name(), cls.DUT_IP, cls.NETMASK))
                upload_file(cls.dut_hostname, '/tmp/iface_file.txt', '~/iface_file.txt')
                command_cp = 'sudo cp ~/iface_file.txt /etc/network/interfaces'
                command_dut_cp = Command(cmd=command_cp, host=cls.dut_hostname)
                command_dut_cp.run_join(5)
            elif cls.dut_ops.is_centos() | cls.dut_ops.is_rhel():
                with open('/tmp/iface_file.txt'.format(cls.dut_ifconfig.get_conn_name()), 'w') as f:
                    f.write(cls.IFACE.format(cls.dut_ifconfig.get_conn_name(), cls.DUT_IP, cls.NETMASK))
                upload_file(cls.dut_hostname, '/tmp/iface_file.txt', '~/iface_file.txt')
                command_cp = 'sudo cp ~/iface_file.txt /etc/sysconfig/network-scripts/ifcfg-{}'.format(
                    cls.dut_ifconfig.get_conn_name())
                command_dut_cp = Command(cmd=command_cp, host=cls.dut_hostname)
                command_dut_cp.run_join(5)

            cls.dut_ifconfig.set_ip_address(cls.DUT_IP, cls.NETMASK, cls.GATEWAY)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, cls.GATEWAY)

            cls.speed = cls.supported_speeds[
                -1] if cls.dut_fw_card in FELICITY_CARDS or 'Switch' in cls.platform else LINK_SPEED_AUTO
            cls.exp_speed = get_expected_speed(cls.speed, cls.lkp_port)

            cls.dut_power = Power(host=cls.dut_hostname)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestPM, self).setup_method(method)
        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(True)
            self.bin_log_file, self.txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(True)

        if not self.is_host_alive_and_ready(self.dut_hostname):
            raise Exception("DUT is not online, can't perform test")

        self.lkp_ifconfig.set_link_speed(self.speed)
        self.dut_ifconfig.set_link_speed(self.speed)
        assert self.lkp_ifconfig.wait_link_up() != LINK_SPEED_NO_LINK, "Link is not up before the test"

    @classmethod
    def teardown_class(cls):
        super(TestPM, cls).teardown_class()
        # Delete created files from DUT and LKP
        if cls.dut_ops.is_ubuntu():
            command_rm = 'sudo cp ~/original_iface_file.txt /etc/network/interfaces'
            command_dut_rm = Command(cmd=command_rm, host=cls.dut_hostname)
            command_dut_rm.run_join(5)
        elif cls.dut_ops.is_centos() | cls.dut_ops.is_rhel():
            command_rm = 'sudo rm -rf /etc/sysconfig/network-scripts/ifcfg-{}'.format(cls.dut_ifconfig.get_conn_name())
            command_dut_rm = Command(cmd=command_rm, host=cls.dut_hostname)
            command_dut_rm.run_join(1)
        if cls.dut_ops.is_linux():
            command_rm_renew_dhcp_lease = 'sudo rm -rf /lib/systemd/system-sleep/renew_dhcp_lease'
            command_dut_rm = Command(cmd=command_rm_renew_dhcp_lease, host=cls.dut_hostname)
            command_dut_rm.run_join(1)

    def teardown_method(self, method):
        super(TestPM, self).teardown_method(method)
        self.bring_host_online(self.dut_hostname)

        if self.MCP_LOG:
            if hasattr(self, "action") and self.action in ["reboot", "shutdown", "cold_reboot", "dirty_shutdown"]:
                self.dut_atltool_wrapper.debug_buffer_enable(True, "remote_mcp.bin")
                time.sleep(5)
                self.dut_atltool_wrapper.debug_buffer_enable(True, "remote_mcp.bin")
                time.sleep(5)

            self.dut_bin_log_file, self.dut_txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.dut_bin_log_file, self.test_log_dir)
            shutil.copy(self.dut_txt_log_file, self.test_log_dir)

            self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

    def turn_off_turn_on_dut(self, action):
        if action in ["shutdown", "hibernate", "standby", "dirty_shutdown"]:
            if action == "shutdown":
                self.dut_power.shutdown()
            elif action == "hibernate":
                if self.dut_ops.is_rhel():
                    pytest.skip("RHEL could not be hibernated with LOM connected")
                if self.dut_fw_card == CARD_FIJI:
                    bus, dev, func = get_bus_dev_func(self.dut_port)
                    command_enbl = 'echo enabled | sudo tee /sys/bus/usb/devices/{}-{}/power/wakeup'.format(dev, func)
                    output = Command(cmd=command_enbl, host=self.dut_hostname).run_join(10)
                    assert output["returncode"] != 0, 'Failed to enable wakeup in fiji config file'
                self.dut_power.hibernate()
            elif action == "standby":
                if self.dut_ops.is_linux():
                    pytest.skip()
                if self.dut_power.is_standby_available():
                    self.dut_power.standby()
                else:
                    log.warning("Standby state is not available on machine {}".format(self.dut_hostname))
                    pytest.xfail()
            elif action == "dirty_shutdown":
                log.info("Shutting down host {} by holding POWER button for {} seconds".format(self.dut_hostname,
                                                                                               15))
                # Dirty shutdown - hold POWER button for some seconds
                pcontrol.PControl().power(self.dut_hostname, 15000, 0)

            if action != "standby":
                if not self.poll_host_powered_off(self.dut_hostname):
                    raise Exception("Couldn't turn off DUT")
            else:
                # PC's LED is blinking in standby mode, can't use PControl to check if host is offline
                if not self.poll_host_offline(self.dut_hostname, self.POWER_UP_TIMEOUT):
                    raise Exception("Couldn't turn DUT off")

            time.sleep(TestPM.AFTER_TURNOFF_DELAY)

            if action != "standby":
                if self.is_host_powered_on(self.dut_hostname):
                    raise Exception("DUT came back online spuriously")
            else:
                # PC's LED is blinking in standby mode, can't use PControl to check if host is offline
                if self.is_host_alive(self.dut_hostname):
                    raise Exception("DUT came back online spuriously")

            log.info("Waking up DUT using power control")
            pcontrol.PControl().power(self.dut_hostname, 500, 0)
            if not self.poll_host_alive_and_ready(self.dut_hostname, self.POWER_UP_TIMEOUT):
                raise Exception("Couldn't wake DUT up using power control")

            if action == "hibernate" and not self.dut_ops.is_linux():
                self.dut_power.hibernate_off()
        elif action == "reboot":
            self.dut_power.reboot()
            if not self.poll_host_offline(self.dut_hostname, self.POWER_UP_TIMEOUT):
                raise Exception("Couldn't turn DUT off")
            if not self.poll_host_alive_and_ready(self.dut_hostname, self.POWER_UP_TIMEOUT):
                raise Exception("Couldn't reboot DUT")
        elif action == "cold_reboot":
            self.cold_restart(self.dut_hostname)

    # @pytest.mark.skip(reason="no way of currently testing this")
    @idparametrize("action", ["reboot", "hibernate", "shutdown", "cold_reboot", "standby", "dirty_shutdown"])
    def test_on_action_x(self, action):
        """
        @description: Check link up after different power actions ("reboot", "hibernate", "shutdown", "cold_reboot",
        "standby", "dirty_shutdown").

        @steps:
        1. In loop for action from ["reboot", "hibernate", "shutdown", "cold_reboot", "standby", "dirty_shutdown"]:
            a. Set link up.
            b. Turn off DUT via speciaal action.
            c. Turn on DUT.
            d. Check link up.
            e. Run ping from DUT to LKP.

        @result: All checks are passed.
        @duration: 10 minutes.
        """
        if self.dut_fw_card in CARD_FIJI and action == "dirty_shutdown":
            pytest.skip("No dirty_shutdown on Fiji is supported")

        assert action in ["reboot", "standby", "hibernate", "shutdown", "cold_reboot", "dirty_shutdown"]
        self.action = action

        self.turn_off_turn_on_dut(action)

        dspeed = self.dut_ifconfig.get_link_speed()
        pspeed = self.lkp_ifconfig.get_link_speed()

        if pspeed == LINK_SPEED_NO_LINK or dspeed == LINK_SPEED_NO_LINK:
            raise Exception("Machines didn't setup link")

        if pspeed != self.exp_speed or dspeed != self.exp_speed:
            raise Exception("Expected speed is {}, LKP actual is {}, \
                DUT actual is {}".format(self.exp_speed, pspeed, dspeed))
        else:
            log.info("Both link speeds on {} and localhost are correct: {}".format(self.dut_hostname, self.exp_speed))

        time.sleep(self.BEFORE_PING_DELAY)
        if not self.ping(from_host="localhost", to_host=TestPM.DUT_IP,
                         number=self.PING_COUNT, ipv6=False, src_addr=self.LKP_IP):
            raise Exception("DUT didn't answer on ping after test")

    def test_datapath_after_sleep(self):
        """
        @description: Check datapath after hibernate.

        @steps:
        1. Set link up.
        2. Hibernate DUT.
        3. Check that DUT is hibernated.
        4. Turn on DUT.
        5. Run TCP traffic from DUT to LKP

        @result: All checks are passed.
        @duration: 10 minutes.
        """
        if self.dut_ops.is_rhel():
            pytest.skip("RHEL could not be hibernated with LOM connected")

        args = {
            'num_threads': 1,
            'num_process': 4,
            'time': self.IPERF_TIME,
            'ipv': 4,
            'buffer_len': 65507,
            'lkp': self.dut_hostname,
            'direction': DIRECTION_RX,
            'lkp4': self.DUT_IP,
            'dut4': self.LKP_IP,
            'speed': self.supported_speeds[-1]
        }

        self.run_iperf(**args)
        self.dut_power.hibernate()

        assert self.poll_host_offline(self.dut_hostname), "Host have not been hibernated"
        time.sleep(self.BEFORE_PING_DELAY)

        assert not self.is_host_alive(self.dut_hostname), "Host waked up spuriously"

        pcontrol.PControl().power(self.dut_hostname, 500, 0)
        assert self.poll_host_alive_and_ready(self.dut_hostname, self.POWER_UP_TIMEOUT), "Host is not ready after wake"

        time.sleep(5)
        self.run_iperf(**args)

    def test_detect_bsod_on_reboot(self):
        """
        @description: Simulate bsod and check that it was detected.

        @steps:
        1. Simulate bsod via powershell command.
        2. Check that bsod is detected.
        3. Run pind form DUT to LKP

        @result: All checks are passed.
        @duration: 2 minutes.
        """
        if not self.dut_ops.is_windows():
            pytest.skip("Only on Windows")

        if self.dut_fw_card in CARD_FIJI:
            pytest.skip("Skip for Fiji")

        for _ in range(20):
            self.turn_off_turn_on_dut("reboot")

            # # Simulate BSOD, only on drv: 2x/2.1.18.200-test-tps-stuck
            # bug_check_cmd = "powershell \"Get-WmiObject -Namespace root/wmi " \
            #                 "-Class Aq_Control | Invoke-WmiMethod -Name BugCheck\""
            # try:
            #     Command(cmd=bug_check_cmd, host=self.dut_hostname).run_join(timeout=5)
            # except subprocess.CalledProcessError:
            #     pass
            #
            # if not self.poll_host_alive_and_ready(self.dut_hostname, self.POWER_UP_TIMEOUT):
            #     raise Exception("Couldn't reboot DUT")

            check_bsod_cmd = 'powershell "wevtutil query-events System /c:1 /rd:true /format:text ' \
                             '/q:\\"Event[System[Provider[@Name=\'Microsoft-Windows-WER-SystemErrorReporting\']]]\\""'
            check_res = Command(cmd=check_bsod_cmd, host=self.dut_hostname).run()

            crash_dump_path = None
            for line in check_res['output']:
                m = re.match(".*dump was saved in: (.*)\.\s.*", line)
                if m is not None:
                    crash_dump_path = m.group(1)

            if crash_dump_path is not None:
                # save dump
                dump_name = crash_dump_path.split('\\')[-1]
                download_file(self.dut_hostname, crash_dump_path, dump_name)
                shutil.move(dump_name, self.test_log_dir)
                raise Exception('BSOD detected, crash dump saved')

            time.sleep(self.BEFORE_PING_DELAY)
            if not self.ping(from_host="localhost", to_host=TestPM.DUT_IP,
                             number=self.PING_COUNT, ipv6=False, src_addr=self.LKP_IP):
                raise Exception("DUT didn't answer on ping after test")


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
