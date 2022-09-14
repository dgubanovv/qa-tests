"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""

import os
import re
import sys
import tempfile
import time
import timeit

import pytest
import pexpect

from infra.test_base import TestBase
from tools.driver import Driver
from tools.utils import get_atf_logger
from tools import ifconfig
from tools import power
from tools.utils import upload_file
from tools import command
from tools import constants

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "TestDriverMacOs"


class TestDriverMacOs(TestBase):
    """
    @description: The DriverMacOsTest test is dedicated to perform manual macOS tests for checking firmware in sleep.
    It performs several wake up by opening iTunes shared library, opening ssh connection, file sharing, duplicated \
    ip address and duplicated local host name.

    @setup: Two Aquantia devices connected via switch.
    """
    SKIP_INSTALL = bool(os.environ.get("SKIP_INSTALL", False))
    SLEEP_AQ_TTL = 255
    SLEEP_LOM_TTL = 32
    NO_SLEEP_LOM_TTL = 64
    MAC_NO_SLEEP = 180
    AQTEST_PASS = "aq90#$rt"
    PEXPECT_TIMEOUT = 60
    PATH_SHARE_LIB = '/tmp/shared_library.txt'
    PATH_OPEN_LIB = '/tmp/open_library.txt'
    PATH_CLOSE_ITUNES = '/tmp/close_itunes.txt'
    SHARE_LIBRARY = """tell application "iTunes" to activate
tell application "System Events" to tell application process "iTunes"
    click menu item 3 of menu "iTunes" of menu bar item "iTunes" of menu bar 1
    try
        click button "General" of toolbar 1 of window "Sharing Preferences"
    end try
    set value of text field 1 of group 1 of window "General Preferences" to "{}_Library"
    click button "Sharing" of toolbar 1 of window "General Preferences"
    click checkbox "Share my library on my local network" of group 1 of window "Sharing Preferences"
    click button "OK" of window "Sharing Preferences"
end tell"""
    CONNECT_TO_LIBRARY = """tell application "iTunes" to activate
tell application "System Events" to tell application process "iTunes"
    click pop up button 1 of window "iTunes"
    set flag to false
    repeat with theItem in rows of outline 1 of scroll area 1 of pop over 1 of pop up button 1 of window "iTunes"
        try
            static text "{}_Library" of UI element 1 of theItem
            click UI element 1 of theItem
            set flag to true
        end try
    end repeat
end tell
return flag"""
    CLOSE_ITUNES = """tell application "iTunes" to quit"""
    REGEXP_TTL_FROM_PING = ".*\d+\s+bytes\s+from\s+[0-9\.]+:\s+icmp_seq=\d+\s+ttl=(\d+)\s+time=\d+.\d+\s+ms.*"
    REGEXP_IP_FROM_PING = ".*\d+\s+bytes\s+from\s+{}+:\s+icmp_seq=\d+\s+ttl=(\d+)\s+time=\d+.\d+\s+ms.*"

    @classmethod
    def setup_class(cls):
        super(TestDriverMacOs, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            if not cls.state.skip_class_setup:
                if not cls.SKIP_INSTALL:
                    cls.install_firmwares()
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
                    cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
                    cls.lkp_driver.install()
                    cls.dut_driver.install()
            cls.host = cls.dut_hostname

            cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port, cls.dut_hostname)
            cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port)
            cls.NETMASK_IPV4 = "255.255.0.0"

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            cls.dut_ifconfig.set_link_speed(constants.LINK_SPEED_1G)
            cls.lkp_ifconfig.set_link_speed(constants.LINK_SPEED_1G)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestDriverMacOs, self).setup_method(method)
        self.dut_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)

    @classmethod
    def teardown_class(cls):
        super(TestDriverMacOs, cls).teardown_class()
        power.Power(host=cls.dut_hostname).reboot()

    def poll_host_sleeping(self, host, time_sleep):
        reg = re.compile(self.REGEXP_TTL_FROM_PING)
        count_wait_for_sleep = 0
        match = 64
        while (match != self.SLEEP_LOM_TTL):
            time.sleep(1)
            count_wait_for_sleep += 1
            ping_dut = command.Command(cmd="ping {} -c 1".format(host))
            output = ping_dut.wait(1)["output"]
            for line in output:
                ttl = reg.match(line)
                if ttl:
                    match = int(ttl.group(1))
            assert count_wait_for_sleep != self.MAC_NO_SLEEP, "Mac didn't fall asleep after 3 minutes"
        self.verify_host_is_sleeping(host, time_sleep)

    def verify_host_is_sleeping(self, host, time_sleep):
        reg = re.compile(self.REGEXP_TTL_FROM_PING)
        ping_dut = command.Command(cmd="ping {} -c {} -i 1".format(host, time_sleep))
        output = ping_dut.wait(time_sleep + 5)["output"]
        ttls = []
        for line in output:
            match = reg.match(line)
            if match:
                ttls.append(int(match.group(1)))
        assert all(i == self.SLEEP_LOM_TTL for i in ttls), \
            "Mac is not asleep. Expected that it shoult be asleep {} seconds".format(time_sleep)
        log.debug("TTLS = {}\n".format(ttls))

    def poll_host_awake(self, host):
        reg = re.compile(self.REGEXP_TTL_FROM_PING)
        count_wait_for_wake = 0
        match = 32
        while (match == self.SLEEP_LOM_TTL):
            time.sleep(1)
            count_wait_for_wake += 1
            ping_dut = command.Command(cmd="ping {} -c 1".format(host))
            output = ping_dut.wait(1)["output"]
            for line in output:
                ttl = reg.match(line)
                if ttl:
                    match = int(ttl.group(1))
            assert count_wait_for_wake < 15, "Mac didn't wake up after 15 seconds"
        log.debug("Mac wake up after {} seconds".format(count_wait_for_wake))

    def wait_pexpect_child(self, child):
        start = timeit.default_timer()
        while timeit.default_timer() - start < self.PEXPECT_TIMEOUT:
            if child.isalive():
                time.sleep(1)
            else:
                return
        raise Exception("Pexpect is timed out")

    def share_library(self):
        log.info("Sharing library...")
        command_lib = self.SHARE_LIBRARY.format(self.dut_hostname)
        with open(self.PATH_SHARE_LIB, 'w') as f:
            f.write(command_lib)
        upload_file(self.dut_hostname, self.PATH_SHARE_LIB, self.PATH_SHARE_LIB)
        open_iTunes = command.Command(cmd="sudo DISPLAY=:0 -u aqtest osascript {}".format(self.PATH_SHARE_LIB), host=self.dut_hostname)
        output = open_iTunes.run_join(180)
        log.info("LIBRARY_SHARED = {}".format(output['output']))

    def check_library_is_shared(self):
        log.info("Check that library is shared...")
        command_lib = self.CONNECT_TO_LIBRARY.format(self.dut_hostname, self.dut_hostname)
        with open(self.PATH_OPEN_LIB, 'w') as f:
            f.write(command_lib)
        open_iTunes = command.Command(cmd="sudo DISPLAY=:0 -u aqtest osascript {}".format(self.PATH_OPEN_LIB), host="localhost")
        result_output = False
        while not result_output:
            output = open_iTunes.run_join(180)["output"]
            result_output = any("true" in line for line in output)
            log.info("LIBRARY_IS_SHARED = {}".format(result_output))
            if not result_output:
                self.share_library()

    def connect_to_shared_library(self):
        command_lib = self.CONNECT_TO_LIBRARY.format(self.dut_hostname)
        with open(self.PATH_OPEN_LIB, 'w') as f:
            f.write(command_lib)
        open_iTunes = command.Command(cmd="sudo DISPLAY=:0 -u aqtest osascript {}".format(self.PATH_OPEN_LIB), host="localhost")
        result = ''
        while result not in [True, False]:
            output = open_iTunes.run_join(180)["output"]
            result = any("true" in line for line in output)
            log.info("CONNECT_TO_SHARED_LIBARARY = {}".format(result))
        assert result is True, 'Mac cannot open shared library'

    def test_wake_up_by_itunes_shared_library(self):
        """
        @description: This subtest performs check that firmware wake up by opening iTunes shared library.

        @steps:
        1. Share iTunes library on DUT.
        2. Put DUT machine to sleep.
        3. On LKP open iTunes shared library.

        @result: Machine wake up after less than 15 seconds.
        @duration: 2 minutes.
        """
        self.check_library_is_shared()
        with open(self.PATH_CLOSE_ITUNES, 'w') as f:
            f.write(self.CLOSE_ITUNES)
        close_iTunes = command.Command(cmd="sudo DISPLAY=:0 -u aqtest osascript {}".format(self.PATH_CLOSE_ITUNES), host="localhost")
        close_iTunes.run_join(180)
        power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        self.connect_to_shared_library()
        self.poll_host_awake(self.dut_hostname)
        upload_file(self.dut_hostname, self.PATH_CLOSE_ITUNES, self.PATH_CLOSE_ITUNES)
        close_iTunes = command.Command(cmd="sudo DISPLAY=:0 -u aqtest osascript {}".format(self.PATH_CLOSE_ITUNES), host=self.dut_hostname)
        close_iTunes.run_join(180)
        close_iTunes = command.Command(cmd="sudo DISPLAY=:0 -u aqtest osascript {}".format(self.PATH_CLOSE_ITUNES), host="localhost")
        close_iTunes.run_join(180)

    def test_wake_up_by_file_sharing(self):
        """
        @description: This subtest performs check that firmware wake up by file sharing.

        @steps:
        1. Put DUT machine to sleep.
        2. On LKP mount DUT shared file directory.

        @result: Machine wake up after less than 15 seconds.
        @duration: 2 minutes.
        """
        power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        smb_mount_point = "/Users/aqtest/data/"
        child = pexpect.spawn("mount_smbfs //aqtest@{}/data {}".format(self.DUT_IPV4_ADDR, smb_mount_point))
        child.logfile_read = sys.stdout
        child.expect("assword")
        child.sendline(self.AQTEST_PASS)
        child.expect(pexpect.EOF)
        self.wait_pexpect_child(child)
        self.poll_host_awake(self.dut_hostname)
        umount_command = command.Command(cmd="sudo umount {}".format(smb_mount_point))
        umount_command.run()

    def test_wake_up_by_ssh(self):
        """
        @description: This subtest performs check that firmware wake up by ssh connection.

        @steps:
        1. Put DUT machine to sleep.
        2. LKP connect to DUT by ssh.

        @result: Machine wake up after less than 15 seconds.
        @duration: 2 minutes.
        """
        power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        local_dut_name = "{}.local".format(self.dut_hostname)
        log.info("Wake up using ssh connection to {}".format(local_dut_name))
        command.Command(cmd="ls", host=local_dut_name).run()
        self.poll_host_awake(self.dut_hostname)

    def test_ping_local_name_in_sleep(self):
        """
        @description: This subtest performs check that firmware didn't wake up by local host name.

        @steps:
        1. Put DUT machine to sleep.
        2. LKP ping DUT by local host name.

        @result: Machine didn't wake up during 2 minutes.
        @duration: 2 minutes.
        """
        power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        local_dut_name = "{}.local".format(self.dut_hostname)
        reg = re.compile(self.REGEXP_IP_FROM_PING.format(self.DUT_IPV4_ADDR))
        ping_dut = command.Command(cmd="ping {} -c 10 -i 1".format(local_dut_name))
        output = ping_dut.wait(15)["output"]
        ttls = []
        for line in output:
            match = reg.match(line)
            if match:
                ttls.append(int(match.group(1)))
        assert all(i == self.SLEEP_AQ_TTL for i in ttls), \
            "Mac is not asleep. Expected that it shoult be asleep {} seconds".format(15)
        log.debug("TTLS = {}\n".format(ttls))
        self.verify_host_is_sleeping(self.dut_hostname, 120)

    def test_wake_up_by_duplicated_ip_address(self):
        """
        @description: This subtest performs check that firmware wake up by duplicated ip address.

        @steps:
        1. Put DUT machine to sleep.
        2. Set DUT_IPV4_ADDR address on LKP interface.

        @result: Machine wake up after less than 15 seconds.
        @duration: 2 minutes.
        """
        lkp_iface = self.lkp_ifconfig.get_conn_name()
        cidr = sum([bin(int(x)).count("1") for x in self.NETMASK_IPV4.split(".")])
        power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        cmd = command.Command(cmd="ip addr add {}/{} dev {}".format(self.DUT_IPV4_ADDR, cidr, lkp_iface))
        cmd.run_join(5)
        self.poll_host_awake(self.dut_hostname)
        cmd = command.Command(cmd="ip addr del {}/{} dev {}".format(self.DUT_IPV4_ADDR, cidr, lkp_iface))
        cmd.run_join(5)

    def test_wake_up_by_duplicated_local_host_name(self):
        """
        @description: This subtest performs check that firmware wake up by duplicated local host name.

        @steps:
        1. Put DUT machine to sleep.
        2. Set DUT local host name as LKP local host name.

        @result: Machine wake up after less than 15 seconds.
        @duration: 2 minutes.
        """
        power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        lkp_name = self.lkp_hostname
        cmd = command.Command(cmd="sudo scutil --set LocalHostName '{}'".format(self.dut_hostname))
        cmd.run_join(5)
        self.poll_host_awake(self.dut_hostname)
        cmd = command.Command(cmd="sudo scutil --set LocalHostName '{}'".format(lkp_name))
        cmd.run_join(5)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
