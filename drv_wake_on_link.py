"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import time

import pytest
import re

from infra.test_base import TestBase
from tools.ifconfig import LINK_SPEED_100M
from tools.driver import Driver
from tools.utils import get_atf_logger
from tools import ifconfig
import tools.power
from tools import command
from tools import constants
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "mac_ptp_avb_streams"


class TestDrvWakeOnLink(TestBase):
    """
    @description: The SleepProxyDriver test is dedicated to perform check firmware is in sleep.
    It performs several link drops, wake on link and other actions first time after sleeping.

    @setup: Two Aquantia devices connected back to back.
    """

    SLEEP_LOM_TTL = 32
    NO_SLEEP_LOM_TTL = 64
    MAC_NO_SLEEP = 180

    REGEXP_TTL_FROM_PING = ".*\d+\s+bytes\s+from\s+[0-9\.]+:\s+icmp_seq=\d+\s+ttl=(\d+)\s+time=\d+.\d+\s+ms.*"

    DUT_IP = "192.168.0.3"
    LKP_IP = "192.168.0.2"
    NETMASK = "255.255.255.0"

    @classmethod
    def setup_class(cls):
        super(TestDrvWakeOnLink, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.host = cls.dut_hostname

            cls.dut_ifconfig.set_ip_address(cls.DUT_IP, cls.NETMASK, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, None)

            cls.dut_ifconfig.set_link_speed(constants.LINK_SPEED_1G)
            cls.lkp_ifconfig.set_link_speed(constants.LINK_SPEED_1G)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestDrvWakeOnLink, self).setup_method(method)
        self.dut_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)

    def teardown_method(self, method):
        super(TestDrvWakeOnLink, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()

    @classmethod
    def teardown_class(cls):
        super(TestDrvWakeOnLink, cls).teardown_class()
        tools.power.Power(host=cls.dut_hostname).reboot()

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
        # verify that host is sleeping by checking TTL of ping the host
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

    def poll_host_awake(self, host, time_wake):
        reg = re.compile(self.REGEXP_TTL_FROM_PING)
        count_wait_for_wake = 0
        match = 32
        while (match == self.SLEEP_LOM_TTL):
            time.sleep(1)
            count_wait_for_wake += 1
            ping_dut = command.Command(cmd="ping {} -c 1".format(host, time_wake))
            output = ping_dut.wait(1)["output"]
            for line in output:
                ttl = reg.match(line)
                if ttl:
                    match = int(ttl.group(1))
            assert count_wait_for_wake < time_wake, "Mac didn't wake up after {} seconds".format(time_wake)
        log.debug("Mac wake up after {} seconds".format(count_wait_for_wake))

    def test_can_sleep_without_link_120s(self):
        """
        @description: This subtest performs check firmware when it goes to sleep with link down.

        @steps:
        1. Put link to DOWN state.
        2. Put machine to sleep.

        @result: Machine didn't wake up during 2 minutes.
        @duration: 2 minutes.
        """

        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_DOWN)
        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 120)

    def test_sleep_without_link_after_20s_connect_link(self):
        """
        @description: This subtest performs check that firmware wake up by link up when it goes to sleep \
        with link down.

        @steps:
        1. Put link to DOWN state.
        2. Put machine to sleep.
        3. Put link to UP state.

        @result: Machine wake up after less than 15 seconds.
        @duration: 1 minutes.
        """

        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_DOWN)
        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)
        self.poll_host_awake(self.dut_hostname, 15)

    def test_sleep_with_link_120s(self):
        """
        @description: This subtest performs check that 100M link is up in sleep when firmware \
        goes to sleep with link down.

        @steps:
        1. Put machine to sleep.

        @result: After 20 seconds 100M link is up and machine didn't wake up during 100 seconds.
        @duration: 2 minutes.
        """

        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        if self.lkp_ifconfig.get_link_speed() != LINK_SPEED_100M:
            raise Exception("DUD didn't setup 100M link after goes asleep")
        self.verify_host_is_sleeping(self.dut_hostname, 100)

    def test_sleep_with_link_after_5_disconnect_link(self):
        """
        @description: This subtest performs check firmware when link drops in sleep.

        @steps:
        1. Put machine to sleep.
        2. Put link to DOWN state.

        @result: Machine didn't wake up during 2 minutes.
        @duration: 2 minutes.
        """

        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 5)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_DOWN)
        self.verify_host_is_sleeping(self.dut_hostname, 120)

    def test_sleep_with_link_20_disc_and_5_con(self):
        """
        @description: This subtest performs check that firmware wake up by link reconnecting.

        @steps:
        1. Put machine to sleep.
        2. After 20 seconds put link to DOWN state.
        3. After 5 seconds put link to UP state.

        @result: Machine wake up after less than 15 seconds.
        @duration: 1 minutes.
        """

        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_DOWN)
        self.verify_host_is_sleeping(self.dut_hostname, 5)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)
        self.poll_host_awake(self.dut_hostname, 15)

    def test_sleep_with_link_5_disc_5_con(self):
        """
        @description: This subtest performs check that firmware cannot wake up by quickly link reconnecting.

        @steps:
        1. Put machine to sleep.
        2. Put link to DOWN state.
        3. Put link to UP state immediately.

        @result: After 20 seconds 100M link is up and machine didn't wake up during 100 seconds.
        @duration: 2 minutes.
        """

        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 1)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_DOWN)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)
        self.verify_host_is_sleeping(self.dut_hostname, 20)
        if self.lkp_ifconfig.get_link_speed() != LINK_SPEED_100M:
            raise Exception("DUD didn't setup 100M link after goes asleep")
        self.verify_host_is_sleeping(self.dut_hostname, 100)

    def test_sleep_with_link_5_disc_and_20_con(self):
        """
        @description: This subtest performs check that firmware wake up by link reconnecting \
        immediately after sleeping.

        @steps:
        1. Put machine to sleep.
        2. Afetr 5 seconds put link to DOWN state.
        3. After 20 seconds put link to UP state.

        @result: Machine wake up after less than 15 seconds.
        @duration: 1 minutes.
        """

        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 5)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_DOWN)
        self.verify_host_is_sleeping(self.dut_hostname, 20)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)
        self.poll_host_awake(self.dut_hostname, 15)

    # TC8
    def test_sleep_with_link_5_disc_and_5_con_several(self):
        """
        @description: This subtest performs check that firmware cannot wake up by quickly several link reconnectings.

        @steps:
        1. Put machine to sleep.
        2. Put link to DOWN state.
        3. Put link to UP state immediately.
        4. Repeat steps 2 and 3 several times.

        @result: After 20 seconds 100M link is up and machine didn't wake up during 1 minute.
        @duration: 1 minutes.
        """

        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 1)
        for i in range(5):
            self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)
            self.verify_host_is_sleeping(self.dut_hostname, 3)
        self.verify_host_is_sleeping(self.dut_hostname, 20)
        if self.lkp_ifconfig.get_link_speed() != LINK_SPEED_100M:
            raise Exception("DUD didn't setup 100M link after goes asleep")
        self.verify_host_is_sleeping(self.dut_hostname, 60)

    # TC9
    def test_sleep_with_link_several_disc_and_5_con(self):
        """
        @description: This subtest performs check that firmware cannot wake up by link down in sleep.

        @steps:
        1. Put machine to sleep.
        2. After 2 minute put link to DOWN state.

        @result: Machine didn't wake up during 2 minutes.
        @duration: 4 minutes.
        """

        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 120)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_DOWN)
        self.verify_host_is_sleeping(self.dut_hostname, 120)

    # TC10
    def test_sleep_with_link_120_disc_and_5_con(self):
        """
        @description: This subtest performs check that firmware can wake up by quickly link reconnecting \
        after 2 minutes.

        @steps:
        1. Put machine to sleep.
        2. Put link to DOWN state.
        3. Put link to UP state immediately.

        @result: Machine wake up after less than 15 seconds.
        @duration: 2 minutes.
        """

        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 120)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_DOWN)
        self.verify_host_is_sleeping(self.dut_hostname, 5)
        self.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)
        self.poll_host_awake(self.dut_hostname, 15)

    # TC11
    def test_small_ping_in_sleep(self):
        """
        @description: This subtest performs check small ping in sleep mode.

        @steps:
        1. Setup autoneg speed on DUT and LKP.
        2. Put machine to sleep.
        3. Run ping with payload size equal to 500.

        @result: Machine didn't wake up and should answer to ping.
        @duration: 2 minutes.
        """
        self.dut_ifconfig.set_link_speed(constants.LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_link_speed(constants.LINK_SPEED_AUTO)
        self.lkp_ifconfig.wait_link_up()
        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        assert self.ping(
            None, self.DUT_IP, 16, ipv6=False, src_addr=self.LKP_IP, payload_size=500, margin=20) \
            is True, "Ping {} from {} failed unexpectedly".format(self.DUT_IP, self.LKP_IP)

    # TC12
    def test_large_ping_in_sleep(self):
        """
        @description: This subtest performs check large ping in sleep mode.

        @steps:
        1. Setup autoneg speed on DUT and LKP.
        2. Put machine to sleep.
        3. Run ping with payload size equal to 4000.

        @result: Machine didn't wake up and should answer to ping.
        @duration: 2 minutes.
        """
        self.dut_ifconfig.set_link_speed(constants.LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_link_speed(constants.LINK_SPEED_AUTO)
        self.lkp_ifconfig.wait_link_up()
        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        assert self.ping(
            None, self.DUT_IP, 16, ipv6=False, src_addr=self.LKP_IP, payload_size=4000, margin=10) \
            is True, "Ping {} from {} failed unexpectedly".format(self.DUT_IP, self.LKP_IP)

    # TC13
    def test_diff_ping_in_sleep(self):
        """
        @description: This subtest performs check two ping simultaneously in sleep mode.

        @steps:
        1. Setup autoneg speed on DUT and LKP.
        2. Put machine to sleep.
        3. Run ping with payload size equal to 500.
        4. Run short-term ping with payload size equal to 4000.

        @result: Machine didn't wake up and should answer to ping.
        @duration: 2 minutes.
        """
        reg = re.compile(self.REGEXP_TTL_FROM_PING)
        self.dut_ifconfig.set_link_speed(constants.LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_link_speed(constants.LINK_SPEED_AUTO)
        self.lkp_ifconfig.wait_link_up()
        tools.power.Power(host=self.dut_hostname).hibernate()
        self.poll_host_sleeping(self.dut_hostname, 20)
        cmd_small_ping = command.Command(cmd="ping {} -c 320 -i 1".format(self.DUT_IP))
        cmd_large_ping = command.Command(cmd="ping {} -c 5 -s 4000 -i 1".format(self.DUT_IP))
        cmd_small_ping.run_async()
        for i in range(20):
            time.sleep(10)
            large_ping_output = cmd_large_ping.wait(10)
            ttls = []
            for line in large_ping_output["output"]:
                match = reg.match(line)
                if match:
                    ttls.append(int(match.group(1)))
            assert len(ttls) != 5, "First large ping should be lost"
            assert len(ttls) == 4, "Large pings are lost more than expected"
        small_ping_output = cmd_small_ping.join(60)
        ttls = []
        for line in small_ping_output["output"]:
            match = reg.match(line)
            if match:
                ttls.append(int(match.group(1)))
        assert len(ttls) >= 300, "Small pings are lost more than expected"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
