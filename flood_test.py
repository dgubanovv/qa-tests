import os
import time
import timeit

import pytest

from tools.atltoolper import AtlTool
from tools.eee import EEE
from tools.killer import Killer
from tools.command import Command
from tools.driver import Driver
from tools.utils import get_atf_logger
from tools.ops import OpSystem
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, \
    DIRECTION_RX, DIRECTION_TX
from infra.test_base import TestBase

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "ping_flood"


class TestPingFlood(TestBase):
    """
    @description: The TestPingFlood test is dedicated to perform check of EEE stability with switches.
    It performs several cycles of ping flood from the host with EEE enabled.

    @setup: Two Aquantia devices connected to 2 ports with EEE support on switch.
    """

    PING_LOG_PATH = "~/pingFlood.log"
    FLOOD_TIME = 600
    NOF_CYCLES = 3

    @classmethod
    def setup_class(cls):
        super(TestPingFlood, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port)
            cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)
            cls.NETMASK_IPV4 = "255.255.0.0"

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            cls.atltool_wrapper_dut = AtlTool(port=cls.dut_port)
            cls.atltool_wrapper_lkp = AtlTool(host=cls.lkp_hostname, port=cls.lkp_port)

            cls.op_sys_lkp = OpSystem(host=cls.lkp_hostname)
            cls.op_sys_dut = OpSystem()

            cls.eee = EEE(dut_hostname=cls.dut_hostname, dut_port=cls.dut_port,
                          lkp_hostname=cls.lkp_hostname, lkp_port=cls.lkp_port)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def kill_ping_on_machines(self):
        Killer().kill("ping")
        Killer(host=self.lkp_hostname).kill("ping")

    @classmethod
    def teardown_class(cls):
        super(TestPingFlood, cls).teardown_class()

        command_rm = 'rm -rf {}'.format(cls.PING_LOG_PATH)
        Command(cmd=command_rm, host=cls.dut_hostname).run()
        Command(cmd=command_rm, host=cls.lkp_hostname).run()

    def verify_eee_fails_during_ping_flood(self, speed, ip_address, host):
        statistics_base_addr = self.atltool_wrapper_dut.readreg(0x360)
        nof_eee_failures_before = self.atltool_wrapper_dut.readmem(statistics_base_addr + 0xe0, 4)[0]

        command_host = 'sudo ping -f {} > {}'.format(ip_address, self.PING_LOG_PATH)
        command_run_host = Command(cmd=command_host, host=host)
        command_run_host.run_async()

        start = timeit.default_timer()
        while True:
            nof_eee_failures_after = self.atltool_wrapper_dut.readmem(statistics_base_addr + 0xe0, 4)[0]

            if (nof_eee_failures_before != nof_eee_failures_after) | (timeit.default_timer() - start > self.FLOOD_TIME):
                command_run_host.join(1)
                self.kill_ping_on_machines()
                break
            time.sleep(5)

    def verify_link_downs_during_ping_flood(self, speed, ip_address, host):
        statistics_base_addr = self.atltool_wrapper_dut.readreg(0x360)
        nof_link_downs_before = self.atltool_wrapper_dut.readmem(statistics_base_addr + 0xb8, 4)[0]

        command_host = 'sudo ping -f {} > {}'.format(ip_address, self.PING_LOG_PATH)
        command_run_host = Command(cmd=command_host, host=host)
        command_run_host.run_async()

        start = timeit.default_timer()
        while True:
            nof_link_downs_after = self.atltool_wrapper_dut.readmem(statistics_base_addr + 0xb8, 4)[0]

            if (nof_link_downs_before != nof_link_downs_after) | (timeit.default_timer() - start > self.FLOOD_TIME):
                command_run_host.join(1)
                self.kill_ping_on_machines()
                break
            time.sleep(5)

    def cfg_hosts_and_run_ping_flood(self, speed, direction):
        if speed not in self.supported_speeds:
            pytest.skip()
        self.kill_ping_on_machines()
        times_eee_disable = []
        for i in range(self.NOF_CYCLES):

            self.dut_ifconfig.set_link_speed(speed)
            self.lkp_ifconfig.set_link_speed(speed)
            # Wait for link up on both hosts since they are connected with switch
            # On Buffalo switch sometimes link becomes UP very slow, so we use 300 sec timeout here
            self.dut_ifconfig.wait_link_up(timeout=300, retry_interval=5)
            self.lkp_ifconfig.wait_link_up(timeout=300, retry_interval=5)

            start = timeit.default_timer()
            if direction == DIRECTION_TX:
                self.verify_link_downs_during_ping_flood(speed, ip_address=self.LKP_IPV4_ADDR, host=self.dut_hostname)
            elif direction == DIRECTION_RX:
                self.verify_link_downs_during_ping_flood(speed, ip_address=self.DUT_IPV4_ADDR, host=self.lkp_hostname)
            duration = timeit.default_timer() - start

            if duration < self.FLOOD_TIME:
                log.info("Link was dropped after {} second".format(duration))
            else:
                log.debug("Link was stable during {} seconds".format(duration))

            times_eee_disable.append(duration)
            time.sleep(5)
        if all(i > self.FLOOD_TIME for i in times_eee_disable):
            log.debug("Link was stable {} seconds".format(times_eee_disable))
        assert all(i > self.FLOOD_TIME for i in times_eee_disable), \
            "Link unexpectedly was dropped unexpectedly {}".format(times_eee_disable)

    def cfg_hosts_with_eee_and_run_ping_flood(self, speed, direction):
        if speed not in self.supported_speeds:
            pytest.skip()
        times_eee_disable = []
        for i in range(self.NOF_CYCLES):

            self.dut_ifconfig.set_link_speed(speed)
            self.lkp_ifconfig.set_link_speed(speed)
            # Wait for link up on both hosts since they are connected with switch
            # On Buffalo switch sometimes link becomes UP very slow, so we use 300 sec timeout here
            self.dut_ifconfig.wait_link_up(timeout=300, retry_interval=5)
            self.lkp_ifconfig.wait_link_up(timeout=300, retry_interval=5)

            self.eee.enable()
            self.eee.disable(EEE.LKP)

            # Wait 10 seconds for EEE become enable
            time.sleep(10)
            start = timeit.default_timer()
            if direction == DIRECTION_TX:
                self.verify_eee_fails_during_ping_flood(speed, ip_address=self.LKP_IPV4_ADDR, host=self.dut_hostname)
            elif direction == DIRECTION_RX:
                self.verify_eee_fails_during_ping_flood(speed, ip_address=self.DUT_IPV4_ADDR, host=self.lkp_hostname)
            duration = timeit.default_timer() - start

            if duration < self.FLOOD_TIME:
                log.info("EEE was disabled after {} second".format(duration))
            else:
                log.debug("EEE didn't disabled during {} seconds".format(duration))

            self.eee.disable(EEE.DUT)

            times_eee_disable.append(duration)
            time.sleep(5)
        if all(i > self.FLOOD_TIME for i in times_eee_disable):
            log.debug("EEE was stable {} seconds".format(times_eee_disable))
        assert all(i > self.FLOOD_TIME for i in times_eee_disable), \
            "EEE was disaled unexpectedly {}".format(times_eee_disable)

        # There are no EEE on 100M and 1G
    def test_2_5G_eee_on_DUT_tx(self):
        """
        @description: This subtest performs 2.5G EEE stability check on DUT host.

        @steps:
        1. Enable 2.5G EEE on DUT.
        2. Disable 2.5G EEE on LKP.
        3. Run ping flood from DUT to LKP.

        @result: 2.5G EEE link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_with_eee_and_run_ping_flood(LINK_SPEED_2_5G, DIRECTION_TX)

    def test_5G_eee_on_DUT_tx(self):
        """
        @description: This subtest performs 5G EEE stability check on DUT host.

        @steps:
        1. Enable 5G EEE on DUT.
        2. Disable 5G EEE on LKP.
        3. Run ping flood from DUT to LKP.

        @result: 5G EEE link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_with_eee_and_run_ping_flood(LINK_SPEED_5G, DIRECTION_TX)

    def test_10G_eee_on_DUT_tx(self):
        """
        @description: This subtest performs 10G EEE stability check on DUT host.

        @steps:
        1. Enable 10G EEE on DUT.
        2. Disable 10G EEE on LKP.
        3. Run ping flood from DUT to LKP.

        @result: 10G EEE link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_with_eee_and_run_ping_flood(LINK_SPEED_10G, DIRECTION_TX)

    def test_2_5G_eee_on_DUT_rx(self):
        """
        @description: This subtest performs 2.5G EEE stability check on DUT host.

        @steps:
        1. Enable 2.5G EEE on DUT.
        2. Disable 2.5G EEE on LKP.
        3. Run ping flood from LKP to DUT.

        @result: 2.5G EEE link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_with_eee_and_run_ping_flood(LINK_SPEED_2_5G, DIRECTION_RX)

    def test_5G_eee_on_DUT_rx(self):
        """
        @description: This subtest performs 5G EEE stability check on DUT host.

        @steps:
        1. Enable 5G EEE on DUT.
        2. Disable 5G EEE on LKP.
        3. Run ping flood from LKP to DUT.

        @result: 5G EEE link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_with_eee_and_run_ping_flood(LINK_SPEED_5G, DIRECTION_RX)

    def test_10G_eee_on_DUT_rx(self):
        """
        @description: This subtest performs 10G EEE stability check on DUT host.

        @steps:
        1. Enable 10G EEE on DUT.
        2. Disable 10G EEE on LKP.
        3. Run ping flood from LKP to DUT.

        @result: 10G EEE link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_with_eee_and_run_ping_flood(LINK_SPEED_10G, DIRECTION_RX)

    def test_100M_on_DUT_tx(self):
        """
        @description: This subtest performs 100M link stability check on DUT host.

        @steps:
        1. Setup 100M link on DUT.
        2. Setup 100M link on LKP.
        3. Run ping flood from DUT to LKP.

        @result: 100M link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_and_run_ping_flood(LINK_SPEED_100M, DIRECTION_TX)

    def test_1G_on_DUT_tx(self):
        """
        @description: This subtest performs 1G link stability check on DUT host.

        @steps:
        1. Setup 1G link on DUT.
        2. Setup 1G link on LKP.
        3. Run ping flood from DUT to LKP.

        @result: 1G link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_and_run_ping_flood(LINK_SPEED_1G, DIRECTION_TX)

    def test_2_5G_on_DUT_tx(self):
        """
        @description: This subtest performs 2.5G link stability check on DUT host.

        @steps:
        1. Setup 2.5G link on DUT.
        2. Setup 2.5G link on LKP.
        3. Run ping flood from DUT to LKP.

        @result: 2.5G link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_and_run_ping_flood(LINK_SPEED_2_5G, DIRECTION_TX)

    def test_5G_on_DUT_tx(self):
        """
        @description: This subtest performs 5G link stability check on DUT host.

        @steps:
        1. Setup 5G link on DUT.
        2. Setup 5G link on LKP.
        3. Run ping flood from DUT to LKP.

        @result: 5G link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_and_run_ping_flood(LINK_SPEED_5G, DIRECTION_TX)

    def test_10G_on_DUT_tx(self):
        """
        @description: This subtest performs 10G link stability check on DUT host.

        @steps:
        1. Setup 10G link on DUT.
        2. Setup 10G link on LKP.
        3. Run ping flood from DUT to LKP.

        @result: 10G link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_and_run_ping_flood(LINK_SPEED_10G, DIRECTION_TX)

    def test_100M_on_DUT_rx(self):
        """
        @description: This subtest performs 100M link stability check on DUT host.

        @steps:
        1. Setup 100M link on DUT.
        2. Setup 100M link on LKP.
        3. Run ping flood from LKP to DUT.

        @result: 100M link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_and_run_ping_flood(LINK_SPEED_100M, DIRECTION_RX)

    def test_1G_on_DUT_rx(self):
        """
        @description: This subtest performs 1G link stability check on DUT host.

        @steps:
        1. Setup 1G link on DUT.
        2. Setup 1G link on LKP.
        3. Run ping flood from LKP to DUT.

        @result: 1G link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_and_run_ping_flood(LINK_SPEED_1G, DIRECTION_RX)

    def test_2_5G_on_DUT_rx(self):
        """
        @description: This subtest performs 2.5G link stability check on DUT host.

        @steps:
        1. Setup 2.5G link on DUT.
        2. Setup 2.5G link on LKP.
        3. Run ping flood from LKP to DUT.

        @result: 2.5G link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_and_run_ping_flood(LINK_SPEED_2_5G, DIRECTION_RX)

    def test_5G_on_DUT_rx(self):
        """
        @description: This subtest performs 5G link stability check on DUT host.

        @steps:
        1. Setup 5G link on DUT.
        2. Setup 5G link on LKP.
        3. Run ping flood from LKP to DUT.

        @result: 5G link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_and_run_ping_flood(LINK_SPEED_5G, DIRECTION_RX)

    def test_10G_on_DUT_rx(self):
        """
        @description: This subtest performs 10G link stability check on DUT host.

        @steps:
        1. Setup 10G link on DUT.
        2. Setup 10G link on LKP.
        3. Run ping flood from LKP to DUT.

        @result: 10G link on DUT doesn't dropped.
        @duration: 50 minutes.
        """
        self.cfg_hosts_and_run_ping_flood(LINK_SPEED_10G, DIRECTION_RX)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
