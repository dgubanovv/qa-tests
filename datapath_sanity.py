import os
import shutil
import time

import pytest

import tools.ping
from infra.test_base import TestBase
from tools.atltoolper import AtlTool
from tools.constants import FELICITY_CARDS, LINK_SPEED_AUTO, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, \
    LINK_SPEED_5G, LINK_SPEED_10G, DIRECTION_RX, DIRECTION_RXTX
from tools.driver import Driver
from tools.utils import get_atf_logger
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "datapath_sanity"


class TestDatapathSanity(TestBase):
    """
    @description: The datapath sanity test is dedicated to perform fast datapath check of new firmware release.
    It performs several datapath checks using ping, iperf and other tools.

    @setup: Two Aquantia devices connected back to back.
    """

    BEFORE_PING_DELAY = 10
    BEFORE_IPERF_DELAY = 10

    @classmethod
    def setup_class(cls):
        super(TestDatapathSanity, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            if cls.MCP_LOG or os.environ.get("LOM_TEST", None):
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
                cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestDatapathSanity, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.dut_atltool_wrapper = AtlTool(port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)
            self.lkp_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestDatapathSanity, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

            self.lkp_bin_log_file, self.lkp_txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.lkp_bin_log_file, self.test_log_dir)
            shutil.copy(self.lkp_txt_log_file, self.test_log_dir)

    def setup_speeds(self, speed):
        if self.dut_fw_card in FELICITY_CARDS or self.lkp_fw_card in FELICITY_CARDS:
            if speed == LINK_SPEED_AUTO:
                pytest.skip()
            if self.supported_speeds is None:
                raise Exception("Do not know supported speeds on Felicity")
            if speed not in self.supported_speeds:
                pytest.skip()
        else:
            if speed != LINK_SPEED_AUTO:
                if speed not in self.supported_speeds:
                    pytest.skip()

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up(retry_interval=2)
        time.sleep(self.BEFORE_PING_DELAY)

    def run_ping_test(self, speed):
        self.setup_speeds(speed)
        assert tools.ping.ping(16, self.LKP_IPV4_ADDR, payload_size=0)
        assert tools.ping.ping(16, self.LKP_IPV4_ADDR, payload_size=17000)

    def run_iperf_test(self, speed, iperf_kwargs):
        self.setup_speeds(speed)
        self.run_iperf(**iperf_kwargs)

    def test_ping_100m(self):
        """
        @description: This subtest performs ping check on 100M link speed.

        @steps:
        1. Run ping with default packet size (16 ping requests).
        2. Make sure all pings are answered.
        3. Run ping with 17000 bytes packet size (16 ping requests).
        4. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 2 minutes.
        """
        self.run_ping_test(LINK_SPEED_100M)

    def test_ping_1g(self):
        """
        @description: This subtest performs ping check on 1G link speed.

        @steps:
        1. Run ping with default packet size (16 ping requests).
        2. Make sure all pings are answered.
        3. Run ping with 17000 bytes packet size (16 ping requests).
        4. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 2 minutes.
        """
        self.run_ping_test(LINK_SPEED_1G)

    def test_ping_2_5g(self):
        """
        @description: This subtest performs ping check on 2.5G link speed.

        @steps:
        1. Run ping with default packet size (16 ping requests).
        2. Make sure all pings are answered.
        3. Run ping with 17000 bytes packet size (16 ping requests).
        4. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 2 minutes.
        """
        self.run_ping_test(LINK_SPEED_2_5G)

    def test_ping_5g(self):
        """
        @description: This subtest performs ping check on 5G link speed.

        @steps:
        1. Run ping with default packet size (16 ping requests).
        2. Make sure all pings are answered.
        3. Run ping with 17000 bytes packet size (16 ping requests).
        4. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 2 minutes.
        """
        self.run_ping_test(LINK_SPEED_5G)

    def test_ping_10g(self):
        """
        @description: This subtest performs ping check on 10G link speed.

        @steps:
        1. Run ping with default packet size (16 ping requests).
        2. Make sure all pings are answered.
        3. Run ping with 17000 bytes packet size (16 ping requests).
        4. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 2 minutes.
        """
        self.run_ping_test(LINK_SPEED_10G)

    def test_iperf_100m(self):
        """
        @description: This subtest performs bidirectional iperf check on 100M link speed.

        @steps:
        1. Run iperf server on DUT.
        2. Run iperf server on LKP.
        3. Run iperf client on DUT for 27 seconds.
        4. Run iperf client on LKP for 27 seconds.
        5. Make sure that perf exited without error.

        @result: Iperf exited without error, there are no traffic drops.
        @duration: 2 minutes.
        """
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_100M,
            'num_threads': 1,
            'num_process': 1,
            'time': 27,
            'ipv': 4,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_ptp': False,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
        }
        self.run_iperf_test(LINK_SPEED_100M, args)

    def test_iperf_1g(self):
        """
        @description: This subtest performs bidirectional iperf check on 1G link speed.

        @steps:
        1. Run iperf server on DUT.
        2. Run iperf server on LKP.
        3. Run iperf client on DUT for 27 seconds.
        4. Run iperf client on LKP for 27 seconds.
        5. Make sure that perf exited without error.

        @result: Iperf exited without error, there are no traffic drops.
        @duration: 2 minutes.
        """
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'num_threads': 1,
            'num_process': 1,
            'time': 27,
            'ipv': 4,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_ptp': False,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
        }
        self.run_iperf_test(LINK_SPEED_1G, args)

    def test_iperf_2_5g(self):
        """
        @description: This subtest performs bidirectional iperf check on 2.5G link speed.

        @steps:
        1. Run iperf server on DUT.
        2. Run iperf server on LKP.
        3. Run iperf client on DUT for 27 seconds.
        4. Run iperf client on LKP for 27 seconds.
        5. Make sure that perf exited without error.

        @result: Iperf exited without error, there are no traffic drops.
        @duration: 2 minutes.
        """
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'num_threads': 1,
            'num_process': 1,
            'time': 27,
            'ipv': 4,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_ptp': False,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
        }
        self.run_iperf_test(LINK_SPEED_2_5G, args)

    def test_iperf_5g(self):
        """
        @description: This subtest performs bidirectional iperf check on 5G link speed.

        @steps:
        1. Run iperf server on DUT.
        2. Run iperf server on LKP.
        3. Run iperf client on DUT for 27 seconds.
        4. Run iperf client on LKP for 27 seconds.
        5. Make sure that perf exited without error.

        @result: Iperf exited without error, there are no traffic drops.
        @duration: 2 minutes.
        """
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'num_threads': 1,
            'num_process': 1,
            'time': 27,
            'ipv': 4,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_ptp': False,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
        }
        self.run_iperf_test(LINK_SPEED_5G, args)

    def test_iperf_10g(self):
        """
        @description: This subtest performs bidirectional iperf check on 10G link speed.

        @steps:
        1. Run iperf server on DUT.
        2. Run iperf server on LKP.
        3. Run iperf client on DUT for 27 seconds.
        4. Run iperf client on LKP for 27 seconds.
        5. Make sure that perf exited without error.

        @result: Iperf exited without error, there are no traffic drops.
        @duration: 2 minutes.
        """
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'num_threads': 1,
            'num_process': 1,
            'time': 27,
            'ipv': 4,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_ptp': False,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
        }
        self.run_iperf_test(LINK_SPEED_10G, args)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
