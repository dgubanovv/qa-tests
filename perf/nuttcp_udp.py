import os
import pytest
import sys
import time
import numpy

if __package__ is None:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from infra.test_base import TestBase, idparametrize
from tools.utils import get_atf_logger
from tools.constants import DIRECTION_TX, DIRECTION_RXTX, DIRECTION_RX, LINK_SPEED_10G, LINK_SPEED_5G, \
                            LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M, LINK_SPEED_10M
from perf.nuttcp import Nuttcp, NuttcpResult
from tools.killer import Killer
from tools.driver import Driver

log = get_atf_logger()

NUTTCP_TIME = 20
MINIMUM_BANDWIDTH = {
                    (LINK_SPEED_10M, 1400): 5,
                    (LINK_SPEED_10M, 8000): 5,
                    (LINK_SPEED_10M, 15000): 5,
                    (LINK_SPEED_100M, 1400): 90,
                    (LINK_SPEED_100M, 8000): 90,
                    (LINK_SPEED_100M, 15000): 90,
                    (LINK_SPEED_1G, 1400): 900,
                    (LINK_SPEED_1G, 8000): 900,
                    (LINK_SPEED_1G, 15000): 900,
                    (LINK_SPEED_2_5G, 1400): 1200,
                    (LINK_SPEED_2_5G, 8000): 2100,
                    (LINK_SPEED_2_5G, 15000): 2200,
                    (LINK_SPEED_5G, 1400): 1200,
                    (LINK_SPEED_5G, 8000): 2700,
                    (LINK_SPEED_5G, 15000): 3100,
                    (LINK_SPEED_10G, 1400): 1200,
                    (LINK_SPEED_10G, 8000): 2700,
                    (LINK_SPEED_10G, 15000): 4100,
                    }


def setup_module(module):
    #import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "nuttcp_udp"


class TestNuttcpUdp(TestBase):
    """
    @description: The TestNuttcpUdp test is dedicated to verify perfomance of udp traffic
    with different parametres using nuttcp

    @setup: Two Aquantia devices connected back to back.
    """

    @classmethod
    def setup_class(cls):
        super(TestNuttcpUdp, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.log_local_dir = cls.working_dir

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.dut_driver.install()

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            cls.prev_speed = None
            cls.test_results = []
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def run_nuttcp_test(self, direction, speed, nof_threads, ipv, window_size, pkt_len):
        if speed not in self.supported_speeds:
            pytest.skip("Not supported speed")

        def kill_nuttcp():
            Killer().kill("nuttcp")
            Killer(host=self.lkp_hostname).kill("nuttcp")

        nuttcp_args = {
            'direction': direction,
            'speed': speed,
            'num_threads': nof_threads,
            "time": NUTTCP_TIME,
            'ipv': ipv,
            "bandwidth": 0,
            'dut': self.dut_hostname,
            'lkp': self.lkp_hostname,
            "dut4": self.DUT_IPV4_ADDR,
            "lkp4": self.LKP_IPV4_ADDR,
            "is_udp": True,
            "buffer_len": pkt_len,
            "window": window_size
        }

        try:
            if self.prev_speed is None or self.prev_speed != speed:
                self.dut_ifconfig.set_link_speed(speed)
                self.lkp_ifconfig.set_link_speed(speed)

                self.prev_speed = speed
                time.sleep(self.LINK_CONFIG_DELAY)

            nuttcp = Nuttcp(**nuttcp_args)
            nuttcp.run_async()
            nuttcp.join()
            bandwidth_list = nuttcp.results[0].bandwidth
            lost_list = nuttcp.results[0].lost
            average_bandwidth = "{:.1f}".format(numpy.mean(bandwidth_list))
            average_lost = "{:.1f}".format(numpy.mean(lost_list))
            log.info(NuttcpResult(bandwidth_list, lost_list))
            self.test_results.append((direction, speed, nof_threads, ipv, window_size, pkt_len,
                                      average_bandwidth, average_lost))
        except Exception as e:
            self.test_results.append((direction, speed, nof_threads, ipv, window_size, pkt_len, None, None))
            raise e

        assert all(ban > 0.75 * MINIMUM_BANDWIDTH[(speed, pkt_len)] for ban in bandwidth_list), \
            "Bandwidth less than the minimum set {}".format(MINIMUM_BANDWIDTH[(speed, pkt_len)] * 0.75)
        assert all(ban > 0.25 * max(bandwidth_list) for ban in bandwidth_list), \
            "Large performance drawdown"

    @idparametrize("pkt_len", [1400, 8000, 15000])
    @idparametrize("speed", [LINK_SPEED_10M, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    @idparametrize("t", [1, 2])
    @idparametrize("dir", [DIRECTION_TX, DIRECTION_RX, DIRECTION_RXTX])
    def test_nuttcp_udp(self, dir, speed, t, pkt_len):
        '''
        @description: Check nuttcp traffic
        @steps:
        1. Set speed.
        2. Start nuttcp with parameters
        3. Check what all bandwidth results for bandwidth list more 75% from the minimum set threshold
        4. Check what all bandwidth results for bandwidth list more 25% from maksimum of bandwidth list
        @result: Traffic is stable and above the established minimum
        @duration: 90 seconds (for each set of parameters).
        '''
        self.run_nuttcp_test(dir, speed, t, 4, '4m', pkt_len)

    def test_print_results(self):
        log.info("direction, speed, nof_threads, ipv, window_size, pkt_len, average_bandwidth, average_lost")
        for test_result in self.test_results:
            log.info(test_result)
        pass

if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
