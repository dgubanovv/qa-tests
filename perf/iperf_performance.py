import os
import pytest
from iperf_test_base import TestIperfBase
from perf.iperf_result import IperfResult

if __package__ is None:
    import sys
    from os import path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))


from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, \
    DIRECTION_RXTX
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "iperf"


class TestIperf(TestIperfBase):

    # count: 34
    def test_iperf_udp_10000m_rxtx_p1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_10000m_rxtx_p1_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_10000m_rxtx_p4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_10000m_rxtx_p4_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_5000m_rxtx_p1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_5000m_rxtx_p1_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_5000m_rxtx_p4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_5000m_rxtx_p4_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_2500m_rxtx_p1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_2500m_rxtx_p1_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_2500m_rxtx_p4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_2500m_rxtx_p4_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_eee_1000m_rxtx_p1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': True,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_eee_1000m_rxtx_p1_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': True,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_1000m_rxtx_p4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_1000m_rxtx_p4_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_rxtx_p1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_rxtx_p1_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_rxtx_p4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_rxtx_p4_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_rxtx_p1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_rxtx_p1_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_rxtx_p4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_rxtx_p4_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_2500m_rxtx_p1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_2500m_rxtx_p1_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_2500m_rxtx_p4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_2500m_rxtx_p4_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_1000m_rxtx_p1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_1000m_rxtx_p1_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'num_process': 1,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_rxtx_p4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_rxtx_p4_v4_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'num_process': 4,
            'time': 314,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_udp_5000m_rxtx_p16_v6_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'num_process': 16,
            'time': 314,
            'ipv': 6,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_rxtx_p16_v6_w8192_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'num_process': 16,
            'time': 314,
            'ipv': 6,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 8192,
            'is_udp': False,
            'is_eee': False,
            'is_fc': True,
            'criterion': IperfResult.PERFORMANCE,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
