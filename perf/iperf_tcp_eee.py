import pytest

from iperf_test_base import TestIperfBase
from infra.test_base import idparametrize
from scapy.all import *
from iperf_result import IperfResult
from tools.constants import DIRECTION_RXTX, LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, \
    LINK_SPEED_1G, LINK_SPEED_100M, LINK_SPEED_10M, DIRECTION_TX, DIRECTION_RX, OFFLOADS_STATE_DSBL, OFFLOADS_STATE_ENBL, \
    CARD_FIJI, MTU_1500, MTU_2000, MTU_4000, MTU_9000, MTU_16000, DUPLEX_HALF, DUPLEX_FULL
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "iperf"


class TestIperf(TestIperfBase):

    def test_iperf_tcp_eee_10000m_full_duplex_rxtx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_10000m_full_duplex_rxtx_p1_t4_v4_w4k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "4k",
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_10000m_full_duplex_rxtx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_5000m_full_duplex_rxtx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_5000m_full_duplex_rxtx_p1_t4_v4_w4k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "4k",
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_5000m_full_duplex_rxtx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_2500m_full_duplex_rxtx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_2500m_full_duplex_rxtx_p1_t4_v4_w4k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "4k",
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_2500m_full_duplex_rxtx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_1000m_full_duplex_rxtx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_1000m_full_duplex_rxtx_p1_t4_v4_w4k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "4k",
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_1000m_full_duplex_rxtx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_1000m_half_duplex_rxtx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_1000m_half_duplex_rxtx_p1_t4_v4_w4k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "4k",
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_eee_1000m_half_duplex_rxtx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 183,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': True,
            'is_fc': True,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    # total tests: 15


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
