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

    def test_iperf_tcp_10000m_full_duplex_rxtx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_rxtx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_rxtx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_rxtx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_rxtx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_rxtx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_rxtx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_rxtx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_tx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_tx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_tx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_tx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_tx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_tx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_tx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_tx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_rx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_rx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_rx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_rx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_rx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_rx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_rx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10000m_full_duplex_rx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_rxtx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_rxtx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_rxtx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_rxtx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_rxtx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_rxtx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_rxtx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_rxtx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_tx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_tx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_tx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_tx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_tx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_tx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_tx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_tx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_rx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_rx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_rx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_rx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_rx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_rx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_5000m_full_duplex_rx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_rx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_2500m_full_duplex_rxtx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_2500m_full_duplex_rxtx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_2500m_full_duplex_tx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_2_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_2500m_full_duplex_tx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_2_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_2500m_full_duplex_rx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_2_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_2500m_full_duplex_rx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_2_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_full_duplex_rxtx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_full_duplex_rxtx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_full_duplex_tx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_full_duplex_tx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_full_duplex_rx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_full_duplex_rx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_half_duplex_rxtx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_half_duplex_rxtx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_half_duplex_tx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_half_duplex_tx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_half_duplex_rx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_half_duplex_rx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_full_duplex_rxtx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_full_duplex_rxtx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_full_duplex_tx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_full_duplex_tx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_full_duplex_rx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_full_duplex_rx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_half_duplex_rxtx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_half_duplex_rxtx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_half_duplex_tx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_half_duplex_tx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_half_duplex_rx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_100m_half_duplex_rx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_rxtx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_rxtx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_rxtx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_rxtx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_rxtx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_rxtx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_rxtx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_rxtx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_tx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_tx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_tx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_tx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_tx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_tx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_tx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_tx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_rx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_rx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_rx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_rx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_rx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_rx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_full_duplex_rx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_rx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_rxtx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_rxtx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_rxtx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_rxtx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_rxtx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_rxtx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_rxtx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_rxtx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_tx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_tx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_tx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_tx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_tx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_tx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_tx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_tx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_TX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_rx_p1_t1_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_rx_p1_t1_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_rx_p1_t1_v4_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_rx_p1_t1_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_rx_p1_t4_v4_w8k_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_rx_p1_t4_v4_w8k(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': "8k",
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10m_half_duplex_rx_p1_t4_v4_fc(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_half_duplex_rx_p1_t4_v4(self):
        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_HALF,
            'num_process': 1,
            'num_threads': 4,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 0,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_1000m_full_duplex_rxtx_p1_t1_v6_l1000_fc(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 6,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_1000m_full_duplex_rxtx_p1_t1_v6_l1000(self):
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 6,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }
        self.iperf(**args)

    def test_iperf_tcp_10000m_full_duplex_rxtx_p1_t1_v4_l1000_fc(self):
        self.dut_ifconfig.set_mtu(MTU_9000)
        self.lkp_ifconfig.set_mtu(MTU_9000)
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_5000m_full_duplex_rxtx_p1_t1_v4_l1000_fc(self):
        self.dut_ifconfig.set_mtu(MTU_9000)
        self.lkp_ifconfig.set_mtu(MTU_9000)
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_2500m_full_duplex_rxtx_p1_t1_v4_l1000_fc(self):
        self.dut_ifconfig.set_mtu(MTU_9000)
        self.lkp_ifconfig.set_mtu(MTU_9000)
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_2_5G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_1000m_full_duplex_rxtx_p1_t1_v4_l1000_fc(self):
        self.dut_ifconfig.set_mtu(MTU_9000)
        self.lkp_ifconfig.set_mtu(MTU_9000)
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_100m_full_duplex_rxtx_p1_t1_v4_l1000_fc(self):
        self.dut_ifconfig.set_mtu(MTU_9000)
        self.lkp_ifconfig.set_mtu(MTU_9000)
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_100M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_10m_full_duplex_rxtx_p1_t1_v4_l1000_fc(self):
        self.dut_ifconfig.set_mtu(MTU_9000)
        self.lkp_ifconfig.set_mtu(MTU_9000)
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10M,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_1000m_full_duplex_rxtx_p1_t1_v4_l1000_w5k_fc(self):
        self.dut_ifconfig.set_mtu(MTU_9000)
        self.lkp_ifconfig.set_mtu(MTU_9000)
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': "5k",
            'is_udp': False,
            'is_eee': False,
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

    def test_iperf_tcp_1000m_full_duplex_rxtx_p1_t1_v4_l1000_w10k_fc(self):
        self.dut_ifconfig.set_mtu(MTU_9000)
        self.lkp_ifconfig.set_mtu(MTU_9000)
        args = {
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': "10k",
            'is_udp': False,
            'is_eee': False,
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

    @idparametrize("mtu", [MTU_1500, MTU_2000, MTU_4000, MTU_9000, MTU_16000])
    def test_workaround_checksum(self, mtu):
        if self.dut_fw_card in CARD_FIJI or self.lkp_fw_card in CARD_FIJI:
            pytest.skip("Skip for Fiji")

        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu)

        CHECKSUM = "checksum"
        LSO = "lso"
        LRO = 'lro'
        OFFLOADS_LKP = [CHECKSUM, LSO]
        
        def select_offload(ops, map_ofl, offload_name):
            if ops.is_windows():
                return map_ofl["Windows"][offload_name]
            elif ops.is_linux():
                return map_ofl["Linux"][offload_name]
            elif ops.is_freebsd():
                return map_ofl["FreeBSD"][offload_name]
        
        def get_offload_for_os(offload_name):
            map_ofl = {"Windows": {CHECKSUM: ["*TCPUDPChecksumOffloadIPv4", "*TCPUDPChecksumOffloadIPv6",
                                              "*IPChecksumOffloadIPv4", "*TCPChecksumOffloadIPv4",
                                              "*UDPChecksumOffloadIPv4", "*TCPChecksumOffloadIPv6",
                                              "*UDPChecksumOffloadIPv6"],
                                   LSO: ["*LsoV1IPv4", "*LsoV2IPv4", "*LsoV2IPv6"],
                                   LRO: [None]},

                       "Linux": {CHECKSUM: ["tx", "rx"],
                                 LSO: ["tso"],
                                 LRO: ["lro"]},
                       "FreeBSD": {CHECKSUM: ["txcsum", "rxcsum"],
                                   LSO: ["lso"],}
                                 }
            if offload_name == LRO:
                offload = select_offload(self.dut_ops, map_ofl, offload_name)
            else:
                offload = select_offload(self.lkp_ops, map_ofl, offload_name)
            return offload

        for offload in OFFLOADS_LKP:
            for offload_name in get_offload_for_os(offload):
                self.lkp_ifconfig.manage_offloads(offload_name, OFFLOADS_STATE_DSBL)
        for offload_name in get_offload_for_os(LRO):
            if offload_name is not None:
                self.dut_ifconfig.manage_offloads(offload_name, OFFLOADS_STATE_ENBL)

        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 6,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }

        self.iperf(**args)

    # total tests: 141


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
