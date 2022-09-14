import os
import time

import pytest
from scapy.utils import wrpcap

from dpdk_test_base import TestDPDKBase
from tools.constants import LINK_STATE_UP
from tools.prof import prof
from tools.tcpdump import Tcpdump
from trafficgen.traffic_gen import Packets
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "dpdk"


class TestDPDKGRE(TestDPDKBase):

    @classmethod
    def setup_class(cls):
        super(TestDPDKGRE, cls).setup_class()

        with prof('set variable for TestDPDKGRE'):
            cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port)
            cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)

            cls.DUT_IPV6_ADDR = cls.suggest_test_ip_address(cls.dut_port, None, True)
            cls.LKP_IPV6_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname, True)

            cls.dut_mac = cls.suggest_test_mac_address(cls.dut_port)
            cls.lkp_mac = cls.suggest_test_mac_address(cls.lkp_port, host=cls.lkp_hostname)

    def teardown_method(self, method):
        super(TestDPDKGRE, self).teardown_method(method)

    def test_gre_ipv4_detect(self):
        self.pytestpmd.exec_cmd('set fwd rxonly')
        self.pytestpmd.exec_cmd('set verbose 1')
        self.pytestpmd.exec_cmd('start port 0')

        time_to_gen = 1

        packets_args = {
            'pktsize': 128,
            'ipv': 4,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'count': 1,
            'protocol': 'gre',
            'gre': {
                'ipv': 4,
                'protocol': 'udp'
            }
        }

        args = {
            'packets': Packets(**packets_args),
            'delay': 0.1,
            'repeat': 5
        }

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.pytestpmd.wait_linkup(0)

        sniffer = Tcpdump(port=self.lkp_port, host=self.lkp_hostname, timeout=time_to_gen + 4)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        output_gre = self.pytestpmd.show_port_xstats(0)
        log.info('output_gre: {}'.format(output_gre))

        packets = sniffer.join()

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
