import multiprocessing
import os
import shutil
import time

import pytest
from scapy.utils import wrpcap

from dpdk_test_base import TestDPDKBase
from tools.sniffer import Sniffer
from trafficgen.traffic_gen import Packets
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "dpdk"


def print_dictionary_to_log(name, d):
    msg = '{}:\n'.format(name)
    for k in sorted(d.keys()):
        msg += '    {}: {}\n'.format(k, d[k])
    log.info(msg)


class TestDPDKSanity(TestDPDKBase):

    @classmethod
    def setup_class(cls):
        super(TestDPDKSanity, cls).setup_class()

    def test_testsute_hello_world(self):
        result = self.run_app(command='./examples/dpdk-helloworld', params_pmd='', params='')

        # parce output
        output = result['output']
        count = 0
        for line in output:
            if 'hello from core' in line:
                count += 1

        assert result['returncode'] == 0
        assert count == multiprocessing.cpu_count()

    def test_testsute_statistics(self):
        packets_args = {
            'pktsize': 1500,
            'protocol': 'udp'
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'duration': 5,
            'delay': 0.05
        }

        self.pytestpmd.exec_cmd('port start all')
        self.pytestpmd.exec_cmd('show port xstats all')
        self.pytestpmd.exec_cmd('start')

        self.pytestpmd.wait_linkup(0)

        time.sleep(1)
        self.traffic_generator.start(**generator_args)
        time.sleep(5)
        self.traffic_generator.stop()
        time.sleep(5)

        stat_after = self.pytestpmd.show_port_xstats(0)
        self.pytestpmd.exec_cmd('stop')

        print_dictionary_to_log('stat_after', stat_after)
        print_dictionary_to_log('show_port_xstats(0)', self.pytestpmd.show_port_xstats(0))
        print_dictionary_to_log('show_port_xstats(1)', self.pytestpmd.show_port_xstats(1))

        assert stat_after['rx_good_bytes'] > 1

    def test_testsute_validate_checksum_rx(self):
        packets_args = {
            'pktsize': 1000,
            'protocal': 'tcp',
            'chksum': True
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'duration': 5,
            'delay': 0.1
        }

        self.pytestpmd.exec_cmd('set fwd csum')
        self.pytestpmd.exec_cmd('port start all')

        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.sniffer = Sniffer(port=self.lkp_port1, timeout=10, host=self.lkp_hostname)
        self.sniffer.run_async(iface=self.lkp_scapy_iface)

        self.traffic_generator.start(**generator_args)
        time.sleep(5)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_stats(0)
        print_dictionary_to_log('show_port_stats(0)', output)

        packets = self.sniffer.join(10)
        wrpcap("packets.pcap", packets)
        shutil.move("packets.pcap", self.test_log_dir)

        assert output['rx_good_packets'] > 0
        assert output['rx_errors'] == 0

    def test_testsute_validate_checksum_rx_with_no_zero_padding(self):
        packets_args = {
            'pktsize': 60,
            'protocal': 'tcp',
            'padding': '\x66' * 10,
            'chksum': True
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'duration': 5,
            'delay': 0.1
        }

        self.pytestpmd.exec_cmd('set fwd csum')
        self.pytestpmd.exec_cmd('port start all')

        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.sniffer = Sniffer(port=self.lkp_port1, timeout=10, host=self.lkp_hostname)
        self.sniffer.run_async(iface=self.lkp_scapy_iface)

        self.traffic_generator.start(**generator_args)
        time.sleep(5)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_stats(0)
        print_dictionary_to_log('show_port_stats(0)', output)

        packets = self.sniffer.join(10)
        wrpcap("packets.pcap", packets)
        shutil.move("packets.pcap", self.test_log_dir)

        assert output['rx_good_packets'] > 0
        assert output['rx_errors'] == 0

    def test_testsute_novalidate_checksum_rx(self):
        packets_args = {
            'pktsize': 1000,
            'protocal': 'tcp',
            'chksum': False
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'duration': 5,
            'delay': 0.1
        }

        self.pytestpmd.exec_cmd('set fwd csum')
        self.pytestpmd.exec_cmd('port start all')

        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.sniffer = Sniffer(port=self.lkp_port1, timeout=10, host=self.lkp_hostname)
        self.sniffer.run_async(iface=self.lkp_scapy_iface)

        self.traffic_generator.start(**generator_args)
        time.sleep(5)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_stats(0)
        print_dictionary_to_log('show_port_stats(0)', output)

        packets = self.sniffer.join(10)
        wrpcap("packets.pcap", packets)
        shutil.move("packets.pcap", self.test_log_dir)

        assert output['rx_good_packets'] > 0
        assert output['rx_errors'] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
