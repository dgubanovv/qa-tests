import shutil

import pytest

from dpdk_test_base import TestDPDKBase
from tools.constants import LINK_SPEED_AUTO, LINK_STATE_UP
from tools.tcpdump import Tcpdump
from tools.utils import get_atf_logger
from scapy.all import *
from tools.sniffer import Sniffer
from trafficgen.traffic_gen import Packets

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "dpdk_vlan_test"


def print_dictionary_to_log(name, d):
    msg = '{}:\n'.format(name)
    for k in sorted(d.keys()):
        msg += '    {}: {}\n'.format(k, d[k])
    log.info(msg)


class TestDPDKVlan(TestDPDKBase):
    VLAN_ID_FOR_TEST = 5
    WRONG_VLAN_ID_FOR_TEST = 4

    @classmethod
    def setup_class(cls):
        super(TestDPDKVlan, cls).setup_class()

    def _send_and_receive_traffic(self, generator_args):
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig1.set_link_speed(LINK_SPEED_AUTO)

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig1.set_link_state(LINK_STATE_UP)

        time.sleep(5)

        log.debug(self.pytestpmd.wait_linkup(0))
        log.debug(self.pytestpmd.wait_linkup(1))

        self.lkp_ifconfig.wait_link_up()
        self.lkp_ifconfig1.wait_link_up()

        log.debug('>>>: show stats')
        print_dictionary_to_log('show_port_info(0)', self.pytestpmd.show_port_info(0))
        print_dictionary_to_log('show_port_info(1)', self.pytestpmd.show_port_info(1))
        print_dictionary_to_log('show_port_stats(0)', self.pytestpmd.show_port_stats(0))
        print_dictionary_to_log('show_port_stats(1)', self.pytestpmd.show_port_stats(1))
        print_dictionary_to_log('show_port_xstats(0)', self.pytestpmd.show_port_xstats(0))
        print_dictionary_to_log('show_port_xstats(1)', self.pytestpmd.show_port_xstats(1))

        self.sniffer_src = Tcpdump(host=self.lkp_hostname, port=self.lkp_port1, timeout=60)
        self.sniffer_dst = Tcpdump(host=self.lkp_hostname, port=self.lkp_port1, timeout=60)

        self.sniffer_src.run_async()
        self.sniffer_dst.run_async()
        time.sleep(30)

        self.traffic_generator.start(**generator_args)
        time.sleep(generator_args['repeat'] * generator_args['delay'] + 1)
        self.traffic_generator.stop()

        log.debug('>>>: show stats')
        print_dictionary_to_log('show_port_info(0)', self.pytestpmd.show_port_info(0))
        print_dictionary_to_log('show_port_info(1)', self.pytestpmd.show_port_info(1))
        print_dictionary_to_log('show_port_stats(0)', self.pytestpmd.show_port_stats(0))
        print_dictionary_to_log('show_port_stats(1)', self.pytestpmd.show_port_stats(1))
        print_dictionary_to_log('show_port_xstats(0)', self.pytestpmd.show_port_xstats(0))
        print_dictionary_to_log('show_port_xstats(1)', self.pytestpmd.show_port_xstats(1))

        packets_src = self.sniffer_src.join(30)
        packets_dst = self.sniffer_dst.join(30)
        wrpcap("packets_src.pcap", packets_src)
        wrpcap("packets_dst.pcap", packets_dst)
        shutil.move("packets_src.pcap", self.test_log_dir)
        shutil.move("packets_dst.pcap", self.test_log_dir)
        log.info('packets_src.pcap has {} packets'.format(len(packets_src)))
        log.info('packets_dst.pcap has {} packets'.format(len(packets_dst)))

        mac_src = generator_args['packets'].mac_src
        mac_dst = generator_args['packets'].mac_dst

        packets_src = [p for p in packets_src if p.src == mac_dst and p.dst == mac_src]
        packets_dst = [p for p in packets_dst if p.src == mac_dst and p.dst == mac_src]
        #packets_dst = [p for p in packets_dst if p.src == mac_dst and p.dst == mac_src]

        wrpcap("packets_filtered_src.pcap", packets_src)
        wrpcap("packets_filtered_dst.pcap", packets_dst)
        shutil.move("packets_filtered_src.pcap", self.test_log_dir)
        shutil.move("packets_filtered_dst.pcap", self.test_log_dir)

        return packets_src, packets_dst

    def test_vlan_strip_on(self):
        self.pytestpmd.exec_cmd('stop')
        self.pytestpmd.exec_cmd('port stop all')
        self.pytestpmd.exec_cmd('set fwd macswap')
        self.pytestpmd.exec_cmd('port start all')
        self.pytestpmd.exec_cmd('vlan set filter off 0')
        self.pytestpmd.exec_cmd('vlan set strip on 0')
        self.pytestpmd.exec_cmd('vlan set stripq on 0,0')
        self.pytestpmd.exec_cmd('start')

        packets_args = {
            'eth_type': 0x8100,
            'mac_src': self.machines['lkp']['mac0'],
            'mac_dst': self.machines['dut']['mac0'],
            'pktsize': 128,
            'protocol': 'icmp',
            'vlan_id': self.VLAN_ID_FOR_TEST
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'repeat': 10,
            'delay': 0.1,
            'iface': self.lkp_scapy_iface
        }

        packets_src, packets_dst = self._send_and_receive_traffic(generator_args)

        assert all(p.haslayer(Dot1Q) == 0 for p in packets_dst), "Vlan packets were received, but should not."
        assert len(packets_src) == generator_args['repeat'], 'Packets can not be send'
        assert len(packets_dst) == generator_args['repeat'], 'Packets loss'

    def test_vlan_strip_off(self):
        self.pytestpmd.exec_cmd('stop')
        self.pytestpmd.exec_cmd('port stop all')
        self.pytestpmd.exec_cmd('set fwd macswap')
        self.pytestpmd.exec_cmd('port start all')
        self.pytestpmd.exec_cmd('vlan set filter off all')
        self.pytestpmd.exec_cmd('vlan set strip off all')
        self.pytestpmd.exec_cmd('start')

        packets_args = {
            'eth_type': 0x8100,
            'ipv4_src': self.LKP_IP,
            'mac_src': self.machines['lkp']['mac0'],
            'mac_dst': self.machines['dut']['mac0'],
            'pktsize': 101,
            'protocol': 'icmp',
            'vlan_id': self.VLAN_ID_FOR_TEST
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'repeat': 10,
            'delay': 0.1,
            'iface': self.lkp_scapy_iface
        }

        packets_src, packets_dst = self._send_and_receive_traffic(generator_args)

        assert all(p.haslayer(Dot1Q) == 1 for p in packets_dst), "Vlan packets were received, but should not."
        assert len(packets_src) == generator_args['repeat'], 'Packets can not be send'
        assert len(packets_dst) == generator_args['repeat'], 'Packets loss'

    def test_vlan_create_vlan_tag_on_tx(self):
        self.pytestpmd.exec_cmd('stop')
        self.pytestpmd.exec_cmd('port stop all')
        self.pytestpmd.exec_cmd('set fwd macswap')
        self.pytestpmd.exec_cmd('vlan set filter off 0')
        self.pytestpmd.exec_cmd('tx_vlan reset 1')
        self.pytestpmd.exec_cmd('tx_vlan set 1 {}'.format(self.VLAN_ID_FOR_TEST))
        self.pytestpmd.exec_cmd('port start all')
        self.pytestpmd.exec_cmd('start')

        packets_args = {
            'eth_type': 0x0800,
            'ipv4_src': self.LKP_IP,
            'mac_src': self.machines['lkp']['mac0'],
            'mac_dst': self.machines['dut']['mac0'],
            'pktsize': 128,
            'protocol': 'icmp',
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'repeat': 10,
            'delay': 0.1,
            'iface': self.lkp_scapy_iface
        }

        packets_src, packets_dst = self._send_and_receive_traffic(generator_args)

        assert all(p.haslayer(Dot1Q) == 1 for p in packets_dst), "Vlan packets were received, but should not."
        assert len(packets_src) == generator_args['repeat'], 'Packets can not be send'
        assert len(packets_dst) == generator_args['repeat'], 'Packets loss'

    def test_vlan_in_filter(self):
        self.pytestpmd.exec_cmd('stop')
        self.pytestpmd.exec_cmd('port stop all')
        self.pytestpmd.exec_cmd('set fwd macswap')
        self.pytestpmd.exec_cmd('port start all')
        self.pytestpmd.exec_cmd('vlan set filter on 0')
        self.pytestpmd.exec_cmd('vlan set inner tpid {} 0'.format(self.VLAN_ID_FOR_TEST))
        self.pytestpmd.exec_cmd('start')

        packets_args = {
            'eth_type': 0x8100,
            'ipv4_src': self.LKP_IP,
            'mac_src': self.machines['lkp']['mac0'],
            'mac_dst': self.machines['dut']['mac0'],
            'pktsize': 101,
            'protocol': 'icmp',
            'vlan_id': self.VLAN_ID_FOR_TEST
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'repeat': 10,
            'delay': 0.1,
            'iface': self.lkp_scapy_iface
        }

        packets_src, packets_dst = self._send_and_receive_traffic(generator_args)

        assert all(p.haslayer(Dot1Q) == 0 for p in packets_dst), "Vlan packets were received, but should not."

    def test_vlan_out_filter(self):
        self.pytestpmd.exec_cmd('stop')
        self.pytestpmd.exec_cmd('port stop all')
        self.pytestpmd.exec_cmd('set fwd macswap')
        self.pytestpmd.exec_cmd('port start all')
        self.pytestpmd.exec_cmd('vlan set filter on 1')
        self.pytestpmd.exec_cmd('vlan set outer tpid {} 1'.format(self.VLAN_ID_FOR_TEST))
        self.pytestpmd.exec_cmd('start')

        packets_args = {
            'eth_type': 0x8100,
            'ipv4_src': self.LKP_IP,
            'mac_src': self.machines['lkp']['mac0'],
            'mac_dst': self.machines['dut']['mac0'],
            'pktsize': 101,
            'protocol': 'icmp',
            'vlan_id': self.VLAN_ID_FOR_TEST
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'repeat': 10,
            'delay': 0.1,
            'iface': self.lkp_scapy_iface
        }

        packets_src, packets_dst = self._send_and_receive_traffic(generator_args)

        assert all(p.haslayer(Dot1Q) == 0 for p in packets_dst), "Vlan packets were received, but should not."


    def test_vlan_rx_add_correct_id(self):
        self.pytestpmd.exec_cmd('port stop all')
        self.pytestpmd.exec_cmd('set fwd macswap')
        self.pytestpmd.exec_cmd('port start all')
        self.pytestpmd.exec_cmd('vlan set filter on 0')
        self.pytestpmd.exec_cmd('rx_vlan add {} 0'.format(self.VLAN_ID_FOR_TEST))
        self.pytestpmd.exec_cmd('start')

        packets_args = {
            'eth_type': 0x8100,
            'ipv4_src': self.LKP_IP,
            'mac_src': self.machines['lkp']['mac0'],
            'mac_dst': self.machines['dut']['mac0'],
            'pktsize': 128,
            'protocol': 'icmp',
            'vlan_id': self.VLAN_ID_FOR_TEST
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'repeat': 10,
            'delay': 0.1,
            'iface': self.lkp_scapy_iface
        }

        packets_src, packets_dst = self._send_and_receive_traffic(generator_args)

        assert all(p.haslayer(Dot1Q) == 1 for p in packets_dst), "Vlan packets were received, but should not."

    def test_vlan_rx_add_wrong_id(self):
        self.pytestpmd.exec_cmd('port stop all')
        self.pytestpmd.exec_cmd('set fwd macswap')
        self.pytestpmd.exec_cmd('port start all')
        self.pytestpmd.exec_cmd('vlan set filter on 0')
        self.pytestpmd.exec_cmd('rx_vlan add {} 0'.format(self.WRONG_VLAN_ID_FOR_TEST))
        self.pytestpmd.exec_cmd('start')

        packets_args = {
            'eth_type': 0x8100,
            'ipv4_src': self.LKP_IP,
            'mac_src': self.machines['lkp']['mac0'],
            'mac_dst': self.machines['dut']['mac0'],
            'pktsize': 101,
            'protocol': 'icmp',
            'vlan_id': self.VLAN_ID_FOR_TEST
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'repeat': 10,
            'delay': 0.1,
            'iface': self.lkp_scapy_iface
        }

        packets_src, packets_dst = self._send_and_receive_traffic(generator_args)

        assert all(p.haslayer(Dot1Q) == 0 for p in packets_dst), "Vlan packets were received, but should not."

if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
