import os
import shutil
import time

import pytest

if __package__ is None:
    import sys
    from os import path

    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from tools.scapy_tools import ScapyTools
from infra.test_base import TestBase
from tools.ops import OpSystem
from tools.driver import Driver
from tools.prof import prof
from tools.tcpdump import Tcpdump
from tools.utils import get_atf_logger, get_compressed_ipv6
from traffic_gen import Packets, TrafficGen, get_protocol_by_name
from tools.constants import MTU_16000
import sys

sys_stdout = sys.stdout
from scapy.all import wrpcap, IP, IPv6, TCP, UDP, ICMP, SCTP, Dot1Q

sys.stdout = sys_stdout

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "traffic_gen"


def packet_filter(packets, packets_args):
    packets_filtered = []

    for pkt in packets:
        shift = 1
        accept = True

        if 'vlan_id' in packets_args.keys():
            accept = accept and isinstance(pkt.getlayer(shift), Dot1Q)
            shift += 1

        if packets_args['ipv'] == 4:
            accept = accept and isinstance(pkt.getlayer(shift), IP)
        else:
            accept = accept and isinstance(pkt.getlayer(shift), IPv6)

        if not accept:
            continue

        accept = accept and pkt.getlayer(shift).src == packets_args['ipv{}_src'.format(packets_args['ipv'])]
        accept = accept and pkt.getlayer(shift).dst == packets_args['ipv{}_dst'.format(packets_args['ipv'])]

        shift += 1

        accept = accept and isinstance(pkt.getlayer(shift), get_protocol_by_name(packets_args['protocol']))

        if accept:
            packets_filtered.append(pkt)

    return packets_filtered

class TestTrafficGen(TestBase):

    @classmethod
    def setup_class(cls):
        super(TestTrafficGen, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.log_local_dir = cls.working_dir

            with prof('install_firmwares'):
                cls.install_firmwares()

            with prof('dut.driver.install'):
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
                cls.dut_driver.install()

            with prof('lkp.driver.install'):
                cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
                cls.lkp_driver.install()

            with prof('set variable for TestIperfBase'):
                cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port)
                cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)

                cls.DUT_IPV6_ADDR = cls.suggest_test_ip_address(cls.dut_port, None, True)
                cls.LKP_IPV6_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname, True)

                cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
                cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)

                cls.dut_ifconfig.set_ipv6_address(cls.DUT_IPV6_ADDR, cls.DEFAULT_PREFIX_IPV6, None)
                cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IPV6_ADDR, cls.DEFAULT_PREFIX_IPV6, None)

                cls.dut_mac = cls.suggest_test_mac_address(cls.dut_port)
                cls.lkp_mac = cls.suggest_test_mac_address(cls.lkp_port, host=cls.lkp_hostname)

            traffic_gen_name = os.environ.get("TRAFFIC_GEN", 'scapy')  # [pktgen, aukua, scapy]

            cls.dut_scapy_tools = ScapyTools(port=cls.dut_port)
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.dut_iface = cls.dut_scapy_tools.get_scapy_iface()
            cls.lkp_iface = cls.lkp_scapy_tools.get_scapy_iface()

            args = {
                'host': cls.lkp_hostname,
                'port': cls.lkp_port,
                'iface': cls.lkp_iface
            }

            cls.traffic_generator = TrafficGen(name=traffic_gen_name, **args)
            cls.lkp_ifconfig.set_mtu(MTU_16000)

            log.debug('traffic gen: {}\t{}'.format(traffic_gen_name, args))

            cls.dut_ops = OpSystem()
            cls.lkp_ops = OpSystem(host=cls.lkp_hostname)

            if cls.dut_ops.is_windows() or cls.lkp_ops.is_windows():
                time.sleep(30)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def public_file(self, file):
        log.info('public: {} --> {}'.format(file, self.test_log_dir))
        shutil.move(file, self.test_log_dir)

    def test_traffic_gen_send_one_packet_v4(self):
        time_to_gen = 1

        packets_args = {
            'pktsize': 128,
            'count': 1,
            'ipv': 4,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'protocol': 'udp'
        }

        args = {
            'packets': Packets(**packets_args),
            'repeat': 1
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 4)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_two_packet_v6(self):
        time_to_gen = 1

        packets_args = {
            'pktsize': 256,
            'count': 1,
            'ipv': 6,
            'ipv6_src': get_compressed_ipv6(self.LKP_IPV6_ADDR),
            'ipv6_dst': get_compressed_ipv6(self.DUT_IPV6_ADDR),
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'protocol': 'tcp'
        }

        args = {
            'packets': Packets(**packets_args),
            'repeat': 2
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 4)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_two_packet_with_vlan(self):
        time_to_gen = 2

        packets_args = {
            'pktsize': 1024,
            'ipv': 4,
            'count': 1,
            'vlan_id': 2,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'protocol': 'udp'
        }

        args = {
            'packets': Packets(**packets_args),
            'repeat': 4
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 6)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_several_packets(self):
        time_to_gen = 1

        packets_args = {
            'pktsize': 64,
            'ipv': 4,
            'count': 2,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'protocol': 'icmp'
        }

        args = {
            'packets': Packets(**packets_args),
            'repeat': 5
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 9)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_tcp_packets(self):
        time_to_gen = 1

        packets_args = {
            'pktsize': 128,
            'ipv': 6,
            'count': 1,
            'ipv6_src': get_compressed_ipv6(self.LKP_IPV6_ADDR),
            'ipv6_dst': get_compressed_ipv6(self.DUT_IPV6_ADDR),
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'protocol': 'tcp'
        }

        args = {
            'packets': Packets(**packets_args),
            'repeat': 13
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 1)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_udp_packets(self):
        time_to_gen = 1

        packets_args = {
            'pktsize': 128,
            'ipv': 4,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'count': 5,
            'protocol': 'udp'
        }

        args = {
            'packets': Packets(**packets_args),
            'repeat': 5,
            'delay': 0.05
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 1)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_icmp_packets(self):
        time_to_gen = 1

        packets_args = {
            'pktsize': 128,
            'ipv': 4,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'count': 10,
            'protocol': 'icmp'
        }

        args = {
            'packets': Packets(**packets_args),
            'delay': 0.05,
            'repeat': 2
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 1)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_gre_packets(self):
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

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 1)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']


    def test_traffic_gen_send_sctp_packets_v4(self):
        time_to_gen = 5

        packets_args = {
            'pktsize': 64,
            'ipv': 4,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'count': 5,
            'protocol': 'sctp'
        }

        args = {
            'packets': Packets(**packets_args),
            'delay': 0.01,
            'repeat': 100
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 5)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_sctp_packets_v6(self):
        time_to_gen = 3

        packets_args = {
            'pktsize': 64,
            'ipv': 6,
            'ipv6_src': get_compressed_ipv6(self.LKP_IPV6_ADDR),
            'ipv6_dst': get_compressed_ipv6(self.DUT_IPV6_ADDR),
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'count': 2,
            'protocol': 'sctp'
        }

        args = {
            'packets': Packets(**packets_args),
            'delay': 0.01,
            'repeat': 100
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 2)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_tcp_packets_1400(self):
        time_to_gen = 1

        packets_args = {
            'pktsize': 1400,
            'count': 1,
            'ipv': 4,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'protocol': 'tcp'
        }

        args = {
            'packets': Packets(**packets_args),
            'repeat': 55
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 4)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_tcp_packets_9400(self):
        time_to_gen = 3

        packets_args = {
            'pktsize': 9400,
            'count': 1,
            'ipv': 4,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'protocol': 'tcp'
        }

        args = {
            'packets': Packets(**packets_args),
            'repeat': 100,
            'delay': 0.01
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 2)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_ten_frag_packets(self):
        time_to_gen = 1

        packets_args = {
            'pktsize': 11000,
            'count': 1,
            'ipv': 4,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'ipfrag': True,
            'protocol': 'udp'
        }

        args = {
            'packets': Packets(**packets_args),
            'repeat': 10
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 4)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_large_of_packets(self):
        time_to_gen = 2

        packets_args = {
            'pktsize': 64,
            'count': 1,
            'ipv': 4,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'protocol': 'udp'
        }

        args = {
            'packets': Packets(**packets_args),
            'repeat': 999
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 3)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: {}'.format(args['repeat'] * packets_args['count']))

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) == args['repeat'] * packets_args['count']

    def test_traffic_gen_send_a_lot_of_packets(self):
        time_to_gen = 2

        packets_args = {
            'pktsize': 64,
            'ipv': 4,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'count': 1,
            'protocol': 'tcp'
        }

        args = {
            'packets': Packets(**packets_args),
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 3)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: >1000')

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) > 1000

    def test_traffic_gen_send_a_lot_of_packets_v6(self):
        time_to_gen = 1

        packets_args = {
            'pktsize': 99,
            'ipv': 6,
            'ipv6_src': get_compressed_ipv6(self.LKP_IPV6_ADDR),
            'ipv6_dst': get_compressed_ipv6(self.DUT_IPV6_ADDR),
            'mac_src': self.lkp_mac,
            'mac_dst': self.dut_mac,
            'count': 8,
            'protocol': 'udp'
        }

        args = {
            'packets': Packets(**packets_args),
        }

        sniffer = Tcpdump(port=self.dut_port, timeout=time_to_gen + 2)
        sniffer.run_async()

        self.traffic_generator.start(**args)
        time.sleep(time_to_gen)
        self.traffic_generator.stop()

        packets = sniffer.join()

        packets_filtered = packet_filter(packets, packets_args)

        log.info('all packets: {}'.format(len(packets)))
        log.info('filter pkts: {}'.format(len(packets_filtered)))
        log.info('    must be: >666')

        wrpcap("packets.pcap", packets)
        self.public_file("packets.pcap")

        wrpcap("packets_filtered.pcap", packets_filtered)
        self.public_file("packets_filtered.pcap")

        assert len(packets_filtered) > 666


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
