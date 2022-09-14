from abc import ABCMeta, abstractmethod
import requests
import sys

from tools.constants import SPEED_TO_MBITS

if __package__ is None:
    import sys
    from os import path

    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

import trafficgen2
from tools.command import Command
from tools.utils import get_atf_logger

sys_stdout = sys.stdout
from scapy.all import Ether, IP, IPv6, Raw, ICMP, UDP, TCP, SCTP, Dot1Q, Padding  # Support all kinds of packets
from scapy.layers.l2 import GRE

sys.stdout = sys_stdout

log = get_atf_logger()

AUKUA_URL = 'http://aukua01/api/v1/'
AUKUA_GENERATOR_URL = AUKUA_URL + 'generators/'

BIT_TIMES_IN_QUANTA = 512

def copy_file(ifile, host, ofile):
    cmd = "sudo -u aqtest scp {} aqtest@{}:{}".format(ifile, host, ofile)
    res = Command(cmd=cmd).run()
    if res["returncode"] != 0:
        raise Exception("Failed to transfer file")


def get_protocol_by_name(name):
    if name == 'tcp':
        return TCP
    if name == 'icmp':
        return ICMP
    if name == 'udp':
        return UDP
    if name == 'sctp':
        return SCTP
    if name == 'gre':
        return GRE
    raise NotImplemented()


class Packets:
    def __init__(self, **kwargs):
        self.count = kwargs.get("count", 1)
        self.pktsize = kwargs.get("pktsize", 1500)

        self.mac_src = kwargs.get("mac_src", None)
        self.mac_dst = kwargs.get("mac_dst", None)
        self.eth_type = kwargs.get("eth_type", None)
        self.is_ipfrag = kwargs.get("ipfrag", False)
        self.padding = kwargs.get('padding', '')

        self.protocol = kwargs.get("protocol", 'tcp')
        protocol = get_protocol_by_name(self.protocol)
        self.gre = kwargs.get("gre", None)

        self.vlan_id = kwargs.get("vlan_id", None)

        self.ipv = kwargs.get("ipv", 4)
        self.ipv4_src = kwargs.get("ipv4_src", "0.0.0.0")
        self.ipv4_dst = kwargs.get("ipv4_dst", "255.255.255.255")
        self.ipv4_ttl = int(kwargs.get("ipv4_ttl", 64))

        self.ipv6_src = kwargs.get("ipv6_src", None)
        self.ipv6_dst = kwargs.get("ipv6_dst", None)
        self.chksum = kwargs.get("chksum", True)

        self.packets = []
        l2_args = {}

        if self.mac_src:
            l2_args['src'] = self.mac_src

        if self.mac_dst:
            l2_args['dst'] = self.mac_dst

        if self.eth_type:
            l2_args['type'] = self.eth_type

        l2 = Ether(**l2_args)

        if self.vlan_id:
            l2 = l2 / Dot1Q(vlan=self.vlan_id)

        ip_frag = "MF" if self.is_ipfrag else None

        l3_args_4 = {}

        if self.ipv4_src:
            l3_args_4['src'] = self.ipv4_src

        if self.ipv4_dst:
            l3_args_4['dst'] = self.ipv4_dst

        if self.ipv4_ttl:
            l3_args_4['ttl'] = self.ipv4_ttl

        if self.is_ipfrag:
            l3_args_4['flags'] = ip_frag

        l3_args_6 = {}

        if self.ipv6_src:
            l3_args_6['src'] = self.ipv6_src

        if self.ipv6_dst:
            l3_args_6['dst'] = self.ipv6_dst

        if self.ipv == 4:
            l3 = IP(**l3_args_4)
        else:
            l3 = IPv6(**l3_args_6)

        pkt = l2 / l3 / protocol()

        if self.protocol == 'gre':
            gre_ipv = self.gre["ipv"]
            gre_protocol_name = self.gre["protocol"]
            protocol = get_protocol_by_name(gre_protocol_name)

            assert gre_protocol_name != 'gre'
            if gre_ipv == 4:
                pkt = pkt / IP() / protocol()
            else:
                pkt = pkt / IPv6() / protocol()

        for _ in range(self.count):
            packet = pkt / Raw(load=('\xff' * (self.pktsize - len(pkt))))
            if len(self.padding) > 0:
                packet = packet / Padding(load=self.padding)
            if not self.chksum:
                packet.chksum = 1
            log.info(packet.summary())
            self.packets.append(packet)

        log.info('Packets: ')
        ps = self.to_str()
        ps = ps[:128] + ' ... ' + ps[-16:] if len(ps) > 128 + 64 else ps
        log.info('{:>25s} -> {} [{}]'.format('packets', ps, len(self.packets[0])))
        for k in sorted(self.__dict__.keys()):
            val = str(self.__dict__[k])
            if k != 'packets':
                log.info('{:>25s} -> {}'.format(k, val))

    def __len__(self):
        return len(self.packets)

    def __iter__(self):
        return iter(self.packets)

    def to_str(self):
        s = ''
        for p in self.packets:
            for b in str(p):
                s += "{:02x}".format(ord(b))
            s += ';'
        return s[:-1]

    @staticmethod
    def get_pause_frames_packets(quanta=0xffff, src_mac='000000000000'):
        pf = ''  # please to see: IEEE802.3X

        pf += '0180C2000001'  # dst mac address
        pf += '{}'.format(src_mac.replace(':', ''))  # src mac address
        pf += '8808'  # Ethertype
        pf += '0001'  # Mac Control Opcode
        pf += '{:04X}'.format(quanta)
        pf += '00' * 42

        return pf


def calc_pause_frames_per_second(speed, timer_in_quantas):
    bit_time = 1.0 / (SPEED_TO_MBITS[speed] * 10 ** 6)
    delta_time_between_pf = BIT_TIMES_IN_QUANTA * bit_time * timer_in_quantas
    pause_frames_per_second = int(1.0 / delta_time_between_pf)
    log.debug("1 pause frame per {} ses.".format(delta_time_between_pf))
    log.debug("Expected pause frames per second count for link speed: {} and Quanta: {:04x} is {} ".format(speed, timer_in_quantas, pause_frames_per_second))
    return pause_frames_per_second


class TrafficGen(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        name = kwargs.get("name", 'scapy')
        if name == 'pktgen':
            return object.__new__(TrafficGenPktGen)
        elif name == 'aukua':
            return object.__new__(TrafficGenAukua)
        elif name == 'scapy':
            return object.__new__(TrafficGenScapy)
        else:
            raise NotImplementedError()

    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def stop(self):
        pass


class TrafficGenScapy(TrafficGen):
    def __init__(self, **kwargs):
        super(TrafficGenScapy, self).__init__(**kwargs)
        self.host = kwargs.get("host", None)
        self.port = kwargs.get("port", 'pci1.00.0')
        self.iface = kwargs.get("iface", None)

        log.info('Creating Scapy traffic gen: {}'.format(self.__dict__))

    def start(self, **kwargs):
        self.duration = kwargs.get("duration", 0)
        self.repeat = kwargs.get("repeat", 0)
        self.delay = kwargs.get("delay", 0)
        self.packets = kwargs.get("packets", None)
        if self.iface is None:
            self.iface = kwargs.get("iface", None)
        assert self.packets is not None

        self.tg = trafficgen2.TrafficGenerator(host=self.host, port=self.port, iface=self.iface)
        s = trafficgen2.TrafficStream()

        s.duration = self.duration
        s.delay = self.delay
        s.packets = self.packets
        s.repeat = self.repeat

        self.tg.add_stream(s)
        self.tg.add_traffic_file()
        self.tg.run_async()

    def stop(self):
        self.tg.join(timeout=1)
        self.tg.remove_traffic_file()


class TrafficGenAukua(TrafficGen):
    def __init__(self, **kwargs):
        super(TrafficGenAukua, self).__init__(**kwargs)
        log.info('Creating Aukua traffic gen: {}'.format(self.__dict__))

    def start(self, **kwargs):
        pktsize = kwargs.get("pktsize", 1500)
        port = kwargs.get("port", 1)
        assert port in [1, 2]

        log.info('start Aukua traffic generator with pktsize: {} on port: {}'.format(pktsize, port))

        requests.patch(url=AUKUA_GENERATOR_URL + '{}/'.format(port), json={"minimum_packet_length": pktsize})

        requests.post(url=AUKUA_GENERATOR_URL + '{}/start/'.format(port), json={"packet_length_variation": 0,
                                                                                "maximum_duration": "65"})

    def stop(self, **kwargs):
        port = kwargs.get("port", 0)
        log.info('stop Aukua traffic generator on port: {}'.format(port))
        requests.post(url=AUKUA_GENERATOR_URL + '{}/stop/'.format(port), json={})


class TrafficGenPktGen(TrafficGen):

    def __init__(self, **kwargs):
        super(TrafficGenPktGen, self).__init__(**kwargs)
        self.threads = kwargs.get("threads", 1)
        self.host = kwargs.get("host", None)
        self.eth = kwargs.get("eth", 'enp1s0')
        self.mac = kwargs.get("mac", '30:9c:23:28:f0:84')
        Command(cmd='sudo modprobe pktgen', host=self.host).run_join(timeout=10)
        log.info('Creating PktGen traffic gen: {}'.format(self.__dict__))

    def start(self, pktsize=1500):
        log.info('start PktGen traffic generator with pktsize: {}'.format(pktsize))

        with open('traffic_gen.sh', 'w') as f:
            f.write('#!/bin/bash\n')

            f.write('echo "reset" > /proc/net/pktgen/pgctrl\n')

            f.write('echo "rem_device_all" > /proc/net/pktgen/kpktgend_0\n')
            f.write('echo "add_device {}" > /proc/net/pktgen/kpktgend_0\n'.format(self.eth))
            f.write('echo "pkt_size {}" > /proc/net/pktgen/{}\n'.format(pktsize, self.eth))
            f.write('echo "delay 0" > /proc/net/pktgen/{}\n'.format(self.eth))
            f.write('echo "count 0" > /proc/net/pktgen/{}\n'.format(self.eth))
            f.write('echo "flag NO_TIMESTAMP" > /proc/net/pktgen/{}\n'.format(self.eth))

            f.write('echo "dst_mac {}" > /proc/net/pktgen/{}\n'.format(self.mac, self.eth))

            f.write('echo "start" > /proc/net/pktgen/pgctrl\n')

        copy_file('traffic_gen.sh', self.host, '/home/aqtest/traffic_gen.sh')

        self.tg = Command(cmd='sudo /home/aqtest/traffic_gen.sh', host=self.host)
        self.tg.run_async()

    def stop(self):
        self.tg.join(timeout=1)
