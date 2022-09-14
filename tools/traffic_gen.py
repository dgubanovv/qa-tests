from abc import ABCMeta, abstractmethod
import requests

from tools import trafficgen2
from tools.command import Command
from scapy.all import *

from tools.utils import get_atf_logger

log = get_atf_logger()

AUKUA_URL = 'http://aukua01/api/v1/'
AUKUA_GENERATOR_URL = AUKUA_URL + 'generators/'


def copy_file(ifile, host, ofile):
    cmd = "sudo -u aqtest scp {} aqtest@{}:{}".format(ifile, host, ofile)
    res = Command(cmd=cmd).run()
    if res["returncode"] != 0:
        raise Exception("Failed to transfer file")


class Packets:
    def __init__(self, **kwargs):
        self.count = kwargs.get("count", 1)
        self.pktsize = kwargs.get("pktsize", 1500)

        self.mac_src = kwargs.get("mac_src", None)
        self.mac_dst = kwargs.get("mac_dst", 'ff:ff:ff:ff:ff:ff')
        self.eth_type = kwargs.get("eth_type", None)
        self.is_ipfrag = kwargs.get("ipfrag", False)

        self.protocol = kwargs.get("protocol", 'tcp')
        protocol = ICMP if self.protocol == 'icmp' else TCP
        protocol = UDP if self.protocol == 'udp' else protocol
        protocol = SCTP if self.protocol == 'sctp' else protocol

        self.is_gre = kwargs.get("gre", False)

        self.vlan_id = kwargs.get("vlan_id", None)

        self.ipv4_src = kwargs.get("ipv4_src", "0.0.0.0")
        self.ipv4_dst = kwargs.get("ipv4_dst", "255.255.255.255")
        self.ipv4_ttl = int(kwargs.get("ipv4_ttl", 64))

        self.ipv6_src = kwargs.get("ipv6_src", None)
        self.ipv6_dst = kwargs.get("ipv6_dst", None)

        self.ipv = kwargs.get("ipv", 4)

        self.packets = []
        l2 = Ether(src=self.mac_src, dst=self.mac_dst, type=self.eth_type)

        if self.vlan_id:
            l2 = l2 / Dot1Q(vlan=self.vlan_id)

        ip_frag = "MF" if self.is_ipfrag else None

        if self.ipv == 4:
            l3 = IP(src=self.ipv4_src, dst=self.ipv4_dst, ttl=self.ipv4_ttl, flags=ip_frag)
        else:
            l3 = IPv6(src=self.ipv6_src, dst=self.ipv6_dst)

        pkt = l2 / l3 / protocol()

        for _ in range(self.count):
            packet = pkt / Raw(load=('\xff' * (self.pktsize - len(pkt))))
            self.packets.append(packet)

    def __len__(self):
        return len(self.packets)

    def __iter__(self):
        return iter(self.packets)


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

        log.info('Creating Scapy traffic gen: {}'.format(self.__dict__))

    def start(self, **kwargs):

        self.duration = kwargs.get("duration", 0)
        self.repeat = kwargs.get("repeat", 0)
        self.delay = kwargs.get("delay", 0)
        self.packets = kwargs.get("packets", None)
        assert self.packets != None

        for pkt in self.packets:
            log.debug(pkt.show2())

        log.info('START: {}'.format(self.__dict__))

        self.tg = trafficgen2.TrafficGenerator(host=self.host, port=self.port)
        s = trafficgen2.TrafficStream()

        s.duration = self.duration
        s.delay = self.delay
        s.packets = self.packets
        s.repeat = self.repeat

        self.tg.add_stream(s)
        self.tg.add_traffic_file()
        self.tg.run_async()

    def stop(self, **kwargs):
        log.info('STOP: {}'.format(self.__dict__))
        self.tg.join()
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

            for i in range(self.threads):
                f.write('echo "rem_device_all" > /proc/net/pktgen/kpktgend_{}\n'.format(i))
                name = self.eth if self.threads == 1 else self.eth + '@' + str(i)
                f.write('echo "add_device {}" > /proc/net/pktgen/kpktgend_{}\n'.format(name, i))
                name = self.eth if self.threads == 1 else self.eth + '\\@' + str(i)
                f.write('echo "pkt_size {}" > /proc/net/pktgen/{}\n'.format(pktsize, name))
                f.write('echo "delay 0" > /proc/net/pktgen/{}\n'.format(name))
                f.write('echo "count 0" > /proc/net/pktgen/{}\n'.format(name))
                f.write('echo "dst_mac {}" > /proc/net/pktgen/{}\n'.format(self.mac, name))

            f.write('echo "start" > /proc/net/pktgen/pgctrl\n')

        copy_file('traffic_gen.sh', self.host, '/home/aqtest/traffic_gen.sh')

        self.tg = Command(cmd='sudo /home/aqtest/traffic_gen.sh', host=self.host)
        self.tg.run_async()

    def stop(self):
        self.tg.join(1)
