import itertools
import os
import shutil
import sys
import time

import ipaddress
import pytest
from scapy.all import Ether, Dot1Q, IP, IPv6, UDP, TCP, SCTP
from scapy.utils import wrpcap

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from infra.test_base import TestBase
from tools.aqpkt import Aqsendp
from tools.command import Command
from tools.constants import LINK_STATE_UP, CARD_ANTIGUA
from tools.driver import Driver
from tools.ops import OpSystem
from tools.tcpdump import Tcpdump
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_ntuple_filters"


class TestDrvFilters(TestBase):
    L3L4_LOCATION = 32
    ETHERTYPE_LOCATION = 16
    VLAN_LOCATION = 0

    def setup_class(cls):
        super(TestDrvFilters, cls).setup_class()
        try:
            # Self protection, the test is implemented only for Linux
            assert OpSystem().is_linux()
            assert OpSystem(host=cls.lkp_hostname).is_linux()

            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.dut_ifconfig.wait_link_up()

            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.dut_iface = cls.dut_ifconfig.get_conn_name()
            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()

            # get rings number
            res = Command(cmd="ethtool -x {} | grep indirection | awk '{{print $9}}'".format(cls.dut_iface)).run()
            cls.rings = int(res['output'][0])
            log.debug("receiver has {} rings".format(cls.rings))

            # set RSS to route all traffic to queue 0
            weights = [1] + [0] * (cls.rings - 1)
            log.info("Set weights table: %s" % weights)
            Command(cmd="ethtool -X {} weight {}".format(cls.dut_iface, " ".join(map(str, weights)))).run()

            if "forwarding" in cls.dut_drv_version:
                cls.queue_name = 'ring_{}_rx_packets'
            else:
                cls.queue_name = 'Queue[{}] InPackets'

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        self.added_l3l4_loc = []
        self.curr_l3l4_loc = self.L3L4_LOCATION

    @staticmethod
    def get_ip_range(ip):
        if isinstance(ip, tuple):
            ip_addr = ipaddress.ip_address(unicode(ip[0]))
            ip_range = map(str, [ip_addr + i for i in range(ip[1])])
        else:
            ip_range = [ip]
        return ip_range

    @staticmethod
    def get_port_range(port):
        if isinstance(port, tuple):
            port_range = [port[0] + i for i in range(port[1])]
        else:
            port_range = [port]
        return port_range

    def add_filter(self, flow_type, src_ip=None, dst_ip=None, src_port=None, dst_port=None, action=1, loc=None):
        log.debug('added_l3l4_loc: {}'.format(self.added_l3l4_loc))
        if loc is not None:
            self.curr_l3l4_loc = loc

        src_ip_range = self.get_ip_range(src_ip)
        dst_ip_range = self.get_ip_range(dst_ip)
        src_port_range = self.get_port_range(src_port)
        dst_port_range = self.get_port_range(dst_port)

        for src_ip, dst_ip, src_port, dst_port in itertools.product(
                src_ip_range, dst_ip_range, src_port_range, dst_port_range):

            sub_cmd = flow_type

            if dst_ip is not None:
                sub_cmd += ' dst-ip {}'.format(dst_ip)
            if src_ip is not None:
                sub_cmd += ' src-ip {}'.format(src_ip)

            if dst_port is not None:
                sub_cmd += ' dst-port {}'.format(dst_port)
            if src_port is not None:
                sub_cmd += ' src-port {}'.format(src_port)

            base_cmd = "ethtool -N {} flow-type {} action {} loc {}"
            exec_cmd = base_cmd.format(self.dut_iface, sub_cmd, action, self.curr_l3l4_loc)
            assert Command(cmd=exec_cmd).run()["returncode"] == 0
            self.added_l3l4_loc.append(self.curr_l3l4_loc)
            self.curr_l3l4_loc += 1

        log.debug('added_l3l4_loc: {}'.format(self.added_l3l4_loc))
        Command(cmd='sudo ethtool -n {}'.format(self.dut_iface)).run()

    def clear_filters(self):
        log.debug('added_l3l4_loc: {}'.format(self.added_l3l4_loc))
        for loc in self.added_l3l4_loc:
            Command(cmd="ethtool -N {} delete {}".format(self.dut_iface, loc)).run()
        self.added_l3l4_loc = []
        log.debug('added_l3l4_loc: {}'.format(self.added_l3l4_loc))

    def send_packets(self, ipv4=False, ipv6=False, udp=False, tcp=False, sctp=False,
                     src_ip=None, dst_ip=None, src_port=None, dst_port=None,
                     count=100, backgroud_traffic=True):
        src_ip_range = self.get_ip_range(src_ip)
        dst_ip_range = self.get_ip_range(dst_ip)
        src_port_range = self.get_port_range(src_port)
        dst_port_range = self.get_port_range(dst_port)

        if backgroud_traffic:
            self.ping(to_host=self.DUT_IPV4_ADDR, from_host=self.LKP_IPV4_ADDR, number=20)

        for src_ip, dst_ip, src_port, dst_port in itertools.product(
                src_ip_range, dst_ip_range, src_port_range, dst_port_range):
            pkt = Ether(dst=self.dut_mac)
            if ipv4:
                pkt = pkt / IP(src=src_ip, dst=dst_ip)
            elif ipv6:
                pkt = pkt / IPv6(src=src_ip, dst=dst_ip)
            if udp:
                pkt = pkt / UDP(sport=src_port, dport=dst_port)
            elif tcp:
                pkt = pkt / TCP(sport=src_port, dport=dst_port)
            elif sctp:
                pkt = pkt / SCTP(sport=src_port, dport=dst_port)

            log.info('Prepared packet: {}'.format(pkt.summary()))
            lkp_aqsendp = Aqsendp(
                packet=pkt, count=count,
                host=self.lkp_hostname, iface=self.lkp_iface
            )
            lkp_aqsendp.run()

    def test_rxflow_vlan(self):
        """
        @description: Test rxflow vlan 1 filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            def create_vlan_iface(vlan):
                self.dut_ifconfig.create_vlan_iface(vlan)
                self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan)
                self.dut_ifconfig.wait_link_up(vlan_id=vlan)

            action_queue = 1
            num_packets = 100
            vlan_id_1 = 1
            vlan_id_2 = 2

            src_ip = "192.168.200.201"
            dst_ip = "192.168.200.200"

            create_vlan_iface(vlan_id_1)
            create_vlan_iface(vlan_id_2)

            set_filter_cmd = "ethtool -N {} flow-type ether vlan {} m 0xF000 action {} loc {}".format(
                self.dut_iface, vlan_id_1, action_queue, self.VLAN_LOCATION + 1)
            assert Command(cmd=set_filter_cmd).run()["returncode"] == 0
            Command(cmd='sudo ethtool -n {}'.format(self.dut_iface)).run()

            stat_before = self.dut_statistics.get_drv_counters()
            for vlan in range(1, 12):
                pkt = Ether(dst=self.dut_mac) / Dot1Q(vlan=vlan) / IP(dst=dst_ip, src=src_ip)
                lkp_aqsendp = Aqsendp(
                    packet=pkt, count=num_packets,
                    host=self.lkp_hostname, iface=self.lkp_iface)
                lkp_aqsendp.run()
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets
        finally:
            self.dut_ifconfig.delete_vlan_iface(vlan_id_1)
            self.dut_ifconfig.delete_vlan_iface(vlan_id_2)
            Command(cmd="ethtool -N {} delete {}".format(self.dut_iface, self.VLAN_LOCATION)).run()

    def test_rxflow_ethertype(self):
        """
        @description: Test rxflow ethertype filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            ethertype = 0x0801
            src_udp_port = 6565
            dst_udp_port = 99

            set_filter_cmd = "ethtool -N {} flow-type ether proto {} action {} loc {}".format(
                self.dut_iface, ethertype, action_queue, self.ETHERTYPE_LOCATION)
            assert Command(cmd=set_filter_cmd).run()["returncode"] == 0
            Command(cmd='sudo ethtool -n {}'.format(self.dut_iface)).run()

            pkt = Ether(dst=self.dut_mac, type=ethertype) / IP() / UDP(sport=src_udp_port, dport=dst_udp_port)
            lkp_aqsendp = Aqsendp(
                packet=pkt, count=num_packets,
                host=self.lkp_hostname, iface=self.lkp_iface
            )

            stat_before = self.dut_statistics.get_drv_counters()
            lkp_aqsendp.run()
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            Command(cmd="ethtool -N {} delete {}".format(self.dut_iface, self.ETHERTYPE_LOCATION)).run()

    def test_rxflow_ethertype_user_prior(self):
        """
        @description: Test rxflow ethertype and user priority filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        if "forwarding" in self.dut_drv_version:
            pytest.skip()
        try:
            action_queue = 1
            num_packets = 100
            src_udp_port = 6565
            dst_udp_port = 99
            ethertype = 0x0801
            vlan = 1
            prio = 4
            vlan_type = (prio << 13) | vlan

            set_filter_cmd = "ethtool -N {} flow-type ether proto {} vlan {} m 0x1FFF action {} loc {}".format(
                self.dut_iface, ethertype, vlan_type, action_queue, self.ETHERTYPE_LOCATION)
            assert Command(cmd=set_filter_cmd).run()["returncode"] == 0

            sniffer = Tcpdump(host=self.dut_hostname, port=self.dut_port, timeout=60)
            sniffer.run_async()
            time.sleep(30)

            stat_before = self.dut_statistics.get_drv_counters()
            # send traffic for all priorities
            for p in range(0, 8):
                l2 = Ether(dst=self.dut_mac) / Dot1Q(vlan=vlan, prio=p, type=ethertype)
                pkt = l2 / IP() / UDP(sport=src_udp_port, dport=dst_udp_port)
                lkp_aqsendp = Aqsendp(
                    packet=pkt, count=num_packets,
                    host=self.lkp_hostname, iface=self.lkp_iface
                )
                lkp_aqsendp.run()
            stat_after = self.dut_statistics.get_drv_counters()

            dut_packets = sniffer.join(30)
            wrpcap("packets.pcap", dut_packets)
            shutil.copy("packets.pcap", self.test_log_dir)

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            Command(cmd="ethtool -N {} delete {}".format(self.dut_iface, self.ETHERTYPE_LOCATION)).run()

    def test_rxflow_ipv4_src_ip(self):
        """
        @description: Test rxflow l3l4 IPv6 srcip

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "169.254.1.1"

            self.add_filter(flow_type='ip4', src_ip=src_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv4=True, src_ip=(src_ip, 4), count=num_packets)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_ipv4_dst_ip(self):
        """
        @description: Test rxflow l3l4 IPv6 dstip

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            dst_ip = "169.254.1.1"

            self.add_filter(flow_type='ip4', dst_ip=dst_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv4=True, dst_ip=(dst_ip, 4), count=num_packets)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_ipv4_src_ip_dst_ip(self):
        """
        @description: Test rxflow l3l4 IPv6 dstip srcip

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "169.254.1.1"
            dst_ip = "169.254.2.1"

            self.add_filter(flow_type='ip4', src_ip=src_ip, dst_ip=dst_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv4=True, src_ip=(src_ip, 5), dst_ip=(dst_ip, 4), count=num_packets)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_ipv6_src_ip(self):
        """
        @description: Test rxflow l3l4 IPv6 srcip

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:dead::1"

            self.add_filter(flow_type='ip6', src_ip=src_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv6=True, src_ip=(src_ip, 5), count=num_packets)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_ipv6_dst_ip(self):
        """
        @description: Test rxflow l3l4 IPv6 dstip

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            dst_ip = "2001:db8:dead::1"

            self.add_filter(flow_type='ip6', dst_ip=dst_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv6=True, dst_ip=(dst_ip, 5), count=num_packets)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_ipv6_src_ip_dst_ip(self):
        """
        @description: Test rxflow l3l4 IPv6 dstip srcip

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_ip_2 = "2001:db8:0001::2"
            dst_ip_2 = "2001:db8:0002::2"

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='ip6', src_ip=src_ip, dst_ip=(dst_ip, 3))
            else:
                filters_count = 2
                self.add_filter(flow_type='ip6', src_ip=src_ip, dst_ip=dst_ip, loc=32)
                self.add_filter(flow_type='ip6', src_ip=src_ip_2, dst_ip=dst_ip_2, loc=36)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv6=True, src_ip=(src_ip, 5), dst_ip=(dst_ip, 5), count=num_packets)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_combine_ipv4_ipv6(self):
        """
        @description: Test rxflow l3l4 IPv6 dstip srcip

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        if self.dut_fw_card != CARD_ANTIGUA:
            pytest.skip()
        try:
            action_queue = 1
            num_packets = 100
            src_ip4 = "169.254.1.1"
            dst_ip4 = "169.254.2.1"
            src_ip6 = "2001:db8:0001::1"
            dst_ip6 = "2001:db8:0002::1"

            self.add_filter(flow_type='ip4', src_ip=src_ip4, dst_ip=dst_ip4)
            self.add_filter(flow_type='ip6', src_ip=src_ip6, dst_ip=dst_ip6)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv4=True, src_ip=(src_ip4, 2), dst_ip=(dst_ip4, 2), count=num_packets)
            self.send_packets(ipv6=True, src_ip=(src_ip6, 2), dst_ip=(dst_ip6, 2), count=num_packets)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * 2

        finally:
            self.clear_filters()

    def test_rxflow_udp4_src_port(self):
        """
        @description: Test rxflow l3l4 udp4 src port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='udp4', src_port=src_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=(src_port, 4), dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_udp4_dst_port(self):
        """
        @description: Test rxflow l3l4 udp4 dst port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='udp4', dst_port=dst_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=(dst_port, 4))
            stat_after = self.dut_statistics.get_drv_counters()
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_udp4_src_ip(self):
        """
        @description: Test rxflow l3l4 udp4 src ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='udp4', src_ip=src_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_udp4_dst_ip(self):
        """
        @description: Test rxflow l3l4 udp4 dst ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='udp4', dst_ip=dst_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=dst_port)
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_udp4_all_multiple_ips(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = "192.168.200.1"
            src_port = 10244
            dst_port = 10243

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='udp4',
                                src_ip=(src_ip, 1), dst_ip=(dst_ip, 3),
                                src_port=src_port, dst_port=dst_port)
            else:
                filters_count = 4
                self.add_filter(flow_type='udp4',
                                src_ip=(src_ip, 2), dst_ip=(dst_ip, 2),
                                src_port=src_port, dst_port=dst_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=(src_port, 2), dst_port=(dst_port, 2))
            stat_after = self.dut_statistics.get_drv_counters()
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_udp4_all_multiple_ports(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = "192.168.200.1"
            src_port = 10244
            dst_port = 10243

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='udp4',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=(dst_port, 3))
            else:
                filters_count = 4
                self.add_filter(flow_type='udp4',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=(src_port, 2), dst_port=(dst_port, 2))

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=(src_ip, 2), dst_ip=(dst_ip, 2),
                              src_port=(src_port, 4), dst_port=(dst_port, 4))
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_udp4_srcport_drop(self):
        """
        @description: Test rxflow l3l4 srcport DROP filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic dropped.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = -1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = "192.168.200.1"
            src_port = 10244
            dst_port = 10243

            self.add_filter(flow_type='udp4', src_port=src_port, action=action_queue)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=(dst_port, 2),
                              backgroud_traffic=False)
            stat_after = self.dut_statistics.get_drv_counters()

            for q in range(self.rings):
                k = self.queue_name.format(q)
                assert stat_after[k] - stat_before[k] < 20
        finally:
            self.clear_filters()

    def test_rxflow_udp6_src_port(self):
        """
        @description: Test rxflow l3l4 udp6 src port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='udp6', src_port=src_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp6
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=(src_port, 4), dst_port=dst_port)
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_udp6_dst_port(self):
        """
        @description: Test rxflow l3l4 udp6 dst port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='udp6', dst_port=dst_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp6
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=(dst_port, 4))
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_udp6_src_ip(self):
        """
        @description: Test rxflow l3l4 udp6 src ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='udp6', src_ip=src_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp6
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_udp6_dst_ip(self):
        """
        @description: Test rxflow l3l4 udp6 dst ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='udp6', dst_ip=dst_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp6
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=dst_port)
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_udp6_all_multiple_ips(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_ip_2 = "2001:db8:0001::2"
            dst_ip_2 = "2001:db8:0002::2"
            src_port = 10244
            dst_port = 10243

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='udp6',
                                src_ip=src_ip, dst_ip=(dst_ip, 3),
                                src_port=src_port, dst_port=dst_port)
            else:
                filters_count = 2
                self.add_filter(flow_type='udp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=dst_port, loc=32)
                self.add_filter(flow_type='udp6',
                                src_ip=src_ip_2, dst_ip=dst_ip_2,
                                src_port=src_port, dst_port=dst_port, loc=36)

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp6
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=(src_port, 2), dst_port=(dst_port, 2))
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_udp6_all_multiple_ports(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 10244
            dst_port = 10243
            src_port_2 = 10246
            dst_port_2 = 10245

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='udp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=(dst_port, 3))
            else:
                filters_count = 2
                self.add_filter(flow_type='udp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=dst_port, loc=32)
                self.add_filter(flow_type='udp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port_2, dst_port=dst_port_2, loc=36)

            stat_before = self.dut_statistics.get_drv_counters()
            # send udp6
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=(src_ip, 2), dst_ip=(dst_ip, 2),
                              src_port=(src_port, 4), dst_port=(dst_port, 4))
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_udp6_srcport_drop(self):
        """
        @description: Test rxflow l3l4 srcport DROP filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic dropped.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = -1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 10244
            dst_port = 10243

            self.add_filter(flow_type='udp6', src_port=src_port, action=action_queue)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=(dst_port, 2),
                              backgroud_traffic=False)
            stat_after = self.dut_statistics.get_drv_counters()

            for q in range(self.rings):
                k = self.queue_name.format(q)
                assert stat_after[k] - stat_before[k] < 20
        finally:
            self.clear_filters()

    def test_rxflow_tcp4_src_port(self):
        """
        @description: Test rxflow l3l4 tcp4 src port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='tcp4', src_port=src_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=(src_port, 4), dst_port=dst_port)
            # send udp (backgroud traffic)
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_tcp4_dst_port(self):
        """
        @description: Test rxflow l3l4 tcp4 dst port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='tcp4', dst_port=dst_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=(dst_port, 4))
            # send udp (backgroud traffic)
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_tcp4_src_ip(self):
        """
        @description: Test rxflow l3l4 tcp4 src ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='tcp4', src_ip=src_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            # send udp (backgroud traffic)
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_tcp4_dst_ip(self):
        """
        @description: Test rxflow l3l4 tcp4 dst ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='tcp4', dst_ip=dst_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=dst_port)
            # send udp (backgroud traffic)
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_tcp4_all_multiple_ips(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = "192.168.200.1"
            src_port = 10244
            dst_port = 10243

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='tcp4',
                                src_ip=src_ip, dst_ip=(dst_ip, 3),
                                src_port=src_port, dst_port=dst_port)
            else:
                filters_count = 4

                self.add_filter(flow_type='tcp4',
                                src_ip=(src_ip, 2), dst_ip=(dst_ip, 2),
                                src_port=src_port, dst_port=dst_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=(src_port, 2), dst_port=(dst_port, 2))
            # send udp (backgroud traffic)
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_tcp4_all_multiple_ports(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = "192.168.200.1"
            src_port = 10244
            dst_port = 10243

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='tcp4',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=(dst_port, 3))
            else:
                filters_count = 4
                self.add_filter(flow_type='tcp4',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=(src_port, 2), dst_port=(dst_port, 2))

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=(src_ip, 2), dst_ip=(dst_ip, 2),
                              src_port=(src_port, 4), dst_port=(dst_port, 4))
            # send udp (backgroud traffic)
            self.send_packets(ipv4=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_tcp4_srcport_drop(self):
        """
        @description: Test rxflow l3l4 srcport DROP filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic dropped.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = -1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = "192.168.200.1"
            src_port = 10244
            dst_port = 10243

            self.add_filter(flow_type='tcp4', src_port=src_port, action=action_queue)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=(dst_port, 2),
                              backgroud_traffic=False)
            stat_after = self.dut_statistics.get_drv_counters()

            for q in range(self.rings):
                k = self.queue_name.format(q)
                assert stat_after[k] - stat_before[k] < 20
        finally:
            self.clear_filters()

    def test_rxflow_tcp6_src_port(self):
        """
        @description: Test rxflow l3l4 tcp6 src port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"

            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='tcp6', src_port=src_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp6
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=(src_port, 4), dst_port=dst_port)
            # send udp6 (background traffic)
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_tcp6_dst_port(self):
        """
        @description: Test rxflow l3l4 tcp6 dst port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='tcp6', dst_port=dst_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp6
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=(dst_port, 4))
            # send udp6 (background traffic)
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_tcp6_src_ip(self):
        """
        @description: Test rxflow l3l4 tcp6 src ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='tcp6', src_ip=src_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp6
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            # send udp6 (background traffic)
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_tcp6_dst_ip(self):
        """
        @description: Test rxflow l3l4 tcp6 dst ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='tcp6', dst_ip=dst_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp6
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=dst_port)
            # send udp6 (background traffic)
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_tcp6_all_multiple_ips(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_ip_2 = "2001:db8:0001::2"
            dst_ip_2 = "2001:db8:0002::2"
            src_port = 10244
            dst_port = 10243

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='tcp6',
                                src_ip=src_ip, dst_ip=(dst_ip, 3),
                                src_port=src_port, dst_port=dst_port)
            else:
                filters_count = 2
                self.add_filter(flow_type='tcp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=dst_port, loc=32)
                self.add_filter(flow_type='tcp6',
                                src_ip=src_ip_2, dst_ip=dst_ip_2,
                                src_port=src_port, dst_port=dst_port, loc=36)

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp6
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=(src_port, 2), dst_port=(dst_port, 2))
            # send udp6 (background traffic)
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_tcp6_all_multiple_ports(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 10244
            dst_port = 10243
            src_port_2 = 10246
            dst_port_2 = 10245

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='tcp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=(dst_port, 3))
            else:
                filters_count = 2
                self.add_filter(flow_type='tcp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=dst_port, loc=32)
                self.add_filter(flow_type='tcp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port_2, dst_port=dst_port_2, loc=36)

            stat_before = self.dut_statistics.get_drv_counters()
            # send tcp6
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=(src_ip, 2), dst_ip=(dst_ip, 2),
                              src_port=(src_port, 4), dst_port=(dst_port, 4))
            # send udp6 (background traffic)
            self.send_packets(ipv6=True, udp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_tcp6_srcport_drop(self):
        """
        @description: Test rxflow l3l4 srcport DROP filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic dropped.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = -1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 10244
            dst_port = 10243

            self.add_filter(flow_type='tcp6', src_port=src_port, action=action_queue)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=(dst_port, 2),
                              backgroud_traffic=False)
            stat_after = self.dut_statistics.get_drv_counters()

            for q in range(self.rings):
                k = self.queue_name.format(q)
                assert stat_after[k] - stat_before[k] < 20
        finally:
            self.clear_filters()

    def test_rxflow_sctp4_src_port(self):
        """
        @description: Test rxflow l3l4 sctp4 src port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='sctp4', src_port=src_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp
            self.send_packets(ipv4=True, sctp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=(src_port, 4), dst_port=dst_port)
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_sctp4_dst_port(self):
        """
        @description: Test rxflow l3l4 sctp4 dst port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='sctp4', dst_port=dst_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp
            self.send_packets(ipv4=True, sctp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=(dst_port, 4))
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_sctp4_src_ip(self):
        """
        @description: Test rxflow l3l4 sctp4 src ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='sctp4', src_ip=src_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp
            self.send_packets(ipv4=True, sctp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_sctp4_dst_ip(self):
        """
        @description: Test rxflow l3l4 sctp4 dst ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = '192.168.200.1'
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='sctp4', dst_ip=dst_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp
            self.send_packets(ipv4=True, sctp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=dst_port)
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_sctp4_all_multiple_ips(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = "192.168.200.1"
            src_port = 10244
            dst_port = 10243

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='sctp4',
                                src_ip=(src_ip, 1), dst_ip=(dst_ip, 3),
                                src_port=src_port, dst_port=dst_port)
            else:
                filters_count = 4
                self.add_filter(flow_type='sctp4',
                                src_ip=(src_ip, 2), dst_ip=(dst_ip, 2),
                                src_port=src_port, dst_port=dst_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp
            self.send_packets(ipv4=True, sctp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=(src_port, 2), dst_port=(dst_port, 2))
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_sctp4_all_multiple_ports(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = "192.168.200.1"
            src_port = 10244
            dst_port = 10243

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='sctp4',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=(dst_port, 3))
            else:
                filters_count = 4
                self.add_filter(flow_type='sctp4',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=(src_port, 2), dst_port=(dst_port, 2))

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp
            self.send_packets(ipv4=True, sctp=True, count=num_packets,
                              src_ip=(src_ip, 2), dst_ip=(dst_ip, 2),
                              src_port=(src_port, 4), dst_port=(dst_port, 4))
            # send tcp (background traffic)
            self.send_packets(ipv4=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_sctp4_srcport_drop(self):
        """
        @description: Test rxflow l3l4 srcport DROP filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic dropped.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = -1
            num_packets = 100
            src_ip = "192.168.100.1"
            dst_ip = "192.168.200.1"
            src_port = 10244
            dst_port = 10243

            self.add_filter(flow_type='sctp4', src_port=src_port, action=action_queue)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv4=True, sctp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=(dst_port, 2),
                              backgroud_traffic=False)
            stat_after = self.dut_statistics.get_drv_counters()

            for q in range(self.rings):
                k = self.queue_name.format(q)
                assert stat_after[k] - stat_before[k] < 20
        finally:
            self.clear_filters()

    def test_rxflow_sctp6_src_port(self):
        """
        @description: Test rxflow l3l4 sctp6 src port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"

            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='sctp6', src_port=src_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp6
            self.send_packets(ipv6=True, sctp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=(src_port, 4), dst_port=dst_port)
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_sctp6_dst_port(self):
        """
        @description: Test rxflow l3l4 sctp6 dst port filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='sctp6', dst_port=dst_port)

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp6
            self.send_packets(ipv6=True, sctp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=(dst_port, 4))
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_sctp6_src_ip(self):
        """
        @description: Test rxflow l3l4 sctp6 src ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='sctp6', src_ip=src_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp6
            self.send_packets(ipv6=True, sctp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_sctp6_dst_ip(self):
        """
        @description: Test rxflow l3l4 sctp6 dst ip filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 6565
            dst_port = 1024

            self.add_filter(flow_type='sctp6', dst_ip=dst_ip)

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp6
            self.send_packets(ipv6=True, sctp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=dst_port)
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets

        finally:
            self.clear_filters()

    def test_rxflow_sctp6_all_multiple_ips(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_ip_2 = "2001:db8:0001::2"
            dst_ip_2 = "2001:db8:0002::2"
            src_port = 10244
            dst_port = 10243

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='sctp6',
                                src_ip=src_ip, dst_ip=(dst_ip, 3),
                                src_port=src_port, dst_port=dst_port)
            else:
                filters_count = 2
                self.add_filter(flow_type='sctp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=dst_port, loc=32)
                self.add_filter(flow_type='sctp6',
                                src_ip=src_ip_2, dst_ip=dst_ip_2,
                                src_port=src_port, dst_port=dst_port, loc=36)

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp6
            self.send_packets(ipv6=True, sctp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=(src_port, 2), dst_port=(dst_port, 2))
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_sctp6_all_multiple_ports(self):
        """
        @description: Test rxflow l3l4 dstip srcip dstport srcport 8 filters

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic recived in target queue.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = 1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 10244
            dst_port = 10243
            src_port_2 = 10246
            dst_port_2 = 10245

            if self.dut_fw_card == CARD_ANTIGUA:
                filters_count = 3
                self.add_filter(flow_type='sctp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=(dst_port, 3))
            else:
                filters_count = 2
                self.add_filter(flow_type='sctp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=dst_port, loc=32)
                self.add_filter(flow_type='sctp6',
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port_2, dst_port=dst_port_2, loc=36)

            stat_before = self.dut_statistics.get_drv_counters()
            # send sctp6
            self.send_packets(ipv6=True, sctp=True, count=num_packets,
                              src_ip=(src_ip, 2), dst_ip=(dst_ip, 2),
                              src_port=(src_port, 4), dst_port=(dst_port, 4))
            # send tcp6 (background traffic)
            self.send_packets(ipv6=True, tcp=True, count=num_packets,
                              src_ip=src_ip, dst_ip=dst_ip,
                              src_port=src_port, dst_port=dst_port)
            stat_after = self.dut_statistics.get_drv_counters()

            k = self.queue_name.format(action_queue)
            assert stat_after[k] - stat_before[k] == num_packets * filters_count

        finally:
            self.clear_filters()

    def test_rxflow_sctp6_srcport_drop(self):
        """
        @description: Test rxflow l3l4 srcport DROP filter

        @steps:
        1. Configure filter.
        2. Send traffic.
        3. Check traffic dropped.

        @result: Check passed.
        @duration: 5 sec.
        """
        try:
            action_queue = -1
            num_packets = 100
            src_ip = "2001:db8:0001::1"
            dst_ip = "2001:db8:0002::1"
            src_port = 10244
            dst_port = 10243

            self.add_filter(flow_type='sctp6', src_port=src_port, action=action_queue)

            stat_before = self.dut_statistics.get_drv_counters()
            self.send_packets(ipv6=True, sctp=True, count=num_packets,
                              src_ip=(src_ip, 4), dst_ip=(dst_ip, 4),
                              src_port=src_port, dst_port=(dst_port, 2),
                              backgroud_traffic=False)
            stat_after = self.dut_statistics.get_drv_counters()

            for q in range(self.rings):
                k = self.queue_name.format(q)
                assert stat_after[k] - stat_before[k] < 20
        finally:
            self.clear_filters()


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
