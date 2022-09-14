"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import pytest
import random
import time

import shutil

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, CARDS_FELICITY_BERMUDA
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvMessage, DrvEthConfig, OffloadIpInfo, OffloadKaInfo, OffloadKa, MdnsRr, \
    OffloadRrInfo, MdnsRrTail, MdnsRdataSrv, OffloadPortInfo
from tools.scapy_tools import ScapyTools, get_l2_scapy_socket, MDNSRecord, get_ipv6_multicast_mac, \
    MULTICAST_MDNS_MAC_IP4, MULTICAST_MDNS_MAC_IP6, MULTICAST_MDNS_IP4, MULTICAST_MDNS_IP6, get_ns_multicast_ip, \
    MULTICAST_ND_IP6, BROADCAST_MAC
from tools.samba import Samba
from tools.sniffer import Sniffer
from tools.utils import get_atf_logger, get_compressed_ipv6

from infra.test_base import TestBase, idparametrize

from scapy.all import conf, Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, Padding, Raw, ICMPv6ParamProblem, \
    RandString, wrpcap

from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup
    os.environ["TEST"] = "fw_2x_packet_filter"


class TestPacketFilter(TestBase):
    """
    @description: The packet filtering tests are dedicated to check FW's ability to filter packets in sleep proxy mode.

    @setup: Two Aquantia devices connected back to back.
    """
    AFTER_LINK_UP_DELAY = 15
    WAKE_COUNTER_DELAY = 2

    DUT_MAC = "00:17:b6:00:07:82"
    FW_REMOTE_MAC = "00:17:b6:33:44:91"

    DUT_IP4 = "169.254.23.232"
    LKP_IP4 = "169.254.23.111"

    NETMASK = "255.255.0.0"
    MULTICAST_IP4 = "169.254.255.255"

    DUT_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2400"
    LKP_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2487"

    DUT_LINK_LOCAL_IP6 = "fe80:0000:0000:0000:1422:570e:fcb6:ad7e"

    FAKE_MAC = "00:00:de:ad:fa:ce"
    FAKE_IP4 = "192.168.0.69"
    FAKE_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:0069"

    @classmethod
    def setup_class(cls):
        super(TestPacketFilter, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", drv_type=DRV_TYPE_DIAG, host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4, cls.NETMASK, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6, 64, None)

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port)

            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()

            # Disable Samba to remove background multicast traffic which affects SerDes
            Samba(host=cls.lkp_hostname).stop()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestPacketFilter, self).setup_method(method)

        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)

        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(True)
            self.bin_log_file, self.txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestPacketFilter, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        if self.MCP_LOG:
            self.dut_bin_log_file, self.dut_txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.dut_bin_log_file, self.test_log_dir)
            shutil.copy(self.dut_txt_log_file, self.test_log_dir)

            self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

    def get_wake_counter_on_dut(self):
        """Read wake counter from MCP memory on DUT"""
        return self.dut_atltool_wrapper.get_wake_counter_2x()

    def get_wake_reason_on_dut(self):
        wake_reason = self.dut_atltool_wrapper.get_wake_reason_2x()
        log.info("Wake reason: {}".format(hex(wake_reason)))
        return wake_reason

    def gen_tcpka_probe_pkt(self, off_ka, ipv):
        probe_pkt = Ether(dst=self.DUT_MAC, src=off_ka.remote_mac_address)
        if ipv == 4:
            ip_layer = IP(dst=off_ka.local_ip, src=off_ka.remote_ip, ttl=128, id=0, flags="DF")
        else:
            ip_layer = IPv6(dst=off_ka.local_ip, src=off_ka.remote_ip, hlim=128)
        probe_pkt /= ip_layer
        probe_pkt /= TCP(flags="A", window=off_ka.win_size, sport=off_ka.remote_port, dport=off_ka.local_port,
                         seq=off_ka.ack_num - 1, ack=off_ka.seq_num + 1)
        padding_size = 60 - len(probe_pkt)
        if padding_size > 0:
            probe_pkt /= Padding(load=RandString(padding_size))

        return probe_pkt

    def gen_tcpka_reply_pkt(self, pkt):
        ans = pkt.copy()
        ans[0].src = pkt[0].dst
        ans[0].dst = pkt[0].src
        ans[1].src = pkt[1].dst
        ans[1].dst = pkt[1].src
        ans[2].seq = pkt[2].ack
        ans[2].ack = pkt[2].seq + 1
        ans[2].sport = pkt[2].dport
        ans[2].dport = pkt[2].sport

        # Recalculate checksum
        ans[1].chksum = None
        ans[2].chksum = None

        return ans

    def get_drv_cfg_with_ips(self):
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC

        cfg.set_standard_ips()

        # Add link local IPv6 address (required on any IPv6 interface)
        cfg.ips.v6_addr_count += 1
        cfg.ips.v6_addresses.append(self.DUT_LINK_LOCAL_IP6)
        cfg.ips.v6_masks.append(64)

        return cfg

    def test_no_mdns_ans_on_wrong_chksum(self):
        """
        @description: Test checksum filtering: no answers on mDNS query with incorrect UDP checksum.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a mDNS TXT record.
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with configured mDNS
        TXT record from offload.

        @result: None of the queries are answered.
        @duration: 2 minutes.
        """
        cfg = self.get_drv_cfg_with_ips()

        cfg.rrs = OffloadRrInfo()
        # configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("WhatAreThose?!._ssh._udp.local", "AdddidasShoes", ttl=2015)
        cfg.rrs.entries.append(mdns_txt)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_mdns_txt.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl)]

        conf.checkIPaddr = False

        try:
            log.info("Checking multicast IPv4")
            pkt = self.lkp_scapy_tools.get_mdns_query(srcip=self.LKP_IP4, srcmac=self.lkp_mac, queries=queries,
                                                      dstip=None, dstmac=None)
            pkt[UDP].chksum = 1337
            pkt.show()
            ans, unans = self.lkp_scapy_tools.sendrecv1(port=self.lkp_port, pkts=pkt, iface=self.lkp_scapy_iface)
            assert len(ans) == 0, "FW answered mDNS query with incorrect UDP checksum"

            log.info("Checking unicast IPv4")
            for address in cfg.ips.v4_addresses:
                pkt = self.lkp_scapy_tools.get_mdns_query(srcip=self.LKP_IP4, srcmac=self.lkp_mac, queries=queries,
                                                          dstip=address, dstmac=self.DUT_MAC)
                pkt[UDP].chksum = 1337
                pkt.show()
                ans, unans = self.lkp_scapy_tools.sendrecv1(port=self.lkp_port, pkts=pkt, iface=self.lkp_scapy_iface)
                assert len(ans) == 0, "FW answered mDNS query with incorrect UDP checksum"

            log.info("Checking multicast IPv6")
            pkt = self.lkp_scapy_tools.get_mdns_query(srcip=self.LKP_IP6, srcmac=self.lkp_mac, queries=queries,
                                                      dstip=None, dstmac=None)
            pkt[UDP].chksum = 1337
            pkt.show()
            ans, unans = self.lkp_scapy_tools.sendrecv1(port=self.lkp_port, pkts=pkt, iface=self.lkp_scapy_iface)
            assert len(ans) == 0, "FW answered mDNS query with incorrect UDP checksum"

            log.info("Checking unicast IPv4")
            for address in cfg.ips.v6_addresses:
                pkt = self.lkp_scapy_tools.get_mdns_query(srcip=self.LKP_IP6, srcmac=self.lkp_mac, queries=queries,
                                                          dstip=address, dstmac=self.DUT_MAC)
                pkt[UDP].chksum = 1337
                pkt.show()
                ans, unans = self.lkp_scapy_tools.sendrecv1(port=self.lkp_port, pkts=pkt, iface=self.lkp_scapy_iface)
                assert len(ans) == 0, "FW answered mDNS query with incorrect UDP checksum"
        finally:
            conf.checkIPaddr = True

    def test_no_wake_on_name_conflict_with_wrong_chksum(self):
        """
        @description: Test checksum filtering: no wake on receiving mDNS name conflict packet with incorrect checksum.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a mDNS SRV record (set network name).
        3. Send mDNS A/AAAA response with configured name from offload with wrong TCP checksum.

        @result: FW doesn't wake PC after receiving packets.
        @duration: 2 minutes.
        """
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407
        cfg.mac = self.DUT_MAC
        cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = 1
        cfg.ips.v4_addresses = [self.DUT_IP4]
        cfg.ips.v4_masks = [16]
        cfg.ips.v6_addr_count = 1
        cfg.ips.v6_addresses = [self.DUT_IP6]
        cfg.ips.v6_masks = [64]

        cfg.rrs = OffloadRrInfo()

        mdns_rr = MdnsRr()
        mdns_rr.tail = MdnsRrTail()
        mdns_rr.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_SRV
        mdns_rr.tail.class_ = 32769
        mdns_rr.tail.ttl = 120
        mdns_rr.question = "iMac (2)._smb._tcp.local"
        mdns_rr.answer = "iMac-3.local"
        mdns_rr.srv = MdnsRdataSrv()
        mdns_rr.srv.priority = 0
        mdns_rr.srv.weight = 48385
        mdns_rr.srv.port = 0
        mdns_rr.tail.rd_len = 8
        cfg.rrs.entries.append(mdns_rr)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_name_conflict.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))
        time.sleep(self.AFTER_LINK_UP_DELAY)

        prev_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        # Form fake mDNS IPv4 response and send it from LKP
        fake_mdns = Ether(src=self.FAKE_MAC, dst=MULTICAST_MDNS_MAC_IP4)
        fake_mdns /= IP(src=self.FAKE_IP4, dst=MULTICAST_MDNS_IP4)
        fake_mdns /= UDP(sport=5353, dport=5353)
        q = DNSQR(qtype="A", qname=mdns_rr.answer)
        a = DNSRR(type="A", rrname=mdns_rr.answer, rdata=self.FAKE_IP4)
        fake_mdns /= DNS(qr=1, aa=1, qd=q, an=a)
        fake_mdns[UDP].chksum = 1337

        self.lkp_scapy_tools.send_packet(fake_mdns, self.lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)

        assert self.get_wake_counter_on_dut() == prev_wake_counter, \
            "FW detected IPv4 name conflict packet with incorrect checksum"

        # Form fake mDNS IPv6 response and send it from LKP
        fake_mdns = Ether(src=self.FAKE_MAC, dst=MULTICAST_MDNS_MAC_IP6)
        fake_mdns /= IPv6(src=self.FAKE_IP6, dst=MULTICAST_MDNS_IP6)
        fake_mdns /= UDP(sport=5353, dport=5353)
        q = DNSQR(qtype="AAAA", qname=mdns_rr.answer)
        a = DNSRR(type="AAAA", rrname=mdns_rr.answer, rdata=self.FAKE_IP6)
        fake_mdns /= DNS(qr=1, aa=1, qd=q, an=a)
        fake_mdns[UDP].chksum = 1337

        self.lkp_scapy_tools.send_packet(fake_mdns, self.lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)

        # Check if FW tried to wake PC
        assert self.get_wake_counter_on_dut() == prev_wake_counter, \
            "FW detected IPv6 name conflict packet with incorrect checksum"

    @idparametrize("ipv", [4, 6])
    def test_tcpka_remote_probes_with_wrong_chksum(self, ipv):
        """
        @description: Test checksum filtering: no answers on TCP KA probes with incorrect checksum.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with TCP KA record.
        3. Send TCP KA probes from LKP with incorrect checksum.

        @result: FW doesn't answer probes with incorrect checksum.
        @duration: 2 minutes.
        """
        assert ipv in [4, 6]

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 3
        off_ka_info.retry_interval = 2000

        # FW starts to count down timeout right after config
        off_ka = OffloadKa(timeout=60, local_port=23, remote_port=22, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=1000, seq_num=2456, ack_num=1212)
        if ipv == 4:
            off_ka.local_ip = self.DUT_IP4
            off_ka.remote_ip = self.LKP_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.DUT_IP6
            off_ka.remote_ip = self.LKP_IP6
            off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        probe_pkt = self.gen_tcpka_probe_pkt(off_ka, ipv)
        probe_pkt[TCP].chksum = 1337
        log.info("Prepared next probe packet:")
        probe_pkt.show()

        beton_file = os.path.join(self.test_log_dir, "remote_probe_ipv{}.txt".format(ipv))
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))
        time.sleep(self.AFTER_LINK_UP_DELAY)

        sock = get_l2_scapy_socket(self.lkp_scapy_iface)

        sniffer = Sniffer(port=self.lkp_port, timeout=20, filter="tcp")
        sniffer.run_async(iface=self.lkp_scapy_iface)

        for pkt_num in range(5):
            time.sleep(2)
            sock.send(probe_pkt)

        all_packets = sniffer.join()
        sock.close()

        wrpcap(os.path.join(self.test_log_dir, "packets.pcap"), all_packets)

        packets = [pkt for pkt in all_packets if
                   pkt[1].dst == (off_ka.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka.remote_ip))]
        wrpcap(os.path.join(self.test_log_dir, "packets-filter.pcap"), packets)

        assert len(packets) == 0, "FW answered on TCP KA probes with incorrect checksum"

    def test_no_wake_on_port_with_wrong_chksum(self):
        """
        @description: Test checksum filtering: FW doesn't wake the host on wake on port packet with incorrect checksum.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with TCP/UDP ports.
        3. Send TCP/UDP wake packets with incorrect checksum.

        @result: FW doesn't wake PC after receiving packets.
        @duration: 2 minutes.
        """
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC
        cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WOL

        cfg.ips = OffloadIpInfo()

        cfg.ips.v4_addr_count = 1
        cfg.ips.v4_addresses = [self.DUT_IP4]
        cfg.ips.v4_masks = [16]

        cfg.ips.v6_addr_count = 1
        cfg.ips.v6_addresses = [self.DUT_IP6]
        cfg.ips.v6_masks = [64]

        cfg.ports = OffloadPortInfo()
        cfg.ports.tcp_ports = [445, 5835]
        cfg.ports.udp_ports = [568, 3453]

        beton_file = os.path.join(self.test_log_dir, "offload_wake_on_ports.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))
        time.sleep(self.AFTER_LINK_UP_DELAY)

        prev_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter before sending wake packets: {}".format(prev_wake_counter))

        for address in cfg.ips.v4_addresses:
            for port in cfg.ports.tcp_ports:
                pkt = self.lkp_scapy_tools.get_wake_on_port_packet(dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                                                   dstip=address, srcip=self.LKP_IP4, protocol="tcp",
                                                                   dport=port)
                pkt[TCP].chksum = 7331
                self.lkp_scapy_tools.send_packet(pkt=pkt, iface=self.lkp_scapy_iface)
                time.sleep(1)
            assert self.get_wake_counter_on_dut() == prev_wake_counter, \
                "FW detected wake on port packet with incorrect checksum"
            for port in cfg.ports.udp_ports:
                pkt = self.lkp_scapy_tools.get_wake_on_port_packet(dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                                                   dstip=address, srcip=self.LKP_IP4, protocol="udp",
                                                                   dport=port)
                pkt[UDP].chksum = 7331
                self.lkp_scapy_tools.send_packet(pkt=pkt, iface=self.lkp_scapy_iface)
                time.sleep(1)
            assert self.get_wake_counter_on_dut() == prev_wake_counter, \
                "FW detected wake on port packet with incorrect checksum"

        for address in cfg.ips.v6_addresses:
            for port in cfg.ports.tcp_ports:
                pkt = self.lkp_scapy_tools.get_wake_on_port_packet(dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                                                   dstip=address, srcip=self.LKP_IP6, protocol="tcp",
                                                                   dport=port)
                pkt[TCP].chksum = 7331
                self.lkp_scapy_tools.send_packet(pkt=pkt, iface=self.lkp_scapy_iface)
                time.sleep(1)
            assert self.get_wake_counter_on_dut() == prev_wake_counter, \
                "FW detected wake on port packet with incorrect checksum"
            for port in cfg.ports.udp_ports:
                pkt = self.lkp_scapy_tools.get_wake_on_port_packet(dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                                                   dstip=address, srcip=self.LKP_IP6, protocol="udp",
                                                                   dport=port)
                pkt[UDP].chksum = 7331
                self.lkp_scapy_tools.send_packet(pkt=pkt, iface=self.lkp_scapy_iface)
                time.sleep(1)
            assert self.get_wake_counter_on_dut() == prev_wake_counter, \
                "FW detected wake on port packet with incorrect checksum"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
