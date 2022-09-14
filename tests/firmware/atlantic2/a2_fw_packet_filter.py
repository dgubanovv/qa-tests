"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import pytest
import time
import sys

import shutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import MdnsRr, OffloadRrInfo, MdnsRrTail, MdnsRdataSrv
from tools.scapy_tools import ScapyTools, get_l2_scapy_socket, MDNSRecord, MULTICAST_MDNS_MAC_IP4, \
    MULTICAST_MDNS_MAC_IP6, MULTICAST_MDNS_IP4, MULTICAST_MDNS_IP6
from tools.samba import Samba
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config, SleepProxyOffload, MDNSOffload
from tools.sniffer import Sniffer
from tools.utils import get_atf_logger, get_compressed_ipv6

from infra.test_base import TestBase, idparametrize

from scapy.all import conf, Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, Padding, RandString, wrpcap

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup   # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_packet_filter"


class TestPacketFilter(TestBase):
    """
    @description: The packet filtering tests are dedicated to check FW's ability to filter packets in sleep proxy mode.

    @setup: Two Aquantia devices connected back to back.
    """
    AFTER_LINK_UP_DELAY = 15
    WAKE_COUNTER_DELAY = 2

    DEFAULT_IDX_OFFSET = 200
    DEFAULT_RR_OFFSET = 2000

    DUT_MAC = "00:17:b6:00:07:82"
    FW_REMOTE_MAC = "00:17:b6:33:44:91"

    LKP_IP4 = "169.254.23.111"
    NETMASK = "255.255.0.0"
    LKP_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2487"


    DEFAULT_SLEEP_IP4S = ["169.254.23.232", "169.254.23.231", "169.254.23.230"]
    DEFAULT_SLEEP_IP6S = ['4000:0000:0000:0000:1601:bd17:0c02:2400',
                          '4000:0000:0000:0000:1601:bd17:0c02:2436',
                          '4000:0000:0000:0000:1601:bd17:0c02:2431',
                          '4000:0000:0000:0000:1601:bd17:0c02:2412',
                          '4000:0000:0000:0000:1601:bd17:0c02:2404']

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
            cls.fw_config = FirmwareA2Config(cls.dut_atltool_wrapper)

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
        self.dut_atltool_wrapper.kickstart2()

    def get_wake_counter_on_dut(self):
        """Read wake counter from MCP memory on DUT"""
        return self.dut_atltool_wrapper.get_wake_counter_2x()

    def get_wake_reason_on_dut(self):
        wake_reason = self.dut_atltool_wrapper.get_wake_reason_2x()
        log.info("Wake reason: {}".format(hex(wake_reason)))
        return wake_reason

    def gen_tcpka_probe_pkt(self, off_ka, ipv):
        probe_pkt = Ether(dst=self.DUT_MAC, src=off_ka.remote_mac_addr)
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

    def get_mds_offload_for_entries(self, entries, idx_offset, rr_offset):
        mdns_offload = MDNSOffload()
        mdns_offload.rr_count = len(entries)
        mdns_offload.rr_buf_len = sum([entrie.SIZEOF for entrie in entries])
        mdns_offload.idx_offset = idx_offset
        mdns_offload.rr_offset = rr_offset
        log.info("MDNS Offload structure:\n rr_count: {}\n rr_buf_len: {}\n idx_offset: {}\n rr_offset: {}\n".format(
            mdns_offload.rr_count, mdns_offload.rr_buf_len, mdns_offload.idx_offset, mdns_offload.rr_offset
        ))
        return mdns_offload

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
        cfg = SleepProxyOffload()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC

        cfg.ipv4_offload.ipv4[:3] = self.DEFAULT_SLEEP_IP4S

        log.info('Configuring IPv4 addresses: {}'.format(cfg.ipv4_offload.ipv4))
        cfg.ipv6_offload.ipv6[:5] = self.DEFAULT_SLEEP_IP6S
        log.info('Configuring IPv4 addresses: {}'.format(cfg.ipv6_offload.ipv6))
        # Add link local IPv6 address (required on any IPv6 interface)
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
        entries = []
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("WhatAreThose?!._ssh._udp.local", "AdddidasShoes", ttl=2015)
        entries.append(mdns_txt)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "txt_record.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
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
            for address in self.DEFAULT_SLEEP_IP4S:
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
            for address in self.DEFAULT_SLEEP_IP6S:
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
        entries = []
        cfg = self.get_drv_cfg_with_ips()

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
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "record.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))
        time.sleep(self.AFTER_LINK_UP_DELAY)

        prev_wol_status = self.fw_config.get_fw_wol_status()

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

        # Check if FW tried to wake PC
        wol_status = self.fw_config.get_fw_wol_status()
        assert prev_wol_status.wakeCount == wol_status.wakeCount, \
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
        wol_status = self.fw_config.get_fw_wol_status()
        assert prev_wol_status.wakeCount == wol_status.wakeCount, \
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

        sp_cfg = self.get_drv_cfg_with_ips()

        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload
        ka_offload.retry_count = 3
        ka_offload.retry_interval = 2000

        # FW starts to count down timeout right after config
        off_ka = ka_offload.offloads[0]
        off_ka.operation_timeout = 60
        off_ka.local_port = 23
        off_ka.remote_port = 22
        off_ka.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka.win_size = 1000
        off_ka.seq_num = 2456
        off_ka.ack_num = 1212

        if ipv == 4:
            off_ka.local_ip = self.DEFAULT_SLEEP_IP4S[0]
            off_ka.remote_ip = self.LKP_IP4
        else:
            off_ka.local_ip = self.DEFAULT_SLEEP_IP6S[0]
            off_ka.remote_ip = self.LKP_IP6

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        probe_pkt = self.gen_tcpka_probe_pkt(off_ka, ipv)
        probe_pkt[TCP].chksum = 1337
        log.info("Prepared next probe packet:")
        probe_pkt.show()

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
        sp_cfg = self.get_drv_cfg_with_ips()

        sp_cfg.tcp_port_offload.ports[0] = 445
        sp_cfg.tcp_port_offload.ports[1] = 5835
        sp_cfg.udp_port_offload.ports[0] = 568
        sp_cfg.udp_port_offload.ports[1] = 3453

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        prev_wol_status = self.fw_config.get_fw_wol_status()

        for address in self.DEFAULT_SLEEP_IP4S:
            for port in sp_cfg.tcp_port_offload.ports:
                pkt = self.lkp_scapy_tools.get_wake_on_port_packet(dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                                                   dstip=address, srcip=self.LKP_IP4, protocol="tcp",
                                                                   dport=port)
                pkt[TCP].chksum = 7331
                self.lkp_scapy_tools.send_packet(pkt=pkt, iface=self.lkp_scapy_iface)
                time.sleep(1)
            wol_status = self.fw_config.get_fw_wol_status()
            assert prev_wol_status.wakeCount == wol_status.wakeCount, \
                "FW detected wake on port packet with incorrect checksum"
            for port in sp_cfg.udp_port_offload.ports:
                pkt = self.lkp_scapy_tools.get_wake_on_port_packet(dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                                                   dstip=address, srcip=self.LKP_IP4, protocol="udp",
                                                                   dport=port)
                pkt[UDP].chksum = 7331
                self.lkp_scapy_tools.send_packet(pkt=pkt, iface=self.lkp_scapy_iface)
                time.sleep(1)
            wol_status = self.fw_config.get_fw_wol_status()
            assert prev_wol_status.wakeCount == wol_status.wakeCount, \
                "FW detected wake on port packet with incorrect checksum"

        for address in self.DEFAULT_SLEEP_IP6S:
            for port in sp_cfg.tcp_port_offload.ports:
                pkt = self.lkp_scapy_tools.get_wake_on_port_packet(dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                                                   dstip=address, srcip=self.LKP_IP6, protocol="tcp",
                                                                   dport=port)
                pkt[TCP].chksum = 7331
                self.lkp_scapy_tools.send_packet(pkt=pkt, iface=self.lkp_scapy_iface)
                time.sleep(1)
            wol_status = self.fw_config.get_fw_wol_status()
            assert prev_wol_status.wakeCount == wol_status.wakeCount, \
                "FW detected wake on port packet with incorrect checksum"
            for port in sp_cfg.udp_port_offload.ports:
                pkt = self.lkp_scapy_tools.get_wake_on_port_packet(dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                                                   dstip=address, srcip=self.LKP_IP6, protocol="udp",
                                                                   dport=port)
                pkt[UDP].chksum = 7331
                self.lkp_scapy_tools.send_packet(pkt=pkt, iface=self.lkp_scapy_iface)
                time.sleep(1)
            wol_status = self.fw_config.get_fw_wol_status()
            assert prev_wol_status.wakeCount == wol_status.wakeCount, \
                "FW detected wake on port packet with incorrect checksum"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
