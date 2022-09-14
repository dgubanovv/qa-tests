"""
This script must be executed on LKP
"""

import os
import random
import shutil
import time

import pytest

from tools.atltoolper import AtlTool
from tools.constants import FELICITY_CARDS, LINK_SPEED_AUTO
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvEthConfig, OffloadIpInfo, OffloadRrInfo, MdnsRr, OffloadPortInfo
from tools.samba import Samba
from tools.scapy_tools import ScapyTools, MDNSRecord, get_l2_scapy_socket
from tools.utils import get_atf_logger

from infra.test_base import TestBase

from scapy.all import Raw, RandString, sendp
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_sp_fragmentation"


class TestFW2xFragmentation(TestBase):
    """
    @description: The sleep proxy fragmentation test is dedicated to FW's ability to work with fragmented packets in
    sleep proxy mode which was introduced in FW 2.9.85.
    The test also checks FW's ability to filter packets (dst MAC address).

    @setup: Two Aquantia devices connected back to back.
    """

    AFTER_LINKUP_DELAY = 15

    DUT_IP4_LIST = ["192.168.10.21", "192.168.10.22", "192.168.10.23"]
    DUT_IP4_MASK_LIST = [24, 24, 24]
    DUT_IP6_LIST = ["4000:0000:0000:0000:1601:bd17:0c02:1021",
                    "4000:0000:0000:0000:1601:bd17:0c02:1022",
                    "4000:0000:0000:0000:1601:bd17:0c02:1023",
                    "4000:0000:0000:0000:1601:bd17:0c02:1024"]
    DUT_IP6_MASK_LIST = [64, 64, 64, 64]
    DUT_LINK_LOCAL_IP6 = "fe80:0000:0000:0000:1422:570e:fcb6:ad7e"

    LKP_IP4 = "192.168.10.100"
    LKP_IP4_MASK = "255.255.255.0"
    LKP_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:1100"
    LKP_IP6_MASK = "64"

    @classmethod
    def setup_class(cls):
        super(TestFW2xFragmentation, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest", host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4, cls.LKP_IP4_MASK, None)

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port)

            cls.dut_mac = cls.dut_atltool_wrapper.get_mac_address()
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()

            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()

            # Disable Samba to remove background multicast traffic which affects SerDes
            Samba(host=cls.lkp_hostname).stop()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestFW2xFragmentation, cls).teardown_class()

    def setup_method(self, method):
        super(TestFW2xFragmentation, self).setup_method(method)
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)

        self.lkp_ifconfig.set_ipv6_address(self.LKP_IP6, self.LKP_IP6_MASK, None)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)
            self.lkp_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestFW2xFragmentation, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

            self.lkp_bin_log_file, self.lkp_txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.lkp_bin_log_file, self.test_log_dir)
            shutil.copy(self.lkp_txt_log_file, self.test_log_dir)

    def get_wake_counter(self):
        wake_counter = self.dut_atltool_wrapper.get_wake_counter_2x()
        log.info("Current wake counter: {}".format(wake_counter))
        return wake_counter

    def send_port_and_verify(self, dut_addrs, lkp_addr, ports, protocol):
        assert protocol in ["tcp", "udp"]

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before sending wake packets: {}".format(prev_wake_counter))

        for address in dut_addrs:
            for port in ports:
                pkt = self.lkp_scapy_tools.get_wake_on_port_packet(dstmac=self.dut_mac, srcmac=self.lkp_mac,
                                                                   dstip=address, srcip=lkp_addr, protocol=protocol,
                                                                   dport=port, size=1000)
                log.info("Prepared next wake packet (length = {}):".format(len(pkt)))
                pkt.show()
                fragments = self.lkp_scapy_tools.fragment_packet(pkt, 200)
                if len(fragments) > 1:
                    log.debug("Fragments:")
                    for fr in fragments:
                        log.debug("Length = {} - {}".format(len(fr), fr.summary()))
                sendp(fragments, iface=self.lkp_scapy_iface)
                time.sleep(2)
        assert self.get_wake_counter() == prev_wake_counter + (len(dut_addrs) * len(ports)), \
            "FW didn't detect one of the wake on port packets"

    def test_ns_offload(self):
        """
        @description: Send fragmented NS request and check for reply.

        @steps:
        1. Configure DUT offload with multiple IPv6 addresses.
        2. Send fragmented NS request for each DUT's IP from LKP.
        3. Check that all requests are answered.

        @result: All NS requests are answered.
        @duration: 90 seconds.
        """
        cfg = DrvEthConfig()
        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.dut_mac

        cfg.ips = OffloadIpInfo()
        cfg.ips.v6_addr_count = len(self.DUT_IP6_LIST)
        cfg.ips.v6_addresses = self.DUT_IP6_LIST
        cfg.ips.v6_masks = self.DUT_IP6_MASK_LIST

        out_beton_filename = os.path.join(self.test_log_dir, "offload_ns.txt")
        cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        time.sleep(self.AFTER_LINKUP_DELAY)

        for address in cfg.ips.v6_addresses:
            log.info("Sending NS offload for IP {}".format(address))
            pkt = self.lkp_scapy_tools.get_address_resolution_packet(self.lkp_mac, address, self.LKP_IP6)
            pkt = pkt / Raw(load=RandString(500))
            fragments = self.lkp_scapy_tools.fragment_packet(pkt, 200)
            log.info("Fragments:")
            for fr in fragments:
                log.info(fr.summary())
            ans, unans = self.lkp_scapy_tools.sendrecv1(self.lkp_port, fragments, pkt, iface=self.lkp_scapy_iface)
            assert len(ans) == 1, "FW didn't answered on fragmented NS request"

    def test_mdns_offload(self):
        """
        @description: Send fragmented mDNS queries and check for responses.

        @steps:
        1. Configure DUT offload with multiple IPv4 and IPv6 addresses, mDNS records.
        2. Send fragmented mDNS query DUT's IP from LKP.
        3. Check that all queries are answered.

        @result: All queries are answered.
        @duration: 90 seconds.
        """
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.dut_mac

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = len(self.DUT_IP4_LIST)
        cfg.ips.v4_addresses = self.DUT_IP4_LIST
        cfg.ips.v4_masks = self.DUT_IP4_MASK_LIST
        cfg.ips.v6_addr_count = len(self.DUT_IP6_LIST)
        cfg.ips.v6_addresses = self.DUT_IP6_LIST
        cfg.ips.v6_masks = self.DUT_IP6_MASK_LIST

        # Add link local IPv6 address (required on any IPv6 interface)
        cfg.ips.v6_addr_count += 1
        cfg.ips.v6_addresses.append(self.DUT_LINK_LOCAL_IP6)
        cfg.ips.v6_masks.append(64)

        cfg.rrs = OffloadRrInfo()
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("standard.question.txt.local", "standard-answer.txt.local", ttl=1234)
        cfg.rrs.entries.append(mdns_txt)
        mdns_txt_2 = MdnsRr.get_drv_iface_txt_rr("super-duper-long-question-with-short-answer.question.txt.local",
                                                 "this-answer-is-nowhere-near-short.txt.local", ttl=4321)
        cfg.rrs.entries.append(mdns_txt_2)

        out_beton_filename = os.path.join(self.test_log_dir, "offload_mdns.txt")
        cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        time.sleep(self.AFTER_LINKUP_DELAY)

        queries = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl),
                   MDNSRecord("TXT", "filler-question-aaaaaaaaaaaaaaaaaaaaaaaaa.question.txt.local", []),
                   MDNSRecord("TXT", mdns_txt_2.question, [mdns_txt_2.txt], ttl=mdns_txt_2.tail.ttl),
                   MDNSRecord("TXT", "filler-question-bbbbbbbbbbbbbbbbbbbbbbbbb.question.txt.local", [])]

        log.info("Testing multicast IPv4 request")
        assert self.lkp_scapy_tools.mdns_request(srcip=self.LKP_IP4, queries=queries, srcmac=self.lkp_mac,
                                                 expected_ip=cfg.ips.v4_addresses[0], iface=self.lkp_scapy_iface,
                                                 fragment_size=100), \
            "Failed while requesting mDNS query. See log above for details"

        log.info("Testing unicast IPv4 requests")
        for address in cfg.ips.v4_addresses:
            assert self.lkp_scapy_tools.mdns_request(dstip=address, srcip=self.LKP_IP4, queries=queries,
                                                     dstmac=self.dut_mac, srcmac=self.lkp_mac, expected_ip=address,
                                                     iface=self.lkp_scapy_iface, fragment_size=100), \
                "Failed while requesting mDNS query. See log above for details"

        log.info("Testing multicast IPv6 request")
        assert self.lkp_scapy_tools.mdns_request(srcip=self.LKP_IP6, queries=queries, srcmac=self.lkp_mac,
                                                 iface=self.lkp_scapy_iface, fragment_size=100), \
            "Failed while requesting mDNS query. See log above for details"

        log.info("Testing unicast IPv6 requests")
        for address in cfg.ips.v6_addresses:
            assert self.lkp_scapy_tools.mdns_request(dstip=address, srcip=self.LKP_IP6, queries=queries,
                                                     dstmac=self.dut_mac, srcmac=self.lkp_mac,
                                                     expected_ip=cfg.ips.v6_addresses[0], iface=self.lkp_scapy_iface,
                                                     fragment_size=100), \
                "Failed while requesting mDNS query. See log above for details"

    def test_shuffle(self):
        """
        @description: Send fragmented ICMP echo requests and check for replies.

        @steps:
        1. Configure DUT offload with IPv4 and IPv6 addresses.
        2. Send fragmented ICMP echo request with fragments in random ordermDNS query DUT's IP from LKP.
        3. Check that all requests are answered.

        @result: All requests are answered.
        @duration: 90 seconds.
        """
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.dut_mac

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = 1
        cfg.ips.v4_addresses = self.DUT_IP4_LIST[:1]
        cfg.ips.v4_masks = self.DUT_IP4_MASK_LIST[:1]
        cfg.ips.v6_addr_count = 1
        cfg.ips.v6_addresses = self.DUT_IP6_LIST[:1]
        cfg.ips.v6_masks = self.DUT_IP6_MASK_LIST[:1]

        out_beton_filename = os.path.join(self.test_log_dir, "offload_shuffle.txt")
        cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        time.sleep(self.AFTER_LINKUP_DELAY)

        def test_shuffled_echo_request(dstip, srcip):
            pkt = ScapyTools.get_echo_request_packet(srcmac=self.lkp_mac, dstip=dstip, srcip=srcip, dstmac=self.dut_mac,
                                                     size=2000, seq=1)
            log.info("Prepared next packet (length = {}):".format(len(pkt)))
            fragments = ScapyTools.fragment_packet(pkt, fragment_size=200)
            random.shuffle(fragments)
            log.info("Fragments:")
            for fr in fragments:
                log.info("Length = {} - {}".format(len(fr), fr.summary()))
            ans, unans = self.lkp_scapy_tools.sendrecv1(self.lkp_port, fragments, pkt, iface=self.lkp_scapy_iface)
            assert len(ans) == 1, "FW didn't answered on shuffled fragmented echo request"

        log.info("Testing IPv4 echo request")
        test_shuffled_echo_request(cfg.ips.v4_addresses[0], self.LKP_IP4)
        # TODO: fix answer detection for ICMPv6
        # log.info("Testing IPv6 echo request")
        # test_shuffled_echo_request(cfg.ips.v6_addresses[0], self.LKP_IP6)

    def test_wake_on_udp_magic(self):
        """
        @description: Send fragmented UDP magic packet and check that FW tries to wake host up.

        @steps:
        1. Configure DUT offload with enabled WoL.
        2. Send fragmented UDP magic packet from LKP.
        3. Check that DUT tried to wake host up.

        @result: DUT detected fragmented magic packet and tried to wake host up.
        @duration: 90 seconds.
        """
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.dut_mac
        cfg.caps = DrvEthConfig.CAPS_HI_WOL | DrvEthConfig.CAPS_HI_SLEEP_PROXY

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = 1
        cfg.ips.v4_addresses = self.DUT_IP4_LIST[:1]
        cfg.ips.v4_masks = self.DUT_IP4_MASK_LIST[:1]

        out_beton_filename = os.path.join(self.test_log_dir, "offload_wake_magic.txt")
        cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        time.sleep(self.AFTER_LINKUP_DELAY)

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before sending magic packet: {}".format(prev_wake_counter))

        pkt = ScapyTools.get_udp_magic_packet(dstmac=self.dut_mac, srcmac=self.lkp_mac, srcip=self.LKP_IP4,
                                              dstip=cfg.ips.v4_addresses[0])
        pkt[Raw].load = str(RandString(200)) + pkt[Raw].load
        log.info("Prepared next magic packet (length = {}):".format(len(pkt)))
        pkt.show()
        fragments = ScapyTools.fragment_packet(pkt, fragment_size=200)
        log.info("Fragments:")
        for fr in fragments:
            log.info("Length = {} - {}".format(len(fr), fr.summary()))
        sock = get_l2_scapy_socket(self.lkp_scapy_iface)
        for fr in fragments:
            sock.send(fr)
        sock.close()

        assert self.get_wake_counter() > prev_wake_counter, "FW didn't detect fragmented magic packet"

    def test_wake_on_port(self):
        """
        @description: Send fragmented TCP/UDP on specific port and check that FW tries to wake host up.

        @steps:
        1. Configure DUT offload with enabled WoL on network ports.
        2. Send fragmented TCP/UDP packet to specific port.
        3. Check that DUT tried to wake host up.

        @result: DUT detected fragmented Wake on Port packet and tried to wake host up.
        @duration: 90 seconds.
        """
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.dut_mac
        cfg.caps = DrvEthConfig.CAPS_HI_WOL | DrvEthConfig.CAPS_HI_SLEEP_PROXY

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = len(self.DUT_IP4_LIST)
        cfg.ips.v4_addresses = self.DUT_IP4_LIST
        cfg.ips.v4_masks = self.DUT_IP4_MASK_LIST
        cfg.ips.v6_addr_count = len(self.DUT_IP6_LIST)
        cfg.ips.v6_addresses = self.DUT_IP6_LIST
        cfg.ips.v6_masks = self.DUT_IP6_MASK_LIST

        cfg.ports = OffloadPortInfo()
        cfg.ports.tcp_ports = [4933, 5347]
        cfg.ports.udp_ports = [6896, 8392]

        out_beton_filename = os.path.join(self.test_log_dir, "offload_wake_on_port.txt")
        cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        time.sleep(self.AFTER_LINKUP_DELAY)

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        self.send_port_and_verify(cfg.ips.v4_addresses, self.LKP_IP4, cfg.ports.tcp_ports, "tcp")
        self.send_port_and_verify(cfg.ips.v4_addresses, self.LKP_IP4, cfg.ports.udp_ports, "udp")
        self.send_port_and_verify(cfg.ips.v6_addresses, self.LKP_IP6, cfg.ports.tcp_ports, "tcp")
        self.send_port_and_verify(cfg.ips.v6_addresses, self.LKP_IP6, cfg.ports.udp_ports, "udp")


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
