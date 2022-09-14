import os
import re
import shutil
import time

import pytest

from infra.test_base import TestBase, idparametrize
from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import LINK_SPEED_AUTO, FELICITY_CARDS, ATF_TOOLS_DIR, LINK_STATE_DOWN, LINK_STATE_UP, \
    LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_NO_LINK
from tools.driver import Driver, DRV_TYPE_DIAG
from tools import drv_iface_cfg
from tools.drv_iface_cfg import DrvMessage, DrvEthConfig, OffloadIpInfo, OffloadPortInfo, DrvWinWoLConfig, \
    DrvMsgWoLAddPattern, OffloadRrInfo, MdnsRr, MdnsRrTail, MdnsRdataSrv, FWSettings, SettingsMemory
from tools.samba import Samba
from tools.scapy_tools import ScapyTools, get_ipv6_multicast_mac, MULTICAST_MDNS_MAC_IP4, MULTICAST_MDNS_MAC_IP6, \
    MULTICAST_MDNS_IP4, MULTICAST_MDNS_IP6, get_ns_multicast_ip, MULTICAST_ND_IP6
from tools.utils import get_atf_logger

# For fake packets
from scapy.all import Ether, ARP, IP, IPv6, ICMP, TCP, UDP, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, ICMPv6EchoRequest, DNS, \
    DNSQR, DNSRR, RandString, Raw, hexdump
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_wol_sanity"


class TestFW2XWoL(TestBase):
    REMOTE_CMD_TIMEOUT = 30
    WOL_LINK_DELAY = 10
    AFTER_LINK_UP_DELAY = 30  # This is needed for windows to send all it's useless packets
    WAKE_COUNTER_DELAY = 1

    DUT_IPs4 = ["192.168.0.3",
                "192.168.0.4",
                "192.168.0.5"]
    LKP_IP4 = "192.168.0.2"
    NETMASK_IP4 = "255.255.255.0"
    MULTICAST_IP4 = "192.168.0.255"

    DUT_IPs6 = ["4000:0000:0000:0000:1601:bd17:0c02:2403",
                "4000:0000:0000:0000:1601:bd17:0c02:2413",
                "4000:0000:0000:0000:1601:bd17:0c02:2423",
                "4000:0000:0000:0000:1601:bd17:0c02:2433",
                "4000:0000:0000:0000:1601:bd17:0c02:2443"]
    LKP_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2402"
    PREFIX_IP6 = "64"

    DUT_MAC = "00:17:b6:00:07:82"
    BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

    FAKE_MAC = "00:00:de:ad:fa:ce"
    FAKE_IP4 = "192.168.0.69"
    FAKE_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:0069"

    WAKEPORT = 13370

    @classmethod
    def setup_class(cls):
        super(TestFW2XWoL, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4, cls.NETMASK_IP4, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6, cls.PREFIX_IP6, None)

            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.dut_fw_ver_maj = cls.atltool_wrapper.get_fw_version()[0]

            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()

            # Disable WOL on LKP to avoid problem with link down on Linux
            cls.lkp_ifconfig.set_power_mgmt_settings(False, False, False)

            # Disable Samba to remove background multicast traffic which affects SerDes
            Samba(host=cls.lkp_hostname).stop()
        except Exception as e:
            log.exception(e)
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestFW2XWoL, cls).teardown_class()

    def setup_method(self, method):
        super(TestFW2XWoL, self).setup_method(method)
        if self.dut_firmware.is_3x():
            # FW 3X requires kickstart after each configuration
            self.atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestFW2XWoL, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        if self.MCP_LOG:
            self.atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

    def configure_simple_offloads(self):
        log.info("Configuring offloads")
        eth_cfg = DrvEthConfig()

        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC
        eth_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY
        log.info("Configuring MAC address: {}".format(eth_cfg.mac))

        eth_cfg.ips = OffloadIpInfo()

        eth_cfg.ips.v4_addr_count = 1
        eth_cfg.ips.v4_addresses = [self.DUT_IPs4[0]]
        eth_cfg.ips.v4_masks = [24]
        log.info("Configuring IPv4 addresses: {}".format(eth_cfg.ips.v4_addresses))
        eth_cfg.ips.v6_addr_count = 1
        eth_cfg.ips.v6_addresses = [self.DUT_IPs6[0]]
        eth_cfg.ips.v6_masks = [64]
        log.info("Configuring IPv6 addresses: {}".format(eth_cfg.ips.v6_addresses))

        beton_file = os.path.join(self.test_log_dir, "offload_fw.txt")
        eth_cfg.apply(self.atltool_wrapper, beton_file, cleanup_fw=True)
        time.sleep(0.5)

    def send_magic_packets_and_check(self):
        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before sending magic packets: {}".format(prev_wake_counter))

        log.info("Sending unicast UDP magic packet from LKP")
        self.lkp_scapy_tools.send_udp_magic_packet(dstmac=self.DUT_MAC, srcip=self.LKP_IP4,
                                                   dstip=self.MULTICAST_IP4, srcmac=self.lkp_mac, broadcast=False,
                                                   iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        curr_wake_counter = self.get_wake_counter()
        wake_reason = self.get_wake_reason()
        assert curr_wake_counter > prev_wake_counter, "FW didn't detect magic packet"
        assert wake_reason == drv_iface_cfg.WAKE_REASON_MAGIC_PACKET, \
            "Wake reason mismatch. Current: {}; Expected: {}".format(
                wake_reason, drv_iface_cfg.WAKE_REASON_MAGIC_PACKET)
        prev_wake_counter = curr_wake_counter

        log.info("Sending unicast RAW magic packet")
        self.lkp_scapy_tools.send_raw_magic_packet(dstmac=self.DUT_MAC, srcmac=self.lkp_mac, broadcast=False,
                                                   iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        curr_wake_counter = self.get_wake_counter()
        wake_reason = self.get_wake_reason()
        assert curr_wake_counter > prev_wake_counter, "FW didn't detect magic packet"
        assert wake_reason == drv_iface_cfg.WAKE_REASON_MAGIC_PACKET, \
            "Wake reason mismatch. Current: {}; Expected: {}".format(
                wake_reason, drv_iface_cfg.WAKE_REASON_MAGIC_PACKET)
        prev_wake_counter = curr_wake_counter

        log.info("Sending broadcast UDP magic packet from LKP")
        self.lkp_scapy_tools.send_udp_magic_packet(dstmac=self.DUT_MAC, srcip=self.LKP_IP4,
                                                   dstip=self.MULTICAST_IP4, srcmac=self.lkp_mac, broadcast=True,
                                                   iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        curr_wake_counter = self.get_wake_counter()
        wake_reason = self.get_wake_reason()
        assert curr_wake_counter > prev_wake_counter, "FW didn't detect magic packet"
        assert wake_reason == drv_iface_cfg.WAKE_REASON_MAGIC_PACKET, \
            "Wake reason mismatch. Current: {}; Expected: {}".format(
                wake_reason, drv_iface_cfg.WAKE_REASON_MAGIC_PACKET)
        prev_wake_counter = curr_wake_counter

        log.info("Sending broadcast RAW magic packet")
        self.lkp_scapy_tools.send_raw_magic_packet(dstmac=self.DUT_MAC, srcmac=self.lkp_mac, broadcast=True,
                                                   iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        curr_wake_counter = self.get_wake_counter()
        wake_reason = self.get_wake_reason()
        assert curr_wake_counter > prev_wake_counter, "FW didn't detect magic packet"
        assert wake_reason == drv_iface_cfg.WAKE_REASON_MAGIC_PACKET, \
            "Wake reason mismatch. Current: {}; Expected: {}".format(
                wake_reason, drv_iface_cfg.WAKE_REASON_MAGIC_PACKET)

    def get_wake_counter(self):
        wake_counter = self.atltool_wrapper.get_wake_counter_2x()
        log.info("Current wake counter: {}".format(wake_counter))
        return wake_counter

    def get_wake_reason(self):
        wake_reason = self.atltool_wrapper.get_wake_reason_2x()
        log.info("Wake reason: {}".format(hex(wake_reason)))
        return wake_reason

    def send_port_and_verify(self, dut_addrs, lkp_addr, ports, protocol, mac, iface):
        assert protocol in ["tcp", "udp"]

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before sending wake packets: {}".format(prev_wake_counter))

        for address in dut_addrs:
            for port in ports:
                self.lkp_scapy_tools.wake_on_port(dstip=address, srcip=lkp_addr, dstmac=mac, dport=port,
                                                  protocol=protocol, srcmac=self.lkp_mac, iface=iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        expected_wake_reason = drv_iface_cfg.WAKE_REASON_SYN if protocol == "tcp" else drv_iface_cfg.WAKE_REASON_UDP
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + (len(dut_addrs) * len(ports)), \
            "FW didn't detect one of the wake on port packets"
        if len(dut_addrs) != 0:
            assert wake_reason == expected_wake_reason, "Wake reason mismatch. Expected: {}. Current: {}".format(
                expected_wake_reason, wake_reason
            )

    @idparametrize("sleep_proxy", [
        pytest.param(False, marks=pytest.mark.xfail(reason="MAC not available without sleep proxy being configured")),
        True
    ])
    def test_magic_packet_only(self, sleep_proxy):
        eth_cfg = DrvEthConfig()

        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC
        eth_cfg.caps = DrvEthConfig.CAPS_HI_WOL
        if sleep_proxy:
            eth_cfg.caps = eth_cfg.caps | DrvEthConfig.CAPS_HI_SLEEP_PROXY

        ips = OffloadIpInfo()
        eth_cfg.ips = ips

        beton_file = os.path.join(self.test_log_dir, "offload_magic.txt")
        eth_cfg.apply(self.atltool_wrapper, beton_file, cleanup_fw=True)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        self.send_magic_packets_and_check()

    def test_long_magic_packet(self):
        if self.dut_fw_ver_maj != 3:
            pytest.skip()

        self.configure_simple_offloads()

        log.info("Configuring wake on lan")
        wol_cfg = DrvWinWoLConfig()

        wol_cfg.mac = self.DUT_MAC
        wol_cfg.magic_enabled = True
        wol_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WOL

        beton_file = os.path.join(self.test_log_dir, "wol_magic_only.txt")
        wol_cfg.apply(self.atltool_wrapper, beton_file, cleanup_fw=False)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        log.info("Sleeping 45 seconds (serdes should be up 60 seconds after link up")
        time.sleep(45)

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before sending magic packet: {}".format(prev_wake_counter))

        pkt = Ether(dst=self.DUT_MAC, src=self.lkp_mac, type=0x0842)
        payload = str(RandString(1000)) + "\xFF" * 6 + (self.DUT_MAC.replace(self.DUT_MAC[2], "") * 16).decode("hex")
        pkt = pkt / Raw(load=payload)
        log.info("Sending unicast RAW magic packet")
        hexdump(pkt)
        self.lkp_scapy_tools.send_packet(pkt)

        time.sleep(self.WAKE_COUNTER_DELAY)
        curr_wake_counter = self.get_wake_counter()
        wake_reason = self.get_wake_reason()
        assert curr_wake_counter > prev_wake_counter, "FW didn't detect magic packet"
        assert wake_reason == drv_iface_cfg.WAKE_REASON_MAGIC_PACKET, \
            "Wake reason mismatch. Current: {}; Expected: {}".format(
                wake_reason, drv_iface_cfg.WAKE_REASON_MAGIC_PACKET)

    def test_win_iface_magic_pkt_only(self):
        self.configure_simple_offloads()

        log.info("Configuring wake on lan")
        wol_cfg = DrvWinWoLConfig()

        wol_cfg.mac = self.DUT_MAC
        wol_cfg.magic_enabled = True
        wol_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WOL

        beton_file = os.path.join(self.test_log_dir, "wol_magic_only.txt")
        wol_cfg.apply(self.atltool_wrapper, beton_file, cleanup_fw=False)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        self.send_magic_packets_and_check()

    @idparametrize("magic", [False, True])
    def test_win_iface_1_filter(self, magic):
        self.configure_simple_offloads()

        log.info("Configuring wake on lan")
        wol_cfg = DrvWinWoLConfig()

        wol_cfg.mac = self.DUT_MAC
        wol_cfg.magic_enabled = magic
        wol_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WOL

        # ARP who has 192.168.0.3
        filter = DrvMsgWoLAddPattern()
        filter.mask = [0x00, 0x30, 0x03, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        filter.crc = 0x1479
        wol_cfg.filters.append(filter)

        beton_file = os.path.join(self.test_log_dir, "wol_1_filter.txt")
        wol_cfg.apply(self.atltool_wrapper, beton_file, cleanup_fw=False)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        if magic:
            self.send_magic_packets_and_check()

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before sending wake packet: {}".format(prev_wake_counter))

        log.info("Sending ARP request from LKP")
        self.lkp_scapy_tools.arping(dstip=self.DUT_IPs4[0], srcip=self.LKP_IP4, dstmac=self.DUT_MAC,
                                    srcmac=self.lkp_mac, iface=None)
        time.sleep(self.WAKE_COUNTER_DELAY)
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 1, "FW didn't detect ARP packet"
        assert wake_reason == drv_iface_cfg.WAKE_REASON_FILTER, "Wake reason mismatch. Current: {} Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_FILTER
        )

    @idparametrize("magic", [False, True])
    def test_win_iface_all_filters(self, magic):
        self.configure_simple_offloads()

        log.info("Configuring wake on lan")
        wol_cfg = DrvWinWoLConfig()

        wol_cfg.mac = self.DUT_MAC
        wol_cfg.magic_enabled = magic

        wol_cfg.caps = DrvMessage.CAPS_HI_WOL | DrvMessage.CAPS_HI_SLEEP_PROXY

        # IPv4 TCP SYN anyone
        filter = DrvMsgWoLAddPattern()
        filter.mask = [0x00, 0x70, 0x80, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        filter.crc = 0x6f98
        wol_cfg.filters.append(filter)

        # IPv6 TCP SYN anyone
        filter = DrvMsgWoLAddPattern()
        filter.mask = [0x00, 0x70, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        filter.crc = 0x7e53
        wol_cfg.filters.append(filter)

        # Ping echo request to 192.168.0.3
        filter = DrvMsgWoLAddPattern()
        filter.mask = [0x00, 0x70, 0x80, 0xc0, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        filter.crc = 0x5830
        wol_cfg.filters.append(filter)

        # Ping echo IPv6 request to 4000:0000:0000:0000:1601:bd17:0c02:2403
        filter = DrvMsgWoLAddPattern()
        filter.mask = [0x00, 0x70, 0x10, 0x00, 0xc0, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        filter.crc = 0x9c06
        wol_cfg.filters.append(filter)

        # ARP who has 192.168.0.3
        filter = DrvMsgWoLAddPattern()
        filter.mask = [0x00, 0x30, 0x03, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        filter.crc = 0x1479
        wol_cfg.filters.append(filter)

        # NS for 4000:0000:0000:0000:1601:bd17:0c02:2403
        filter = DrvMsgWoLAddPattern()
        filter.mask = [0x00, 0x70, 0x10, 0x00, 0xc0, 0xff, 0x7f, 0xc0, 0xff, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        filter.crc = 0x2e60
        wol_cfg.filters.append(filter)

        # IPv4 UDP with port 13370
        filter = DrvMsgWoLAddPattern()
        filter.mask = [0x00, 0x70, 0x80, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        filter.crc = 0xfb90
        wol_cfg.filters.append(filter)

        # IPv6 UDP with port 13370
        filter = DrvMsgWoLAddPattern()
        filter.mask = [0x00, 0x70, 0x10, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        filter.crc = 0x3280
        wol_cfg.filters.append(filter)

        beton_file = os.path.join(self.test_log_dir, "wol_all_filters.txt")
        wol_cfg.apply(self.atltool_wrapper, beton_file, cleanup_fw=False)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        # Cache scapy iface on LKP
        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        if magic:
            self.send_magic_packets_and_check()

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        filter_name = "IPv4 TCP SYN anyone"
        log.info("Checking filter #1: {}".format(filter_name))
        self.lkp_scapy_tools.wake_on_port(dstip=self.DUT_IPs4[0], srcip=self.LKP_IP4, dstmac=self.DUT_MAC, dport=12345,
                                          protocol="tcp", srcmac=self.lkp_mac, iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 1, "FW didn't detect '{}' packet".format(filter_name)
        assert wake_reason == drv_iface_cfg.WAKE_REASON_FILTER, "Wake reason mismatch. Current: {} Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_FILTER
        )

        filter_name = "IPv6 TCP SYN anyone"
        log.info("Checking filter #2: {}".format(filter_name))
        self.lkp_scapy_tools.wake_on_port(dstip=self.DUT_IPs6[0], srcip=self.LKP_IP6, dstmac=self.DUT_MAC, dport=12345,
                                          protocol="tcp", srcmac=self.lkp_mac, iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 2, "FW didn't detect '{}' packet".format(filter_name)
        assert wake_reason == drv_iface_cfg.WAKE_REASON_FILTER, "Wake reason mismatch. Current: {} Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_FILTER
        )

        filter_name = "Ping echo request to 192.168.0.3"
        log.info("Checking filter #3: {}".format(filter_name))
        self.lkp_scapy_tools.ping(dstip=self.DUT_IPs4[0], srcip=self.LKP_IP4, dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                  number=1, iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 3, "FW didn't detect '{}' packet".format(filter_name)
        assert wake_reason == drv_iface_cfg.WAKE_REASON_FILTER, "Wake reason mismatch. Current: {} Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_FILTER
        )

        filter_name = "Ping echo IPv6 request to 4000:0000:0000:0000:1601:bd17:0c02:2403"
        log.info("Checking filter #4: {}".format(filter_name))
        self.lkp_scapy_tools.ping(dstip=self.DUT_IPs6[0], srcip=self.LKP_IP6, dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                  number=1, iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 4, "FW didn't detect '{}' packet".format(filter_name)
        assert wake_reason == drv_iface_cfg.WAKE_REASON_FILTER, "Wake reason mismatch. Current: {} Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_FILTER
        )

        filter_name = "ARP who has 192.168.0.3"
        log.info("Checking filter #5: {}".format(filter_name))
        self.lkp_scapy_tools.arping(dstip=self.DUT_IPs4[0], srcip=self.LKP_IP4, dstmac=self.DUT_MAC,
                                    srcmac=self.lkp_mac, iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 5, "FW didn't detect '{}' packet".format(filter_name)
        assert wake_reason == drv_iface_cfg.WAKE_REASON_FILTER, "Wake reason mismatch. Current: {} Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_FILTER
        )

        filter_name = "NS for 4000:0000:0000:0000:1601:bd17:0c02:2403"
        log.info("Checking filter #6: {}".format(filter_name))
        self.lkp_scapy_tools.arping(dstip=self.DUT_IPs6[0], srcip=self.LKP_IP6, dstmac=self.DUT_MAC,
                                    srcmac=self.lkp_mac, iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 6, "FW didn't detect '{}' packet".format(filter_name)
        assert wake_reason == drv_iface_cfg.WAKE_REASON_FILTER, "Wake reason mismatch. Current: {} Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_FILTER
        )

        filter_name = "IPv4 UDP with port 13370"
        log.info("Checking filter #7: {}".format(filter_name))
        self.lkp_scapy_tools.wake_on_port(dstip=self.DUT_IPs4[0], srcip=self.LKP_IP4, dstmac=self.DUT_MAC,
                                          dport=self.WAKEPORT, protocol="udp", srcmac=self.lkp_mac,
                                          iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 7, "FW didn't detect '{}' packet".format(filter_name)
        assert wake_reason == drv_iface_cfg.WAKE_REASON_FILTER, "Wake reason mismatch. Current: {} Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_FILTER
        )

        filter_name = "IPv6 UDP with port 13370"
        log.info("Checking filter #8: {}".format(filter_name))
        self.lkp_scapy_tools.wake_on_port(dstip=self.DUT_IPs6[0], srcip=self.LKP_IP6, dstmac=self.DUT_MAC,
                                          dport=self.WAKEPORT, protocol="udp", srcmac=self.lkp_mac,
                                          iface=lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 8, "FW didn't detect '{}' packet".format(filter_name)
        assert wake_reason == drv_iface_cfg.WAKE_REASON_FILTER, "Wake reason mismatch. Current: {} Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_FILTER
        )

    def test_win_iface_link_up(self):
        self.configure_simple_offloads()

        log.info("Configuring wake on lan")
        wol_cfg = DrvWinWoLConfig()

        wol_cfg.mac = self.DUT_MAC
        wol_cfg.magic_enabled = False
        wol_cfg.link_up_enabled = True
        wol_cfg.link_down_enabled = False
        wol_cfg.link_up_timeout = self.WOL_LINK_DELAY * 1000
        wol_cfg.link_down_timeout = self.WOL_LINK_DELAY * 1000
        wol_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WOL

        beton_file = os.path.join(self.test_log_dir, "wol_link_up.txt")
        wol_cfg.apply(self.atltool_wrapper, beton_file, cleanup_fw=False)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        log.info("Setting link down")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        time.sleep(10)
        log.info("Setting link up")
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

        self.lkp_ifconfig.wait_link_up()

        time.sleep(self.WOL_LINK_DELAY + self.WAKE_COUNTER_DELAY)
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 1, "FW didn't wake host on link up"
        assert wake_reason == drv_iface_cfg.WAKE_REASON_LINK, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_LINK
        )

    def test_win_iface_link_down(self):
        self.configure_simple_offloads()

        log.info("Configuring wake on lan")
        wol_cfg = DrvWinWoLConfig()

        wol_cfg.mac = self.DUT_MAC
        wol_cfg.magic_enabled = False
        wol_cfg.link_up_enabled = False
        wol_cfg.link_down_enabled = True
        wol_cfg.link_up_timeout = self.WOL_LINK_DELAY * 1000
        wol_cfg.link_down_timeout = self.WOL_LINK_DELAY * 1000
        wol_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WOL

        beton_file = os.path.join(self.test_log_dir, "wol_link_down.txt")
        wol_cfg.apply(self.atltool_wrapper, beton_file, cleanup_fw=False)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        log.info("Setting link down")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        time.sleep(self.WOL_LINK_DELAY + self.WAKE_COUNTER_DELAY)

        try:
            wake_reason = self.get_wake_reason()
            assert self.get_wake_counter() == prev_wake_counter + 1, "FW didn't wake host on link down"
            assert wake_reason == drv_iface_cfg.WAKE_REASON_LINK, \
                "Wake reason mismatch. Current: {}; Expected: {}".format(
                    wake_reason, drv_iface_cfg.WAKE_REASON_LINK)
        finally:
            log.info("Setting link up")
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

    def test_ipv4_conflict(self):
        ip4_c = 3

        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC
        cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY
        log.info("Configuring MAC address: {}".format(cfg.mac))

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = ip4_c
        cfg.ips.v4_addresses = self.DUT_IPs4[:ip4_c]
        cfg.ips.v4_masks = [24] * ip4_c
        log.info("Configuring IPv4 addresses: {}".format(cfg.ips.v4_addresses))

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_ipv4.txt")
        cfg.apply(self.atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        for i, address in enumerate(cfg.ips.v4_addresses):
            # Form fake Gratuitous ARP and send it from LKP
            fake_arp = Ether(src=self.FAKE_MAC, dst=self.BROADCAST_MAC)
            fake_arp /= ARP(op="is-at", hwsrc=self.FAKE_MAC, psrc=address, hwdst=self.BROADCAST_MAC, pdst=address)
            self.lkp_scapy_tools.send_packet(fake_arp, lkp_scapy_iface)
            time.sleep(self.WAKE_COUNTER_DELAY)
            wake_reason = self.get_wake_reason()
            assert self.get_wake_counter() == prev_wake_counter + i + 1, "FW didn't detect wake frame"
            assert wake_reason == drv_iface_cfg.WAKE_REASON_ADDR_GUARD, \
                "Wake reason mismatch. Current: {}; Expected: {}".format(
                    wake_reason, drv_iface_cfg.WAKE_REASON_ADDR_GUARD)

    def test_ipv6_conflict(self):
        ip6_c = 5

        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC
        cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY
        log.info("Configuring MAC address: {}".format(cfg.mac))

        cfg.ips = OffloadIpInfo()
        cfg.ips.v6_addr_count = ip6_c
        cfg.ips.v6_addresses = self.DUT_IPs6[:ip6_c]
        cfg.ips.v6_masks = [64] * ip6_c
        log.info("Configuring IPv6 addresses: {}".format(cfg.ips.v6_addresses))

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_ipv6.txt")
        cfg.apply(self.atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        for i, address in enumerate(cfg.ips.v6_addresses):
            # Form fake NA packet and send it from LKP
            fake_na = Ether(src=self.FAKE_MAC, dst=get_ipv6_multicast_mac(MULTICAST_ND_IP6))
            fake_na /= IPv6(src=address, dst=MULTICAST_ND_IP6)
            fake_na /= ICMPv6ND_NA(tgt=address, R=0, S=0, O=1)
            fake_na /= ICMPv6NDOptDstLLAddr(lladdr=self.FAKE_MAC)
            self.lkp_scapy_tools.send_packet(fake_na, lkp_scapy_iface)
            time.sleep(self.WAKE_COUNTER_DELAY)
            wake_reason = self.get_wake_reason()
            assert self.get_wake_counter() == prev_wake_counter + i + 1, "FW didn't detect wake frame"
            assert wake_reason == drv_iface_cfg.WAKE_REASON_ADDR_GUARD, \
                "Wake reason mismatch. Current: {}; Expected: {}".format(
                    wake_reason, drv_iface_cfg.WAKE_REASON_ADDR_GUARD)

    def test_name_conflict(self):
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407
        cfg.mac = self.DUT_MAC
        cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY
        log.info("Configuring MAC address: {}".format(cfg.mac))

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = 1
        cfg.ips.v4_addresses = [self.DUT_IPs4[0]]
        cfg.ips.v4_masks = [24]
        log.info("Configuring IPv4 addresses: {}".format(cfg.ips.v4_addresses))
        cfg.ips.v6_addr_count = 1
        cfg.ips.v6_addresses = [self.DUT_IPs6[0]]
        cfg.ips.v6_masks = [64]
        log.info("Configuring IPv6 addresses: {}".format(cfg.ips.v6_addresses))

        rrs = OffloadRrInfo()

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
        log.info('Configuring mDNS SRV record: class = {}, TTL = {}, question = "{}", answer = "{}"'
                 ''.format(mdns_rr.tail.class_, mdns_rr.tail.ttl, mdns_rr.question, mdns_rr.answer))
        rrs.entries.append(mdns_rr)
        cfg.rrs = rrs

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_name_conflict.txt")
        cfg.apply(self.atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        # Form fake mDNS IPv4 response and send it from LKP
        fake_mdns = Ether(src=self.FAKE_MAC, dst=MULTICAST_MDNS_MAC_IP4)
        fake_mdns /= IP(src=self.FAKE_IP4, dst=MULTICAST_MDNS_IP4)
        fake_mdns /= UDP(sport=5353, dport=5353)
        q = DNSQR(qtype="A", qname=mdns_rr.answer)
        a = DNSRR(type="A", rrname=mdns_rr.answer, rdata=self.FAKE_IP4)
        fake_mdns /= DNS(qr=1, aa=1, qd=q, an=a)

        self.lkp_scapy_tools.send_packet(fake_mdns, lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)

        # Check if FW tried to wake PC
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 1, "FW didn't detect IPv4 name conflict packet"
        assert wake_reason == drv_iface_cfg.WAKE_REASON_NAME_GUARD, \
            "Wake reason mismatch. Current: {}; Expected: {}".format(
                wake_reason, drv_iface_cfg.WAKE_REASON_NAME_GUARD)

        # Form fake mDNS IPv6 response and send it from LKP
        fake_mdns = Ether(src=self.FAKE_MAC, dst=MULTICAST_MDNS_MAC_IP6)
        fake_mdns /= IPv6(src=self.FAKE_IP6, dst=MULTICAST_MDNS_IP6)
        fake_mdns /= UDP(sport=5353, dport=5353)
        q = DNSQR(qtype="AAAA", qname=mdns_rr.answer)
        a = DNSRR(type="AAAA", rrname=mdns_rr.answer, rdata=self.FAKE_IP6)
        fake_mdns /= DNS(qr=1, aa=1, qd=q, an=a)

        self.lkp_scapy_tools.send_packet(fake_mdns, lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)

        # Check if FW tried to wake PC
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter + 2, "FW didn't detect IPv4 name conflict packet"
        assert wake_reason == drv_iface_cfg.WAKE_REASON_NAME_GUARD, \
            "Wake reason mismatch. Current: {}; Expected: {}".format(
                wake_reason, drv_iface_cfg.WAKE_REASON_NAME_GUARD)

    def test_no_wake_on_empty_name_conflict(self):
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407
        cfg.mac = self.DUT_MAC
        cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY
        log.info("Configuring MAC address: {}".format(cfg.mac))

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = 1
        cfg.ips.v4_addresses = [self.DUT_IPs4[0]]
        cfg.ips.v4_masks = [24]
        log.info("Configuring IPv4 addresses: {}".format(cfg.ips.v4_addresses))
        cfg.ips.v6_addr_count = 1
        cfg.ips.v6_addresses = [self.DUT_IPs6[0]]
        cfg.ips.v6_masks = [64]
        log.info("Configuring IPv6 addresses: {}".format(cfg.ips.v6_addresses))

        # Configure at list 1 mDNS record (for FW to initialize it's domain name)
        cfg.rrs = OffloadRrInfo()
        mdns_rr = MdnsRr()
        mdns_rr.tail = MdnsRrTail()
        mdns_rr.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_PTR
        mdns_rr.tail.class_ = 1
        mdns_rr.tail.ttl = 4500
        mdns_rr.question = "standard.ptr.question.local"
        mdns_rr.answer = "standard.ptr.answer.local"
        mdns_rr.tail.rd_len = mdns_rr.answer_length + 1
        log.info('Configuring mDNS PTR record: class = {}, TTL = {}, question = "{}", answer = "{}"'
                 ''.format(mdns_rr.tail.class_, mdns_rr.tail.ttl, mdns_rr.question, mdns_rr.answer))
        cfg.rrs.entries.append(mdns_rr)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_empty_name_conflict.txt")
        cfg.apply(self.atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason()
        log.info("Wake reason before text: {}".format(hex(prev_wake_reason)))

        # Form fake mDNS IPv4 response and send it from LKP
        fake_mdns = Ether(src=self.FAKE_MAC, dst=MULTICAST_MDNS_MAC_IP4)
        fake_mdns /= IP(src=self.FAKE_IP4, dst=MULTICAST_MDNS_IP4)
        fake_mdns /= UDP(sport=5353, dport=5353)
        a1 = DNSRR(type="A", rrname="mm99.local", rdata=self.FAKE_IP4)
        a2 = DNSRR(type="A", rrname="", rdata=self.DUT_IPs4[0])
        fake_mdns /= DNS(qr=1, aa=1, an=a1 / a2)

        self.lkp_scapy_tools.send_packet(fake_mdns, lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)

        # Check if FW tried to wake PC
        assert self.get_wake_counter() == prev_wake_counter, "FW tried to wake host, while it shouldn't"
        log.info("FW didn't tried to wake the host as expected")

        # Form fake mDNS IPv6 response and send it from LKP
        fake_mdns = Ether(src=self.FAKE_MAC, dst=MULTICAST_MDNS_MAC_IP6)
        fake_mdns /= IPv6(src=self.FAKE_IP6, dst=MULTICAST_MDNS_IP6)
        fake_mdns /= UDP(sport=5353, dport=5353)
        a1 = DNSRR(type="AAAA", rrname="mm99.local", rdata=self.FAKE_IP6)
        a2 = DNSRR(type="AAAA", rrname="", rdata=self.DUT_IPs6[0])
        fake_mdns /= DNS(qr=1, aa=1, an=a1 / a2)

        self.lkp_scapy_tools.send_packet(fake_mdns, lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)

        # Check if FW tried to wake PC
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter, "FW tried to wake host, while it shouldn't"
        log.info("FW didn't tried to wake the host as expected")
        assert wake_reason == prev_wake_reason, "Wake reason was changed. Previous: {}; Current: {}".format(
            prev_wake_reason, wake_reason
        )

    def test_no_wake_on_traffic(self):
        self.lkp_ifconfig.set_ip_address("17.224.15.227", self.NETMASK_IP4, None)

        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407
        cfg.mac = "00:17:b6:00:00:00"
        cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WOL
        log.info("Configuring MAC address: {}".format(cfg.mac))

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = 1
        cfg.ips.v4_addresses = ["17.224.15.228"]
        cfg.ips.v4_masks = [24]
        log.info("Configuring IPv4 addresses: {}".format(cfg.ips.v4_addresses))
        cfg.ips.v6_addr_count = 3
        cfg.ips.v6_addresses = ["fe80:0000:0000:0000:149b:f6af:510b:6f61",
                                "2620:0149:0005:0201:04bd:661c:49be:f836",
                                "2620:0149:0005:0201:2190:2553:e482:2788"]
        cfg.ips.v6_masks = [64, 64, 64]
        log.info("Configuring IPv6 addresses: {}".format(cfg.ips.v6_addresses))

        # Configure at list 1 mDNS record (for FW to initialize it's domain name)
        cfg.rrs = OffloadRrInfo()
        mdns_rr = MdnsRr()
        mdns_rr.tail = MdnsRrTail()
        mdns_rr.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_PTR
        mdns_rr.tail.class_ = 1
        mdns_rr.tail.ttl = 4500
        mdns_rr.question = "standard.ptr.question.local"
        mdns_rr.answer = "standard.ptr.answer.local"
        mdns_rr.tail.rd_len = mdns_rr.answer_length + 1
        log.info('Configuring mDNS PTR record: class = {}, TTL = {}, question = "{}", answer = "{}"'
                 ''.format(mdns_rr.tail.class_, mdns_rr.tail.ttl, mdns_rr.question, mdns_rr.answer))
        cfg.rrs.entries.append(mdns_rr)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_traffic.txt")
        cfg.apply(self.atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason()
        log.info("Wake reason before test: {}".format(hex(prev_wake_reason)))

        # Send big pings to wake up SERDES
        ping = Command(cmd="cd {} && sudo python ping.py -n 4 -l 1000 -t 1 {}".format(
            ATF_TOOLS_DIR, cfg.ips.v4_addresses[0]), host=self.lkp_hostname)
        ping.run_async()
        # Sleep to make sure that SERDES is UP
        time.sleep(3)

        self.lkp_scapy_tools.replay_pcap("mdns_wake.pcap")

        # Check if FW tried to wake PC
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter, "FW tried to wake host, while it shouldn't"
        log.info("FW didn't tried to wake the host as expected")
        assert wake_reason == prev_wake_reason, "Wake reason was changed. Previous: {}; Current: {}".format(
            prev_wake_reason, wake_reason
        )
        ping.join(10)

    @idparametrize("pr,ip4_c,ip6_c,port_c", [("tcp", 1, 0, 5),
                                             ("tcp", 0, 1, 5),
                                             ("tcp", 3, 5, 3),
                                             ("udp", 1, 0, 5),
                                             ("udp", 0, 1, 5),
                                             ("udp", 3, 3, 5),
                                             ])
    def test_wake_on_port(self, pr, ip4_c, ip6_c, port_c):
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC
        cfg.caps = cfg.caps | DrvEthConfig.CAPS_HI_WOL  # TODO: add test that checks all that functionality
        log.info("Configuring MAC address: {}".format(cfg.mac))

        cfg.ips = OffloadIpInfo()

        cfg.ips.v4_addr_count = ip4_c
        cfg.ips.v4_addresses = self.DUT_IPs4[:ip4_c]
        cfg.ips.v4_masks = [16] * ip4_c
        log.info("Configuring IPv4 addresses: {}".format(cfg.ips.v4_addresses))

        cfg.ips.v6_addr_count = ip6_c
        cfg.ips.v6_addresses = self.DUT_IPs6[:ip6_c]
        cfg.ips.v6_masks = [64] * ip6_c
        log.info("Configuring IPv6 addresses: {}".format(cfg.ips.v6_addresses))

        cfg_ports = OffloadPortInfo()
        if pr == "udp":
            ports = [9, 22, 445, 6896, 3453][:port_c]
            cfg_ports.udp_ports = ports
            log.info("Configuring UDP ports: {}".format(cfg_ports.udp_ports))
        else:
            ports = [22, 445, 5900, 548, 9][:port_c]
            cfg_ports.tcp_ports = ports
            log.info("Configuring TCP ports: {}".format(cfg_ports.tcp_ports))
        cfg.ports = cfg_ports

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir,
                                  "offload_wake_{}_ports_{}ipv4_{}ipv6_{}ports.txt".format(pr, ip4_c, ip6_c, port_c))
        cfg.apply(self.atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_port_and_verify(cfg.ips.v4_addresses, self.LKP_IP4, ports, pr, cfg.mac, lkp_scapy_iface)
        self.send_port_and_verify(cfg.ips.v6_addresses, self.LKP_IP6, ports, pr, cfg.mac, lkp_scapy_iface)

    def cause_fw_panic(self):
        mcp_start = self.atltool_wrapper.readreg(0x360)
        if self.dut_fw_ver_maj == 2:
            start_offset = mcp_start + 0x17000
        elif self.dut_fw_ver_maj > 2:
            start_offset = mcp_start + 0xB000
        else:
            raise Exception("Unknown firmware version")
        if self.dut_fw_card in FELICITY_CARDS:
            data = [0] * 20000
        else:
            data = [0] * 5000
        self.atltool_wrapper.writemem(start_offset, data)

    def test_wake_on_panic(self):

        # Writting MCP memory is prohibited on B1 chip. So skip this test at the moment
        chip_ver_indicator = self.atltool_wrapper.readreg(0x1c)
        if chip_ver_indicator == 0x102:
            chip_ver = 0xb0
        elif chip_ver_indicator == 0x10a:
            chip_ver = 0xb1
        else:
            raise Exception("Unknow chip revision")
        log.info("CHIP_REV: {}".format(chip_ver))
        if chip_ver != 0xb0:
            pytest.skip("B1 chip doesn't support write operation to mcp memory")

        eth_cfg = DrvEthConfig()

        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC
        eth_cfg.caps = DrvEthConfig.CAPS_HI_WOL
        eth_cfg.caps = eth_cfg.caps | DrvEthConfig.CAPS_HI_SLEEP_PROXY

        ips = OffloadIpInfo()
        eth_cfg.ips = ips

        beton_file = os.path.join(self.test_log_dir, "offload_magic.txt")
        eth_cfg.apply(self.atltool_wrapper, beton_file, cleanup_fw=True)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        try:
            self.cause_fw_panic()
            time.sleep(self.WOL_LINK_DELAY + self.WAKE_COUNTER_DELAY)

            # Check if FW tried to wake PC
            wake_reason = self.get_wake_reason()
            assert self.get_wake_counter() == prev_wake_counter + 1, "FW didn't try to wake host after panic"
            assert wake_reason == drv_iface_cfg.WAKE_REASON_PANIC, \
                "Wake reason mismatch. Current: {}; Expected: {}".format(
                    wake_reason, drv_iface_cfg.WAKE_REASON_PANIC)
        finally:
            self.atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)

    @idparametrize("protocol", ["icmp", "tcp", "udp"])
    @idparametrize(
        "ip_ver", [4, 6]
    )
    def test_no_wake_on_fragments(self, protocol, ip_ver):
        """Reassembling was disabled that is why FW should wake after that"""
        total_payload_length = 12000
        fragment_size = 600
        # Cache scapy iface on LKP
        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()
        self.configure_simple_offloads()

        log.info("Configuring wake on lan")
        wol_cfg = DrvWinWoLConfig()

        wol_cfg.mac = self.DUT_MAC
        wol_cfg.magic_enabled = False
        wol_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WOL

        beton_file = os.path.join(self.test_log_dir, "wol_link_down.txt")
        wol_cfg.apply(self.atltool_wrapper, beton_file, cleanup_fw=False)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()

        prev_wake_counter = self.get_wake_counter()
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason()
        log.info("Wake reason before text: {}".format(hex(prev_wake_reason)))
        l2 = Ether(src=self.lkp_mac, dst=self.DUT_MAC)
        if ip_ver == 4:
            l3 = IP(src=self.LKP_IP4, dst=self.DUT_IPs4[0])
        elif ip_ver == 6:
            l3 = IPv6(src=self.LKP_IP6, dst=self.DUT_IPs6[0])
        else:
            raise ValueError("Invalid ip version: {}".format(ip_ver))

        if protocol == "icmp":
            if ip_ver == 4:
                l4 = ICMP()
            else:
                l4 = ICMPv6EchoRequest()
        elif protocol == "tcp":
            l4 = TCP()
        elif protocol == "udp":
            l4 = UDP()

        payload = "H" * total_payload_length
        pkt = l2 / l3 / l4 / payload

        self.lkp_scapy_tools.send_packet(pkt, lkp_scapy_iface, fragment_size=fragment_size)

        time.sleep(self.WAKE_COUNTER_DELAY)
        # Check if FW tried to wake PC
        wake_reason = self.get_wake_reason()
        assert self.get_wake_counter() == prev_wake_counter, "FW tried to wake host. It's unexpected."
        assert wake_reason == prev_wake_reason, "Wake reason was changed. Current: {}; Previous: {}".format(
            wake_reason, prev_wake_reason
        )

    @idparametrize("speed", [LINK_SPEED_NO_LINK, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G,
                             LINK_SPEED_10G])
    def test_link_reset_after_wake_on_magic(self, speed):
        """
        @description: Verify that FW restores link speed that was set before enabling WoL. Applicable for FW 3.x only.

        @steps:
        1. Enable WOL_EX_WAKE_ON_MAGIC_RESTORE_RATE FW setting.
        2. Set link speed to *speed*. Wait for it to go up.
        3. Configure WoL (magic) via Windows-like driver interface.
        4. Wake FW via magic packet.
        5. Check link speed.

        @result: FW restores original link speed upon waking the PC.
        @duration: 1 minute.
        """
        if self.dut_fw_ver_maj != 3:
            pytest.skip()

        if speed != LINK_SPEED_NO_LINK and speed not in self.supported_speeds:
            pytest.skip()

        # Enable WOL_EX_WAKE_ON_MAGIC_RESTORE_RATE setting
        SettingsMemory.write_dword(self.atltool_wrapper, FWSettings.WOL_EX_OFS,
                                   FWSettings.WolEx.WAKE_ON_MAGIC_RESTORE_RATE)

        # Set link speed
        if speed != LINK_SPEED_NO_LINK:
            self.atltool_wrapper.set_link_params_2x(speed)
            self.atltool_wrapper.wait_link_up()

        # Configure WoL
        self.configure_simple_offloads()

        wol_cfg = DrvWinWoLConfig()
        wol_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WOL
        wol_cfg.mac = self.DUT_MAC
        wol_cfg.magic_enabled = True

        beton_file = os.path.join(self.test_log_dir, "wol_magic_link_reset.txt")
        wol_cfg.apply(self.atltool_wrapper, beton_file, cleanup_fw=False)

        self.lkp_ifconfig.wait_link_up()

        # Send magic packer
        prev_wake_counter = self.get_wake_counter()
        self.lkp_scapy_tools.send_raw_magic_packet(dstmac=self.DUT_MAC, srcmac=self.lkp_mac, broadcast=False)
        time.sleep(self.WAKE_COUNTER_DELAY)
        if speed != LINK_SPEED_NO_LINK:
            link_speed = self.lkp_ifconfig.wait_link_up()
        else:
            log.info("FW will wake the PC only after 30 second timeout. Sleeping...")
            time.sleep(30)
            link_speed = self.lkp_ifconfig.get_link_speed()
        assert link_speed == speed, "FW didn't restore original link speed after wake. Current: {}".format(link_speed)
        assert self.get_wake_counter() > prev_wake_counter, "FW didn't wake PC after sending magic packet"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
