import os
import random
import struct
import time
import sys
import shutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import crcmod
import pytest


from infra.test_base import TestBase, idparametrize
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.atltoolper import AtlTool
from tools import fw_a2_drv_iface_cfg
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config
from tools.drv_iface_cfg import MdnsRr
from tools.ifconfig import LINK_STATE_UP, LINK_STATE_DOWN, LINK_SPEED_NO_LINK, LINK_SPEED_100M, LINK_SPEED_1G, \
    LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_AUTO
from tools.scapy_tools import ScapyTools, get_ipv6_multicast_mac, MULTICAST_ND_IP6, MULTICAST_MDNS_MAC_IP4, \
    MULTICAST_MDNS_MAC_IP6, MULTICAST_MDNS_IP4, MULTICAST_MDNS_IP6
from tools.fw_a2_drv_iface_cfg import SleepProxyOffload, MDNSOffload, WAKE_REASON_MAGIC_PACKET, WAKE_REASON_PING,\
    WAKE_REASON_PATTERN, WAKE_REASON_UDP, WAKE_REASON_SYN, WAKE_REASON_ADDR_GUARD, WAKE_REASON_LINK, \
    WAKE_REASON_PANIC, HOST_MODE_ACTIVE
from tools.utils import get_atf_logger
from scapy.all import Ether, IP, IPv6, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, Raw, RandString, TCP, hexdump, UDP, \
    ARP, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, DNS, DNSQR, DNSRR

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_wol_sanity"


class TestA2FWWOLSanity(TestBase):
    WOL_LINK_DELAY = 10
    GLOBAL_GENERAL_PROVISIONING = 0x514
    GLOBAL_INTERNAL_ALARMS = 0x920

    FAKE_MAC = "00:00:de:ad:fa:ce"
    FAKE_IP4 = "192.168.0.69"
    FAKE_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:0069"

    WAKE_COUNTER_DELAY = 1

    DUT_MAC_ADDR = "00:17:B6:01:02:03"

    DUT_IP4_ADDR = [
        "192.168.0.3", "192.168.0.4", "192.168.0.5", "192.168.0.6",
        "192.168.0.7", "192.168.0.8", "192.168.0.9", "192.168.0.10"
    ]

    DUT_IP6_ADDR = [
        "4000:0000:0000:0000:1601:bd17:0c02:2403", "4000:0000:0000:0000:1601:bd17:0c02:2404",
        "4000:0000:0000:0000:1601:bd17:0c02:2405", "4000:0000:0000:0000:1601:bd17:0c02:2406",
        "4000:0000:0000:0000:1601:bd17:0c02:2407", "4000:0000:0000:0000:1601:bd17:0c02:2408",
        "4000:0000:0000:0000:1601:bd17:0c02:2409", "4000:0000:0000:0000:1601:bd17:0c02:2410",
        "4000:0000:0000:0000:1601:bd17:0c02:2411", "4000:0000:0000:0000:1601:bd17:0c02:2412",
        "4000:0000:0000:0000:1601:bd17:0c02:2413", "4000:0000:0000:0000:1601:bd17:0c02:2414",
        "4000:0000:0000:0000:1601:bd17:0c02:2415", "4000:0000:0000:0000:1601:bd17:0c02:2416",
        "4000:0000:0000:0000:1601:bd17:0c02:2417", "4000:0000:0000:0000:1601:bd17:0c02:2418"
    ]

    LKP_IP4_ADDR = "192.168.0.2"
    NETMASK_IPV4 = "255.255.255.0"
    MULTICAST_IPV4 = "192.168.0.255"

    LKP_IP6_ADDR = "4000:0000:0000:0000:1601:bd17:0c02:2402"
    PREFIX_IPV6 = "64"

    CRC32_POLYNOM = 0x104c11db7

    @classmethod
    def setup_class(cls):
        super(TestA2FWWOLSanity, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", host=cls.dut_hostname,
                                    drv_type=DRV_TYPE_DIAG)
            cls.dut_driver.install()
            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.fw_config = FirmwareA2Config(cls.atltool_wrapper)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6_ADDR, cls.PREFIX_IPV6, None)
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            cls.lkp_mac_addr = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestA2FWWOLSanity, cls).teardown_class()

    def setup_method(self, method):
        super(TestA2FWWOLSanity, self).setup_method(method)
        self.atltool_wrapper.kickstart2()

    def teardown_method(self, method):
        super(TestA2FWWOLSanity, self).teardown_method(method)

    def check_wake_up_packet(self, pkt_str, wol_status):
        wake_up_packet = b""

        if len(pkt_str) < 60:
            pkt_str = pkt_str.ljust(60, "\x00")

        for dw in wol_status.wakeUpPacket:
            wake_up_packet += struct.pack("<I", dw)

        wake_up_packet = wake_up_packet[:wol_status.wakeUpPacketLength]

        if pkt_str != wake_up_packet:
            log.error("Wake Up packet differs. See hexdump below")
            log.error("Expected packet:")
            hexdump(pkt_str)
            log.error("Wake Up packet:")
            hexdump(wake_up_packet)
            raise AssertionError("Wake Up packet differs")

    def get_wake_counter(self):
        return self.fw_config.get_fw_wol_status().wakeCount

    def get_wake_reason(self):
        return self.fw_config.get_fw_wol_status().wakeReason

    def check_fw_wake_status(self, wol_status, wake_reason, packet=None, packet_length=None, pattern_number=None,
                             err_str="FW didn't detect wake up frame"):
        prev_wake_count = wol_status.wakeCount
        if prev_wake_count == 255:
            prev_wake_count = -1

        time.sleep(self.WAKE_COUNTER_DELAY)
        wol_status = self.fw_config.get_fw_wol_status()
        assert wol_status.wakeCount > prev_wake_count, err_str
        assert wol_status.wakeReason == wake_reason, \
            "Wrong wake reason: {}, expected: {}".format(wol_status.wakeReason, wake_reason)
        if packet_length and pattern_number:
            assert wol_status.wakeUpPacketLength == packet_length
            assert wol_status.wakeUpPatternNumber == pattern_number
        if packet is not None:
            self.check_wake_up_packet(str(packet), wol_status)
        return wol_status

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

    def calculate_crc32(self, packet, mask_dw):
        packet_str = str(packet)
        mask = [
            mask_dw[0] & 0x000000FF,
            (mask_dw[0] & 0x0000FF00) >> 8,
            (mask_dw[0] & 0x00FF0000) >> 16,
            (mask_dw[0] & 0xFF000000) >> 24,
            mask_dw[1] & 0x000000FF,
            (mask_dw[1] & 0x0000FF00) >> 8,
            (mask_dw[1] & 0x00FF0000) >> 16,
            (mask_dw[1] & 0xFF000000) >> 24,
            mask_dw[2] & 0x000000FF,
            (mask_dw[2] & 0x0000FF00) >> 8,
            (mask_dw[2] & 0x00FF0000) >> 16,
            (mask_dw[2] & 0xFF000000) >> 24,
            mask_dw[3] & 0x000000FF,
            (mask_dw[3] & 0x0000FF00) >> 8,
            (mask_dw[3] & 0x00FF0000) >> 16,
            (mask_dw[3] & 0xFF000000) >> 24
        ]

        packet_masked = b""

        for bit_num in range(min(len(packet_str), 128)):
            if mask[bit_num / 8] & (1 << (bit_num % 8)):
                packet_masked += packet_str[bit_num]

        crc32_func = crcmod.mkCrcFun(self.CRC32_POLYNOM, initCrc=0, rev=True, xorOut=0xffffffff)
        crc32_swapped = crc32_func(packet_masked)
        return crc32_swapped

    def test_wake_magic_packet_basic(self):
        sp_cfg = SleepProxyOffload()

        sp_cfg.wake_on_lan.wake_on_magic_packet = True

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.get_fw_wol_status()

        log.info("Sending unicast RAW magic packet from LKP")
        self.lkp_scapy_tools.send_raw_magic_packet(dstmac=self.DUT_MAC_ADDR, srcmac=self.lkp_mac_addr, broadcast=False,
                                                   iface=self.lkp_scapy_iface)
        wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_MAGIC_PACKET,
                                               err_str="FW didn't detect unicast RAW magic packet")

        log.info("Sending broadcast RAW magic packet from LKP")
        self.lkp_scapy_tools.send_raw_magic_packet(dstmac=self.DUT_MAC_ADDR, srcmac=self.lkp_mac_addr, broadcast=True,
                                                   iface=self.lkp_scapy_iface)
        wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_MAGIC_PACKET,
                                               err_str="FW didn't detect broadcast RAW magic packet")

        log.info("Sending unicast UDP magic packet from LKP")
        self.lkp_scapy_tools.send_udp_magic_packet(dstmac=self.DUT_MAC_ADDR, srcip=self.LKP_IP4_ADDR,
                                                   dstip=self.MULTICAST_IPV4, srcmac=self.lkp_mac_addr, broadcast=False,
                                                   iface=self.lkp_scapy_iface)
        wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_MAGIC_PACKET,
                                               err_str="FW didn't detect unicast UDP magic packet")

        log.info("Sending broadcast UDP magic packet from LKP")
        self.lkp_scapy_tools.send_udp_magic_packet(dstmac=self.DUT_MAC_ADDR, srcip=self.LKP_IP4_ADDR,
                                                   dstip=self.MULTICAST_IPV4, srcmac=self.lkp_mac_addr, broadcast=True,
                                                   iface=self.lkp_scapy_iface)
        self.check_fw_wake_status(wol_status, WAKE_REASON_MAGIC_PACKET,
                                  err_str="FW didn't detect broadcast UDP magic packet")

    def test_wake_magic_packet_diff_sizes(self):
        sp_cfg = SleepProxyOffload()

        sp_cfg.wake_on_lan.wake_on_magic_packet = True

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.get_fw_wol_status()

        magic_payload = ("FFFFFFFFFFFF" + self.DUT_MAC_ADDR.replace(":", "") * 16).decode("hex")

        log.info("Sending long magic packet with WoL pattern at the end")
        pkt = Ether(dst="FF:FF:FF:FF:FF:FF", src=self.lkp_mac_addr, type=0x0842) / \
            Raw(load=str(RandString(1000)) + magic_payload)
        self.lkp_scapy_tools.send_packet(pkt, iface=self.lkp_scapy_iface)
        wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_MAGIC_PACKET, pkt,
                                               "FW didn't detect magic packet")

        log.info("Sending long magic packet with WoL pattern at the beginning")
        pkt = Ether(dst="FF:FF:FF:FF:FF:FF", src=self.lkp_mac_addr, type=0x0842) / \
            Raw(load=magic_payload + str(RandString(1000)))
        self.lkp_scapy_tools.send_packet(pkt, iface=self.lkp_scapy_iface)
        self.check_fw_wake_status(wol_status, WAKE_REASON_MAGIC_PACKET, pkt, "FW didn't detect magic packet")

    def test_wake_on_ping_ipv4(self):
        sp_cfg = SleepProxyOffload()

        sp_cfg.wake_on_lan.wake_on_ping = True

        # sp_cfg.ipv4_offload.echo_responder = True
        sp_cfg.ipv4_offload.ipv4 = self.DUT_IP4_ADDR

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.get_fw_wol_status()

        for address in sp_cfg.ipv4_offload.ipv4:
            log.info("Sending echo request to {}".format(address))
            pkt = Ether(dst=self.DUT_MAC_ADDR, src=self.lkp_mac_addr) / IP(dst=address, src=self.LKP_IP4_ADDR) / \
                ICMP(type="echo-request")
            self.lkp_scapy_tools.send_packet(pkt, iface=self.lkp_scapy_iface)
            wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_PING, pkt, "FW didn't detect ping request")

        # Check that FW doesn't wake up on echo reply
        log.info("Sending echo reply from {}".format(sp_cfg.ipv4_offload.ipv4[0]))
        pkt = Ether(dst=self.DUT_MAC_ADDR, src=self.lkp_mac_addr) / IP(dst=sp_cfg.ipv4_offload.ipv4[0],
                                                                       src=self.LKP_IP4_ADDR) / ICMP(type="echo-reply")
        self.lkp_scapy_tools.send_packet(pkt, iface=self.lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        assert wol_status.wakeCount == self.get_wake_counter(), "FW woke up on echo reply"

    def test_wake_on_ping_ipv6(self):
        sp_cfg = SleepProxyOffload()

        sp_cfg.wake_on_lan.wake_on_ping = True

        # sp_cfg.ipv6_offload.echo_responder = True
        sp_cfg.ipv6_offload.ipv6 = self.DUT_IP6_ADDR

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.get_fw_wol_status()

        for address in sp_cfg.ipv6_offload.ipv6:
            log.info("Sending echo request to {}".format(address))
            pkt = Ether(dst=self.DUT_MAC_ADDR, src=self.lkp_mac_addr) / IPv6(dst=address, src=self.LKP_IP6_ADDR) / \
                ICMPv6EchoRequest(id=0x0001)
            self.lkp_scapy_tools.send_packet(pkt, iface=self.lkp_scapy_iface)
            wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_PING, pkt, "FW didn't detect ping request")

        # Check that FW doesn't wake up on echo reply
        log.info("Sending echo reply from {}".format(sp_cfg.ipv6_offload.ipv6[0]))
        pkt = Ether(dst=self.DUT_MAC_ADDR, src=self.lkp_mac_addr) / \
            IPv6(dst=sp_cfg.ipv6_offload.ipv6[0], src=self.LKP_IP6_ADDR) / ICMPv6EchoReply(id=0x0001)
        self.lkp_scapy_tools.send_packet(pkt, iface=self.lkp_scapy_iface)
        time.sleep(self.WAKE_COUNTER_DELAY)
        assert wol_status.wakeCount == self.get_wake_counter(), "FW woke up on echo reply"

    def test_wake_on_pattern_match(self):
        sp_cfg = SleepProxyOffload()

        sp_cfg.wake_on_lan.wake_on_pattern = True

        # 128 byte packet with general mask
        packet_128_general = Ether(dst="00:17:b6:aa:bb:cc", src="00:17:b6:11:22:33") / Raw(load=str(RandString(114)))

        sp_cfg.wake_on_lan.wake_up_patterns[0].mask[0] = 0x12345678
        sp_cfg.wake_on_lan.wake_up_patterns[0].mask[1] = 0x9ABCDEF0
        sp_cfg.wake_on_lan.wake_up_patterns[0].mask[2] = 0xAABBCCDD
        sp_cfg.wake_on_lan.wake_up_patterns[0].mask[3] = 0x98765432
        sp_cfg.wake_on_lan.wake_up_patterns[0].crc32 = self.calculate_crc32(
            packet_128_general, sp_cfg.wake_on_lan.wake_up_patterns[0].mask)

        # 150 byte packet with full mask
        packet_150_full = Ether(dst="FF:FF:FF:FF:FF:FF", src="00:17:b6:01:02:03") / Raw(load=str(RandString(136)))

        sp_cfg.wake_on_lan.wake_up_patterns[1].mask[0] = 0xFFFFFFFF
        sp_cfg.wake_on_lan.wake_up_patterns[1].mask[1] = 0xFFFFFFFF
        sp_cfg.wake_on_lan.wake_up_patterns[1].mask[2] = 0xFFFFFFFF
        sp_cfg.wake_on_lan.wake_up_patterns[1].mask[3] = 0xFFFFFFFF
        sp_cfg.wake_on_lan.wake_up_patterns[1].crc32 = self.calculate_crc32(
            packet_150_full, sp_cfg.wake_on_lan.wake_up_patterns[1].mask)

        # 60 byte packet, short mask
        packet_60_byte = Ether(dst="FF:FF:FF:FF:FF:FF", src="00:17:b6:10:20:30") / Raw(load=str(RandString(46)))

        sp_cfg.wake_on_lan.wake_up_patterns[2].mask[0] = 0xCCCCCCCC
        sp_cfg.wake_on_lan.wake_up_patterns[2].mask[1] = 0x00000000
        sp_cfg.wake_on_lan.wake_up_patterns[2].mask[2] = 0x00000000
        sp_cfg.wake_on_lan.wake_up_patterns[2].mask[3] = 0x00000000
        sp_cfg.wake_on_lan.wake_up_patterns[2].crc32 = self.calculate_crc32(
            packet_60_byte, sp_cfg.wake_on_lan.wake_up_patterns[2].mask)

        # 1500 byte packet, short mask
        packet_1500_short = Ether(dst="FF:FF:FF:FF:FF:FF", src="00:17:b6:18:29:3A") / Raw(load=str(RandString(1486)))

        sp_cfg.wake_on_lan.wake_up_patterns[3].mask[0] = 0x43218765
        sp_cfg.wake_on_lan.wake_up_patterns[3].mask[1] = 0xAAAABBBB
        sp_cfg.wake_on_lan.wake_up_patterns[3].mask[2] = 0x00000000
        sp_cfg.wake_on_lan.wake_up_patterns[3].mask[3] = 0x00000000
        sp_cfg.wake_on_lan.wake_up_patterns[3].crc32 = self.calculate_crc32(
            packet_1500_short, sp_cfg.wake_on_lan.wake_up_patterns[3].mask)

        # 1500 byte packet, full mask
        packet_1500_full = Ether(dst="FF:FF:FF:FF:FF:FF", src="00:17:b6:45:56:67") / Raw(load=str(RandString(1486)))

        sp_cfg.wake_on_lan.wake_up_patterns[4].mask[0] = 0xDEADC0DE
        sp_cfg.wake_on_lan.wake_up_patterns[4].mask[1] = 0xBEEFCAFE
        sp_cfg.wake_on_lan.wake_up_patterns[4].mask[2] = 0xBABEFACE
        sp_cfg.wake_on_lan.wake_up_patterns[4].mask[3] = 0xD0D0CACA
        sp_cfg.wake_on_lan.wake_up_patterns[4].crc32 = self.calculate_crc32(
            packet_1500_full, sp_cfg.wake_on_lan.wake_up_patterns[4].mask)

        # Random packet (> 128 bytes), full mask
        packet_random_5 = Ether(dst="FF:FF:FF:FF:FF:FF", src="00:17:b6:45:56:67") / \
            Raw(load=str(RandString(random.randint(114, 1486))))

        sp_cfg.wake_on_lan.wake_up_patterns[5].mask[0] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[5].mask[1] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[5].mask[2] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[5].mask[3] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[5].crc32 = self.calculate_crc32(
            packet_random_5, sp_cfg.wake_on_lan.wake_up_patterns[5].mask)

        # Random packet (> 128 bytes), full mask
        packet_random_6 = Ether(dst="FF:FF:FF:FF:FF:FF", src="00:17:b6:45:56:67") / \
            Raw(load=str(RandString(random.randint(114, 1486))))

        sp_cfg.wake_on_lan.wake_up_patterns[6].mask[0] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[6].mask[1] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[6].mask[2] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[6].mask[3] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[6].crc32 = self.calculate_crc32(
            packet_random_6, sp_cfg.wake_on_lan.wake_up_patterns[6].mask)

        # Random packet (> 128 bytes), full mask
        packet_random_7 = Ether(dst="FF:FF:FF:FF:FF:FF", src="00:17:b6:45:56:67") / \
            Raw(load=str(RandString(random.randint(114, 1486))))

        sp_cfg.wake_on_lan.wake_up_patterns[7].mask[0] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[7].mask[1] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[7].mask[2] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[7].mask[3] = random.randint(0, 0xFFFFFFFF)
        sp_cfg.wake_on_lan.wake_up_patterns[7].crc32 = self.calculate_crc32(
            packet_random_7, sp_cfg.wake_on_lan.wake_up_patterns[7].mask)

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        packets = [
            ("128 byte length, general mask", packet_128_general),
            ("150 byte length, full mask", packet_150_full),
            ("60 byte length, short mask", packet_60_byte),
            ("1500 byte length, short mask", packet_1500_short),
            ("1500 byte length, full mask", packet_1500_full),
            ("{} byte length, random".format(len(packet_random_5)), packet_random_5),
            ("{} byte length, random".format(len(packet_random_6)), packet_random_6),
            ("{} byte length, random".format(len(packet_random_7)), packet_random_7),
        ]

        wol_status = self.fw_config.get_fw_wol_status()

        for i, (desc, packet) in enumerate(packets):
            log.info("Sending packet: {}".format(desc))
            self.lkp_scapy_tools.send_packet(packet, iface=self.lkp_scapy_iface)
            wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_PATTERN, packet, len(packet), i,
                                                   "FW didn't detect wake packet: {}".format(desc))

    def test_wake_on_port_ipv4_tcp(self):
        sp_cfg = SleepProxyOffload()

        sp_cfg.ipv4_offload.ipv4 = self.DUT_IP4_ADDR

        for i in range(len(sp_cfg.tcp_port_offload.ports)):
            sp_cfg.tcp_port_offload.ports[i] = random.randint(1, 0xFFFF)

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.get_fw_wol_status()

        for address in sp_cfg.ipv4_offload.ipv4:
            for port in sp_cfg.tcp_port_offload.ports:
                packet = Ether(dst=self.DUT_MAC_ADDR, src=self.lkp_mac_addr) / \
                         IP(dst=address, src=self.LKP_IP4_ADDR) / \
                         TCP(flags="S", dport=port)
                self.lkp_scapy_tools.send_packet(packet, iface=self.lkp_scapy_iface)
                wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_SYN, packet)

    def test_wake_on_port_ipv4_udp(self):
        sp_cfg = SleepProxyOffload()

        sp_cfg.ipv4_offload.ipv4 = self.DUT_IP4_ADDR

        for i in range(len(sp_cfg.udp_port_offload.ports)):
            sp_cfg.udp_port_offload.ports[i] = random.randint(1, 0xFFFF)

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.get_fw_wol_status()

        for address in sp_cfg.ipv4_offload.ipv4:
            for port in sp_cfg.udp_port_offload.ports:
                packet = Ether(dst=self.DUT_MAC_ADDR, src=self.lkp_mac_addr) / \
                         IP(dst=address, src=self.LKP_IP4_ADDR) / \
                         UDP(dport=port)
                self.lkp_scapy_tools.send_packet(packet, iface=self.lkp_scapy_iface)
                wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_UDP, packet)

    def test_wake_on_port_ipv6_tcp(self):
        sp_cfg = SleepProxyOffload()

        sp_cfg.ipv6_offload.ipv6 = self.DUT_IP6_ADDR

        for i in range(len(sp_cfg.tcp_port_offload.ports)):
            sp_cfg.tcp_port_offload.ports[i] = random.randint(1, 0xFFFF)

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.get_fw_wol_status()

        for address in sp_cfg.ipv6_offload.ipv6:
            for port in sp_cfg.tcp_port_offload.ports:
                packet = Ether(dst=self.DUT_MAC_ADDR, src=self.lkp_mac_addr) / \
                         IPv6(dst=address, src=self.LKP_IP6_ADDR) / TCP(flags="S", dport=port)
                self.lkp_scapy_tools.send_packet(packet, iface=self.lkp_scapy_iface)
                wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_SYN, packet)

    def test_wake_on_port_ipv6_udp(self):
        sp_cfg = SleepProxyOffload()

        sp_cfg.ipv6_offload.ipv6 = self.DUT_IP6_ADDR

        for i in range(len(sp_cfg.udp_port_offload.ports)):
            sp_cfg.udp_port_offload.ports[i] = random.randint(1, 0xFFFF)

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.get_fw_wol_status()

        for address in sp_cfg.ipv6_offload.ipv6:
            for port in sp_cfg.udp_port_offload.ports:
                packet = Ether(dst=self.DUT_MAC_ADDR, src=self.lkp_mac_addr) / \
                         IPv6(dst=address, src=self.LKP_IP6_ADDR) / UDP(dport=port) / Raw(load="\x00\x00")
                self.lkp_scapy_tools.send_packet(packet, iface=self.lkp_scapy_iface)
                wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_UDP, packet)

    def test_wake_on_address_guard_ipv4(self):
        sp_cfg = SleepProxyOffload()

        # sp_cfg.ipv4_offload.arp_responder = True
        sp_cfg.ipv4_offload.address_guard = True
        sp_cfg.ipv4_offload.ipv4 = self.DUT_IP4_ADDR

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.get_fw_wol_status()

        for address in sp_cfg.ipv4_offload.ipv4:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.lkp_mac_addr) / \
                     ARP(op="who-has", hwsrc=self.lkp_mac_addr, hwdst="ff:ff:ff:ff:ff:ff", psrc=address, pdst=address)
            self.lkp_scapy_tools.send_packet(packet, iface=self.lkp_scapy_iface)
            wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_ADDR_GUARD, packet,
                                                   "FW didn't detect address conflict")

    def test_wake_on_address_guard_ipv6(self):
        sp_cfg = SleepProxyOffload()

        # sp_cfg.ipv6_offload.ns_responder = True
        sp_cfg.ipv6_offload.address_guard = True
        sp_cfg.ipv6_offload.ipv6 = self.DUT_IP6_ADDR

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.get_fw_wol_status()

        for address in sp_cfg.ipv6_offload.ipv6:
            packet = Ether(dst=get_ipv6_multicast_mac(MULTICAST_ND_IP6), src=self.FAKE_MAC) / \
                    IPv6(dst=MULTICAST_ND_IP6, src=address) / \
                    ICMPv6ND_NA(R=0, S=0, O=1, tgt=address) / \
                    ICMPv6NDOptDstLLAddr(lladdr=self.FAKE_MAC)
            self.lkp_scapy_tools.send_packet(packet, iface=self.lkp_scapy_iface)
            time.sleep(self.WAKE_COUNTER_DELAY)
            wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_ADDR_GUARD, packet,
                                                   "FW didn't detect address conflict")

    def test_no_wake_on_link_up_without_link(self):
        """
        @description: Check did not wake up on the link up while stabilizing the link (20 seconds).

        @steps:
        1. Set link to DOWN state.
        2. Configure Sleep Proxy offloads with wake_on_link_down true and link_down_timeout.
        3. Put link to UP state.
        4. Check that FW no wake up.

        @result: All ckecks are passed.
        @duration: 1 minute.
        """
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)

        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_link_up = True
        sp_cfg.wake_on_lan.link_up_timeout = 3 * 1000

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_down()

        prev_wol_status = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        log.info("Wake count before test: {}".format(prev_wol_status))

        log.info("Wake host by setting link up")
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.wait_link_up()
        time.sleep(3 + 2)

        wol_status = self.fw_config.get_fw_wol_status()
        assert wol_status.wakeCount == prev_wol_status.wakeCount, "Machine wake on link up until the link stabilized"

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_AUTO])
    def test_no_wake_on_link_up_with_link(self, speed):
        """
        @description: Check did not wake up on the link up while stabilizing the link (20 seconds).

        @steps:
        1. In loop for each speed in KNOWN_LINK_SPEEDS:
            a. Set link speed.
            b. Configure Sleep Proxy offloads with wake_on_link_up true and link_up_timeout.
            c. Put link to DOWN state and back to UP state.
            d. Check that FW no wake up.

        @result: All ckecks are passed.
        @duration: 1 minute.
        """
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(speed)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()

        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_link_up = True
        sp_cfg.wake_on_lan.link_up_timeout = 3 * 1000
        sp_cfg.wake_on_lan.link_down_timeout = 0

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        prev_wol_status = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        log.info("Wake count before test: {}".format(prev_wol_status))

        log.info("Wake host by setting link up")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.wait_link_up()
        time.sleep(3 + 2)

        wol_status = self.fw_config.get_fw_wol_status()
        assert wol_status.wakeCount == prev_wol_status.wakeCount, "Machine wake on link up until the link stabilized"

    def test_wake_on_link_up_without_link(self):
        """
        @description: Check wake on link up without link before going to Sleep Proxy mode.

        @steps:
        1. Set link to DOWN state.
        2. Configure Sleep Proxy offloads with wake_on_link_down true and link_down_timeout.
        3. Put link to UP state.
        4. Check FW wake status.

        @result: All ckecks are passed.
        @duration: 1 minute.
        """
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)

        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_link_up = True
        sp_cfg.wake_on_lan.link_up_timeout = self.WOL_LINK_DELAY * 1000

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_down()

        wol_status = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        log.info("Wake count before test: {}".format(wol_status))

        # Wait 20 second. It is link up stabilization timeout in Sleep mode.
        log.info("Sleeping {} seconds".format(20))
        time.sleep(20)
        log.info("Wake host by setting link up")
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.WOL_LINK_DELAY + 2)
        lkpspeed = self.lkp_ifconfig.get_link_speed()
        assert lkpspeed != LINK_SPEED_NO_LINK

        self.check_fw_wake_status(wol_status, WAKE_REASON_LINK, None, "FW didn't detect link up")

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_AUTO])
    def test_wake_on_link_up_with_link(self, speed):
        """
        @description: Check wake on link up with link in up state before going to Sleep Proxy mode.

        @steps:
        1. In loop for each speed in KNOWN_LINK_SPEEDS:
            a. Set link speed.
            b. Configure Sleep Proxy offloads with wake_on_link_up true and link_up_timeout.
            c. Put link to DOWN state and back to UP state.
            d. Check FW wake status.

        @result: All ckecks are passed.
        @duration: 1 minute.
        """
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(speed)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()

        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_link_up = True
        sp_cfg.wake_on_lan.link_up_timeout = self.WOL_LINK_DELAY * 1000
        sp_cfg.wake_on_lan.link_down_timeout = 0

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        log.info("Wake count before test: {}".format(wol_status))

        # Wait 20 second. It is link up stabilization timeout in Sleep mode.
        log.info("Sleeping {} seconds".format(20))
        time.sleep(20)
        log.info("Wake host by setting link up")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.WOL_LINK_DELAY + 2)
        lkpspeed = self.lkp_ifconfig.get_link_speed()
        assert lkpspeed != LINK_SPEED_NO_LINK

        self.check_fw_wake_status(wol_status, WAKE_REASON_LINK, None, "FW didn't detect link up")

    def test_no_wake_on_link_down_without_link(self):
        """
        @description: Check did not wake up on the link up while stabilizing the link (20 seconds).

        @steps:
        1. Set link to DOWN state.
        2. Configure Sleep Proxy offloads with wake_on_link_down true and link_down_timeout.
        3. Put link to UP state and back to DOWN state.
        4.  Check that FW no wake up.

        @result: All ckecks are passed.
        @duration: 1 minute.
        """
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)

        prev_wol_status = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_link_up = False
        sp_cfg.wake_on_lan.wake_on_link_down = True
        sp_cfg.wake_on_lan.link_down_timeout = 3 * 1000
        sp_cfg.wake_on_lan.link_up_timeout = 0

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_down()

        wol_status_after_link_up = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        assert prev_wol_status.wakeCount == wol_status_after_link_up.wakeCount, "FW waked up unexpectedly"

        log.info("Wake host by setting link up/down")
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.wait_link_up()
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.lkp_ifconfig.wait_link_down()
        time.sleep(3 + 2)
        lkpspeed = self.lkp_ifconfig.get_link_speed()
        assert lkpspeed == LINK_SPEED_NO_LINK

        wol_status = self.fw_config.get_fw_wol_status()
        assert wol_status.wakeCount == prev_wol_status.wakeCount, "Machine wake on link up until the link stabilized"

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_AUTO])
    def test_no_wake_on_link_down_with_link(self, speed):
        """
        @description: Check did not wake up on the link up while stabilizing the link (20 seconds).

        @steps:
        1. In loop for each speed in KNOWN_LINK_SPEEDS:
            a. Set link speed.
            b. Configure Sleep Proxy offloads with wake_on_link_down true and link_down_timeout.
            c. Put link to DOWN state.
            d.  Check that FW no wake up.

        @result: All ckecks are passed.
        @duration: 1 minute.
        """
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(speed)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()

        prev_wol_status = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_link_up = False
        sp_cfg.wake_on_lan.wake_on_link_down = True
        sp_cfg.wake_on_lan.link_down_timeout = 3 * 1000

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status_after_link_up = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        assert prev_wol_status.wakeCount == wol_status_after_link_up.wakeCount, "FW waked up unexpectedly"

        log.info("Wake host by setting link down")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.lkp_ifconfig.wait_link_down()
        time.sleep(3 + 2)

        wol_status = self.fw_config.get_fw_wol_status()
        assert wol_status.wakeCount == prev_wol_status.wakeCount, "Machine wake on link up until the link stabilized"

    def test_wake_on_link_down_without_link(self):
        """
        @description: Check wake on link down without link before going to Sleep Proxy mode.

        @steps:
        1. Set link to DOWN state.
        2. Configure Sleep Proxy offloads with wake_on_link_down true and link_down_timeout.
        3. Put link to UP state and back to DOWN state.
        4. Check FW wake status.

        @result: All ckecks are passed.
        @duration: 1 minute.
        """
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)

        wol_status = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_link_up = False
        sp_cfg.wake_on_lan.wake_on_link_down = True
        sp_cfg.wake_on_lan.link_down_timeout = self.WOL_LINK_DELAY * 1000
        sp_cfg.wake_on_lan.link_up_timeout = 0

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_down()

        wol_status_after_link_up = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        assert wol_status.wakeCount == wol_status_after_link_up.wakeCount, "FW waked up unexpectedly"

        # Wait 20 second. It is link up stabilization timeout in Sleep mode.
        log.info("Sleeping {} seconds".format(20))
        time.sleep(20)
        log.info("Wake host by setting link up/down")
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.wait_link_up()
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.lkp_ifconfig.wait_link_down()
        time.sleep(self.WOL_LINK_DELAY + 4)
        lkpspeed = self.lkp_ifconfig.get_link_speed()
        assert lkpspeed == LINK_SPEED_NO_LINK

        self.check_fw_wake_status(wol_status, WAKE_REASON_LINK, None, "FW didn't detect link down")

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_AUTO])
    def test_wake_on_link_down_with_link(self, speed):
        """
        @description: Check wake on link down with link in up state before going to Sleep Proxy mode.

        @steps:
        1. In loop for each speed in KNOWN_LINK_SPEEDS:
            a. Set link speed.
            b. Configure Sleep Proxy offloads with wake_on_link_down true and link_down_timeout.
            c. Put link to DOWN state.
            d. Check FW wake status.

        @result: All ckecks are passed.
        @duration: 1 minute.
        """
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(speed)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        sp_cfg = SleepProxyOffload()
        sp_cfg.wake_on_lan.wake_on_link_up = False
        sp_cfg.wake_on_lan.wake_on_link_down = True
        sp_cfg.wake_on_lan.link_down_timeout = self.WOL_LINK_DELAY * 1000

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status_after_link_up = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        assert wol_status.wakeCount == wol_status_after_link_up.wakeCount, "FW waked up unexpectedly"

        # Wait 20 second. It is link up stabilization timeout in Sleep mode.
        log.info("Sleeping {} seconds".format(20))
        time.sleep(20)
        log.info("Wake host by setting link down")
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.lkp_ifconfig.wait_link_down()
        time.sleep(self.WOL_LINK_DELAY + 4)
        lkpspeed = self.lkp_ifconfig.get_link_speed()
        assert lkpspeed == LINK_SPEED_NO_LINK

        self.check_fw_wake_status(wol_status, WAKE_REASON_LINK, None, "FW didn't detect link down")

    def test_wake_on_panic(self):
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        sp_cfg = SleepProxyOffload()

        sp_cfg.ipv4_offload.ipv4 = self.DUT_IP4_ADDR

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        wol_status = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")

        # Write bit Global DRAM ECC Inject error
        self.atltool_wrapper.writereg(self.GLOBAL_GENERAL_PROVISIONING, 0x400)
        time.sleep(1)
        # Check ECC error alarm
        ecc_error_alarm = self.atltool_wrapper.readreg(self.GLOBAL_INTERNAL_ALARMS) & 0x800
        assert ecc_error_alarm == 2048

        wol_status = self.check_fw_wake_status(wol_status, WAKE_REASON_PANIC, None, "FW didn't detect Exception")

    def test_name_conflict_ipv4(self):
        entries = []
        cfg = SleepProxyOffload()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC_ADDR

        cfg.ipv4_offload.ipv4 = self.DUT_IP4_ADDR
        log.info('Configuring IPv4 addresses: {}'.format(cfg.ipv4_offload.ipv4))
        cfg.ipv6_offload.ipv6 = self.DUT_IP6_ADDR
        log.info('Configuring IPv6 addresses: {}'.format(cfg.ipv6_offload.ipv6))

        # configure mDNS PTR record
        mdns_rr = MdnsRr.get_drv_iface_srv_rr("iMac (2)._smb._tcp.local", "iMac-3.local", weight=48385, class_=32769)
        entries.append(mdns_rr)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, 200, 2000)
        mdns_record_file = "srv_record.bin"
        self.fw_config.write_mdns_records(entries, 200, 2000, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()
        prev_wol_status = self.fw_config.get_fw_wol_status()
        log.info("Wake counter before test: {}".format(prev_wol_status.wakeCount))

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
        self.check_fw_wake_status(prev_wol_status, fw_a2_drv_iface_cfg.WAKE_REASON_MDNS)

    def test_name_conflict_ipv6(self):
        entries = []
        cfg = SleepProxyOffload()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC_ADDR

        cfg.ipv4_offload.ipv4 = self.DUT_IP4_ADDR
        log.info('Configuring IPv4 addresses: {}'.format(cfg.ipv4_offload.ipv4))
        cfg.ipv6_offload.ipv6 = self.DUT_IP6_ADDR
        log.info('Configuring IPv6 addresses: {}'.format(cfg.ipv6_offload.ipv6))

        # configure mDNS PTR record
        mdns_rr = MdnsRr.get_drv_iface_srv_rr("iMac (2)._smb._tcp.local", "iMac-3.local", weight=48385, class_=32769)
        entries.append(mdns_rr)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, 200, 2000)
        mdns_record_file = "srv_record.bin"
        self.fw_config.write_mdns_records(entries, 200, 2000, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()
        prev_wol_status = self.fw_config.get_fw_wol_status()
        log.info("Wake counter before test: {}".format(prev_wol_status.wakeCount))

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
        self.check_fw_wake_status(prev_wol_status, fw_a2_drv_iface_cfg.WAKE_REASON_MDNS)

    def test_no_wake_on_empty_name_conflict(self):
        entries = []
        cfg = SleepProxyOffload()

        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC_ADDR

        cfg.ipv4_offload.ipv4 = self.DUT_IP4_ADDR
        log.info('Configuring IPv4 addresses: {}'.format(cfg.ipv4_offload.ipv4))
        cfg.ipv6_offload.ipv6 = self.DUT_IP6_ADDR
        log.info('Configuring IPv6 addresses: {}'.format(cfg.ipv6_offload.ipv6))

        mdns_rr = MdnsRr.get_drv_iface_srv_rr("standard.ptr.question.local", "standard.ptr.answer.local",
                                              weight=48385, ttl=4500, class_=1)
        entries.append(mdns_rr)
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, 200, 2000)
        mdns_record_file = "srv_record.bin"
        self.fw_config.write_mdns_records(entries, 200, 2000, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        prev_wol_status = self.fw_config.get_fw_wol_status()
        prev_wake_counter = prev_wol_status.wakeCount
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason()
        log.info("Wake reason before text: {}".format(hex(prev_wol_status.wakeReason)))

        # Form fake mDNS IPv4 response and send it from LKP
        fake_mdns = Ether(src=self.FAKE_MAC, dst=MULTICAST_MDNS_MAC_IP4)
        fake_mdns /= IP(src=self.FAKE_IP4, dst=MULTICAST_MDNS_IP4)
        fake_mdns /= UDP(sport=5353, dport=5353)
        a1 = DNSRR(type="A", rrname="mm99.local", rdata=self.FAKE_IP4)
        a2 = DNSRR(type="A", rrname="", rdata=self.DUT_IP4_ADDR[0])
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
        a2 = DNSRR(type="AAAA", rrname="", rdata=self.DUT_IP6_ADDR[0])
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


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
