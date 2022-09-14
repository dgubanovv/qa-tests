import os
import shutil
import sys
import time

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import MdnsRr
from infra.test_base import TestBase, idparametrize
from tools.trafficgen import TrafficGenerator, TrafficStream
from tools.samba import Samba
from tools.scapy_tools import ScapyTools, MDNSRecord
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config, SleepProxyOffload, MDNSOffload
from tools.tcpdump import Tcpdump
from tools.utils import get_atf_logger
from tools.aqpkt import Aqsendp

# import order is important, sometimes stdout is not producing though script works
from scapy.all import Ether, IP, ICMP, Raw, wrpcap, UDP, DNS, DNSQR, DNSRR

log = get_atf_logger()


def setup_module(module):
    import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_mdns_proxy"


class TestMDNS(TestBase):
    """
    @description: The mDNS test is dedicated to verify mDNS offload functionality of the firmware. In the sleep
    proxy mode the firmware can answer on different mDNS queries.

    @setup: Two Aquantia devices connected back to back.
    """

    DUT_MAC = "00:17:b6:00:07:82"

    LKP_IP4 = "169.254.0.100"
    LKP_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:6000"

    DUT_LINK_LOCAL_IP6 = "fe80:0000:0000:0000:1422:570e:fcb6:ad7e"

    AFTER_LINK_UP_DELAY = 30

    DEFAULT_IDX_OFFSET = 200
    DEFAULT_RR_OFFSET = 2000

    DEFAULT_SLEEP_IP4S = ["169.254.23.232", "169.254.23.231", "169.254.23.230"]
    DEFAULT_SLEEP_IP6S = ['4000:0000:0000:0000:1601:bd17:0c02:2400',
                          '4000:0000:0000:0000:1601:bd17:0c02:2436',
                          '4000:0000:0000:0000:1601:bd17:0c02:2431',
                          '4000:0000:0000:0000:1601:bd17:0c02:2412',
                          '4000:0000:0000:0000:1601:bd17:0c02:2404',
                         ]

    @classmethod
    def setup_class(cls):
        super(TestMDNS, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            # cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest")
            # cls.dut_driver.install()
            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.fw_config = FirmwareA2Config(cls.dut_atltool_wrapper)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            # cls.lkp_driver.install()
            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            # cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4, cls.DEFAULT_NETMASK_IPV4, None)
            # cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6, cls.DEFAULT_PREFIX_IPV6, None)
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            # Disable Samba to remove background multicast traffic which affects SerDes
            Samba(host=cls.lkp_hostname).stop()
        except Exception as e:
            log.exception(e)
            log.error("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestMDNS, cls).teardown_class()

    def setup_method(self, method):
        super(TestMDNS, self).setup_method(method)
        self.dut_atltool_wrapper.kickstart2()

    def teardown_method(self, method):
        super(TestMDNS, self).teardown_method(method)

    def background_ping(self, src_mac, dst_mac, src_ip, dst_ip, flood_type, duration, nof_packets=10, rate=None):
        """Run backround ICMP traffic with specified parameters
        * flood_type - "burst" or "cont" (continuous)
        * duration - time interval in seconds
        * rate - number of packets per second (if flood_type=="cont")
        """
        log.info("Preparing background ping traffic...")
        eth = Ether(src=src_mac, dst=dst_mac)
        ip = IP(src=src_ip, dst=dst_ip)
        icmp = ICMP()
        raw = Raw(load="abba900d900dabba")
        pkt1 = eth / ip / icmp / raw
        log.info("Ping packet size = {}".format(len(pkt1)))

        self.trfgen = TrafficGenerator(port=self.lkp_port, host=self.lkp_hostname)

        s1 = TrafficStream()
        if flood_type.lower() == "burst":
            s1.type = TrafficStream.STREAM_TYPE_BURST
        elif flood_type.lower() == "cont":
            s1.type = TrafficStream.STREAM_TYPE_CONTINUOUS
            if rate is None:
                raise ValueError("Rate is required for continuous traffic")
            s1.rate = rate
        s1.nof_packets = nof_packets
        s1.duration = duration
        s1.packets = pkt1
        self.trfgen.add_stream(s1)

        if s1.type == TrafficStream.STREAM_TYPE_BURST:
            self.trfgen.run()
        else:
            self.trfgen.run_async()
            time.sleep(3)  # scapy initialization on remote host
        log.info("Background ping traffic has been started")

    def send_requests_check_answers(self, queries, ips_v4, ips_v6, iface=None, additional_records=None, should_fail=False):
        log.info("Testing multicast IPv4 request")
        res = []

        res.append(self.lkp_scapy_tools.mdns_request(srcip=self.LKP_IP4, queries=queries, srcmac=self.lkp_mac,
                                                 expected_ip=ips_v4[0], iface=iface,
                                                 additional_records=additional_records))

        log.info("Testing unicast IPv4 requests")
        for address in ips_v4:
            res.append(self.lkp_scapy_tools.mdns_request(dstip=address, srcip=self.LKP_IP4, queries=queries,
                                                     dstmac=self.DUT_MAC, srcmac=self.lkp_mac, expected_ip=address,
                                                     iface=iface, additional_records=additional_records))

        log.info("Testing multicast IPv6 request")
        res.append(self.lkp_scapy_tools.mdns_request(srcip=self.LKP_IP6, queries=queries, srcmac=self.lkp_mac,
                                                 iface=iface, additional_records=additional_records))

        log.info("Testing unicast IPv6 requests")
        for address in ips_v6:
            res.append(self.lkp_scapy_tools.mdns_request(dstip=address, srcip=self.LKP_IP6, queries=queries,
                                                     dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                                     expected_ip=ips_v6[0],  # Always the 1st IPv6 (intentional #2162)
                                                     iface=iface, additional_records=additional_records))
        if should_fail:
            assert all(r == False for r in res), "mDNS ping are success"
        else:
            assert all(r == True for r in res), "mDNS ping are fail"

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

    def adjust_lkp_link_speed(self):
        # Method for Felicity LKP as autoneg works inpropper on DAC cable
        lkp_link_speed = self.lkp_ifconfig.wait_link_up()
        fw_link_speed = self.fw_config.get_fw_link_speed()

        # Change speed on LKP so traffic can pass through
        if lkp_link_speed != fw_link_speed:
            self.lkp_ifconfig.set_link_speed(fw_link_speed)
            self.lkp_ifconfig.wait_link_up()

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

    def get_default_srv_record(self):
        return MdnsRr.get_drv_iface_srv_rr("iMac (2)._smb._tcp.local", "iMac-3.local", ttl=231, priority=1,
                                           weight=24000, port=50)

    def _apply_mdns(self,entries, cfg, mdns_record_file):
        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

    @idparametrize("bg_traffic", ["no",
                                  # "ping_burst_100pkts_norate",
                                  # "ping_burst_500pkts_norate",
                                  # "ping_cont_-1pkts_rate20",
                                  # "ping_cont_-1pkts_rate40",
                                  # "ping_cont_-1pkts_rate80"
                                  ])
    def test_txt_record(self, bg_traffic):
        """
        @description: Test mDNS Offload for standard TXT record. Background traffic is configured.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a couple of mDNS TXT records.
        3. Configure background traffic (if needed). ICMP packets are sent at a constant rate.
        4. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with one of the configured
        mDNS record from offload.

        @result: All mDNS queries are answered.
        @duration: 2 minutes.
        """
        entries = [self.get_default_srv_record()]
        cfg = self.get_drv_cfg_with_ips()

        # Configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("standard.question.txt.local", "standard-answer.txt.local", ttl=1234)
        entries.append(mdns_txt)
        # Configure 2nd TXT record
        mdns_txt_2 = MdnsRr.get_drv_iface_txt_rr("ololo.question.txt.local", "ololo-answer.txt.local", ttl=12345)
        entries.append(mdns_txt_2)

        # Apply configuration to FW
        mdns_record_file = "txt_record_{}.bin".format(bg_traffic)
        self._apply_mdns(entries, cfg, mdns_record_file)

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        if bg_traffic != "no":
            [traf_type, flood_type, nof_packets, rate] = bg_traffic.split("_")
            nof_packets = int(nof_packets.replace("pkts", ""))
            if flood_type == "burst":
                rate = None
            else:
                rate = int(rate.replace("rate", ""))
            if traf_type == "ping":
                self.background_ping(src_mac=cfg.mac, dst_mac=self.lkp_mac, src_ip=self.LKP_IP4,
                                     dst_ip=cfg.ipv4_offload.ipv4[0], flood_type=flood_type,
                                     duration=30,  # Time needed for all mDNS requests is ~ 30 sec
                                     nof_packets=nof_packets, rate=rate)
            else:
                raise Exception("Detected wrong test parameter: {}".format(bg_traffic))

        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S,
                                         self.DEFAULT_SLEEP_IP6S, iface=lkp_scapy_iface)

        if "cont" in bg_traffic.lower():
            self.trfgen.join()



    def test_txt_record_empty_question(self):
        """
        @description: Test mDNS Offload for standard TXT record with empty question
                      RFC6763 (item 6.1)
        @steps:
        1. Kickstart DUT.
        2. Configure offload with a couple of mDNS TXT records (empty questions).
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with one of the configured
        mDNS record from offload.

        @result: All mDNS queries are not answered.
        @duration: 2 minutes.
        """
        entries = [self.get_default_srv_record()]
        cfg = self.get_drv_cfg_with_ips()

        # Configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("", "standard-answer.txt.local", ttl=1234)
        entries.append(mdns_txt)
        # Configure 2nd TXT record
        mdns_txt_2 = MdnsRr.get_drv_iface_txt_rr("", "ololo-answer.txt.local", ttl=12345)
        entries.append(mdns_txt_2)

        # Apply configuration to FW
        mdns_record_file ="txt_record.bin"
        self._apply_mdns(entries, cfg, mdns_record_file)

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()


        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S,
                                         self.DEFAULT_SLEEP_IP6S, iface=lkp_scapy_iface, should_fail=True)

    def test_txt_record_empty_answer(self):
        """
        @description: Test mDNS Offload for standard TXT record with empty answer
                      RFC6763 (item 6.1)
        @steps:
        1. Kickstart DUT.
        2. Configure offload with a couple of mDNS TXT records (empty answer).
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with one of the configured
        mDNS record from offload.

        @result: All mDNS queries are not answered.
        @duration: 2 minutes.
        """
        entries = [self.get_default_srv_record()]
        cfg = self.get_drv_cfg_with_ips()

        # Configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("standard.question.txt.local", "", ttl=1234)
        entries.append(mdns_txt)
        # Configure 2nd TXT record
        mdns_txt_2 = MdnsRr.get_drv_iface_txt_rr("ololo.question.txt.local", "", ttl=12345)
        entries.append(mdns_txt_2)

        # Apply configuration to FW
        mdns_record_file ="txt_record.bin"
        self._apply_mdns(entries, cfg, mdns_record_file)

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S,
                                         self.DEFAULT_SLEEP_IP6S, iface=lkp_scapy_iface, should_fail=True)

    '''
    def test_txt_record_no_ending(self):
        """
        @description: Test mDNS Offload for TXT record without tailed zero.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a couple of mDNS TXT records, first record not contained tailed zero.
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with one of the configured
        mDNS record from offload.

        @result: All mDNS queries are answered.
        @duration: 2 minutes.
        """
        entries = [self.get_default_srv_record()]
        cfg = self.get_drv_cfg_with_ips()

        # Configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("standard.question.txt.local", bytearray(b"standard-answer.txt.local"), ttl=1234)
        entries.append(mdns_txt)
        # Configure 2nd TXT record
        mdns_txt_2 = MdnsRr.get_drv_iface_txt_rr("ololo.question.txt.local", "ololo-answer.txt.local", ttl=12345)
        entries.append(mdns_txt_2)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "txt_record.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        # Restore TXT record with answer as text instead bytearray
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("standard.question.txt.local", "standard-answer.txt.local", ttl=1234)
        queries = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S,
                                         self.DEFAULT_SLEEP_IP6S, iface=lkp_scapy_iface)

    def test_ptr_record(self):
        """
        @description: Test mDNS Offload for standard PTR record.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a mDNS PTR record.
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with configured mDNS
        record from offload.

        @result: All mDNS queries are answered.
        @duration: 2 minutes.
        """
        entries = [self.get_default_srv_record()]
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS PTR record
        mdns_ptr = MdnsRr.get_drv_iface_ptr_rr("standard.question.ptr.local", "standard.answer.ptr.local", ttl=4321)
        entries.append(mdns_ptr)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "ptr_record.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("PTR", mdns_ptr.question, [mdns_ptr.answer], ttl=mdns_ptr.tail.ttl)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S,
                                         self.DEFAULT_SLEEP_IP6S, iface=lkp_scapy_iface)

    def test_srv_record(self):
        """
        @description: Test mDNS Offload for standard SRV record.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a mDNS SRV record.
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with configured mDNS
        record from offload.

        @result: All mDNS queries are answered.
        @duration: 2 minutes.
        """
        entries = []
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS SRV record
        mdns_srv = MdnsRr.get_drv_iface_srv_rr("iMac (2)._smb._tcp.local", "iMac-3.local", ttl=231, priority=1,
                                               weight=24000, port=50)
        entries.append(mdns_srv)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "srv_record.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("SRV", mdns_srv.question, [mdns_srv.answer], ttl=mdns_srv.tail.ttl,
                              priority=mdns_srv.srv.priority, weight=mdns_srv.srv.weight,
                              port=mdns_srv.srv.port)]

        # According to RFC 6762 TTL for A and AAAA records should be 255
        additional_records = [MDNSRecord("AAAA", mdns_srv.answer, self.DEFAULT_SLEEP_IP6S, ttl=255),
                              MDNSRecord("A", mdns_srv.answer, self.DEFAULT_SLEEP_IP4S, ttl=255)]
        for additional_record in additional_records:
            log.info("\n{}".format(additional_record))
        log.info("Number of additional records is: {}".format(len(additional_records)))

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S, self.DEFAULT_SLEEP_IP6S,
                                         iface=lkp_scapy_iface, additional_records=additional_records)

    @idparametrize("answer_length", [140, 141])
    def test_large_txt_record(self, answer_length):
        """
        @description: Test mDNS Offload for large TXT record.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a mDNS TXT record of big length.
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with configured mDNS
        record from offload.

        @result: All mDNS queries are answered.
        @duration: 2 minutes.
        """
        entries = [self.get_default_srv_record()]
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("standard.question.txt.local",
                                               ("x" * 62 + ".blah" * 40)[:answer_length - 16] +
                                               ".answer.txt.local", ttl=1337)
        entries.append(mdns_txt)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "large_txt_record_{}.bin".format(answer_length)
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S,
                                         self.DEFAULT_SLEEP_IP6S, iface=lkp_scapy_iface)

    def test_multi_record(self):
        """
        @description: Test mDNS request with multiple queries.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with multiple mDNS records (TXT, PTR, SRV).
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with all configured mDNS
        record in one packet.

        @result: All mDNS queries are answered.
        @duration: 2 minutes.
        """
        entries = []
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS records

        # TXT
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("standard.question.txt.local", "standard.answer.txt.local", ttl=4500)
        entries.append(mdns_txt)
        # PTR
        mdns_ptr = MdnsRr.get_drv_iface_ptr_rr("standard.question.ptr.local", "standard.answer.ptr.local", ttl=4500)
        entries.append(mdns_ptr)
        # SRV
        mdns_srv = MdnsRr.get_drv_iface_srv_rr("iMac (2)._smb._tcp.local", "iMac-3.local", ttl=120, priority=1,
                                               weight=32000, port=22)
        entries.append(mdns_srv)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "multi_record.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl),
                   MDNSRecord("PTR", mdns_ptr.question, [mdns_ptr.answer], ttl=mdns_ptr.tail.ttl),
                   MDNSRecord("SRV", mdns_srv.question, [mdns_srv.answer], ttl=mdns_srv.tail.ttl,
                              priority=mdns_srv.srv.priority, weight=mdns_srv.srv.weight,
                              port=mdns_srv.srv.port),
                   MDNSRecord("PTR", "_fake._tcp.local", [])]

        # According to RFC 6762 TTL for A and AAAA records should be 255
        additional_records = [MDNSRecord("AAAA", mdns_srv.answer, self.DEFAULT_SLEEP_IP6S, ttl=255),
                              MDNSRecord("A", mdns_srv.answer, self.DEFAULT_SLEEP_IP4S, ttl=255)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S, self.DEFAULT_SLEEP_IP6S,
                                         iface=lkp_scapy_iface, additional_records=additional_records)

    def test_busy_query(self):
        """
        @description: Test mDNS request with only 1 useful query.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with mDNS PTR record.
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with configured mDNS
        record as well as with a bunch of unknown records in one packet.

        @result: All mDNS queries are answered with 1 expected record.
        @duration: 2 minutes.
        """
        entries = [self.get_default_srv_record()]
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS records
        mdns_ptr = MdnsRr.get_drv_iface_ptr_rr("standard.question.ptr.local", "standard.answer.ptr.local", ttl=8000)
        entries.append(mdns_ptr)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "busy_query.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        fake_record = MDNSRecord("TXT", "fake-question.local", [])
        queries = [fake_record] * 6 + \
                  [MDNSRecord("PTR", mdns_ptr.question, [mdns_ptr.answer], ttl=mdns_ptr.tail.ttl)] + \
                  [fake_record] * 6

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S,
                                         self.DEFAULT_SLEEP_IP6S, iface=lkp_scapy_iface)

    def test_a_record(self):
        """
        @description: Test mDNS Offload for A record.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a mDNS A record.
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with configured mDNS
        record from offload.

        @result: All mDNS queries are answered.
        @duration: 2 minutes.
        """
        entries = []
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS SRV record
        mdns_rr = MdnsRr.get_drv_iface_srv_rr("iMac (2)._smb._tcp.local", "iMac-3.local")
        entries.append(mdns_rr)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "a_record.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        # According to RFC 6762 TTL for A and AAAA records should be 255
        queries = [MDNSRecord("A", mdns_rr.answer, self.DEFAULT_SLEEP_IP4S, ttl=255)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S,
                                         self.DEFAULT_SLEEP_IP6S, iface=lkp_scapy_iface)

    def test_aaaa_record(self):
        """
        @description: Test mDNS Offload for AAAA record.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a mDNS AAAA record.
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with configured mDNS
        record from offload.

        @result: All mDNS queries are answered.
        @duration: 2 minutes.
        """
        entries = []
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS SRV record
        cfg.mdns_offload = MDNSOffload()
        mdns_rr = MdnsRr.get_drv_iface_srv_rr("iMac (2)._smb._tcp.local", "iMac-3.local")
        entries.append(mdns_rr)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "aaaa_record.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        # According to RFC 6762 TTL for A and AAAA records should be 255
        qeries = [MDNSRecord("AAAA", mdns_rr.answer, self.DEFAULT_SLEEP_IP6S, ttl=255)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(qeries, self.DEFAULT_SLEEP_IP4S, self.DEFAULT_SLEEP_IP6S, lkp_scapy_iface)

    def test_ptr_service(self):
        """
        @description: Test mDNS Offload for service info (PTR query - TXT + PTR + SRV + A/AAAA reply).

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a information about service (linked PTR, SRV, TXT mDNS records).
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with configured mDNS
        PTR record from offload.

        @result: All mDNS queries are answered with PTR, SRV, TXT and A/AAAA additional records.
        @duration: 2 minutes.
        """
        entries = []
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("IAmMac._smb._tcp.local", "Hello,_I_am_Mac", ttl=123)
        entries.append(mdns_txt)
        # configure mDNS PTR record
        mdns_ptr = MdnsRr.get_drv_iface_ptr_rr("_smb._tcp.local", "IAmMac._smb._tcp.local", ttl=456)
        entries.append(mdns_ptr)
        # configure mDNS SRV record
        mdns_srv = MdnsRr.get_drv_iface_srv_rr("IAmMac._smb._tcp.local", "IAmMac.local", ttl=789, priority=0,
                                               weight=777, port=69)
        entries.append(mdns_srv)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "ptr_service.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("PTR", mdns_ptr.question, [mdns_ptr.answer], ttl=mdns_ptr.tail.ttl)]

        # According to RFC 6762 TTL for A and AAAA records should be 255
        additional_records = [MDNSRecord("AAAA", mdns_srv.answer, self.DEFAULT_SLEEP_IP6S, ttl=255),
                              MDNSRecord("A", mdns_srv.answer, self.DEFAULT_SLEEP_IP4S, ttl=255),
                              MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl),
                              MDNSRecord("SRV", mdns_srv.question, [mdns_srv.answer], ttl=mdns_srv.tail.ttl,
                                         priority=mdns_srv.srv.priority, weight=mdns_srv.srv.weight,
                                         port=mdns_srv.srv.port)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S, self.DEFAULT_SLEEP_IP6S,
                                         iface=lkp_scapy_iface, additional_records=additional_records)

    def test_ptr_adds_txt(self):
        """
        @description: Test mDNS Offload for service info (PTR query - TXT + PTR reply).

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a information about service (linked PTR, TXT mDNS records). Don't configure any of
        SRV records.
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with configured mDNS
        PTR record from offload.

        @result: All mDNS queries are answered with PTR and TXT additional record.
        @duration: 2 minutes.
        """
        entries = []
        cfg = self.get_drv_cfg_with_ips()

        cfg.mdns_offload = MDNSOffload()
        # configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("IAmLuke._ssh._udp.local", "Luke,_I_Am_Your_Father", ttl=1977)
        entries.append(mdns_txt)
        # configure mDNS PTR record
        mdns_ptr = MdnsRr.get_drv_iface_ptr_rr("_ssh._udp.local", "IAmLuke._ssh._udp.local", ttl=1977)
        entries.append(mdns_ptr)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "ptr_adds_txt.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("PTR", mdns_ptr.question, [mdns_ptr.answer], ttl=mdns_ptr.tail.ttl)]

        additional_records = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, self.DEFAULT_SLEEP_IP4S, self.DEFAULT_SLEEP_IP6S,
                                         iface=lkp_scapy_iface, additional_records=additional_records)

    def test_query_with_answer(self):
        """
        @description: Test mDNS Offload for service info (PTR query - TXT + PTR + SRV + A/AAAA reply) in case
        then the request contains an answer.

        @steps:
        1. Kickstart DUT.
        2. Configure offload with a information about service (linked PTR, SRV, TXT mDNS records).
        3. Send mDNS queries to all DUT's IP addresses (multicast and unicast IPv4 and IPv6) with configured mDNS
        PTR record from offload that contains an answer.

        @result: All mDNS queries are answered with PTR, SRV, TXT and A/AAAA additional records.
        @duration: 2 minutes.
        """
        entries = []
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("IAmMac._smb._tcp.local", "Hello,_I_am_Mac", ttl=123)
        entries.append(mdns_txt)
        # configure mDNS PTR record
        mdns_ptr = MdnsRr.get_drv_iface_ptr_rr("_smb._tcp.local", "IAmMac._smb._tcp.local", ttl=456)
        entries.append(mdns_ptr)
        # configure mDNS SRV record
        mdns_srv = MdnsRr.get_drv_iface_srv_rr("IAmMac._smb._tcp.local", "IAmMac.local", ttl=789, priority=0,
                                               weight=777, port=69)
        entries.append(mdns_srv)

        # Apply configuration to FW
        cfg.mdns_offload = self.get_mds_offload_for_entries(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET)
        mdns_record_file = "ptr_service.bin"
        self.fw_config.write_mdns_records(entries, self.DEFAULT_IDX_OFFSET, self.DEFAULT_RR_OFFSET, mdns_record_file)
        shutil.copy(mdns_record_file, self.test_log_dir)
        self.fw_config.configure_sleep_proxy(cfg, self.DUT_MAC, os.path.join(self.test_log_dir, "config.txt"))

        log.info("Making sure that link is up")
        self.adjust_lkp_link_speed()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("PTR", mdns_ptr.question, [mdns_ptr.answer], ttl=mdns_ptr.tail.ttl)]

        eth = Ether(dst="01:00:5E:00:00:FB", src=self.lkp_mac)
        udp = UDP(sport=5353, dport=5353)
        ip = IP(dst="224.0.0.251", src=self.LKP_IP4)

        question_records = DNSQR(qtype=queries[0].type, qname=queries[0].question)
        answer_record = DNSRR(type='PTR', rrname=queries[0].question, ttl=10, rdata=queries[0].answers[0])
        mdns = DNS(rd=1, ad=1, ar=[DNSRR(type="OPT")], qd=question_records, an=answer_record)

        query_pkt = eth / ip / udp / mdns

        log.debug("Prepared mDNS query:")
        log.debug("Length = {}".format(len(query_pkt)))
        query_pkt.show()

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        sniffer = Tcpdump(port=self.lkp_port, host=self.lkp_hostname, timeout=6)
        sniffer.run_async()
        time.sleep(1)

        try:
            lkp_aqsendp = Aqsendp(
                packet=query_pkt, count=1, rate=1,
                host=self.lkp_hostname, iface=lkp_scapy_iface
            )
            lkp_aqsendp.run()
        finally:
            time.sleep(1)
            packets = sniffer.join(6)
            wrpcap("packets.pcap", packets)
            shutil.move("packets.pcap", self.test_log_dir)

        for packet in packets:
            if packet.haslayer(DNSRR):
                if packet.qr == 1:
                    if (packet.an.rrname == mdns_ptr.question + '.' and
                            packet.an.rdata == mdns_ptr.answer + '.'):
                        break
        else:
            raise Exception('mDNS response not received')
'''

if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
