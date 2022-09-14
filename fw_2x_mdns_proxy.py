import os
import shutil
import time
import tempfile

import pytest

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, FELICITY_CARDS
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvEthConfig, OffloadRrInfo, MdnsRr, MdnsRrTail, MdnsRdataSrv
from infra.test_base import TestBase, idparametrize
from tools.trafficgen import TrafficGenerator, TrafficStream
from tools.samba import Samba
from tools.scapy_tools import ScapyTools, MDNSRecord

from tools.utils import get_atf_logger

# import order is important, sometimes stdout is not producing though script works
from scapy.all import Ether, IP, ICMP, Raw
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_mdns_proxy"


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

    @classmethod
    def setup_class(cls):
        super(TestMDNS, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4, cls.DEFAULT_NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6, cls.DEFAULT_PREFIX_IPV6, None)

            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
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
        if self.dut_firmware.is_3x():
            # FW 3X requires kickstart after each configuration
            self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)
            self.lkp_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestMDNS, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

            self.lkp_bin_log_file, self.lkp_txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.lkp_bin_log_file, self.test_log_dir)
            shutil.copy(self.lkp_txt_log_file, self.test_log_dir)

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

    def send_requests_check_answers(self, queries, ips_v4, ips_v6, iface=None, additional_records=None):
        log.info("Testing multicast IPv4 request")
        assert self.lkp_scapy_tools.mdns_request(srcip=self.LKP_IP4, queries=queries, srcmac=self.lkp_mac,
                                                 expected_ip=ips_v4[0], iface=iface,
                                                 additional_records=additional_records), \
            "Failed while requesting mDNS query. See log above for details"

        log.info("Testing unicast IPv4 requests")
        for address in ips_v4:
            assert self.lkp_scapy_tools.mdns_request(dstip=address, srcip=self.LKP_IP4, queries=queries,
                                                     dstmac=self.DUT_MAC, srcmac=self.lkp_mac, expected_ip=address,
                                                     iface=iface, additional_records=additional_records), \
                "Failed while requesting mDNS query. See log above for details"

        log.info("Testing multicast IPv6 request")
        assert self.lkp_scapy_tools.mdns_request(srcip=self.LKP_IP6, queries=queries, srcmac=self.lkp_mac,
                                                 iface=iface, additional_records=additional_records), \
            "Failed while requesting mDNS query. See log above for details"

        log.info("Testing unicast IPv6 requests")
        for address in ips_v6:
            assert self.lkp_scapy_tools.mdns_request(dstip=address, srcip=self.LKP_IP6, queries=queries,
                                                     dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                                     expected_ip=ips_v6[0],  # Always the 1st IPv6 (intentional #2162)
                                                     iface=iface, additional_records=additional_records), \
                "Failed while requesting mDNS query. See log above for details"

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

    @idparametrize("bg_traffic", ["no",
                                  "ping_burst_100pkts_norate",
                                  "ping_burst_500pkts_norate",
                                  "ping_cont_-1pkts_rate20",
                                  "ping_cont_-1pkts_rate40",
                                  "ping_cont_-1pkts_rate80"
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
        cfg = self.get_drv_cfg_with_ips()

        # Configure mDNS TXT record
        cfg.rrs = OffloadRrInfo()
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("standard.question.txt.local", "standard-answer.txt.local", ttl=1234)
        cfg.rrs.entries.append(mdns_txt)
        # Configure 2nd TXT record
        mdns_txt_2 = MdnsRr.get_drv_iface_txt_rr("ololo.question.txt.local", "ololo-answer.txt.local", ttl=12345)
        cfg.rrs.entries.append(mdns_txt_2)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_mdns_txt.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
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
                                     dst_ip=cfg.ips.v4_addresses[0], flood_type=flood_type,
                                     duration=30,  # Time needed for all mDNS requests is ~ 30 sec
                                     nof_packets=nof_packets, rate=rate)
            else:
                raise Exception("Detected wrong test parameter: {}".format(bg_traffic))

        self.send_requests_check_answers(queries, cfg.ips.v4_addresses,
                                         cfg.ips.v6_addresses, iface=lkp_scapy_iface)

        if "cont" in bg_traffic.lower():
            self.trfgen.join()

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
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS PTR record
        cfg.rrs = OffloadRrInfo()
        mdns_ptr = MdnsRr.get_drv_iface_ptr_rr("standard.question.ptr.local", "standard.answer.ptr.local", ttl=4321)
        cfg.rrs.entries.append(mdns_ptr)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_mdns_ptr.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("PTR", mdns_ptr.question, [mdns_ptr.answer], ttl=mdns_ptr.tail.ttl)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, cfg.ips.v4_addresses,
                                         cfg.ips.v6_addresses, iface=lkp_scapy_iface)

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
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS SRV record
        cfg.rrs = OffloadRrInfo()
        mdns_srv = MdnsRr.get_drv_iface_srv_rr("iMac (2)._smb._tcp.local", "iMac-3.local", ttl=231, priority=1,
                                               weight=24000, port=50)
        cfg.rrs.entries.append(mdns_srv)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_mdns_srv.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("SRV", mdns_srv.question, [mdns_srv.answer], ttl=mdns_srv.tail.ttl,
                              priority=mdns_srv.srv.priority, weight=mdns_srv.srv.weight,
                              port=mdns_srv.srv.port)]

        # According to RFC 6762 TTL for A and AAAA records should be 255
        additional_records = [MDNSRecord("AAAA", mdns_srv.answer, cfg.ips.v6_addresses, ttl=255),
                              MDNSRecord("A", mdns_srv.answer, cfg.ips.v4_addresses, ttl=255)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, cfg.ips.v4_addresses, cfg.ips.v6_addresses,
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
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS TXT record
        cfg.rrs = OffloadRrInfo()
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("standard.question.txt.local",
                                               ("blah-" * 40)[:answer_length - 16] + "answer.txt.local", ttl=1337)
        cfg.rrs.entries.append(mdns_txt)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_mdns_txt_length_{}.txt".format(answer_length))
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, cfg.ips.v4_addresses,
                                         cfg.ips.v6_addresses, iface=lkp_scapy_iface)

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
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS records
        cfg.rrs = OffloadRrInfo()

        # TXT
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("standard.question.txt.local", "standard.answer.txt.local", ttl=4500)
        cfg.rrs.entries.append(mdns_txt)
        # PTR
        mdns_ptr = MdnsRr.get_drv_iface_ptr_rr("standard.question.ptr.local", "standard.answer.ptr.local", ttl=4500)
        cfg.rrs.entries.append(mdns_ptr)
        # SRV
        mdns_srv = MdnsRr.get_drv_iface_srv_rr("iMac (2)._smb._tcp.local", "iMac-3.local", ttl=120, priority=1,
                                               weight=32000, port=22)
        cfg.rrs.entries.append(mdns_srv)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_mdns_multi.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl),
                   MDNSRecord("PTR", mdns_ptr.question, [mdns_ptr.answer], ttl=mdns_ptr.tail.ttl),
                   MDNSRecord("SRV", mdns_srv.question, [mdns_srv.answer], ttl=mdns_srv.tail.ttl,
                              priority=mdns_srv.srv.priority, weight=mdns_srv.srv.weight,
                              port=mdns_srv.srv.port),
                   MDNSRecord("PTR", "_fake._tcp.local", [])]

        # According to RFC 6762 TTL for A and AAAA records should be 255
        additional_records = [MDNSRecord("AAAA", mdns_srv.answer, cfg.ips.v6_addresses, ttl=255),
                              MDNSRecord("A", mdns_srv.answer, cfg.ips.v4_addresses, ttl=255)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, cfg.ips.v4_addresses, cfg.ips.v6_addresses,
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
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS records
        cfg.rrs = OffloadRrInfo()
        mdns_ptr = MdnsRr.get_drv_iface_ptr_rr("standard.question.ptr.local", "standard.answer.ptr.local", ttl=8000)
        cfg.rrs.entries.append(mdns_ptr)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_mdns_busy.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        fake_record = MDNSRecord("TXT", "fake-question.local", [])
        queries = [fake_record] * 6 + \
                  [MDNSRecord("PTR", mdns_ptr.question, [mdns_ptr.answer], ttl=mdns_ptr.tail.ttl)] + \
                  [fake_record] * 6

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, cfg.ips.v4_addresses,
                                         cfg.ips.v6_addresses, iface=lkp_scapy_iface)

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
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS SRV record
        cfg.rrs = OffloadRrInfo()
        mdns_rr = MdnsRr.get_drv_iface_srv_rr("iMac (2)._smb._tcp.local", "iMac-3.local")
        cfg.rrs.entries.append(mdns_rr)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_mdns_a.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        # According to RFC 6762 TTL for A and AAAA records should be 255
        queries = [MDNSRecord("A", mdns_rr.answer, cfg.ips.v4_addresses, ttl=255)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, cfg.ips.v4_addresses,
                                         cfg.ips.v6_addresses, iface=lkp_scapy_iface)

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
        cfg = self.get_drv_cfg_with_ips()

        # configure mDNS SRV record
        cfg.rrs = OffloadRrInfo()
        mdns_rr = MdnsRr.get_drv_iface_srv_rr("iMac (2)._smb._tcp.local", "iMac-3.local")
        cfg.rrs.entries.append(mdns_rr)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_mdns_aaaa.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        # According to RFC 6762 TTL for A and AAAA records should be 255
        qeries = [MDNSRecord("AAAA", mdns_rr.answer, cfg.ips.v6_addresses, ttl=255)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(qeries, cfg.ips.v4_addresses, cfg.ips.v6_addresses, lkp_scapy_iface)

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
        cfg = self.get_drv_cfg_with_ips()

        cfg.rrs = OffloadRrInfo()
        # configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("IAmMac._smb._tcp.local", "Hello,_I_am_Mac", ttl=123)
        cfg.rrs.entries.append(mdns_txt)
        # configure mDNS PTR record
        mdns_ptr = MdnsRr.get_drv_iface_ptr_rr("_smb._tcp.local", "IAmMac._smb._tcp.local", ttl=456)
        cfg.rrs.entries.append(mdns_ptr)
        # configure mDNS SRV record
        mdns_srv = MdnsRr.get_drv_iface_srv_rr("IAmMac._smb._tcp.local", "IAmMac.local", ttl=789, priority=0,
                                               weight=777, port=69)
        cfg.rrs.entries.append(mdns_srv)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_mdns_ptr.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("PTR", mdns_ptr.question, [mdns_ptr.answer], ttl=mdns_ptr.tail.ttl)]

        # According to RFC 6762 TTL for A and AAAA records should be 255
        additional_records = [MDNSRecord("AAAA", mdns_srv.answer, cfg.ips.v6_addresses, ttl=255),
                              MDNSRecord("A", mdns_srv.answer, cfg.ips.v4_addresses, ttl=255),
                              MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl),
                              MDNSRecord("SRV", mdns_srv.question, [mdns_srv.answer], ttl=mdns_srv.tail.ttl,
                                         priority=mdns_srv.srv.priority, weight=mdns_srv.srv.weight,
                                         port=mdns_srv.srv.port)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, cfg.ips.v4_addresses, cfg.ips.v6_addresses,
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
        cfg = self.get_drv_cfg_with_ips()

        cfg.rrs = OffloadRrInfo()
        # configure mDNS TXT record
        mdns_txt = MdnsRr.get_drv_iface_txt_rr("IAmLuke._ssh._udp.local", "Luke,_I_Am_Your_Father", ttl=1977)
        cfg.rrs.entries.append(mdns_txt)
        # configure mDNS PTR record
        mdns_ptr = MdnsRr.get_drv_iface_ptr_rr("_ssh._udp.local", "IAmLuke._ssh._udp.local", ttl=1977)
        cfg.rrs.entries.append(mdns_ptr)

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_mdns_ptr.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        queries = [MDNSRecord("PTR", mdns_ptr.question, [mdns_ptr.answer], ttl=mdns_ptr.tail.ttl)]

        additional_records = [MDNSRecord("TXT", mdns_txt.question, [mdns_txt.txt], ttl=mdns_txt.tail.ttl)]

        lkp_scapy_iface = self.lkp_scapy_tools.get_scapy_iface()

        self.send_requests_check_answers(queries, cfg.ips.v4_addresses, cfg.ips.v6_addresses,
                                         iface=lkp_scapy_iface, additional_records=additional_records)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
