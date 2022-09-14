"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import pytest
import random
import time

import shutil

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, FELICITY_CARDS
from tools.driver import Driver, DRV_TYPE_DIAG
from tools import drv_iface_cfg
from tools.drv_iface_cfg import DrvEthConfig, OffloadIpInfo, OffloadKaInfo, OffloadKa
from tools.samba import Samba
from tools.scapy_tools import ScapyTools, get_l2_scapy_socket
from tools.sniffer import Sniffer
from tools.utils import get_atf_logger, get_compressed_ipv6

from infra.test_base import TestBase, idparametrize

from scapy.all import Ether, IP, IPv6, TCP, Padding, Raw, ICMPv6ParamProblem, RandString, wrpcap
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup
    os.environ["TEST"] = "fw_2x_tcp_ka"


class TestTcpKeepAlive(TestBase):
    """
    @description: The TCP keep alive test is dedicated to verify TCPKA functionality of the firmware. In the sleep
    proxy mode the firmware continuously sends TCP KA packets for opened TCP sessions to keep them alive. Also the
    firmware can wakeup the computer in several cases.

    @setup: Two Aquantia devices connected back to back.
    """

    EPS = 0.25
    WAKEUP_EPS = 15

    DUT_MAC = "00:17:b6:00:07:82"
    FW_REMOTE_MAC = "00:17:b6:33:44:91"

    FW_LOCAL_IP4 = "169.254.23.232"
    FW_REMOTE_IP4 = "169.254.23.111"

    FW_LOCAL_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2400"
    FW_REMOTE_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2487"

    FW_WAKEUP_DELAY = 60  # firmware wakes up after KA timeout + 60 seconds

    @classmethod
    def setup_class(cls):
        super(TestTcpKeepAlive, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", drv_type=DRV_TYPE_DIAG, host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.FW_REMOTE_IP4, "255.255.0.0", None)
            cls.lkp_ifconfig.set_ipv6_address(cls.FW_REMOTE_IP6, 64, None)

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port)

            # Disable Samba to remove background multicast traffic which affects SerDes
            Samba(host=cls.lkp_hostname).stop()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestTcpKeepAlive, self).setup_method(method)

        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)
        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(True)
            self.bin_log_file, self.txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestTcpKeepAlive, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        if self.MCP_LOG:
            self.dut_bin_log_file, self.dut_txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.dut_bin_log_file, self.test_log_dir)
            shutil.copy(self.dut_txt_log_file, self.test_log_dir)

            self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

        if os.path.exists("packets.pcap"):
            shutil.move("packets.pcap", self.test_log_dir)
        if os.path.exists("packets-filter.pcap"):
            shutil.move("packets-filter.pcap", self.test_log_dir)

    def get_wake_counter_on_dut(self, cleanup_fw=False):
        """
        Read wake counter from MCP memory on DUT
        *cleanup_fw* is needed to be sure that counter won't be increased between tests
        """
        if cleanup_fw:
            self.dut_atltool_wrapper.writereg(0x36c, 0x0)
            time.sleep(1)
        return self.dut_atltool_wrapper.get_wake_counter_2x()

    def get_wake_reason_on_dut(self):
        wake_reason = self.dut_atltool_wrapper.get_wake_reason_2x()
        log.info("Wake reason: {}".format(hex(wake_reason)))
        return wake_reason

    def gen_probe_ka_pkt(self, off_ka, ipv):
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

    def gen_reply_ka_pkt(self, pkt):
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

    def check_pkt_is_fw_probe(self, pkt, fw_mac, off_ka, ipv):
        assert pkt[0].src == fw_mac
        assert pkt[0].dst == off_ka.remote_mac_address
        if ipv == 4:
            assert pkt[1].src == off_ka.local_ip
            assert pkt[1].dst == off_ka.remote_ip
        else:
            assert pkt[1].src == get_compressed_ipv6(off_ka.local_ip)
            assert pkt[1].dst == get_compressed_ipv6(off_ka.remote_ip)
        assert pkt[2].sport == off_ka.local_port
        assert pkt[2].dport == off_ka.remote_port
        # Seq and Ack nums are configured for FW's probes
        assert pkt[2].seq == off_ka.seq_num
        assert pkt[2].ack == off_ka.ack_num
        assert pkt[2].window == off_ka.win_size

    def check_pkt_is_fw_ack(self, pkt, fw_mac, off_ka, ipv):
        assert pkt[0].src == fw_mac
        assert pkt[0].dst == off_ka.remote_mac_address
        if ipv == 4:
            assert pkt[1].src == off_ka.local_ip
            assert pkt[1].dst == off_ka.remote_ip
        else:
            assert pkt[1].src == get_compressed_ipv6(off_ka.local_ip)
            assert pkt[1].dst == get_compressed_ipv6(off_ka.remote_ip)
        assert pkt[2].sport == off_ka.local_port
        assert pkt[2].dport == off_ka.remote_port
        assert pkt[2].seq == off_ka.seq_num + 1
        assert pkt[2].ack == off_ka.ack_num
        assert pkt[2].window == off_ka.win_size

    def perform_wakeup_on_packet_test(self, pkt, eth_cfg):
        log.info("Next packet will be used to wake the host:")
        pkt.show()

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        beton_file = os.path.join(self.test_log_dir, "wake_on_wrong_pkt.txt")
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)
        sock.send(pkt)
        sock.close()

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter after test: {}".format(new_wake_counter))

        assert new_wake_counter > prev_wake_counter, "Wake counter hasn't been increased; FW didn't wake host"
        log.info("Wake counter has been increased; FW tried wake host")

    @idparametrize("retry_interval,ipv", [(1500, 4), (1000, 4), (1700, 6), (800, 6)])
    def test_no_answers_small_retry(self, retry_interval, ipv):
        """
        @description: This subtest verifies TCPKA retry interval attribute. The following parameters will be checked:
        retry interval is less than timeout, intervals to check: [1500, 1000, 1700, 800], IPv4 and IPv6.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT.
        3. Make sure that link is up on LKP.
        4. Sniff traffic on LKP during 1 minute.
        5. Analyse traffic, make sure that time delta between packets is increased according to retry interval.

        @result: Time delta between packets is increased correctly.
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
        off_ka_info.retry_interval = retry_interval

        # FW starts to count down timeout right after config
        off_ka = OffloadKa(timeout=15, local_port=23, remote_port=22, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=1000, seq_num=2456, ack_num=1212)

        # Check main aim of the test
        assert retry_interval / 1000.0 < off_ka.timeout

        if ipv == 4:
            off_ka.local_ip = self.FW_LOCAL_IP4
            off_ka.remote_ip = self.FW_REMOTE_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.FW_LOCAL_IP6
            off_ka.remote_ip = self.FW_REMOTE_IP6
            off_ka_info.v6_kas.append(off_ka)

        eth_cfg.kas = off_ka_info

        beton_file = os.path.join(self.test_log_dir, "no_answers_{}_{}.txt".format(retry_interval, ipv))
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        sniffer = Sniffer(port=self.lkp_port, timeout=60, filter="tcp")
        packets = sniffer.run()
        wrpcap("packets.pcap", packets)
        assert len(packets) >= 2, "Captured too few packets"

        log.info("\n".join(["Sniffed packets:"] + ["{}: {}".format(p.time, p.summary()) for p in packets]))

        retry_interval_sec = retry_interval / 1000.0
        expected_ka_timings = [
            off_ka.timeout + retry_interval_sec * 2 * 2 * 2,
            retry_interval_sec,
            retry_interval_sec * 2,
            retry_interval_sec * 2 * 2
        ]
        log.info("Expected timings: {}".format(", ".join(str(t) for t in expected_ka_timings)))

        first_timing = packets[1].time - packets[0].time
        log.info("First timing is {}".format(first_timing))

        start_timing = -1
        log.info("Checking start timing...")
        for i in range(len(expected_ka_timings)):
            if abs(first_timing - expected_ka_timings[i]) < self.EPS:
                start_timing = i
                break
        log.info("start_timing = {}".format(start_timing))
        assert start_timing != -1, "Didn't found start timing in timings pattern"

        log.info("Checking timings between packets...")
        for i in range(1, len(packets)):
            timing = packets[i].time - packets[i - 1].time
            log.info("Timing between {} and {} packets = {}".format(i - 1, i, timing))
            assert abs(expected_ka_timings[start_timing % len(expected_ka_timings)] - timing) < self.EPS
            log.info("Before packet {}: timing = {}, OK".format(i, timing))
            start_timing += 1

    @idparametrize("timeout", [2, 3])
    def test_timeout_with_answers(self, timeout):
        """
        @description: This subtest verifies TCPKA timeout attribute. The following timeouts will be checked: [2, 3].
        TCPKA probes sent by the firmware should be answered.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT.
        3. Make sure that link is up on LKP.
        4. Sniff traffic on LKP during 1 minute, answer TCPKA probes.
        5. Analyse traffic, make sure that time delta between packets is constant.

        @result: Time delta between packets is constant.
        @duration: 2 minutes.
        """

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 2
        off_ka_info.retry_interval = 5000

        off_ka = OffloadKa(timeout=timeout, local_port=22, remote_port=23, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=2000, seq_num=1357, ack_num=2424, local_ip=self.FW_LOCAL_IP4,
                           remote_ip=self.FW_REMOTE_IP4)
        off_ka_info.v4_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        beton_file = os.path.join(self.test_log_dir, "timeout_{}_with_ans.txt".format(timeout))
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        def callback(pkt):
            if pkt[1].dst == off_ka.remote_ip:
                ans = self.gen_reply_ka_pkt(pkt)
                sock.send(ans)

        sniffer = Sniffer(port=self.lkp_port, timeout=timeout * 20, filter="tcp")
        all_packets = sniffer.run(callback=callback, iface=lkp_scapy_iface)[1:]  # throw away first packet
        sock.close()

        wrpcap("packets.pcap", all_packets)

        packets = [pkt for pkt in all_packets if pkt[1].dst == off_ka.remote_ip]

        wrpcap("packets-filter.pcap", all_packets)

        assert len(packets) >= 2, "Captured too few packets"

        log.info("\n".join(["ALL packets:"] + ["{}: {}".format(p.time, p.summary()) for p in all_packets]))
        log.info("\n".join(["Sniffed packets:"] + ["{}: {}".format(p.time, p.summary()) for p in packets]))

        for i in range(1, len(packets)):
            timing = packets[i].time - packets[i - 1].time
            log.info("Timing between {} and {} packets = {}".format(i - 1, i, timing))
            assert abs(timeout - timing) < self.EPS

        log.info("Checking if all packets have right fields, configured in FW")
        for pkt in packets:
            self.check_pkt_is_fw_probe(pkt, eth_cfg.mac, off_ka, 4), "Packet is not FW's probe"

    def test_multiple_kas(self):
        """
        @description: This subtest verifies multiple TCPKA configuration. It creates 2 IPv4 and 2 IPv6 entries. TCP
        probes are not answered.

        @steps:
        1. Kickstart DUT.
        2. Configure all TCPKAs on DUT.
        3. Make sure that link is up on LKP.
        4. Sniff traffic on LKP during 1 minute, answer TCPKA probes.
        5. Make sure that all TCPKA entries are sending TCP probes.

        @result: All TCPKA entries works well.
        @duration: 2 minutes.
        """

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 3
        off_ka_info.retry_interval = 1000

        off_ka_v4_1 = OffloadKa(timeout=1, local_port=22, remote_port=23, remote_mac_address="00:17:b6:33:44:91",
                                win_size=1000, seq_num=1100, ack_num=1111, local_ip="169.254.23.232",
                                remote_ip="169.254.23.111")
        off_ka_v4_2 = OffloadKa(timeout=2, local_port=24, remote_port=25, remote_mac_address="00:17:b6:33:44:92",
                                win_size=2000, seq_num=2200, ack_num=2222, local_ip="169.254.23.233",
                                remote_ip="169.254.23.112")
        off_ka_v6_1 = OffloadKa(timeout=3, local_port=26, remote_port=27, remote_mac_address="00:17:b6:33:44:93",
                                win_size=3000, seq_num=3300, ack_num=3333,
                                local_ip="4000:0000:0000:0000:1601:bd17:0c02:2400",
                                remote_ip="4000:0000:0000:0000:1601:bd17:0c02:2487")
        off_ka_v6_2 = OffloadKa(timeout=4, local_port=28, remote_port=29, remote_mac_address="00:17:b6:33:44:94",
                                win_size=4000, seq_num=4400, ack_num=4444,
                                local_ip="4000:0000:0000:0000:1601:bd17:0c02:2401",
                                remote_ip="4000:0000:0000:0000:1601:bd17:0c02:2488")
        off_ka_info.v4_kas.append(off_ka_v4_1)
        off_ka_info.v4_kas.append(off_ka_v4_2)
        off_ka_info.v6_kas.append(off_ka_v6_1)
        off_ka_info.v6_kas.append(off_ka_v6_2)
        eth_cfg.kas = off_ka_info

        beton_file = os.path.join(self.test_log_dir, "multiple_kas.txt")
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        sniffer = Sniffer(port=self.lkp_port, timeout=40, filter="tcp")
        packets = sniffer.run()
        wrpcap("packets.pcap", packets)
        wrpcap("packets-filter.pcap", packets)
        assert len(packets) >= 2, "Captured too few packets"

        log.info("\n".join(["Sniffed packets:"] + ["{}: {}".format(p.time, p.summary()) for p in packets]))

        log.info("Searching for 4 different KA types")
        kas_found = []
        for pkt in packets:
            if pkt[0].dst == off_ka_v4_1.remote_mac_address:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_probe(pkt, eth_cfg.mac, off_ka_v4_1, 4), "Packet is not FW's probe"
            elif pkt[0].dst == off_ka_v4_2.remote_mac_address:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_probe(pkt, eth_cfg.mac, off_ka_v4_2, 4), "Packet is not FW's probe"
            elif pkt[0].dst == off_ka_v6_1.remote_mac_address:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_probe(pkt, eth_cfg.mac, off_ka_v6_1, 6), "Packet is not FW's probe"
            elif pkt[0].dst == off_ka_v6_2.remote_mac_address:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_probe(pkt, eth_cfg.mac, off_ka_v6_2, 6), "Packet is not FW's probe"
        assert len(kas_found) == 4, "Didn't found all 4 different KA types in sniffed packets"

    @idparametrize("ipv", [4, 6])
    def test_remote_probe(self, ipv):
        """
        @description: Verify that FW is able to answer probes with ack, IPv4 and IPv6 protocols are tested.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT.
        3. Make sure that link is up on LKP.
        4. In the loop send TCPKA probes from LKP to DUT.
        5. Verify that all probes are answered.

        @result: Probes are answered.
        @duration: 2 minutes.
        """

        timeout = 30  # sec

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
        off_ka = OffloadKa(timeout=timeout, local_port=23, remote_port=22, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=1000, seq_num=2456, ack_num=1212)
        if ipv == 4:
            off_ka.local_ip = self.FW_LOCAL_IP4
            off_ka.remote_ip = self.FW_REMOTE_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.FW_LOCAL_IP6
            off_ka.remote_ip = self.FW_REMOTE_IP6
            off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        probe_pkt = self.gen_probe_ka_pkt(off_ka, ipv)
        log.info("Prepared next probe packet:")
        probe_pkt.show()

        beton_file = os.path.join(self.test_log_dir, "remote_probe_ipv{}.txt".format(ipv))
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        sniffer = Sniffer(port=self.lkp_port, timeout=timeout, filter="tcp")
        sniffer.run_async(iface=lkp_scapy_iface)

        for pkt_num in range(5):
            time.sleep(2)
            sock.send(probe_pkt)

        all_packets = sniffer.join()
        sock.close()

        wrpcap("packets.pcap", all_packets)

        packets = [pkt for pkt in all_packets if
                   pkt[1].dst == (off_ka.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka.remote_ip))]
        wrpcap("packets-filter.pcap", packets)

        assert len(packets) >= 5, "Captured too few packets"

        log.info("\n".join(["ALL packets:"] + ["{}: {}".format(p.time, p.summary()) for p in all_packets]))
        log.info("\n".join(["Sniffed packets:"] + ["{}: {}".format(p.time, p.summary()) for p in packets]))

        log.info("Checking if all packets have right fields, configured in FW")
        for pkt in packets:
            self.check_pkt_is_fw_ack(pkt, eth_cfg.mac, off_ka, ipv), "Packet is not FW's ack"

    def test_multi_remote_probes(self):
        """
        @description: Check that FW is able to answer on multiple probes with ack.

        @steps:
        1. Kickstart DUT.
        2. Configure multiple IPv4 and IPv6 TCPKAs on DUT.
        3. Make sure that link is up on LKP.
        4. In the loop send TCPKA probes from LKP to DUT for all configured TCPKAs.
        5. Verify that all probes are answered.

        @result: Probes are answered.
        @duration: 2 minutes.
        """

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 3
        off_ka_info.retry_interval = 2000

        off_ka_v4_1 = OffloadKa(timeout=27, local_port=122, remote_port=123, remote_mac_address="00:17:b6:33:44:91",
                                win_size=1500, seq_num=1000, ack_num=1110, local_ip="169.254.23.232",
                                remote_ip="169.254.23.111")
        off_ka_v4_2 = OffloadKa(timeout=29, local_port=124, remote_port=125, remote_mac_address="00:17:b6:33:44:92",
                                win_size=2500, seq_num=2000, ack_num=2220, local_ip="169.254.23.233",
                                remote_ip="169.254.23.112")
        off_ka_v6_1 = OffloadKa(timeout=31, local_port=126, remote_port=127, remote_mac_address="00:17:b6:33:44:93",
                                win_size=3500, seq_num=3000, ack_num=3330,
                                local_ip="4000:0000:0000:0000:1601:bd17:0c02:2400",
                                remote_ip="4000:0000:0000:0000:1601:bd17:0c02:2487")
        off_ka_v6_2 = OffloadKa(timeout=33, local_port=128, remote_port=129, remote_mac_address="00:17:b6:33:44:94",
                                win_size=4500, seq_num=4000, ack_num=4440,
                                local_ip="4000:0000:0000:0000:1601:bd17:0c02:2401",
                                remote_ip="4000:0000:0000:0000:1601:bd17:0c02:2488")
        off_ka_info.v4_kas.append(off_ka_v4_1)
        off_ka_info.v4_kas.append(off_ka_v4_2)
        off_ka_info.v6_kas.append(off_ka_v6_1)
        off_ka_info.v6_kas.append(off_ka_v6_2)
        eth_cfg.kas = off_ka_info

        probe_ka_v4_1 = self.gen_probe_ka_pkt(off_ka_v4_1, 4)
        probe_ka_v4_2 = self.gen_probe_ka_pkt(off_ka_v4_2, 4)
        probe_ka_v6_1 = self.gen_probe_ka_pkt(off_ka_v6_1, 6)
        probe_ka_v6_2 = self.gen_probe_ka_pkt(off_ka_v6_2, 6)

        log.info("Prepared next probe packets:")
        probe_ka_v4_1.show()
        probe_ka_v4_2.show()
        probe_ka_v6_1.show()
        probe_ka_v6_2.show()

        beton_file = os.path.join(self.test_log_dir, "multi_probes.txt")
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        # fltr = "tcp and ({})".format(" or ".join("dst host {}".format(ka_entry.remote_ip)
        #                                          for ka_entry in off_ka_info.v4_kas + off_ka_info.v6_kas))
        sniffer = Sniffer(port=self.lkp_port, timeout=20, filter="tcp")
        sniffer.run_async()
        for pkt_num in range(5):
            time.sleep(1)
            sock.send(probe_ka_v4_1)
            time.sleep(1)
            sock.send(probe_ka_v4_2)
            time.sleep(1)
            sock.send(probe_ka_v6_1)
            time.sleep(1)
            sock.send(probe_ka_v6_2)
        all_packets = sniffer.join()
        sock.close()

        wrpcap("packets.pcap", all_packets)

        ips = [off_ka.remote_ip for off_ka in off_ka_info.v4_kas] + [get_compressed_ipv6(off_ka.remote_ip) for off_ka in
                                                                     off_ka_info.v6_kas]

        packets = [pkt for pkt in all_packets if pkt[1].dst in ips]
        wrpcap("packets-filter.pcap", packets)

        assert len(packets) >= 4, "Captured too few packets"

        log.info("\n".join(["ALL packets:"] + ["{}: {}".format(p.time, p.summary()) for p in all_packets]))
        log.info("\n".join(["Sniffed packets:"] + ["{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack)
                                                   for p in packets]))

        log.info("Searching for 4 different KA types")
        kas_found = []
        for pkt in packets:
            if pkt[0].dst == off_ka_v4_1.remote_mac_address:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_ack(pkt, eth_cfg.mac, off_ka_v4_1, 4), "Packet is not FW's ack"
            elif pkt[0].dst == off_ka_v4_2.remote_mac_address:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_ack(pkt, eth_cfg.mac, off_ka_v4_2, 4), "Packet is not FW's ack"
            elif pkt[0].dst == off_ka_v6_1.remote_mac_address:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_ack(pkt, eth_cfg.mac, off_ka_v6_1, 6), "Packet is not FW's ack"
            elif pkt[0].dst == off_ka_v6_2.remote_mac_address:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_ack(pkt, eth_cfg.mac, off_ka_v6_2, 6), "Packet is not FW's ack"
        assert len(kas_found) == 4, "Didn't found all 4 different KA types in sniffed packets"

    @idparametrize("ipv", [4, 6])
    def test_fw_probes_after_remote_probes(self, ipv):
        """
        @description: Verify that FW sends probes after remote host stops sending it.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT.
        3. Make sure that link is up on LKP.
        4. Start sniffing traffic.
        4. Send 4 probes in the loop from LKP.
        5. Continue sniffing traffic.
        6. Make sure that number of firmware's probes is more than 6.

        @result: Firmware sends probes all the time.
        @duration: 2 minutes.
        """

        PROBE_INTERVAL = 1
        PROBE_COUNT = 4
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
        off_ka = OffloadKa(timeout=20, local_port=545, remote_port=9, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=500, seq_num=11, ack_num=22)
        if ipv == 4:
            off_ka.local_ip = self.FW_LOCAL_IP4
            off_ka.remote_ip = self.FW_REMOTE_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.FW_LOCAL_IP6
            off_ka.remote_ip = self.FW_REMOTE_IP6
            off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        probe_pkt = self.gen_probe_ka_pkt(off_ka, ipv)

        beton_file = os.path.join(self.test_log_dir, "fw_probes_after_remote.txt")
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        tmout = PROBE_COUNT * PROBE_INTERVAL + off_ka.timeout + \
                (off_ka_info.retry_interval / 1000.0 * (1 << (off_ka_info.retry_count + 1))) * 2 + 10
        log.info("Filter: tcp, timeout: {}".format(tmout))
        sniffer = Sniffer(port=self.lkp_port, timeout=tmout, filter="tcp")
        sniffer.run_async(iface=lkp_scapy_iface)

        for pkt_num in range(PROBE_COUNT):
            time.sleep(PROBE_INTERVAL)
            sock.send(probe_pkt)

        all_packets = sniffer.join()
        sock.close()

        wrpcap("packets.pcap", all_packets)

        packets = [pkt for pkt in all_packets
                   if pkt[1].dst == (off_ka.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka.remote_ip))]

        wrpcap("packets-filter.pcap", packets)

        assert len(packets) >= 6, "Captured too few packets"

        log.info("\n".join(["ALL packets:"] + ["{}: {}".format(p.time, p.summary()) for p in all_packets]))
        log.info("\n".join(["Sniffed packets:"] + ["{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack)
                                                   for p in packets]))

        actual_timings = [packets[i].time - packets[i - 1].time for i in range(1, len(packets))]
        log.info("Actual timings: {}".format(", ".join(str(t) for t in actual_timings)))

        retry_interval_sec = off_ka_info.retry_interval / 1000.0
        expected_ka_timings = [PROBE_INTERVAL] * (PROBE_COUNT - 1)
        expected_ka_timings.append(off_ka.timeout)
        expected_ka_timings.extend([retry_interval_sec,
                                    retry_interval_sec * 2,
                                    retry_interval_sec * 2 * 2,
                                    off_ka.timeout + retry_interval_sec * 2 * 2 * 2] * 3)
        log.info("Expected timings: {}".format(", ".join(str(t) for t in expected_ka_timings)))

        for i, act_t in enumerate(actual_timings):
            assert abs(act_t - expected_ka_timings[i]) < self.EPS, \
                "Actual timing is different that expected: {} != {}".format(act_t, expected_ka_timings[i])

    @idparametrize("ipv", [4, 6])
    def test_wakeup_by_timeout_no_answers_single_ka(self, ipv):
        """
        @description: Verify that FW wakes host after timeout for remote probes and all retry intervals are expired.
        IPv4 and IPv6 protocols are tested.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT.
        3. Make sure that link is up on LKP.
        4. Sleep needed time to wakeup.
        5. Make sure that DUT woke up.

        @result: FW wake the host after all timeouts are expired.
        @duration: 2 minutes.
        """

        assert ipv in [4, 6]

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 2
        off_ka_info.retry_interval = 1500

        off_ka = OffloadKa(timeout=10, local_port=22, remote_port=23, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=1000, seq_num=2456, ack_num=1212)
        if ipv == 4:
            off_ka.local_ip = self.FW_LOCAL_IP4
            off_ka.remote_ip = self.FW_REMOTE_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.FW_LOCAL_IP6
            off_ka.remote_ip = self.FW_REMOTE_IP6
            off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        beton_file = os.path.join(self.test_log_dir, "wake_no_ans_single_ipv{}.txt".format(ipv))
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        time_to_sleep = off_ka.timeout + off_ka_info.retry_interval / 1000.0 * (1 << (off_ka_info.retry_count + 1))
        log.info("Sleeping {} seconds (timeout + all retry intervals)".format(time_to_sleep))
        time.sleep(time_to_sleep)

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter after test: {}".format(new_wake_counter))

        wake_reason = self.get_wake_reason_on_dut()
        assert new_wake_counter > prev_wake_counter, "Wake counter hasn't been increased; FW didn't wake host"
        log.info("Wake counter has been increased; FW tried wake host")
        assert wake_reason == drv_iface_cfg.WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_TCPKA
        )

    def test_wakeup_by_timeout_no_answers_multiple_kas(self):
        """
        @description: Verify that FW wakes host after timeout for remote probes and all retry intervals are expired.

        @steps:
        1. Kickstart DUT.
        2. Configure multiple TCPKAs on DUT.
        3. Make sure that link is up on LKP.
        4. Sleep needed time to wakeup.
        5. Make sure that DUT woke up.

        @result: FW wake the host after all timeouts are expired.
        @duration: 2 minutes.
        """

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 2
        off_ka_info.retry_interval = 1500

        off_ka_v4_1 = OffloadKa(timeout=15, local_port=22, remote_port=23, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=1000, seq_num=1111, ack_num=1100, local_ip="192.168.0.2",
                                remote_ip="192.168.0.3")
        off_ka_v4_2 = OffloadKa(timeout=70, local_port=24, remote_port=25, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=1000, seq_num=2222, ack_num=2200, local_ip="192.168.0.4",
                                remote_ip="192.168.0.5")
        off_ka_v6_1 = OffloadKa(timeout=50, local_port=26, remote_port=27, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=4000, seq_num=3333, ack_num=3300,
                                local_ip="4000:0000:0000:0000:1601:bd17:0c02:2426",
                                remote_ip="4000:0000:0000:0000:1601:bd17:0c02:2427")
        off_ka_v6_2 = OffloadKa(timeout=100, local_port=28, remote_port=29, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=4000, seq_num=4444, ack_num=4400,
                                local_ip="4000:0000:0000:0000:1601:bd17:0c02:2428",
                                remote_ip="4000:0000:0000:0000:1601:bd17:0c02:2429")
        off_ka_info.v4_kas.append(off_ka_v4_1)
        off_ka_info.v4_kas.append(off_ka_v4_2)
        off_ka_info.v6_kas.append(off_ka_v6_1)
        off_ka_info.v6_kas.append(off_ka_v6_2)

        eth_cfg.kas = off_ka_info

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        beton_file = os.path.join(self.test_log_dir, "wake_no_ans_multi_kas.txt")
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        min_timeout = min(ka_entry.timeout for ka_entry in off_ka_info.v4_kas + off_ka_info.v6_kas)
        time_to_sleep = min_timeout + off_ka_info.retry_interval / 1000.0 * (1 << (off_ka_info.retry_count + 1))
        log.info("Sleeping {} seconds (min timeout + all retry intervals)".format(time_to_sleep))
        time.sleep(time_to_sleep)

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter after test: {}".format(new_wake_counter))

        wake_reason = self.get_wake_reason_on_dut()
        assert new_wake_counter > prev_wake_counter, "Wake counter hasn't been increased; FW didn't wake host"
        log.info("Wake counter has been increased; FW tried wake host")
        assert wake_reason == drv_iface_cfg.WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_TCPKA
        )

    def test_wakeup_with_answers_multiple_kas(self):
        """
        @description: Verify that FW wakes host on any KA timeout (if multiple KAs are configured).

        @steps:
        1. Kickstart DUT.
        2. Configure multiple TCPKAs on DUT.
        3. Make sure that link is up on LKP.
        4. Sleep needed time to wakeup, answer only several configured KAs.
        5. Make sure that DUT woke up by not answered KA.

        @result: FW wake the host after all timeouts are expired.
        @duration: 2 minutes.
        """

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 3
        off_ka_info.retry_interval = 1500

        off_ka_v4_1 = OffloadKa(timeout=10, local_port=22, remote_port=23, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=1000, seq_num=1111, ack_num=1100, local_ip="192.168.0.2",
                                remote_ip="192.168.0.3")
        off_ka_v4_2 = OffloadKa(timeout=2, local_port=24, remote_port=25, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=1000, seq_num=2222, ack_num=2200, local_ip="192.168.0.4",
                                remote_ip="192.168.0.5")
        off_ka_v6_1 = OffloadKa(timeout=20, local_port=26, remote_port=27, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=4000, seq_num=3333, ack_num=3300,
                                local_ip="4000:0000:0000:0000:1601:bd17:0c02:2426",
                                remote_ip="4000:0000:0000:0000:1601:bd17:0c02:2427")
        off_ka_v6_2 = OffloadKa(timeout=3, local_port=28, remote_port=29, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=4000, seq_num=4444, ack_num=4400,
                                local_ip="4000:0000:0000:0000:1601:bd17:0c02:2428",
                                remote_ip="4000:0000:0000:0000:1601:bd17:0c02:2429")
        off_ka_info.v4_kas.append(off_ka_v4_1)
        off_ka_info.v4_kas.append(off_ka_v4_2)
        off_ka_info.v6_kas.append(off_ka_v6_1)
        off_ka_info.v6_kas.append(off_ka_v6_2)

        eth_cfg.kas = off_ka_info

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        beton_file = os.path.join(self.test_log_dir, "wake_with_ans_multi_kas.txt")
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        def callback(pkt):
            # We answer only on off_ka_v4_2 and off_ka_v6_2
            if pkt[1].src == off_ka_v4_1.local_ip and pkt[1].dst == off_ka_v4_1.remote_ip:
                return
            if pkt[1].src == off_ka_v6_1.local_ip and pkt[1].dst == off_ka_v6_1.remote_ip:
                return

            ans = self.gen_reply_ka_pkt(pkt)
            sock.send(ans)

        # Since we answer on off_ka_v4_2 and off_ka_v6_2 only we expect that
        # off_ka_v4_1 or off_ka_v6_1 will trigger wakeup
        min_ka_timeout = min([off_ka_v4_1.timeout, off_ka_v6_1.timeout])

        fltr = "tcp and ({})".format(" or ".join("dst host {}".format(ka_entry.remote_ip)
                                                 for ka_entry in off_ka_info.v4_kas + off_ka_info.v6_kas))
        log.debug("Filter for sniffer: {}".format(fltr))

        # Sniffer timeout: min unanswered KA timeout + all retry intervals
        sniffer_timeout = min_ka_timeout + off_ka_info.retry_interval / 1000.0 * (1 << (off_ka_info.retry_count + 1))
        log.debug("Calculated sniffer timeout: {}".format(sniffer_timeout))

        sniffer = Sniffer(port=self.lkp_port, timeout=sniffer_timeout, filter=fltr)
        sniffer.run(callback=callback, iface=lkp_scapy_iface)
        sock.close()

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter after test: {}".format(new_wake_counter))

        wake_reason = self.get_wake_reason_on_dut()
        assert new_wake_counter > prev_wake_counter, "Wake counter hasn't been increased; FW didn't wake host"
        log.info("Wake counter has been increased; FW tried wake host")
        assert wake_reason == drv_iface_cfg.WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_TCPKA
        )

    @idparametrize("ipv", [4, 6])
    def test_no_wakeup_with_answers_single_ka(self, ipv):
        """
        @description: Verify that FW doesn't wake the host if it receives ACK to its own probes (1 KA is configured).
        IPv4 and IPv6 protocols are tested.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT.
        3. Make sure that link is up on LKP.
        4. Answer DUT probes during some time.
        5. Make sure that DUT didn't wake up.

        @result: Host didn't wake up if all probs are answered.
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

        off_ka = OffloadKa(timeout=5, local_port=22, remote_port=23, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=1000, seq_num=2456, ack_num=1212)
        if ipv == 4:
            off_ka.local_ip = self.FW_LOCAL_IP4
            off_ka.remote_ip = self.FW_REMOTE_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.FW_LOCAL_IP6
            off_ka.remote_ip = self.FW_REMOTE_IP6
            off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason_on_dut()
        log.info("Wake reason before test: {}".format(prev_wake_reason))

        beton_file = os.path.join(self.test_log_dir, "no_wake_with_ans_single_ka_ipv{}.txt".format(ipv))
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        def callback(pkt):
            if pkt[1].dst == (off_ka.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka.remote_ip)):
                ans = self.gen_reply_ka_pkt(pkt)
                sock.send(ans)

        log.info("Answering on FW's probes for 60 seconds in background")
        sniffer = Sniffer(port=self.lkp_port, timeout=60, filter="tcp")
        sniffer.run_async(callback=callback, iface=lkp_scapy_iface)

        log.info("Sleeping 45 seconds")
        time.sleep(45)

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Current wake counter: {}".format(new_wake_counter))
        new_wake_reason = self.get_wake_reason_on_dut()
        log.info("Current wake reason: {}".format(new_wake_reason))
        log.info("Waiting for sniffer to exit")
        all_packets = sniffer.join()
        sock.close()
        wrpcap("packets.pcap", all_packets)

        packets = [pkt for pkt in all_packets if
                   pkt[1].dst == (off_ka.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka.remote_ip))]

        wrpcap("packets-filter.pcap", packets)

        log.info("\n".join(["ALL packets:"] + ["{}: {}".format(p.time, p.summary()) for p in all_packets]))
        log.info("\n".join(["Answered on next packets:"] + ["{}: {}".format(p.time, p.summary()) for p in packets]))

        assert prev_wake_counter == new_wake_counter, "FW has tried to wake host while it shouldn't have"
        log.info("FW didn't try to wake host as expected")
        assert new_wake_reason == prev_wake_reason, "Wake reason was changed. Current: {}; Previous: {}".format(
            new_wake_reason, prev_wake_reason
        )

    def test_no_wakeup_with_answers_multiple_kas(self):
        """
        @description: Verify that FW doesn't wake the host if it receives ACK to its own probes (multi
        KA are configured).

        @steps:
        1. Kickstart DUT.
        2. Configure multiple TCPKAs on DUT.
        3. Make sure that link is up on LKP.
        4. Answer DUT probes during some time.
        5. Make sure that DUT didn't wake up.

        @result: Host didn't wake up if all probes are answered.
        @duration: 2 minutes.
        """

        ANS_TIMEOUT = 60

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 3
        off_ka_info.retry_interval = 2000

        off_ka_v4_1 = OffloadKa(timeout=5, local_port=22, remote_port=23, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=1000, seq_num=1111, ack_num=1100, local_ip="192.168.0.2",
                                remote_ip="192.168.0.3")
        off_ka_v4_2 = OffloadKa(timeout=7, local_port=24, remote_port=25, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=2000, seq_num=2222, ack_num=2200, local_ip="192.168.0.4",
                                remote_ip="192.168.0.5")
        off_ka_v6_1 = OffloadKa(timeout=9, local_port=26, remote_port=27, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=3000, seq_num=3333, ack_num=3300,
                                local_ip="4000:0000:0000:0000:1601:bd17:0c02:2426",
                                remote_ip="4000:0000:0000:0000:1601:bd17:0c02:2427")
        off_ka_v6_2 = OffloadKa(timeout=11, local_port=28, remote_port=29, remote_mac_address=self.FW_REMOTE_MAC,
                                win_size=4000, seq_num=4444, ack_num=4400,
                                local_ip="4000:0000:0000:0000:1601:bd17:0c02:2428",
                                remote_ip="4000:0000:0000:0000:1601:bd17:0c02:2429")
        off_ka_info.v4_kas.append(off_ka_v4_1)
        off_ka_info.v4_kas.append(off_ka_v4_2)
        off_ka_info.v6_kas.append(off_ka_v6_1)
        off_ka_info.v6_kas.append(off_ka_v6_2)

        eth_cfg.kas = off_ka_info

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason_on_dut()
        log.info("Wake reason before test: {}".format(prev_wake_reason))

        ips = [off_ka.remote_ip for off_ka in off_ka_info.v4_kas] + [get_compressed_ipv6(off_ka.remote_ip) for off_ka in
                                                                     off_ka_info.v6_kas]

        beton_file = os.path.join(self.test_log_dir, "no_wake_with_ans_multi_ka.txt")
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        def callback(pkt):
            if pkt[1].dst in ips:
                ans = self.gen_reply_ka_pkt(pkt)
                sock.send(ans)

        log.info("Answering on FW's probes for {} seconds in background".format(ANS_TIMEOUT))
        sniffer = Sniffer(port=self.lkp_port, timeout=ANS_TIMEOUT, filter="tcp")
        sniffer.run_async(callback=callback, iface=lkp_scapy_iface)

        log.info("Sleeping {} seconds".format(ANS_TIMEOUT - 15))
        time.sleep(ANS_TIMEOUT - 15)

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Current wake counter: {}".format(new_wake_counter))
        new_wake_reason = self.get_wake_reason_on_dut()
        log.info("Current wake reason: {}".format(new_wake_reason))

        log.info("Waiting for sniffer to exit")
        all_packets = sniffer.join()
        sock.close()

        wrpcap("packets.pcap", all_packets)

        packets = [pkt for pkt in all_packets if pkt[1].dst in ips]

        wrpcap("packets-filter.pcap", packets)

        log.debug("\n".join(["ALL packets:"] + ["{}: {}".format(p.time, p.summary()) for p in all_packets]))
        log.debug("\n".join(["Answered on next packets:"] + ["{}: {}".format(p.time, p.summary()) for p in packets]))

        assert prev_wake_counter == new_wake_counter, "FW has tried to wake host while it shouldn't have"
        log.info("FW didn't try to wake host as expected")
        assert new_wake_reason == prev_wake_reason, "Wake reason was changed. Current: {}; Previous: {}".format(
            new_wake_reason, prev_wake_reason
        )

    @idparametrize("ipv", [4, 6])
    def test_no_wakeup_with_remote_probes(self, ipv):
        """
        @description: Verify that FW doesn't wake the host if it receives probes from remote host.
        IPv4 and IPv6 protocols are tested.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT.
        3. Make sure that link is up on LKP.
        4. Send probes from LKP fto DUT during some time.
        5. Make sure that DUT didn't wake up.

        @result: Host doesn't wake up if it receives remote probes.
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
        off_ka = OffloadKa(timeout=20, local_port=123, remote_port=122, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=2048, seq_num=5000, ack_num=3001)
        if ipv == 4:
            off_ka.local_ip = self.FW_LOCAL_IP4
            off_ka.remote_ip = self.FW_REMOTE_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.FW_LOCAL_IP6
            off_ka.remote_ip = self.FW_REMOTE_IP6
            off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        probe_pkt = self.gen_probe_ka_pkt(off_ka, ipv)
        log.info("Prepared next probe packet:")
        probe_pkt.show()

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason_on_dut()
        log.info("Wake reason before test: {}".format(prev_wake_reason))

        beton_file = os.path.join(self.test_log_dir, "no_wake_with_probes.txt")
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        for pkt_num in range(5):
            sock.send(probe_pkt)
            time.sleep(off_ka.timeout / 2)
        sock.send(probe_pkt)
        sock.close()

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Current wake counter: {}".format(new_wake_counter))
        new_wake_reason = self.get_wake_reason_on_dut()
        log.info("Current wake reason: {}".format(new_wake_reason))

        assert prev_wake_counter == new_wake_counter, "FW has tried to wake host while it shouldn't have"
        log.info("FW didn't try to wake host as expected")
        assert new_wake_reason == prev_wake_reason, "Wake reason was changed. Current: {}; Previous: {}".format(
            new_wake_reason, prev_wake_reason
        )

    @idparametrize("ipv", [4, 6])
    def test_wakeup_on_wrong_probe_seq_num(self, ipv):
        """
        @description: Verify that FW wakes the host on TCP ACK packet with unexpected SEQ num.
        IPv4 and IPv6 protocols are tested.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT.
        3. Make sure that link is up on LKP.
        4. Send TCP ACK with invalid SEQ number from LKP to DUT.
        5. Make sure that DUT woke up.

        @result: DUT woke up due to invalid TCP SEQ number.
        @duration: 2 minutes.
        """

        assert ipv in [4, 6]

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 2
        off_ka_info.retry_interval = 1500

        off_ka = OffloadKa(timeout=40, local_port=22, remote_port=23, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=1000, seq_num=2456, ack_num=1212)
        if ipv == 4:
            off_ka.local_ip = self.FW_LOCAL_IP4
            off_ka.remote_ip = self.FW_REMOTE_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.FW_LOCAL_IP6
            off_ka.remote_ip = self.FW_REMOTE_IP6
            off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        fake_probe_pkt = self.gen_probe_ka_pkt(off_ka, ipv)
        fake_probe_pkt[2].seq += random.randint(10, 100)

        self.perform_wakeup_on_packet_test(fake_probe_pkt, eth_cfg)
        wake_reason = self.get_wake_reason_on_dut()
        assert wake_reason == drv_iface_cfg.WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_TCPKA
        )

    @idparametrize("ipv", [4, 6])
    def test_wakeup_on_wrong_probe_flags(self, ipv):
        """
        @description: Verify that FW wakes the host on TCP packet with flags other than ACK.
        IPv4 and IPv6 protocols are tested.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT.
        3. Make sure that link is up on LKP.
        4. Send TCP packet with not ACK flag.
        5. Make sure that DUT woke up.

        @result: DUT woke up due to not ACT flag presented in TCP packet.
        @duration: 2 minutes.
        """

        assert ipv in [4, 6]

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 2
        off_ka_info.retry_interval = 1500

        off_ka = OffloadKa(timeout=40, local_port=32, remote_port=33, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=2000, seq_num=7456, ack_num=7212)
        if ipv == 4:
            off_ka.local_ip = self.FW_LOCAL_IP4
            off_ka.remote_ip = self.FW_REMOTE_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.FW_LOCAL_IP6
            off_ka.remote_ip = self.FW_REMOTE_IP6
            off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        pkt = self.gen_probe_ka_pkt(off_ka, ipv)
        pkt[2].flags = "AP"

        self.perform_wakeup_on_packet_test(pkt, eth_cfg)
        wake_reason = self.get_wake_reason_on_dut()
        assert wake_reason == drv_iface_cfg.WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_TCPKA
        )

    @idparametrize("ipv", [4, 6])
    def test_wakeup_on_fin_ack(self, ipv):
        """
        @description: Verify that FW wakes the host on TCP FIN packet.
        IPv4 and IPv6 protocols are tested.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT.
        3. Make sure that link is up on LKP.
        4. Send TCP FIN packet.
        5. Make sure that DUT woke up.

        @result: DUT woke up due to TCP FIN packet (closed TCP session).
        @duration: 2 minutes.
        """

        assert ipv in [4, 6]

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 10  # To make sure FW doesn't stop sending packets to test wake event
        off_ka_info.retry_interval = 1500

        off_ka = OffloadKa(timeout=10, local_port=19, remote_port=20, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=1000, seq_num=2456, ack_num=1212)
        if ipv == 4:
            off_ka.local_ip = self.FW_LOCAL_IP4
            off_ka.remote_ip = self.FW_REMOTE_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.FW_LOCAL_IP6
            off_ka.remote_ip = self.FW_REMOTE_IP6
            off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        beton_file = os.path.join(self.test_log_dir, "wake_on_fin_ipv{}.txt".format(ipv))
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        def callback(pkt):
            if pkt[1].dst == (off_ka.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka.remote_ip)):
                ans = self.gen_reply_ka_pkt(pkt)
                ans[2].ack = 0  # FIN packet should have ack = 0
                ans[2].flags = "F"
                sock.send(ans)
                log.info("Sending packet: {}".format(ans.summary()))

        sniffer = Sniffer(port=self.lkp_port, timeout=40, filter="tcp")
        all_packets = sniffer.run(callback=callback, iface=lkp_scapy_iface)
        sock.close()

        wrpcap("packets.pcap", all_packets)

        packets = [pkt for pkt in all_packets if
                   pkt[1].dst == (off_ka.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka.remote_ip))]

        wrpcap("packets-filter.pcap", packets)

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter after test: {}".format(new_wake_counter))

        assert new_wake_counter > prev_wake_counter, "Wake counter hasn't been increased; FW didn't wake host"
        log.info("Wake counter has been increased; FW tried wake host")
        wake_reason = self.get_wake_reason_on_dut()
        assert wake_reason == drv_iface_cfg.WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, drv_iface_cfg.WAKE_REASON_TCPKA
        )

    def test_no_icmpv6_on_wrong_remote_probe(self):
        """
        @description: Test that FW doesn't send any ICMPv6 Parameter Problem packets.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT.
        3. Make sure that link is up on LKP.
        4. Answer DUT probes with TCK ACK packet with additional payload.
        5. Make sure that DUT didn't send parameter problem packets.

        @result: DUT didn't send parameter problem packets.
        @duration: 2 minutes.
        """

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()
        eth_cfg.ips.v6_addr_count = 1
        eth_cfg.ips.v6_addresses = [self.FW_LOCAL_IP6]
        eth_cfg.ips.v6_masks = [64]

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 2
        off_ka_info.retry_interval = 5000

        off_ka = OffloadKa(timeout=20, local_port=49258, remote_port=3005, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=4105, seq_num=346427013, ack_num=3436736187, local_ip=self.FW_LOCAL_IP6,
                           remote_ip=self.FW_REMOTE_IP6)
        off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        beton_file = os.path.join(self.test_log_dir, "no_icmpv6_parameter_problem.txt")
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        def callback(pkt):
            if pkt.haslayer(TCP) and pkt[1].dst == get_compressed_ipv6(self.FW_REMOTE_IP6):
                ans = self.gen_reply_ka_pkt(pkt)
                sock.send(ans)

                time.sleep(5)
                fake_ack = ans.copy()
                fake_ack[2].flags = "PA"
                # Recalculate checksum
                fake_ack[1].chksum = None
                fake_ack[2].chksum = None
                fake_ack /= Raw(load="test4\x00\x02\x00\x00\x00")
                sock.send(fake_ack)

        fltr = "tcp or icmp6"
        sniffer = Sniffer(port=self.lkp_port, timeout=60, filter=fltr)
        packets = sniffer.run(callback=callback, iface=lkp_scapy_iface)
        sock.close()
        wrpcap("packets.pcap", packets)
        wrpcap("packets-filter.pcap", packets)

        assert len(packets) >= 1, "Captured too few packets"

        log.info("\n".join(["Sniffed packets:"] + ["{}: {}".format(p.time, p.summary()) for p in packets]))

        log.info("Making sure that there is no Parameter Problem packets in sniffed packets")
        assert not [pkt for pkt in packets if pkt.haslayer(ICMPv6ParamProblem)], \
            "FW sent ICMPv6 Parameter Problem packet on remote TCP KA ACK"

    @idparametrize("ipv", [4, 6])
    def test_no_wakeup_on_seq_out_of_window(self, ipv):
        """
        @description: Verify that FW doesn't wake the host if it receives SYN with SEQ out of window (1 KA is
        configured).
        IPv4 and IPv6 protocols are tested.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT with large timeout (to prevent false wake).
        3. Make sure that link is up on LKP.
        4. Send TCP KA probe with sequence number out of window range.
        5. Make sure that DUT didn't wake up.

        @result: Host didn't wake up (FW skipped TCP packets with SEQ out of window).
        @duration: 2 minutes.
        """

        assert ipv in [4, 6]

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 10
        off_ka_info.retry_interval = 2000

        off_ka = OffloadKa(timeout=30, local_port=22, remote_port=23, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=1000, seq_num=2456, ack_num=1212)
        if ipv == 4:
            off_ka.local_ip = self.FW_LOCAL_IP4
            off_ka.remote_ip = self.FW_REMOTE_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.FW_LOCAL_IP6
            off_ka.remote_ip = self.FW_REMOTE_IP6
            off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason_on_dut()
        log.info("Wake reason before test: {}".format(prev_wake_reason))

        beton_file = os.path.join(self.test_log_dir, "no_wake_on_seq_out_of_window_ipv{}.txt".format(ipv))
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        pkt = self.gen_probe_ka_pkt(off_ka, ipv)
        pkts = [pkt.copy(), pkt.copy()]
        pkts[0][TCP].seq += off_ka.win_size + 2
        pkts[1][TCP].seq += off_ka.win_size + 100

        log.info("Sending wrong probes")
        for pkt in pkts:
            log.info(pkt.summary())
            sock.send(pkt)

        sock.close()

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Current wake counter: {}".format(new_wake_counter))
        new_wake_reason = self.get_wake_reason_on_dut()
        log.info("Current wake reason: {}".format(new_wake_reason))

        assert prev_wake_counter == new_wake_counter, "FW has tried to wake host while it shouldn't have"
        log.info("FW didn't try to wake host as expected")
        assert new_wake_reason == prev_wake_reason, "Wake reason was changed. Current: {}; Previous: {}".format(
            new_wake_reason, prev_wake_reason
        )

    @idparametrize("ipv", [4, 6])
    def test_no_wakeup_on_smaller_seq(self, ipv):
        """
        @description: Verify that FW doesn't wake the host if it receives SYN with SEQ out of window (1 KA is
        configured).
        IPv4 and IPv6 protocols are tested.

        @steps:
        1. Kickstart DUT.
        2. Configure TCPKA on DUT with large timeout (to prevent false wake).
        3. Make sure that link is up on LKP.
        4. Send TCP KA probe with sequence number lower than configured.
        5. Make sure that DUT didn't wake up.

        @result: Host didn't wake up (FW skipped TCP packets with SEQ out of window).
        @duration: 2 minutes.
        """

        assert ipv in [4, 6]

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()

        off_ka_info = OffloadKaInfo()
        off_ka_info.retry_count = 10
        off_ka_info.retry_interval = 2000

        off_ka = OffloadKa(timeout=30, local_port=22, remote_port=23, remote_mac_address=self.FW_REMOTE_MAC,
                           win_size=1000, seq_num=2456, ack_num=1212)
        if ipv == 4:
            off_ka.local_ip = self.FW_LOCAL_IP4
            off_ka.remote_ip = self.FW_REMOTE_IP4
            off_ka_info.v4_kas.append(off_ka)
        else:
            off_ka.local_ip = self.FW_LOCAL_IP6
            off_ka.remote_ip = self.FW_REMOTE_IP6
            off_ka_info.v6_kas.append(off_ka)
        eth_cfg.kas = off_ka_info

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason_on_dut()
        log.info("Wake reason before test: {}".format(prev_wake_reason))

        beton_file = os.path.join(self.test_log_dir, "no_wake_on_seq_out_of_window_ipv{}.txt".format(ipv))
        eth_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        pkt = self.gen_probe_ka_pkt(off_ka, ipv)
        pkts = [pkt.copy(), pkt.copy()]
        pkts[0][TCP].seq -= 2
        pkts[1][TCP].seq -= 10

        log.info("Sending wrong probes")
        for pkt in pkts:
            log.info(pkt.summary())
            sock.send(pkt)

        sock.close()

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Current wake counter: {}".format(new_wake_counter))
        new_wake_reason = self.get_wake_reason_on_dut()
        log.info("Current wake reason: {}".format(new_wake_reason))

        assert prev_wake_counter == new_wake_counter, "FW has tried to wake host while it shouldn't have"
        log.info("FW didn't try to wake host as expected")
        assert new_wake_reason == prev_wake_reason, "Wake reason was changed. Current: {}; Previous: {}".format(
            new_wake_reason, prev_wake_reason
        )


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
