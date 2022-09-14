import os
import random
import shutil
import sys
import time

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO
from tools.scapy_tools import ScapyTools, get_l2_scapy_socket
from tools.sniffer import Sniffer
from tools.utils import get_atf_logger, get_compressed_ipv6
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config, SleepProxyOffload, WAKE_REASON_TCPKA

from infra.test_base import TestBase, idparametrize

from scapy.all import Ether, IP, IPv6, TCP, Padding, Raw, ICMPv6ParamProblem, RandString, wrpcap

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_tcp_ka"


class TestFWTcpKeepAlive(TestBase):
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

    FW_LOCAL_IP4 = [
        "169.254.23.11", "169.254.23.12", "169.254.23.13", "169.254.23.14",
        "169.254.23.15", "169.254.23.16", "169.254.23.17", "169.254.23.18"
    ]

    FW_REMOTE_IP4 = [
        "169.254.23.21", "169.254.23.22", "169.254.23.23", "169.254.23.24",
        "169.254.23.25", "169.254.23.26", "169.254.23.27", "169.254.23.28"
    ]

    FW_LOCAL_IP6 = [
        "4000:0000:0000:0000:1601:bd17:0c02:2403", "4000:0000:0000:0000:1601:bd17:0c02:2404",
        "4000:0000:0000:0000:1601:bd17:0c02:2405", "4000:0000:0000:0000:1601:bd17:0c02:2406",
        "4000:0000:0000:0000:1601:bd17:0c02:2407", "4000:0000:0000:0000:1601:bd17:0c02:2408",
        "4000:0000:0000:0000:1601:bd17:0c02:2409", "4000:0000:0000:0000:1601:bd17:0c02:2410",
        "4000:0000:0000:0000:1601:bd17:0c02:2411", "4000:0000:0000:0000:1601:bd17:0c02:2412",
        "4000:0000:0000:0000:1601:bd17:0c02:2413", "4000:0000:0000:0000:1601:bd17:0c02:2414",
        "4000:0000:0000:0000:1601:bd17:0c02:2415", "4000:0000:0000:0000:1601:bd17:0c02:2416",
        "4000:0000:0000:0000:1601:bd17:0c02:2417", "4000:0000:0000:0000:1601:bd17:0c02:2418"
    ]

    FW_REMOTE_IP6 = [
        "4000:0000:0000:0000:1601:bd17:0c02:2503", "4000:0000:0000:0000:1601:bd17:0c02:2504",
        "4000:0000:0000:0000:1601:bd17:0c02:2505", "4000:0000:0000:0000:1601:bd17:0c02:2506",
        "4000:0000:0000:0000:1601:bd17:0c02:2507", "4000:0000:0000:0000:1601:bd17:0c02:2508",
        "4000:0000:0000:0000:1601:bd17:0c02:2509", "4000:0000:0000:0000:1601:bd17:0c02:2510",
        "4000:0000:0000:0000:1601:bd17:0c02:2511", "4000:0000:0000:0000:1601:bd17:0c02:2512",
        "4000:0000:0000:0000:1601:bd17:0c02:2513", "4000:0000:0000:0000:1601:bd17:0c02:2514",
        "4000:0000:0000:0000:1601:bd17:0c02:2515", "4000:0000:0000:0000:1601:bd17:0c02:2516",
        "4000:0000:0000:0000:1601:bd17:0c02:2517", "4000:0000:0000:0000:1601:bd17:0c02:2518"
    ]

    @classmethod
    def setup_class(cls):
        super(TestFWTcpKeepAlive, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", host=cls.dut_hostname,
                                    drv_type=DRV_TYPE_DIAG)
            cls.dut_driver.install()
            cls.atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.fw_config = FirmwareA2Config(cls.atltool_wrapper)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.FW_REMOTE_IP4[0], "255.255.0.0", None)
            cls.lkp_ifconfig.set_ipv6_address(cls.FW_REMOTE_IP6[0], 64, None)
        except Exception:
            log.exception("Failed while setting up class")
            raise

    def setup_method(self, method):
        super(TestFWTcpKeepAlive, self).setup_method(method)
        self.atltool_wrapper.kickstart2()

    def get_wake_counter_on_dut(self, cleanup_fw=False):
        wol_status = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        return wol_status.wakeCount

    def get_wake_reason_on_dut(self):
        wol_status = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        return wol_status.wakeReason

    def gen_probe_ka_pkt(self, off_ka, ipv):
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
        assert pkt[0].dst == off_ka.remote_mac_addr
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
        assert pkt[0].dst == off_ka.remote_mac_addr
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

    @idparametrize("ipv", [4, 6])
    def test_no_answers_small_retry(self, ipv):
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        retry_interval = 1500
        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload
        ka_offload.retry_count = 3
        ka_offload.retry_interval = retry_interval

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = 5
        off_ka_0.local_port = 23
        off_ka_0.remote_port = 22
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 1000
        off_ka_0.seq_num = 2456
        off_ka_0.ack_num = 1212

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        retry_interval_sec = retry_interval / 1000.0
        tmout = off_ka_0.operation_timeout + \
            sum(map(lambda x: retry_interval_sec * pow(2, x), range(ka_offload.retry_count)))
        sniffer = Sniffer(port=self.lkp_port, timeout=tmout, filter="tcp")
        packets = sniffer.run()
        wrpcap("packets.pcap", packets)
        shutil.move("packets.pcap", self.test_log_dir)

        log.info("\n".join(["Sniffed packets:"] + [
            "{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack) for p in packets]))
        assert len(packets) >= 2, "Captured too few packets"

        expected_ka_timings = [
            off_ka_0.operation_timeout + retry_interval_sec * 2 * 2 * 2,
            retry_interval_sec,
            retry_interval_sec * 2,
            retry_interval_sec * 2 * 2
        ]
        log.info("Expected timings: {}".format(", ".join(str(t) for t in expected_ka_timings)))

        first_timing = float(packets[1].time - packets[0].time)
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
            timing = float(packets[i].time - packets[i - 1].time)
            log.info("Timing between {} and {} packets = {}".format(i - 1, i, timing))
            assert abs(expected_ka_timings[start_timing % len(expected_ka_timings)] - timing) < self.EPS
            log.info("Before packet {}: timing = {}, OK".format(i, timing))
            start_timing += 1

    @idparametrize("ipv", [4, 6])
    def test_timeout_with_answers(self, ipv):
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

        timeout = 5  # sec

        assert ipv in [4, 6]

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload
        ka_offload.retry_count = 3
        ka_offload.retry_interval = 2000

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = timeout
        off_ka_0.local_port = 23
        off_ka_0.remote_port = 22
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 1000
        off_ka_0.seq_num = 2456
        off_ka_0.ack_num = 1212

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        def callback(pkt):
            if pkt[1].dst == (off_ka_0.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka_0.remote_ip)):
                ans = self.gen_reply_ka_pkt(pkt)
                sock.send(ans)

        sniffer = Sniffer(port=self.lkp_port, timeout=40, filter="tcp")
        all_packets = sniffer.run(callback=callback, iface=lkp_scapy_iface)[1:]  # throw away first packet
        sock.close()

        wrpcap("packets.pcap", all_packets)
        shutil.move("packets.pcap", self.test_log_dir)

        packets = [pkt for pkt in all_packets if
                   pkt[1].dst == (off_ka_0.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka_0.remote_ip))]

        log.info("\n".join(["ALL packets:"] + [
            "{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack) for p in all_packets]))
        log.info("\n".join(["Sniffed packets:"] + [
            "{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack) for p in packets]))
        assert len(packets) >= 2, "Captured too few packets"

        for i in range(1, len(packets)):
            timing = packets[i].time - packets[i - 1].time
            log.info("Timing between {} and {} packets = {}".format(i - 1, i, timing))
            assert abs(timeout - timing) < self.EPS

        log.info("Checking if all packets have right fields, configured in FW")
        for pkt in packets:
            self.check_pkt_is_fw_probe(pkt, self.DUT_MAC, off_ka_0, ipv), "Packet is not FW's probe"

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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        ka4_offload = sp_cfg.ka4_offload
        ka4_offload.retry_count = 3
        ka4_offload.retry_interval = 2000

        off_ka4_0 = ka4_offload.offloads[0]
        off_ka4_0.operation_timeout = 5
        off_ka4_0.local_port = 22
        off_ka4_0.remote_port = 23
        off_ka4_0.remote_mac_addr = "00:17:b6:33:44:91"
        off_ka4_0.win_size = 1000
        off_ka4_0.seq_num = 1100
        off_ka4_0.ack_num = 1111
        off_ka4_0.local_ip = self.FW_LOCAL_IP4[0]
        off_ka4_0.remote_ip = self.FW_REMOTE_IP4[0]

        off_ka4_1 = ka4_offload.offloads[1]
        off_ka4_1.operation_timeout = 6
        off_ka4_1.local_port = 24
        off_ka4_1.remote_port = 25
        off_ka4_1.remote_mac_addr = "00:17:b6:33:44:92"
        off_ka4_1.win_size = 2000
        off_ka4_1.seq_num = 2200
        off_ka4_1.ack_num = 2222
        off_ka4_1.local_ip = self.FW_LOCAL_IP4[1]
        off_ka4_1.remote_ip = self.FW_REMOTE_IP4[1]

        ka6_offload = sp_cfg.ka6_offload
        ka6_offload.retry_count = 7
        ka6_offload.retry_interval = 2000

        off_ka6_0 = ka6_offload.offloads[0]
        off_ka6_0.operation_timeout = 8
        off_ka6_0.local_port = 26
        off_ka6_0.remote_port = 27
        off_ka6_0.remote_mac_addr = "00:17:b6:33:44:93"
        off_ka6_0.win_size = 3000
        off_ka6_0.seq_num = 3300
        off_ka6_0.ack_num = 3333
        off_ka6_0.local_ip = self.FW_LOCAL_IP6[0]
        off_ka6_0.remote_ip = self.FW_REMOTE_IP6[0]

        off_ka6_1 = ka6_offload.offloads[1]
        off_ka6_1.operation_timeout = 9
        off_ka6_1.local_port = 28
        off_ka6_1.remote_port = 29
        off_ka6_1.remote_mac_addr = "00:17:b6:33:44:94"
        off_ka6_1.win_size = 4000
        off_ka6_1.seq_num = 4400
        off_ka6_1.ack_num = 4444
        off_ka6_1.local_ip = self.FW_LOCAL_IP6[1]
        off_ka6_1.remote_ip = self.FW_REMOTE_IP6[1]

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        sniffer = Sniffer(port=self.lkp_port, timeout=20, filter="tcp")
        packets = sniffer.run()
        wrpcap("packets.pcap", packets)

        log.info("\n".join(["Sniffed packets:"] + [
            "{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack) for p in packets]))
        assert len(packets) >= 2, "Captured too few packets"

        log.info("Searching for 4 different KA types")
        kas_found = []
        for pkt in packets:
            if pkt[0].dst == off_ka4_0.remote_mac_addr:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_probe(pkt, self.DUT_MAC, off_ka4_0, 4), "Packet is not FW's probe"
            elif pkt[0].dst == off_ka4_1.remote_mac_addr:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_probe(pkt, self.DUT_MAC, off_ka4_1, 4), "Packet is not FW's probe"
            elif pkt[0].dst == off_ka6_0.remote_mac_addr:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_probe(pkt, self.DUT_MAC, off_ka6_0, 6), "Packet is not FW's probe"
            elif pkt[0].dst == off_ka6_1.remote_mac_addr:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_probe(pkt, self.DUT_MAC, off_ka6_1, 6), "Packet is not FW's probe"
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload
        ka_offload.retry_count = 3
        ka_offload.retry_interval = 2000

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = timeout
        off_ka_0.local_port = 23
        off_ka_0.remote_port = 22
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 1000
        off_ka_0.seq_num = 2456
        off_ka_0.ack_num = 1212

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        probe_pkt = self.gen_probe_ka_pkt(off_ka_0, ipv)
        log.info("Prepared next probe packet:")
        probe_pkt.show()

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        sniffer = Sniffer(port=self.lkp_port, timeout=20, filter="tcp")
        sniffer.run_async(iface=lkp_scapy_iface)

        for pkt_num in range(5):
            time.sleep(2)
            sock.send(probe_pkt)

        all_packets = sniffer.join()
        sock.close()

        wrpcap("packets.pcap", all_packets)
        shutil.move("packets.pcap", self.test_log_dir)

        packets = [pkt for pkt in all_packets if
                   pkt[1].dst == (off_ka_0.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka_0.remote_ip))]
        wrpcap("packets-filter.pcap", packets)

        log.info("\n".join(["ALL packets:"] + [
            "{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack) for p in all_packets]))
        log.info("\n".join(["Sniffed packets:"] + [
            "{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack) for p in packets]))
        assert len(packets) >= 5, "Captured too few packets"

        log.info("Checking if all packets have right fields, configured in FW")
        for pkt in packets:
            self.check_pkt_is_fw_ack(pkt, self.DUT_MAC, off_ka_0, ipv), "Packet is not FW's ack"

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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        ka4_offload = sp_cfg.ka4_offload
        ka4_offload.retry_count = 3
        ka4_offload.retry_interval = 1000

        off_ka4_0 = ka4_offload.offloads[0]
        off_ka4_0.operation_timeout = 20
        off_ka4_0.local_port = 22
        off_ka4_0.remote_port = 23
        off_ka4_0.remote_mac_addr = "00:17:b6:33:44:91"
        off_ka4_0.win_size = 1000
        off_ka4_0.seq_num = 1100
        off_ka4_0.ack_num = 1111
        off_ka4_0.local_ip = self.FW_LOCAL_IP4[0]
        off_ka4_0.remote_ip = self.FW_REMOTE_IP4[0]

        off_ka4_1 = ka4_offload.offloads[1]
        off_ka4_1.operation_timeout = 22
        off_ka4_1.local_port = 24
        off_ka4_1.remote_port = 25
        off_ka4_1.remote_mac_addr = "00:17:b6:33:44:92"
        off_ka4_1.win_size = 2000
        off_ka4_1.seq_num = 2200
        off_ka4_1.ack_num = 2222
        off_ka4_1.local_ip = self.FW_LOCAL_IP4[1]
        off_ka4_1.remote_ip = self.FW_REMOTE_IP4[1]

        ka6_offload = sp_cfg.ka6_offload
        ka6_offload.retry_count = 3
        ka6_offload.retry_interval = 1000

        off_ka6_0 = ka6_offload.offloads[0]
        off_ka6_0.operation_timeout = 13
        off_ka6_0.local_port = 26
        off_ka6_0.remote_port = 27
        off_ka6_0.remote_mac_addr = "00:17:b6:33:44:93"
        off_ka6_0.win_size = 3000
        off_ka6_0.seq_num = 3300
        off_ka6_0.ack_num = 3333
        off_ka6_0.local_ip = self.FW_LOCAL_IP6[0]
        off_ka6_0.remote_ip = self.FW_REMOTE_IP6[0]

        off_ka6_1 = ka6_offload.offloads[1]
        off_ka6_1.operation_timeout = 14
        off_ka6_1.local_port = 28
        off_ka6_1.remote_port = 29
        off_ka6_1.remote_mac_addr = "00:17:b6:33:44:94"
        off_ka6_1.win_size = 4000
        off_ka6_1.seq_num = 4400
        off_ka6_1.ack_num = 4444
        off_ka6_1.local_ip = self.FW_LOCAL_IP6[1]
        off_ka6_1.remote_ip = self.FW_REMOTE_IP6[1]

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        # =======================================================================

        probe_ka_v4_1 = self.gen_probe_ka_pkt(off_ka4_0, 4)
        probe_ka_v4_2 = self.gen_probe_ka_pkt(off_ka4_1, 4)
        probe_ka_v6_1 = self.gen_probe_ka_pkt(off_ka6_0, 6)
        probe_ka_v6_2 = self.gen_probe_ka_pkt(off_ka6_1, 6)

        log.info("Prepared next probe packets:")
        probe_ka_v4_1.show()
        probe_ka_v4_2.show()
        probe_ka_v6_1.show()
        probe_ka_v6_2.show()

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

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
        shutil.copy("packets.pcap", self.test_log_dir)

        ips = self.FW_REMOTE_IP4 + map(get_compressed_ipv6, self.FW_REMOTE_IP6)
        packets = [pkt for pkt in all_packets if pkt[1].dst in ips]
        wrpcap("packets-filter.pcap", packets)
        shutil.copy("packets-filter.pcap", self.test_log_dir)

        log.info("\n".join(["ALL packets:"] + [
            "{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack) for p in all_packets]))
        log.info("\n".join(["Sniffed packets:"] + [
            "{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack) for p in packets]))
        assert len(packets) >= 4, "Captured too few packets"

        log.info("Searching for 4 different KA types")
        kas_found = []
        for pkt in packets:
            if pkt[0].dst == off_ka4_0.remote_mac_addr:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_ack(pkt, self.DUT_MAC, off_ka4_0, 4), "Packet is not FW's ack"
            elif pkt[0].dst == off_ka4_1.remote_mac_addr:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_ack(pkt, self.DUT_MAC, off_ka4_1, 4), "Packet is not FW's ack"
            elif pkt[0].dst == off_ka6_0.remote_mac_addr:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_ack(pkt, self.DUT_MAC, off_ka6_0, 6), "Packet is not FW's ack"
            elif pkt[0].dst == off_ka6_1.remote_mac_addr:
                if pkt[0].dst not in kas_found:
                    kas_found.append(pkt[0].dst)
                self.check_pkt_is_fw_ack(pkt, self.DUT_MAC, off_ka6_1, 6), "Packet is not FW's ack"
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload
        ka_offload.retry_count = 3
        ka_offload.retry_interval = 2000

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = 20
        off_ka_0.local_port = 545
        off_ka_0.remote_port = 9
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 500
        off_ka_0.seq_num = 11
        off_ka_0.ack_num = 22

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        probe_pkt = self.gen_probe_ka_pkt(off_ka_0, ipv)

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        tmout = PROBE_COUNT * PROBE_INTERVAL + off_ka_0.operation_timeout + \
                (ka_offload.retry_interval / 1000.0 * (1 << (ka_offload.retry_count + 1))) * 2 + 10
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
                   if pkt[1].dst == (off_ka_0.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka_0.remote_ip))]

        wrpcap("packets-filter.pcap", packets)

        log.info("\n".join(["ALL packets:"] + [
            "{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack) for p in all_packets]))
        log.info("\n".join(["Sniffed packets:"] + [
            "{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack) for p in packets]))
        assert len(packets) >= 6, "Captured too few packets"

        actual_timings = [packets[i].time - packets[i - 1].time for i in range(1, len(packets))]
        log.info("Actual timings: {}".format(", ".join(str(t) for t in actual_timings)))

        retry_interval_sec = ka_offload.retry_interval / 1000.0
        expected_ka_timings = [PROBE_INTERVAL] * (PROBE_COUNT - 1)
        expected_ka_timings.append(off_ka_0.operation_timeout)
        expected_ka_timings.extend([retry_interval_sec,
                                    retry_interval_sec * 2,
                                    retry_interval_sec * 2 * 2,
                                    off_ka_0.operation_timeout + retry_interval_sec * 2 * 2 * 2] * 3)
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload
        ka_offload.retry_count = 2
        ka_offload.retry_interval = 1500

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = 10
        off_ka_0.local_port = 22
        off_ka_0.remote_port = 23
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 1000
        off_ka_0.seq_num = 2456
        off_ka_0.ack_num = 1212

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        prev_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        time_to_sleep = off_ka_0.operation_timeout + 1 + \
            ka_offload.retry_interval / 1000.0 * (1 << (ka_offload.retry_count + 1))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        sniffer = Sniffer(port=self.lkp_port, timeout=time_to_sleep, filter="tcp")
        sniffer.run_async(iface=lkp_scapy_iface)

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        # time_to_sleep = off_ka_0.operation_timeout + 1 + \
        #     ka_offload.retry_interval / 1000.0 * (1 << (ka_offload.retry_count + 1))
        log.info("Sleeping {} seconds (timeout + all retry intervals)".format(time_to_sleep))
        time.sleep(time_to_sleep)

        packets = sniffer.join()
        wrpcap("packets.pcap", packets)
        shutil.move("packets.pcap", self.test_log_dir)

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter after test: {}".format(new_wake_counter))

        wake_reason = self.get_wake_reason_on_dut()
        assert new_wake_counter > prev_wake_counter, "Wake counter hasn't been increased; FW didn't wake host"
        log.info("Wake counter has been increased; FW tried wake host")
        assert wake_reason == WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, WAKE_REASON_TCPKA
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        ka4_offload = sp_cfg.ka4_offload
        ka4_offload.retry_count = 2
        ka4_offload.retry_interval = 1500

        off_ka4_0 = ka4_offload.offloads[0]
        off_ka4_0.operation_timeout = 1
        off_ka4_0.local_port = 22
        off_ka4_0.remote_port = 23
        off_ka4_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka4_0.win_size = 1000
        off_ka4_0.seq_num = 1111
        off_ka4_0.ack_num = 1100
        off_ka4_0.local_ip = self.FW_LOCAL_IP4[0]
        off_ka4_0.remote_ip = self.FW_REMOTE_IP4[0]

        off_ka4_1 = ka4_offload.offloads[1]
        off_ka4_1.operation_timeout = 2
        off_ka4_1.local_port = 24
        off_ka4_1.remote_port = 25
        off_ka4_1.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka4_1.win_size = 1000
        off_ka4_1.seq_num = 2222
        off_ka4_1.ack_num = 2200
        off_ka4_1.local_ip = self.FW_LOCAL_IP4[1]
        off_ka4_1.remote_ip = self.FW_REMOTE_IP4[1]

        ka6_offload = sp_cfg.ka6_offload
        ka6_offload.retry_count = 2
        ka6_offload.retry_interval = 1500

        off_ka6_0 = ka6_offload.offloads[0]
        off_ka6_0.operation_timeout = 3
        off_ka6_0.local_port = 26
        off_ka6_0.remote_port = 27
        off_ka6_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka6_0.win_size = 4000
        off_ka6_0.seq_num = 3333
        off_ka6_0.ack_num = 3300
        off_ka6_0.local_ip = self.FW_LOCAL_IP6[0]
        off_ka6_0.remote_ip = self.FW_REMOTE_IP6[0]

        off_ka6_1 = ka6_offload.offloads[1]
        off_ka6_1.operation_timeout = 4
        off_ka6_1.local_port = 28
        off_ka6_1.remote_port = 29
        off_ka6_1.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka6_1.win_size = 4000
        off_ka6_1.seq_num = 4444
        off_ka6_1.ack_num = 4400
        off_ka6_1.local_ip = self.FW_LOCAL_IP6[1]
        off_ka6_1.remote_ip = self.FW_REMOTE_IP6[1]

        prev_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        min_timeout = min(ka_entry.operation_timeout for ka_entry in ka4_offload.offloads + ka6_offload.offloads)
        time_to_sleep = min_timeout + ka4_offload.retry_interval / 1000.0 * (1 << (ka4_offload.retry_count + 1))
        log.info("Sleeping {} seconds (min timeout + all retry intervals)".format(time_to_sleep))
        time.sleep(time_to_sleep)

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter after test: {}".format(new_wake_counter))

        wake_reason = self.get_wake_reason_on_dut()
        assert new_wake_counter > prev_wake_counter, "Wake counter hasn't been increased; FW didn't wake host"
        log.info("Wake counter has been increased; FW tried wake host")
        assert wake_reason == WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, WAKE_REASON_TCPKA
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        ka4_offload = sp_cfg.ka4_offload
        ka4_offload.retry_count = 3
        ka4_offload.retry_interval = 1500

        off_ka4_0 = ka4_offload.offloads[0]
        off_ka4_0.operation_timeout = 1
        off_ka4_0.local_port = 22
        off_ka4_0.remote_port = 23
        off_ka4_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka4_0.win_size = 1000
        off_ka4_0.seq_num = 1111
        off_ka4_0.ack_num = 1100
        off_ka4_0.local_ip = self.FW_LOCAL_IP4[0]
        off_ka4_0.remote_ip = self.FW_REMOTE_IP4[0]

        off_ka4_1 = ka4_offload.offloads[1]
        off_ka4_1.operation_timeout = 2
        off_ka4_1.local_port = 24
        off_ka4_1.remote_port = 25
        off_ka4_1.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka4_1.win_size = 1000
        off_ka4_1.seq_num = 2222
        off_ka4_1.ack_num = 2200
        off_ka4_1.local_ip = self.FW_LOCAL_IP4[1]
        off_ka4_1.remote_ip = self.FW_REMOTE_IP4[1]

        ka6_offload = sp_cfg.ka6_offload
        ka6_offload.retry_count = 3
        ka6_offload.retry_interval = 1500

        off_ka6_0 = ka6_offload.offloads[0]
        off_ka6_0.operation_timeout = 3
        off_ka6_0.local_port = 26
        off_ka6_0.remote_port = 27
        off_ka6_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka6_0.win_size = 4000
        off_ka6_0.seq_num = 3333
        off_ka6_0.ack_num = 3300
        off_ka6_0.local_ip = self.FW_LOCAL_IP6[0]
        off_ka6_0.remote_ip = self.FW_REMOTE_IP6[0]

        off_ka6_1 = ka6_offload.offloads[1]
        off_ka6_1.operation_timeout = 4
        off_ka6_1.local_port = 28
        off_ka6_1.remote_port = 29
        off_ka6_1.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka6_1.win_size = 4000
        off_ka6_1.seq_num = 4444
        off_ka6_1.ack_num = 4400
        off_ka6_1.local_ip = self.FW_LOCAL_IP6[1]
        off_ka6_1.remote_ip = self.FW_REMOTE_IP6[1]

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        def callback(pkt):
            # We answer only on off_ka4_1 and off_ka6_1
            if pkt[1].src == off_ka4_0.local_ip and pkt[1].dst == off_ka4_0.remote_ip:
                return
            if pkt[1].src == off_ka6_0.local_ip and pkt[1].dst == off_ka6_0.remote_ip:
                return

            ans = self.gen_reply_ka_pkt(pkt)
            sock.send(ans)

        # Since we answer on off_ka4_1 and off_ka6_1 only we expect that
        # off_ka4_0 or off_ka6_0 will trigger wakeup
        min_ka_timeout = min([off_ka4_0.operation_timeout, off_ka6_0.operation_timeout])

        fltr = "tcp and ({})".format(" or ".join("dst host {}".format(ka_entry.remote_ip)
                                                 for ka_entry in ka4_offload.offloads + ka6_offload.offloads
                                                 if ka_entry.operation_timeout != 0))
        log.debug("Filter for sniffer: {}".format(fltr))

        # Sniffer timeout: min unanswered KA timeout + all retry intervals
        sniffer_timeout = min_ka_timeout + ka4_offload.retry_interval / 1000.0 * (1 << (ka4_offload.retry_count + 1))
        log.debug("Calculated sniffer timeout: {}".format(sniffer_timeout))

        sniffer = Sniffer(port=self.lkp_port, timeout=sniffer_timeout, filter=fltr)
        sniffer.run(callback=callback, iface=lkp_scapy_iface)
        sock.close()

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter after test: {}".format(new_wake_counter))

        wake_reason = self.get_wake_reason_on_dut()
        assert new_wake_counter > prev_wake_counter, "Wake counter hasn't been increased; FW didn't wake host"
        log.info("Wake counter has been increased; FW tried wake host")
        assert wake_reason == WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, WAKE_REASON_TCPKA
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6
        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload

        ka_offload.retry_count = 3
        ka_offload.retry_interval = 2000

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = 5
        off_ka_0.local_port = 22
        off_ka_0.remote_port = 23
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 1000
        off_ka_0.seq_num = 2456
        off_ka_0.ack_num = 1212

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason_on_dut()
        log.info("Wake reason before test: {}".format(prev_wake_reason))

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        def callback(pkt):
            if pkt[1].dst == (off_ka_0.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka_0.remote_ip)):
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
                   pkt[1].dst == (off_ka_0.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka_0.remote_ip))]

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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        ka4_offload = sp_cfg.ka4_offload
        ka4_offload.retry_count = 3
        ka4_offload.retry_interval = 2000

        off_ka4_0 = ka4_offload.offloads[0]
        off_ka4_0.operation_timeout = 1
        off_ka4_0.local_port = 22
        off_ka4_0.remote_port = 23
        off_ka4_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka4_0.win_size = 1000
        off_ka4_0.seq_num = 1111
        off_ka4_0.ack_num = 1100
        off_ka4_0.local_ip = self.FW_LOCAL_IP4[0]
        off_ka4_0.remote_ip = self.FW_REMOTE_IP4[0]

        off_ka4_1 = ka4_offload.offloads[1]
        off_ka4_1.operation_timeout = 2
        off_ka4_1.local_port = 24
        off_ka4_1.remote_port = 25
        off_ka4_1.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka4_1.win_size = 1000
        off_ka4_1.seq_num = 2222
        off_ka4_1.ack_num = 2200
        off_ka4_1.local_ip = self.FW_LOCAL_IP4[1]
        off_ka4_1.remote_ip = self.FW_REMOTE_IP4[1]

        ka6_offload = sp_cfg.ka6_offload
        ka6_offload.retry_count = 3
        ka6_offload.retry_interval = 2000

        off_ka6_0 = ka6_offload.offloads[0]
        off_ka6_0.operation_timeout = 3
        off_ka6_0.local_port = 26
        off_ka6_0.remote_port = 27
        off_ka6_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka6_0.win_size = 4000
        off_ka6_0.seq_num = 3333
        off_ka6_0.ack_num = 3300
        off_ka6_0.local_ip = self.FW_LOCAL_IP6[0]
        off_ka6_0.remote_ip = self.FW_REMOTE_IP6[0]

        off_ka6_1 = ka6_offload.offloads[1]
        off_ka6_1.operation_timeout = 4
        off_ka6_1.local_port = 28
        off_ka6_1.remote_port = 29
        off_ka6_1.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka6_1.win_size = 4000
        off_ka6_1.seq_num = 4444
        off_ka6_1.ack_num = 4400
        off_ka6_1.local_ip = self.FW_LOCAL_IP6[1]
        off_ka6_1.remote_ip = self.FW_REMOTE_IP6[1]

        prev_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason_on_dut()
        log.info("Wake reason before test: {}".format(prev_wake_reason))

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        ips = [off_ka.remote_ip for off_ka in ka4_offload.offloads if off_ka.operation_timeout != 0] + \
              [get_compressed_ipv6(off_ka.remote_ip) for off_ka in ka6_offload.offloads if off_ka.operation_timeout != 0]

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6
        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload

        ka_offload.retry_count = 3
        ka_offload.retry_interval = 2000

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = 20
        off_ka_0.local_port = 123
        off_ka_0.remote_port = 12
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 2048
        off_ka_0.seq_num = 5000
        off_ka_0.ack_num = 3001

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        probe_pkt = self.gen_probe_ka_pkt(off_ka_0, ipv)
        log.info("Prepared next probe packet:")
        probe_pkt.show()

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason_on_dut()
        log.info("Wake reason before test: {}".format(prev_wake_reason))

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        for pkt_num in range(5):
            sock.send(probe_pkt)
            time.sleep(off_ka_0.operation_timeout / 2)
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6
        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload

        ka_offload.retry_count = 2
        ka_offload.retry_interval = 1500

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = 40
        off_ka_0.local_port = 22
        off_ka_0.remote_port = 23
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 1000
        off_ka_0.seq_num = 2456
        off_ka_0.ack_num = 1212

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        prev_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        fake_probe_pkt = self.gen_probe_ka_pkt(off_ka_0, ipv)
        fake_probe_pkt[2].seq += random.randint(10, 100)

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)
        sock.send(fake_probe_pkt)
        sock.close()

        log.info("Next packet will be used to wake the host:")
        fake_probe_pkt.show()

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter after test: {}".format(new_wake_counter))

        assert new_wake_counter > prev_wake_counter, "Wake counter hasn't been increased; FW didn't wake host"
        log.info("Wake counter has been increased; FW tried wake host")

        wake_reason = self.get_wake_reason_on_dut()
        assert wake_reason == WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, WAKE_REASON_TCPKA
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6
        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload

        ka_offload.retry_count = 2
        ka_offload.retry_interval = 1500

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = 40
        off_ka_0.local_port = 32
        off_ka_0.remote_port = 33
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 2000
        off_ka_0.seq_num = 7456
        off_ka_0.ack_num = 7212

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        prev_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        fake_probe_pkt = self.gen_probe_ka_pkt(off_ka_0, ipv)
        fake_probe_pkt[2].flags = "AP"

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)
        sock.send(fake_probe_pkt)
        sock.close()

        log.info("Next packet will be used to wake the host:")
        fake_probe_pkt.show()

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter after test: {}".format(new_wake_counter))

        assert new_wake_counter > prev_wake_counter, "Wake counter hasn't been increased; FW didn't wake host"
        log.info("Wake counter has been increased; FW tried wake host")

        wake_reason = self.get_wake_reason_on_dut()
        assert wake_reason == WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, WAKE_REASON_TCPKA
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6
        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload

        ka_offload.retry_count = 10  # To make sure FW doesn't stop sending packets to test wake event
        ka_offload.retry_interval = 1500

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = 10
        off_ka_0.local_port = 19
        off_ka_0.remote_port = 20
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 1000
        off_ka_0.seq_num = 2456
        off_ka_0.ack_num = 1212

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        def callback(pkt):
            if pkt[1].dst == (off_ka_0.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka_0.remote_ip)):
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
                   pkt[1].dst == (off_ka_0.remote_ip if ipv == 4 else get_compressed_ipv6(off_ka_0.remote_ip))]

        wrpcap("packets-filter.pcap", packets)

        new_wake_counter = self.get_wake_counter_on_dut()
        log.info("Wake counter after test: {}".format(new_wake_counter))

        assert new_wake_counter > prev_wake_counter, "Wake counter hasn't been increased; FW didn't wake host"
        log.info("Wake counter has been increased; FW tried wake host")
        wake_reason = self.get_wake_reason_on_dut()
        assert wake_reason == WAKE_REASON_TCPKA, "Wake reason mismatch. Current: {}; Expected: {}".format(
            wake_reason, WAKE_REASON_TCPKA
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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6
        ka6_offload = sp_cfg.ka6_offload

        ka6_offload.retry_count = 2
        ka6_offload.retry_interval = 5000

        off_ka6_0 = ka6_offload.offloads[0]
        off_ka6_0.operation_timeout = 20
        off_ka6_0.local_port = 49258
        off_ka6_0.remote_port = 3005
        off_ka6_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka6_0.win_size = 4105
        off_ka6_0.seq_num = 346427013
        off_ka6_0.ack_num = 3436736187
        off_ka6_0.local_ip = self.FW_LOCAL_IP6[0]
        off_ka6_0.remote_ip = self.FW_REMOTE_IP6[0]

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        lkp_scapy_iface = ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        def callback(pkt):
            if pkt.haslayer(TCP) and pkt[1].dst == get_compressed_ipv6(self.FW_REMOTE_IP6[0]):
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

        log.info("\n".join(["Sniffed packets:"] + [
            "{}: {}, seq {}, ack {}".format(p.time, p.summary(), p.seq, p.ack) for p in packets]))
        assert len(packets) >= 1, "Captured too few packets"

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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6
        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload

        ka_offload.retry_count = 10
        ka_offload.retry_interval = 2000

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = 30
        off_ka_0.local_port = 23
        off_ka_0.remote_port = 22
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 1000
        off_ka_0.seq_num = 2456
        off_ka_0.ack_num = 1212

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason_on_dut()
        log.info("Wake reason before test: {}".format(prev_wake_reason))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        pkt = self.gen_probe_ka_pkt(off_ka_0, ipv)
        pkts = [pkt.copy(), pkt.copy()]
        pkts[0][TCP].seq += off_ka_0.win_size + 2
        pkts[1][TCP].seq += off_ka_0.win_size + 100

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

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6
        ka_offload = sp_cfg.ka4_offload if ipv == 4 else sp_cfg.ka6_offload

        ka_offload.retry_count = 10
        ka_offload.retry_interval = 2000

        off_ka_0 = ka_offload.offloads[0]
        off_ka_0.operation_timeout = 30
        off_ka_0.local_port = 23
        off_ka_0.remote_port = 22
        off_ka_0.remote_mac_addr = self.FW_REMOTE_MAC
        off_ka_0.win_size = 1000
        off_ka_0.seq_num = 2456
        off_ka_0.ack_num = 1212

        if ipv == 4:
            off_ka_0.local_ip = self.FW_LOCAL_IP4[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP4[0]
        else:
            off_ka_0.local_ip = self.FW_LOCAL_IP6[0]
            off_ka_0.remote_ip = self.FW_REMOTE_IP6[0]

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC)
        self.lkp_ifconfig.wait_link_up()

        prev_wake_counter = self.get_wake_counter_on_dut(cleanup_fw=True)
        log.info("Wake counter before test: {}".format(prev_wake_counter))
        prev_wake_reason = self.get_wake_reason_on_dut()
        log.info("Wake reason before test: {}".format(prev_wake_reason))

        lkp_scapy_iface = ScapyTools(port=self.lkp_port).get_scapy_iface()
        sock = get_l2_scapy_socket(lkp_scapy_iface)

        pkt = self.gen_probe_ka_pkt(off_ka_0, ipv)
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
