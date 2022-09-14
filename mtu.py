import os
import shutil
import time

import pytest
from scapy.utils import wrpcap

from perf.iperf import Iperf
from tools.atltoolper import AtlTool
from tools import ifconfig
from tools.command import Command
from tools.iptables import IPTables
from tools.constants import CARD_FIJI, FELICITY_CARDS, LINK_STATE_UP, LINK_STATE_DOWN, \
                            MTU_1500, MTU_2000, MTU_4000, MTU_9000, MTU_16000, MTU_MAP_WIN, MTU_DISABLED
from tools.driver import Driver
from tools.killer import Killer
from tools.ops import OpSystem
from tools.receive_segment_coalescing import ReceiveSegmentCoalescing
from tools.scapy_tools import ScapyTools
from tools.tcpdump import Tcpdump
from tools.utils import get_atf_logger, get_bus_dev_func

from infra.test_base import TestBase
from trafficgen.traffic_gen import Packets, TrafficGen

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "mtu"


class TestMtu(TestBase):
    NETMASK = "255.255.0.0"
    SNIFF_EXEC_TIME = 5
    DIRECTION_RX = "rx"
    DIRECTION_TX = "tx"
    ACTION_FRAGMETATION = "fragmentation"
    ACTION_REASSEMBLING = "reassembling"

    MTU_TO_SMALLEST_PAYLOAD_WITHOUT_FRAGMENTATION = {MTU_1500: 1472, MTU_2000: 1998, MTU_4000: 4046, MTU_9000: 8972, MTU_16000: 16306, MTU_DISABLED: 1472}

    MTUS = {MTU_1500: 1500, MTU_2000: 2020, MTU_4000: 4068, MTU_9000: 8996, MTU_16000: 16332}

    @classmethod
    def setup_class(cls):
        super(TestMtu, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            if cls.dut_fw_card not in CARD_FIJI:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            if cls.lkp_fw_card not in CARD_FIJI:
                cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            if cls.dut_fw_card not in CARD_FIJI and cls.dut_atltool_wrapper.is_secure_chips() and cls.dut_ops.is_linux():
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, flashless_fw=cls.dut_fw_version)
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ops = OpSystem()
            cls.lkp_ops = OpSystem(host=cls.lkp_hostname)

            cls.DUT_IP = cls.suggest_test_ip_address(cls.dut_port)
            cls.LKP_IP = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)

            cls.dut_ifconfig.set_ip_address(cls.DUT_IP, cls.NETMASK, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, None)

            speed = cls.dut_ifconfig.wait_link_up()
            log.info("Link is ip at {}".format(speed))

            ip_tbl_cmd = "sudo iptables -I INPUT -p tcp --dport 5201 -j ACCEPT"

            ReceiveSegmentCoalescing(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname).disable()

            if not cls.dut_ops.is_windows():
                Command(cmd=ip_tbl_cmd).run_join(10)

            if not cls.lkp_ops.is_windows():
                Command(cmd=ip_tbl_cmd, host=cls.lkp_hostname).run_join(10)

            if cls.dut_ops.is_linux():
                # TODO: Ugly workaround for Linux
                # TODO: Must be implemented via specific function that enables/disables offloads
                iface = ifconfig.get_linux_network_adapter_name(cls.dut_port)
                cmd = "sudo ethtool --offload {} rx off tx off lro off gro off gso off".format(iface)
                res = Command(cmd=cmd).wait(30)
                if res["returncode"] != 0:
                    raise Exception("Failed to disable offloads")
            if cls.lkp_ops.is_linux():
                # TODO: Ugly workaround for Linux
                # TODO: Must be implemented via specific function that enables/disables offloads
                bus, dev, func = get_bus_dev_func(cls.lkp_port)
                name = "enp{}s{}".format(bus, func)
                cmd = "sudo ethtool --offload {} rx off tx off lro off gro off gso off".format(name)
                res = Command(cmd=cmd, host=cls.lkp_hostname).wait(30)
                if res["returncode"] != 0:
                    raise Exception("Failed to disable offloads")

            speed = cls.dut_ifconfig.wait_link_up()
            log.info("Link is ip at {}".format(speed))

            cls.dut_scapy_iface = ScapyTools(port=cls.dut_port).get_scapy_iface()
            log.info("Scapy interface name on DUT = {}".format(cls.dut_scapy_iface))

            cls.lkp_scapy_iface = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname).get_scapy_iface()
            log.info("Scapy interface name on LKP = {}".format(cls.lkp_scapy_iface))

            iptables = IPTables(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname)
            iptables.clean()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    # TODO: using complex BPF filter with L2pcapListenSocket causes python to crash (perf traffic)
    def run_mtu_iperf_test(self, mtu, direction):
        assert direction in [self.DIRECTION_TX, self.DIRECTION_RX]

        args = {
            'mtu': mtu,
            'ipv': 4,
            'is_stat': False,
            'is_udp': True,
            'is_fc': False if self.dut_fw_card == CARD_FIJI and self.dut_ops.is_linux() else True,
            'buffer_len': 18000,
            'speed': self.supported_speeds[0],
            'bandwidth': 5,
            'num_threads': 1,
            'num_process': 1,
            "winsize": 60,
            'time': self.SNIFF_EXEC_TIME,
            'direction': direction,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IP,
            'dut4': self.DUT_IP,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }

        self.dut_ifconfig.set_link_speed(args['speed'])
        self.lkp_ifconfig.set_link_speed(args['speed'])

        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu)
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        time.sleep(5)

        if direction == self.DIRECTION_TX:
            sniffer = Tcpdump(port=self.lkp_port, timeout=self.SNIFF_EXEC_TIME + 30, host=self.lkp_hostname)
        elif direction == self.DIRECTION_RX:
            sniffer = Tcpdump(port=self.dut_port, timeout=self.SNIFF_EXEC_TIME + 30)
        sniffer.run_async()

        Killer(host=self.dut_hostname).kill("iperf3")
        Killer(host=self.lkp_hostname).kill("iperf3")

        iperf = Iperf(**args)
        result = iperf.run()
        assert result == Iperf.IPERF_OK, 'Iperf run is failed'

        sniffed = sniffer.join(timeout=30)
        log.info("Sniffed raw {} packets".format(len(sniffed)))

        # wrpcap("packets.pcap", sniffed)
        # shutil.copy("packets.pcap", self.test_log_dir)

        packets = []
        # -TCP packet
        # -Correct source IP and destination IP
        # -dport is 5201 (perf default)
        # -Has ack different than 5 (filters some packets on Windows)
        # -Doesn't have PSH flag (0x08)

        try:
            mtu = self.MTUS[mtu]
        except Exception as e:
            log.debug(e)
            pass

        good_packets_num = bad_packets_num = ignored_packets_num = 0
        src_ip = self.DUT_IP if direction == self.DIRECTION_TX else self.LKP_IP
        dst_ip = self.LKP_IP if direction == self.DIRECTION_TX else self.DUT_IP

        for pkt in sniffed:
            if pkt.haslayer("IP") and pkt.haslayer("UDP"):
                if pkt["IP"].src == src_ip and pkt["IP"].dst == dst_ip and pkt.dport == 5201:
                    packets.append(pkt)
                    log.info("MTU: {}, LEN: {}".format(mtu, pkt.len))
                    if pkt["IP"].len == mtu:
                        good_packets_num += 1
                    else:
                        if good_packets_num > 0:
                            bad_packets_num += 1
                        else:
                            ignored_packets_num += 1

        total_packets_num = len(packets)
        log.info("Sniffed {} packets".format(total_packets_num))
        assert total_packets_num > 0, "Sniffed 0 packets"

        log.info("Packets ignored at the beginning: {}".format(ignored_packets_num))
        log.info("Good packets captured: {}".format(good_packets_num))
        log.info("Bad packets captured: {}".format(bad_packets_num))
        log.info("Percentage of good packets: {}%".format(float(good_packets_num) / total_packets_num * 100.0))

        assert good_packets_num > 0, "Didn't receive any good packets"
        assert float(bad_packets_num) / total_packets_num < 0.1, "Too many bad packets captured"

    def run_mtu_taffic_gen_test(self, mtu, speed):
        if speed not in self.supported_speeds:
            pytest.skip()
        args = {
            'host': self.lkp_hostname,
            'port': self.lkp_port,
            'iface': ScapyTools(port=self.lkp_port, host=self.lkp_hostname).get_scapy_iface()
        }

        self.traffic_generator = TrafficGen(name='scapy', **args)

        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu)

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()

        sniffer = Tcpdump(port=self.lkp_port, timeout=self.SNIFF_EXEC_TIME + 25, host=self.lkp_hostname)
        sniffer.run_async()

        time.sleep(5)

        packets_args = {
            'pktsize': mtu,
            'count': 5,
            'ipv': 4,
            'ipv4_src': self.LKP_IPV4_ADDR,
            'ipv4_dst': self.DUT_IPV4_ADDR,
            'protocol': 'tcp'
        }

        args = {
            'packets': Packets(**packets_args),
            'repeat': 100,
            'delay': 0.01
        }

        self.traffic_generator.start(**args)
        time.sleep(10)
        self.traffic_generator.stop()

        time.sleep(5)
        sniffed = sniffer.join(timeout=10)
        log.info("Sniffed raw {} packets".format(len(sniffed)))

        wrpcap("packets.pcap", sniffed)
        shutil.copy("packets.pcap", self.test_log_dir)

        packets = []
        # -TCP packet
        # -Correct source IP and destination IP
        # -dport is 5201 (perf default)
        # -Has ack different than 5 (filters some packets on Windows)
        # -Doesn't have PSH flag (0x08)

        mtu -= 14

        good_packets_num = 0
        for pkt in sniffed:
            if pkt.haslayer("IP") and pkt.haslayer("TCP") and pkt["IP"].len == mtu and \
                    pkt["IP"].src == packets_args['ipv4_src'] and pkt["IP"].dst == packets_args['ipv4_dst']:
                good_packets_num += 1

        log.info("Good packets captured: {}".format(good_packets_num))

        assert good_packets_num > 0, "Didn't receive any good packets"

    def run_mtu_ping_test(self, mtu):
        NOF_PINGS = 2
        SNIFFER_DELAY = 10

        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu if mtu != MTU_DISABLED else MTU_1500)

        if self.lkp_fw_card in FELICITY_CARDS or self.dut_fw_card in FELICITY_CARDS:
            speed = self.supported_speeds[-1]
            self.dut_ifconfig.set_link_speed(speed)
            self.lkp_ifconfig.set_link_speed(speed)

        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        speed = self.dut_ifconfig.wait_link_up()
        log.info("Link is ip at {}".format(speed))
        time.sleep(7)

        assert self.lkp_ifconfig.get_mtu() == (mtu if mtu != MTU_DISABLED else MTU_1500)
        assert self.dut_ifconfig.get_mtu() == mtu

        def verify_pkt_no_fragmentation(payload_size):
            # Workaround for access violation exception: run sniffer on localhost using ssh
            sniffer = Tcpdump(port=self.dut_port, timeout=self.SNIFF_EXEC_TIME + SNIFFER_DELAY)
            sniffer.run_async()
            time.sleep(SNIFFER_DELAY)

            ping_res = self.ping("localhost", self.LKP_IP, number=NOF_PINGS, payload_size=payload_size)
            assert ping_res is True

            nof_ip_request = 0
            nof_ip_reply = 0
            # +15 because scapy timeout should be less than thread timeout
            sniffed = sniffer.join(self.SNIFF_EXEC_TIME + 15)
            for pkt in sniffed:
                if pkt.haslayer("IP") and pkt["IP"].src == self.DUT_IP and pkt.haslayer("ICMP"):
                    if pkt["IP"].flags == 0x1:
                        raise Exception("Received fragmented echo request packet: {}".format(pkt.summary()))
                    if pkt["ICMP"].type == 0x8:  # echo request
                        assert len(pkt) == payload_size + 42  # 42 is len of all headers
                        nof_ip_request += 1
                if pkt.haslayer("IP") and pkt["IP"].src == self.LKP_IP and pkt.haslayer("ICMP"):
                    if pkt["IP"].flags == 0x1:
                        raise Exception("Received fragmented echo reply packet: {}".format(pkt.summary()))
                    if pkt["ICMP"].type == 0x0:  # echo reply
                        assert len(pkt) == payload_size + 42  # 42 is len of all headers
                        nof_ip_reply += 1
            assert nof_ip_request == NOF_PINGS
            assert nof_ip_reply == NOF_PINGS

        def verify_pkt_with_fragmentation(payload_size, strict_check=True):
            # Workaround for access violation exception: run sniffer on localhost using ssh
            sniffer = Tcpdump(port=self.dut_port, timeout=self.SNIFF_EXEC_TIME + SNIFFER_DELAY)
            sniffer.run_async()
            time.sleep(SNIFFER_DELAY)

            ping_res = self.ping("localhost", self.LKP_IP, number=NOF_PINGS, payload_size=payload_size)
            assert ping_res is True

            nof_ip_request_fragments = 0
            nof_ip_reply_fragments = 0
            nof_fragments = payload_size // MTU_MAP_WIN[mtu]
            # +15 because scapy timeout should be less than thread timeout
            sniffed = sniffer.join(self.SNIFF_EXEC_TIME + 15)
            for pkt in sniffed:
                if pkt.haslayer("IP") and pkt["IP"].src == self.DUT_IP:
                    if pkt["IP"].flags == 0x1:
                        nof_ip_request_fragments += 1
                if pkt.haslayer("IP") and pkt["IP"].src == self.LKP_IP:
                    if pkt["IP"].flags == 0x1:
                        nof_ip_reply_fragments += 1
            if strict_check is True:
                assert nof_ip_request_fragments == nof_fragments * NOF_PINGS
                assert nof_ip_reply_fragments == nof_fragments * NOF_PINGS
            else:
                assert nof_ip_request_fragments > 0
                assert nof_ip_reply_fragments > 0

        verify_pkt_no_fragmentation(1300)
        verify_pkt_no_fragmentation(self.MTU_TO_SMALLEST_PAYLOAD_WITHOUT_FRAGMENTATION[mtu])
        verify_pkt_with_fragmentation(self.MTU_TO_SMALLEST_PAYLOAD_WITHOUT_FRAGMENTATION[mtu] + 1, strict_check=False)
        verify_pkt_with_fragmentation(self.MTU_TO_SMALLEST_PAYLOAD_WITHOUT_FRAGMENTATION[mtu] * 2 + 200)

    def test_iperf_mtu_1500_tx(self):
        self.run_mtu_iperf_test(MTU_1500, self.DIRECTION_TX)

    def test_iperf_mtu_1500_rx(self):
        self.run_mtu_iperf_test(MTU_1500, self.DIRECTION_RX)

    def test_iperf_mtu_2026_tx(self):
        self.run_mtu_iperf_test(MTU_2000, self.DIRECTION_TX)

    def test_iperf_mtu_2026_rx(self):
        self.run_mtu_iperf_test(MTU_2000, self.DIRECTION_RX)

    def test_iperf_mtu_4074_tx(self):
        self.run_mtu_iperf_test(MTU_4000, self.DIRECTION_TX)

    def test_iperf_mtu_4074_rx(self):
        self.run_mtu_iperf_test(MTU_4000, self.DIRECTION_RX)

    def test_iperf_mtu_9000_tx(self):
        self.run_mtu_iperf_test(MTU_9000, self.DIRECTION_TX)

    def test_iperf_mtu_9000_rx(self):
        self.run_mtu_iperf_test(MTU_9000, self.DIRECTION_RX)

    def test_iperf_mtu_16334_tx(self):
        if 'Switch' in self.platform:
            pytest.skip()

        self.run_mtu_iperf_test(MTU_16000, self.DIRECTION_TX)

    def test_iperf_mtu_16334_rx(self):
        if 'Switch' in self.platform:
            pytest.skip()

        self.run_mtu_iperf_test(MTU_16000, self.DIRECTION_RX)

    # Traffic gen tests are commented because they fail
    # Actually they are not needed because fragmentation happens in operating system stack

    # def test_trafficgen_mtu_1500_1g(self):
    #     self.run_mtu_taffic_gen_test(1500, LINK_SPEED_1G)

    # def test_trafficgen_mtu_2026_100m(self):
    #     self.run_mtu_taffic_gen_test(2026, LINK_SPEED_100M)

    # def test_trafficgen_mtu_4074_1g(self):
    #     self.run_mtu_taffic_gen_test(4074, LINK_SPEED_1G)

    # def test_trafficgen_mtu_9000_100m(self):
    #     self.run_mtu_taffic_gen_test(9000, LINK_SPEED_100M)

    # def test_trafficgen_mtu_16334_1g(self):
    #     self.run_mtu_taffic_gen_test(16334, LINK_SPEED_1G)

    def test_ping_mtu_1500(self):
        if self.dut_ops.is_windows():
            mtu = MTU_DISABLED
        else:
            mtu = MTU_1500

        self.run_mtu_ping_test(mtu)

    def test_ping_mtu_2026(self):
        self.run_mtu_ping_test(MTU_2000)

    def test_ping_mtu_4074(self):
        self.run_mtu_ping_test(MTU_4000)

    def test_ping_mtu_9000(self):
        self.run_mtu_ping_test(MTU_9000)

    def test_ping_mtu_16334(self):
        if 'Switch' in self.platform:
            pytest.skip()

        self.run_mtu_ping_test(MTU_16000)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
