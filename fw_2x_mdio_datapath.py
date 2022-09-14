"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import copy
import os
import random
import struct
import time
import timeit

import pytest
import shutil

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_NO_LINK, FELICITY_CARDS, \
    LINK_STATE_UP, LINK_STATE_DOWN, MTU_1500, MTU_9000
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvMessage, DrvEthConfig, OffloadIpInfo, OffloadRrInfo, MdnsRr
from tools.trafficgen import TrafficStream, TrafficGenerator
from tools.samba import Samba
from tools.utils import get_atf_logger

from infra.test_base import TestBase

from tools.lom import LightsOutManagement

# import order is important, sometimes stdout is not producing though script works
from scapy.all import Ether, IP, ICMP, Raw, RandString, UDP, ARP

log = get_atf_logger()

def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_sleep_crash"


class TestFw2xMdioDatapath(TestBase):
    AFTER_LINK_UP_DELAY = 5
    DUT_IP4s = ["17.224.15.228"]
    LKP_IP4 = "17.224.15.100"
    TRAFFIC_TEST_ARGS_TEMPLATE = {
        "l2": {"nof": 0, "min_size": 64, "max_size": 120},
        "icmp": {"nof": 0, "min_size": 64, "max_size": 120},
        "arp": {"nof": 0, "min_size": 64, "max_size": 120},
        "udp": {"nof": 0, "min_size": 64, "max_size": 120}
    }
    DEFAULT_FLOOD_TIME = 300

    @classmethod
    def setup_class(cls):
        super(TestFw2xMdioDatapath, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest", host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4, cls.DEFAULT_NETMASK_IPV4, None)

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port)

            cls.dut_mac = cls.dut_atltool_wrapper.get_mac_address()
            cls.lkp_mac = cls.lkp_atltool_wrapper.get_mac_address()

            # Disable Samba to remove background multicast traffic which affects SerDes
            Samba(host=cls.lkp_hostname).stop()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestFw2xMdioDatapath, cls).teardown_class()

    def setup_method(self, method):
        super(TestFw2xMdioDatapath, self).setup_method(method)
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)

        self.dut_atltool_wrapper.debug_buffer_enable(True)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            mdio_value = self.LOM_ctrl.read_data(self.LOM_ctrl.LOM_OFFSET_LOM_STATUS, 1)[0]
            if os.environ.get("LOM_MDIO_MODE", None):
                mdio_value = mdio_value | 0x20
            else:
                mdio_value = mdio_value & 0xDF
            self.LOM_ctrl.write_data(self.LOM_ctrl.LOM_OFFSET_LOM_STATUS, [mdio_value], 1)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestFw2xMdioDatapath, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        # Save MCP log from DUT
        self.dut_bin_log_file, self.dut_txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(False)
        shutil.copy(self.dut_bin_log_file, self.test_log_dir)
        shutil.copy(self.dut_txt_log_file, self.test_log_dir)

        # Dump PHY DRAM from DUT
        with open(os.path.join(self.test_log_dir, "phy_dram.bin"), "wb") as bf:
            phy_dram = self.dut_atltool_wrapper.read_phy_dram()
            for val in phy_dram:
                bf.write(struct.pack("I", val))

        if self.MCP_LOG:
            self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

    def configure_sleep_proxy_on_dut(self, tcpka=False, mdns=False):
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407
        cfg.mac = self.dut_mac
        cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WOL

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = 0  # not used by FW
        cfg.ips.v4_addresses = self.DUT_IP4s
        cfg.ips.v4_masks = [24] * len(self.DUT_IP4s)

        cfg.ips.v6_addr_count = 0  # not used by FW
        cfg.ips.v6_addresses = []
        cfg.ips.v6_masks = []

        if mdns:
            cfg.rrs = OffloadRrInfo()

            rec = MdnsRr.get_drv_iface_txt_rr("iMac._smb._tcp.local", "random_text")
            cfg.rrs.entries.append(rec)

            rec = MdnsRr.get_drv_iface_ptr_rr("_smb._tcp.local", "iMac._smb._tcp.local")
            cfg.rrs.entries.append(rec)

            rec = MdnsRr.get_drv_iface_srv_rr("iMac._smb._tcp.local", "IAmMac.local", port=8787)
            cfg.rrs.entries.append(rec)

        beton_file = os.path.join(self.test_log_dir, "offload.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

    def create_l2_packet(self, traffic_args):
        size = random.randint(traffic_args["l2"]["min_size"], traffic_args["l2"]["max_size"])
        l2 = Ether(dst=self.dut_mac, src=self.lkp_mac)
        raw = Raw(RandString(size - len(l2)))

        pkt = l2 / raw
        return pkt

    def create_icmp_packet(self, traffic_args):
        size = random.randint(traffic_args["icmp"]["min_size"], traffic_args["icmp"]["max_size"])
        l2 = Ether(dst=self.dut_mac, src=self.lkp_mac)
        l3 = IP(dst=self.DUT_IP4s[0], src=self.LKP_IP4)
        l4 = ICMP()
        raw = Raw(RandString(size - len(l2 / l3 / l4)))

        pkt = l2 / l3 / l4 / raw
        return pkt

    def create_arp_packet(self, traffic_args):
        l2 = Ether(dst=self.dut_mac, src=self.lkp_mac)
        l3 = ARP(pdst=self.DUT_IP4s[0], psrc=self.LKP_IP4, hwsrc=l2.src)

        pkt = l2 / l3
        return pkt

    def create_udp_packet(self, traffic_args):
        size = random.randint(traffic_args["udp"]["min_size"], traffic_args["udp"]["max_size"])
        l2 = Ether(dst=self.dut_mac, src=self.lkp_mac)
        l3 = IP(dst=self.DUT_IP4s[0], src=self.LKP_IP4)
        l4 = UDP()
        raw = Raw(RandString(size - len(l2 / l3 / l4)))

        pkt = l2 / l3 / l4 / raw
        return pkt

    def prepare_test(self, speed, mtu):
        self.lkp_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_link_speed(speed)
        self.configure_sleep_proxy_on_dut()
        assert self.lkp_ifconfig.wait_link_up() == speed

    def run_traffic_test(self, speed, mtu, duration, traffic_args):
        self.prepare_test(speed, mtu)

        pkts = []

        for i in range(traffic_args["l2"]["nof"]):
            pkts.append(self.create_l2_packet(traffic_args))

        for i in range(traffic_args["icmp"]["nof"]):
            pkts.append(self.create_icmp_packet(traffic_args))

        for i in range(traffic_args["arp"]["nof"]):
            pkts.append(self.create_arp_packet(traffic_args))

        stream = TrafficStream()
        stream.type = TrafficStream.STREAM_TYPE_FLOOD
        stream.duration = duration
        stream.delay = 0.0001
        stream.packets = pkts

        generator = TrafficGenerator(port=self.lkp_port)
        generator.add_stream(stream)
        generator.run()

        self.check_fail_criteria(speed)

    def run_fragmentation_test(self, speed, mtu, size):
        self.prepare_test(speed, mtu)

        # Ping using requested packet size
        self.ping(None, self.DUT_IP4s[0], 32, ipv6=False, src_addr=self.LKP_IP4, payload_size=size - 46)
        self.check_fail_criteria(speed)

    def check_serdes_status(self, expected_statuses):
        serdes_status = self.dut_atltool_wrapper.readphyreg(0x4, 0xE812)
        msg = "PHY register 0x4.0xE812 == {} (expected == {})".format(hex(serdes_status),
                                                                      [hex(status) for status in expected_statuses])
        assert serdes_status in expected_statuses, "SerDes status is incorrect: {}".format(msg)
        log.info("SerDes status is OK: {}".format(msg))

    def check_fail_criteria(self, speed):
        log.info("Dumping PHY heartbeat:")
        self.dut_atltool_wrapper.exec_beton(["readphyreg 0x1e.0xc886", "pause 2 s", "readphyreg 0x1e.0xc886"])

        log.info("Sleep 5 seconds to avoid SERDES up/down events")
        time.sleep(5)

        log.info("Getting head/tail pointers on DUT")
        reg_1c416 = self.dut_atltool_wrapper.readphyreg(0x1, 0xc416)
        reg_1c417 = self.dut_atltool_wrapper.readphyreg(0x1, 0xc417)

        assert self.dut_atltool_wrapper.readreg(0x354) == 0, "Invalid packet length reproduced"

        # Check that link is still up
        if speed != LINK_SPEED_AUTO:
            assert speed == self.lkp_ifconfig.get_link_speed(), "Link is not UP after test"
        else:
            assert self.lkp_ifconfig.get_link_speed() != LINK_SPEED_NO_LINK, "Link is not UP after test"

        if speed != LINK_SPEED_100M:
            # For link speed 1G and above MDIO datapath should be disabled so we check that tail and head are zero
            log.info("Checking that head/tail pointers are no moving")
            assert reg_1c416 == 0, "Head pointer is moving, but should not"
            assert reg_1c417 == 0, "Tail pointer is moving, but should not"

        log.info("Pinging DUT using standard ping")
        ping_result = self.ping(None, self.DUT_IP4s[0], 32, ipv6=False, src_addr=self.LKP_IP4)
        if speed == LINK_SPEED_100M:
            log.info("Checking that head/tail pointers are moved to new positions after ping")
            assert reg_1c416 != self.dut_atltool_wrapper.readphyreg(0x1, 0xc416), "RX stuck reproduced"
            assert reg_1c417 != self.dut_atltool_wrapper.readphyreg(0x1, 0xc417), "RX stuck reproduced"
        assert ping_result is True, "RX stuck reproduced"

    def test_huge_rx_low_tx_small_packets_100m(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nof": 50, "min_size": 64, "max_size": 120}
        self.run_traffic_test(LINK_SPEED_100M, MTU_1500, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_huge_rx_low_tx_small_packets_1g(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nof": 50, "min_size": 64, "max_size": 120}
        self.run_traffic_test(LINK_SPEED_1G, MTU_1500, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_huge_rx_normal_tx_small_packets_100m(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nof": 50, "min_size": 64, "max_size": 120}
        traffic_args["arp"] = {"nof": 50, "min_size": 64, "max_size": 120}
        traffic_args["icmp"] = {"nof": 50, "min_size": 64, "max_size": 120}
        traffic_args["udp"] = {"nof": 50, "min_size": 64, "max_size": 120}
        self.run_traffic_test(LINK_SPEED_100M, MTU_1500, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_huge_rx_normal_tx_small_packets_1g(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nof": 50, "min_size": 64, "max_size": 120}
        traffic_args["arp"] = {"nof": 50, "min_size": 64, "max_size": 120}
        traffic_args["icmp"] = {"nof": 50, "min_size": 64, "max_size": 120}
        traffic_args["udp"] = {"nof": 50, "min_size": 64, "max_size": 120}
        self.run_traffic_test(LINK_SPEED_1G, MTU_1500, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_huge_rx_normal_tx_normal_packets_100m(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nof": 50, "min_size": 200, "max_size": 1400}
        traffic_args["arp"] = {"nof": 50, "min_size": 200, "max_size": 1400}
        traffic_args["icmp"] = {"nof": 50, "min_size": 200, "max_size": 1400}
        traffic_args["udp"] = {"nof": 50, "min_size": 200, "max_size": 1400}
        self.run_traffic_test(LINK_SPEED_100M, MTU_1500, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_huge_rx_normal_tx_normal_packets_1g(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nof": 50, "min_size": 200, "max_size": 1400}
        traffic_args["arp"] = {"nof": 50, "min_size": 200, "max_size": 1400}
        traffic_args["icmp"] = {"nof": 50, "min_size": 200, "max_size": 1400}
        traffic_args["udp"] = {"nof": 50, "min_size": 200, "max_size": 1400}
        self.run_traffic_test(LINK_SPEED_1G, MTU_1500, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_huge_rx_normal_tx_big_packets_100m(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nof": 50, "min_size": 450, "max_size": 2900}
        traffic_args["arp"] = {"nof": 50, "min_size": 450, "max_size": 2900}
        traffic_args["icmp"] = {"nof": 50, "min_size": 450, "max_size": 2900}
        traffic_args["udp`"] = {"nof": 50, "min_size": 450, "max_size": 2900}
        self.run_traffic_test(LINK_SPEED_100M, MTU_9000, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_huge_rx_normal_tx_big_packets_1g(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nof": 50, "min_size": 450, "max_size": 2900}
        traffic_args["arp"] = {"nof": 50, "min_size": 450, "max_size": 2900}
        traffic_args["icmp"] = {"nof": 50, "min_size": 450, "max_size": 2900}
        traffic_args["udp"] = {"nof": 50, "min_size": 450, "max_size": 2900}
        self.run_traffic_test(LINK_SPEED_1G, MTU_9000, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_huge_rx_normal_tx_oversize_packets_100m(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nof": 50, "min_size": 2900, "max_size": 3500}
        traffic_args["arp"] = {"nof": 50, "min_size": 2900, "max_size": 3500}
        traffic_args["icmp"] = {"nof": 50, "min_size": 2900, "max_size": 3500}
        self.run_traffic_test(LINK_SPEED_100M, MTU_9000, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_huge_rx_normal_tx_oversize_packets_1g(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nof": 50, "min_size": 2900, "max_size": 3500}
        traffic_args["arp"] = {"nof": 50, "min_size": 2900, "max_size": 3500}
        traffic_args["icmp"] = {"nof": 50, "min_size": 2900, "max_size": 3500}
        traffic_args["udp"] = {"nof": 50, "min_size": 2900, "max_size": 3500}
        self.run_traffic_test(LINK_SPEED_1G, MTU_9000, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_fragmentation_small_size(self):
        self.run_fragmentation_test(LINK_SPEED_100M, MTU_1500, 70)

    def test_fragmentation_medium_size(self):
        self.run_fragmentation_test(LINK_SPEED_100M, 300, 650)

    def test_fragmentation_big_size(self):
        self.run_fragmentation_test(LINK_SPEED_100M, MTU_1500, 2000)

    def test_fragmentation_oversize(self):
        self.run_fragmentation_test(LINK_SPEED_100M, MTU_1500, 3100)

    def test_serdes_flapping(self):
        self.prepare_test(LINK_SPEED_100M, MTU_1500)

        icmp_pkt = self.create_icmp_packet({"icmp": {"min_size": 70, "max_size": 70}})
        stream = TrafficStream()
        stream.nof_packets = 120
        stream.rate = 20
        stream.type = TrafficStream.STREAM_TYPE_CONTINUOUS
        stream.packets = [icmp_pkt]

        generator = TrafficGenerator(port=self.lkp_port)
        generator.add_stream(stream)

        exec_time = 10 * 60
        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time < exec_time:
            generator.run()
            self.ping(None, self.DUT_IP4s[0], 1, ipv6=False, src_addr=self.LKP_IP4, payload_size=650 - 46)

        self.check_fail_criteria(LINK_SPEED_100M)

    def test_huge_rx_huge_tx_normal_size(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["icmp"] = {"nof": 50, "min_size": 64, "max_size": 100}
        traffic_args["arp"] = {"nof": 50, "min_size": 64, "max_size": 100}
        self.run_traffic_test(LINK_SPEED_100M, MTU_1500, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_huge_rx_huge_tx_different_size(self):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["icmp"] = {"nof": 50, "min_size": 150, "max_size": 1400}
        traffic_args["arp"] = {"nof": 50, "min_size": 150, "max_size": 1400}
        self.run_traffic_test(LINK_SPEED_100M, MTU_1500, self.DEFAULT_FLOOD_TIME, traffic_args)

    def test_link_down_when_serdes_up(self):
        self.prepare_test(LINK_SPEED_100M, MTU_1500)
        log.info("Sleeping 15 seconds to make sure that SERDES is down")
        time.sleep(15)
        for i in range(10):
            log.info("Checking SerDes is turned off")
            self.check_serdes_status([0x2048, 0x48])
            self.ping(None, self.DUT_IP4s[0], 1, ipv6=False, src_addr=self.LKP_IP4, payload_size=650 - 46)
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            time.sleep(3)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            assert self.lkp_ifconfig.wait_link_up() == LINK_SPEED_100M
            self.check_fail_criteria(LINK_SPEED_100M)

    def test_silence(self):
        self.prepare_test(LINK_SPEED_100M, MTU_1500)
        log.info("Sleeping 15 seconds to make sure that SERDES is down")
        time.sleep(15)
        log.info("Checking SerDes is turned off")
        self.check_serdes_status([0x2048, 0x48])
        for i in range(10):
            time.sleep(10)
            self.ping(None, self.DUT_IP4s[0], 1, ipv6=False, src_addr=self.LKP_IP4, payload_size=650 - 46)
            time.sleep(10)
            assert self.ping(None, self.DUT_IP4s[0], 1, ipv6=False, src_addr=self.LKP_IP4) is True

    def test_fast_buffer_overlap(self):
        self.prepare_test(LINK_SPEED_100M, MTU_1500)

        pkts = []
        for i in range(29):
            pkts.append(self.create_l2_packet({"l2": {"min_size": 100, "max_size": 100}}))
        pkts.append(self.create_l2_packet({"l2": {"min_size": 180, "max_size": 180}}))

        stream = TrafficStream()
        stream.duration = 180
        stream.delay = 0.0001
        stream.type = TrafficStream.STREAM_TYPE_FLOOD
        stream.packets = pkts

        generator = TrafficGenerator(port=self.lkp_port)
        generator.add_stream(stream)
        generator.run()

        self.check_fail_criteria(LINK_SPEED_100M)

    def test_traffic_pulse_storm(self):
        exec_time = 3 * 60
        self.prepare_test(LINK_SPEED_100M, MTU_1500)

        pkts = []
        for i in range(10):
            pkts.append(self.create_l2_packet({"l2": {"min_size": 150, "max_size": 1000}}))
        for i in range(10):
            pkts.append(self.create_icmp_packet({"icmp": {"min_size": 150, "max_size": 1000}}))
        for i in range(10):
            pkts.append(self.create_arp_packet({"arp": {"min_size": 150, "max_size": 1000}}))
        for i in range(10):
            pkts.append(self.create_udp_packet({"udp": {"min_size": 150, "max_size": 1000}}))

        stream = TrafficStream()
        stream.type = TrafficStream.STREAM_TYPE_BURST
        stream.packets = pkts

        generator = TrafficGenerator(port=self.lkp_port)
        generator.add_stream(stream)

        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time < exec_time:
            generator.run()
            time.sleep(10)
        self.check_fail_criteria(LINK_SPEED_100M)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
