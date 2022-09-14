"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import copy
import os
import random
import time
import pytest
import sys
import timeit


sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from infra.test_base import idparametrize, TestBase
from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_100M, \
    LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, FELICITY_CARDS, \
    MTU_1500, MTU_2000, MTU_4000, MTU_9000, MTU_16000, LINK_STATE_UP, LINK_STATE_DOWN, \
    KNOWN_LINK_SPEEDS, MTUS
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.utils import get_atf_logger
from tools.ping import ping
from tools.scapy_tools import ScapyTools
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config

# import order is important, sometimes stdout is not producing though script works
from scapy.all import Ether, IP, ICMP, Raw, RandString, UDP, ARP
from tools.aqpkt import Aqsendp, scapy_pkt_to_aqsendp_str

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_datapath"


class TestA2FwDatapath(TestBase):
    AFTER_LINK_UP_DELAY = 5
    TRAFFIC_TEST_ARGS_TEMPLATE = {
        "l2": {"nos": 0, "min_size": 64, "max_size": 120},
        "icmp": {"nos": 0, "min_size": 64, "max_size": 120},
        "arp": {"nos": 0, "min_size": 64, "max_size": 120},
        "udp": {"nos": 0, "min_size": 64, "max_size": 120}
    }
    DEFAULT_FLOOD_TIME = 300
    DUT_IP = "192.168.0.1"
    LKP_IP = "192.168.0.2"
    NETMASK = "255.255.255.0"

    @classmethod
    def setup_class(cls):
        cls.security = True
        super(TestA2FwDatapath, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            # Set up DUT
            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname,
                                    drv_type=DRV_TYPE_DIAG)
            cls.dut_driver.install()
            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.fw_config = FirmwareA2Config(cls.atltool_wrapper)

            # Set up LKP
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, None)
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestA2FwDatapath, cls).teardown_class()

    def setup_method(self, method):
        super(TestA2FwDatapath, self).setup_method(method)
        self.atltool_wrapper.kickstart2()

    def teardown_method(self, method):
        super(TestA2FwDatapath, self).teardown_method(method)

    def establish_link_speed(self, link_speed):
        # self.dut_ifconfig.set_link_speed(link_speed)
        self.lkp_ifconfig.set_link_speed(link_speed)
        # self.dut_ifconfig.set_ip_address(self.DUT_IP, self.NETMASK, None)
        self.lkp_ifconfig.set_ip_address(self.LKP_IP, self.NETMASK, None)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        # self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        # self.dut_ifconfig.wait_link_up()

    def create_l2_packet(self, traffic_args):
        size = random.randint(traffic_args["l2"]["min_size"], traffic_args["l2"]["max_size"])
        l2 = Ether(dst=self.dut_mac, src=self.lkp_mac)
        raw = Raw(RandString(size - len(l2)))

        pkt = l2 / raw
        return pkt

    def create_icmp_packet(self, traffic_args):
        size = random.randint(traffic_args["icmp"]["min_size"], traffic_args["icmp"]["max_size"])
        l2 = Ether(dst=self.dut_mac, src=self.lkp_mac)
        l3 = IP(dst=self.DUT_IP, src=self.LKP_IP)
        l4 = ICMP()
        raw = Raw(RandString(size - len(l2 / l3 / l4)))

        pkt = l2 / l3 / l4 / raw
        return pkt

    def create_arp_packet(self, traffic_args):
        l2 = Ether(dst=self.dut_mac, src=self.lkp_mac)
        l3 = ARP(pdst=self.DUT_IP, psrc=self.LKP_IP, hwsrc=l2.src)

        pkt = l2 / l3
        return pkt

    def create_udp_packet(self, traffic_args):
        size = random.randint(traffic_args["udp"]["min_size"], traffic_args["udp"]["max_size"])
        l2 = Ether(dst=self.dut_mac, src=self.lkp_mac)
        l3 = IP(dst=self.DUT_IP, src=self.LKP_IP)
        l4 = UDP()
        raw = Raw(RandString(size - len(l2 / l3 / l4)))

        pkt = l2 / l3 / l4 / raw
        return pkt

    def send_packets_async(self, time_limit, send_rate, hostname, pkt):
        pkt_data = scapy_pkt_to_aqsendp_str(pkt)
        aqsendp = Aqsendp(timeout=time_limit, rate=send_rate, host=hostname, packet=pkt_data)
        aqsendp.run_async()

    def check_fail_criteria(self, speed):
        # Check heartbeats
        mac_heart_beat_1 = self.fw_config. \
            read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.macHealthMonitor.macHeartBeat")
        phy_heart_beat_1 = self.fw_config. \
            read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.phyHealthMonitor.phyHeartBeat")
        time.sleep(2)
        mac_heart_beat_2 = self.fw_config. \
            read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.macHealthMonitor.macHeartBeat")
        phy_heart_beat_2 = self.fw_config. \
            read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.phyHealthMonitor.phyHeartBeat")
        assert mac_heart_beat_2 > mac_heart_beat_1, "MAC heart beat is not ticking"
        assert phy_heart_beat_2 > phy_heart_beat_1, "PHY heart beat is not ticking"

        # Check that link is still up
        assert self.lkp_ifconfig.get_link_speed() == speed, \
            'LKP link speed was changed from {} to {}'.format(speed, self.lkp_ifconfig.get_link_speed())
        assert self.fw_config.get_fw_link_speed() == speed, \
            'DUT link speed was changed from {} to {}'.format(speed, self.fw_config.get_fw_link_speed())

        # Check by ping
        log.info("Pinging DUT using standard ping")
        assert ping(number=1, host=self.LKP_IP, src_addr=self.DUT_IP), 'After test ping check failed'

    def prepare_test(self, speed, mtu):
        if speed not in self.supported_speeds:
            pytest.skip("Not supported speed")

        self.establish_link_speed(speed)
        self.lkp_ifconfig.set_mtu(mtu)

        assert self.lkp_ifconfig.get_link_speed() == speed, \
            'LKP link speed set at wrong rate {} instead of {}'.format(self.lkp_ifconfig.get_link_speed(), speed)
        # assert self.fw_config.get_fw_link_speed() == speed, \
            # 'DUT link speed set at wrong rate {} instead of {}'.format(self.dut_ifconfig.get_link_speed(), speed)
        log.info("Pinging DUT using standard ping")
        assert ping(number=1, host=self.LKP_IP, src_addr=self.DUT_IP), 'Before test ping check failed'

    def prepare_packets(self, traffic_args):
        pkts = []

        for i in range(traffic_args["l2"]["nos"]):
            pkts.append(self.create_l2_packet(traffic_args))

        for i in range(traffic_args["icmp"]["nos"]):
            pkts.append(self.create_icmp_packet(traffic_args))

        for i in range(traffic_args["arp"]["nos"]):
            pkts.append(self.create_arp_packet(traffic_args))

        return pkts

    def run_traffic_test(self, speed, mtu, duration, traffic_args):
        self.prepare_test(speed, mtu)
        pkts = []
        pkts = self.prepare_packets(traffic_args)

        for p in pkts:
            self.send_packets_async(time_limit=duration, send_rate=1000, hostname=self.lkp_hostname, pkt=p)

        log.info('Awaiting traffic')
        time.sleep(duration)
        log.info('Traffic sent')
        self.check_fail_criteria(speed)

    def run_fragmentation_test(self, speed, mtu, size):
        self.prepare_test(speed, mtu)

        # Ping using requested packet size
        self.ping(None, self.DUT_IP, 32, ipv6=False, src_addr=self.LKP_IP4, payload_size=size - 46)
        self.check_fail_criteria(speed)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    @idparametrize("mtu", MTUS)
    @idparametrize("pkt_sizes", [[64, 120], [64, 1400], [64, 8900], [600, 1400], [600, 8900], [6000, 8900]])
    def test_mix_rx_various_packets(self, speed, mtu, pkt_sizes):
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nos": 50, "min_size": pkt_sizes[0], "max_size": pkt_sizes[1]}
        traffic_args["arp"] = {"nos": 50, "min_size": pkt_sizes[0], "max_size": pkt_sizes[1]}
        traffic_args["icmp"] = {"nos": 50, "min_size": pkt_sizes[0], "max_size": pkt_sizes[1]}
        traffic_args["udp"] = {"nos": 50, "min_size": pkt_sizes[0], "max_size": pkt_sizes[1]}
        self.run_traffic_test(speed, mtu, self.DEFAULT_FLOOD_TIME, traffic_args)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    @idparametrize("mtu", [MTU_1500])
    @idparametrize("pkt_size", [70, 650, 2000, 3100])
    def test_fragmentation_small_size(self, speed, mtu, pkt_size):
        self.run_fragmentation_test(speed, mtu, pkt_size)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_serdes_flapping(self, speed):
        self.prepare_test(speed, MTU_1500)

        pkts = []
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["icmp"] = {"nos": 120, "min_size": 70, "max_size": 70}
        pkts = self.prepare_packets(traffic_args)

        exec_time = 10 * 60
        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time < exec_time:
            for p in pkts:
                self.send_packets_async(time_limit=10, send_rate=1000, hostname=self.lkp_hostname, pkt=p)
            self.ping(None, self.DUT_IP, 1, ipv6=False, src_addr=self.LKP_IP, payload_size=650 - 46)

        self.check_fail_criteria(speed)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_fast_buffer_overlap(self, speed):
        self.prepare_test(speed, MTU_1500)

        pkts = []
        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nos": 29, "min_size": 100, "max_size": 100}
        pkts = self.prepare_packets(traffic_args)
        traffic_args["l2"] = {"nos": 1, "min_size": 180, "max_size": 180}
        pkts.append(self.prepare_packets(traffic_args)[0])

        for p in pkts:
            self.send_packets_async(180, 10000, self.lkp_hostname, p)

        self.check_fail_criteria(speed)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_traffic_pulse_storm(self, speed):
        exec_time = 3 * 60
        self.prepare_test(speed, MTU_1500)

        traffic_args = copy.deepcopy(self.TRAFFIC_TEST_ARGS_TEMPLATE)
        traffic_args["l2"] = {"nos": 10, "min_size": 150, "max_size": 1000}
        traffic_args["arp"] = {"nos": 10, "min_size": 150, "max_size": 1000}
        traffic_args["icmp"] = {"nos": 10, "min_size": 150, "max_size": 1000}
        traffic_args["udp"] = {"nos": 10, "min_size": 150, "max_size": 1000}

        pkts = []
        pkts = self.prepare_packets(traffic_args)

        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time < exec_time:
            for p in pkts:
                self.send_packets_async(time_limit=10, send_rate=1000, hostname=self.lkp_hostname, pkt=p)
            time.sleep(10)
        self.check_fail_criteria(speed)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
