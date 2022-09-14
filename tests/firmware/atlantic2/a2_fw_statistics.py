import os
import time
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import pytest

from infra.test_base import TestBase
from tools.driver import Driver
from tools.atltoolper import AtlTool
from tools.fw_a2_drv_iface_cfg import HOST_MODE_ACTIVE, SleepProxyOffload, FirmwareA2Config
from tools.ifconfig import LINK_SPEED_AUTO, LINK_SPEED_NO_LINK, LINK_STATE_UP, LINK_STATE_DOWN
from tools.scapy_tools import ScapyTools
from tools.utils import get_atf_logger
from scapy.all import Ether, IP, IPv6, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_statistics"


class TestA2FWStatistics(TestBase):
    DUT_MAC_ADDR = "00:17:b6:01:02:03"
    MULTICAST_MAC_IP4 = "01:00:5E:00:00:FB"
    MULTICAST_MAC_IP6 = "33:33:00:00:00:FB"

    @classmethod
    def setup_class(cls):
        super(TestA2FWStatistics, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
            cls.dut_driver.install()
            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.fw_config = FirmwareA2Config(cls.atltool_wrapper)
            cls.dut_scapy_tools = ScapyTools(port=cls.dut_port, host=cls.dut_hostname)
            cls.dut_scapy_iface = cls.dut_scapy_tools.get_scapy_iface()
            cls.dut_mac_addr = cls.dut_ifconfig.get_mac_address()

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            cls.lkp_mac_addr = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestA2FWStatistics, cls).teardown_class()

    def setup_method(self, method):
        super(TestA2FWStatistics, self).setup_method(method)

    def teardown_method(self, method):
        super(TestA2FWStatistics, self).teardown_method(method)

    def test_link_up(self):
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.fw_config.set_link_state(LINK_STATE_DOWN)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        new_link_up = self.fw_config.get_fw_link_speed()
        assert new_link_up == LINK_SPEED_NO_LINK, "Link is not up"

        couter_link_up = self.fw_config.get_link_statistics()["link_up"]
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.fw_config.wait_link_up()
        time.sleep(1)
        couter_link_up_after = self.fw_config.get_link_statistics()["link_up"]
        assert couter_link_up + 1 == couter_link_up_after

    def test_link_down(self):
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.fw_config.wait_link_up()

        couter_link_down = self.fw_config.get_link_statistics()["link_down"]
        self.fw_config.set_link_state(LINK_STATE_DOWN)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        time.sleep(3)
        new_link_up = self.fw_config.get_fw_link_speed()
        assert new_link_up == LINK_SPEED_NO_LINK, "Link is not down"
        time.sleep(1)
        couter_link_down_after = self.fw_config.get_link_statistics()["link_down"]
        assert couter_link_down + 1 == couter_link_down_after

    def setup_on_rx_msm_tests(self):
        sp_cfg = SleepProxyOffload()

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        time.sleep(5)

    def test_msm_rx_unicast(self):
        self.setup_on_rx_msm_tests()
        pkt = Ether(dst=self.DUT_MAC_ADDR, src=self.lkp_mac_addr) / ('\xff' * 54)
        couter_msm_rx_good_frames = self.fw_config.get_msm_statistics()["rx_good_frames"]
        couter_msm_rx_unicast_octets = self.fw_config.get_msm_statistics()["rx_unicast_octets"]
        couter_msm_rx_unicast_frames = self.fw_config.get_msm_statistics()["rx_unicast_frames"]
        self.lkp_scapy_tools.send_packet(pkt, iface=self.lkp_scapy_iface)
        time.sleep(3)
        couter_msm_rx_good_frames_after = self.fw_config.get_msm_statistics()["rx_good_frames"]
        couter_msm_rx_unicast_octets_after = self.fw_config.get_msm_statistics()["rx_unicast_octets"]
        couter_msm_rx_unicast_frames_after = self.fw_config.get_msm_statistics()["rx_unicast_frames"]
        assert couter_msm_rx_good_frames + 1 == couter_msm_rx_good_frames_after, "Rx good frames are incorrect"
        assert couter_msm_rx_unicast_frames + 1 == couter_msm_rx_unicast_frames_after, "Rx unicast frames are incorrect"
        assert couter_msm_rx_unicast_octets + (max(len(pkt) + 4, 64)) == \
            couter_msm_rx_unicast_octets_after, "Rx unicast octets are incorrect"

    def test_msm_rx_multicast(self):
        self.setup_on_rx_msm_tests()
        for mac in [self.MULTICAST_MAC_IP6, self.MULTICAST_MAC_IP4]:
            pkt = Ether(dst=mac, src=self.lkp_mac_addr) / ('\xff' * 54)
            couter_msm_rx_good_frames = self.fw_config.get_msm_statistics()["rx_good_frames"]
            couter_msm_rx_multicast_octets = self.fw_config.get_msm_statistics()["rx_multicast_octets"]
            couter_msm_rx_multicast_frames = self.fw_config.get_msm_statistics()["rx_multicast_frames"]
            self.lkp_scapy_tools.send_packet(pkt, iface=self.lkp_scapy_iface)
            time.sleep(3)
            couter_msm_rx_good_frames_after = self.fw_config.get_msm_statistics()["rx_good_frames"]
            couter_msm_rx_multicast_octets_after = self.fw_config.get_msm_statistics()["rx_multicast_octets"]
            couter_msm_rx_multicast_frames_after = self.fw_config.get_msm_statistics()["rx_multicast_frames"]
            assert couter_msm_rx_good_frames + 1 == couter_msm_rx_good_frames_after, "Rx good frames are incorrect"
            assert couter_msm_rx_multicast_frames + 1 == couter_msm_rx_multicast_frames_after, \
                "Rx multicast frames are incorrect"
            assert couter_msm_rx_multicast_octets + max(len(pkt) + 4, 64) == \
                couter_msm_rx_multicast_octets_after, "Rx multicast octets are incorrect"

    def test_msm_rx_broadcast(self):
        self.setup_on_rx_msm_tests()
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.lkp_mac_addr) / ('\xff' * 54)
        couter_msm_rx_good_frames = self.fw_config.get_msm_statistics()["rx_good_frames"]
        couter_msm_rx_broadcast_octets = self.fw_config.get_msm_statistics()["rx_broadcast_octets"]
        couter_msm_rx_broadcast_frames = self.fw_config.get_msm_statistics()["rx_broadcast_frames"]
        self.lkp_scapy_tools.send_packet(pkt, iface=self.lkp_scapy_iface)
        time.sleep(3)
        couter_msm_rx_good_frames_after = self.fw_config.get_msm_statistics()["rx_good_frames"]
        couter_msm_rx_broadcast_octets_after = self.fw_config.get_msm_statistics()["rx_broadcast_octets"]
        couter_msm_rx_broadcast_frames_after = self.fw_config.get_msm_statistics()["rx_broadcast_frames"]
        assert couter_msm_rx_good_frames + 1 == couter_msm_rx_good_frames_after, "Rx good frames are incorrect"
        assert couter_msm_rx_broadcast_frames + 1 == couter_msm_rx_broadcast_frames_after, \
            "Rx broadcast frames are incorrect"
        assert couter_msm_rx_broadcast_octets + max(len(pkt) + 4, 64) == \
            couter_msm_rx_broadcast_octets_after, "Rx broadcast octets are incorrect"

    def setup_on_tx_msm_tests(self):
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()

    def test_msm_tx_unicast(self):
        self.setup_on_tx_msm_tests()
        pkt = Ether(dst=self.lkp_mac_addr, src=self.dut_mac_addr) / ('\xff' * 54)
        couter_msm_tx_good_frames = self.fw_config.get_msm_statistics()["tx_good_frames"]
        couter_msm_tx_unicast_octets = self.fw_config.get_msm_statistics()["tx_unicast_octets"]
        couter_msm_tx_unicast_frames = self.fw_config.get_msm_statistics()["tx_unicast_frames"]
        self.dut_scapy_tools.send_packet(pkt, iface=self.dut_scapy_iface)
        time.sleep(3)
        couter_msm_tx_good_frames_after = self.fw_config.get_msm_statistics()["tx_good_frames"]
        couter_msm_tx_unicast_octets_after = self.fw_config.get_msm_statistics()["tx_unicast_octets"]
        couter_msm_tx_unicast_frames_after = self.fw_config.get_msm_statistics()["tx_unicast_frames"]
        assert couter_msm_tx_good_frames + 1 == couter_msm_tx_good_frames_after, "Tx good frames are incorrect"
        assert couter_msm_tx_unicast_frames + 1 == couter_msm_tx_unicast_frames_after, "Tx unicast frames are incorrect"
        assert couter_msm_tx_unicast_octets + max(len(pkt) + 4, 64) == \
            couter_msm_tx_unicast_octets_after, "Tx unicast octets are incorrect"

    def test_msm_tx_multicast(self):
        self.setup_on_tx_msm_tests()
        for mac in [self.MULTICAST_MAC_IP6, self.MULTICAST_MAC_IP6]:
            pkt = Ether(dst=mac, src=self.dut_mac_addr) / ('\xff' * 54)
            couter_msm_tx_good_frames = self.fw_config.get_msm_statistics()["tx_good_frames"]
            couter_msm_tx_multicast_octets = self.fw_config.get_msm_statistics()["tx_multicast_octets"]
            couter_msm_tx_multicast_frames = self.fw_config.get_msm_statistics()["tx_multicast_frames"]
            self.dut_scapy_tools.send_packet(pkt, iface=self.dut_scapy_iface)
            time.sleep(3)
            couter_msm_tx_good_frames_after = self.fw_config.get_msm_statistics()["tx_good_frames"]
            couter_msm_tx_multicast_octets_after = self.fw_config.get_msm_statistics()["tx_multicast_octets"]
            couter_msm_tx_multicast_frames_after = self.fw_config.get_msm_statistics()["tx_multicast_frames"]
            assert couter_msm_tx_good_frames + 1 == couter_msm_tx_good_frames_after, "Tx good frames are incorrect"
            assert couter_msm_tx_multicast_frames + 1 == couter_msm_tx_multicast_frames_after, \
                "Tx multicast frames are incorrect"
            assert couter_msm_tx_multicast_octets + max(len(pkt) + 4, 64) == \
                couter_msm_tx_multicast_octets_after, "Tx multicast octets are incorrect"

    def test_msm_tx_broadcast(self):
        self.setup_on_tx_msm_tests()
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.dut_mac_addr) / ('\xff' * 54)
        couter_msm_tx_good_frames = self.fw_config.get_msm_statistics()["tx_good_frames"]
        couter_msm_tx_broadcast_octets = self.fw_config.get_msm_statistics()["tx_broadcast_octets"]
        couter_msm_tx_broadcast_frames = self.fw_config.get_msm_statistics()["tx_broadcast_frames"]
        self.dut_scapy_tools.send_packet(pkt, iface=self.dut_scapy_iface)
        time.sleep(3)
        couter_msm_tx_good_frames_after = self.fw_config.get_msm_statistics()["tx_good_frames"]
        couter_msm_tx_broadcast_octets_after = self.fw_config.get_msm_statistics()["tx_broadcast_octets"]
        couter_msm_tx_broadcast_frames_after = self.fw_config.get_msm_statistics()["tx_broadcast_frames"]
        assert couter_msm_tx_good_frames + 1 == couter_msm_tx_good_frames_after, "Tx good frames are incorrect"
        assert couter_msm_tx_broadcast_frames + 1 == couter_msm_tx_broadcast_frames_after, "Tx broadcast frames " \
                                                                                           "are incorrect"
        assert couter_msm_tx_broadcast_octets + max(len(pkt) + 4, 64) == \
            couter_msm_tx_broadcast_octets_after, "Tx broadcast octets are incorrect"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
