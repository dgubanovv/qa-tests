import os
import time
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import pytest

from hlh.register import Register
from infra.test_base import TestBase
from tools.driver import Driver
from tools.atltoolper import AtlTool
from tools.constants import ENABLE
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config
from tools.ifconfig import LINK_SPEED_AUTO, LINK_STATE_UP
from tools.tcpdump import Tcpdump
from tools.scapy_tools import ScapyTools
from tools.utils import get_atf_logger
from scapy.all import Ether, IP, TCP

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_with_drv"


class TestA2FWDRV(TestBase):
    DUT_MAC_ADDR = "00:17:b6:01:02:03"

    @classmethod
    def setup_class(cls):
        super(TestA2FWDRV, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
            cls.dut_driver.install()
            cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port, cls.dut_hostname)
            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, cls.LKP_IPV4_ADDR)
            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.fw_config = FirmwareA2Config(cls.atltool_wrapper)
            cls.dut_scapy_tools = ScapyTools(port=cls.dut_port, host=cls.dut_hostname)
            cls.dut_scapy_iface = cls.dut_scapy_tools.get_scapy_iface()
            cls.dut_mac_addr = cls.dut_ifconfig.get_mac_address()

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            cls.lkp_mac_addr = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def send_loopback_system(self):
        dut_scapy_tool = ScapyTools(port=self.dut_port, host=self.dut_hostname)
        dut_scapy_iface = dut_scapy_tool.get_scapy_iface()
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="ff:ff:ff:ff:ff:ff") / IP(dst=self.DUT_IPV4_ADDR) / TCP(dport=1111) / \
              ("1234567890" * 5)
        sniffer = Tcpdump(port=self.dut_port, timeout=5, host=self.dut_hostname)
        sniffer.run_async()
        dut_scapy_tool.send_packet(pkt=pkt, iface=dut_scapy_iface)
        sniffed = sniffer.join(10)
        pkts = []
        for pkt in sniffed:
            if TCP in pkt and pkt[TCP].dport == 1111:
                pkts.append(pkt)
        assert len(pkts) == 2, "Loopback is not work"
        assert pkts[0] == pkts[1], "Loopback is not work"

    def test_internal_loopback(self):
        """"
        @description: Test internal loopback.

        @steps:
        1. Enable internal loopback.
        2. Turn on loopback.
        3. Check that in registers loopback is on.
        4. Send packets from DUT
        5. Check that package send and receive on DUT

        @result: Package send and receive on DUT.
        @duration: 20 seconds.
        """
        self.fw_config.set_internal_loopback(ENABLE)
        time.sleep(2)
        reg_status = Register(self.atltool_wrapper.readmsmreg(0x8))
        assert reg_status[0x1c] == 0x1
        self.send_loopback_system()


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
