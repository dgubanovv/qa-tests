import os
import sys
import time

import pytest
# from scapy.utils import wrpcap

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from infra.test_base import idparametrize
from tools.test_configure import auto_configure
from hlh.phy import PHY
from infra.test_base_phy import TestBasePhy
from tools.constants import LINK_STATE_UP, ALL_LINK_SPEEDS
from tools.tcpdump import Tcpdump
from tools.driver import Driver
from tools.log import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "phy_traffic_generator"


class TestPhyTrafficGenerator(TestBasePhy):
    """
        @description: This tests checking correct work phy traffic generator.

        @duration: 30 seconds.
    """

    @classmethod
    def setup_class(cls):
        super(TestPhyTrafficGenerator, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_phy = PHY(port=cls.dut_port, host=cls.dut_hostname)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @auto_configure
    def run_test_tg_several_packets(self, speed):
        packet_count = 13
        pkt_len = 128

        self.lkp_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

        self.dut_phy.set_advertise(speeds=[speed])
        self.dut_phy.restart_autoneg()
        self.dut_phy.wait_link_up()

        assert self.lkp_ifconfig.wait_link_up() == speed, "Failed link up"

        sniffer = Tcpdump(host=self.lkp_hostname, port=self.lkp_port, timeout=4)
        sniffer.run_async()
        time.sleep(1)

        self.dut_phy.send_n_packets(speed, packet_count, pkt_len)

        time.sleep(1)

        packets = sniffer.join(timeout=1)

        filtered_packets = [p for p in packets if len(p) == (pkt_len - 4)]
        log.info('Filtered packets: {}'.format(len(filtered_packets)))
        # wrpcap(os.path.join(self.test_log_dir, "packets.pcap"), packets)

        assert len(filtered_packets) == packet_count

    @idparametrize('speed', ALL_LINK_SPEEDS)
    def test_tg_several_packets(self, speed):
        """
            @description: This test checking that phy traffic generator can send several packets.

            @steps:
                1. set link up on LKP
                2. set link up on DUT
                3. send several packets
                4. check that captured packets is same that was send

            @result: amount capture packets is amount sended packets

            @requirements:

            @duration: 30 seconds.
        """

        self.run_test_tg_several_packets(speed=speed)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
