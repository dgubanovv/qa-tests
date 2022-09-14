import os
import pytest

from tools.constants import LINK_SPEED_5G, \
    DIRECTION_RXTX, DIRECTION_RX, DIRECTION_TX
from tools.utils import get_atf_logger
from usb_iperf_test_base import TestUsbThroughputBase

log = get_atf_logger()

PAIR_1 = "1"
PAIR_4 = "4"
PAIR_5 = "5"
PAIR_10 = "10"
FC_OFF = "off"
FC_ON = "on"


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "usb_iperf_throughput_low_power"
    os.environ["LOW_POWER"] = "TRUE"


class TestUsbThroughputLowPower(TestUsbThroughputBase):
    # ============================== TCP ===============================

    def test_pair_5_dir_tx_speed_5g_fc_on(self):
        self.run_iperf_usb(PAIR_5, DIRECTION_TX, dut_speed=LINK_SPEED_5G, lkp_speed=LINK_SPEED_5G, fc=FC_ON)

    def test_pair_5_dir_tx_rx_speed_5g_fc_on(self):
        self.run_iperf_usb(PAIR_5, DIRECTION_RXTX, dut_speed=LINK_SPEED_5G, lkp_speed=LINK_SPEED_5G, fc=FC_ON)

    def test_pair_5_dir_rx_speed_5g_fc_on(self):
        self.run_iperf_usb(PAIR_5, DIRECTION_RX, dut_speed=LINK_SPEED_5G, lkp_speed=LINK_SPEED_5G, fc=FC_ON)

    def test_pair_5_dir_tx_speed_5g_fc_off(self):
        self.run_iperf_usb(PAIR_5, DIRECTION_TX, dut_speed=LINK_SPEED_5G, lkp_speed=LINK_SPEED_5G, fc=FC_OFF)

    def test_pair_5_dir_tx_rx_speed_5g_fc_off(self):
        self.run_iperf_usb(PAIR_5, DIRECTION_RXTX, dut_speed=LINK_SPEED_5G, lkp_speed=LINK_SPEED_5G, fc=FC_OFF)

    def test_pair_5_dir_rx_speed_5g_fc_off(self):
        self.run_iperf_usb(PAIR_5, DIRECTION_RX, dut_speed=LINK_SPEED_5G, lkp_speed=LINK_SPEED_5G, fc=FC_OFF)

    # ============================== UDP ===============================
    def test_udp_pair_5_dir_tx_rx_speed_auto_5G_fc_on(self):
        self.run_iperf_usb(PAIR_5, DIRECTION_RXTX, dut_speed=LINK_SPEED_5G,
                           lkp_speed=LINK_SPEED_5G, is_udp=True, buffer_num_len=[5000, 6000, 7000, 8000, 65500])

    def test_udp_pair_5_dir_tx_rx_speed_auto_5G_fc_off(self):
        self.run_iperf_usb(PAIR_5, DIRECTION_RXTX, dut_speed=LINK_SPEED_5G,
                           lkp_speed=LINK_SPEED_5G, fc=FC_OFF, is_udp=True, buffer_num_len=[5000, 6000, 7000, 8000, 65500])


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])