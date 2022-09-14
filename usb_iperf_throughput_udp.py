import os
import pytest

from tools.constants import LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M, LINK_SPEED_10G, \
    DIRECTION_RXTX, DIRECTION_RX, DIRECTION_TX, KNOWN_LINK_SPEEDS, LINK_SPEED_10M
from tools.utils import get_atf_logger
from usb_iperf_test_base import TestUsbThroughputBase
from infra.test_base import idparametrize

log = get_atf_logger()

PAIR_1 = "1"
PAIR_4 = "4"
PAIR_5 = "5"
PAIR_10 = "10"
FC_OFF = "off"
FC_ON = "on"

DIRECTIONS = [DIRECTION_RX, DIRECTION_TX, DIRECTION_RXTX]


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "usb_iperf_throughput"


class TestUsbThroughput(TestUsbThroughputBase):

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    @idparametrize("dir", [DIRECTION_RX, DIRECTION_TX])
    @idparametrize("fc", [FC_OFF, FC_ON])
    def test_iperf_udp(self, speed, dir, fc):
        self.run_iperf_usb(pair=PAIR_1, direction=dir, speed=speed, fc=fc, is_udp=True)

    # ============================== UDP sanity multiple pair===============================
    @idparametrize("speed", [LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_10G])
    @idparametrize("fc", [FC_OFF, FC_ON])
    def test_iperf_udp_txrx_1(self, speed, fc):
        self.run_iperf_usb(pair=PAIR_5, direction=DIRECTION_RXTX, speed=speed, is_udp=True, fc=fc,
                           buffer_num_len=[5000, 6000, 7000, 8000, 65500])

    @idparametrize("speed", [LINK_SPEED_10M, LINK_SPEED_100M, LINK_SPEED_1G])
    @idparametrize("fc", [FC_OFF, FC_ON])
    def test_iperf_udp_txrx_2(self, speed, fc):
        self.run_iperf_usb(pair=PAIR_4, direction=DIRECTION_RXTX, speed=speed, is_udp=True, fc=fc,
                           buffer_num_len=[2000, 3000, 4000, 5000, 6000])

    def test_report(self):
        self.make_report()


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
