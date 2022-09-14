import os
import pytest

from tools.constants import DIRECTION_RXTX, DIRECTION_RX, DIRECTION_TX, KNOWN_LINK_SPEEDS
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

PAIRS = [PAIR_1, PAIR_5, PAIR_10]
DIRECTIONS = [DIRECTION_RX, DIRECTION_TX, DIRECTION_RXTX]


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "usb_iperf_throughput"


class TestUsbThroughput(TestUsbThroughputBase):

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    @idparametrize("pair", PAIRS)
    @idparametrize("dir", DIRECTIONS)
    @idparametrize("fc", [FC_OFF, FC_ON])
    def test_iperf_tcp(self, speed, dir, pair, fc):
        self.run_iperf_usb(pair=pair, direction=dir, speed=speed, fc=fc)

    def test_report(self):
        self.make_report()


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
