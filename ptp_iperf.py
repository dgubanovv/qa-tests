import os
import sys

import pytest

from tools import constants
from tools import macos_ptp_avb_base
from tools.macos_ptp_avb_base import AVB_SOURCE_NONE


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "ptp_iperf"


class TestPtpIperfBidirectional(macos_ptp_avb_base.TestMacPtpAvbBackToBack):

    def test_ptp_avb_roles_100M_no_avb(self):
        self.check_roles(*self.ptp_avb_bidir_get_log(constants.LINK_SPEED_100M, AVB_SOURCE_NONE, bg_iperf=True))

    def test_ptp_avb_pdelays_100M_no_avb(self):
        self.check_delays(*self.ptp_avb_bidir_get_log(constants.LINK_SPEED_100M, AVB_SOURCE_NONE, bg_iperf=True))

    def test_ptp_avb_roles_1G_no_avb(self):
        self.check_roles(*self.ptp_avb_bidir_get_log(constants.LINK_SPEED_1G, AVB_SOURCE_NONE, bg_iperf=True))

    def test_ptp_avb_pdelays_1G_no_avb(self):
        self.check_delays(*self.ptp_avb_bidir_get_log(constants.LINK_SPEED_1G, AVB_SOURCE_NONE, bg_iperf=True))
        
    def test_ptp_avb_roles_2_5G_no_avb(self):
        self.check_roles(*self.ptp_avb_bidir_get_log(constants.LINK_SPEED_2_5G, AVB_SOURCE_NONE, bg_iperf=True))

    def test_ptp_avb_pdelays_2_5G_no_avb(self):
        self.check_delays(*self.ptp_avb_bidir_get_log(constants.LINK_SPEED_2_5G, AVB_SOURCE_NONE, bg_iperf=True))
        
    def test_ptp_avb_roles_5G_no_avb(self):
        self.check_roles(*self.ptp_avb_bidir_get_log(constants.LINK_SPEED_5G, AVB_SOURCE_NONE, bg_iperf=True))

    def test_ptp_avb_pdelays_5G_no_avb(self):
        self.check_delays(*self.ptp_avb_bidir_get_log(constants.LINK_SPEED_5G, AVB_SOURCE_NONE, bg_iperf=True))

    def test_ptp_avb_roles_10G_no_avb(self):
        self.check_roles(*self.ptp_avb_bidir_get_log(constants.LINK_SPEED_10G, AVB_SOURCE_NONE, bg_iperf=True))

    def test_ptp_avb_pdelays_10G_no_avb(self):
        self.check_delays(*self.ptp_avb_bidir_get_log(constants.LINK_SPEED_10G, AVB_SOURCE_NONE, bg_iperf=True))


if __name__ == "__main__":
    exec_list = [__file__, "-s", "-v"]
    if sys.argv:
        exec_list.append("-k {}".format(sys.argv[1]))
    pytest.main(exec_list)
