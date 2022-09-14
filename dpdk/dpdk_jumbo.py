import os
import time

import pytest

from dpdk_test_base import TestDPDKBase
from trafficgen.traffic_gen import Packets
from tools.utils import get_atf_logger


log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "dpdk"


class TestDPDKJumbo(TestDPDKBase):

    @classmethod
    def setup_class(cls):
        super(TestDPDKJumbo, cls).setup_class()

    def test_testsute_jumbo_frames_with_no_jumbo_frame_1517(self):
        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 1517
        }

        args = {
            'packets': Packets(**packets_args),
            'duration': 5
        }

        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**args)
        time.sleep(5)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_stats(0)
        log.info(output)

        assert output['rx_good_packets'] > 0
        assert output['rx_errors'] == 0

    def test_testsute_jumbo_frames_with_no_jumbo_frame_1518(self):
        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 1518
        }

        args = {
            'packets': Packets(**packets_args),
            'duration': 5
        }

        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**args)
        time.sleep(5)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_stats(0)
        log.info(output)

        assert output['rx_good_packets'] > 0
        assert output['rx_errors'] == 0


    def test_testsute_jumbo_frames_with_no_jumbo_frame_1519(self):
        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 1519
        }

        args = {
            'packets': Packets(**packets_args),
            'duration': 5
        }

        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**args)
        time.sleep(5)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_stats(0)
        log.info(output)

        assert output['rx_good_packets'] == 0
        assert output['rx_errors'] == 0

    def test_testsute_jumbo_frames_with_jumbo_frame_1519(self):
        self.pytestpmd.parse_args(['max-pkt-len', '9600'])

        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 1519
        }

        args = {
            'packets': Packets(**packets_args),
            'duration': 5
        }

        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**args)
        time.sleep(5)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_stats(0)
        log.info(output)

        assert output['rx_good_packets'] > 0
        assert output['rx_errors'] == 0


    def test_testsute_jumbo_frames_with_jumbo_frame_9600(self):
        self.pytestpmd.parse_args(['max-pkt-len', '9600'])

        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 9600
        }

        args = {
            'packets': Packets(**packets_args),
            'duration': 5
        }

        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**args)
        time.sleep(5)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_stats(0)
        log.info(output)

        assert output['rx_good_packets'] > 0
        assert output['rx_errors'] == 0

    def test_testsute_jumbo_frames_with_jumbo_frame_9601(self):
        self.pytestpmd.parse_args(['max-pkt-len', '9600'])

        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 9601
        }

        args = {
            'packets': Packets(**packets_args),
            'duration': 5
        }

        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**args)
        time.sleep(5)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_stats(0)
        log.info(output)

        assert output['rx_good_packets'] == 0
        assert output['rx_errors'] == 0

if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
