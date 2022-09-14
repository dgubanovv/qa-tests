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


class TestDPDKIPFragmentation(TestDPDKBase):

    @classmethod
    def setup_class(cls):
        super(TestDPDKIPFragmentation, cls).setup_class()

    def test_testsute_testpmd_ip_fragmentation(self):

        for ps in [64, 1518]:
            self.run_ip_frag_async(params_pmd='-c 0xff -n 3', params='-p 3')

            packets_args = {
                'pktsize': ps,
                'ipfrag': True,
            }

            args = {
                'packets': Packets(**packets_args),
                'duration': 30
            }

            time.sleep(10)
            self.traffic_generator.start(**args)
            time.sleep(30)
            self.traffic_generator.stop()
            time.sleep(10)

            result = self.run_ip_frag_join(1)
            log.info(result['output'])

            assert result['returncode'] == 0

if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
