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


class TestDPDKIPReassembly(TestDPDKBase):

    @classmethod
    def setup_class(cls):
        super(TestDPDKIPReassembly, cls).setup_class()

    def test_testsute_testpmd_ip_reassembly(self):

        for ps in [2048]:
            self.run_ip_reassembly_async(params_pmd='-c 0xff -n 2', params='-p 3 --maxflows=1024 --flowttl=10s')

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

            output = self.run_ip_reassembly_join(1)['output']
            log.info(output)

            assert False

if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
