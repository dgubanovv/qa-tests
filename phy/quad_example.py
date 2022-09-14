import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from infra.test_base_phy import TestBasePhy
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "quad_example"


class TestQuadExample(TestBasePhy):
    @classmethod
    def setup_class(cls):
        super(TestQuadExample, cls).setup_class()

    def test_heartbeat(self):
        for phy_id in self.dut_phy_ids:
            hb = self.phy_controls[phy_id].rmap.glb.GlobalReservedStatus_2()\
                .nearlySecondsLSW.readValue(self.phy_controls[phy_id])
            log.info("PHY heartbeat {}".format(hb))


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])



# 2019-02-21 12:30:24,585 -    INFO -        conftest:228  - ##############################################################################
# 2019-02-21 12:30:24,586 -    INFO -        conftest:229  - STARTING TEST QuadExample.heartbeat ##########################################
# 2019-02-21 12:30:24,588 -    INFO -        conftest:230  - ##############################################################################

# 2019-02-21 12:30:24,611 -    INFO -    quad_example:27   - PHY heartbeat 28782
# 2019-02-21 12:30:24,612 -    INFO -    quad_example:27   - PHY heartbeat 28782
# 2019-02-21 12:30:24,615 -    INFO -    quad_example:27   - PHY heartbeat 28782
# 2019-02-21 12:30:24,615 -    INFO -    quad_example:27   - PHY heartbeat 28782
# QuadExample.heartbeat - PASSED

# 2019-02-21 12:30:24,617 -    INFO -        conftest:205  - ################################################################################
# 2019-02-21 12:30:24,617 -    INFO -        conftest:206  - ENDING TEST QuadExample.heartbeat - PASSED #####################################
# 2019-02-21 12:30:24,617 -    INFO -        conftest:207  - DURATION = 0.0260000228882 seconds #############################################
# 2019-02-21 12:30:24,618 -    INFO -        conftest:208  - ################################################################################