import os

import pytest

from infra.test_base import idparametrize
from tests.common.lom_test_base import LOMTestBase
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "TestFw2xLoM"


class TestFw2xLoM(LOMTestBase):
    # dummy example how to reuse base class tests with idparametrize
    @idparametrize("mode", ["serdes_only", "mdio/serdes"])
    def test_check_who_am_i(self, mode):
        super(TestFw2xLoM, self).test_check_who_am_i()


class TestFw2xLoM_Sleep(TestFw2xLoM):
    @classmethod
    def setup_class(cls):
        cls.DUT_POWER_ACTION = cls.DUT_POWER_STATES.SUSPEND
        super(TestFw2xLoM_Sleep, cls).setup_class()


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
