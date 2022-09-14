import os
import sys
import time
import timeit

import pytest


sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.atltoolper import AtlTool
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config
from tools.utils import get_atf_logger
from infra.test_base import TestBase

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_cable_diag"


MAP_PAIR_STATUS = {
    0b000: 'OK',
    0b001: 'Connected to Pair +1',
    0b010: 'Connected to Pair +2',
    0b011: 'Connected to Pair +3',
    0b100: 'Short Circuit (<  30 Om)',
    0b101: 'Low   Impedance (<  85 Om)',
    0b110: 'High  Impedance (> 115 Om)',
    0b111: 'Open  Circuit (> 300 Om)'
}


class TestA2FwCableDiag(TestBase):

    @classmethod
    def setup_class(cls):
        super(TestA2FwCableDiag, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", host=cls.dut_hostname, drv_type=DRV_TYPE_DIAG)
            cls.dut_driver.install()
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()

            cls.dut_atltool = AtlTool(port=cls.dut_port, silent=False)
            cls.fw_config = FirmwareA2Config(cls.dut_atltool)
        except Exception:
            log.exception("Failed while setting up class")
            raise

    def test_cable_diagnostics(self):
        """
        @description: This test performs check cable diag works fine.

        @steps:
        1. write bit to perform cable diag.
        2. wait while cable diag is complete.
        4. check status and anther parameters.

        @result: cable len must be more 0.
        @duration: 5 minutes.
        """
        assert self.cable_length is not None, 'CABLE_LENGTH is not specified'

        timeout = 30

        self.dut_atltool.kickstart2()

        st = self.fw_config.get_cable_diag_status()
        transactId = st.transactId

        self.fw_config.run_cable_diag(timeout=timeout)

        is_ok = False
        start = timeit.default_timer()
        for i in range(timeout):
            time.sleep(1)
            st = self.fw_config.get_cable_diag_status()
            if st.transactId > transactId:
                is_ok = True
                break

        log.info('Cable diagnostics finished: {:.1f} sec'.format(timeit.default_timer() - start))
        assert is_ok, "TransactId not changed"
        assert st.status == 0, "Status must be zero"

        log.info('-' * 80)
        for i in range(4):
            log.info('  PAIR {}'.format('ABCD'[i]))
            log.info('      status: {}'.format(MAP_PAIR_STATUS[st.laneData[i].resultCode]))
            log.info('        dist: {}'.format(st.laneData[i].dist))
            log.info('    far dist: {}'.format(st.laneData[i].farDist))
            log.info('-' * 80)

        for i in range(4):
            assert abs(self.cable_length - st.laneData[i].farDist) < 2, \
                "Real length of cable must be equal CABLE_LENGTH with tolerance 1 meters"
            assert st.laneData[i].resultCode == 0, "Status is not OK"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
