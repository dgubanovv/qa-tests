import os
import sys
import time

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hlh.phy import PHY, NORMAL_POWER, LOW_POWER
from infra.test_base_phy import TestBasePhy
from tools.constants import LINK_SPEED_10G, LINK_STATE_UP
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.log import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_cable_diagnostics"


class TestPhyA2CableDiagnostics(TestBasePhy):
    """
    @description: The TestPhyA2CableDiagnostics test checking state of cable.

    @setup: any card with LKP
    """

    @classmethod
    def setup_class(cls):
        super(TestPhyA2CableDiagnostics, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, drv_type=DRV_TYPE_DIAG)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_phy = PHY(port=cls.dut_port, host=cls.dut_hostname)
            cls.expected_cable_len = int(os.environ.get("CABLE_LENGTH", 0))

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def teardown_method(self, method):
        super(TestPhyA2CableDiagnostics, self).teardown_method(method)
        self.dut_phy.set_power_mode(LOW_POWER)

    def test_cable_diagnostics(self):
        self.dut_phy.set_power_mode(NORMAL_POWER)

        time_cable_diagnostics = int(self.dut_phy.run_cable_diagnostics())
        assert time_cable_diagnostics > 0, "Failed cable diagnostics"
        log.info('Cable diagnostics time: {:d} ms'.format(time_cable_diagnostics))

        data = self.dut_phy.get_cable_diagnostics_data()

        self.dut_phy.set_power_mode(LOW_POWER)

        log.info('-' * 120)
        log.debug(data)
        log.info('-' * 120)

        for channel in 'ABCD':
            log.info('Pair {}'.format(channel))
            log.info('  {:>18s}: {} m'.format('expected distance', self.expected_cable_len))
            log.info('  {:>18s}: {} m'.format('far distance', data[channel]['far_distance']))
            log.info('  {:>18s}: {} m'.format('reflection', data[channel]['reflection']))
            log.info('  {:>18s}: {:.2f} dB'.format('margin', data[channel]['margin']))
            log.info('  {:>18s}: {}'.format('status', data[channel]['status']))
            log.info('-' * 120)

        for channel in 'ABCD':
            assert abs(data[channel]['far_distance'] - self.expected_cable_len) < 3, \
                "Cable length must be equal CABLE_LENGTH environment variable"
            assert data[channel]['status'] == 'OK', "Connection status must be OK"

    def test_get_cable_length_by_link(self):
        """
        @description: The test check cable length, and status each pair in cable

        @steps:
        1. run cable diagnostics
        2. wait finish
        3. check status

        @result: cable length must be almost equal(with tolerance) variable(CABLE_LENGTH) from environment

        @requirements:

        @duration: 30 seconds.
        """
        speed = LINK_SPEED_10G
        if speed not in self.supported_speeds:
            pytest.skip()

        self.lkp_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

        self.dut_phy.set_advertise(speeds=[speed])
        self.dut_phy.restart_autoneg()

        assert self.lkp_ifconfig.wait_link_up() == speed, "Failed link up on LKP: {}".format(speed)
        self.dut_phy.wait_link_up()

        link_status = self.dut_phy.get_link_status()
        assert link_status['link'] == speed, "Failed link up on DUT: {}".format(speed)
        assert link_status['status'] == 'Connected'

        cable_len = self.dut_phy.get_cable_length()

        log.info('  Actual cable length: {} m'.format(cable_len))
        log.info('Expected cable length: {} m'.format(self.expected_cable_len))

        assert abs(cable_len - self.expected_cable_len) < 3, \
            "Cable length must be equal CABLE_LENGTH environment variable"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
