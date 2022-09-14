import os
import sys
import time
import pytest


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from infra.test_base import idparametrize
from infra.test_base_phy import TestBasePhy, print_statistics
from hlh.phy import PHY
from tools.constants import LINK_SPEED_10G, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G
from tools.driver import Driver
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "phy_link_switch"


class TestPhyLinkUpTime(TestBasePhy):
    """
    @description: The test checks multiply link up/down on separate phy and measurement time of it.

    @setup: Felicity <-> Dac cable <-> separate PHY <-> Eth cable <-> LKP
    """
    TRIES = 10
    MAXIMUM_LINKUP_TIME_IN_MS = {
        LINK_SPEED_100M: 4000,
        LINK_SPEED_1G: 4500,
        LINK_SPEED_2_5G: 5000,
        LINK_SPEED_5G: 5500,
        LINK_SPEED_10G: 6000
    }
    reports = []

    @classmethod
    def setup_class(cls):
        super(TestPhyLinkUpTime, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            cls.dut_phy = PHY(phy_control=cls.phy_controls[0])

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_link_switch_short(self, speed):
        """
        @description: This test checks that link up is correct and measurement time of it.

        @steps:
        1. configure setup: set speed and mtu
        2. do several(TRIES) iterations:
            - measurement time of link up on PHY. The time must be less MAXIMUM_LINKUP_TIME_IN_MS
            - read and check phy counters

        @result:
        @duration: 120 seconds.
        """
        
        if speed not in self.supported_speeds:
            pytest.skip()

        self.reports.append({'speed': speed, 'times': [0]})

        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.set_link_speed(speed)

        self.dut_ifconfig.wait_link_up()
        assert speed == self.dut_ifconfig.wait_link_up()
        assert speed == self.lkp_ifconfig.wait_link_up()

        times_down = []
        times_up = []

        for i in range(self.TRIES):
            log.info('Iteration #{}'.format(i))
            link_down_time, link_up_time = self.dut_phy.restart_autoneg()

            times_down.append(link_down_time)
            times_up.append(link_up_time)

            log.info('Link down time: {} ms'.format(link_down_time))
            log.info('Link   up time: {} ms -> {}'.format(link_up_time, 'PASS' if link_up_time > 0 else 'FAIL'))

            time.sleep(1)

            self.read_phy_counters()

            time.sleep(9)

            # get phy statistics
            phy_counters = self.read_phy_counters()
            print_statistics(phy_counters)

            for k in phy_counters.keys():
                if 'bad' in k:
                    assert phy_counters[k] == 0, 'Bad counters must be zero'

        log.info('#' * 90)
        log.info('# Link down time: {} ms'.format(times_down))
        log.info('#' * 90)
        log.info('# Link   up time: {} ms'.format(times_up))
        log.info('#' * 90)
        self.reports[-1] = {'speed': speed, 'times': times_up}

        v_min = all([e > 0 for e in times_up])
        v_max = all([self.MAXIMUM_LINKUP_TIME_IN_MS[speed] > e for e in times_up])
        assert v_min and v_max, 'Time linkup time must be less {} ms and more 0'.format(self.MAXIMUM_LINKUP_TIME_IN_MS[speed])

    def test_reports(self):
        log.info('+-------+' + '-' * 64 + '+')
        for p in self.reports:
            t = p['times']
            v_min = all([e > 0 for e in t])
            v_max = all([self.MAXIMUM_LINKUP_TIME_IN_MS[p['speed']] > e for e in t])
            passed = 'PASS' if v_min and v_max else 'FAIL'
            msg = '| {:>5s} | min: {:5d} ms      max: {:5d} ms      avg: {:5} ms   {:>8} |'
            log.info(msg.format(str(p['speed']), min(t), max(t), sum(t) / len(t), passed))

        log.info('+-------+' + '-' * 64 + '+')


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
