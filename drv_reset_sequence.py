import os
import time
import tempfile

import pytest

import tools.driver
import tools.ifconfig
import tools.ping
from infra.test_base import TestBase
from tools.constants import LINK_STATE_DOWN, LINK_STATE_UP, CARD_FELICITY_KR, CARD_FELICITY_EUROPA, CARD_FELICITY, \
    LINK_SPEED_1G
from tools.power import Power
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_reset_sequence_test"


class TestDriverResetSequence(TestBase):

    DUT_IP = "192.168.0.2"
    LKP_IP = "192.168.0.3"
    GATEWAY = "192.168.0.1"
    NETMASK = "255.255.255.0"
    BEFORE_PING_DELAY = 10

    @classmethod
    def setup_class(cls):
        super(TestDriverResetSequence, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = tools.driver.Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
            cls.lkp_driver = tools.driver.Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IP, cls.NETMASK, cls.GATEWAY)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, cls.GATEWAY)

            cls.dut_power = Power(host=cls.dut_hostname)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def teardown_method(self, method):
        super(TestDriverResetSequence, self).teardown_method(method)

        self.bring_host_online(self.dut_hostname)
        self.dut_power.hibernate_off()

    def test_by_disable(self):
        if self.dut_fw_card in [CARD_FELICITY_KR, CARD_FELICITY_EUROPA, CARD_FELICITY]:
            if self.supported_speeds is None:
                raise Exception("Do not know supported speeds on Felicity")
            speed = self.supported_speeds[0]
        else:
            speed = LINK_SPEED_1G

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)

        i = 0
        max_nof_resets = 300

        while i < max_nof_resets:
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)

            assert self.lkp_ifconfig.wait_link_up() == speed
            time.sleep(self.BEFORE_PING_DELAY)
            assert self.ping(from_host="localhost", to_host=self.DUT_IP)
            i += 1

    def test_by_hibernate(self):
        if self.dut_fw_card in [CARD_FELICITY_KR, CARD_FELICITY_EUROPA, CARD_FELICITY]:
            if self.supported_speeds is None:
                raise Exception("Do not know supported speeds on Felicity")
            speed = self.supported_speeds[0]
        else:
            speed = LINK_SPEED_1G

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)

        i = 0
        max_nof_resets = 30

        while i < max_nof_resets:
            self.dut_power.hibernate()
            assert self.poll_host_powered_off(self.dut_hostname)
            self.bring_host_online(self.dut_hostname)

            assert self.lkp_ifconfig.wait_link_up() == speed
            time.sleep(self.BEFORE_PING_DELAY)
            assert self.ping(from_host="localhost", to_host=self.DUT_IP)
            i += 1


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
