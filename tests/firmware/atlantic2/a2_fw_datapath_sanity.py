"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import time
import pytest
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from infra.test_base import idparametrize, TestBase
from tools.atltoolper import AtlTool
from tools.constants import LINK_STATE_UP, KNOWN_LINK_SPEEDS, DIRECTION_RXTX
from tools.driver import Driver
from tools.utils import get_atf_logger, str_to_bool
from tools.ping import ping
from tools.scapy_tools import ScapyTools
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_datapath"


class TestA2FwDatapath(TestBase):
    DUT_IP = "192.168.0.1"
    LKP_IP = "192.168.0.2"
    NETMASK = "255.255.255.0"
    DEFAULT_LINK_UP_CHECKS = 1
    IPERF_TIME = 330

    @classmethod
    def setup_class(cls):
        super(TestA2FwDatapath, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            # Set up DUT
            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
            cls.dut_driver.install()
            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.fw_config = FirmwareA2Config(cls.atltool_wrapper)

            # Set up LKP
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, None)
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()
            if "STRESS_TEST" in os.environ:
                cls.stress_test = str_to_bool(os.environ["STRESS_TEST"])
            else:
                cls.stress_test = False
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestA2FwDatapath, cls).teardown_class()

    def setup_method(self, method):
        super(TestA2FwDatapath, self).setup_method(method)

    def teardown_method(self, method):
        super(TestA2FwDatapath, self).teardown_method(method)

    def establish_link_speed(self, link_speed):
        if link_speed not in self.supported_speeds:
            pytest.skip("Not supported speed")

        self.dut_ifconfig.set_link_speed(link_speed)
        self.lkp_ifconfig.set_link_speed(link_speed)
        self.dut_ifconfig.set_ip_address(self.DUT_IP, self.NETMASK, None)
        self.lkp_ifconfig.set_ip_address(self.LKP_IP, self.NETMASK, None)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()

    def check_fail_criteria(self, speed):
        # Check heartbeats
        mac_heart_beat_1 = self.fw_config. \
            read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.macHealthMonitor.macHeartBeat")
        phy_heart_beat_1 = self.fw_config. \
            read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.phyHealthMonitor.phyHeartBeat")
        time.sleep(2)
        mac_heart_beat_2 = self.fw_config. \
            read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.macHealthMonitor.macHeartBeat")
        phy_heart_beat_2 = self.fw_config. \
            read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.phyHealthMonitor.phyHeartBeat")
        assert mac_heart_beat_2 > mac_heart_beat_1, "MAC heart beat is not ticking"
        assert phy_heart_beat_2 > phy_heart_beat_1, "PHY heart beat is not ticking"

        # Check that link is still up
        assert self.lkp_ifconfig.get_link_speed() == speed, \
            'LKP link speed was changed from {} to {}'.format(speed, self.lkp_ifconfig.get_link_speed())
        assert self.fw_config.get_fw_link_speed() == speed, \
            'DUT link speed was changed from {} to {}'.format(speed, self.fw_config.get_fw_link_speed())

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_ping(self, speed):
        self.establish_link_speed(speed)
        assert ping(16, self.LKP_IP, payload_size=0)
        assert ping(16, self.LKP_IP, payload_size=17000)
        self.check_fail_criteria(speed)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_iperf(self, speed):
        if self.stress_test:
            self.DEFAULT_LINK_UP_CHECKS = 100
            self.IPERF_TIME = 20

        for i in range(self.DEFAULT_LINK_UP_CHECKS):
            log.info("Make {} link up with traffic check".format(i + 1))
            self.establish_link_speed(speed)
            args = {
                'direction': DIRECTION_RXTX,
                'speed': speed,
                'num_threads': 1,
                'num_process': 1,
                'time': self.IPERF_TIME,
                'ipv': 4,
                'buffer_len': 0,
                'is_udp': False,
                'is_eee': False,
                'is_ptp': False,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': self.LKP_IP,
                'dut4': self.DUT_IP,
            }
            self.run_iperf(**args)
            self.check_fail_criteria(speed)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
