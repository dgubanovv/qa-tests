import os
import tempfile
import time

import pytest
import shutil

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_10G, FELICITY_CARDS, BERMUDA_CARDS, LINK_SPEED_NO_LINK, CARDS_FELICITY_BERMUDA
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvEthConfig, OffloadIpInfo
from tools.ifconfig import get_expected_speed
from tools.mbuper import LINK_STATE_UP, LINK_CONTROL_SLEEP_PROXY, LINK_CONTROL_WOL, LINK_CONTROL_LINK_DROP
from tools.utils import get_atf_logger

from infra.test_base import TestBase

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_sanity"


class TestResetSequence(TestBase):
    @classmethod
    def setup_class(cls):
        super(TestResetSequence, cls).setup_class()

        try:
            cls.BEFORE_PING_DELAY = 15
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest")
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            if cls.lkp_fw_card not in FELICITY_CARDS:
                # For felicity case we will set LKP link speed in the test
                cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            if cls.dut_fw_card in FELICITY_CARDS or cls.lkp_fw_card in FELICITY_CARDS:
                if cls.supported_speeds is None:
                    raise Exception("Do not know supported speeds on Felicity")
                else:
                    cls.speeds = cls.supported_speeds
            else:
                cls.speeds = [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G]
                # Check whether 10G is supported
                cls.auto_speed = get_expected_speed(LINK_SPEED_AUTO, cls.dut_port)
                if cls.auto_speed == LINK_SPEED_10G:
                    cls.speeds.append(LINK_SPEED_10G)

            cls.fw_is_1x = cls.dut_firmware.is_1x()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestResetSequence, cls).teardown_class()
        # For Bermuda perform cold restart after the test due to possible PHY stuck
        if cls.dut_fw_card in BERMUDA_CARDS:
            cls.state.test_cleanup_cold_restart = True

    def setup_method(self, method):
        super(TestResetSequence, self).setup_method(method)
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)
            self.lkp_atltool_wrapper.debug_buffer_enable(True)
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

    def teardown_method(self, method):
        super(TestResetSequence, self).teardown_method(method)
        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

            self.lkp_bin_log_file, self.lkp_txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.lkp_bin_log_file, self.test_log_dir)
            shutil.copy(self.lkp_txt_log_file, self.test_log_dir)

    def set_dut_link_speed(self, speed):
        log.info("Setting link speed {} on DUT".format(speed))

        if self.fw_is_1x:
            self.dut_atltool_wrapper.set_link_params(speed, LINK_STATE_UP)
        else:
            self.dut_atltool_wrapper.set_link_params_2x(speed)
            self.dut_atltool_wrapper.wait_link_up()

    def test_reset_sequence_with_ping(self):
        dut_ip = "192.168.1.11"
        lkp_ip = "192.168.1.12"

        cfg = DrvEthConfig()
        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = "00:17:b6:00:07:81"
        log.info('Configuring MAC address: {}'.format(cfg.mac))

        ips = OffloadIpInfo()
        ips.v4_addr_count = 1
        ips.v4_addresses = [dut_ip]
        ips.v4_masks = [16]
        cfg.ips = ips
        log.info('Configuring IPv4 addresses: {}'.format(ips.v4_addresses))

        out_beton_filename = os.path.join(self.test_log_dir, 'offload_ipv4.txt')

        self.lkp_ifconfig.set_ip_address(lkp_ip, self.DEFAULT_NETMASK_IPV4, "192.168.1.1")

        for i in range(20):
            if self.lkp_fw_card in FELICITY_CARDS:
                expected_speed = self.speeds[-1]
            else:
                expected_speed = self.speeds[i % len(self.speeds)]

            log.info("Kickstart attempt #{} with speed {}".format(i, expected_speed))
            self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

            self.lkp_ifconfig.set_link_speed(expected_speed)

            # Apply configuration to FW
            cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

            actual_speed = self.lkp_ifconfig.wait_link_up()

            assert actual_speed == expected_speed, "Invalid link speed negotiated: {}".format(actual_speed)

            time.sleep(self.BEFORE_PING_DELAY)

            log.info("Ping {} from {}".format(dut_ip, lkp_ip))
            assert self.ping(self.lkp_hostname, dut_ip, 10, ipv6=False, src_addr=lkp_ip) is True, \
                "Failed to ping {} from {}".format(dut_ip, lkp_ip)

    def test_reset_sequence_with_link_up(self):
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

        for i in range(50):
            if self.lkp_fw_card in FELICITY_CARDS:
                expected_speed = self.speeds[-1]
            else:
                expected_speed = self.speeds[i % len(self.speeds)]

            log.info("Kickstart attempt #{} with speed {}".format(i, expected_speed))
            self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

            if self.lkp_fw_card in FELICITY_CARDS:
                # If the card is felicity we cannot use AUTO link speed on LKP
                self.lkp_ifconfig.set_link_speed(expected_speed)
            self.set_dut_link_speed(expected_speed)
            actual_speed = self.dut_atltool_wrapper.wait_link_up()
            assert actual_speed == expected_speed, "Invalid link speed negotiated: {}".format(actual_speed)

    def test_reset_sequence_from_sleep_proxy(self):
        if self.fw_is_1x:
            pytest.skip()

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

        for i in range(50):
            if self.lkp_fw_card in FELICITY_CARDS:
                expected_speed = self.speeds[-1]
                self.lkp_ifconfig.set_link_speed(expected_speed)
            else:
                expected_speed = self.speeds[i % len(self.speeds)]

            self.set_dut_link_speed(expected_speed)
            actual_speed = self.dut_atltool_wrapper.wait_link_up()
            assert actual_speed == expected_speed, "Invalid link speed negotiated: {}".format(actual_speed)

            self.dut_atltool_wrapper.set_link_control_2x(LINK_CONTROL_SLEEP_PROXY)
            time.sleep(1)
            assert self.lkp_ifconfig.wait_link_up() != LINK_SPEED_NO_LINK

            log.info("Kickstart attempt #{} from sleep proxy".format(i))
            self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

    def test_reset_sequence_from_wol(self):
        if self.fw_is_1x:
            pytest.skip()

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

        for i in range(50):
            if self.lkp_fw_card in FELICITY_CARDS:
                expected_speed = self.speeds[-1]
                self.lkp_ifconfig.set_link_speed(expected_speed)
            else:
                expected_speed = self.speeds[i % len(self.speeds)]

            self.set_dut_link_speed(expected_speed)
            actual_speed = self.dut_atltool_wrapper.wait_link_up()
            assert actual_speed == expected_speed, "Invalid link speed negotiated: {}".format(actual_speed)

            self.dut_atltool_wrapper.set_link_control_2x(LINK_CONTROL_WOL)
            time.sleep(1)
            assert self.lkp_ifconfig.wait_link_up() != LINK_SPEED_NO_LINK

            log.info("Kickstart attempt #{} from wol".format(i))
            self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

    def test_reset_sequence_from_link_drop(self):
        if self.fw_is_1x:
            pytest.skip()

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

        for i in range(30):
            if self.lkp_fw_card in FELICITY_CARDS:
                expected_speed = self.speeds[-1]
                self.lkp_ifconfig.set_link_speed(expected_speed)
            else:
                expected_speed = self.speeds[i % len(self.speeds)]

            self.set_dut_link_speed(expected_speed)
            actual_speed = self.dut_atltool_wrapper.wait_link_up()
            assert actual_speed == expected_speed, "Invalid link speed negotiated: {}".format(actual_speed)

            self.dut_atltool_wrapper.set_link_control_2x(LINK_CONTROL_LINK_DROP)
            time.sleep(3)
            assert self.lkp_ifconfig.get_link_speed() == LINK_SPEED_NO_LINK

            log.info("Kickstart attempt #{} from link drop".format(i))
            self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
