import shutil
import time

import pytest

if __package__ is None:
    import sys
    from os import path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from infra.test_base import TestBase
from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_1G, FELICITY_CARDS, CARD_FIJI, CARD_NIKKI, DUPLEX_FULL, \
    DUPLEX_HALF, CARD_ANTIGUA
from tools.driver import Driver, DRV_TYPE_KO
from tools.ops import OpSystem
from tools.prof import prof, timing
from tools.test_configure import auto_configure
from tools.utils import get_atf_logger


log = get_atf_logger()


class TestIperfBase(TestBase):

    @classmethod
    def setup_class(cls):
        super(TestIperfBase, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.log_local_dir = cls.working_dir

            cls.dut_atltool_wrapper = None if 'usb' in cls.dut_port else AtlTool(port=cls.dut_port)

            with prof('install_firmwares'):
                cls.install_firmwares()

            with prof('dut.driver.install'):
                if cls.dut_fw_card not in CARD_FIJI and cls.dut_atltool_wrapper.is_secure_chips() and cls.dut_ops.is_linux():
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version,
                                            flashless_fw=cls.dut_fw_version)
                else:
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
                cls.dut_driver.install()

            with prof('lkp.driver.install'):
                cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
                cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.dut_ifconfig.set_ipv6_address(cls.DUT_IPV6_ADDR, cls.DEFAULT_PREFIX_IPV6, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IPV6_ADDR, cls.DEFAULT_PREFIX_IPV6, None)
            cls.dut_ops = OpSystem()

            cls.prev_speed = None
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestIperfBase, self).setup_method(method)
        if self.MCP_LOG and not self.dut_atltool_wrapper is None:
            self.bin_log_file, self.txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestIperfBase, self).teardown_method(method)
        if self.MCP_LOG and not self.dut_atltool_wrapper is None:
            self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

    @timing
    @auto_configure
    def iperf(self, **kwargs):
        speed = kwargs.get('speed', LINK_SPEED_AUTO)

        if self.dut_fw_card in FELICITY_CARDS or self.lkp_fw_card in FELICITY_CARDS:
            if speed == LINK_SPEED_AUTO:
                pytest.skip()

        is_eee = kwargs.get('is_eee', False)
        is_fc = kwargs.get('is_fc', False)
        duplex = kwargs.get('duplex', DUPLEX_FULL)

        if duplex == DUPLEX_HALF and (self.dut_fw_card != CARD_ANTIGUA or self.lkp_fw_card != CARD_ANTIGUA):
            pytest.skip()
        if is_eee and (self.dut_fw_card in FELICITY_CARDS or self.lkp_fw_card in FELICITY_CARDS):
            pytest.skip()

        if is_eee and speed == LINK_SPEED_1G and (self.dut_fw_card == CARD_NIKKI or self.lkp_fw_card == CARD_NIKKI):
            pytest.skip()

        if self.dut_fw_card != CARD_FIJI:
            # Skip 1G EEE tests for 2x Firmware and mac OS
            maj_ver, _, _ = self.dut_atltool_wrapper.get_fw_version()
            if (self.dut_ops.is_mac() or maj_ver == 2) and speed == LINK_SPEED_1G and is_eee:
                pytest.skip()

        if is_fc and self.dut_fw_card == CARD_FIJI and self.dut_ops.is_linux():
            log.info("Not supported for FC in Linux for USB")
            pytest.skip()

        if self.prev_speed is None or self.prev_speed != speed:
            self.dut_ifconfig.set_link_speed(speed, True if duplex == DUPLEX_HALF else False)
            self.dut_ifconfig.set_link_speed(speed, True if duplex == DUPLEX_HALF else False)
            self.lkp_ifconfig.set_link_speed(speed, True if duplex == DUPLEX_HALF else False)

            self.dut_ifconfig.set_ipv6_address(self.DUT_IPV6_ADDR, self.DEFAULT_PREFIX_IPV6, None)
            self.lkp_ifconfig.set_ipv6_address(self.LKP_IPV6_ADDR, self.DEFAULT_PREFIX_IPV6, None)

            self.prev_speed = speed
            time.sleep(self.LINK_CONFIG_DELAY)

        self.run_iperf(**kwargs)
