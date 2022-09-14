import os
import re
import tempfile
import time
import timeit
from shutil import copyfile

import pytest
import shutil

from infra.test_base import TestBase
from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_100M, LINK_SPEED_1G, \
    LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G
from tools import ops
from tools import test_configure
from tools.atltoolper import AtlTool
from tools.driver import Driver
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "link_up_time"


class TestLinkUpTime(TestBase):
    LOCAL_LINK_CAP_REG = 0x368
    LINK_CAP_RESOLUTION_REG = 0x370

    @classmethod
    def setup_class(cls):
        super(TestLinkUpTime, cls).setup_class()

        cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port)
        cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)
        cls.NETMASK_IPV4 = "255.255.0.0"

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.network_interface = cls.dut_ifconfig.get_conn_name()

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestLinkUpTime, cls).teardown_class()
        # cls.state.test_cleanup_cold_restart = True

    def setup_method(self, method):
        pass
        
    def teardown_method(self, method):
        super(TestLinkUpTime, self).teardown_method(method)
        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

            self.lkp_bin_log_file, self.lkp_txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.lkp_bin_log_file, self.test_log_dir)
            shutil.copy(self.lkp_txt_log_file, self.test_log_dir)
    
    @test_configure.auto_configure_link_speed
    def link_state_reset(self, speed):
        timeout = 0.1
        cycles = 150
        
        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        
        time.sleep(timeout * cycles)

        start_value = self.dut_atltool_wrapper.readreg(self.LOCAL_LINK_CAP_REG)
        ival = self.dut_atltool_wrapper.readreg(self.LINK_CAP_RESOLUTION_REG)
        
        new_value = start_value - pow(2, 30)

        self.dut_atltool_wrapper.writereg(self.LOCAL_LINK_CAP_REG, new_value)
        
        pval = ival
        change_counter = 0
        for _ in range(cycles):
            tval = self.dut_atltool_wrapper.readreg(self.LINK_CAP_RESOLUTION_REG)
            if tval != pval:
                change_counter += 1
                pval = tval
            time.sleep(timeout)
        
        log.info('Link state changes detected: %i' % change_counter)
        assert (change_counter == 2 and ival != 0) or (change_counter == 1 and ival == 0)

    def test_link_reset_AUTO(self):
        """Test that auto negotiated link becomes up with single try."""
        self.link_state_reset(speed=LINK_SPEED_AUTO)
        
    def test_link_reset_100M(self):
        """Test that 100M link becomes up with single try."""
        self.link_state_reset(speed=LINK_SPEED_100M)

    def test_link_reset_1G(self):
        """Test that 1G link becomes up with single try."""
        self.link_state_reset(speed=LINK_SPEED_1G)

    def test_link_reset_2_5G(self):
        """Test that 2.5G link becomes up with single try."""
        self.link_state_reset(speed=LINK_SPEED_2_5G)
    
    def test_link_reset_5G(self):
        """Test that 5G link becomes up with single try."""
        self.link_state_reset(speed=LINK_SPEED_5G)

    def test_link_reset_10G(self):
        """Test that 10G link becomes up with single try."""
        self.link_state_reset(speed=LINK_SPEED_10G)
        
if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
