import os
import shutil
import socket
import time
import pytest

from enum import Enum
from infra.test_base import TestBase
from tools import pcontrol
from tools.atltoolper import AtlTool
from tools.constants import LINK_STATE_DOWN, \
    LINK_STATE_UP
from tools.driver import Driver
from tools.log import get_atf_logger
from tools.lom import LightsOutManagement
from tools.power import Power

log = get_atf_logger()


class LOMTestBase(TestBase):
    DUT_POWER_STATES = Enum("POWER_STATES", "SUSPEND, SHUTDOWN, HIBERNATE")
    DUT_POWER_ACTION = None

    WHO_AM_I = 0xA5

    @classmethod
    def setup_class(cls):
        super(LOMTestBase, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.arduino_port = os.environ.get("ARDUINO_PORT", None)
            cls.run_on_dut = socket.gethostname() == cls.dut_hostname
            if cls.arduino_port and cls.run_on_dut:
                pytest.skip("When ARDUINO_PORT is set, then test must be run on LKP, not on DUT.")
            if cls.DUT_POWER_ACTION and cls.run_on_dut:
                pytest.skip("When power action is set, then test must be run on LKP, not on DUT.")
            if cls.DUT_POWER_ACTION and not cls.arduino_port:
                pytest.skip("Cannot perform tests with power actions without SMBus connection by Arduino.")

            if not cls.skip_fw_install:
                cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            if not cls.skip_drv_install:
                cls.dut_driver.install()
                cls.lkp_driver.install()

            cls.dut_atltool_wrapper = AtlTool(host=cls.dut_hostname, port=cls.dut_port)
            log.info("LOM DATA: HOST: {}\tPORT: {}".format(cls.dut_hostname, cls.dut_port))
            cls.lom_cntrl = LightsOutManagement(host=cls.dut_hostname, port=cls.dut_port, serial_port=cls.arduino_port)

            # Disable WOL on LKP to avoid problem with link down on Linux
            cls.lkp_ifconfig.set_power_mgmt_settings(False, False, False)

            if cls.DUT_POWER_ACTION:
                power = Power(host=cls.dut_hostname)
                pwr_action = {cls.DUT_POWER_STATES.SUSPEND: power.suspend,
                              cls.DUT_POWER_STATES.SHUTDOWN: power.shutdown,
                              cls.DUT_POWER_STATES.HIBERNATE: power.hibernate}
                pwr_action[cls.DUT_POWER_ACTION]()
                time.sleep(30)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(LOMTestBase, cls).teardown_class()
        if cls.DUT_POWER_ACTION:
            pcontrol.PControl().power(cls.dut_hostname, 500, 0)

    def setup_method(self, method):
        super(LOMTestBase, self).setup_method(method)
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

        if not self.DUT_POWER_ACTION:
            if self.dut_fw_card == "Nikki":
                self.dut_atltool_wrapper.kickstart()
            if self.dut_fw_card == "Antigua":
                self.dut_atltool_wrapper.kickstart2()
            time.sleep(1)  # TODO: looks like smbus needs some time after kickstart

        self.lom_cntrl.LoM_enable()
        self.lkp_ifconfig.wait_link_up()
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(LOMTestBase, self).teardown_method(method)
        self.lom_cntrl.LoM_disable()
        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)

    def test_check_who_am_i(self):
        """
        @description: Perform simple check LOM ID byte

        @steps:
        1. Read LOM ID byte

        @result: ID contain 0xA5
        @duration: 60 seconds.
        """
        test_value = self.lom_cntrl.read_data(self.lom_cntrl.LOM_OFFSET_WHO_AM_I, 1)[0]
        log.info("Memory contain: {}".format(str(test_value)))
        assert self.WHO_AM_I == test_value, \
            "'Who am I' byte expected to be {}, actual value differs".format(self.WHO_AM_I)

    def test_fw_version(self):
        """
        @description: Perform simple check FW Version byte

        @steps:
        1. Read FW Version byte

        @result: Byte must contain minor FW version
        @duration: 60 seconds.
        """
        # LOM_OFFSET_FW_VERSION byte contain MINOR FW version 2.XX.5
        test_value = self.lom_cntrl.read_data(self.lom_cntrl.LOM_OFFSET_FW_VERSION, 1)[0]
        log.info("Memory contain: {}".format(str(test_value)))
        # TODO: rework test to get FW version on the fly
        assert 12 == test_value, "Actual FW version differs from expected"

    def test_check_LOM_states(self):
        """
        @description: Perform simple check LOM states

        @steps:
        1. Read State value -  indication must be enabled
        2. Disable LOM
        3. Read State value -  indication must be disabled

        @result: values are met with actual LOM state
        @duration: 60 seconds.
        """
        test_value = self.lom_cntrl.read_data(self.lom_cntrl.LOM_OFFSET_LOM_STATUS, 1)[0]
        log.info("Memory contain: {}".format(str(test_value)))
        assert 1 == test_value, "LOM status expected to be enabled"
        self.lom_cntrl.LoM_disable()
        test_value = self.lom_cntrl.read_data(self.lom_cntrl.LOM_OFFSET_LOM_STATUS, 1)[0]
        log.info("Memory contain: {}".format(str(test_value)))
        assert 0 == test_value, "LOM status expected to be disabled"

    def test_check_link_status(self):
        """
        @description: Perform simple check link state

        @steps:
        1. Link down
        2. Check link state - indication must be link down
        3. Link up
        4. Check link state - indication must be link up

        @result: values are met with actual LOM state
        @duration: 60 seconds.
        """
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        time.sleep(1)  # TODO: wait for link change bit instead of sleep
        test_value = self.lom_cntrl.read_data(self.lom_cntrl.LOM_OFFSET_LINK_STATUS, 1)[0]
        log.info("Memory contain: {}".format(str(test_value)))
        assert 0 == test_value, "Link status expected to be down"
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.wait_link_up()
        test_value = self.lom_cntrl.read_data(self.lom_cntrl.LOM_OFFSET_LINK_STATUS, 1)[0]
        log.info("Memory contain: {}".format(str(test_value)))
        assert 1 == test_value, "Link status expected to be up"

    def test_mac_address_write_read(self):
        """
        @description: Perform LOM MAC address configuration

        @steps:
        1. Set LOM MAC address
        2. Check LOM MAC address

        @result: MAC address must contain defined MAC
        @duration: 60 seconds.
        """
        self.lom_cntrl.set_lom_mac_address(self.lom_cntrl.LOM_MAC_ADDRESS)
        log.info("Memory contain: {}".format(self.lom_cntrl.read_data(self.lom_cntrl.LOM_OFFSET_MAC_ADDRESS[0], 6)[0:6]))
        tmp_mac_address = ["{:02X}".format(self.lom_cntrl.read_data(self.lom_cntrl.LOM_OFFSET_MAC_ADDRESS[0], 6)[i]) for i in range(6)]
        tmp_mac_address = ':'.join(tmp_mac_address)
        assert self.lom_cntrl.LOM_MAC_ADDRESS == tmp_mac_address, "Actual MAC address differs from expected"

    def test_ip_address_write_read(self):
        """
        @description: Perform LOM IP address configuration

        @steps:
        1. Set LOM IP address
        2. Check LOM IP address

        @result: IP address must contain defined IP
        @duration: 60 seconds.
        """
        self.lom_cntrl.set_lom_ip_address(self.lom_cntrl.LOM_IP_ADDRESS)
        log.info("Memory contain: {}".format(self.lom_cntrl.read_data(self.lom_cntrl.LOM_OFFSET_ARP_IP_ADDRESS[0], 4)[0:4]))
        tmp_ip_address = ["{}".format(self.lom_cntrl.read_data(self.lom_cntrl.LOM_OFFSET_ARP_IP_ADDRESS[i], 1)[0]) for i in range(4)]
        tmp_ip_address = '.'.join(tmp_ip_address)
        assert self.lom_cntrl.LOM_IP_ADDRESS == tmp_ip_address, "Actual IP address differs from expected"
