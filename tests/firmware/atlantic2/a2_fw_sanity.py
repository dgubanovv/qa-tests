import os
import random
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import pytest

from hlh.register import Register
from infra.test_base import TestBase, idparametrize
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.atltoolper import AtlTool
from tools.ctypes_struct_helper import dump_struct_log
from tools.constants import ENABLE, DISABLE, OFFLOADS_STATE_DSBL, OFFLOADS_STATE_TX, OFFLOADS_STATE_RX, \
    OFFLOADS_STATE_TX_RX, MTU_1500
from tools.command import Command
from tools.fw_a2_drv_iface_cfg import HOST_MODE_ACTIVE, HOST_MODE_INVALID, HOST_MODE_SLEEP_PROXY, \
    Boot_Status, FirmwareA2Config
from tools.ifconfig import LINK_SPEED_100M, LINK_SPEED_AUTO, LINK_SPEED_NO_LINK, LINK_STATE_UP, LINK_STATE_DOWN, \
    KNOWN_LINK_SPEEDS
from tools.scapy_tools import ScapyTools
from tools.utils import get_atf_logger, get_bus_dev_func

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_sanity"


class TestA2FWSanity(TestBase):
    DEFAULT_LINK_CHECKS = 20
    COMMON_GENERAL_CTRL_REG = 0x3000

    LKP_IP4_ADDR = "192.168.0.2"
    NETMASK_IPV4 = "255.255.255.0"
    MULTICAST_IPV4 = "192.168.0.255"

    LKP_IP6_ADDR = "4000:0000:0000:0000:1601:bd17:0c02:2402"
    PREFIX_IPV6 = "64"

    GLOBAL_GENERAL_PROVISIONING = 0x514

    THERMAL_SHUTDOWN_STATUS = (0x1e, 0xc478, 0x1)
    HIGH_TEMP_FAILURE_THRESHOLD = (0x1e, 0xc421, 0x6c00)
    HIGH_TEMP_WARNING_THRESHOLD = (0x1e, 0xc423, 0x3c00)
    LOW_TEMP_WARNING_THRESHOLD = (0x1e, 0xc424, 0x0a00)

    SHUTDOWN_TEMP_THRESHOLD = 108
    WARNING_HOT_TEMP_THRESHOLD = 100
    WARNING_COLD_TEMP_THRESHOLD = 80
    REG_MSM_MAXIMUM_FRAME_LENGTH = 0x14

    MAX_RETRY_COUNT = 15

    @classmethod
    def setup_class(cls):
        super(TestA2FWSanity, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", host=cls.dut_hostname,
                                    drv_type=DRV_TYPE_DIAG)
            cls.dut_driver.install()
            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.fw_config = FirmwareA2Config(cls.atltool_wrapper)
            cls.Boot_Status = Boot_Status(cls.atltool_wrapper)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6_ADDR, cls.PREFIX_IPV6, None)
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            cls.lkp_mac_addr = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()
            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestA2FWSanity, cls).teardown_class()

    def setup_method(self, method):
        super(TestA2FWSanity, self).setup_method(method)
        self.atltool_wrapper.kickstart2()

    def teardown_method(self, method):
        super(TestA2FWSanity, self).teardown_method(method)

    def link_down_up(self):
        self.fw_config.set_link_state(LINK_STATE_DOWN)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_down()
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()

    def test_downshift(self):
        """"
        @description: Check FW downshift.

        @steps:
        1. Set link up.
        2. Enable downshift.
        3. In loop foreach value of downshift retry count from 0 to 15:
            a. Set retry count.
            b. Check downshift in phy register.
            c. Check retry count in phy register.

        @result: All ckecs are passed.
        @duration: 5 seconds.
        """
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.fw_config.set_downshift(ENABLE)

        for i in range(self.MAX_RETRY_COUNT):
            self.fw_config.set_downshift_retry(i)
            phy_downshift = Register(self.atltool_wrapper.readphyreg(0x7, 0xc400))
            assert phy_downshift[0x4] == 1, "Downshift is disable"
            assert phy_downshift[0x0:0x3] == i, "Wrong retry count in PHY: {}".format(i)

    def test_fw_mtu(self):
        """"
        @description: Test check downshift.

        @steps:
        1. Set link up.
        2. Configure mtu by driver interface option.
        3. Check MSM register.

        @result: Check is passed.
        @duration: 5 seconds.
        """
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(LINK_SPEED_AUTO)
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_fw_mtu(MTU_1500)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()
        assert self.atltool_wrapper.readmsmreg(self.REG_MSM_MAXIMUM_FRAME_LENGTH) == MTU_1500

    def test_minimal_link_speed(self):
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.fw_config.set_minimal_link_speed(ENABLE)
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()
        assert self.fw_config.get_fw_link_speed() == self.supported_speeds[0]

    def check_msm_set(self, timeout=15, bit=0, value=0):
        msm8 = Register(self.atltool_wrapper.readmsmreg(0x8))
        if msm8[bit] == value:
            return value
        raise Exception('Feature not enable in msm'.format(timeout))

    def test_frame_padding_rx(self):
        self.fw_config.set_padding_removal_rx(DISABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x5, value=0)

        self.fw_config.set_padding_removal_rx(ENABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x5, value=1)

    def test_promiscuous_mode(self):
        self.fw_config.set_promscuous_mode_state(DISABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x4, value=0)

        self.fw_config.set_promscuous_mode_state(ENABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x4, value=1)

    def test_crc_forwarding(self):
        self.fw_config.set_crc_forwarding_state(DISABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x6, value=0)

        self.fw_config.set_crc_forwarding_state(ENABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x6, value=1)

    def test_tx_padding(self):
        self.fw_config.set_tx_padding_state(DISABLE)
        self.link_down_up()
        self.check_msm_set(bit=0xb, value=0)

        self.fw_config.set_tx_padding_state(ENABLE)
        self.link_down_up()
        self.check_msm_set(bit=0xb, value=1)

    def test_control_frame(self):
        self.fw_config.set_control_frame_state(DISABLE)
        self.link_down_up()
        self.check_msm_set(bit=0xd, value=0)

        self.fw_config.set_control_frame_state(ENABLE)
        self.link_down_up()
        self.check_msm_set(bit=0xd, value=1)

    def test_discard_errored_frames(self):
        self.fw_config.set_discard_errored_frames(DISABLE)
        self.link_down_up()
        self.check_msm_set(bit=0xe, value=0)

        self.fw_config.set_discard_errored_frames(ENABLE)
        self.link_down_up()
        self.check_msm_set(bit=0xe, value=1)

    def test_disable_length_check(self):
        self.fw_config.set_disable_length_check_state(DISABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x11, value=0)

        self.fw_config.set_disable_length_check_state(ENABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x11, value=1)

    def test_priority_flow_control(self):
        self.fw_config.set_priority_flow_control_state(DISABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x13, value=0)

        self.fw_config.set_priority_flow_control_state(ENABLE)
        self.link_down_up()
        time.sleep(1)
        self.check_msm_set(bit=0x13, value=1)

    def test_discard_short_frames(self):
        self.fw_config.set_discard_short_frames_state(DISABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x19, value=0)

        self.fw_config.set_discard_short_frames_state(ENABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x19, value=1)

    def test_disable_crc_corruption(self):
        self.fw_config.set_disable_crc_corruption_state(DISABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x1a, value=0)

        self.fw_config.set_disable_crc_corruption_state(ENABLE)
        self.link_down_up()
        self.check_msm_set(bit=0x1a, value=1)

    def test_phy_temperature(self):
        time.sleep(3)  # wait for mac to read information from phy
        temp_phy = self.atltool_wrapper.readphyreg(0x1e, 0xc820) / 256.0
        dif = abs(temp_phy - self.fw_config.get_phy_health_monitor().phyTemperature)
        assert dif < 2

    def test_thermal_shutdown_default_settings(self):
        assert self.fw_config.get_thermal_shutdown_state() == self.THERMAL_SHUTDOWN_STATUS[2]

        temp_treshold = self.fw_config.get_thermal_shutdown_threshold()
        assert temp_treshold.shutdownTempThreshold == self.SHUTDOWN_TEMP_THRESHOLD,\
            "Incorrect default high temperature failure threshold. Expected: {}. Actual: {}.".\
            format(self.SHUTDOWN_TEMP_THRESHOLD, temp_treshold.shutdownTempThreshold)
        assert temp_treshold.warningColdTempThreshold == self.WARNING_COLD_TEMP_THRESHOLD,\
            "Incorrect default low temperature warning threshold. Expected: {}. Actual: {}.".\
            format(self.WARNING_COLD_TEMP_THRESHOLD, temp_treshold.warningColdTempThreshold)
        assert temp_treshold.warningHotTempThreshold == self.WARNING_HOT_TEMP_THRESHOLD,\
            "Incorrect default high temperature warning threshold. Expected: {}. Actual: {}.".\
            format(self.WARNING_HOT_TEMP_THRESHOLD, temp_treshold.warningHotTempThreshold)

    def test_thermal_shutdown_status(self):
        self.fw_config.set_thermal_shutdown_state(DISABLE)
        time.sleep(2)
        reg_status = Register(
            self.atltool_wrapper.readphyreg(self.THERMAL_SHUTDOWN_STATUS[0], self.THERMAL_SHUTDOWN_STATUS[1]))
        assert reg_status[0xa] == 0
        self.fw_config.set_thermal_shutdown_state(ENABLE)
        time.sleep(2)
        reg_status = Register(
            self.atltool_wrapper.readphyreg(self.THERMAL_SHUTDOWN_STATUS[0], self.THERMAL_SHUTDOWN_STATUS[1]))
        assert reg_status[0xa] == 1

    def test_thermal_shutdown_threshold(self):
        def phy_temp_to_normal(temp):
            return (temp >> 8) & 0xFF
        shutdown_temperature = random.randint(65, 80)
        warning_temperature = random.randint(50, 65)
        cold_temperature = random.randint(10, 20)
        self.fw_config.set_thermal_shutdown_threshold(shutdown_temperature, warning_temperature, cold_temperature)
        time.sleep(2)
        dut_high_temp_fail = self.atltool_wrapper.readphyreg(self.HIGH_TEMP_FAILURE_THRESHOLD[0],
                                                             self.HIGH_TEMP_FAILURE_THRESHOLD[1])
        assert phy_temp_to_normal(dut_high_temp_fail) == shutdown_temperature, \
            "Driver set incorrect high temperature failure threshold"

    def test_warning_thermal_threshold(self):
        time.sleep(3)  # wait for mac to read information from phy
        self.fw_config.set_thermal_shutdown_state(ENABLE)
        now_temp_phy = self.fw_config.get_phy_health_monitor().phyTemperature
        shutdown_temperature = 108
        warning_temperature = now_temp_phy - 3
        cold_temperature = now_temp_phy - 7
        self.fw_config.set_thermal_shutdown_threshold(shutdown_temperature, warning_temperature, cold_temperature)
        time.sleep(2)
        assert self.fw_config.get_phy_health_monitor().phyTemperature > now_temp_phy - 3
        assert self.fw_config.get_phy_health_monitor().phyHotWarning == 1
        now_temp_phy = self.fw_config.get_phy_health_monitor().phyTemperature
        self.fw_config.set_thermal_shutdown_threshold(shutdown_temperature, now_temp_phy + 20, now_temp_phy - 10)
        time.sleep(2)
        assert self.fw_config.get_phy_health_monitor().phyHotWarning == 0

    def test_kickstart(self):
        self.Boot_Status.read()
        dump_struct_log(self.Boot_Status.bits, log.info, "Boot Status")

        self.atltool_wrapper.kickstart2()

        heart_beat_1 = self.fw_config.get_mac_health_monitor().macHeartBeat
        time.sleep(2)
        mac_health = self.fw_config.get_mac_health_monitor()
        assert mac_health.macReady == 1
        heart_beat_2 = mac_health.macHeartBeat

        assert heart_beat_2 > heart_beat_1, "MAC heart beat is not ticking"

        time.sleep(3)

        heart_beat_1 = self.fw_config.get_phy_health_monitor().phyHeartBeat
        time.sleep(2)
        phy_health = self.fw_config.get_phy_health_monitor()
        assert phy_health.phyReady == 1
        heart_beat_2 = phy_health.phyHeartBeat

        assert heart_beat_2 > heart_beat_1, "PHY heart beat is not ticking"

    def test_mac_fault(self):
        """
        @description: Test Mac Fault and Mac Fault Code are reports correctly
        through Driver-Firmware interface after fault.

        @steps:
        1. Inject error via Global general provisioning register.
        2. Read mac_health_monitor structure.
        3. Check macFault and macFaultCode.

        @result: Checks passed.
        @duration: 1 sec.
        """
        # Global IRAM ECC Inject error
        self.atltool_wrapper.writereg(self.GLOBAL_GENERAL_PROVISIONING, 0x400)
        time.sleep(1)
        mac_health = self.fw_config.get_mac_health_monitor()

        assert mac_health.macFault == 1
        assert mac_health.macFaultCode != 0

    def test_phy_fault(self):
        """
        @description: Test Phy Fault and Phy Fault Code are reports correctly
        through Driver-Firmware interface after fault.

        @steps:
        1. Enable thermal shutdown.
        2. Set thermal shutdown threshold below current temperature.
        3. Read phy_health_monitor structure.
        4. Check phyFault and phyFaultCode.

        @result: Checks passed.
        @duration: 3 sec.
        """
        now_temp_phy = self.fw_config.get_phy_health_monitor().phyTemperature
        shutdown_temperature = now_temp_phy - 10
        warning_temperature = now_temp_phy - 15
        cold_temperature = now_temp_phy - 20
        self.fw_config.set_thermal_shutdown_state(ENABLE)
        self.fw_config.set_thermal_shutdown_threshold(shutdown_temperature, warning_temperature, cold_temperature)
        time.sleep(3)
        phy_health = self.fw_config.get_phy_health_monitor()

        assert phy_health.phyFault == 1
        assert phy_health.phyFaultCode != 0

    def test_fw_version(self):
        actual_version = self.dut_firmware.actual_version
        log.info("Actual FW version is {}".format(actual_version))
        actual_maj, actual_min, actual_bld = map(int, actual_version.split("."))

        version = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.version")

        dump_struct_log(version.bundle, log.info, "Bundle version")
        dump_struct_log(version.mac, log.info, "MAC FW version")
        dump_struct_log(version.phy, log.info, "PHY FW version")

        assert version.bundle.major == actual_maj
        assert version.bundle.minor == actual_min
        assert version.bundle.build == actual_bld

    def test_firmware_log_with_counter(self):
        link_speed = self.supported_speeds[0]
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        bus, dev, func = get_bus_dev_func(self.dut_port)
        readlog_cmd = "sudo timeout 7 readlog2 -p -d {}:".format(bus)
        count_new_line_in_log = self.atltool_wrapper.readreg(0x00013800)
        readlog_cmd = Command(cmd=readlog_cmd, host=self.dut_hostname)
        readlog_cmd.run_async()
        time.sleep(1)
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(link_speed)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        time.sleep(1)
        readlog_cmd.join()
        count_new_line_in_log_after = self.atltool_wrapper.readreg(0x00013800)
        assert count_new_line_in_log < count_new_line_in_log_after

    def test_firmware_log(self):
        bus, dev, func = get_bus_dev_func(self.dut_port)
        readlog_cmd = "sudo timeout 10 readlog2 -p -d {}:".format(bus)
        log.info("Executing readlog2: '{}'".format(readlog_cmd))
        readlog_cmd = Command(cmd=readlog_cmd, host=self.dut_hostname)
        readlog_cmd.run_async()
        time.sleep(2)
        self.atltool_wrapper.writereg(self.COMMON_GENERAL_CTRL_REG, 0x1)
        time.sleep(1)
        res = readlog_cmd.join()
        fw_log = res["output"]
        assert ("PCIe: PERST HIGH" in log_line for log_line in fw_log)
        assert ("F/W version: {}".format(self.dut_fw_version) in log_line for log_line in fw_log)

    def set_cfg_dut_pause_options(self, pauserx, pausetx):
        self.fw_config.set_link_control_mode(HOST_MODE_INVALID)
        time.sleep(1)
        self.fw_config.set_pause_rx_tx(pauseRx=pauserx, pauseTx=pausetx)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.fw_config.wait_link_up()
        pauserx, pausetx = self.fw_config.get_pause_rx_tx_status()
        return pauserx, pausetx

    def run_pauserxtx(self, speed):
        if speed not in self.supported_speeds:
            pytest.skip()
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(speed=speed)
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        # DUT RX 0 TX 0, LKP RX 1 TX 1
        self.lkp_ifconfig.set_flow_control(OFFLOADS_STATE_TX_RX)
        pauserx, pausetx = self.set_cfg_dut_pause_options(False, False)
        assert pauserx == 0, "FW Pause RX is enabled"
        assert pausetx == 0, "FW Pause TX is enabled"
        # DUT RX 0 TX 1, LKP RX 0 TX 0
        self.lkp_ifconfig.set_flow_control(OFFLOADS_STATE_DSBL)
        pauserx, pausetx = self.set_cfg_dut_pause_options(False, True)
        assert pauserx == 0, "FW Pause RX is enabled"
        assert pausetx == 0, "FW Pause TX is enabled"
        # DUT RX 0 TX 1, LKP RX 0 TX 1
        self.lkp_ifconfig.set_flow_control(OFFLOADS_STATE_TX)
        pauserx, pausetx = self.set_cfg_dut_pause_options(False, True)
        assert pauserx == 0, "FW Pause RX is enabled"
        assert pausetx == 0, "FW Pause TX is enabled"
        # DUT RX 0 TX 1, LKP RX 1 TX 0
        self.lkp_ifconfig.set_flow_control(OFFLOADS_STATE_RX)
        pauserx, pausetx = self.set_cfg_dut_pause_options(False, True)
        assert pauserx == 0, "FW Pause RX is enabled"
        assert pausetx == 1, "FW Pause TX is disabled"

        # DUT RX 1 TX 1, LKP RX 0 TX 0
        self.lkp_ifconfig.set_flow_control(OFFLOADS_STATE_DSBL)
        pauserx, pausetx = self.set_cfg_dut_pause_options(True, True)
        assert pauserx == 0, "FW Pause RX is disabled"
        assert pausetx == 0, "FW Pause TX is enabled"
        # DUT RX 1 TX 1, LKP RX 1 TX 1
        self.lkp_ifconfig.set_flow_control(OFFLOADS_STATE_TX_RX)
        pauserx, pausetx = self.set_cfg_dut_pause_options(True, True)
        assert pauserx == 1, "FW Pause RX is disabled"
        assert pausetx == 1, "FW Pause TX is disabled"

        # DUT RX 1 TX 0, LKP RX 0 TX 0
        self.lkp_ifconfig.set_flow_control(OFFLOADS_STATE_DSBL)
        pauserx, pausetx = self.set_cfg_dut_pause_options(True, False)
        assert pauserx == 0, "FW Pause RX is enabled"
        assert pausetx == 0, "FW Pause TX is enabled"
        # DUT RX 1 TX 0, LKP RX 0 TX 1
        self.lkp_ifconfig.set_flow_control(OFFLOADS_STATE_TX)
        pauserx, pausetx = self.set_cfg_dut_pause_options(True, False)
        assert pauserx == 1, "FW Pause RX is disabled"
        assert pausetx == 0, "FW Pause TX is enabled"
        # DUT RX 1 TX 0, LKP RX 1 TX 0
        self.lkp_ifconfig.set_flow_control(OFFLOADS_STATE_RX)
        pauserx, pausetx = self.set_cfg_dut_pause_options(True, False)
        assert pauserx == 1, "FW Pause RX is disabled"
        assert pausetx == 1, "FW Pause TX is disabled"

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_pauserxtx(self, speed):
        """
        @description: Check pause FW Rx and Tx pause options.

        @steps:
        1. In loop for each speed in KNOWN_LINK_SPEEDS:
            a. Enable flow-control via drv settings for LKP.
            b. Configure FW pause options Rx=0 and Tx=0 for DUT. Check FW pause status.
            c. Configure FW pause options Rx=0 and Tx=1 for DUT.
            d. Disable flow-control via drv settings for LKP. Check FW pause status.
            e. Configure Rx disabled and Tx enabled flow-control via drv settings for LKP. FW pause status.
            f. Configure Rx enabled and Tx disabled flow-control via drv settings for LKP. FW pause status.
            g. Configure FW pause options Rx=1 and Tx=1 for DUT.
            h. Disable flow-control via drv settings for LKP. Check FW pause status.
            i. Enable flow-control via drv settings for LKP. Check FW pause status.
            j. Configure FW pause options Rx=1 and Tx=0 for DUT.
            k. Disable flow-control via drv settings for LKP. Check FW pause status.
            l. Configure Rx disabled and Tx enabled flow-control via drv settings for LKP. FW pause status.
            m. Configure Rx enabled and Tx enabled flow-control via drv settings for LKP. FW pause status.

        @result: All ckecks are passed.
        @duration: 3 minutes.
        """
        self.run_pauserxtx(speed)

    def test_control_link_sleep_proxy(self):
        """
        @description: Check FW link in sleep proxy.

        @steps:
        1. Set autoneg link speed on DUT and LKP.
        2. Ckeck that link is up.
        3. Put FW to Sleep Proxy mode.
        4. Ckeck link state.

        @result: All ckecks are passed.
        @duration: 2 minutes.
        """
        self.atltool_wrapper.kickstart2()
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(LINK_SPEED_AUTO)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()

        self.fw_config.set_link_control_mode(HOST_MODE_SLEEP_PROXY)
        speed = self.lkp_ifconfig.wait_link_up()
        dut_link_state = self.fw_config.get_fw_link_state()
        assert dut_link_state == 1, "Firmware should up link"
        dut_link_speed = self.fw_config.wait_link_up()

        assert speed != LINK_SPEED_NO_LINK
        assert dut_link_speed == LINK_SPEED_100M

    def test_downshift_attempts_config(self):
        self.atltool_wrapper.kickstart2()
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(LINK_SPEED_AUTO)

        link_option = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions")
        link_option.downshift = 1
        link_option.downshiftRetry = 5
        self.fw_config.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions", link_option)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.wait_link_up()

        # TODO: read downshift config from PHY
        # phy_dnshft_att = self.dut_atltool_wrapper.readphyreg(0x07, 0xC400) & 0x7
        # assert phy_dnshft_att == 5, "MAC FW didn't pass correct downshift attempts to PHY FW"

        # Upload another Drv Downshift message to config memory
        link_option.downshiftRetry = 3
        self.fw_config.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions", link_option)

        # Link down - up

        # Make sure that downshift settings are the same
        # phy_dnshft_att = self.dut_atltool_wrapper.readphyreg(0x07, 0xC400) & 0x7
        # assert phy_dnshft_att == 5, "MAC FW didn't pass correct downshift attempts to PHY FW"

    def test_lasi_interrupts(self):
        """
        @description: This subtest performs check that MAC FW should configure LASI interrupt mask
        and read Alarms register (don't configure High/Low alarms mask and don't read Internal Alarms register).

        @steps:
        1. Request firmware to bringup link
        2. Verify that all "High Priority Alarm Mask" and "Low Priority Alarm Mask" registers are set to 0

        @result: All checks passed
        """
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()

        regs = [
            0x00006F60,  # Rx High Priority Interrupt Mask 1
            0x00006F80,  # Rx Low Priority Interrupt Mask 1
            0x00008F60,  # Tx High Priority Interrupt Mask 1
            0x00008F80,  # Tx Low Priority Interrupt Mask 1
            0x00000960,  # Global High Priority Interrupt Mask 1
            0x00000964,  # Global High Priority Interrupt Mask 2
            0x00000968,  # Global High Priority Interrupt Mask 3
            0x0000096C,  # Global High Priority Interrupt Mask 4
            0x00000970,  # Global High Priority Interrupt Mask 5
            0x00000980,  # Global Low Priority Interrupt Mask 1
            0x00000984,  # Global Low Priority Interrupt Mask 2
            0x00000988,  # Global Low Priority Interrupt Mask 3
            0x0000098C,  # Global Low Priority Interrupt Mask 4
            0x00000990,  # Global Low Priority Interrupt Mask 5
        ]

        for reg in regs:
            reg_val = self.atltool_wrapper.readreg(reg)
            assert reg_val == 0


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
