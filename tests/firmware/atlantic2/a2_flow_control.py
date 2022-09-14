import os
import time
import sys
import random

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import pytest

from hlh.register import Register
from infra.test_base import idparametrize, TestBase
from perf.iperf import Iperf
from perf.iperf_result import IperfResult
from tools.atltoolper import AtlTool
from tools.aqpkt import Aqsendp
from tools.constants import LINK_STATE_UP, LINK_STATE_DOWN, FELICITY_CARDS, LINK_SPEED_AUTO, \
    DIRECTION_TX, KNOWN_LINK_SPEEDS, LINK_SPEED_1G, LINK_SPEED_100M, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, \
    LINK_SPEED_10M
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.killer import Killer
from tools.scapy_tools import ScapyTools
from tools.sniffer import SnifferRemote
from tools.utils import get_atf_logger
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config, PauseQuantaOffload, HOST_MODE_ACTIVE


log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_flow_control"


class TestFWPauseFrameCfg(TestBase):
    REG_54_PAUSE_CONTROL_QUANTA_10 = 0x54
    REG_58_PAUSE_CONTROL_QUANTA_32 = 0x58
    REG_5C_PAUSE_CONTROL_QUANTA_54 = 0x5C
    REG_60_PAUSE_CONTROL_QUANTA_76 = 0x60

    REG_64_PAUSE_CONTROL_THRESHOLD_10 = 0x64
    REG_68_PAUSE_CONTROL_THRESHOLD_32 = 0x68
    REG_6C_PAUSE_CONTROL_THRESHOLD_54 = 0x6C
    REG_70_PAUSE_CONTROL_THRESHOLD_76 = 0x70

    DEFAULT_PAUSE_CONTROL_QUANTA = 0xFF00
    DEFAULT_PAUSE_CONTROL_THRESHOLD = 0x000F

    @classmethod
    def setup_class(cls):
        cls.security = True
        super(TestFWPauseFrameCfg, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", host=cls.dut_hostname,
                                    drv_type=DRV_TYPE_DIAG)
            cls.dut_driver.install()
            cls.dut_atltool = AtlTool(port=cls.dut_port)
            cls.fw_config = FirmwareA2Config(cls.dut_atltool)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestFWPauseFrameCfg, self).setup_method(method)
        self.dut_atltool.kickstart2()

    @idparametrize("speed", [LINK_SPEED_10M, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G,
                             LINK_SPEED_10G])
    def test_flow_control_driver_interface(self, speed):
        if speed not in self.supported_speeds:
            pytest.skip()
        fc_cfg = PauseQuantaOffload()

        for i in range(8):
            fc_cfg.pause_traffic_class[i].quanta_10M = random.randint(0x2222, 0xFFFF)
            fc_cfg.pause_traffic_class[i].threshold_10M = random.randint(64, 80)
            fc_cfg.pause_traffic_class[i].quanta_100M = random.randint(0x2222, 0xFFFF)
            fc_cfg.pause_traffic_class[i].threshold_100M = random.randint(64, 80)
            fc_cfg.pause_traffic_class[i].quanta_1G = random.randint(0x2222, 0xFFFF)
            fc_cfg.pause_traffic_class[i].threshold_1G = random.randint(64, 80)
            fc_cfg.pause_traffic_class[i].quanta_2P5G = random.randint(0x2222, 0xFFFF)
            fc_cfg.pause_traffic_class[i].threshold_2P5G = random.randint(64, 80)
            fc_cfg.pause_traffic_class[i].quanta_5G = random.randint(0x2222, 0xFFFF)
            fc_cfg.pause_traffic_class[i].threshold_5G = random.randint(64, 80)
            fc_cfg.pause_traffic_class[i].quanta_10G = random.randint(0x2222, 0xFFFF)
            fc_cfg.pause_traffic_class[i].threshold_10G = random.randint(64, 80)

        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(speed)

        self.fw_config.configure_pause_quanta(fc_cfg=fc_cfg, flow_control_mode=True,
                                              out_file_name=os.path.join(self.test_log_dir, "config.txt"))

        self.lkp_ifconfig.wait_link_up()

        quanta_values = []
        quanta_values.append(self.dut_atltool.readmsmreg(self.REG_54_PAUSE_CONTROL_QUANTA_10) & 0xFFFF)
        quanta_values.append((
            self.dut_atltool.readmsmreg(self.REG_54_PAUSE_CONTROL_QUANTA_10) & 0xFFFF0000) >> 16)
        quanta_values.append(self.dut_atltool.readmsmreg(self.REG_58_PAUSE_CONTROL_QUANTA_32) & 0xFFFF)
        quanta_values.append((
            self.dut_atltool.readmsmreg(self.REG_58_PAUSE_CONTROL_QUANTA_32) & 0xFFFF0000) >> 16)
        quanta_values.append(self.dut_atltool.readmsmreg(self.REG_5C_PAUSE_CONTROL_QUANTA_54) & 0xFFFF)
        quanta_values.append((
            self.dut_atltool.readmsmreg(self.REG_5C_PAUSE_CONTROL_QUANTA_54) & 0xFFFF0000) >> 16)
        quanta_values.append(self.dut_atltool.readmsmreg(self.REG_60_PAUSE_CONTROL_QUANTA_76) & 0xFFFF)
        quanta_values.append((
            self.dut_atltool.readmsmreg(self.REG_60_PAUSE_CONTROL_QUANTA_76) & 0xFFFF0000) >> 16)

        threshold_values = []
        threshold_values.append(self.dut_atltool.readmsmreg(self.REG_64_PAUSE_CONTROL_THRESHOLD_10) & 0xFFFF)
        threshold_values.append((
            self.dut_atltool.readmsmreg(self.REG_64_PAUSE_CONTROL_THRESHOLD_10) & 0xFFFF0000) >> 16)
        threshold_values.append(self.dut_atltool.readmsmreg(self.REG_68_PAUSE_CONTROL_THRESHOLD_32) & 0xFFFF)
        threshold_values.append((
            self.dut_atltool.readmsmreg(self.REG_68_PAUSE_CONTROL_THRESHOLD_32) & 0xFFFF0000) >> 16)
        threshold_values.append(self.dut_atltool.readmsmreg(self.REG_6C_PAUSE_CONTROL_THRESHOLD_54) & 0xFFFF)
        threshold_values.append((
            self.dut_atltool.readmsmreg(self.REG_6C_PAUSE_CONTROL_THRESHOLD_54) & 0xFFFF0000) >> 16)
        threshold_values.append(self.dut_atltool.readmsmreg(self.REG_70_PAUSE_CONTROL_THRESHOLD_76) & 0xFFFF)
        threshold_values.append((
            self.dut_atltool.readmsmreg(self.REG_70_PAUSE_CONTROL_THRESHOLD_76) & 0xFFFF0000) >> 16)

        if speed == LINK_SPEED_10M:
            for i in range(8):
                log.info("Check {} traffic class for {} link speed".format(i, speed))
                assert quanta_values[i] == fc_cfg.pause_traffic_class[i].quanta_10M
                assert threshold_values[i] == fc_cfg.pause_traffic_class[i].threshold_10M
        elif speed == LINK_SPEED_100M:
            for i in range(8):
                log.info("Check {} traffic class for {} link speed".format(i, speed))
                assert quanta_values[i] == fc_cfg.pause_traffic_class[i].quanta_100M
                assert threshold_values[i] == fc_cfg.pause_traffic_class[i].threshold_100M
        elif speed == LINK_SPEED_1G:
            for i in range(8):
                log.info("Check {} traffic class for {} link speed".format(i, speed))
                assert quanta_values[i] == fc_cfg.pause_traffic_class[i].quanta_1G
                assert threshold_values[i] == fc_cfg.pause_traffic_class[i].threshold_1G
        elif speed == LINK_SPEED_2_5G:
            for i in range(8):
                log.info("Check {} traffic class for {} link speed".format(i, speed))
                assert quanta_values[i] == fc_cfg.pause_traffic_class[i].quanta_2P5G
                threshold_values[i] == fc_cfg.pause_traffic_class[i].threshold_2P5G
        elif speed == LINK_SPEED_5G:
            for i in range(8):
                log.info("Check {} traffic class for {} link speed".format(i, speed))
                assert quanta_values[i] == fc_cfg.pause_traffic_class[i].quanta_5G
                assert threshold_values[i] == fc_cfg.pause_traffic_class[i].threshold_5G
        elif speed == LINK_SPEED_10G:
            for i in range(8):
                log.info("Check {} traffic class for {} link speed".format(i, speed))
                assert quanta_values[i] == fc_cfg.pause_traffic_class[i].quanta_10G
                assert threshold_values[i] == fc_cfg.pause_traffic_class[i].threshold_10G

    @idparametrize("speed", [LINK_SPEED_10M, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G,
                             LINK_SPEED_10G])
    def test_flow_control_default_settings(self, speed):
        if speed not in self.supported_speeds:
            pytest.skip()
        self.fw_config.set_link_state(LINK_STATE_UP)
        self.fw_config.set_link_speed(speed)
        self.fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
        self.lkp_ifconfig.wait_link_up()

        quanta_values = []
        quanta_values.append(self.dut_atltool.readmsmreg(self.REG_54_PAUSE_CONTROL_QUANTA_10) & 0xFFFF)
        quanta_values.append((
            self.dut_atltool.readmsmreg(self.REG_54_PAUSE_CONTROL_QUANTA_10) & 0xFFFF0000) >> 16)
        quanta_values.append(self.dut_atltool.readmsmreg(self.REG_58_PAUSE_CONTROL_QUANTA_32) & 0xFFFF)
        quanta_values.append((
            self.dut_atltool.readmsmreg(self.REG_58_PAUSE_CONTROL_QUANTA_32) & 0xFFFF0000) >> 16)
        quanta_values.append(self.dut_atltool.readmsmreg(self.REG_5C_PAUSE_CONTROL_QUANTA_54) & 0xFFFF)
        quanta_values.append((
            self.dut_atltool.readmsmreg(self.REG_5C_PAUSE_CONTROL_QUANTA_54) & 0xFFFF0000) >> 16)
        quanta_values.append(self.dut_atltool.readmsmreg(self.REG_60_PAUSE_CONTROL_QUANTA_76) & 0xFFFF)
        quanta_values.append((
            self.dut_atltool.readmsmreg(self.REG_60_PAUSE_CONTROL_QUANTA_76) & 0xFFFF0000) >> 16)

        threshold_values = []
        threshold_values.append(self.dut_atltool.readmsmreg(self.REG_64_PAUSE_CONTROL_THRESHOLD_10) & 0xFFFF)
        threshold_values.append((
            self.dut_atltool.readmsmreg(self.REG_64_PAUSE_CONTROL_THRESHOLD_10) & 0xFFFF0000) >> 16)
        threshold_values.append(self.dut_atltool.readmsmreg(self.REG_68_PAUSE_CONTROL_THRESHOLD_32) & 0xFFFF)
        threshold_values.append((
            self.dut_atltool.readmsmreg(self.REG_68_PAUSE_CONTROL_THRESHOLD_32) & 0xFFFF0000) >> 16)
        threshold_values.append(self.dut_atltool.readmsmreg(self.REG_6C_PAUSE_CONTROL_THRESHOLD_54) & 0xFFFF)
        threshold_values.append((
            self.dut_atltool.readmsmreg(self.REG_6C_PAUSE_CONTROL_THRESHOLD_54) & 0xFFFF0000) >> 16)
        threshold_values.append(self.dut_atltool.readmsmreg(self.REG_70_PAUSE_CONTROL_THRESHOLD_76) & 0xFFFF)
        threshold_values.append((
            self.dut_atltool.readmsmreg(self.REG_70_PAUSE_CONTROL_THRESHOLD_76) & 0xFFFF0000) >> 16)

        for i in range(8):
            log.info("Check {} traffic class".format(i))
            assert quanta_values[i] == self.DEFAULT_PAUSE_CONTROL_QUANTA
            assert threshold_values[i] == self.DEFAULT_PAUSE_CONTROL_THRESHOLD


class TestFlowControl(TestBase):
    LINK_UP_TIME = 10
    IPERF_TIME = 30
    REG_5700_BUFFER_CONTROL = 0x5700
    REG_7100_SCHEDULER_DATA = 0x7100
    REG_08_GENERAL_CONTROL = 0x08
    REG_A8_TX_PAUSE_FRAMES = 0x000000A0
    REG_A8_RX_PAUSE_FRAMES = 0x000000A8
    REG_5714_PACKET_BUFFER = 0x5714
    REG_5714_PACKET_BUFFER_VALUE = 0x80010000
    REG_54_PAUSE_CONTROL_QUANTA = 0x54
    REG_54_PAUSE_CONTROL_QUANTA_VALUE = 0x0
    REG_54_PAUSE_CONTROL_QUANTA_VALUE0 = 0xff00
    REG_54_PAUSE_CONTROL_QUANTA_VALUE1 = 0xef00
    REG_54_PAUSE_CONTROL_QUANTA_VALUE2 = 0xa800
    REG_54_PAUSE_CONTROL_QUANTA_VALUE3 = 0x6200
    REG_58_PAUSE_CONTROL_QUANTA = 0x58
    REG_58_PAUSE_CONTROL_QUANTA_VALUE = 0xff00
    REG_58_PAUSE_CONTROL_QUANTA_VALUE1 = 0xef00
    REG_58_PAUSE_CONTROL_QUANTA_VALUE2 = 0xa800
    REG_60_PAUSE_CONTROL_QUANTA = 0x60
    REG_60_PAUSE_CONTROL_QUANTA_VALUE = 0xff000000
    REG_60_PAUSE_CONTROL_QUANTA_VALUE1 = 0xef000000
    REG_60_PAUSE_CONTROL_QUANTA_VALUE2 = 0xa8000000
    REG_5C_PAUSE_CONTROL_QUANTA = 0x5C
    REG_5C_PAUSE_CONTROL_QUANTA_VALUE = 0xff00
    REG_5C_PAUSE_CONTROL_QUANTA_VALUE1 = 0xef00
    REG_5C_PAUSE_CONTROL_QUANTA_VALUE2 = 0xa800
    REG_64_PAUSE_CONTROL_THRESHOLD = 0x64
    SNIFF_EXEC_TIME = 10
    AFTER_LINK_UP_DELAY = 10
    PING_COUNT = 4
    DUT_IP = "192.168.0.1"
    LKP_IP = "192.168.0.2"
    NETMASK = "255.255.255.0"

    @classmethod
    def setup_class(cls):
        cls.security = True
        super(TestFlowControl, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            # Set up DUT
            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
            cls.dut_driver.install()
            cls.dut_ifconfig.set_ip_address(cls.DUT_IP, cls.NETMASK, None)
            cls.dut_ifconfig.set_link_state(LINK_STATE_UP)
            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.dut_atltool = AtlTool(port=cls.dut_port)
            cls.fw_config = FirmwareA2Config(cls.dut_atltool)

            # Set up LKP
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, None)
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            cls.dut_ifconfig.wait_link_up()
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()
            cls.lkp_atltool = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            cls.REG_64_PAUSE_CONTROL_THRESHOLD_VALUE = 0xf
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestFlowControl, cls).teardown_class()

    def setup_method(self, method):
        super(TestFlowControl, self).setup_method(method)

    def teardown_method(self, method):
        super(TestFlowControl, self).teardown_method(method)

    def setup_registers_pfc(self):
        self.dut_atltool.writereg(self.REG_5714_PACKET_BUFFER, self.REG_5714_PACKET_BUFFER_VALUE)
        msm_reg_val = self.lkp_atltool.readmsmreg(self.REG_08_GENERAL_CONTROL)
        self.lkp_atltool.writemsmreg(self.REG_08_GENERAL_CONTROL, msm_reg_val | 0x80080)
        reg_val = self.lkp_atltool.readreg(self.REG_7100_SCHEDULER_DATA)
        self.lkp_atltool.writereg(self.REG_7100_SCHEDULER_DATA, reg_val | 0x4)
        reg_val = self.lkp_atltool.readreg(self.REG_5700_BUFFER_CONTROL)
        reg_val = (reg_val & 0xffffffef) | 0x20
        self.lkp_atltool.writereg(self.REG_5700_BUFFER_CONTROL, reg_val)

        msm_reg_val = self.dut_atltool.readmsmreg(self.REG_08_GENERAL_CONTROL)
        self.dut_atltool.writemsmreg(self.REG_08_GENERAL_CONTROL, msm_reg_val | 0x80000)
        reg_val = self.dut_atltool.readreg(self.REG_7100_SCHEDULER_DATA)
        self.dut_atltool.writereg(self.REG_7100_SCHEDULER_DATA, reg_val | 0x4)
        reg_val = self.dut_atltool.readreg(self.REG_5700_BUFFER_CONTROL)
        reg_val = (reg_val & 0xffffffef) | 0x20
        self.dut_atltool.writereg(self.REG_5700_BUFFER_CONTROL, reg_val)

    def setting_msm_treshold(self):
        if self.dut_atltool.readreg(0xf4) != 0 and self.dut_atltool.readreg(0xf8) != 0:
            speed = self.lkp_ifconfig.get_link_speed()
            if speed not in [LINK_SPEED_10G, LINK_SPEED_5G]:
                self.dut_atltool.writemsmreg(0x20, 0x00400020)
                self.dut_atltool.writemsmreg(0x1c, 0x00400020)
            else:
                self.dut_atltool.writemsmreg(0x20, 0x0c000600)
                self.dut_atltool.writemsmreg(0x1c, 0x0c000600)

    def test_default_quanta_value(self):
        """
        @description: Check RX/TX PFM counters with default quanta value in 0x54 register.

        @steps:
        1. Configure DUT to send pause frames with default quanta value in 0x5714, 0x54 registers and threshold in 0x64.
        2. Get PFM counter values before traffic.
        3. Run ping from LKP to DUT.
        4. Check PFM counters after traffic.
        5. Check traffic output.

        @result: All checks are passed.

        @duration: 2 minutes.
        """
        if self.sfp and self.sfp.startswith("ETH"):
            pytest.skip("ETH SFP+ modules have unpredicted pause frame processing")
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()

        val = self.dut_atltool.readreg(self.REG_5714_PACKET_BUFFER)
        assert (val & 0x7fffff) != 0
        self.dut_atltool.writereg(self.REG_5714_PACKET_BUFFER, self.REG_5714_PACKET_BUFFER_VALUE)
        msm_reg_val = self.lkp_atltool.readmsmreg(self.REG_08_GENERAL_CONTROL)
        self.lkp_atltool.writemsmreg(self.REG_08_GENERAL_CONTROL, msm_reg_val | 0x80)
        log.info("Sleeping {} seconds util iperf is running".format(self.LINK_UP_TIME))
        time.sleep(self.LINK_UP_TIME)
        register54 = Register(self.dut_atltool.readmsmreg(self.REG_54_PAUSE_CONTROL_QUANTA))
        register64 = Register(self.dut_atltool.readmsmreg(self.REG_64_PAUSE_CONTROL_THRESHOLD))
        assert register54[0x0:0xf] == self.REG_54_PAUSE_CONTROL_QUANTA_VALUE0 # class 0
        assert register54[0x10:0x1f] == self.REG_54_PAUSE_CONTROL_QUANTA_VALUE0 # class 1
        assert register64[0x0:0xf] == self.REG_64_PAUSE_CONTROL_THRESHOLD_VALUE # class 0
        assert register64[0x10:0x1f] == self.REG_64_PAUSE_CONTROL_THRESHOLD_VALUE # class 1
        sniffer = object.__new__(SnifferRemote)
        sniffer.__init__(port=self.lkp_port, timeout=self.SNIFF_EXEC_TIME, host=self.lkp_hostname)
        sniffer.run_async(iface=self.lkp_scapy_iface)
        self.msm_counters = self.dut_atltool.get_msm_counters()
        count_before = self.msm_counters["tx_pfm"]
        self.ping(self.lkp_hostname, self.DUT_IP, self.PING_COUNT)
        sniffed = sniffer.join(timeout=self.PING_COUNT + 5)
        self.msm_counters = self.dut_atltool.get_msm_counters()
        count_after = self.msm_counters["tx_pfm"]
        assert count_after > count_before
        counter = 0
        for p in sniffed:
            if p[0].type == 0x8808:
                counter = counter + 1
                barr = str(p[1])
                quanta = ord(barr[2]) << 8 | ord(barr[3])
                assert quanta in [0, self.REG_54_PAUSE_CONTROL_QUANTA_VALUE0], 'Quanta is not equal \
                    to the bottom value of the register'
        assert counter != 0, 'Packets are not sent'

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_pause_frame_with_different_quanta_and_rate(self, speed):
        """
        @description: Check datapath during sending pause frame with specified quanta and rate.

        @steps:
        1. In loop for each speed in KNOWN_LINK_SPEEDS:
            a. Set link speed and wait for link up.
            b. Starting TCP traffic.
            c. During TCP traffic send pause frames with with specified quanta and rate.
            d. Check that traffic bandwidth slowed down acording specified quanta and rate.

        @result: Traffic bandwidth is correct.

        @duration: 10 minutes.
        """
        max_datapath_map = {
            # Bits per second
            LINK_SPEED_100M: 95244000,
            LINK_SPEED_1G: 950164000,
            LINK_SPEED_2_5G: 2373492000,
            LINK_SPEED_5G: 4747062000,
            LINK_SPEED_10G: 9491574000,
        }

        def get_expected_bandwidth(speed, nof_quantas, nof_pauses_per_second):
            time_per_bit = 1.0 / max_datapath_map[speed]
            time_per_quanta = time_per_bit * 512.0
            sleep_time_per_second = time_per_quanta * nof_quantas * nof_pauses_per_second
            expected_bandwidth = (1.0 - sleep_time_per_second) * max_datapath_map[speed]
            return expected_bandwidth

        if speed == LINK_SPEED_100M and "atlantic2" in self.dut_fw_version:
            pytest.xfail("Hardware problem")

        if speed not in self.supported_speeds:
            pytest.skip("Not supported speed")

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()
        self.setting_msm_treshold()
        self.iptables.clean()

        iperf_args = {
            'direction': DIRECTION_TX,
            'speed': speed,
            'num_threads': 4,
            'num_process': 1,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'is_udp': False,
            'dut': self.dut_hostname,
            'lkp': self.lkp_hostname,
            'dut4': self.DUT_IP,
            'lkp4': self.LKP_IP,
            'time': 40
        }

        exp_bandwidth_map = {
            (LINK_SPEED_100M, 0x4444, 3): get_expected_bandwidth(LINK_SPEED_100M, 0x4444, 3),
            (LINK_SPEED_100M, 0x1111, 25): get_expected_bandwidth(LINK_SPEED_100M, 0x1111, 25),
            (LINK_SPEED_1G, 0x4444, 10): get_expected_bandwidth(LINK_SPEED_1G, 0x4444, 10),
            (LINK_SPEED_1G, 0x2ee0, 50): get_expected_bandwidth(LINK_SPEED_1G, 0x2ee0, 50),
            (LINK_SPEED_2_5G, 0x2ee0, 50): get_expected_bandwidth(LINK_SPEED_2_5G, 0x2ee0, 50),
            (LINK_SPEED_2_5G, 0x5dc0, 50): get_expected_bandwidth(LINK_SPEED_2_5G, 0x5dc0, 50),
            (LINK_SPEED_5G, 0x5dc0, 50): get_expected_bandwidth(LINK_SPEED_5G, 0x5dc0, 50),
            (LINK_SPEED_10G, 0x8888, 50): get_expected_bandwidth(LINK_SPEED_10G, 0x8888, 50),
            (LINK_SPEED_10G, 0xbbbb, 50): get_expected_bandwidth(LINK_SPEED_10G, 0xbbbb, 50),
        }

        for (spd, nof_quantas, pause_frame_rate), expected_bandwidth in exp_bandwidth_map.items():
            if spd != speed:
                continue

            Killer().kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")

            log.info("Checking speed {}, nof quantas {}, pause frame rate {}, expected bandwidth {}".format(
                spd, nof_quantas, pause_frame_rate, expected_bandwidth / 1000000.0))

            iperf = Iperf(**iperf_args)
            iperf.run_async()

            time.sleep(iperf_args["time"] / 4)

            pause_frame_pkt = "0180c200000100000000000088080001{:04x}000000000000000000000000000000000000"\
                "000000000000000000000000000000000000000000000000".format(nof_quantas)
            pfgen = Aqsendp(timeout=iperf_args["time"] / 2, rate=pause_frame_rate,
                            host=self.lkp_hostname, packet=pause_frame_pkt)
            pfgen.run_async()
            pfgen.join()

            if iperf.join() == Iperf.IPERF_OK:
                bands = iperf.get_performance()[0].bandwidth
                bands_before_pauses = bands[3:iperf_args["time"] // 4 - 3]
                bands_during_pauses = bands[iperf_args["time"] // 4 + 3:iperf_args["time"] * 3 // 4 - 3]
                bands_after_pauses = bands[-7:-2]

                log.info("Bands before pauses: {}".format(bands_before_pauses))
                log.info("Bands during pauses: {}".format(bands_during_pauses))
                log.info("Bands after pauses : {}".format(bands_after_pauses))

                if speed == LINK_SPEED_100M:
                    eps = max_datapath_map[speed] / 1000000.0 / 100.0 * 30  # 30% of max datapath
                else:
                    eps = max_datapath_map[speed] / 1000000.0 / 100.0 * 15  # 15% of max datapath
                for band in bands_before_pauses:
                    assert max_datapath_map[speed] / 1000000.0 - eps < band < max_datapath_map[speed] / 1000000.0 + eps
                for band in bands_during_pauses:
                    assert expected_bandwidth / 1000000.0 - eps < band < expected_bandwidth / 1000000.0 + eps
                for band in bands_after_pauses:
                    assert max_datapath_map[speed] / 1000000.0 - eps < band < max_datapath_map[speed] / 1000000.0 + eps
            else:
                raise Exception("Iperf failed")

    def test_pause_frame_opcode(self):
        """
        @description: Check datapath during sending pause frame (opcode != 0x1)

        @steps:
        1. Set link speed and wait for link up.
        2. Starting TCP traffic.
        3. During TCP traffic send pause frames with operation code != 0x1.
        4. Check that traffic bandwidth was not changed.

        @result: Traffic bandwidth was not changed.
        @requirements: FW_FLOW_CONTROL_13
        @duration: 1 minutes.
        """
        speed = self.supported_speeds[-1]
        if self.lkp_fw_card not in FELICITY_CARDS:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        else:
            self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()
        self.setting_msm_treshold()

        iperf_args = {
            'direction': DIRECTION_TX,
            'speed': speed,
            'num_threads': 1,
            'num_process': 1,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'bandwidth': 0,
            'buffer_len': 32768,
            'is_udp': False,
            'dut': self.dut_hostname,
            'lkp': self.lkp_hostname,
            'dut4': self.DUT_IP,
            'lkp4': self.LKP_IP,
            'time': 30
        }
        pause_frame_pkt = "0180c200000100000000000088080002ffff000000000000000000000000000000000000000000000" \
            "000000000000000000000000000000000000000"
        self.iptables.clean()
        performance = []
        for i in range(3):
            Killer().kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")
            time.sleep(0.5)

            iperf = Iperf(**iperf_args)
            iperf.run_async()

            time.sleep(iperf_args["time"] / 4)

            send_pf = Aqsendp(timeout=iperf_args["time"] / 2, rate=200, host=self.lkp_hostname,
                              packet=pause_frame_pkt)
            send_pf.run_async()
            send_pf.join()

            if iperf.join() == Iperf.IPERF_OK:
                performance = iperf.get_performance()
                break

            log.info('>>> IPERF:')
            log.info(performance)
            ban = performance[0].bandwidth
            sp = 0
            for i in xrange(len(ban)):
                if i == int(round(len(ban) / 10)):
                    sp = ban[i]
                if (len(ban) - (len(ban) / 4)) - 2 > i > ((len(ban) / 4) + 2):
                    assert sp - sp * 0.2 < ban[i]

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    @idparametrize("dst", ['multicast', 'unicast'])
    def test_pause_frame_with_iperf(self, speed, dst):
        """
        @description: Compare datapaths with sending pause frames and without it.

        @steps:
        1. In loop for each speed in KNOWN_LINK_SPEEDS:
            a. Set link speed and wait for link up.
            b. Run UDP traffic.
            c. Collect statistic without pause frames.
            d. Run UDP traffic.
            e. During UDP traffic send pause frame flood.
            f. Collect traffic statistic with pause frames.
            g. Compare two collected statistics.

        @result: Check that traffic bandwidth with pause frames is slower.

        @duration: 2 minutes.
        """
        if speed not in self.supported_speeds:
            pytest.skip("Not supported speed")
        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()
        self.setting_msm_treshold()
        iperf_args = {
            'direction': DIRECTION_TX,
            'speed': speed,
            'num_threads': 1,
            'num_process': 1,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'bandwidth': 10000,
            'buffer_len': 1400,
            'window': "128k",
            'is_udp': True,
            'dut': self.dut_hostname,
            'lkp': self.lkp_hostname,
            'dut4': self.DUT_IP,
            'lkp4': self.LKP_IP,
            'time': 40
        }
        self.iptables.clean()
        performance = None
        for i in range(3):
            Killer().kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")
            time.sleep(0.5)

            iperf = Iperf(**iperf_args)
            iperf.run_async()
            if iperf.join() == Iperf.IPERF_OK:
                performance = iperf.get_performance()
                break

        log.info('>>> IPERF BEFORE:')
        log.info(performance)
        ban_before = performance[0].bandwidth

        # Pause packet
        if dst == 'multicast':
            dst_mac = "01:80:c2:00:00:01"
        elif dst == 'unicast':
            dst_mac = self.dut_mac
        else:
            raise Exception('Unknown dst: {}'.format(dst))
        mac = dst_mac.replace(":", "")

        pause_frame_pkt_1 = "0180c2000001{}88080001ffff000000000000000000000000000000000000000000000000000" \
            "000000000000000000000000000000000".format(mac)

        performance = None
        self.msm_counters = self.dut_atltool.get_msm_counters()
        count_before = self.msm_counters["rx_pfm"]
        for i in range(3):
            Killer().kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")
            time.sleep(0.5)
            iperf = Iperf(**iperf_args)
            iperf.run_async()

            time.sleep(iperf_args["time"] / 4)

            send_pf = Aqsendp(timeout=iperf_args["time"] / 2, host=self.lkp_hostname,
                              packet=[pause_frame_pkt_1])
            send_pf.run_async()
            send_pf.join()

            if iperf.join() == Iperf.IPERF_OK:
                performance = iperf.get_performance()
                break

        self.msm_counters = self.dut_atltool.get_msm_counters()
        count_after = self.msm_counters["rx_pfm"]
        assert count_after - count_before > 10000
        log.info('>>> IPERF AFTER:')
        log.info(performance)
        ban_after = performance[0].bandwidth
        if len(ban_before) != len(ban_after):
            if len(ban_before) > len(ban_after):
                ban_before = ban_before[:len(ban_after)]
            else:
                ban_after = ban_after[:len(ban_before)]

        for i in xrange(len(ban_after)):
            if (len(ban_after) - (len(ban_after) / 4)) - 5 > i > ((len(ban_after) / 4) + 5):
                assert ban_after[i] < (ban_before[i] / 1.6)
            if (len(ban_after) - (len(ban_after) / 4)) + 5 < i:
                assert ban_after[i] > 0

    def test_pause_frame_with_zero_quanta(self):
        """
        @description: Check datapath during sending pause frame (quanta = 0)

        @steps:
        1. Set link speed and wait for link up.
        2. Starting TCP traffic.
        3. During TCP traffic send pause frames with zero quanta.
        4. Check that traffic bandwidth was not changed.

        @result: Traffic bandwidth was not changed.
        @requirements: FW_FLOW_CONTROL_14
        @duration: 1 minutes.
        """
        speed = self.supported_speeds[-1]
        if self.lkp_fw_card not in FELICITY_CARDS:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        else:
            self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()
        self.setting_msm_treshold()
        iperf_args = {
            'direction': DIRECTION_TX,
            'speed': speed,
            'num_threads': 1,
            'num_process': 1,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'bandwidth': 0,
            'buffer_len': 32768,
            'is_udp': False,
            'dut': self.dut_hostname,
            'lkp': self.lkp_hostname,
            'dut4': self.DUT_IP,
            'lkp4': self.LKP_IP,
            'time': 30
        }
        pause_frame_pkt = "0180c200000100000000000088080001000000000000000000000000000000000000000000000000000000" \
            "0000000000000000000000000000000000"
        self.iptables.clean()
        performance = []
        for i in range(1):
            Killer().kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")
            time.sleep(0.5)
            iperf = Iperf(**iperf_args)
            iperf.run_async()

            time.sleep(iperf_args["time"] / 4)

            send_pf = Aqsendp(timeout=iperf_args["time"] / 2, rate=200, host=self.lkp_hostname,
                              packet=pause_frame_pkt)
            send_pf.run_async()
            send_pf.join()

            if iperf.join() == Iperf.IPERF_OK:
                performance = iperf.get_performance()
                break

            log.info('>>> IPERF:')
            log.info(performance)
            ban = performance[0].bandwidth
            sp = 0
            for i in xrange(len(ban)):
                if i == int(round(len(ban) / 10)):
                    sp = ban[i]
                if (len(ban) - (len(ban) / 4)) - 2 > i > ((len(ban) / 4) + 2):
                    assert sp - sp * 0.2 < ban[i]

    def test_tx_rx_pfm_counters(self):
        """
        @description: Check RX/TX PFM counters.

        @steps:
        1. Configure DUT to send pause frames with special quanta value in 0x5714 and 0x54 registers.
        2. Get PFM counter values before traffic.
        3. Run UDP traffic.
        4. Configure DUT to send pause frames with zero quanta value in 0x5714 and 0x54 registers.
        5. Run UDP traffic.
        6. Compare PFM counters after traffic with counters before traffic.

        @result: Counters should be equal.

        @duration: 2 minutes.
        """

        thr = 12
        self.setting_msm_treshold()
        self.dut_atltool.writereg(self.REG_5714_PACKET_BUFFER, self.REG_5714_PACKET_BUFFER_VALUE)
        self.dut_atltool.writemsmreg(self.REG_54_PAUSE_CONTROL_QUANTA, self.REG_54_PAUSE_CONTROL_QUANTA_VALUE)

        lkp_rx_pfm_before = self.lkp_atltool.readmsmreg(self.REG_A8_RX_PAUSE_FRAMES)
        dut_tx_pfm_before = self.dut_atltool.readmsmreg(self.REG_A8_TX_PAUSE_FRAMES)
        args = {
            'num_threads': 1,
            'num_process': 1,
            'ipv': 4,
            'buffer_len': 0,
            'is_udp': True,
            'is_eee': False,
            "time": self.IPERF_TIME,
            "speed": LINK_SPEED_10G,
            'lkp': self.lkp_hostname,
            'lkp4': self.LKP_IP,
            'dut4': self.DUT_IP,
        }
        self.iptables.clean()
        Killer().kill("iperf3")
        iperf = Iperf(**args)
        iperf.run()

        lkp_rx_pfm_after = self.lkp_atltool.readmsmreg(self.REG_A8_RX_PAUSE_FRAMES)
        dut_tx_pfm_after = self.dut_atltool.readmsmreg(self.REG_A8_TX_PAUSE_FRAMES)
        assert abs((lkp_rx_pfm_after - lkp_rx_pfm_before) - (dut_tx_pfm_after - dut_tx_pfm_before)) < thr, \
            "TX is not equal to RX"

        self.dut_atltool.writemsmreg(self.REG_54_PAUSE_CONTROL_QUANTA, self.REG_54_PAUSE_CONTROL_QUANTA_VALUE0)
        self.dut_atltool.writemsmreg(self.REG_64_PAUSE_CONTROL_THRESHOLD, self.REG_64_PAUSE_CONTROL_THRESHOLD_VALUE)
        lkp_rx_pfm_before = self.lkp_atltool.readmsmreg(self.REG_A8_RX_PAUSE_FRAMES)
        dut_tx_pfm_before = self.dut_atltool.readmsmreg(self.REG_A8_TX_PAUSE_FRAMES)

        Killer().kill("iperf3")
        iperf.run()

        lkp_rx_pfm_after = self.lkp_atltool.readmsmreg(self.REG_A8_RX_PAUSE_FRAMES)
        dut_tx_pfm_after = self.dut_atltool.readmsmreg(self.REG_A8_TX_PAUSE_FRAMES)
        assert abs((lkp_rx_pfm_after - lkp_rx_pfm_before) - (dut_tx_pfm_after - dut_tx_pfm_before)) < thr, \
            "TX is not equal to RX"

    def test_different_quanta_values(self):
        """
        @description: Check RX/TX PFM counters with different quanta values in 0x54 register.

        @steps:
        1. In loop for different quanta values:
            a. Configure DUT to send pause frames with special quanta value in 0x5714 and 0x54 registers.
            b. Get PFM counter values before traffic.
            c. Run ping from LKP to DUT.
            d. Check PFM counters after traffic.
            e. Check traffic output.

        @result: All checks are passed.

        @duration: 5 minutes.
        """
        self.dut_atltool.writereg(self.REG_5714_PACKET_BUFFER, self.REG_5714_PACKET_BUFFER_VALUE)
        msm_reg_val = self.lkp_atltool.readmsmreg(self.REG_08_GENERAL_CONTROL)
        self.lkp_atltool.writemsmreg(self.REG_08_GENERAL_CONTROL, msm_reg_val | 0x80)
        time.sleep(self.AFTER_LINK_UP_DELAY)
        sniffer = object.__new__(SnifferRemote)
        reg_val = [self.REG_54_PAUSE_CONTROL_QUANTA_VALUE1, self.REG_54_PAUSE_CONTROL_QUANTA_VALUE2,
                   self.REG_54_PAUSE_CONTROL_QUANTA_VALUE3]
        for number in range(3):
            self.dut_atltool.writemsmreg(self.REG_54_PAUSE_CONTROL_QUANTA, reg_val[number])
            register = self.dut_atltool.readmsmreg(self.REG_54_PAUSE_CONTROL_QUANTA)
            sniffer.__init__(port=self.lkp_port, timeout=self.SNIFF_EXEC_TIME, host=self.lkp_hostname)
            sniffer.run_async(iface=self.lkp_scapy_iface)
            self.msm_counters = self.dut_atltool.get_msm_counters()
            count_before = self.msm_counters["tx_pfm"]
            self.ping(self.lkp_hostname, self.DUT_IP, self.PING_COUNT)
            sniffed = sniffer.join(timeout=self.PING_COUNT + 5)
            self.msm_counters = self.dut_atltool.get_msm_counters()

            count_after = self.msm_counters["tx_pfm"]
            assert count_after > count_before
            counter = 0
            for p in sniffed:
                if p[0].type == 0x8808:
                    counter = counter + 1
                    barr = str(p[1])
                    quanta = ord(barr[2]) << 8 | ord(barr[3])
                    assert quanta in [0, register], 'Quanta is not equal to the bottom value of the register'
            assert counter != 0, 'Packets are not sent'

    def test_pfc_different_quanta_values(self):
        """
        @description: Check RX/TX PFM counters with diffrent quanta values in 0x58, 0x60 and 0x5c registers.

        @steps:
        1. In loop for different quanta values in 0x58, 0x60 and 0x5c registers:
            a. Configure DUT to send pause frames with special quanta value in 0x58, 0x60 and 0x5c registers.
            b. Get PFM counter values before traffic.
            c. Run ping from LKP to DUT.
            d. Check PFM counters after traffic.
            e. Check traffic output.

        @result: All checks are passed.

        @duration: 5 minutes.
        """
        self.setup_registers_pfc()
        sniffer = object.__new__(SnifferRemote)
        reg_val_58 = [self.REG_58_PAUSE_CONTROL_QUANTA_VALUE, self.REG_58_PAUSE_CONTROL_QUANTA_VALUE1,
                      self.REG_58_PAUSE_CONTROL_QUANTA_VALUE2]
        reg_val_60 = [self.REG_60_PAUSE_CONTROL_QUANTA_VALUE, self.REG_60_PAUSE_CONTROL_QUANTA_VALUE1,
                      self.REG_60_PAUSE_CONTROL_QUANTA_VALUE2]
        reg_val_62 = [self.REG_5C_PAUSE_CONTROL_QUANTA_VALUE, self.REG_5C_PAUSE_CONTROL_QUANTA_VALUE1,
                      self.REG_5C_PAUSE_CONTROL_QUANTA_VALUE2]
        for number in range(3):
            self.dut_atltool.writemsmreg(self.REG_58_PAUSE_CONTROL_QUANTA, reg_val_58[number])
            register58 = self.dut_atltool.readmsmreg(self.REG_58_PAUSE_CONTROL_QUANTA)
            self.dut_atltool.writemsmreg(self.REG_60_PAUSE_CONTROL_QUANTA, reg_val_60[number])
            register60 = self.dut_atltool.readmsmreg(self.REG_60_PAUSE_CONTROL_QUANTA) >> 16
            self.dut_atltool.writemsmreg(self.REG_5C_PAUSE_CONTROL_QUANTA, reg_val_62[number])
            register5C = self.dut_atltool.readmsmreg(self.REG_5C_PAUSE_CONTROL_QUANTA)
            sniffer.__init__(port=self.lkp_port, timeout=self.SNIFF_EXEC_TIME, host=self.lkp_hostname)
            sniffer.run_async(iface=self.lkp_scapy_iface)
            time.sleep(3)
            self.msm_counters = self.dut_atltool.get_msm_counters()
            count_before = self.msm_counters["tx_pfm"]
            self.ping(self.lkp_hostname, self.DUT_IP, self.PING_COUNT)
            sniffed = sniffer.join(timeout=self.PING_COUNT + 5)
            self.msm_counters = self.dut_atltool.get_msm_counters()

            count_after = self.msm_counters["tx_pfm"]
            assert count_after > count_before
            counter = 0
            for p in sniffed:
                if p[0].type == 0x8808:
                    counter = counter + 1
                    barr = str(p[1])
                    quanta1 = ord(barr[8]) << 8 | ord(barr[9])
                    quanta2 = ord(barr[12]) << 8 | ord(barr[13])
                    quanta3 = ord(barr[18]) << 8 | ord(barr[19])
                    assert quanta1 in [0, register58], 'Quanta is not equal to the bottom value of the register'
                    assert quanta2 in [0, register5C], 'Quanta is not equal to the bottom value of the register'
                    assert quanta3 in [0, register60], 'Quanta is not equal to the bottom value of the register'
            assert counter != 0, 'Packets are not sent'


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
