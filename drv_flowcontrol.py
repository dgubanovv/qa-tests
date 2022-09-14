import os
import re
import time

import pytest

from infra.test_base import TestBase, idparametrize
from scapy.all import Ether, Raw
from perf.iperf import Iperf
from perf.iperf_result import IperfResult
from tools.aqpkt import Aqsendp, scapy_pkt_to_aqsendp_str
from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import LINK_STATE_UP, LINK_STATE_DOWN, FELICITY_CARDS, LINK_SPEED_AUTO, ATF_TOOLS_DIR, \
    DIRECTION_TX, KNOWN_LINK_SPEEDS, LINK_SPEED_1G, LINK_SPEED_100M, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_10G, SETUP_PERFORMANCE_LOW
from tools.driver import Driver
from tools.killer import Killer
from tools.scapy_tools import ScapyTools
from tools.sniffer import SnifferRemote
from tools.utils import get_atf_logger
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_flowcontrol"


class TestDrvFlowControl(TestBase):
    """
    @description: The TestDrvFlowControl test is dedicated to verify Driver Flow Control.

    @setup: Two Aquantia devices connected back to back.
    """
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

    @classmethod
    def setup_class(cls):
        super(TestDrvFlowControl, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            if cls.dut_atltool_wrapper.is_secure_chips() and cls.dut_ops.is_linux():
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, flashless_fw=cls.dut_fw_version)
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.dut_ifconfig.wait_link_up()

            cls.lkp_scapy = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_scapy_iface = cls.lkp_scapy.get_scapy_iface()
            log.info("Scapy interface name on LKP = {}".format(cls.lkp_scapy_iface))
            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()

            cls.REG_64_PAUSE_CONTROL_THRESHOLD_VALUE = 0xfef0
            ver_major, ver_minor, ver_release = cls.dut_atltool_wrapper.get_fw_version()
            if (ver_major == 3 and ver_minor == 0 and ver_release >= 152) or \
                    (ver_major == 3 and ver_minor == 1 and ver_release >= 77):
                # Quanta threshold was changed starting from this version
                cls.REG_64_PAUSE_CONTROL_THRESHOLD_VALUE = 0xf

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestDrvFlowControl, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.dut_atltool_wrapper = AtlTool(port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)

    def teardown_method(self, method):
        super(TestDrvFlowControl, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_pause_frame_with_ping(self, speed):
        """
        @description: Check datapath during pause frame flood.

        @steps:
        1. In loop for each speed in KNOWN_LINK_SPEEDS:
            a. Set link speed and wait for link up.
            b. Starting ping from DUT to LKP during 30 seconds.
            c. Sleep 5 seconds.
            d. During ping run pause frame flood from LKP to DUT for 5 seconds.
            e. Finish ping and collect output.
            f. Make sure that last 5 ping requests were successfull.

        @result: Last pings should be passed and no traffic stuck is reproduced.
        @requirements: FW_FLOW_CONTROL_12
        @duration: 2 minutes.
        """
        if speed not in self.supported_speeds:
            pytest.skip("Not supported speed")

        nof_pings = 30

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()

        pfm = "0180c200000100000000000088080001ffff"

        for i in range(1):
            cmd = "cd {} && python ping.py {} --src {} -n {} -i 1".format(
                "tools/", self.LKP_IPV4_ADDR, self.DUT_IPV4_ADDR, nof_pings)
            ping_cmd = Command(cmd=cmd, host=self.dut_hostname)
            ping_cmd.run_async()

            time.sleep(5)

            aqsendp = Aqsendp(timeout=5, rate=200, host=self.lkp_hostname, packet=pfm)
            aqsendp.run()

            res = ping_cmd.join()

            successful_ping_regex_windows = re.compile(
                '^Reply from {}: bytes=\d+ time[<>=]+([0-9]+)ms TTL=\d+$'.format(self.LKP_IPV4_ADDR))
            successful_ping_regex_linux = re.compile(
                '^\d+ bytes from {}: icmp_seq=\d+ ttl=\d+ time=([0-9.]+) ms$'.format(self.LKP_IPV4_ADDR))

            # Determine first and last ping lines for output
            first_ping_line = -1
            last_ping_line = -1

            for i, line in enumerate(res["output"]):
                if line.startswith("PING") or line.startswith("Pinging"):
                    first_ping_line = i + 1
                if "ing statistics" in line:
                    last_ping_line = i - 2
            log.info("First ping line = {}, last ping line = {}".format(first_ping_line, last_ping_line))

            # Using last ping line get latest 5 lines of ping and make sure that they are passed
            last_pings_to_check = res["output"][last_ping_line - 5:last_ping_line]
            for line in last_pings_to_check:
                assert successful_ping_regex_windows.match(line) or successful_ping_regex_linux.match(line)

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
            'dut4': self.DUT_IPV4_ADDR,
            'lkp4': self.LKP_IPV4_ADDR,
            'time': 30
        }
        pause_frame_pkt = "0180c2000001000000000000880800010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
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
            'dut4': self.DUT_IPV4_ADDR,
            'lkp4': self.LKP_IPV4_ADDR,
            'time': 30
        }
        pause_frame_pkt = "0180c200000100000000000088080002ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
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
        if self.setup_performance == SETUP_PERFORMANCE_LOW:
            pytest.skip("This test cannot run on low performance setup")

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

        if speed not in self.supported_speeds:
            pytest.skip("Not supported speed")

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()
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
            'dut4': self.DUT_IPV4_ADDR,
            'lkp4': self.LKP_IPV4_ADDR,
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
                    eps = max_datapath_map[speed] / 1000000.0 / 100.0 * 15  # 15% of max datapath
                else:
                    eps = max_datapath_map[speed] / 1000000.0 / 100.0 * 10  # 10% of max datapath
                for band in bands_before_pauses:
                    assert max_datapath_map[speed] / 1000000.0 - eps < band < max_datapath_map[speed] / 1000000.0 + eps
                for band in bands_during_pauses:
                    assert expected_bandwidth / 1000000.0 - eps < band < expected_bandwidth / 1000000.0 + eps
                for band in bands_after_pauses:
                    assert max_datapath_map[speed] / 1000000.0 - eps < band < max_datapath_map[speed] / 1000000.0 + eps
            else:
                raise Exception("Iperf failed")

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
        if self.lkp_fw_card not in FELICITY_CARDS:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        else:
            self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()
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
            'dut4': self.DUT_IPV4_ADDR,
            'lkp4': self.LKP_IPV4_ADDR,
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

        l2 = Ether(
            src="00:00:00:00:00:00",
            dst=dst_mac,
            type=0x8808
        )
        raw = Raw(
            load='\x00\x01'  # Pause frame
                 '\xff\xff'  # Pause time
                 + '\x00' * 42  # Padding
        )
        pause_frame_pkt = scapy_pkt_to_aqsendp_str(l2 / raw)

        performance = None
        for i in range(3):
            Killer().kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")
            time.sleep(0.5)

            iperf = Iperf(**iperf_args)
            iperf.run_async()

            time.sleep(iperf_args["time"] / 4)

            send_pf = Aqsendp(timeout=iperf_args["time"] / 2, rate=200, host=self.lkp_hostname, packet=pause_frame_pkt)
            send_pf.run_async()
            send_pf.join()

            if iperf.join() == Iperf.IPERF_OK:
                performance = iperf.get_performance()
                break

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

    def get_pause_function(self):
        if self.os.is_windows():
            ps_script = "script.ps1"
            with open(ps_script, "w") as f:
                f.write('$hdr = ([wmiclass]\'root\wmi:MSNdis_ObjectHeader\').CreateInstance()\n\
                         $hdr.Revision = 1\n\
                         $hdr.Type = 0x02\n\
                         $hdr.Size = 0xffff\n\
                         $whdr = ([wmiclass]\'root\wmi:MSNdis_WmiMethodHeader\').CreateInstance()\n\
                         $whdr.Header = $hdr\n\
                         $whdr.PortNumber = 0\n\
                         $whdr.NetLuid = 0\n\
                         $whdr.Padding = 0\n\
                         $whdr.RequestId = 0\n\
                         $whdr.Timeout = 5\n\
                         $adapters = Get-WmiObject -Namespace root\wmi -Class MSNdis_LinkState\n\
                         ForEach  ($a in $adapters) { \n\
                         If ($a.InstanceName.Contains(\'Aquantia\')) {\n\
                         $a.WmiQueryLinkState($whdr).LinkState | grep PauseFunctions\n\
                         break}}')

    def setup_registers_pfc(self):
        self.dut_atltool_wrapper.writereg(self.REG_5714_PACKET_BUFFER, self.REG_5714_PACKET_BUFFER_VALUE)
        msm_reg_val = self.lkp_atltool_wrapper.readmsmreg(self.REG_08_GENERAL_CONTROL)
        self.lkp_atltool_wrapper.writemsmreg(self.REG_08_GENERAL_CONTROL, msm_reg_val | 0x80080)
        reg_val = self.lkp_atltool_wrapper.readreg(self.REG_7100_SCHEDULER_DATA)
        self.lkp_atltool_wrapper.writereg(self.REG_7100_SCHEDULER_DATA, reg_val | 0x4)
        reg_val = self.lkp_atltool_wrapper.readreg(self.REG_5700_BUFFER_CONTROL)
        reg_val = (reg_val & 0xffffffef) | 0x20
        self.lkp_atltool_wrapper.writereg(self.REG_5700_BUFFER_CONTROL, reg_val)

        msm_reg_val = self.dut_atltool_wrapper.readmsmreg(self.REG_08_GENERAL_CONTROL)
        self.dut_atltool_wrapper.writemsmreg(self.REG_08_GENERAL_CONTROL, msm_reg_val | 0x80000)
        reg_val = self.dut_atltool_wrapper.readreg(self.REG_7100_SCHEDULER_DATA)
        self.dut_atltool_wrapper.writereg(self.REG_7100_SCHEDULER_DATA, reg_val | 0x4)
        reg_val = self.dut_atltool_wrapper.readreg(self.REG_5700_BUFFER_CONTROL)
        reg_val = (reg_val & 0xffffffef) | 0x20
        self.dut_atltool_wrapper.writereg(self.REG_5700_BUFFER_CONTROL, reg_val)

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
        if self.sfp and self.sfp.startswith("ETH"):
            pytest.skip("ETH SFP+ modules have unpredicted pause frame processing")
        thr = 12
        self.dut_atltool_wrapper.writereg(self.REG_5714_PACKET_BUFFER, self.REG_5714_PACKET_BUFFER_VALUE)
        self.dut_atltool_wrapper.writemsmreg(self.REG_54_PAUSE_CONTROL_QUANTA, self.REG_54_PAUSE_CONTROL_QUANTA_VALUE)
        lkp_rx_pfm_before = self.lkp_atltool_wrapper.readmsmreg(self.REG_A8_RX_PAUSE_FRAMES)
        dut_tx_pfm_before = self.dut_atltool_wrapper.readmsmreg(self.REG_A8_TX_PAUSE_FRAMES)

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
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
        }

        Killer().kill("iperf3")
        iperf = Iperf(**args)
        iperf.run()

        lkp_rx_pfm_after = self.lkp_atltool_wrapper.readmsmreg(self.REG_A8_RX_PAUSE_FRAMES)
        dut_tx_pfm_after = self.dut_atltool_wrapper.readmsmreg(self.REG_A8_TX_PAUSE_FRAMES)
        assert abs((lkp_rx_pfm_after - lkp_rx_pfm_before) - (dut_tx_pfm_after - dut_tx_pfm_before)) < thr, \
            "TX is not equal to RX"

        self.dut_atltool_wrapper.writemsmreg(self.REG_54_PAUSE_CONTROL_QUANTA, self.REG_54_PAUSE_CONTROL_QUANTA_VALUE0)
        self.dut_atltool_wrapper.writemsmreg(self.REG_64_PAUSE_CONTROL_THRESHOLD, self.REG_64_PAUSE_CONTROL_THRESHOLD_VALUE)
        lkp_rx_pfm_before = self.lkp_atltool_wrapper.readmsmreg(self.REG_A8_RX_PAUSE_FRAMES)
        dut_tx_pfm_before = self.dut_atltool_wrapper.readmsmreg(self.REG_A8_TX_PAUSE_FRAMES)

        Killer().kill("iperf3")
        iperf.run()

        lkp_rx_pfm_after = self.lkp_atltool_wrapper.readmsmreg(self.REG_A8_RX_PAUSE_FRAMES)
        dut_tx_pfm_after = self.dut_atltool_wrapper.readmsmreg(self.REG_A8_TX_PAUSE_FRAMES)
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
        if self.sfp and self.sfp.startswith("ETH"):
            pytest.skip("ETH SFP+ modules have unpredicted pause frame processing")
        self.dut_ifconfig.wait_link_up()
        self.dut_atltool_wrapper.writereg(self.REG_5714_PACKET_BUFFER, self.REG_5714_PACKET_BUFFER_VALUE)
        msm_reg_val = self.lkp_atltool_wrapper.readmsmreg(self.REG_08_GENERAL_CONTROL)
        self.lkp_atltool_wrapper.writemsmreg(self.REG_08_GENERAL_CONTROL, msm_reg_val | 0x80)
        time.sleep(self.AFTER_LINK_UP_DELAY)
        sniffer = object.__new__(SnifferRemote)
        reg_val = [self.REG_54_PAUSE_CONTROL_QUANTA_VALUE1, self.REG_54_PAUSE_CONTROL_QUANTA_VALUE2,
                   self.REG_54_PAUSE_CONTROL_QUANTA_VALUE3]
        for number in range(3):
            self.dut_atltool_wrapper.writemsmreg(self.REG_54_PAUSE_CONTROL_QUANTA, reg_val[number])
            register = self.dut_atltool_wrapper.readmsmreg(self.REG_54_PAUSE_CONTROL_QUANTA)
            sniffer.__init__(port=self.lkp_port, timeout=self.SNIFF_EXEC_TIME, host=self.lkp_hostname)
            sniffer.run_async(iface=self.lkp_scapy_iface)
            self.msm_counters = self.dut_atltool_wrapper.get_msm_counters()
            count_before = self.msm_counters["tx_pfm"]
            self.ping(self.lkp_hostname, self.DUT_IPV4_ADDR, self.PING_COUNT)
            sniffed = sniffer.join(timeout=self.PING_COUNT + 5)
            self.msm_counters = self.dut_atltool_wrapper.get_msm_counters()
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

        self.dut_atltool_wrapper.writereg(self.REG_5714_PACKET_BUFFER, self.REG_5714_PACKET_BUFFER_VALUE)
        msm_reg_val = self.lkp_atltool_wrapper.readmsmreg(self.REG_08_GENERAL_CONTROL)
        self.lkp_atltool_wrapper.writemsmreg(self.REG_08_GENERAL_CONTROL, msm_reg_val | 0x80)
        log.info("Sleeping {} seconds util iperf is running".format(self.LINK_UP_TIME))
        time.sleep(self.LINK_UP_TIME)
        register54 = self.dut_atltool_wrapper.readmsmreg(self.REG_54_PAUSE_CONTROL_QUANTA)
        register64 = self.dut_atltool_wrapper.readmsmreg(self.REG_64_PAUSE_CONTROL_THRESHOLD)
        assert register54 == self.REG_54_PAUSE_CONTROL_QUANTA_VALUE0
        assert register64 == self.REG_64_PAUSE_CONTROL_THRESHOLD_VALUE
        sniffer = object.__new__(SnifferRemote)
        sniffer.__init__(port=self.lkp_port, timeout=self.SNIFF_EXEC_TIME, host=self.lkp_hostname)
        sniffer.run_async(iface=self.lkp_scapy_iface)
        self.msm_counters = self.dut_atltool_wrapper.get_msm_counters()
        count_before = self.msm_counters["tx_pfm"]
        self.ping(self.lkp_hostname, self.DUT_IPV4_ADDR, self.PING_COUNT)
        sniffed = sniffer.join(timeout=self.PING_COUNT + 5)
        self.msm_counters = self.dut_atltool_wrapper.get_msm_counters()
        count_after = self.msm_counters["tx_pfm"]
        assert count_after > count_before
        counter = 0
        for p in sniffed:
            if p[0].type == 0x8808:
                counter = counter + 1
                barr = str(p[1])
                quanta = ord(barr[2]) << 8 | ord(barr[3])
                assert quanta in [0, register54], 'Quanta is not equal to the bottom value of the register'
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
        if self.sfp and self.sfp.startswith("ETH"):
            pytest.skip("ETH SFP+ modules have unpredicted pause frame processing")
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        self.setup_registers_pfc()
        sniffer = object.__new__(SnifferRemote)
        reg_val_58 = [self.REG_58_PAUSE_CONTROL_QUANTA_VALUE, self.REG_58_PAUSE_CONTROL_QUANTA_VALUE1,
                      self.REG_58_PAUSE_CONTROL_QUANTA_VALUE2]
        reg_val_60 = [self.REG_60_PAUSE_CONTROL_QUANTA_VALUE, self.REG_60_PAUSE_CONTROL_QUANTA_VALUE1,
                      self.REG_60_PAUSE_CONTROL_QUANTA_VALUE2]
        reg_val_62 = [self.REG_5C_PAUSE_CONTROL_QUANTA_VALUE, self.REG_5C_PAUSE_CONTROL_QUANTA_VALUE1,
                      self.REG_5C_PAUSE_CONTROL_QUANTA_VALUE2]
        for number in range(3):
            self.dut_atltool_wrapper.writemsmreg(self.REG_58_PAUSE_CONTROL_QUANTA, reg_val_58[number])
            register58 = self.dut_atltool_wrapper.readmsmreg(self.REG_58_PAUSE_CONTROL_QUANTA)
            self.dut_atltool_wrapper.writemsmreg(self.REG_60_PAUSE_CONTROL_QUANTA, reg_val_60[number])
            register60 = self.dut_atltool_wrapper.readmsmreg(self.REG_60_PAUSE_CONTROL_QUANTA) >> 16
            self.dut_atltool_wrapper.writemsmreg(self.REG_5C_PAUSE_CONTROL_QUANTA, reg_val_62[number])
            register5C = self.dut_atltool_wrapper.readmsmreg(self.REG_5C_PAUSE_CONTROL_QUANTA)
            sniffer.__init__(port=self.lkp_port, timeout=self.SNIFF_EXEC_TIME, host=self.lkp_hostname)
            sniffer.run_async(iface=self.lkp_scapy_iface)
            time.sleep(3)
            self.msm_counters = self.dut_atltool_wrapper.get_msm_counters()
            count_before = self.msm_counters["tx_pfm"]
            self.ping(self.lkp_hostname, self.DUT_IPV4_ADDR, self.PING_COUNT)
            sniffed = sniffer.join(timeout=self.PING_COUNT + 5)
            self.msm_counters = self.dut_atltool_wrapper.get_msm_counters()
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
