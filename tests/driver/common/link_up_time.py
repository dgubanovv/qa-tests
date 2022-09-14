import csv
import shutil
import enum
import os
import re
import sys
import time
import timeit
qa_tests = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(qa_tests)

import pytest

from infra.test_base import TestBase
from tools import command
from tools import ops
from tools import test_configure
from tools.atltoolper import AtlTool
from tools.driver import Driver
from tools.mcplog.eurdbgtrace import DebugTrace
from tools.statistics import Statistics
from tools.utils import get_atf_logger
from tools.constants import CARD_FIJI, LINK_STATE_UP, LINK_STATE_DOWN, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, \
    LINK_SPEED_AUTO, LINK_SPEED_NO_LINK, LINK_SPEED_100M, WIN_OSES, LINUX_OSES, MAC_OSES, ATF_TOOLS_DIR, \
    LINK_SPEED_1G
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "link_up_time"


class PhyConnectionState(enum.IntEnum):
    INACTIVE = 0x00
    CABLE_DIAGNOSTICS = 0x01
    AUTONEGOTIATION = 0x02
    TRAINING = 0x03
    CONNECTED = 0x04
    AUTONEGOTIATION_BREAK_LINK = 0x05
    TEST_MODE = 0x06
    LOOPBACK_MODE = 0x07
    LOW_POWER_MODE = 0x08
    CONNECTED_WOL_MODE = 0x09
    SYSTEM_CALIBRATING = 0x0A
    CABLE_DISCONNECTED = 0x0B
    RESERVED1 = 0x0C
    RESERVED2 = 0x0D
    RESERVED3 = 0x0E
    INVALID = 0x1F


class TestLinkUpTime(TestBase):
    DEFAULT_LINK_CHECKS = 15
    LINK_UP_TIME_LIMIT = 15  # 15 seconds for tests with long cable

    @classmethod
    def setup_class(cls):
        super(TestLinkUpTime, cls).setup_class()

        cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port)
        cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)
        cls.NETMASK_IPV4 = "255.255.0.0"

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            if cls.dut_fw_card not in CARD_FIJI:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            if cls.lkp_fw_card not in CARD_FIJI:
                cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            if cls.dut_fw_card not in CARD_FIJI and cls.dut_atltool_wrapper.is_secure_chips() and cls.dut_ops.is_linux():
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version,
                                        flashless_fw=cls.dut_fw_version)
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.dut_ifconfig.set_link_state(LINK_STATE_UP)
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)

            cls.network_interface = cls.dut_ifconfig.get_conn_name()
            cls.dut_fw_is_a2 = cls.dut_firmware.is_atlantic2()
            if cls.dut_fw_card != CARD_FIJI:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
                if cls.dut_fw_is_a2:
                    cls.fw_config = FirmwareA2Config(cls.dut_atltool_wrapper)

            cls.dut_statistics = Statistics(port=cls.dut_port)
            cls.lkp_statistics = Statistics(port=cls.lkp_port, host=cls.lkp_hostname)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestLinkUpTime, self).setup_method(method)
        if self.MCP_LOG and self.dut_fw_card != CARD_FIJI:
            self.bin_log_file, self.txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestLinkUpTime, self).teardown_method(method)

        self.dut_atltool_wrapper.read_phy_dbg_buffer(False)

        if self.MCP_LOG and self.dut_fw_card != CARD_FIJI:
            self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

    def get_dut_link_state(self):
        # It was done to speed up link state polling for windows.
        # In previous versions polling of link state was done via WMI device. It worked really slow on
        # slow machines and caused unreliable measuremets
        if ops.OpSystem().is_windows():
            cmd = 'netsh interface show interface "{}"'.format(self.network_interface)
            output = command.Command(cmd=cmd, silent=True).run()["output"]
            reg = re.compile('.*Connect state:\s+([a-zA-Z]+).*')
            result = None
            for line in output:
                match = reg.match(line)
                if match:
                    result = match.group(1)
                    break
            if not result:
                raise Exception("Failed to get connection state for interface {}".format(self.network_interface))
            result = LINK_STATE_UP if result == "Connected" else LINK_STATE_DOWN
        else:
            if  self.dut_ifconfig.get_link_speed() != LINK_SPEED_NO_LINK:
                result = LINK_STATE_UP
            else:
                result = LINK_STATE_DOWN
        return result

    def read_phy_connection_state(self):
        conn_state = (self.dut_atltool_wrapper.readphyreg(0x7, 0xC810) >> 9) & 0b11111
        conn_state = PhyConnectionState(conn_state)
        return conn_state

    def read_states(self, csv_writer, start_time=0.0):
        time = (timeit.default_timer() - start_time) * 1000
        driver_link_state = self.get_dut_link_state()
        if self.dut_fw_is_a2:
            mac_speed = self.fw_config.get_fw_link_speed()
        else:
            mac_speed = self.dut_atltool_wrapper.get_link_speed_2x() if self.dut_fw_card != CARD_FIJI else None
        phy_state = self.read_phy_connection_state().name if self.phy_available else None
        csv_writer.writerow([str(item) for item in (time, phy_state, mac_speed, driver_link_state)])
        return phy_state, mac_speed, driver_link_state

    def read_phy_statistics(self, speed):
        stats = self.dut_statistics.get_phy_statistics()
        if speed not in [LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]:
            stats[Statistics.PHY_SNR_MRG_A] = None
            stats[Statistics.PHY_SNR_MRG_B] = None
            stats[Statistics.PHY_SNR_MRG_C] = None
            stats[Statistics.PHY_SNR_MRG_D] = None
        if speed != LINK_SPEED_10G:
            del stats[Statistics.PHY_CABLE_LEN]

        for k, v in stats.items():
            log.info("{} = {}".format(k, v))

        return stats

    def check_phy_stats_for_errors(self, stats):
        errors_zero = True
        for err_counter in Statistics.PHY_ERROR_STATS:
            if stats[err_counter]:
                log.error("Counter '{}' is not zero: {}".format(err_counter, stats[err_counter]))
        return errors_zero

    def force_phy_role(self, role):
        force_master = 0x3
        force_slave = 0x2
        bits_to_set = force_master if role == "Master" else force_slave
        reg_val = self.dut_atltool_wrapper.readphyreg(0x7, 0x20)
        current_bits = (reg_val >> 0xe) & 0b11
        diff = bits_to_set - current_bits
        new_reg_val = (diff << 0xe) + reg_val
        self.dut_atltool_wrapper.writephyreg(0x7, 0x20, new_reg_val)

    def read_phy_role(self):
        """7.21.14"""
        reg_val = self.dut_atltool_wrapper.readphyreg(0x7, 0x21)
        phy_role_raw = (reg_val >> 14) & 1
        phy_role = "Master" if phy_role_raw == 1 else "Slave"
        return phy_role

    def restart_autoneg(self):
        reg_val = self.dut_atltool_wrapper.readphyreg(0x7, 0x0)
        new_val = reg_val | (1 << 9)
        self.dut_atltool_wrapper.writephyreg(0x7, 0x0, new_val)

    @test_configure.auto_configure_link_speed
    def link_up_time_ifconfig(self, speed, phy_role):
        self.phy_available = True if self.dut_fw_card != CARD_FIJI else False
        timeout = 20
        # In windows PCI is disable when link is down
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.auto = True if speed == LINK_SPEED_AUTO else False

        if self.dut_fw_card == "Felicity":
            try:
                first = self.dut_atltool_wrapper.readphyreg(0x1e, 0xc886)
                time.sleep(1)
                second = self.dut_atltool_wrapper.readphyreg(0x1e, 0xc886)
                if first == second:
                    self.phy_available = False
            except Exception:
                self.phy_available = False

        # speed = (speed if speed != LINK_SPEED_AUTO else self.supported_speeds[-1])
        # if speed not in self.supported_speeds:
                # pytest.xfail()

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        link_speed = self.dut_ifconfig.wait_link_up(retry_interval=2)
        log.info("Link speed {} is up".format(link_speed))
        phy_link_up_times = []
        mac_link_up_times = []
        driver_link_up_times = []
        phy_stats_checks = []
        mac_speeds = []
        driver_speeds = []

        if self.dut_fw_card != CARD_FIJI:
            after_stat_file = os.path.join(self.test_log_dir, "link_up_stats_{}.csv".format(speed))
            after_stat_csv = open(after_stat_file, 'wb')
            after_stat_csv_writer = csv.DictWriter(after_stat_csv, Statistics.PHY_ALL_STATS, delimiter=';',
                                                   quotechar='|', quoting=csv.QUOTE_MINIMAL)
            after_stat_csv_writer.writeheader()

        for num in xrange(self.DEFAULT_LINK_CHECKS):
            log.info('Making link to be down')
            link_up_csv = os.path.join(self.test_log_dir, "link_up_{}_{}.csv".format(speed, num))
            link_up_phy_log = os.path.join(self.test_log_dir, "link_up_phy_log_{}_{}.bin".format(speed, num))

            with open(link_up_csv, 'wb') as csvfile:
                csv_writer = csv.writer(csvfile, delimiter=';', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                csv_writer.writerow(["Time", "PHY state", "MAC speed", "Driver speed"])
                self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
                log.info('Waiting for link to become actually down')
                link_state = self.get_dut_link_state()
                start = timeit.default_timer()
                while link_state != LINK_STATE_DOWN:
                    link_state = self.get_dut_link_state()
                    if (timeit.default_timer() - start) > timeout:
                        break

                log.info('Making link to be up')
                self.dut_ifconfig.set_link_state(LINK_STATE_UP)

                if self.phy_available:
                    self.dut_atltool_wrapper.read_phy_dbg_buffer(True, link_up_phy_log, False)
                    self.force_phy_role(phy_role)
                    self.restart_autoneg()
                start = timeit.default_timer()

                phy_state, mac_speed, driver_link_state = self.read_states(csv_writer, start_time=start)

                if self.phy_available:
                    while phy_state != PhyConnectionState.CONNECTED.name:
                        phy_state, mac_speed, driver_link_state = self.read_states(csv_writer, start_time=start)
                        log.info("Current states: {}; {}; {}".format(phy_state, mac_speed, driver_link_state))
                        assert (timeit.default_timer() - start) < timeout, \
                            "Link is not up during timeout {} seconds".format(timeout)
                    phy_link_up_time = (timeit.default_timer() - start) * 1000
                    log.info("PHY link up time: {} ms".format(phy_link_up_time))
                    phy_link_up_times.append(phy_link_up_time)

                if self.dut_fw_card != CARD_FIJI:
                    while mac_speed == LINK_SPEED_NO_LINK:
                        phy_state, mac_speed, driver_link_state = self.read_states(csv_writer, start_time=start)
                        log.info("Current states: {}; {}; {}".format(phy_state, mac_speed, driver_link_state))
                        assert (timeit.default_timer() - start) < timeout, \
                            "Link is not up during timeout {} seconds".format(timeout)

                    mac_link_up_time = (timeit.default_timer() - start) * 1000
                    mac_link_up_times.append(mac_link_up_time)
                    log.info("MAC link up time: {} ms".format(mac_link_up_time))

                while driver_link_state == LINK_STATE_DOWN:
                    phy_state, mac_speed, driver_link_state = self.read_states(csv_writer, start_time=start)
                    log.info("Current states: {}; {}; {}".format(phy_state, mac_speed, driver_link_state))
                    assert (timeit.default_timer() - start) < timeout, \
                        "Link is not up during timeout {} seconds".format(timeout)

                driver_link_up_time = (timeit.default_timer() - start) * 1000
                driver_link_up_times.append(driver_link_up_time)
                log.info("Driver link up time: {} ms".format(driver_link_up_time))
                log.info("MAC speed: {}".format(mac_speed))
                mac_speeds.append(mac_speed)
                log.info("Driver state: {}".format(driver_link_state))
                driver_speed = self.dut_ifconfig.get_link_speed()
                driver_speeds.append(driver_speed)

            if self.phy_available:
                # Stop collecting binary PHY log and parse it to text
                bin_log, txt_log = self.dut_atltool_wrapper.read_phy_dbg_buffer(False)
                try:
                    DebugTrace(None).parseDebugTrace(None, txt_log, bin_log, "ble", None)
                except:
                    pass

                # Clean-up statistics (clean on read)
                self.dut_statistics.get_phy_statistics()
                time.sleep(5)
                stats = self.read_phy_statistics(driver_speed)
                after_stat_csv_writer.writerow(stats)
                phy_stats_checks.append(self.check_phy_stats_for_errors(stats))

                for k, v in stats.items():
                    if type(v) not in [float, int, long]:
                        # Skip string (and etc) characteristics
                        continue
                    self.send_metric("Link up time info: " + k, "count", v, v, v, 1, "", "")

        if self.dut_fw_card != CARD_FIJI:
            after_stat_csv.close()

        if self.phy_available:
            log.info("PHY link up times: {}".format(phy_link_up_times))
            assert all(item < self.LINK_UP_TIME_LIMIT * 1000 for item in phy_link_up_times), \
                'Sometimes link up time is longer than {} seconds on PHY'.format(self.LINK_UP_TIME_LIMIT)

            assert all(item for item in phy_stats_checks), \
                'Some of the error counters are not zero (see log above for details)'

            self.send_metric("PHY Link up times", "ms",
                             min(phy_link_up_times), max(phy_link_up_times),
                             float(sum(phy_link_up_times)) / float(len(phy_link_up_times)),
                             len(phy_link_up_times), "", "")
        if self.dut_fw_card != CARD_FIJI:
            log.info("MAC link up times: {}".format(mac_link_up_times))
            assert all(item < self.LINK_UP_TIME_LIMIT * 1000 for item in mac_link_up_times), \
                'Sometimes link up time is longer than {} seconds on MAC'.format(self.LINK_UP_TIME_LIMIT)

            self.send_metric("MAC Link up times", "ms",
                             min(mac_link_up_times), max(mac_link_up_times),
                             float(sum(mac_link_up_times)) / float(len(mac_link_up_times)),
                             len(mac_link_up_times), "", "")

        log.info("Driver link up times: {}".format(driver_link_up_times))
        assert all(item < self.LINK_UP_TIME_LIMIT * 1000 for item in driver_link_up_times), \
            'Sometimes link up time is longer than {} seconds in Driver'.format(self.LINK_UP_TIME_LIMIT)

        if self.dut_fw_card != CARD_FIJI:
            self.send_metric("MAC Link up times", "ms",
                             min(driver_link_up_times), max(driver_link_up_times),
                             float(sum(driver_link_up_times)) / float(len(driver_link_up_times)),
                             len(driver_link_up_times), "", "")

    def test_link_up_time_ifconfig_100M_Master(self):
        """Test that 100M link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_100M, phy_role="Master")

    def test_link_up_time_ifconfig_100M_Slave(self):
        """Test that 100M link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_100M, phy_role="Slave")

    def test_link_up_time_ifconfig_1G_Master(self):
        """Test that 1G link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_1G, phy_role="Master")

    def test_link_up_time_ifconfig_1G_Slave(self):
        """Test that 1G link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_1G, phy_role="Slave")

    def test_link_up_time_ifconfig_2_5G_Master(self):
        """Test that 2_5G link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_2_5G, phy_role="Master")

    def test_link_up_time_ifconfig_2_5G_Slave(self):
        """Test that 2_5G link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_2_5G, phy_role="Slave")

    def test_link_up_time_ifconfig_5G_Master(self):
        """Test that 5G link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_5G, phy_role="Master")

    def test_link_up_time_ifconfig_5G_Slave(self):
        """Test that 5G link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_5G, phy_role="Slave")

    def test_link_up_time_ifconfig_10G_Master(self):
        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Skip 10G for Fiji")

        """Test that 10G link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_10G, phy_role="Master")

    def test_link_up_time_ifconfig_10G_Slave(self):
        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Skip 10G for Fiji")

        """Test that 10G link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_10G, phy_role="Slave")

    def test_link_up_time_ifconfig_AUTO_Master(self):
        """Test that AUTO link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_AUTO, phy_role="Master")

    def test_link_up_time_ifconfig_AUTO_Slave(self):
        """Test that AUTO link becomes up in less than 15 seconds using ifconfig."""
        self.link_up_time_ifconfig(speed=LINK_SPEED_AUTO, phy_role="Slave")

    @test_configure.auto_configure_link_speed
    def link_up_time_ping(self, speed):
        """Test that link becomes up in less than 15 seconds using ping from LKP"""
        lkp_os_name = ops.OpSystem(host=self.lkp_hostname).get_name()
        pinging_time = 40  # seconds
        if lkp_os_name in WIN_OSES:
            interval = 1
        else:
            interval = 0.1  # seconds
        pings_to_send = int(pinging_time / interval)
        successful_ping_regex_windows = re.compile(
            '^Reply from {}: bytes=\d+ time[<>=]+([0-9]+)ms TTL=\d+$'.format(self.DUT_IPV4_ADDR)
        )
        successful_ping_regex_linux = re.compile(
            '^\d+ bytes from {}: icmp_seq=\d+ ttl=\d+ time=([0-9.]+) ms$'.format(self.DUT_IPV4_ADDR)
        )
        log.info("LKP OS NAME: {}".format(lkp_os_name))
        if lkp_os_name in WIN_OSES:
            successful_ping_regex = successful_ping_regex_windows

        elif lkp_os_name in LINUX_OSES + MAC_OSES:
            successful_ping_regex = successful_ping_regex_linux

        else:
            raise Exception('Unsupported OS')

        link_up_times = []

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)

        link_speed = self.dut_ifconfig.wait_link_up(retry_interval=2)
        log.info("Link speed {} is up".format(link_speed))
        assert self.ping(self.lkp_hostname, self.DUT_IPV4_ADDR, number=1, timeout=5, interval=interval), \
            "Failed to ping DUT from LKP"
        for _ in xrange(self.DEFAULT_LINK_CHECKS):
            if "centos" in lkp_os_name.lower():
                log.debug("LKP: CentOS detected: Link down and link up to flush receive buffer")
                self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
                self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
                self.lkp_ifconfig.wait_link_up(20)

            # Sleep 10 seconds to make sure that traffic will go on Windows
            time.sleep(10)

            cmd = "cd {} && python ping.py {} --src {} -n {} -t {} -i {} -S 65536".format(
                ATF_TOOLS_DIR, self.DUT_IPV4_ADDR, self.LKP_IPV4_ADDR, pings_to_send, 0.1, interval
            )
            command_obj = command.Command(cmd=cmd, host=self.lkp_hostname)
            command_obj.run_async()
            time.sleep(10)
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            start = timeit.default_timer()
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            link_up_command_exec_time = (timeit.default_timer() - start) * 1000
            log.info("LINK UP COMMAND EXECUTION TIME: {}".format(link_up_command_exec_time))
            log.info("Waiting for ping to be finished")
            result = command_obj.join()
            output = result['output']

            max_ping_time = 10

            ping_lines_begin_index = None
            ping_lines_end_index = None

            for i, line in enumerate(output):
                if successful_ping_regex.match(line):
                    ping_lines_begin_index = i
                    break

            for i, line in enumerate(output[::-1]):
                if successful_ping_regex.match(line):
                    ping_lines_end_index = len(output) - i
                    break

            output_tmp = output[ping_lines_begin_index: ping_lines_end_index]
            output = []
            for line in output_tmp:
                if "Destination Host Unreachable" not in line:
                    output.append(line)

            last_successful_ping_before_link_down = None
            first_successful_ping_after_link_down = None

            for i, line in enumerate(output):
                if not successful_ping_regex.match(line):
                    last_successful_ping_before_link_down = i - 1
                    break

            for i, line in enumerate(output[last_successful_ping_before_link_down + 1:]):
                if successful_ping_regex.match(line):
                    first_successful_ping_after_link_down = i + last_successful_ping_before_link_down + 1
                    break

            first_stable_ping_after_link_down = None

            for i, line in enumerate(output[first_successful_ping_after_link_down:]):
                if successful_ping_regex.match(line) and \
                        float(successful_ping_regex.match(line).group(1)) < max_ping_time:
                    first_stable_ping_after_link_down = i + first_successful_ping_after_link_down
                    break

            is_ping_passed_before_linkdown = True
            nof_too_long_pings_before_link_down = 0

            for line in output[:last_successful_ping_before_link_down + 1]:
                m = successful_ping_regex.match(line)
                if m:
                    if float(m.group(1)) >= max_ping_time:
                        log.warning("Too long ping before link down: {}".format(line))
                        nof_too_long_pings_before_link_down += 1
                else:
                    log.warning("Ping is failed before link down: {}".format(line))
                    is_ping_passed_before_linkdown = False

            is_ping_passed_after_linkup = True
            nof_too_long_pings_after_link_up = 0

            for line in output[first_stable_ping_after_link_down:]:
                m = successful_ping_regex.match(line)
                if m:
                    if float(m.group(1)) >= max_ping_time:
                        log.warning("Too long ping after link up: {}".format(line))
                        nof_too_long_pings_after_link_up += 1
                else:
                    log.warning("Ping is failed after link up: {}".format(line))
                    is_ping_passed_after_linkup = False

            link_up_time_ms = (first_stable_ping_after_link_down - last_successful_ping_before_link_down) * interval
            link_up_time_ms *= 1000
            link_up_time_ms -= link_up_command_exec_time

            log.info("LINK UP TIME: {}".format(link_up_time_ms))
            link_up_times.append(link_up_time_ms)

            assert is_ping_passed_before_linkdown, "There are failed pings before link down"
            assert nof_too_long_pings_before_link_down <= \
                len(output[:last_successful_ping_before_link_down + 1]) * 0.05, \
                "Number of too slow pings before link down is more than 5%"
            assert is_ping_passed_after_linkup, "There are failed pings after link up"
            assert nof_too_long_pings_after_link_up <= \
                len(output[first_stable_ping_after_link_down:]) * 0.05, \
                "Number of too slow pings after link up is more than 5%"

        log.info("LINK UP TIMES: {}".format(link_up_times))
        assert all(item < self.LINK_UP_TIME_LIMIT * 1000 for item in link_up_times), \
            'Sometimes link up time is longer than {} seconds'.format(self.LINK_UP_TIME_LIMIT)
        log.info('Check that all the link up times are less than {} seconds..... OK'.format(self.LINK_UP_TIME_LIMIT))

        self.send_metric("Link up times", "ms",
                         min(link_up_times), max(link_up_times),
                         float(sum(link_up_times)) / float(len(link_up_times)),
                         len(link_up_times), "", "")

    def test_link_up_time_ping_AUTO(self):
        """Checks that the tests could be passed with AUTO link speed"""
        self.link_up_time_ping(speed=LINK_SPEED_AUTO)

    def test_link_up_time_ping_100m(self):
        """Checks that the tests could be passed with 100M link speed"""
        self.link_up_time_ping(speed=LINK_SPEED_100M)

    def test_link_up_time_ping_1000m(self):
        """Checks that the tests could be passed with 1G link speed"""
        self.link_up_time_ping(speed=LINK_SPEED_1G)

    def test_link_up_time_ping_2500m(self):
        """Checks that the tests could be passed with 2.5G link speed"""
        self.link_up_time_ping(speed=LINK_SPEED_2_5G)

    def test_link_up_time_ping_5000m(self):
        """Checks that the tests could be passed with 5G link speed"""
        self.link_up_time_ping(speed=LINK_SPEED_5G)

    def test_link_up_time_ping_10000m(self):
        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Skip 10G for Fiji")

        """Checks that the tests could be passed with 10G link speed"""
        self.link_up_time_ping(speed=LINK_SPEED_10G)


if __name__ == "__main__":
    exec_list = [__file__, "-s", "-v"]
    if len(sys.argv) > 1:
        exec_list.append("-k {}".format(sys.argv[1]))
    pytest.main(exec_list)
