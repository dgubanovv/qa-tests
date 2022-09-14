import copy
import os
import re
import shutil
import socket
import sys
import time

import pytest
from scapy.all import Ether, IP, UDP, Raw, RandString

from infra.test_base import TestBase, idparametrize
from perf.iperf import Iperf
from perf.iperf_result import IperfResult
from tools import git
from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import (
    LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_AUTO,
    LINK_SPEED_NO_LINK, NFS_SERVER, LINK_STATE_UP, LINK_STATE_DOWN, DIRECTION_RX, DIRECTION_TX, DIRECTION_RXTX,
    MTU_1500, MTU_9000, MTU_4000, MTU_12000)
from tools.driver import Driver
from tools.killer import Killer
from tools.nvidia_board_power import NvidiaBoardPower
from tools.ops import OpSystem
from tools.power import Power
from tools.serial_console import SerialConsole
from tools.tcpdump import Tcpdump
from tools.trafficgen import TrafficStream, TrafficGenerator
from tools.utils import get_atf_logger, str_to_bool

log = get_atf_logger()
SE_SETUP = (str_to_bool(os.environ.get("DUT_SE", "False"))
            and str_to_bool(os.environ.get("LKP_SE", "False")))


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "xavier_test"


class TegraConsole(object):
    TCU_MUXER_REMOTE_PATH = "/storage/export/qa/testing/qnx/tcu_muxer"
    TCU_MUXER_LOCAL_PATH = "/tmp/tcu_muxer"
    TCU_MUXER_OUTPUT = "/tmp/tcu_muxer_output.txt"

    def __init__(self, tegra_console, name="xavier"):
        # download and run tcu_muxer
        cmd = "scp aqtest@{}:{} {} ".format(NFS_SERVER, self.TCU_MUXER_REMOTE_PATH, self.TCU_MUXER_LOCAL_PATH)
        Command(cmd=cmd).run()
        Command(cmd="sudo chmod +x " + self.TCU_MUXER_LOCAL_PATH).run()
        cmd_tcu_muxer = "sudo {} -g 16 -b 15 -d {} > {}".format(
            self.TCU_MUXER_LOCAL_PATH, tegra_console, self.TCU_MUXER_OUTPUT)
        self.tcu_muxer_thread = Command(cmd=cmd_tcu_muxer)
        self.tcu_muxer_thread.run_async()
        tegra_os_console, tegra_hv_console = self.get_tegra_consoles()

        # create consoles
        os_log = "/tmp/{}_os_console.log".format(name)
        hw_log = "/tmp/{}_hv_console.log".format(name)
        self.serial_os_console = SerialConsole(tegra_os_console, path_to_console_log=os_log)
        self.serial_hv_console = SerialConsole(tegra_hv_console, path_to_console_log=hw_log)

    def get_tegra_consoles(self):
        time.sleep(3)
        os_console = ""
        hv_console = ""
        with open(self.TCU_MUXER_OUTPUT) as tcu_muxer_output:
            for line in tcu_muxer_output:
                line = line.strip()
                if "CCPLEX: 0" in line:
                    os_console = line.split()[0].strip()
                if "CCPLEX: 15" in line:
                    hv_console = line.split()[0].strip()
        if os_console == "":
            raise Exception("Can't fined OS console")
        if hv_console == "":
            raise Exception("Can't fined HV console")
        log.info("OS console found on: " + os_console)
        log.info("Hipervisor console found on: " + hv_console)
        return os_console, hv_console

    def close(self):
        self.tcu_muxer_thread.join(0)


class XavierTestBase(TestBase):
    AURIX_CONSOLE = os.environ.get("AURIX_CONSOLE", "/dev/ttyUSB3")
    XAVIER_A_HW_CONSOLE = os.environ.get("XAVIER_A_HW_CONSOLE", "/dev/ttyUSB6")
    XAVIER_B_HW_CONSOLE = os.environ.get("XAVIER_B_HW_CONSOLE", "/dev/ttyUSB2")

    @classmethod
    def setup_class(cls):
        xavier_dut_hostname = os.environ.get("XAVIER_DUT_HOSTNAME", None)
        xavier_lkp_hostname = os.environ.get("XAVIER_LKP_HOSTNAME", None)
        if xavier_dut_hostname is None or xavier_lkp_hostname is None:
            raise Exception

        base_dut_hostname = os.environ.get("DUT_HOSTNAME", None)
        base_lkp_hostname = os.environ.get("LKP_HOSTNAME", None)

        os.environ["DUT_HOSTNAME"] = xavier_dut_hostname
        os.environ["LKP_HOSTNAME"] = xavier_lkp_hostname

        if base_dut_hostname is None:
            base_dut_hostname = socket.gethostname()
        elif base_lkp_hostname is None:
            base_lkp_hostname = socket.gethostname()

        log.info("base_dut_hostname: {}".format(base_dut_hostname))
        log.info("base_lkp_hostname: {}".format(base_lkp_hostname))
        log.info("xavier_dut_hostname: {}".format(xavier_dut_hostname))
        log.info("xavier_lkp_hostname: {}".format(xavier_lkp_hostname))

        test_tool = os.environ.get("TEST_TOOL_VERSION", "LATEST")
        if xavier_dut_hostname not in [base_dut_hostname, base_lkp_hostname]:
            dut_ops = OpSystem(host=xavier_dut_hostname)
            git.clone(test_tool, xavier_dut_hostname)
        if xavier_lkp_hostname not in [base_dut_hostname, base_lkp_hostname]:
            lkp_ops = OpSystem(host=xavier_lkp_hostname)
            git.clone(test_tool, xavier_lkp_hostname)

        if SE_SETUP:
            os.environ["LKP_DRV_VERSION"] = os.environ.get("DUT_DRV_VERSION", None)
            os.environ["LKP_FW_VERSION"] = os.environ.get("DUT_FW_VERSION", None)

        super(XavierTestBase, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            Killer().kill("tcu_muxer")

            # create aurix console
            cls.dut_serial_aurix_console = SerialConsole(cls.AURIX_CONSOLE)

            # create hypervisor consoles
            cls.xavier_a = TegraConsole(cls.XAVIER_A_HW_CONSOLE, "xavier_a")
            cls.xavier_b = TegraConsole(cls.XAVIER_B_HW_CONSOLE, "xavier_b")

            # create board power control
            cls.board_power = NvidiaBoardPower(cls.dut_serial_aurix_console)

            cls.restore_driver_loading(cls.dut_hostname)
            cls.restore_driver_loading(cls.lkp_hostname)

            # reset board
            cls.board_power.aurixreset()
            cls.wait_host_up(cls.dut_hostname)
            cls.wait_host_up(cls.lkp_hostname)

            lkp_is_intel = "intel" in cls.lkp_fw_card.lower()
            cls.skip_lkp_fw_install = lkp_is_intel
            cls.install_firmwares()

            dut_drv_type = os.environ.get("DUT_DRV_TYPE", None)
            lkp_drv_type = os.environ.get("LKP_DRV_TYPE", None)
            cls.dut_driver = Driver(port=cls.dut_port, host=cls.dut_hostname, version=cls.dut_drv_version,
                                    drv_type=dut_drv_type)
            cls.lkp_driver = Driver(port=cls.lkp_port, host=cls.lkp_hostname, version=cls.lkp_drv_version,
                                    drv_type=lkp_drv_type)

            cls.dut_driver.install()
            if not lkp_is_intel:
                cls.lkp_driver.install()
            else:
                cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()
                cmd = "sudo ip addr flush dev {}".format(cls.lkp_iface)
                res = Command(cmd=cmd, host=cls.lkp_hostname).run()
                if res["returncode"] != 0:
                    raise Exception("Failed to flush ip addr for {}".format(cls.lkp_iface))

            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()
            cls.dut_iface = cls.dut_ifconfig.get_conn_name()

            # remove ifaces from bridge
            cls.brctl_delif()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, gateway=None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, gateway=None)
            cls.dut_ifconfig.set_link_state(LINK_STATE_UP)
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            cls.speed = cls.dut_ifconfig.wait_link_up(retry_interval=2)

            # smoke check
            assert cls.ping(from_host=cls.lkp_hostname, to_host=cls.DUT_IPV4_ADDR, number=3)

            # Check FW and Driver
            Command(cmd="sudo ethtool -i {}".format(cls.dut_iface), host=cls.dut_hostname).run()
            Command(cmd="sudo ethtool -i {}".format(cls.lkp_iface), host=cls.lkp_hostname).run()

            cls.iperf_cfg = {
                'direction': DIRECTION_RXTX,
                'speed': LINK_SPEED_10G,
                'num_threads': 1,
                'num_process': 1,
                'time': 27,
                'ipv': 4,
                'buffer_len': 0,
                'is_udp': False,
                'is_eee': False,
                'is_stat': False,
                'lkp4': cls.LKP_IPV4_ADDR,
                'dut4': cls.DUT_IPV4_ADDR,
                'lkp': cls.lkp_hostname,
                'dut': cls.dut_hostname,
            }

        except Exception:
            log.exception("Failed while setting up class")
            raise

    def teardown_method(self, method):
        xavier_a_hv_log = self.xavier_a.serial_hv_console.path_to_console_log
        xavier_b_hv_log = self.xavier_b.serial_hv_console.path_to_console_log
        if not os.path.exists(xavier_a_hv_log):
            self.xavier_a.serial_hv_console.read_from_serial()
        shutil.move(xavier_a_hv_log, self.test_log_dir)
        if not os.path.exists(xavier_b_hv_log):
            self.xavier_b.serial_hv_console.read_from_serial()
        shutil.move(xavier_b_hv_log, self.test_log_dir)

    @classmethod
    def teardown_class(cls):
        cls.xavier_a.close()
        cls.xavier_b.close()

    @classmethod
    def brctl_delif(cls):
        if not SE_SETUP:
            cmd_brctl = "brctl show | grep {0} && sudo brctl delif br0 {0}"
            Command(cmd=cmd_brctl.format(cls.dut_iface), host=cls.dut_hostname).run()
            Command(cmd=cmd_brctl.format(cls.lkp_iface), host=cls.lkp_hostname).run()

    @classmethod
    def cold_restart(cls, host=None):
        if (os.environ.get("XAVIER_DUT_HOSTNAME", False) == host or
                os.environ.get("XAVIER_LKP_HOSTNAME", False) == host):
            cls.xavier_cold_boot()
        else:
            TestBase.cold_restart(host)

        cls.state.skip_reboot = False
        cls.state.update()

    @classmethod
    def xavier_cold_boot(cls):
        Command(cmd="sync", host=cls.dut_hostname).run()
        Command(cmd="sync", host=cls.lkp_hostname).run()

        cls.board_power.power_off()
        time.sleep(10)
        cls.board_power.power_on()

        cls.wait_host_up(cls.dut_hostname)
        cls.wait_host_up(cls.lkp_hostname)

    @classmethod
    def wait_host_up(cls, host, wait_time=120, interval=10):
        attempts = wait_time / interval
        for _ in range(attempts):
            if cls.is_host_alive(host):
                break
            else:
                log.info("Sleeping {} sec...".format(interval))
                time.sleep(interval)
        else:
            raise Exception("DUT is not online, can't perform test")

    def check_hypervisor(self):
        # check xavier_a hypervisor
        xavier_a_hw_out = self.xavier_a.serial_hv_console.read_from_serial()
        log.info("Hypervisor console log:\n{}".format(xavier_a_hw_out))
        assert all("DRIVE Hypervisor" in line for line in xavier_a_hw_out.splitlines())

        # check xavier_b hypervisor
        xavier_b_hw_out = self.xavier_b.serial_hv_console.read_from_serial()
        log.info("Hypervisor console log:\n{}".format(xavier_b_hw_out))
        assert all("DRIVE Hypervisor" in line for line in xavier_b_hw_out.splitlines())

    @staticmethod
    def clear_dmesg(host):
        Command(cmd="sudo dmesg -C", host=host).run()

    @staticmethod
    def check_dmesg(host):
        res = Command(cmd="dmesg | grep atlantic", host=host).run()
        # TODO: Add a more thorough checks
        assert any("enP2p1s0: renamed from" in line for line in res["output"])
        assert not any("error" in line.lower() for line in res["output"])
        assert not any("fault" in line.lower() for line in res["output"])

    @classmethod
    def prevent_driver_loading(cls, host):
        cmd = "sudo sed -i 's/^atlantic/# atlantic/g' /etc/modules"
        Command(cmd=cmd, host=host).run()
        cmd = "echo 'blacklist atlantic' | sudo tee /etc/modprobe.d/blacklist-module.conf ; sync"
        Command(cmd=cmd, host=host).run()

    @classmethod
    def restore_driver_loading(cls, host):
        cmd = "sudo sed -i 's/^# atlantic/atlantic/g' /etc/modules"
        Command(cmd=cmd, host=host).run()
        cmd = "sudo rm /etc/modprobe.d/blacklist-module.conf"
        Command(cmd=cmd, host=host).run()

    def check_driver_not_loaded(self, host):
        res = Command(cmd="lsmod | grep atlantic", host=host).run()
        assert res["returncode"] != 0, 'atlantic module still loaded'
        log.info('Checked atlantic module is not loaded')


class TestXavierPing(XavierTestBase):
    TCPDUMP_START_TIME = 15
    NOF_PINGS = 20

    def test_ping_large_size(self):
        assert self.ping(from_host=self.lkp_hostname, to_host=self.DUT_IPV4_ADDR, number=3, payload_size=19998)

    @idparametrize('mtu_size, payload_size', [
        (MTU_1500, MTU_4000),
        (MTU_9000, MTU_12000)
    ])
    def test_mtu_sanity(self, mtu_size, payload_size):
        self.lkp_ifconfig.set_mtu(mtu_size)

        tcpdump = Tcpdump(host=self.dut_hostname, port=self.dut_port,
                          timeout=self.TCPDUMP_START_TIME + self.NOF_PINGS + 15)
        tcpdump.run_async()
        log.info("Sleeping {} sec. Waiting tcpdump initialisation.".format(self.TCPDUMP_START_TIME))
        time.sleep(15)
        self.ping(from_host=self.lkp_hostname, to_host=self.DUT_IPV4_ADDR,
                  number=self.NOF_PINGS, payload_size=payload_size, timeout=1)
        time.sleep(1)
        packets = tcpdump.join(timeout=self.NOF_PINGS + 10)

        total_len = sum(
            len(p[Raw]) for p in packets
            if IP in p and p[IP].src == self.LKP_IPV4_ADDR and p[IP].dst == self.DUT_IPV4_ADDR)

        assert total_len == payload_size * self.NOF_PINGS

    def get_stat(self):
        stat_cmd = "ethtool -S {}".format(self.dut_iface)
        re_stat = re.compile(".*Queue\[(\d)\]\sInPackets:\s(\d+)")
        res = Command(cmd=stat_cmd, host=self.dut_hostname).run()
        stats = []
        for line in res["output"]:
            m = re_stat.match(line)
            if m is not None:
                q_num, in_pkts = m.groups()
                stats.append(in_pkts)

        return stats

    def test_udp_rss_disabled_single_stream(self):
        iperf_cfg = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10G,
            'bandwidth': 10000,
            'num_threads': 1,
            'num_process': 1,
            'time': 27,
            'ipv': 4,
            'buffer_len': 0,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        before_stat = self.get_stat()
        self.run_iperf(**iperf_cfg)
        after_stat = self.get_stat()

        # InPackets counter of 1 queue is increased by more than 1000
        assert sum(int(q_a) > int(q_b) + 100 for q_b, q_a in zip(before_stat, after_stat)) == 1

    @pytest.mark.xfail()
    def test_udp_rss_disabled_multiple_streams(self):
        iperf_cfg_1 = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_10G,
            'bandwidth': 10000,
            'num_threads': 1,
            'num_process': 1,
            'port': 5201,
            'time': 27,
            'ipv': 4,
            'buffer_len': 0,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        iperf_cfg_2 = copy.deepcopy(iperf_cfg_1)
        iperf_cfg_2["port"] = 5202

        iperf1 = Iperf(**iperf_cfg_1)
        iperf2 = Iperf(**iperf_cfg_2)

        before_stat = self.get_stat()
        iperf1.run_async()
        iperf2.run_async()
        iperf1.join()
        iperf2.join()
        after_stat = self.get_stat()

        # InPackets counters of 2 queues are increased by more than 1000
        assert sum(int(q_a) > int(q_b) + 1000 for q_b, q_a in zip(before_stat, after_stat)) == 2


class TestXavierDriverLoad(XavierTestBase):

    def test_driver_load_sanity_as_module(self):
        self.clear_dmesg(host=self.dut_hostname)
        for i in range(10):
            log.info("Run Driver load sanity as module cycle #{}".format(i))
            self.dut_driver.install()
            self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, gateway=None)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.dut_ifconfig.wait_link_up()
            self.run_iperf(**self.iperf_cfg)
            self.dut_driver.uninstall()
            self.check_hypervisor()
            self.check_dmesg(host=self.dut_hostname)

    def test_driver_load_sanity_built_in(self):
        self.clear_dmesg(host=self.dut_hostname)
        self.dut_driver.install()
        for i in range(10):
            log.info("Run Driver load sanity buit in cycle #{}".format(i))
            self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, gateway=None)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.dut_ifconfig.wait_link_up()
            self.run_iperf(**self.iperf_cfg)
            self.dut_driver.unbind()
            self.dut_driver.bind()
            self.check_hypervisor()
            self.check_dmesg(host=self.dut_hostname)
        self.dut_driver.uninstall()


class TestXavierLinkSanity(XavierTestBase):
    AFTER_LINK_UP_DELAY = 15
    NOF_PINGS = 10

    def run_link_up_sanity(self, dut_speed, lkp_speed, double_disable):
        Command(cmd="brctl show", host=self.dut_hostname).run()

        if not self.supported_speeds:
            raise Exception("Do not know supported speeds")
        if dut_speed != LINK_SPEED_AUTO and dut_speed not in self.supported_speeds:
            pytest.skip()
        if lkp_speed != LINK_SPEED_AUTO and lkp_speed not in self.supported_speeds:
            pytest.skip()

        if dut_speed == LINK_SPEED_AUTO:
            exp_speed = lkp_speed
        else:
            exp_speed = dut_speed

        self.dut_ifconfig.set_link_speed(dut_speed)
        self.lkp_ifconfig.set_link_speed(lkp_speed)

        cur_speed = self.dut_ifconfig.wait_link_up()
        if cur_speed != exp_speed:
            raise Exception("Invalid link speed, current = {}, expected = {}".format(cur_speed, exp_speed))
        time.sleep(self.AFTER_LINK_UP_DELAY)
        assert self.ping(number=self.NOF_PINGS, from_host=self.lkp_hostname, to_host=self.DUT_IPV4_ADDR)

        if double_disable:
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

            cur_speed = self.dut_ifconfig.wait_link_up()
            if cur_speed != exp_speed:
                raise Exception("Invalid link speed, current = {}, expected = {}".format(cur_speed, exp_speed))
            time.sleep(self.AFTER_LINK_UP_DELAY)
            assert self.ping(number=self.NOF_PINGS, from_host=self.lkp_hostname, to_host=self.DUT_IPV4_ADDR)

    # LKP AUTO, DUT X

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_100m_lkp_auto(self):
        self.run_link_up_sanity(LINK_SPEED_100M, LINK_SPEED_AUTO, False)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_1g_lkp_auto(self):
        self.run_link_up_sanity(LINK_SPEED_1G, LINK_SPEED_AUTO, False)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_2_5g_lkp_auto(self):
        self.run_link_up_sanity(LINK_SPEED_2_5G, LINK_SPEED_AUTO, False)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_5g_lkp_auto(self):
        self.run_link_up_sanity(LINK_SPEED_5G, LINK_SPEED_AUTO, False)

    def test_dut_10g_lkp_auto(self):
        self.run_link_up_sanity(LINK_SPEED_10G, LINK_SPEED_AUTO, False)

    # LKP AUTO, DUT X, DOUBLE DISABLE

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_100m_lkp_auto_dd(self):
        self.run_link_up_sanity(LINK_SPEED_100M, LINK_SPEED_AUTO, True)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_1g_lkp_auto_dd(self):
        self.run_link_up_sanity(LINK_SPEED_1G, LINK_SPEED_AUTO, True)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_2_5g_lkp_auto_dd(self):
        self.run_link_up_sanity(LINK_SPEED_2_5G, LINK_SPEED_AUTO, True)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_5g_lkp_auto_dd(self):
        self.run_link_up_sanity(LINK_SPEED_5G, LINK_SPEED_AUTO, True)

    def test_dut_10g_lkp_auto_dd(self):
        self.run_link_up_sanity(LINK_SPEED_10G, LINK_SPEED_AUTO, True)

    # DUT AUTO, LKP X

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_auto_lkp_100m(self):
        self.run_link_up_sanity(LINK_SPEED_AUTO, LINK_SPEED_100M, False)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_auto_lkp_1g(self):
        self.run_link_up_sanity(LINK_SPEED_AUTO, LINK_SPEED_1G, False)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_auto_lkp_2_5g(self):
        self.run_link_up_sanity(LINK_SPEED_AUTO, LINK_SPEED_2_5G, False)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_auto_lkp_5g(self):
        self.run_link_up_sanity(LINK_SPEED_AUTO, LINK_SPEED_5G, False)

    def test_dut_auto_lkp_10g(self):
        self.run_link_up_sanity(LINK_SPEED_AUTO, LINK_SPEED_10G, False)

    # DUT AUTO, LKP X, DOUBLE DISABLE

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_auto_lkp_100m_dd(self):
        self.run_link_up_sanity(LINK_SPEED_AUTO, LINK_SPEED_100M, True)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_auto_lkp_1g_dd(self):
        self.run_link_up_sanity(LINK_SPEED_AUTO, LINK_SPEED_1G, True)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_auto_lkp_2_5g_dd(self):
        self.run_link_up_sanity(LINK_SPEED_AUTO, LINK_SPEED_2_5G, True)

    @pytest.mark.xfail(SE_SETUP, reason="", run=False)
    def test_dut_auto_lkp_5g_dd(self):
        self.run_link_up_sanity(LINK_SPEED_AUTO, LINK_SPEED_5G, True)

    def test_dut_auto_lkp_10g_dd(self):
        self.run_link_up_sanity(LINK_SPEED_AUTO, LINK_SPEED_10G, True)


class TestXavierPromisc(XavierTestBase):
    TCPDUMP_START_TIME = 10

    @idparametrize('state', ['on', 'off'])
    def test_promisc_mode(self, state):
        nof_packets = 10
        if state == 'on':
            conf_state = "Enable"
            exp_packets = nof_packets
        else:
            conf_state = "Disable"
            exp_packets = 0

        self.dut_ifconfig.set_promisc_mode(conf_state)

        lkp_mac = self.lkp_ifconfig.get_mac_address()
        rnd_mac = self.suggest_test_mac_address(str(RandString(10)))
        l2 = Ether(src=lkp_mac, dst=rnd_mac)
        l3 = IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR)
        l4 = UDP(sport=25000, dport=25000)
        raw = Raw(("f" * 40).decode("hex"))
        pkt = l2 / l3 / l4 / raw

        stream = TrafficStream()
        stream.type = TrafficStream.STREAM_TYPE_CONTINUOUS
        stream.nof_packets = nof_packets
        stream.rate = 20
        stream.packets = [pkt]

        generator = TrafficGenerator(host=self.lkp_hostname, port=self.lkp_port)
        generator.add_stream(stream)

        tcpdump = Tcpdump(host=self.dut_hostname, port=self.dut_port,
                          timeout=self.TCPDUMP_START_TIME + nof_packets, nopromisc=True)
        tcpdump.run_async()
        log.info("Sleeping {} sec. Waiting tcpdump initialisation.".format(self.TCPDUMP_START_TIME))
        time.sleep(self.TCPDUMP_START_TIME)
        generator.run()
        time.sleep(1)
        packets = tcpdump.join(timeout=10)

        res_pkts = len([p for p in packets if IP in p and
                        p[IP].src == self.LKP_IPV4_ADDR and p[IP].dst == self.DUT_IPV4_ADDR])
        assert exp_packets == res_pkts, 'Expected {} got {} packets'.format(exp_packets, res_pkts)


class TestXavierIperf(XavierTestBase):
    IPERF_TIME = 30
    STATE_ON = "on"
    STATE_OFF = "off"
    test_results = []

    @classmethod
    def setup_class(cls):
        super(TestXavierIperf, cls).setup_class()

        try:
            # Enable offloads
            offloads_list = ['rx', 'tx', 'tso', 'gro', 'gso', 'lro']
            for offload in offloads_list:
                cls.dut_ifconfig.manage_offloads(offload, cls.STATE_ON)
                cls.lkp_ifconfig.manage_offloads(offload, cls.STATE_ON)

            # Enable flow control
            cls.dut_ifconfig.set_media_options(["flow-control"])
            if "intel" not in cls.lkp_fw_card.lower():
                cls.lkp_ifconfig.set_media_options(["flow-control"])

            cls.speed = cls.dut_ifconfig.wait_link_up(retry_interval=2)
            time.sleep(2)

        except Exception:
            log.exception("Failed while setting up class")
            raise

    def run_iperf_with_result(self, **kwargs):
        speed = kwargs.get('speed', LINK_SPEED_AUTO)
        criterion = kwargs.get('criterion', IperfResult.SANITY)

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        current_link_speed = self.dut_ifconfig.wait_link_up()
        assert current_link_speed != LINK_SPEED_NO_LINK, '{} != {}'.format(current_link_speed, 'NO LINK')

        self.iptables.clean()

        for i in range(3):
            log.info('iperf #{}'.format(i))

            Killer(host=self.dut_hostname).kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")

            iperf = Iperf(**kwargs)
            result = iperf.run()

            if result != Iperf.IPERF_OK:
                continue

            results = iperf.get_performance()
            self.test_results.append(results)

            # print statistics
            for res in results:
                log.info(res)

            # check results
            for res in results:
                res.check(criterion=criterion)

            break
        else:
            self.test_results.append(None)
            raise Exception("Failed to run iperf 3 times")

    def set_offloads(self, state):
        offloads_list = ['rx', 'tx', 'tso', 'gro', 'gso', 'lro']
        for offload in offloads_list:
            self.dut_ifconfig.manage_offloads(offload, state)
        self.dut_ifconfig.wait_link_up(retry_interval=2)
        time.sleep(2)

    def set_mtu(self, mtu):
        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu)
        self.dut_ifconfig.wait_link_up()

    @pytest.fixture()
    def teardown_offloads_on(self):
        yield
        self.set_offloads(self.STATE_ON)

    def check_regression(self):
        results = self.test_results[-2:]
        assert results[0] is not None, 'test has not results'
        assert results[1] is not None, 'test has not results'
        avg_with_offloads = results[0][0].get_metrics()[0][4]
        avg_without_offloads = results[1][0].get_metrics()[0][4]
        log.info('MEAN bandwidths with offloads: {}'.format(avg_with_offloads))
        log.info('MEAN bandwidths withoGet stats:ut offloads: {}'.format(avg_without_offloads))
        assert avg_with_offloads * 1.1 > avg_without_offloads, 'AVG bandwidths with offlads < AVG bandwidths without offloads'

    # TCP TX

    def test_tcp_tx_mtu1500_p1t1(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_tcp_tx_mtu1500_p1t4_w_offlds(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_tcp_tx_mtu1500_p1t4_wo_offlds(self, teardown_offloads_on):
        self.set_mtu(MTU_1500)
        self.set_offloads(self.STATE_OFF)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_offloads_regression_tcp_tx_mtu1500_p1t4(self):
        self.check_regression()

    def test_tcp_tx_mtu9000_p1t1(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_tcp_tx_mtu9000_p1t4(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    # TCP RX

    def test_tcp_rx_mtu1500_p1t1(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_tcp_rx_mtu1500_p1t4_w_offlds(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_tcp_rx_mtu1500_p1t4_wo_offlds(self, teardown_offloads_on):
        self.set_mtu(MTU_1500)
        self.set_offloads(self.STATE_OFF)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_offloads_regression_tcp_rx_mtu1500_p1t4(self):
        self.check_regression()

    def test_tcp_rx_mtu9000_p1t1(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_tcp_rx_mtu9000_p1t4(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 0,
            'is_udp': False,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    # UDP TX

    def test_udp_tx_mtu1500_p1t1_l1450(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 1450,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_tx_mtu1500_p1t4_l1450_w_offlds(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 1450,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_udp_tx_mtu1500_p1t4_l1450_wo_offlds(self, teardown_offloads_on):
        self.set_mtu(MTU_1500)
        self.set_offloads(self.STATE_OFF)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 1450,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_offlds_regression_udp_tx_mtu1500_p1t4_l1450(self):
        self.check_regression()

    def test_udp_tx_mtu1500_p1t1_l8192(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_tx_mtu1500_p1t4_l8192_w_offlds(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_udp_tx_mtu1500_p1t4_l8192_wo_offlds(self, teardown_offloads_on):
        self.set_mtu(MTU_1500)
        self.set_offloads(self.STATE_OFF)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_offlds_regression_udp_tx_mtu1500_p1t4_l8192(self):
        self.check_regression()

    def test_udp_tx_mtu9000_p1t1_l8192(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_tx_mtu9000_p1t4_l8192(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_tx_mtu9000_p1t1_l32768(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 32768,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_tx_mtu9000_p1t4_l32768(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_TX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 32768,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    # UDP RX

    def test_udp_rx_mtu1500_p1t1_l1450(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 1450,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_rx_mtu1500_p1t4_l1450_w_offlds(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 1450,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_udp_rx_mtu1500_p1t4_l1450_wo_offlds(self, teardown_offloads_on):
        self.set_mtu(MTU_1500)
        self.set_offloads(self.STATE_OFF)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 1450,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_offlds_regression_udp_rx_mtu1500_p1t4_l1450(self):
        self.check_regression()

    def test_udp_rx_mtu1500_p1t1_l8192(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_rx_mtu1500_p1t4_l8192_w_offlds(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_udp_rx_mtu1500_p1t4_l8192_wo_offlds(self, teardown_offloads_on):
        self.set_mtu(MTU_1500)
        self.set_offloads(self.STATE_OFF)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf_with_result(**args)

    def test_offlds_regression_udp_rx_mtu1500_p1t4_l8192(self):
        self.check_regression()

    def test_udp_rx_mtu9000_p1t1_l8192(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_rx_mtu9000_p1t4_l8192(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 8192,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_rx_mtu9000_p1t1_l32768(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 32768,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_rx_mtu9000_p1t4_l32768(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 32768,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    #

    def test_udp_rx_mtu1500_p1t1_b0_l32k(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 32768,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_rx_mtu1500_p1t4_b0_l32k(self):
        self.set_mtu(MTU_1500)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 32768,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_rx_mtu9000_p1t1_b0_l32k(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'buffer_len': 32768,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)

    def test_udp_rx_mtu9000_p1t4_b0_l32k(self):
        self.set_mtu(MTU_9000)

        args = {
            'direction': DIRECTION_RX,
            'speed': self.speed,
            'bandwidth': 10000,
            'num_process': 1,
            'num_threads': 4,
            'time': self.IPERF_TIME,
            'buffer_len': 32768,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'ipv': 4,
            'criterion': IperfResult.SANITY,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
        }

        self.run_iperf(**args)


class TestXavierPowerManagement(XavierTestBase):
    @classmethod
    def setup_class(cls):
        super(TestXavierPowerManagement, cls).setup_class()
        try:
            cls.dut_power = Power(host=cls.dut_hostname)

            # replace driver
            res = Command(cmd="modinfo atlantic", host=cls.dut_hostname).run()
            drv_path = ""
            for line in res["output"]:
                m = re.match("filename:\s+(.+)", line)
                if m is not None:
                    drv_path = m.groups()[0]

            dut_drv_file = cls.dut_driver.download()
            cmd = "cd qa-tests/tools && sudo mv {} {}".format(dut_drv_file, drv_path)
            Command(cmd=cmd, host=cls.dut_hostname).run()
            Command(cmd="modinfo atlantic", host=cls.dut_hostname).run()

            if SE_SETUP:
                lkp_drv_file = cls.lkp_driver.download()
                cmd = "cd qa-tests/tools && sudo mv {} {}".format(lkp_drv_file, drv_path)
                Command(cmd=cmd, host=cls.lkp_hostname).run()
                Command(cmd="modinfo atlantic", host=cls.lkp_hostname).run()

        except Exception:
            log.exception("Failed while setting up class")
            raise

    def setup_interface(self):
        # TODO:  modprobe atlantic
        self.wait_host_up(self.dut_hostname)
        self.wait_host_up(self.lkp_hostname)
        self.brctl_delif()
        self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, gateway=None)
        self.lkp_ifconfig.set_ip_address(self.LKP_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, gateway=None)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up(retry_interval=2)
        self.lkp_ifconfig.wait_link_up(retry_interval=2)

    def test_aurix_reset(self):
        for i in range(10):
            log.info("Run aurix reset cycle #{}".format(i))
            self.board_power.aurixreset()
            self.wait_host_up(self.dut_hostname)
            self.wait_host_up(self.lkp_hostname)
            self.setup_interface()
            self.run_iperf(**self.iperf_cfg)
            self.check_hypervisor()

    def test_tegra_reset(self):
        for i in range(10):
            log.info("Run tegra reset cycle #{}".format(i))
            # TODO: DUT Xavier A/B ?
            self.board_power.tegrareset_x2()
            self.wait_host_up(self.dut_hostname)
            self.setup_interface()
            self.run_iperf(**self.iperf_cfg)
            self.check_hypervisor()

    @pytest.mark.skip(msg="Interfaces are unavailable after reboot.")
    def test_linux_reboot(self):
        for i in range(50):
            log.info("Run reboot cycle #{}".format(i))
            self.dut_power.reboot()
            self.wait_host_up(self.dut_hostname)
            self.setup_interface()
            self.run_iperf(**self.iperf_cfg)
            self.check_hypervisor()


class TestXavierLinkUpSpeed(XavierTestBase):
    LINK_UP_COLD_BOOT = 4000
    LINK_UP_KICKSTART = 1500
    LINK_UP_AURIXRESET = 4000
    LINK_DOWN_UP_PAUSE = 1200
    LINK_DOWN_UP_NO_PAUSE = 1200

    @classmethod
    def setup_class(cls):
        super(TestXavierLinkUpSpeed, cls).setup_class()

        if not SE_SETUP:
            pytest.skip(msg="Test only for SE FW")

        try:
            cls.lkp_driver.uninstall()
            cls.dut_driver.uninstall()

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            # Prevent atlantic driver loading
            cls.prevent_driver_loading(cls.dut_hostname)
            cls.prevent_driver_loading(cls.lkp_hostname)
        except Exception:
            log.exception("Failed while setting up class")
            raise

    @classmethod
    def teardown_class(cls):
        super(TestXavierLinkUpSpeed, cls).teardown_class()
        cls.restore_driver_loading(cls.dut_hostname)
        cls.restore_driver_loading(cls.lkp_hostname)

    def configure_interfaces(self):
        self.lkp_driver.install()
        self.lkp_ifconfig.set_ip_address(self.LKP_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, gateway=None)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.wait_link_up(retry_interval=2)

        self.dut_driver.install()
        self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, gateway=None)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up(retry_interval=2)

    def wait_link_up(self, wait_time=15):
        for i in range(wait_time):
            val = self.dut_atltool_wrapper.readreg(0x370) & 0xf20
            if val == 0:
                time.sleep(1)
            else:
                break
        else:
            raise Exception("No link")

    def get_link_up_time(self, atltool_wrapper):
        atltool_wrapper.debug_buffer_enable(True)
        time.sleep(5)
        bin_log_file, txt_log_file = atltool_wrapper.debug_buffer_enable(False)

        shutil.move(bin_log_file, self.test_log_dir)
        shutil.move(txt_log_file, self.test_log_dir)

        time_str = 0
        total_time = float('INF')
        with open(os.path.join(self.test_log_dir, txt_log_file), "r") as mcp_log:
            for line in mcp_log:
                # Find last occurrence of "link up" report
                if "HOST report link up" in line:
                    time_str = line
        if time_str:
            total_time = int(time_str.split(' ')[0]) * 20
        else:
            Exception("Can't retrieve link up time.")

        return total_time

    def test_cold_boot(self):
        exp_time = self.LINK_UP_COLD_BOOT
        times = []
        for i in range(10):
            log.info("cold_boot cycle #{}".format(i))
            self.board_power.power_off()
            log.info("Sleeping 10 sec...")
            time.sleep(10)
            self.board_power.power_on()
            self.wait_host_up(self.dut_hostname)
            self.wait_host_up(self.lkp_hostname)
            self.check_driver_not_loaded(self.dut_hostname)
            self.check_driver_not_loaded(self.lkp_hostname)
            self.wait_link_up(wait_time=30)
            dut_time = self.get_link_up_time(self.dut_atltool_wrapper)
            lkp_time = self.get_link_up_time(self.lkp_atltool_wrapper)
            total_time = min(dut_time, lkp_time)
            times.append(total_time)

        assert max(*times) < exp_time, "Link up times is {}ms, max is more than {}ms".format(times, exp_time)
        log.info("Link up times is {}ms".format(times))

    def test_kickstart(self):
        exp_time = self.LINK_UP_KICKSTART
        times = []
        for i in range(10):
            log.info("kickstart cycle #{}".format(i))
            self.dut_atltool_wrapper.kickstart()
            self.wait_link_up()
            total_time = self.get_link_up_time(self.dut_atltool_wrapper)
            times.append(total_time)

        assert max(*times) < exp_time, "Link up times is {}ms, max is more than {}ms".format(times, exp_time)
        log.info("Link up times is {}ms".format(times))

    def test_aurixreset(self):
        exp_time = self.LINK_UP_AURIXRESET
        times = []
        for i in range(10):
            log.info("aurixreset cycle #{}".format(i))
            self.board_power.aurixreset()
            self.wait_host_up(self.dut_hostname)
            self.wait_host_up(self.lkp_hostname)
            self.check_driver_not_loaded(self.dut_hostname)
            self.check_driver_not_loaded(self.lkp_hostname)
            self.wait_link_up(wait_time=30)
            dut_time = self.get_link_up_time(self.dut_atltool_wrapper)
            lkp_time = self.get_link_up_time(self.lkp_atltool_wrapper)
            total_time = min(dut_time, lkp_time)
            times.append(total_time)

        assert max(*times) < exp_time, "Link up times is {}ms, max is more than {}ms".format(times, exp_time)
        log.info("Link up times is {}ms".format(times))

    def test_link_down_up_pause(self):
        exp_time = self.LINK_DOWN_UP_PAUSE
        times = []
        for i in range(10):
            log.info("link_down_up_pause cycle #{}".format(i))
            self.configure_interfaces()
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            log.info("Sleeping 5 sec...")
            time.sleep(5)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.wait_link_up()
            total_time = self.get_link_up_time(self.dut_atltool_wrapper)
            times.append(total_time)

        assert max(*times) < exp_time, "Link up times is {}ms, max is more than {}ms".format(times, exp_time)
        log.info("Link up times is {}ms".format(times))

    def test_link_down_up_no_pause(self):
        exp_time = self.LINK_DOWN_UP_NO_PAUSE
        times = []
        for i in range(10):
            log.info("link_down_up_no_pause cycle #{}".format(i))
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.wait_link_up(wait_time=30)
            total_time = self.get_link_up_time(self.dut_atltool_wrapper)
            times.append(total_time)

        assert max(*times) < exp_time, "Link up times is {}ms, max is more than {}ms".format(times, exp_time)
        log.info("Link up times is {}ms".format(times))


class TestXavierCollectPerformance(TestXavierIperf):
    IPERF_TIME = 10
    STATE_ON = "on"
    STATE_OFF = "off"
    test_results = []

    def run_iperf(self, **kwargs):
        results = []
        for _ in range(10):
            results.append(super(TestXavierCollectPerformance, self).run_iperf(**kwargs))

        max_avg_result = max(
            [
                (result[0].get_metrics()[0][4], 0)
                if len(result[0].get_metrics()) == 1 else
                (result[0].get_metrics()[0][4], result[0].get_metrics()[1][4])
                for result in results
            ]
        )

        log.info("MAX MEAN RESULT:  bandwidth: {} , lost: {}".format(max_avg_result[0], max_avg_result[1]))
        return results

    def run_iperf_with_result(self, **kwargs):
        try:
            results = self.run_iperf(**kwargs)
            if results:
                self.test_results.append(results[0])
            else:
                self.test_results.append(None)
        except Exception:
            self.test_results.append(None)
            raise


if __name__ == "__main__":
    exec_list = [__file__, "-s", "-v"]
    if len(sys.argv) > 1:
        exec_list.append("-k {}".format(sys.argv[1]))
    pytest.main(exec_list)
