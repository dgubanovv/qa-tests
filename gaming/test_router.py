import os
import sys
import time

import numpy as np
import pytest

from aq_gaming_base import AqGamingBase
from infra.test_base import idparametrize
from tools.command import Command
from tools.constants import DIRECTION_RX, DIRECTION_TX
from tools.killer import Killer
from tools.log import get_atf_logger
from tools.virtual_network import VirtualHost

if __package__ is None:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    # os.environ["SESSION_ID"] = "36681"  # Define if virtual network is already running on LKP
    os.environ["TEST"] = "gaming"


class Neighbour(VirtualHost):
    def __init__(self, virtual_host, id=0, priority=0):
        super(Neighbour, self).__init__(virtual_host.name, virtual_host.ipv4, virtual_host.ipv6, virtual_host.mac)
        self.id = id
        self.priority = priority

    def __str__(self):
        return "{} {} {} {} {}".format(self.id, self.name, self.ipv4, self.mac, self.priority)


class TestAqRouter(AqGamingBase):
    """
    @description: TestAqRouter is dedicated to verify basic functionality of AQ Gaming Router by running
    AQ Gaming Client on Windows DUT and building and running AQ Router on Ubuntu in virtual network.

    Please pay attention that Router has some stability problems on Ubuntu due to underlying libnl issues.

    @setup: Two Aquantia devices connected back to back. LKP: Linux OS required.
    """

    DEFAULT_ROUTER_PORT = 8080
    DEFAULT_ROUTER_PASSWORD = "password1"

    ROUTER_LOG_PATH = "/tmp/router_test.log"
    ROUTER_REPO = "https://github.com/Aquantia/router.git"
    ROUTER_REPO_BRANCH = "dev"
    ROUTER_LIN_PATH = "/tmp/router"
    ROUTER_SERVICE_LIN_PATH = "{}/src/aqservice".format(ROUTER_LIN_PATH)
    ROUTER_ENV_SCRIPT = "/tmp/ubuntu_env_for_building_aqrouter.sh"
    ROUTER_ENV_SCRIPT_URL = "http://qa-nfs01.rdc-lab.marvell.com/qa/testing/ubuntu_env_for_building_aqrouter.sh"

    Neighbours = []

    @classmethod
    def _update_neighbour_priority(cls, id, priority):
        for neighbour in cls.Neighbours:
            if neighbour.id == id:
                neighbour.priority = priority

    @classmethod
    def _update_neighbour(cls, id, name):
        updated_mac = name.replace("-", ":")[:17].lower()
        for neighbour in cls.Neighbours:
            if neighbour.mac == updated_mac:
                neighbour.id = id
                neighbour.priority = cls.get_neighbour_priority_by_id(id)
                return
        if updated_mac != cls.dut_ifconfig.get_mac_address().lower():
            log.warning("AQRouter reported neighbour which is not found in LOCAL_HOSTS list: {} {}".format(id, name))

    @classmethod
    def setup_class(cls):
        super(TestAqRouter, cls).setup_class()
        cls.aqrouter_build()

    @classmethod
    def run_lkp_command(cls, cmd, description="", timeout=30, raise_if_failed=True):
        res = Command(cmd=cmd, host=cls.lkp_hostname).run_join(timeout)
        if raise_if_failed and res["returncode"] != 0:
            raise Exception("'{}' failed on LKP".format(description if description else cmd))
        return res

    @classmethod
    def aqrouter_build(cls):
        cls.run_lkp_command("sudo rm -rf {}".format(cls.ROUTER_LIN_PATH))
        cls.run_lkp_command(cmd="git clone '{link}' -b {branch} {path}".format(path=cls.ROUTER_LIN_PATH,
                                                                               link=cls.ROUTER_REPO,
                                                                               branch=cls.ROUTER_REPO_BRANCH))
        cls.run_lkp_command("wget -O {} \"{}\"".format(cls.ROUTER_ENV_SCRIPT, cls.ROUTER_ENV_SCRIPT_URL))
        cls.run_lkp_command("chmod +x {}".format(cls.ROUTER_ENV_SCRIPT))
        cls.run_lkp_command("sudo {}".format(cls.ROUTER_ENV_SCRIPT), timeout=300)
        cls.run_lkp_command("cd {}/src && make".format(cls.ROUTER_LIN_PATH))
        cls.run_lkp_command("sudo cp {}/files/*.pem /etc/ssl/".format(cls.ROUTER_LIN_PATH))

    def aqrouter_set_password(cls, password):
        cls.run_lkp_command("sudo echo -e \"[general] \\npassword = {}\" > /tmp/aqservice.conf".format(password))

    def aqrouter_start(self, port=DEFAULT_ROUTER_PORT, password=DEFAULT_ROUTER_PASSWORD):
        self.aqrouter_set_password(password)
        cmd = "bash -c '{exe} -d eth0 -o eth1 -p {port} -s -c /tmp/aqservice.conf -a {addr} 2> {log}'".format(
            exe=self.ROUTER_SERVICE_LIN_PATH, port=port, addr=self.DUT_IP4_GATEWAY, log=self.ROUTER_LOG_PATH)
        self.lkp_virtual_network.virtual_cmd(name=self.VIRTUAL_ROUTER.name, cmd=cmd).run_async()

    def aqrouter_stop(self):
        self.lkp_virtual_network.virtual_cmd(name=self.VIRTUAL_ROUTER.name, cmd="pkill -TERM aqservice").run_join(5)
        Killer(host=self.lkp_hostname).kill("aqservice")
        self.virtual_network_clear_shaping()

    def aqrouter_restart(self, port=DEFAULT_ROUTER_PORT, password=DEFAULT_ROUTER_PASSWORD):
        self.aqrouter_stop()
        self.aqrouter_start(port, password)
        self.aqgaming_idle(5)

    def aqrouter_is_connected(self):
        return self.aqgaming.getParameter(self.aqgaming.AQCOMM_PARAM_ROUTER_SERVICE_STATUS) == 0

    def aqgaming_set_router_port(self, port):
        self.aqgaming.setParameter(self.aqgaming.AQCOMM_PARAM_ROUTER_PORT, port)

    def aqgaming_set_router_password(self, password):
        self.aqgaming.setString(self.aqgaming.AQCOMM_STRING_ROUTER_PASSWORD, password)

    def aqgaming_connect_to_router(self, port=DEFAULT_ROUTER_PORT, password=DEFAULT_ROUTER_PASSWORD):
        self.aqgaming_set_router_port(port)
        self.aqgaming_set_router_password(password)
        # TODO: add '17' parameter to aqgaming wrapper as named Constant
        self.aqgaming.setParameter(17, 1)
        self.aqgaming_deactivate()
        self.aqgaming_activate()
        self.aqgaming_idle(5)
        return self.aqrouter_is_connected()

    def aqrouter_get_log(self):
        return self.run_lkp_command(cmd="cat {}".format(self.ROUTER_LOG_PATH), timeout=5)["output"]

    def skip_if_line_in_router_log(self, line):
        grep = self.run_lkp_command(cmd="grep \"{line}\" {log}".format(line=line, log=self.ROUTER_LOG_PATH),
                                    timeout=5, raise_if_failed=False)
        if grep["returncode"] == 0:
            log.error("Router often has problems on Linux, if zero attempts pass - RECHECK MANUALLY on physical setup!")
            pytest.skip("CHECK MANUALLY! Skipped because router '{}'".format(line))

    def setup_method(self, method):
        super(TestAqRouter, self).setup_method(method)
        self.virtual_network_clear_shaping()
        self.aqgaming.setNeighbourPriorityCallback(self.neighbour_priority_callback)
        self.aqgaming.setNeighbourNameCallback(self.neighbour_name_callback)

        del self.Neighbours[:]
        for host in self.LOCAL_HOSTS:
            self.Neighbours.append(Neighbour(host, self.lkp_virtual_network))

        # TODO: investigate why ping helps tests pass
        Command(cmd="ping {}".format(self.REMOTE_HOSTS[0].ipv4)).run()

    def teardown_method(self, method):
        super(TestAqRouter, self).teardown_method(method)
        self.aqrouter_stop()
        self.aqrouter_get_log()

    def start_remote_iperf(self, exec_time, dut_name, dut_address, lkp_name, port=5201, direction=DIRECTION_RX,
                           iperf_bin="iperf3", traffic=AqGamingBase.TCP, threads=1):
        traffic_args = {self.TCP: "-P {}".format(threads),
                        self.TCP_NOT_FRAG: "-P {} -l 1K".format(threads),
                        self.UDP: "-u -b 10G -l 60K -w 64K",
                        self.UDP_NOT_FRAG: "-u -b 10G -l 1K"}
        client_cmd_str = \
            "iperf3 --json -i 1 {} -t {} -c {} -4 -p {}".format(traffic_args[traffic], exec_time, dut_address, port)
        if direction == DIRECTION_TX:
            client_cmd_str += " -R"
        client_cmd = self.lkp_virtual_network.virtual_cmd(lkp_name, client_cmd_str, silent=True)

        server_cmd_str = "{} --json -s -4 -1 -p {}".format(iperf_bin, port)
        server_cmd = self.lkp_virtual_network.virtual_cmd(dut_name, server_cmd_str, silent=True)

        server_cmd.run_async()
        time.sleep(5)
        client_cmd.run_async()

        return server_cmd, client_cmd

    @staticmethod
    def neighbour_priority_callback(id, priority):
        log.info("Neighbour {} has {} priority".format(id, priority))
        TestAqRouter._update_neighbour_priority(id, priority)

    @staticmethod
    def neighbour_name_callback(id, name):
        log.info("Neighbour {} has {} name".format(id, name))
        TestAqRouter._update_neighbour(id, name)

    @classmethod
    def get_neighbour_priority_by_id(cls, id):
        priority = cls.aqgaming.getParameter(id)
        cls._update_neighbour_priority(id, priority)
        return priority

    def get_neighbour_priority(self, neighbour):
        return self.get_neighbour_priority_by_id(neighbour.id)

    def set_neighbour_priority(self, neighbour, priority):
        self.aqgaming.setParameter(neighbour.id, priority)
        assert self.get_neighbour_priority(neighbour) == priority, \
            "failed to set priority {} for neighbour {}".format(priority, neighbour.name)

    def startup(self):
        self.aqrouter_start()
        self.aqgaming_clientRegister()
        self.aqgaming_activate()
        self.aqgaming_connect_to_router()
        assert self.aqrouter_is_connected()

    def test_connection_to_router(self):
        """
        @description: Verify that AQ Router accepts connections with correct passwords.

        @steps:
        1. Open AQGaming client.
        2. Turn on AQGaming client.
        3. Make sure client cannot connect to turned off Router.
        4. Start AQ Router service.
        5. Make sure client cannot connect ro router with wrong port/password.
        6. Make sure connection established when correct port/password entered.
        7. Make sure client still cannot connect ro router with wrong port/password.
        8. Restart AQ Router service with new port/password
        9. Make sure client can connect to Router with new port/password.

        @result: AQ Router should accept correct connections and decline wrong port/passwords.
        @duration: 1 minute (for each set of parameters).
        """
        port = 8083
        password = "qwerty"

        self.aqgaming_clientRegister()
        self.aqgaming_activate()
        assert not self.aqrouter_is_connected(), "Router is not active, but client reported that it has connected"

        self.aqrouter_start()
        assert not self.aqgaming_connect_to_router(port, password), \
            "Client connected to router with wrong port/password"
        assert self.aqgaming_connect_to_router(self.DEFAULT_ROUTER_PORT, self.DEFAULT_ROUTER_PASSWORD), \
            "Client failed to connect to router with correct port/password"
        assert not self.aqgaming_connect_to_router(port, password), \
            "Client connected to router with wrong port/password"

        self.aqrouter_restart(port, password)
        assert self.aqgaming_connect_to_router(port, password), \
            "Client failed to connect to router with correct port/password"
        assert not self.aqgaming_connect_to_router(self.DEFAULT_ROUTER_PORT, self.DEFAULT_ROUTER_PASSWORD), \
            "Client connected to router with wrong port/password"

    @idparametrize("traffic", [AqGamingBase.TCP, AqGamingBase.UDP_NOT_FRAG, AqGamingBase.TCP_NOT_FRAG])
    def test_router_enables_shaper(self, traffic):
        """
        @description: Verify that AQ Router enables shaper for neighbours traffic.

        @steps:
        1. Open AQGaming client.
        2. Turn on AQGaming client.
        3. Connect client to Aq Router.
        4. Start iperf between neighbour in local network (LPC1) and remote network PC (RPC1).
        5. Wait for 30 seconds and Set shaper values to 100 Mbit/s.
        6. Wait for 30 seconds and set shaper values to 300 Mbit/s.
        7. Make sure there was no performance degradation on first interval without shaper.
        8. Make sure neighbours traffic was shaped correctly on second and third intervals.

        @result: AQ Router should not drop link performance and correctly apply shaper to neighbours traffic.
        @duration: 2 minutes (for each set of parameters).
        """
        self.startup()

        iperf_time = 90
        shaper_value = [100, 300]
        link_speed = 1000

        dut_cmd, lkp_cmd = self.start_remote_iperf(iperf_time, self.LOCAL_HOSTS[0].name, self.LOCAL_HOSTS[0].ipv4,
                                                   self.REMOTE_HOSTS[0].name, traffic=traffic)
        self.aqgaming_connect_to_router()
        self.aqgaming_idle(iperf_time / 3)
        self.aqgaming_set_shaper_settings(shaper_value[0], shaper_value[0])
        self.aqgaming_idle(iperf_time / 3)
        self.aqgaming_set_shaper_settings(shaper_value[1], shaper_value[1])
        self.aqgaming_idle(iperf_time / 3)
        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        speed_full = np.average(server_speeds[:30])
        speed_first = np.average(server_speeds[40:60])
        speed_second = np.average(server_speeds[70:90])

        log.info(speed_full)
        log.info(speed_first)
        log.info(speed_second)

        self.assert_no_performance_degradation(link_speed, server_speeds[:30], "Router")
        self.assert_speed_is_shaped(shaper_value[0], server_speeds[40:60])
        self.assert_speed_is_shaped(shaper_value[1], server_speeds[70:90])

    def test_router_detects_neighbour(self):
        """
        @description: Verify that AQ Router detects neighbour in local network and reports its MAC and priority.

        @steps:
        1. Open AQGaming client.
        2. Turn on AQGaming client.
        3. Connect client to Aq Router.
        4. Start iperf between neighbour in local network (LPC1) and remote network PC (RPC1).
        5. Make sure AQ Router assigned ID and Priority for LPC1.

        @result: AQ Router should assign ID and Priority for neighbour which is running traffic.
        @duration: 1 minute (for each set of parameters).
        """
        self.startup()

        iperf_time = 20
        dut_cmd, lkp_cmd = self.start_remote_iperf(iperf_time, self.Neighbours[0].name, self.Neighbours[0].ipv4,
                                                   self.REMOTE_HOSTS[0].name)
        self.aqgaming_connect_to_router()
        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        assert self.Neighbours[0].id, "Router has not assigned ID to neighbour"
        assert self.Neighbours[0].priority, "Router has not assigned priority to Neighbour"

    @idparametrize("attempt", [1, 2, 3])
    @idparametrize("neighbour_priority", [1, 2, 4])
    @idparametrize("gaming_priority", [1, 2, 3, 4])
    def test_prioritization(self, attempt, neighbour_priority, gaming_priority):
        """
        @description: Verify that AQ Router can prioritize Gaming Client (DUT) and Neighbour (LPC1) traffic.
        Notice: you cannot change priorities on the fly due to libnl issues on Ubuntu, so first set up priorities and
        only then start router and run test.

        @steps:
        1. Open AQGaming client.
        2. Turn on AQGaming client.
        3. Set shaper settings to 100 Mbit/s.
        4. Start iperf between Gaming client (DUT) and RPC1.
        5. Start iperf between Neighbour (LPC1) and RPC2.
        6. Set <gaming_priority> to iperf running on DUT.
        7. Start AQ Router and connect client to it.
        8. Set <neighbour_priority> at Router for iperf running on Neighbour (LPC1).
        9. Observe iperfs performances.

        @result: AQ Router should prioritize Gaming client and DUT traffic according to set up priorities.
        @duration: 1.5 minute (for each set of parameters).
        """
        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        shaper_value = 100
        self.aqgaming_set_shaper_settings(shaper_value, shaper_value)

        iperf_time = 60
        dut_cmd, lkp_cmd = self.start_iperf(iperf_time, self.DUT_IP4, self.REMOTE_HOSTS[1].name, threads=1)
        lpc1_cmd, rpc1_cmd = self.start_remote_iperf(iperf_time, self.Neighbours[0].name, self.Neighbours[0].ipv4,
                                                     self.REMOTE_HOSTS[0].name)

        self.aqgaming_set_app_priority_by_name("IPERF3", gaming_priority)
        self.aqrouter_start()
        assert self.aqgaming_connect_to_router()
        self.set_neighbour_priority(self.Neighbours[0], neighbour_priority)
        self.aqgaming_idle(iperf_time)

        neighbour_speeds = self.collect_iperf(lpc1_cmd, rpc1_cmd)
        dut_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        for speed in neighbour_speeds:
            log.info("neighbour_speed: {}".format(speed / 1000000))
        for speed in dut_speeds:
            log.info("dut_speeds: {}".format(speed / 1000000))

        neighbour_average = np.average(neighbour_speeds[20:]) / 1000000
        dut_average = np.average(dut_speeds[20:]) / 1000000
        log.info("neighbour priority: {} average speed: {}".format(self.get_neighbour_priority(self.Neighbours[0]),
                                                                   neighbour_average))
        log.info("dut average: {}".format(dut_average))

        # anyway, there could be some extra factors which can affect libnl and router,
        # so skip test if router could not set priority for neighbour
        self.skip_if_line_in_router_log("Failed to add mac rule")

        # lower number = higher priority
        if neighbour_priority <= gaming_priority:
            assert neighbour_average > dut_average * self.BANDWIDTH_PRIORITY_RATIO, \
                "Neighbour has higher priority, but its performance is lower than Gaming client's"
            return
        assert dut_average > neighbour_average * self.BANDWIDTH_PRIORITY_RATIO, \
            "Gaming client has higher priority, but its performance is lower than neighbour's"

    @idparametrize("lpc1_priority", [1, 2, 4])
    @idparametrize("lpc2_priority", [1, 2, 4])
    def test_neighbours_prioritization(self, lpc1_priority, lpc2_priority):
        """
        @description: Verify that AQ Router can prioritize traffic of two neighbours.

        @steps:
        1. Open AQGaming client.
        2. Turn on AQGaming client.
        3. Set shaper settings to 100 Mbit/s.
        4. Start iperf between Neighbour1 (LPC1) and RPC1.
        5. Start iperf between Neighbour2 (LPC2) and RPC2.
        7. Start AQ Router and connect client to it.
        8. Set neighbour priorities at Router for LPC1 and LPC2.
        9. Observe iperfs performances.

        @result: AQ Router should prioritize neighbours traffic according to set up priorities.
        @duration: 1.5 minute (for each set of parameters).
        """
        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        shaper_value = 100
        self.aqgaming_set_shaper_settings(shaper_value, shaper_value)

        iperf_time = 60
        lpc1_cmd, rpc1_cmd = self.start_remote_iperf(iperf_time, self.Neighbours[0].name, self.Neighbours[0].ipv4,
                                                     self.REMOTE_HOSTS[0].name)
        lpc2_cmd, rpc2_cmd = self.start_remote_iperf(iperf_time, self.Neighbours[1].name, self.Neighbours[1].ipv4,
                                                     self.REMOTE_HOSTS[1].name)
        self.aqrouter_start()
        assert self.aqgaming_connect_to_router()

        self.set_neighbour_priority(self.Neighbours[0], lpc1_priority)
        self.aqgaming_idle(5)
        self.set_neighbour_priority(self.Neighbours[1], lpc2_priority)
        self.aqgaming_idle(iperf_time)

        lpc1_speeds = self.collect_iperf(lpc1_cmd, rpc1_cmd)
        lpc2_speeds = self.collect_iperf(lpc2_cmd, rpc2_cmd)

        lpc1_average = np.average(lpc1_speeds[20:]) / 1000000
        lpc2_average = np.average(lpc2_speeds[20:]) / 1000000

        if lpc1_priority == lpc2_priority:
            assert lpc1_average < shaper_value / 2 * self.BANDWIDTH_TOLERANCE_HIGH \
                   and lpc2_average < shaper_value / 2 * self.BANDWIDTH_TOLERANCE_HIGH, \
                "Neighbours priorities are the same, but their traffic differs significantly: " \
                "LPC1 = {}, LPC2 = {}".format(lpc1_average, lpc2_average)
            return

        if lpc1_priority < lpc2_priority:
            assert lpc1_average > lpc2_average * self.BANDWIDTH_PRIORITY_RATIO, \
                "LPC1 has higher priority, but its performance is too low"
        else:
            assert lpc2_average > lpc1_average * self.BANDWIDTH_PRIORITY_RATIO, \
                "LPC2 has higher priority, but its performance is too low"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
