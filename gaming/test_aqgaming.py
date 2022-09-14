import os
import sys
import time
import timeit

import ipaddress
import numpy as np
import pytest

from aq_gaming_base import AqGamingBase
from infra.test_base import idparametrize
from tools.constants import DIRECTION_RX, DIRECTION_TX, LINK_SPEED_10G, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, \
    LINK_SPEED_5G, LINK_SPEED_AUTO
from tools.log import get_atf_logger
from tools.utils import get_compressed_ipv6, check_digital_signature

if __package__ is None:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    # os.environ["SESSION_ID"] = "36923"  # Define if virtual network is already running on LKP
    os.environ["TEST"] = "gaming"


class TestAqGaming(AqGamingBase):
    """
    @description: AqGaming test is dedicated to verify basic functionality of AQ Control Center gaming app by using
    special python wrapper to control application.

    @setup: Two Aquantia devices connected back to back. LKP: Linux OS required.
    """

    def setup_method(self, method):
        super(TestAqGaming, self).setup_method(method)
        self.virtual_network_clear_shaping()

    def test_digital_signatures(self):
        """
        @description: Verify that AQGaming executable and sys files have valid digital signatures.

        @steps:
        1. Install AQCC
        2. Verify installer file digital signature
        3. Verify installed exe and sys files digital signatures
        4. If package is whql-certified make sure sys files have additional whql signatures

        @result: All signatures are present and valid, no errors or warnings generated
        @duration: 15 seconds.
        """

        def get_installation_path(path):
            return os.path.abspath(os.path.join(self.AQGAMING_INSTALL_PATH[0], path))

        def get_expected_signatures(file):
            result = ["Aquantia Corp."]
            if file.endswith(".sys") and "whql" in self.MSI_PATH:
                result.append("Microsoft Windows Hardware Compatibility Publisher")
            return result

        files = [self.MSI_PATH,
                 get_installation_path("AqApp/AqApp.exe"),
                 get_installation_path("AQCC/AQtion.exe"),
                 get_installation_path("AqApp/drivers/filter/AqCallout.sys"),
                 get_installation_path("AqApp/drivers/lwf/AQNdisLwf.sys")]
        files.extend(self.AQGAMING_DRIVER_FILES)

        for f in files:
            check_digital_signature(f, get_expected_signatures(f))

    def test_client_init(self):
        """
        @description: Verify that AQGaming client initializes with correct string settings.

        @steps:
        1. Open AQGaming client
        2. Verify reported string settings (IP, NETMASK, etc.)

        @result: All settings are correct (they are setup by test in setup_class)
        @duration: 10 seconds.
        """

        self.aqgaming_clientRegister()
        self.aqgaming_idle(5)

        adapter_name = self.aqgaming.getString(self.aqgaming.AQCOMM_STRING_ADAPTER_NAME)
        log.info("AQGaming Adapter Name = \"{}\"".format(adapter_name))
        ipv4_address = self.aqgaming.getString(self.aqgaming.AQCOMM_STRING_IPV4_ADDRESS)
        log.info("AQGaming IPv4 Address = \"{}\"".format(ipv4_address))
        ipv6_address = self.aqgaming.getString(self.aqgaming.AQCOMM_STRING_IPV6_ADDRESS)
        log.info("AQGaming IPv6 Address = \"{}\"".format(ipv6_address))
        mac_address = self.aqgaming.getString(self.aqgaming.AQCOMM_STRING_MAC_ADDRESS)
        log.info("AQGaming MAC Address = \"{}\"".format(mac_address))
        gateway_address = self.aqgaming.getString(self.aqgaming.AQCOMM_STRING_GATEWAY_ADDRESS)
        log.info("AQGaming IPv4 Gateway = \"{}\"".format(gateway_address))
        netmask = self.aqgaming.getString(self.aqgaming.AQCOMM_STRING_NETMASK)
        log.info("AQGaming IPv4 Mask = \"{}\"".format(netmask))
        adapter_model = self.aqgaming.getString(self.aqgaming.AQCOMM_STRING_ADAPTER_MODEL)
        log.info("AQGaming Adapter Model = \"{}\"".format(adapter_model))

        assert ipv4_address == self.DUT_IP4, "IPv4 address mismatch"
        assert get_compressed_ipv6(ipv6_address) == get_compressed_ipv6(self.DUT_IP6), "IPv6 mismatch"
        assert mac_address.replace("-", ":").lower() == self.dut_ifconfig.get_mac_address().lower(), \
            "MAC address mismatch"
        assert gateway_address == self.DUT_IP4_GATEWAY, "IPv4 gateway mismatch"
        assert netmask == self.DUT_IP4_MASK, "IPv4 mask mismatch"

    def test_client_change_ip_settings(self):
        """
        @description: Verify that AQGaming client picks up changes in system IP settings on the fly.

        @steps:
        1. Open AQGaming client
        2. Note current reported string settings (IP, NETMASK, etc.)
        3. Change some IP settings in the system.
        4. Verify that AQGaming client picked up new settings.

        @result: AQGaming reports new settings correctly.
        @duration: 25 seconds.
        """

        NEW_IP4_ADDRESS = "192.168.2.10"
        NEW_IP4_MASK = "255.255.0.0"
        NEW_IP4_GATEWAY = "192.168.1.1"

        self.aqgaming_clientRegister()

        try:
            self.dut_ifconfig.del_ip_address(self.DUT_IP4)
            self.aqgaming_idle(5)
            self.dut_ifconfig.set_ip_address(NEW_IP4_ADDRESS, NEW_IP4_MASK, NEW_IP4_GATEWAY)
            self.aqgaming_idle(5)

            ipv4_address = self.aqgaming.getString(self.aqgaming.AQCOMM_STRING_IPV4_ADDRESS)
            log.info("AQGaming IPv4 Address = \"{}\"".format(ipv4_address))
            gateway_address = self.aqgaming.getString(self.aqgaming.AQCOMM_STRING_GATEWAY_ADDRESS)
            log.info("AQGaming IPv4 Gateway = \"{}\"".format(gateway_address))
            netmask = self.aqgaming.getString(self.aqgaming.AQCOMM_STRING_NETMASK)
            log.info("AQGaming IPv4 Mask = \"{}\"".format(netmask))

            if ipaddress.ip_address(ipv4_address).is_link_local:
                log.warning("AQGaming detected link local IPv4 address, sleeping 5 seconds")
                self.aqgaming_idle(5)
                ipv4_address = self.aqgaming.getString(self.aqgaming.AQCOMM_STRING_IPV4_ADDRESS)
                log.info("AQGaming IPv4 Address = \"{}\"".format(ipv4_address))

            assert ipv4_address == NEW_IP4_ADDRESS, "IPv4 address mismatch"
            assert netmask == NEW_IP4_MASK, "IPv4 mask mismatch"
            assert gateway_address == NEW_IP4_GATEWAY, "IPv4 gateway mismatch"
        finally:
            self.dut_ifconfig.del_ip_address(NEW_IP4_ADDRESS)
            self.dut_ifconfig.set_ip_address(self.DUT_IP4, self.DUT_IP4_MASK, self.DUT_IP4_GATEWAY)

    def test_init_uninit_cycle(self):
        """
        @description: Verify that AQGaming client turns on and off multiple times without hanging in one state.
        Bug: GAME-236

        @steps:
        1. Open AQGaming client
        2. Turn on AQGaming client.
        3. Idle 10 seconds.
        4. Turn off AQGaming client.
        5. Close AQGaming client.
        6. Repeat steps 1-5 multiple times (20)

        @result: AQGaming turns on and off as expected.
        @duration: 10 minutes.
        """

        for i in range(20):
            log.info("#" * 80)
            log.info("Iteration {}".format(i))
            log.info("#" * 80)

            self.aqgaming_clientRegister()
            self.aqgaming_activate(retry=False)

            self.aqgaming.setVerbose(0)
            for _ in range(10):
                self.aqgaming.kickLib()
                time.sleep(1)
            self.aqgaming.setVerbose(1)

            activated = self.aqgaming.getParameter(self.aqgaming.AQCOMM_SERVER_ACTUAL_STATE)
            assert activated, "AQGaming client is not activate after 10 seconds idling"

            log.info("Deactivating AQGaming client...")
            self.aqgaming_deactivate(retry=False)
            self.aqgaming.clientUnregister()
            time.sleep(3)

    @idparametrize("speed_mbit", [10, 50])
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_static_local_shaper(self, speed_mbit, direction):
        """
        @description: Verify that AQGaming shaper doesn't reduce traffic on the local network.
        Bug: GAME-236

        @steps:
        1. Open AQGaming client
        2. Turn on AQGaming client.
        3. Set shaper settings to *speed_mbit* / *speed_mbit*.
        4. Start iperf between DUT and PC on the local network with direction = *direction*.
        5. Observe iperf performance.

        @result: Iperf performance is at max of local network capability (bigger than shaper settings).
        @duration: 1 minute (for each set of parameters).
        """
        IPERF_TIME = 30

        link_speed = self.get_link_speed_mbit(self.dut_ifconfig.get_link_speed())
        log.info("link speed = {}".format(link_speed))

        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        self.aqgaming_set_shaper_settings(speed_mbit, speed_mbit)

        dut_cmd, lkp_cmd = self.start_iperf(IPERF_TIME, self.DUT_IP4, self.LOCAL_HOSTS[0].name, direction=direction)
        self.aqgaming_idle(IPERF_TIME)
        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        self.assert_no_performance_degradation(link_speed, server_speeds[2:-2], "Shaper")

    @idparametrize("traffic", [AqGamingBase.TCP, AqGamingBase.UDP])
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_performance_enable_service(self, traffic, direction):
        """
        @description: Verify that AQ Service and client doesn't reduce traffic on the remote network.
        Bug: GAME-316

        @steps:
        1. Start iperf between DUT and PC on the remote network with direction = *direction*.
        2. Measure Iperf performance
        3. Turn on AQ Service
        4. Make sure iperf performance doesn't change
        5. Turn on AQGaming client.
        6. Make sure iperf performance doesn't fall down significantly

        @result: Iperf performance is at max of remote network capability.
        @duration: 1 minute (for each set of parameters).
        """
        IPERF_TIME = 60
        link_speed = self.get_link_speed_mbit(self.dut_ifconfig.get_link_speed())

        self.aqgaming_kill_service()

        dut_cmd, lkp_cmd = self.start_iperf(IPERF_TIME, self.DUT_IP4, self.REMOTE_HOSTS[1].name, direction=direction,
                                            traffic=traffic)
        time.sleep(IPERF_TIME // 3)

        self.aqgaming_start_service()
        self.aqgaming_clientRegister()
        self.aqgaming_idle(IPERF_TIME // 3)

        self.aqgaming_activate()
        self.aqgaming_idle(IPERF_TIME // 3)

        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        iperf_base = np.average(server_speeds[:20])
        iperf_with_service = np.average(server_speeds[20:40])
        iperf_with_client = np.average(server_speeds[40:])

        self.skip_if_bad_performance(link_speed, iperf_base)

        assert iperf_with_service > iperf_base * 0.9
        assert iperf_with_client > iperf_base * self.BANDWIDTH_TOLERANCE_LOW

        self.assert_no_performance_degradation(link_speed, server_speeds[22:39], "Service")
        self.assert_no_performance_degradation(link_speed, server_speeds[42:-2], "Client")

    @idparametrize("traffic", [AqGamingBase.TCP, AqGamingBase.UDP])
    @idparametrize("speed_mbit", [10, 2000])
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_enable_shaper_on_the_fly(self, traffic, speed_mbit, direction):
        """
        @description: Verify that enabling AQGaming shaper on the fly reduces traffic on the remote network.

        @steps:
        1. Open AQGaming client
        2. Turn on AQGaming client.
        3. Start iperf between DUT and PC on the remote network with direction = *direction*.
        5. Observe iperf performance.
        4. Set shaper settings to *speed_mbit* / *speed_mbit*.
        5. Observe iperf performance.

        @result: Iperf performance changes according to shaper settings.
        @duration: 1 minute (for each set of parameters).
        """
        IPERF_TIME = 60
        link_speed = self.get_link_speed_mbit(self.dut_ifconfig.get_link_speed())

        if speed_mbit > 5000 and LINK_SPEED_10G not in self.supported_speeds:
            pytest.skip("Skipping {} Mbit test, card doesn't support 10 GbE".format(speed_mbit))

        # UDP TX traffic has low performance on 10G link - something around ~3000 Mbit/s
        if traffic == self.UDP and direction == DIRECTION_TX and link_speed > 3000:
            link_speed = 3000

        self.aqgaming_clientRegister()
        self.aqgaming_activate()
        dut_cmd, lkp_cmd = self.start_iperf(IPERF_TIME, self.DUT_IP4, self.REMOTE_HOSTS[1].name, direction=direction,
                                            traffic=traffic)
        self.aqgaming_idle(IPERF_TIME // 3)

        self.aqgaming_set_shaper_settings(speed_mbit, speed_mbit)
        self.aqgaming_idle(IPERF_TIME // 3)

        self.aqgaming_deactivate()
        self.aqgaming_idle(IPERF_TIME // 3)

        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        iperf_base = np.average(server_speeds[:20])
        self.skip_if_bad_performance(link_speed, iperf_base)

        self.assert_speed_is_shaped(speed_mbit, server_speeds[22:38])
        self.assert_no_performance_degradation(link_speed, server_speeds[42:-2], "Client")

    @idparametrize("priority", [1, 2, 3, 4])
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_shaper_for_priorities(self, priority, direction):
        """
        @description: Verify that AQGaming shaper reduces traffic with any priority on the remote network.
        Bug: GAME-320

        @steps:
        1. Open AQGaming client
        2. Turn on AQGaming client.
        3. Set shaper settings to *speed_mbit* / *speed_mbit*.
        4. Start iperf between DUT and PC on the remote network with direction = *direction*.
        5. Change iperf priority.
        5. Observe iperf performance.
        7. Repeat 5-6 for all priorities

        @result: Iperf performance changes according to shaper settings.
        @duration: 1 minute (for each set of parameters).
        """
        IPERF_TIME = 30
        speed_mbit = 100

        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        self.aqgaming_set_shaper_settings(speed_mbit, speed_mbit)

        dut_cmd, lkp_cmd = self.start_iperf(IPERF_TIME, self.DUT_IP4, self.REMOTE_HOSTS[1].name, direction=direction)
        self.aqgaming_set_app_priority_by_name("IPERF3", priority)
        self.aqgaming_idle(IPERF_TIME)
        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        self.assert_speed_is_shaped(speed_mbit, server_speeds[2:-2])

    @idparametrize("traffic", [AqGamingBase.TCP, AqGamingBase.UDP, AqGamingBase.TCP_NOT_FRAG, AqGamingBase.UDP_NOT_FRAG])
    @idparametrize("speed_mbit", [10, 30, 50, 80, 100, 1000, 2500, 4500, 8000])
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_static_remote_shaper(self, traffic, speed_mbit, direction):
        """
        @description: Verify that AQGaming shaper reduces traffic on the remote network.

        @steps:
        1. Open AQGaming client
        2. Turn on AQGaming client.
        3. Set shaper settings to *speed_mbit* / *speed_mbit*.
        4. Start iperf between DUT and PC on the remote network with direction = *direction*.
        5. Observe iperf performance.

        @result: Iperf performance changes according to shaper settings.
        @duration: 1 minute (for each set of parameters).
        """
        if traffic in (self.TCP_NOT_FRAG, self.UDP_NOT_FRAG) and speed_mbit > 500:
            pytest.skip("Not fragmented traffic performance is not enough for such shaper values")

        IPERF_TIME = 30

        if speed_mbit > 5000 and LINK_SPEED_10G not in self.supported_speeds:
            pytest.skip("Skipping {} Mbit test, card doesn't support 10 GbE".format(speed_mbit))

        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        self.aqgaming_set_shaper_settings(speed_mbit, speed_mbit)

        dut_cmd, lkp_cmd = self.start_iperf(IPERF_TIME, self.DUT_IP4, self.REMOTE_HOSTS[1].name, direction=direction,
                                            traffic=traffic)
        self.aqgaming_idle(IPERF_TIME)
        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        self.assert_speed_is_shaped(speed_mbit, server_speeds[2:-2])

    @idparametrize("from_mbit,to_mbit", [(10, 30), (100, 4000), (50, 20), (3500, 300)])
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_changed_remote_shaper(self, from_mbit, to_mbit, direction):
        """
        @description: Verify that AQGaming shaper reduces traffic on the remote network while changing shaper settings
        on the fly.

        @steps:
        1. Open AQGaming client
        2. Turn on AQGaming client.
        3. Set shaper settings to *from_mbit* / *from_mbit*.
        4. Start iperf between DUT and PC on the remote network with direction = *direction*.
        5. After some time change shaper settings to *to_mbit* / *to_mbit*
        6. Observe iperf performance.

        @result: Iperf performance changes according to shaper settings.
        @duration: 1 minute (for each set of parameters).
        """
        IPERF_TIME = 30
        middle = IPERF_TIME // 2

        if (from_mbit > 5000 or to_mbit > 5000) and LINK_SPEED_10G not in self.supported_speeds:
            pytest.skip("Skipping {}->{} Mbit test, card doesn't support 10 GbE".format(from_mbit, to_mbit))

        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        self.aqgaming_set_shaper_settings(from_mbit, from_mbit)

        dut_cmd, lkp_cmd = self.start_iperf(IPERF_TIME, self.DUT_IP4, self.REMOTE_HOSTS[1].name, direction=direction)
        self.aqgaming_idle(middle)
        self.aqgaming_set_shaper_settings(to_mbit, to_mbit)
        self.aqgaming_idle(middle)
        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        self.assert_speed_is_shaped(from_mbit, server_speeds[2:middle - 2])
        self.assert_speed_is_shaped(to_mbit, server_speeds[middle + 2:-2])

    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_traffic_report(self, direction):
        """
        @description: Verify that AQGaming reports correct download / upload speed on the network.

        @steps:
        1. Open AQGaming client
        2. Turn on AQGaming client.
        3. Set shaper settings to 10000 / 10000.
        4. Start iperf between DUT and PC on the remote network with direction = *direction*.
        5. Observe iperf performance and download / upload speed reported by client.

        @result: Iperf performance should match reported speed.
        @duration: 3 minutes (for each set of parameters).
        """

        IPERF_TIME = 120

        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        self.aqgaming_set_shaper_settings(10000, 10000)

        dut_cmd, lkp_cmd = self.start_iperf(IPERF_TIME, self.DUT_IP4, self.REMOTE_HOSTS[1].name, direction=direction)

        aqcc_speeds = []

        self.aqgaming.setVerbose(0)
        for i in range(IPERF_TIME + 15):
            self.aqgaming.kickLib()
            aqcc_speeds.append(self.aqgaming.getParameter(
                self.aqgaming.AQCOMM_PARAM_DNRATE if direction == DIRECTION_RX else self.aqgaming.AQCOMM_PARAM_UPRATE))
            time.sleep(1)
        self.aqgaming.setVerbose(1)

        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        self.create_bar_plot(os.path.join(self.test_log_dir, "{}_gaming.png".format(direction)),
                             ("AQCC", [s / 1000.0 for s in aqcc_speeds]),
                             ("Iperf", [s / 1000.0 / 1000.0 for s in server_speeds]))

        aqcc_avg_speed = np.average(aqcc_speeds[15:-15])
        iperf_avg_speed = np.average(server_speeds[10:-10]) / 1000

        log.info("AQ Command Center average speed = {} Mbit/s".format(aqcc_avg_speed))
        log.info("Iperf average speed = {} Mbit/s".format(iperf_avg_speed))

        assert min(aqcc_avg_speed, iperf_avg_speed) / max(aqcc_avg_speed, iperf_avg_speed) > 0.8, \
            "AQ Control Center and Iperf average speeds are too different"

    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_app_traffic_report(self, direction):
        """
        @description: Verify that AQGaming reports correct download / upload speed per application.

        @steps:
        1. Open AQGaming client
        2. Turn on AQGaming client.
        3. Set shaper settings to 10000 / 10000.
        4. Start iperf between DUT and PC on the remote network with direction = *direction*.
        5. Observe iperf performance and download / upload speed reported by client.

        @result: Iperf performance should match reported speed.
        @duration: 3 minutes (for each set of parameters).
        """

        IPERF_TIME = 120

        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        self.aqgaming_set_shaper_settings(10000, 10000)

        dut_cmd, lkp_cmd = self.start_iperf(IPERF_TIME + 5, self.DUT_IP4, self.REMOTE_HOSTS[1].name,
                                            direction=direction)
        start_time = timeit.default_timer()

        self.aqgaming.kickLib()
        time.sleep(2)
        self.aqgaming.kickLib()
        app_id = self.aqgaming_get_app_by_name("IPERF3")["id"]

        aqcc_speeds = []

        start_idle_time = timeit.default_timer()
        self.aqgaming.setVerbose(0)
        for i in range(IPERF_TIME):
            self.aqgaming.kickLib()
            try:
                app = self.aqgaming.getAppById(app_id)
                aqcc_speeds.append(app["dnRate" if direction == DIRECTION_RX else "upRate"])
                log.debug("Application UP / DN speed = {} / {} Mbit/s".format(app["upRate"] / 1000.0,
                                                                              app["dnRate"] / 1000.0))
            except self.aqgaming.AqgamingError:
                break
            time.sleep(1)
        self.aqgaming.setVerbose(1)

        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        self.create_bar_plot(
            os.path.join(self.test_log_dir, "{}_gaming.png".format(direction)),
            ("AQCC", [s / 1000.0 for s in aqcc_speeds]),
            ("Iperf", [s / 1000.0 / 1000.0 for s in server_speeds[int(start_idle_time - start_time):]]))

        aqcc_avg_speed = np.average(aqcc_speeds[10:-10])
        iperf_avg_speed = np.average(server_speeds[10:-10]) / 1000

        log.info("AQ Command Center average application speed = {} Mbit/s".format(aqcc_avg_speed))
        log.info("Iperf average speed = {} Mbit/s".format(iperf_avg_speed))

        assert min(aqcc_avg_speed, iperf_avg_speed) / max(aqcc_avg_speed, iperf_avg_speed) > 0.8, \
            "AQ Control Center and Iperf average speeds are too different"

    @idparametrize("from_to_mbit,channel", [((80, 200), 100), ((50, 9000), 200), ((3000, 100), 400)])
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_changed_remote_shaper_with_channel_limit(self, from_to_mbit, channel, direction):
        """
        @description: Verify that AQGaming shaper reduces traffic on the remote network while changing shaper settings
        on the fly. Remote network has bandwidth limit.
        Parameters: from_mbit < channel < to_mbit, from_mbit > channel > to_mbit

        @steps:
        1. Set bandwidth limit for remote network to *channel* Mbit.
        2. Open AQGaming client
        3. Turn on AQGaming client.
        4. Set shaper settings to *from_to_mbit[0]* / *from_to_mbit[0]*.
        5. Start iperf between DUT and PC on the remote network with direction = *direction*.
        6. After some time change shaper settings to *from_to_mbit[1]* / *from_to_mbit[1]*
        7. Observe iperf performance.

        @result: Iperf performance changes according to shaper settings and remote network bandwidth limit.
        @duration: 1 minute (for each set of parameters).
        """
        IPERF_TIME = 30
        middle = IPERF_TIME // 2

        from_mbit, to_mbit = from_to_mbit

        if (from_mbit > 5000 or channel > 5000) and LINK_SPEED_10G not in self.supported_speeds:
            pytest.skip("Skipping test, card doesn't support 10 GbE")

        self.virtual_network_set_shaping(channel)

        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        self.aqgaming_set_shaper_settings(from_mbit, from_mbit)

        dut_cmd, lkp_cmd = self.start_iperf(IPERF_TIME, self.DUT_IP4, self.REMOTE_HOSTS[1].name, direction=direction)
        self.aqgaming_idle(middle)
        self.aqgaming_set_shaper_settings(to_mbit, to_mbit)
        self.aqgaming_idle(middle)
        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

        self.assert_speed_is_shaped(min(from_mbit, channel), server_speeds[2:middle - 2])
        self.assert_speed_is_shaped(min(to_mbit, channel), server_speeds[middle + 2:-2])

    def test_priority_changed(self):
        """
        @description: Make sure priority is set and not rolled back
        Bug: http://jira.aquantia.com:8080/browse/GAME-137

        @steps:
        1. Run AQCC, run iperf server
        2. Set shaping on both sides to 200Mbps for example
        3. Run iperf and wait some time.
        4. Change priority for Iperf app.

        @result: Priority for iperf changed
        @duration: 1.5 minutes.
        """

        def assert_priority_changes(app_name, required_priority, sleep):
            self.aqgaming_set_app_priority_by_name(app_name, required_priority)
            self.aqgaming_idle(sleep)
            actual_priority = self.aqgaming_get_app_priority_by_name(app_name)
            assert actual_priority == required_priority, "{} != {}".format(actual_priority, required_priority)

        IPERF_TIME = 60
        speed_mbit = 200

        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        self.aqgaming_set_shaper_settings(speed_mbit, speed_mbit)

        dut_cmd, lkp_cmd = self.start_iperf(IPERF_TIME, self.DUT_IP4, self.REMOTE_HOSTS[1].name, direction=DIRECTION_RX)
        assert_priority_changes("IPERF3", self.aqgaming.PRIORITY_CRITICAL, 10)
        assert_priority_changes("IPERF3", self.aqgaming.PRIORITY_HIGH, 10)
        assert_priority_changes("IPERF3", self.aqgaming.PRIORITY_NORMAL, 10)
        assert_priority_changes("IPERF3", self.aqgaming.PRIORITY_LOW, 10)
        server_speeds = self.collect_iperf(dut_cmd, lkp_cmd)

    def test_ping_prioritization(self):
        """
        @steps:
        1. Start game as low priority (rttclient / rttserver).
        2. Start DL via torrent as low priority (iperf).
        3. In-Game ping should raise up.
        4. Increase game priority to critical.
        5. In-Game ping shall restore to initial values.
        6. Decrease game priority to high.
        7. In-Game ping shouldn't rise up significantly.
        8. Decrease game priority to low.
        9. In-Game ping shall raise up.

        @result: In-Game ping changes accordingly.
        @duration: 4 minutes.
        """

        RTT_PORTION_TIME = 30
        # RTT time = (~3 + 10) +   (~3 + 10) + (~3 + 10) + (~3 + 10) + (~3 + 10)
        #            low,w/o iperf low         critical    high        low
        RTT_TIME = (5 + RTT_PORTION_TIME) * 5 + 2

        rtt_portions = []

        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        self.aqgaming_set_shaper_settings(100, 100)

        dut_rtt_cmd, lkp_rtt_cmd_host = self.start_rtt(RTT_TIME, self.REMOTE_HOSTS[0])
        start_time = timeit.default_timer()
        time.sleep(2)

        self.aqgaming_set_app_priority_by_name("rttclient", self.aqgaming.PRIORITY_LOW)
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        dut_iperf_cmd, lkp_iperf_cmd = self.start_iperf(RTT_TIME - RTT_PORTION_TIME, self.DUT_IP4,
                                                        self.REMOTE_HOSTS[1].name, direction=DIRECTION_RX)
        self.aqgaming_set_app_priority_by_name("IPERF3", self.aqgaming.PRIORITY_LOW)
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        self.aqgaming_set_app_priority_by_name("rttclient", self.aqgaming.PRIORITY_CRITICAL)
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        self.aqgaming_set_app_priority_by_name("rttclient", self.aqgaming.PRIORITY_HIGH)
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        self.aqgaming_set_app_priority_by_name("rttclient", self.aqgaming.PRIORITY_LOW)
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        iperf_speeds = self.collect_iperf(dut_iperf_cmd, lkp_iperf_cmd)
        rtt_delays, rtt_losses, rtt_disorder = self.collect_rtt(dut_rtt_cmd, lkp_rtt_cmd_host)

        self.create_bar_plot(os.path.join(self.test_log_dir, "delays.png"), ("Ping RTT", rtt_delays))

        log.info("Average delays for each portion (you can use them to analyze plot):")
        averages = []
        for portion in rtt_portions:
            averages.append(np.average(rtt_delays[portion[0] + 2:portion[1] - 6]))
            log.info("Portion {} = {} us".format(portion, averages[-1]))

        assert averages[1] - averages[0] > 1000, "Ping didn't raise up after starting Iperf at low priority"
        assert averages[1] - averages[2] > 1000, "Ping didn't fall down after changing game app's priority to critical"
        assert abs(averages[2] - averages[3]) < 1000, "Ping raised up after changing game app's priority to high"
        assert averages[4] - averages[3] > 1000, "Ping didn't raise up after changing game app's priority back to low"
        assert rtt_losses == 0, "Ping lost some packets during testing"

        log.info("Simple analytics look fine. For more information please see plot image")

    def test_feature_reenabling(self):
        """
        @steps:
        1. Start game as critical priority (rttclient / rttserver).
        2. Start DL via torrent as low priority (iperf).
        3. In-Game ping shouldn't raise up.
        4. Disable gaming feature.
        5. In-Game ping shall raise up.
        6. Game connectivity shouldn't be interrupted (no lost packets).
        7. Enable gaming feature.
        8. In-Game ping shall restore to initial values.
        9. Game connectivity shouldn't be interrupted (no lost packets).

        @result: In-Game ping changes accordingly.
        @duration: 3 minutes.
        """

        RTT_PORTION_TIME = 30
        # RTT time = (~3 + 10) +        (~3 + 10) + (~3 + 10) + (~3 + 10)
        #            critical,w/o iperf critical    disable     enable
        RTT_TIME = (5 + RTT_PORTION_TIME) * 4 + 2

        rtt_portions = []

        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        self.aqgaming_set_shaper_settings(100, 100)
        self.virtual_network_set_shaping(200)

        dut_rtt_cmd, lkp_rtt_cmd_host = self.start_rtt(RTT_TIME, self.REMOTE_HOSTS[0])
        start_time = timeit.default_timer()
        time.sleep(2)

        self.aqgaming_set_app_priority_by_name("rttclient", self.aqgaming.PRIORITY_CRITICAL)
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        dut_iperf_cmd, lkp_iperf_cmd = self.start_iperf(RTT_TIME - RTT_PORTION_TIME, self.DUT_IP4,
                                                        self.REMOTE_HOSTS[1].name, direction=DIRECTION_RX)
        self.aqgaming_set_app_priority_by_name("IPERF3", self.aqgaming.PRIORITY_LOW)
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        self.aqgaming_deactivate()
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        self.aqgaming_activate()
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        iperf_speeds = self.collect_iperf(dut_iperf_cmd, lkp_iperf_cmd)
        rtt_delays, rtt_losses, rtt_disorder = self.collect_rtt(dut_rtt_cmd, lkp_rtt_cmd_host)

        self.create_bar_plot(os.path.join(self.test_log_dir, "delays.png"), ("Ping RTT", rtt_delays))

        log.info("Average delays for each portion (you can use them to analyze plot):")
        averages = []
        for portion in rtt_portions:
            averages.append(np.average(rtt_delays[portion[0] + 2:portion[1] - 6]))
            log.info("Portion {} = {} us".format(portion, averages[-1]))

        assert abs(averages[1] - averages[0]) < 1000, "Ping raised up after starting Iperf at low priority"
        assert averages[2] - averages[1] > 1000, "Ping didn't raise up after turning off gaming feature"
        assert averages[2] - averages[3] > 1000, "Ping didn't reset to normal after turning gaming feature back on"
        assert rtt_losses == 0, "Ping lost some packets during testing"

        log.info("Simple analytics look fine. For more information please see plot image")

    def test_speed_limit_reconfiguration(self):
        """
        @steps:
        1. Configure bandwidth limit on the remote network.
        2. Start game as critical priority (rttclient / rttserver).
        3. Start DL/UL via torrent as low priority (iperf).
        4. In-Game ping shouldn't raise up.
        5. Decrease shaping values.
        6. Game connectivity shouldn't be interrupted (no lost packets).
        7. In-Game ping shouldn't change significantly.
        8. Total system throughput should decrease to new value.
        9. Increase shaping values (less than channel bandwidth).
        10. Game connectivity shouldn't be interrupted.
        11. In-Game ping shouldn't change significantly.
        12. Total system throughput should increase to new value.

        @result: In-Game ping and iperf throughput change accordingly.
        @duration: 3 minutes.
        """

        RTT_PORTION_TIME = 30
        # RTT time = (~3 + 10) +        (~3 + 10) + (~3 + 10) +      (~3 + 10)
        #            critical,w/o iperf critical    decrease shaping increase shaping
        RTT_TIME = (5 + RTT_PORTION_TIME) * 4 + 2

        rtt_portions = []

        self.virtual_network_set_shaping(200)

        self.aqgaming_clientRegister()
        self.aqgaming_activate()

        self.aqgaming_set_shaper_settings(150, 150)

        dut_rtt_cmd, lkp_rtt_cmd_host = self.start_rtt(RTT_TIME, self.REMOTE_HOSTS[0])
        start_time = timeit.default_timer()
        time.sleep(2)

        self.aqgaming_set_app_priority_by_name("rttclient", self.aqgaming.PRIORITY_CRITICAL)
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        dut_iperf_cmd, lkp_iperf_cmd = self.start_iperf(RTT_TIME - RTT_PORTION_TIME, self.DUT_IP4,
                                                        self.REMOTE_HOSTS[1].name, direction=DIRECTION_RX)
        iperf_start_time = timeit.default_timer()
        self.aqgaming_set_app_priority_by_name("IPERF3", self.aqgaming.PRIORITY_LOW)
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        self.aqgaming_set_shaper_settings(100, 100)
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        self.aqgaming_set_shaper_settings(180, 180)
        self.aqgaming_idle_with_timestamps(RTT_PORTION_TIME, start_time, rtt_portions)

        iperf_speeds = self.collect_iperf(dut_iperf_cmd, lkp_iperf_cmd)
        rtt_delays, rtt_losses, rtt_disorder = self.collect_rtt(dut_rtt_cmd, lkp_rtt_cmd_host)

        self.create_bar_plot(os.path.join(self.test_log_dir, "ping.png"), ("Ping RTT", rtt_delays))
        self.create_bar_plot(os.path.join(self.test_log_dir, "iperf.png"),
                             ("Iperf speed", [speed / 1000 / 1000 for speed in iperf_speeds]))

        iperf_portions = []
        iperf_averages = []
        log.info("Average delays for each portion (you can use them to analyze plot):")
        rtt_averages = []
        for i, portion in enumerate(rtt_portions):
            rtt_averages.append(np.average(rtt_delays[portion[0] + 2:portion[1] - 6]))
            log.info("RTT portion {} = {} us".format(portion, rtt_averages[-1]))
            if i > 0:
                iperf_portions.append([portion[0] - int(iperf_start_time - start_time),
                                       portion[1] - int(iperf_start_time - start_time)])
                iperf_averages.append(np.average(iperf_speeds[iperf_portions[-1][0] + 3:iperf_portions[-1][1] - 3]))
                log.info("Iperf portion {} = {} Mbit/s".format(iperf_portions[-1], iperf_averages[-1]))

        assert abs(rtt_averages[1] - rtt_averages[0]) < 1000, "Ping raised up after starting Iperf at low priority"
        assert abs(rtt_averages[2] - rtt_averages[1]) < 1000, "Ping raised up after lowering shaper setting"
        assert abs(rtt_averages[3] - rtt_averages[2]) < 1000, "Ping raised up after increasing shaper setting"
        assert rtt_losses == 0, "Ping lost some packets during testing"

        assert iperf_averages[0] / 150 > 0.8, "Iperf speed on the first segment is incorrect"
        assert iperf_averages[1] / 100 > 0.8, "Iperf speed on the second segment is incorrect"
        assert iperf_averages[2] / 180 > 0.8, "Iperf speed on the third segment is incorrect"

        log.info("Simple analytics look fine. For more information please see plot image")

    def iperf_prioritization(self, host):
        """
        @steps:
        1. Start iperf as low priority and iperf_copy as normal priority.
        2. Bandwidth of iperf_copy is greater than the bandwidth of iperf * BANDWIDTH_PRIORITY.
        3. Increase iperf priority to high.
        4. Bandwidth of iperf is greater than the bandwidth of iperf_copy * BANDWIDTH_PRIORITY.
        5. Decrease iperf3_copy priority to critical.
        6. Bandwidth of iperf_copy is greater than the bandwidth of iperf * BANDWIDTH_PRIORITY.

        @duration: 1.5 minutes.
        """
        IPERF_TIME = 90
        dut_iperf_cmd, lkp_iperf_cmd = self.start_iperf(IPERF_TIME, self.DUT_IP4, host, port=5201,
                                                        direction=DIRECTION_RX)
        dut_iperf_copy_cmd, lkp_iperf_copy_cmd = self.start_iperf(IPERF_TIME, self.DUT_IP4, host, port=5202,
                                                                  direction=DIRECTION_RX, iperf_bin=self.IPERF_COPY)
        self.aqgaming_set_app_priority_by_name("IPERF3", self.aqgaming.PRIORITY_LOW)
        self.aqgaming_set_app_priority_by_name("IPERF3_COPY", self.aqgaming.PRIORITY_NORMAL)

        self.aqgaming_idle(IPERF_TIME // 3)
        self.aqgaming_set_app_priority_by_name("IPERF3", self.aqgaming.PRIORITY_HIGH)
        self.aqgaming_idle(IPERF_TIME // 3)
        self.aqgaming_set_app_priority_by_name("IPERF3_COPY", self.aqgaming.PRIORITY_CRITICAL)

        iperf_speeds = self.collect_iperf(dut_iperf_cmd, lkp_iperf_cmd)
        iperf_copy_speeds = self.collect_iperf(dut_iperf_copy_cmd, lkp_iperf_copy_cmd)

        iperf_copy_normal_1interval = np.average(iperf_copy_speeds[10:30])
        iperf_copy_normal_2interval = np.average(iperf_copy_speeds[40:60])
        iperf_copy_critical_3interval = np.average(iperf_copy_speeds[70:])
        iperf_low_1interval = np.average(iperf_speeds[10:30])
        iperf_high_2interval = np.average(iperf_speeds[40:60])
        iperf_high_3interval = np.average(iperf_speeds[70:])

        assert iperf_copy_normal_1interval / iperf_low_1interval > self.BANDWIDTH_PRIORITY_RATIO
        assert iperf_high_2interval / iperf_copy_normal_2interval > self.BANDWIDTH_PRIORITY_RATIO
        assert iperf_copy_critical_3interval / iperf_high_3interval > self.BANDWIDTH_PRIORITY_RATIO

    @idparametrize("link_speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G])
    def test_local_iperf_prioritization(self, link_speed):
        """
        @steps:
        1. Set link to *link_speed* and shaper settings to 100 / 100
        2. Start iperf_prioritization at locale host
        """
        if link_speed == LINK_SPEED_5G and LINK_SPEED_10G not in self.supported_speeds:
            pytest.skip("Skipping test")
        self.dut_ifconfig.set_link_speed(link_speed)
        self.aqgaming_clientRegister()
        self.aqgaming_activate()
        self.aqgaming_set_shaper_settings(100, 100)

        self.iperf_prioritization(self.LOCAL_HOSTS[0].name)

    @idparametrize("speed_mbit", [10, 50, 100, 1000, 2500, 5000, 8000])
    def test_remote_iperf_prioritization(self, speed_mbit):
        """
        @steps:
        1. Set shaper settings to *speed_mbit* / *speed_mbit* and set link to LINK_SPEED_AUTO
        2. Start iperf_prioritization at remote host
        """
        if speed_mbit > 5000 and LINK_SPEED_10G not in self.supported_speeds:
            pytest.skip("Skipping test, card doesn't support 10 GbE")
        self.dut_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.aqgaming_clientRegister()
        self.aqgaming_activate()
        self.aqgaming_set_shaper_settings(speed_mbit, speed_mbit)
        self.iperf_prioritization(self.REMOTE_HOSTS[1].name)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
