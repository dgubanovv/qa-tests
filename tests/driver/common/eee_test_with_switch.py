import copy
import os
import sys
import time
import timeit
import numpy

qa_tests = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(qa_tests)

import pytest

from hlh.register import Register
from infra.test_base import TestBase, idparametrize
from tools.command import Command
from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, DIRECTION_RX, DIRECTION_TX, \
    CARD_NIKKI, SPEED_TO_MBITS, KNOWN_LINK_SPEEDS
from tools.driver import Driver
from tools.killer import Killer
from perf.iperf import Iperf
from perf.nuttcp import Nuttcp
from perf.iperf_result import IperfResult
from tools.iptables import IPTables
from tools.utils import get_atf_logger, str_to_bool

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "eee"


class TestEee(TestBase):
    """
    @description: The TestEee test is dedicated to verify External EEE mode.

    @setup: Two Aquantia devices are connected via switch or connected back-to-back.
    """
    PING_LOG_PATH = "pingFlood.log"
    BEFORE_TRAFFIC_DELAY = 10
    IPERF_TIME = 120
    PING_FLOOD_TIME = 600
    PING_FLOOD_CHECKS = 10

    @classmethod
    def setup_class(cls):
        super(TestEee, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            if not (cls.skip_drv_install or cls.skip_dut_drv_install):
                cls.dut_driver.install()
            if not (cls.skip_drv_install or cls.skip_lkp_drv_install):
                cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            cls.IPERF_ARGS = {
                'direction': None,
                'speed': None,
                'num_threads': 1,
                'num_process': 1,
                'ipv': 4,
                'criterion': IperfResult.SANITY,
                "bandwidth": 0,
                'dut': cls.dut_hostname,
                'lkp': cls.lkp_hostname,
                "dut4": cls.DUT_IPV4_ADDR,
                "lkp4": cls.LKP_IPV4_ADDR,
                "time": cls.IPERF_TIME
            }

            cls.dut_atltool = AtlTool(port=cls.dut_port)
            cls.lkp_atltool = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            cls.iptables = IPTables(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname)
            cls.iptables.clean()

            if "LKP_EEE_ENABLE" in os.environ:
                cls.lkp_eee_enable = str_to_bool(os.environ["LKP_EEE_ENABLE"])
            else:
                cls.lkp_eee_enable = True
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestEee, cls).teardown_class()

        command_rm = 'rm -rf {}'.format(cls.PING_LOG_PATH)
        Command(cmd=command_rm, host=cls.dut_hostname).run()
        Command(cmd=command_rm, host=cls.lkp_hostname).run()

    def setup_method(self, method):
        super(TestEee, self).setup_method(method)
        Killer().kill("iperf3")
        Killer(host=self.lkp_hostname).kill("iperf3")
        Killer().kill("ping")
        Killer(host=self.lkp_hostname).kill("ping")
        Killer().kill("nuttcp")
        Killer(host=self.dut_hostname).kill("nuttcp")
        Killer().kill("nuttcp")
        Killer(host=self.lkp_hostname).kill("nuttcp")

    def teardown_method(self, method):
        super(TestEee, self).teardown_method(method)
        nof_sif_reconfigs_after = self._phy_get_nof_sif_reconfigs()
        log.info('Number of PHY reconfiguration after test is {}'.format(nof_sif_reconfigs_after))

    def _setup_link_and_eee(self, speed):
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()
        nof_sif_reconfigs_after = self._phy_get_nof_sif_reconfigs()
        log.info('Number of PHY reconfiguration before EEE config is {}'.format(nof_sif_reconfigs_after))

        if self.lkp_eee_enable:
            self.lkp_ifconfig.set_media_options(["full-duplex", "energy-efficient-ethernet"])
        else:
            self.lkp_ifconfig.set_media_options(["full-duplex"])
        self.dut_ifconfig.set_media_options(["full-duplex", "energy-efficient-ethernet"])
        nof_sif_reconfigs_after = self._phy_get_nof_sif_reconfigs()
        log.info('Number of PHY reconfiguration after EEE config is {}'.format(nof_sif_reconfigs_after))

        assert speed == self.dut_ifconfig.wait_link_up()
        assert speed == self.lkp_ifconfig.wait_link_up()

    def _set_mtu(self, mtu):
        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu)

    def _phy_get_nof_sif_reconfigs(self):
        return self.dut_atltool.readphyreg(0xa, 0x0096)

    def _phy_get_lpi_status(self, speed, direction):
        if speed == LINK_SPEED_2_5G or speed == LINK_SPEED_5G or speed == LINK_SPEED_10G:
            if direction == 'tx':
                return Register(self.dut_atltool.readphyreg(0x3, 0x1))[0x9]
            elif direction == 'rx':
                return Register(self.dut_atltool.readphyreg(0x3, 0x1))[0x8]
        elif speed == LINK_SPEED_1G:
            if direction == 'tx':
                return Register(self.dut_atltool.readphyreg(0x1D, 0xD203))[0x4]
            elif direction == 'rx':
                return Register(self.dut_atltool.readphyreg(0x1D, 0xD202))[0x4]

    def verify_eee_is_up(self, speed):
        speed_to_eee_map = {
            LINK_SPEED_1G: 0x100,
            LINK_SPEED_2_5G: 0x200,
            LINK_SPEED_5G: 0x400,
            LINK_SPEED_10G: 0x800,
        }
        self.dut_ifconfig.check_media_options(["full-duplex", "energy-efficient-ethernet"])
        if self.lkp_eee_enable:
            self.lkp_ifconfig.check_media_options(["full-duplex", "energy-efficient-ethernet"])
            if self.lkp_fw_card == CARD_NIKKI:
                # Double check that EEE is enabled
                lkp_374_reg = self.lkp_atltool.readreg(0x374)
                assert lkp_374_reg & speed_to_eee_map[speed] != 0
        else:
            self.lkp_ifconfig.check_media_options(["full-duplex"])
            if self.lkp_fw_card == CARD_NIKKI:
                # Double check that EEE is disabled
                lkp_374_reg = self.lkp_atltool.readreg(0x374)
                assert lkp_374_reg & speed_to_eee_map[speed] == 0

    def precondition(self, speed, mtu):
        if speed not in self.supported_speeds:
            pytest.skip()
        self._set_mtu(mtu)  # set MTU before EEE because is causes link down
        self._setup_link_and_eee(speed)
        self.dut_ifconfig.wait_link_up()
        self.lkp_ifconfig.wait_link_up()

        log.info('verify that EEE is negotiated after all configurations')
        self.verify_eee_is_up(speed)  # verify that EEE is negotiated after all configurations
        time.sleep(self.BEFORE_TRAFFIC_DELAY)
        assert self._phy_get_lpi_status(speed=speed, direction='rx') == 1, 'Rx EEE LPI indication is disabled'
        assert self._phy_get_lpi_status(speed=speed, direction='tx') == 1, 'Tx EEE LPI indication is disabled'

    def postcondition(self, beginning_nof_sif_reconfigs, speed):
        nof_sif_reconfigs_after = self._phy_get_nof_sif_reconfigs()
        assert beginning_nof_sif_reconfigs == nof_sif_reconfigs_after, "Link down during ping flood detected"
        log.info('verify that EEE is negotiated after test')
        self.verify_eee_is_up(speed)  # verify that EEE is negotiated after all configurations
        assert self._phy_get_lpi_status(speed=speed, direction='rx') == 1, 'Rx EEE LPI indication is disabled'
        assert self._phy_get_lpi_status(speed=speed, direction='tx') == 1, 'Tx EEE LPI indication is disabled'

    def run_check_lpi_indication_status(self, speed, rx_direction=1, tx_direction=1, degree='all'):
        value_rx = value_tx = []
        for i in range(self.IPERF_TIME):
            value_rx.append(self._phy_get_lpi_status(speed=speed, direction='rx'))
            value_tx.append(self._phy_get_lpi_status(speed=speed, direction='tx'))
            time.sleep(1)
        log.info('LPI status for speed {}, direction rx = {}'.format(speed, value_rx))
        log.info('LPI status for speed {}, direction tx = {}'.format(speed, value_tx))
        if degree == 'all':
            assert all(i == rx_direction for i in value_rx), 'Rx EEE LPI indication is disabled'
            assert all(i == tx_direction for i in value_tx), 'Tx EEE LPI indication is disabled'
        elif degree == 'any':
            assert any(i == rx_direction for i in value_rx), 'Rx EEE LPI indication is disabled'
            assert any(i == tx_direction for i in value_tx), 'Tx EEE LPI indication is disabled'

    def run_test_lpi_checks(self, speed, mtu, pkt_sizes=[1400]):
        self.precondition(speed, mtu)

        self.run_check_lpi_indication_status(speed=speed)

        iperf_args = copy.deepcopy(self.IPERF_ARGS)
        iperf_args["speed"] = speed
        iperf_args["direction"] = DIRECTION_RX
        iperf_args["is_udp"] = False
        iperf_args["bandwidth"] = 128 * 1024
        iperf_args["num_threads"] = 4

        time.sleep(self.BEFORE_TRAFFIC_DELAY)

        iperf = Iperf(port=5201, buffer_len=1450, **iperf_args)
        iperf.run_async()
        self.run_check_lpi_indication_status(speed=speed, rx_direction=0, tx_direction=1, degree='any')
        iperf.join()

        iperf_args = copy.deepcopy(self.IPERF_ARGS)
        iperf_args["speed"] = speed
        iperf_args["direction"] = DIRECTION_TX
        iperf_args["is_udp"] = False
        iperf_args["bandwidth"] = 128 * 1024
        iperf_args["num_threads"] = 4

        time.sleep(self.BEFORE_TRAFFIC_DELAY)

        iperf = Iperf(port=5201, buffer_len=1450, **iperf_args)
        iperf.run_async()
        self.run_check_lpi_indication_status(speed=speed, rx_direction=1, tx_direction=0, degree='any')
        iperf.join()

        self.run_check_lpi_indication_status(speed=speed)

    def run_iperf_tcp_test(self, speed, mtu, direction):
        self.precondition(speed, mtu)
        nof_sif_reconfigs_before = self._phy_get_nof_sif_reconfigs()
        log.info('Number of PHY reconfiguration before traffic is {}'.format(nof_sif_reconfigs_before))

        iperf_args = copy.deepcopy(self.IPERF_ARGS)
        iperf_args["speed"] = speed
        iperf_args["direction"] = direction
        iperf_args["is_udp"] = False
        iperf_args["buffer_len"] = 128 * 1024

        iperf_runner = Iperf(**iperf_args)
        iperf_runner.run()
        results = iperf_runner.get_performance()

        log.info("Server result:")
        for res in results:
            log.info(res)

        for res in results:
            for b in res.bandwidth:
                assert b > 1, 'Bandwidth is low'

        self.postcondition(speed=speed, beginning_nof_sif_reconfigs=nof_sif_reconfigs_before)

    def run_iperf_udp_test(self, speed, direction, pkt_sizes, mtu):
        self.precondition(speed, mtu)
        nof_sif_reconfigs_before = self._phy_get_nof_sif_reconfigs()
        log.info('Number of PHY reconfiguration before traffic is {}'.format(nof_sif_reconfigs_before))

        iperf_args = copy.deepcopy(self.IPERF_ARGS)
        iperf_args["speed"] = speed
        iperf_args["direction"] = direction
        iperf_args["is_udp"] = True
        iperf_args["bandwidth"] = 50

        iperfs = []

        time.sleep(self.BEFORE_TRAFFIC_DELAY)

        for i, pkt_size in enumerate(pkt_sizes):
            iperf = Iperf(port=5201 + i * 100, buffer_len=pkt_size, **iperf_args)
            iperf.run_async()
            iperfs.append(iperf)
        results = []
        for iperf in iperfs:
            iperf.join()
            results.append(iperf.get_performance())

        for result in results:
            for res in result:
                log.info(res)
                for b in res.bandwidth:
                    assert b > 0.1, 'Bandwidth is low'

        self.postcondition(speed=speed, beginning_nof_sif_reconfigs=nof_sif_reconfigs_before)

    def run_ping_flood_from_lkp_test(self, speed, mtu):
        for i in range(self.PING_FLOOD_CHECKS):
            log.info("{} ping flood check".format(i + 1))
            self.precondition(speed, mtu)
            nof_sif_reconfigs_before = self._phy_get_nof_sif_reconfigs()
            log.info('Number of PHY reconfiguration before traffic is {}'.format(nof_sif_reconfigs_before))

            Command(cmd='touch {}'.format(self.PING_LOG_PATH), host=self.lkp_hostname).run()
            cmd = "sudo ping -f {} > {}".format(self.DUT_IPV4_ADDR, self.PING_LOG_PATH)
            cmd = Command(cmd=cmd, host=self.lkp_hostname)
            cmd.run_async()

            start = timeit.default_timer()
            while True:
                nof_sif_reconfigs_after = self._phy_get_nof_sif_reconfigs()
                if (nof_sif_reconfigs_before != nof_sif_reconfigs_after) | \
                   (timeit.default_timer() - start > self.PING_FLOOD_TIME):
                    cmd.join(1)
                    Killer(host=self.lkp_hostname).kill("ping")
                    break
                time.sleep(5)

            self.postcondition(speed=speed, beginning_nof_sif_reconfigs=nof_sif_reconfigs_before)

    def run_test_different_bandwidth(self, speed, mtu, direction, pkt_size=64):
        skip_different_bandwidth_test = str_to_bool(os.environ.get("SKIP_DIFFERENT_BANDWIDTH_TEST", "False"))
        if skip_different_bandwidth_test:
            pytest.skip("Skip long test")
        self.precondition(speed, mtu)

        iperf_args = copy.deepcopy(self.IPERF_ARGS)
        iperf_args["speed"] = speed
        iperf_args["direction"] = direction
        iperf_args["is_udp"] = True
        iperf_args["buffer_len"] = pkt_size
        iperf_args["port"] = 5201
        iperf_args["window"] = "4m"
        iperf_args["time"] = 60
        bandwidth_pcnt = 0.01

        while bandwidth_pcnt < 1:
            nof_sif_reconfigs_before = self._phy_get_nof_sif_reconfigs()
            log.info('Number of PHY reconfiguration before traffic is {}'.format(nof_sif_reconfigs_before))
            iperf_args.update({'buffer_len': int(pkt_size + 3 * iperf_args["bandwidth"])})
            iperf_args["bandwidth"] = SPEED_TO_MBITS[speed] * bandwidth_pcnt
            time.sleep(self.BEFORE_TRAFFIC_DELAY)
            iperf = Nuttcp(**iperf_args)
            iperf.run_async()
            iperf.join()
            assert all(bandw > 1 for bandw in iperf.results[0].bandwidth)
            assert numpy.mean(iperf.results[0].bandwidth) > iperf_args["bandwidth"] * 0.5

            self.postcondition(speed=speed, beginning_nof_sif_reconfigs=nof_sif_reconfigs_before)
            bandwidth_pcnt += 0.01

    def run_test_eee_negotiation(self, speed, nof_negotiations=10):
        if speed not in self.supported_speeds:
            pytest.skip()

        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.set_link_speed(speed)
        if self.lkp_eee_enable:
            self.lkp_ifconfig.set_media_options(["full-duplex", "energy-efficient-ethernet"])
        else:
            self.lkp_ifconfig.set_media_options(["full-duplex"])

        self.lkp_ifconfig.wait_link_up()
        self.dut_ifconfig.wait_link_up()
        nof_sif_reconfigs_before = self._phy_get_nof_sif_reconfigs()
        log.info('Number of PHY reconfiguration before EEE config is {}'.format(nof_sif_reconfigs_before))

        for i in range(nof_negotiations):
            log.info("Loop cycle #{}".format(i + 1))
            log.info("Checking that EEE can be negotiated")
            self.dut_ifconfig.set_media_options(["full-duplex", "energy-efficient-ethernet"])
            self.dut_ifconfig.wait_link_up()
            self.dut_ifconfig.check_media_options(["full-duplex", "energy-efficient-ethernet"])
            nof_sif_reconfigs_after = self._phy_get_nof_sif_reconfigs()
            log.info('Number of PHY reconfiguration before EEE config is {}'.format(nof_sif_reconfigs_after))
            assert nof_sif_reconfigs_after == nof_sif_reconfigs_before + 1, "There was unexpected additional link down \
                immediately after EEE enabled"

            log.info("Checking that EEE can be disabled")
            self.dut_ifconfig.set_media_options(["full-duplex"])
            self.dut_ifconfig.wait_link_up()
            self.dut_ifconfig.check_media_options(["full-duplex"])
            nof_sif_reconfigs_before = self._phy_get_nof_sif_reconfigs()
            log.info('Number of PHY reconfiguration before EEE config is {}'.format(nof_sif_reconfigs_before))
            assert nof_sif_reconfigs_after + 1 == nof_sif_reconfigs_before, "There was unexpected additional link down \
                immediately after EEE disabled"

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_eee_negotiation(self, speed):
        """
        @description: This test checks EEE negotiation.

        @steps:
        1. In the loop 10G/5G/2,5G/1G link speed::
            a. Enable EEE advertizement.
            b. Make sure that EEE is negotiated.
            c. Disable EEE advertisement.
            d. Make sure that EEE is not negotiated.

        @result: All checks are passed.
        @duration: 5 minutes.
        """
        self.run_test_eee_negotiation(speed=speed)

    # LPI check
    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_lpi_check(self, speed):
        """
        @description: Check LPI indication of EEE mode for different link speeds.

        @steps:
        1. In loop for 10G/5G/2,5G/1G link speed:
            a. Set EEE mode.
            b. Check that EEE is negotiated.
            c. Check that LPI indication is detected.
            d. Run continuous TCP traffic. During 2 minutes check that LPI indication changes its status.
            e. After traffic check that EEE is still negotiated, LPI indication is enabled and there are no MAC/PHY
                link drops.

        @result: All checks are passed.
        @duration: 15 minutes for each link speed.
        """
        self.run_test_lpi_checks(speed=speed, mtu=9000)

    # TCP tests
    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_iperf_tcp(self, speed):
        """
        @description: Check EEE mode with TCP traffic load.

        @steps:
        1. In loop for 10G/5G/2,5G/1G link speed:
            a. Set EEE mode.
            b. Check that EEE is negotiated.
            c. Run TCP traffic during 2 minutes.
            d. After traffic check that EEE is still negotiated and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 5 minutes for each speed.
        """
        self.run_iperf_tcp_test(speed=speed, mtu=9000, direction=DIRECTION_RX)

    # UDP tests
    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_iperf_udp_30_40_50(self, speed, direction):
        """
        @description: Check EEE mode under RX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. In loop for 10G/5G/2,5G/1G link speed and RX/TX directions:
            a. Set EEE mode.
            b. Check that EEE is negotiated.
            c. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in RX direction during 2 minutes.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 10 minutes for each speed.
        """
        self.run_iperf_udp_test(speed=speed, direction=direction, pkt_sizes=[30, 40, 50], mtu=1500)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_iperf_udp_30_40_1400(self, speed, direction):
        """
        @description: Check EEE mode under bidirectional UDP traffic with payload length: 30, 40 and 1400 bytes.

        @steps:
        1. In loop for 10G/5G/2,5G/1G link speed and RX/TX directions:
            a. Set EEE mode.
            b. Check that EEE is negotiated.
            c. Set mtu 1500. Run 2 UPD iperf streams with payload of 30, 1400 bytes in RXTX direction during 2 minutes.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 10 minutes for each speed.
        """
        self.run_iperf_udp_test(speed=speed, direction=direction, pkt_sizes=[30, 40, 1400], mtu=1500)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_iperf_udp_30_8000(self, speed, direction):
        """
        @description: Check EEE mode under bidirectional UDP traffic with payload length: 30, 8000 bytes.

        @steps:
        1. In loop for 10G/5G/2,5G/1G link speed and RX/TX directions:
            a. Set EEE mode.
            b. Check that EEE is negotiated.
            c. Set mtu 9000. Run 2 UPD iperf streams with payload of 30, 8000 bytes in RXTX direction during 2 minutes.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 10 minutes for each speed.
        """
        self.run_iperf_udp_test(speed=speed, direction=direction, pkt_sizes=[30, 8000], mtu=9000)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_iperf_udp_30_4000_8000(self, speed, direction):
        """
        @description: Check EEE mode under RX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. In loop for 10G/5G/2,5G/1G link speed and RX/TX directions:
            a. Set EEE mode.
            b. Check that EEE is negotiated.
            c. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in RX direction during 2
                minutes.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 10 minutes for each speed.
        """
        self.run_iperf_udp_test(speed=speed, direction=direction, pkt_sizes=[30, 4000, 8000], mtu=9000)

    # Ping Flood tests
    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_ping_flood(self, speed):
        """
        @description: Check EEE mode during ping flood traffic.

        @steps:
        1. In loop for 10G/5G/2,5G/1G link speed and RX/TX directions:
            a. Set EEE mode.
            b. Check that EEE is negotiated.
            c. Run ping flood traffic during 5 minutes. Every 5 seconds check that there are no MAC/PHY link drops.
            d. After traffic check that EEE is still negotiated.

        @result: All checks are passed.
        @duration: 2 hours for each speed.
        """
        self.run_ping_flood_from_lkp_test(speed=speed, mtu=9000)

    # Different bandwidth tests
    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    @idparametrize("direction", [DIRECTION_RX, DIRECTION_TX])
    def test_extl_different_bandwidth(self, speed, direction):
        """
        @description: Check EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3.5 hours for each speed.
        """
        self.run_test_different_bandwidth(speed=speed, direction=direction, mtu=9000)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
