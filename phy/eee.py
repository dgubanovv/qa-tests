import copy
import os
import sys
import time
import timeit
import numpy

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from infra.test_base import idparametrize
from infra.test_base_phy import TestBasePhy
from tools.command import Command
from tools.atltoolper import AtlTool
from tools.constants import FELICITY_CARDS, LINK_SPEED_AUTO, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, \
    LINK_SPEED_5G, LINK_SPEED_10G, DIRECTION_RX, DIRECTION_TX, DIRECTION_RXTX, CARD_NIKKI, SPEED_TO_MBITS, MTU_1500
from tools.driver import Driver
from tools.killer import Killer
from perf.iperf import Iperf
from perf.nuttcp import Nuttcp
from perf.iperf_result import IperfResult
from tools.iptables import IPTables
from tools.utils import get_atf_logger, str_to_bool
from tools.ifconfig import IfconfigLocalWithSeparatePhy

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "eee_external_internal_phy"


class TestPhyEee(TestBasePhy):
    """
    @description: The TestPhyEee test is dedicated to verify External and Internal EEE mode.

    @setup: Felicity <-> Dac cable <-> separate PHY <-> Eth cable <-> LKP 
    """
    PING_LOG_PATH = "pingFlood.log"
    BEFORE_TRAFFIC_DELAY = 10
    IPERF_TIME = 120
    PING_FLOOD_TIME = 300

    @classmethod
    def setup_class(cls):
        super(TestPhyEee, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.dut_fw_version = '3x/3.0.179-3.0.179_iloz_eee_debug_504-iloz-714'
            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            cls.IPERF_ARGS = {
                'direction': None,
                'speed': None,
                'num_threads': 1,
                'num_process': 1,
                'time': 10,
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
                cls.lkp_eee_enable = False
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestPhyEee, cls).teardown_class()

        command_rm = 'rm -rf {}'.format(cls.PING_LOG_PATH)
        Command(cmd=command_rm, host=cls.dut_hostname).run()
        Command(cmd=command_rm, host=cls.lkp_hostname).run()

    def setup_method(self, method):
        super(TestPhyEee, self).setup_method(method)
        Killer().kill("iperf3")
        Killer(host=self.lkp_hostname).kill("iperf3")
        Killer().kill("ping")
        Killer(host=self.lkp_hostname).kill("ping")
        Killer().kill("nuttcp")
        Killer(host=self.dut_hostname).kill("nuttcp")
        Killer().kill("nuttcp")
        Killer(host=self.lkp_hostname).kill("nuttcp")

    def teardown_method(self, method):
        super(TestPhyEee, self).teardown_method(method)
        nof_sif_reconfigs_after = self._phy_get_nof_sif_reconfigs()
        log.info('Number of PHY reconfiguration after test is {}'.format(nof_sif_reconfigs_after))

    def _setup_link_and_eee(self, speed, eee_mode='external'):
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()
        nof_sif_reconfigs_after = self._phy_get_nof_sif_reconfigs()
        log.info('Number of PHY reconfiguration before EEE config is {}'.format(nof_sif_reconfigs_after))

        if self.lkp_eee_enable:
            self.lkp_ifconfig.set_media_options(["full-duplex", "energy-efficient-ethernet"])
        else:
            self.lkp_ifconfig.set_media_options(["full-duplex"])
        self.dut_ifconfig.set_media_options(["full-duplex", "energy-efficient-ethernet"],
                                            eee_mode=eee_mode)
        nof_sif_reconfigs_after = self._phy_get_nof_sif_reconfigs()
        log.info('Number of PHY reconfiguration after EEE config is {}'.format(nof_sif_reconfigs_after))

        assert speed == self.dut_ifconfig.wait_link_up()
        assert speed == self.lkp_ifconfig.wait_link_up()

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
                # Double check that EEE is enabled
                lkp_374_reg = self.lkp_atltool.readreg(0x374)
                assert lkp_374_reg & speed_to_eee_map[speed] == 0

        log.info("EEE is active")

    def _set_mtu(self, mtu):
        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu)

    def apply_eee_provisioning(self, speed):
        if speed == LINK_SPEED_10G or speed == LINK_SPEED_1G:
            self.dut_ifconfig.phy_hard_reset()
        # A.0002 = 0x3 Conditional provision
        # 1E.C4A0.0 = 0x1
        # 1.E800.0 = 0x1
        # 1E.7001.A:8 = 0x1 // External EEE mode Ingress side
        # 1E.4001.A:8 = 0x1 // External EEE mode Egress side
        # When we are in external EEE we need to pass the LPIs across the MACSEC, RSI, TSI.
        # 3.C49E.1 = 0x0  // xgsMacsecNetworkSgmiiRxErrorSuppressionEnable = 0
        # 3.C499.1 = 0x0  // xgsMacsecSystemSgmiiRxErrorSuppressionEnable = 0
        # 1D.C290.2 = 0x0 // tsiTxErSuppressionEnable = 0x0
        # 1D.C350.8 = 0x0 // rsiTxErSuppressionEnable = 0x0
        self.phy_control.rmap.fw.FwProvisioningControl().conditionalProvisioningOperator.rmw(self.phy_control, 3)
        self.phy_control.rmap.glb.GlobalEeeProvisioning_1().eeeMode.rmw(self.phy_control, 1)
        self.phy_control.rmap.pma.PmaReceiveVendorState_1().pmaReceiveLinkCurrentStatus.rmw(self.phy_control, 1)
        self.phy_control.rmap.secing.SecIngressControlRegister_2().secIngressEeeMode.rmw(self.phy_control, 1)
        self.phy_control.rmap.seceg.SecEgressControlRegister_2().secEgressEeeMode.rmw(self.phy_control, 1)
        self.phy_control.rmap.pcs.PcsTransmitXgsVendorProvisioning_31().xgsMacsecNetworkSgmiiRxErrorSuppressionEnable.rmw(self.phy_control, 0)
        self.phy_control.rmap.pcs.PcsTransmitXgsVendorProvisioning_26().xgsMacsecSystemSgmiiRxErrorSuppressionEnable.rmw(self.phy_control, 0)
        self.phy_control.rmap.gbe.GbePhyTsi1Control_1().tsiTxErSuppressionEnable.rmw(self.phy_control, 0)
        self.phy_control.rmap.gbe.GbePhyRsi1Control_1().rsiTxErSuppressionEnable.rmw(self.phy_control, 0)
        if speed == LINK_SPEED_10G or speed == LINK_SPEED_1G:
            self.dut_ifconfig.phy_restart_autoneg()
        time.sleep(self.BEFORE_TRAFFIC_DELAY)
        log.info('PHY was provicioned to external EEE mode')

    def precondition(self, speed, mtu, eee_mode=''):
        if speed not in self.supported_speeds:
            pytest.skip()
        state_external_eee = self.phy_control.rmap.secing.SecIngressControlRegister_2().secIngressEeeMode.readValue(self.phy_control)
        log.info('external EEE mode is {}'.format('true' if state_external_eee == 1 else 'false'))
        if state_external_eee != 1 and eee_mode == 'external':
            self.apply_eee_provisioning(speed=speed)

        self._set_mtu(mtu)  # set MTU before EEE because is causes link down
        self._setup_link_and_eee(speed, eee_mode=eee_mode)

        self.dut_ifconfig.wait_link_up()
        self.lkp_ifconfig.wait_link_up()

        log.info('verify that EEE is negotiated after all configurations')
        if eee_mode == 'external':
            self.verify_eee_is_up(speed)  # verify that EEE is negotiated after all configurations
        if (speed == LINK_SPEED_5G or speed == LINK_SPEED_2_5G) and eee_mode == 'external':
            # Link down/up clear configured provisionning on 2.5G/5G link speed, so need to apply it again
            self.apply_eee_provisioning(speed=speed)
        assert self._phy_get_lpi_status(speed=speed, direction='rx') == 1, 'Rx EEE LPI indication is disabled'
        assert self._phy_get_lpi_status(speed=speed, direction='tx') == 1, 'Tx EEE LPI indication is disabled'
        time.sleep(self.BEFORE_TRAFFIC_DELAY)

    def postcondition(self, beginning_nof_sif_reconfigs, speed, eee_mode=''):
        nof_sif_reconfigs_after = self._phy_get_nof_sif_reconfigs()
        assert beginning_nof_sif_reconfigs == nof_sif_reconfigs_after, "Link down during ping flood detected"
        log.info('verify that EEE is negotiated after test')
        if eee_mode == 'external':
            self.verify_eee_is_up(speed)  # verify that EEE is negotiated after all configurations
        assert self._phy_get_lpi_status(speed=speed, direction='rx') == 1, 'Rx EEE LPI indication is disabled'
        assert self._phy_get_lpi_status(speed=speed, direction='tx') == 1, 'Tx EEE LPI indication is disabled'
        log.info('RX and TX LPI indication are enabled')
        # Add check BAD statistic counters

    def _phy_get_nof_sif_reconfigs(self):
        return self.phy_control.rmap.fw.SifFwDebug_7().numberOfSifReconfigs.readValue(self.phy_control)

    def _phy_get_lpi_status(self, speed='', direction=''):
        if speed == LINK_SPEED_2_5G or speed == LINK_SPEED_5G or speed == LINK_SPEED_10G:
            if direction == 'tx':
                return self.phy_control.rmap.pcs.PcsStandardStatus_1().txLpiIndication.readValue(self.phy_control)
            elif direction == 'rx':
                return self.phy_control.rmap.pcs.PcsStandardStatus_1().rxLpiReceived.readValue(self.phy_control)
        elif speed == LINK_SPEED_1G:
            if direction == 'tx':
                return self.phy_control.rmap.gbe.GbePhyTgeStatus_4().tgeEeeTxLpiIndication.readValue(self.phy_control)
            elif direction == 'rx':
                return self.phy_control.rmap.gbe.GbePhyTgeStatus_3().tgeEeeRxLpiIndication.readValue(self.phy_control)

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

    def run_iperf_tcp_test(self, speed=LINK_SPEED_1G, direction=DIRECTION_RXTX, mtu=MTU_1500, eee_mode='external'):
        self.precondition(speed, mtu, eee_mode=eee_mode)
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

        self.postcondition(speed=speed, beginning_nof_sif_reconfigs=nof_sif_reconfigs_before, eee_mode=eee_mode)

    def run_iperf_udp_test(self, speed=LINK_SPEED_1G, direction=DIRECTION_RXTX, pkt_sizes=[1400],
                           mtu=MTU_1500, eee_mode='external'):
        self.precondition(speed, mtu, eee_mode=eee_mode)
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

        self.postcondition(speed=speed, beginning_nof_sif_reconfigs=nof_sif_reconfigs_before, eee_mode=eee_mode)

    def run_ping_flood_from_lkp_test(self, speed, ping_size=80, mtu=MTU_1500, eee_mode='external'):
        self.precondition(speed, mtu, eee_mode=eee_mode)
        nof_sif_reconfigs_before = self._phy_get_nof_sif_reconfigs()
        log.info('Number of PHY reconfiguration before traffic is {}'.format(nof_sif_reconfigs_before))

        Command(cmd='touch {}'.format(self.PING_LOG_PATH), host=self.lkp_hostname).run()
        cmd = "sudo ping -f {} > {}".format(self.DUT_IPV4_ADDR, self.PING_LOG_PATH)
        cmd = Command(cmd=cmd, host=self.lkp_hostname)
        cmd.run_async()

        start = timeit.default_timer()
        while True:
            nof_sif_reconfigs_after = self._phy_get_nof_sif_reconfigs()
            if (nof_sif_reconfigs_before != nof_sif_reconfigs_after) | (timeit.default_timer() - start > self.PING_FLOOD_TIME):
                cmd.join(1)
                break
            time.sleep(5)

        self.postcondition(speed=speed, beginning_nof_sif_reconfigs=nof_sif_reconfigs_before, eee_mode=eee_mode)

    def run_test_eee_negotiation(self, speed=LINK_SPEED_1G, nof_negotiations=10, eee_mode='external'):
        if speed not in self.supported_speeds:
            pytest.skip()
        if speed in [LINK_SPEED_2_5G, LINK_SPEED_5G] and eee_mode == 'internal':
            # Link down/up clear configured provicionning on 2.5G/5G link speed
            pytest.skip()

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_ifconfig.set_link_speed(speed)

        if self.lkp_eee_enable:
            self.lkp_ifconfig.set_media_options(["full-duplex", "energy-efficient-ethernet"])
        else:
            self.lkp_ifconfig.set_media_options(["full-duplex"])

        self.lkp_ifconfig.wait_link_up()
        self.dut_ifconfig.wait_link_up()

        for i in range(nof_negotiations):
            log.info("Loop cycle #{}".format(i + 1))
            log.info("Checking that EEE can be negotiated")
            self.dut_ifconfig.set_media_options(["full-duplex", "energy-efficient-ethernet"],
                                                eee_mode=eee_mode)
            self.dut_ifconfig.wait_link_up()
            self.dut_ifconfig.check_media_options(["full-duplex", "energy-efficient-ethernet"], eee_mode=eee_mode)

            log.info("Checking that EEE can be disabled")
            self.dut_ifconfig.set_media_options(["full-duplex"], eee_mode=eee_mode)
            self.dut_ifconfig.wait_link_up()
            self.dut_ifconfig.check_media_options(["full-duplex"], eee_mode=eee_mode)

    def run_test_lpi_checks(self, speed='', pkt_sizes=[1400], mtu=MTU_1500, eee_mode='external'):
        self.precondition(speed, mtu, eee_mode=eee_mode)

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

    def run_test_different_bandwidth(self, speed='', pkt_size=64, mtu=MTU_1500, eee_mode='external', direction=''):
        skip_different_bandwidth_test = str_to_bool(os.environ.get("SKIP_DIFFERENT_BANDWIDTH_TEST", "False"))
        if skip_different_bandwidth_test:
            pytest.skip("Skip long test")
        self.precondition(speed, mtu, eee_mode=eee_mode)

        iperf_args = copy.deepcopy(self.IPERF_ARGS)
        iperf_args["speed"] = speed
        iperf_args["direction"] = direction
        iperf_args["is_udp"] = True
        iperf_args["buffer_len"] = pkt_size
        iperf_args["port"] = 5201
        iperf_args["window"] = "4m"
        iperf_args["time"] = 30
        bandwidth_pcnt = 0.005

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

            self.postcondition(speed=speed, beginning_nof_sif_reconfigs=nof_sif_reconfigs_before, eee_mode=eee_mode)
            bandwidth_pcnt += 0.005

    # Enternal PHY EEE mode
    ################################################################################
    # EEE NEGOTIATION TESTS ########################################################
    ################################################################################

    def test_extl_eee_negotiation_1g(self):
        """
        @description: This test checks Enternal 1G EEE mode negotiation.

        @steps:
        1. In the loop:
            a. Enable EEE advertizement for 1G and set Enternal EEE mode.
            b. Make sure that EEE is negotiated.
            c. Disable EEE advertisement for 1G.
            d. Make sure that EEE is not negotiated.

        @result: All checks are passed.
        @duration: 5 minutes.
        """
        self.run_test_eee_negotiation(speed=LINK_SPEED_1G)

    def test_extl_eee_negotiation_2_5g(self):
        """
        @description: This test checks Enternal 2.5G EEE mode negotiation.

        @steps:
        1. In the loop:
            a. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
            b. Make sure that EEE is negotiated.
            c. Disable EEE advertisement for 2.5G.
            d. Make sure that EEE is not negotiated.

        @result: All checks are passed.
        @duration: 5 minutes.
        """
        self.run_test_eee_negotiation(speed=LINK_SPEED_2_5G)

    def test_extl_eee_negotiation_5g(self):
        """
        @description: This test checks Enternal 5G EEE mode negotiation.

        @steps:
        1. In the loop:
            a. Enable EEE advertizement for 5G and set Enternal EEE mode.
            b. Make sure that EEE is negotiated.
            c. Disable EEE advertisement for 5G.
            d. Make sure that EEE is not negotiated.

        @result: All checks are passed.
        @duration: 5 minutes.
        """
        self.run_test_eee_negotiation(speed=LINK_SPEED_5G)

    def test_extl_eee_negotiation_10g(self):
        """
        @description: This test checks Enternal 10G EEE mode negotiation.

        @steps:
        1. In the loop:
            a. Enable EEE advertizement for 10G and set Enternal EEE mode.
            b. Make sure that EEE is negotiated.
            c. Disable EEE advertisement for 10G.
            d. Make sure that EEE is not negotiated.

        @result: All checks are passed.
        @duration: 5 minutes.
        """
        self.run_test_eee_negotiation(speed=LINK_SPEED_10G)

    ###############################################################################
    # IPERF TESTS WITH LPI CHECK ##################################################
    ###############################################################################

    def test_extl_lpi_check_1g(self):
        """
        @description: This test checks LPI indication of Enternal 1G EEE mode.

        @steps:
        1. Enable EEE advertizement for 1G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Check that LPI indication is detected.
        4. Run continuous TCP traffic.
            a. During 2 minutes check that LPI indication changes its status.
        5. After traffic check that EEE is still negotiated, LPI indication is enabled and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_test_lpi_checks(speed=LINK_SPEED_1G)

    def test_extl_lpi_check_2_5g(self):
        """
        @description: This test checks LPI indication of Enternal 2.5G EEE mode.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Check that LPI indication is detected.
        4. Run continuous TCP traffic.
            a. During 2 minutes check that LPI indication changes its status.
        5. After traffic check that EEE is still negotiated, LPI indication is enabled and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_test_lpi_checks(speed=LINK_SPEED_2_5G)

    def test_extl_lpi_check_5g(self):
        """
        @description: This test checks LPI indication of Enternal 5G EEE mode.

        @steps:
        1. Enable EEE advertizement for 5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Check that LPI indication is detected.
        4. Run continuous TCP traffic.
            a. During 2 minutes check that LPI indication changes its status.
        5. After traffic check that EEE is still negotiated, LPI indication is enabled and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_test_lpi_checks(speed=LINK_SPEED_5G)

    def test_extl_lpi_check_10g(self):
        """
        @description: This test checks LPI indication of Enternal 10G EEE mode.

        @steps:
        1. Enable EEE advertizement for 10G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Check that LPI indication is detected.
        4. Run continuous TCP traffic.
            a. During 2 minutes check that LPI indication changes its status.
        5. After traffic check that EEE is still negotiated, LPI indication is enabled and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_test_lpi_checks(speed=LINK_SPEED_10G)

    ################################################################################
    # IPERF TCP TESTS ##############################################################
    ################################################################################

    def test_extl_iperf_tcp_eee_1g(self):
        """
        @description: This test checks Enternal 1G EEE mode with TCP traffic load.

        @steps:
        1. Enable EEE advertizement for 1G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Run TCP traffic during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_tcp_test(speed=LINK_SPEED_1G)

    def test_extl_iperf_tcp_eee_2_5g(self):
        """
        @description: This test checks Enternal 2.5G EEE mode with TCP traffic load.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Run TCP traffic during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_tcp_test(speed=LINK_SPEED_2_5G)

    def test_extl_iperf_tcp_eee_5g(self):
        """
        @description: This test checks Enternal 5G EEE mode with TCP traffic load.

        @steps:
        1. Enable EEE advertizement for 5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Run TCP traffic during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_tcp_test(speed=LINK_SPEED_5G)

    def test_extl_iperf_tcp_eee_10g(self):
        """
        @description: This test checks Enternal 10G EEE mode with TCP traffic load.

        @steps:
        1. Enable EEE advertizement for 10G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Run TCP traffic during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_tcp_test(speed=LINK_SPEED_10G)

    ################################################################################
    # IPERF UDP TESTS ##############################################################
    ################################################################################

    def test_extl_iperf_udp_eee_1g_pkt_sizes_30_40_50_rx(self):
        """
        @description: This test checks Enternal 1G EEE mode under RX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, direction=DIRECTION_RX, pkt_sizes=[30, 40, 50], mtu=1500)

    def test_extl_iperf_udp_eee_1g_pkt_sizes_30_40_50_tx(self):
        """
        @description: This test checks Enternal 1G EEE mode under TX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, direction=DIRECTION_TX, pkt_sizes=[30, 40, 50], mtu=1500)

    def test_extl_iperf_udp_eee_1g_pkt_sizes_30_1400(self):
        """
        @description: This test checks Enternal 1G EEE mode under bidirectional UDP traffic with payload length: 30, 1400 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 2 UPD iperf streams with payload of 30, 1400 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, pkt_sizes=[30, 1400], mtu=1500)

    def test_extl_iperf_udp_eee_1g_pkt_sizes_30_8000(self):
        """
        @description: This test checks Enternal 1G EEE mode under bidirectional UDP traffic with payload length: 30, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 2 UPD iperf streams with payload of 30, 8000 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, pkt_sizes=[30, 8000], mtu=9000)

    def test_extl_iperf_udp_eee_1g_pkt_sizes_30_4000_8000_rx(self):
        """
        @description: This test checks Enternal 1G EEE mode under RX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, direction=DIRECTION_RX, pkt_sizes=[30, 4000, 8000], mtu=9000)

    def test_extl_iperf_udp_eee_1g_pkt_sizes_30_4000_8000_tx(self):
        """
        @description: This test checks Enternal 1G EEE mode under TX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, direction=DIRECTION_TX, pkt_sizes=[30, 4000, 8000], mtu=9000)

    def test_extl_iperf_udp_eee_2_5g_pkt_sizes_30_40_50_rx(self):
        """
        @description: This test checks Enternal 2.5G EEE mode under RX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, direction=DIRECTION_RX, pkt_sizes=[30, 40, 50], mtu=1500)

    def test_extl_iperf_udp_eee_2_5g_pkt_sizes_30_40_50_tx(self):
        """
        @description: This test checks Enternal 2.5G EEE mode under TX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, direction=DIRECTION_TX, pkt_sizes=[30, 40, 50], mtu=1500)

    def test_extl_iperf_udp_eee_2_5g_pkt_sizes_30_40_1400(self):
        """
        @description: This test checks Enternal 2.5G EEE mode under bidirectional UDP traffic with payload length: 30, 1400 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 2 UPD iperf streams with payload of 30, 1400 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, pkt_sizes=[30, 40, 1400], mtu=1500)

    def test_extl_iperf_udp_eee_2_5g_pkt_sizes_30_8000(self):
        """
        @description: This test checks Enternal 2.5G EEE mode under bidirectional UDP traffic with payload length: 30, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 2 UPD iperf streams with payload of 30, 8000 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, pkt_sizes=[30, 8000], mtu=9000)

    def test_extl_iperf_udp_eee_2_5g_pkt_sizes_30_4000_8000_rx(self):
        """
        @description: This test checks Enternal 2.5G EEE mode under RX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, direction=DIRECTION_RX, pkt_sizes=[30, 4000, 8000], mtu=9000)

    def test_extl_iperf_udp_eee_2_5g_pkt_sizes_30_4000_8000_tx(self):
        """
        @description: This test checks Enternal 2.5G EEE mode under TX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, direction=DIRECTION_TX, pkt_sizes=[30, 4000, 8000], mtu=9000)

    def test_extl_iperf_udp_eee_5g_pkt_sizes_30_40_50_rx(self):
        """
        @description: This test checks Enternal 5G EEE mode under RX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, direction=DIRECTION_RX, pkt_sizes=[30, 40, 50], mtu=1500)

    def test_extl_iperf_udp_eee_5g_pkt_sizes_30_40_50_tx(self):
        """
        @description: This test checks Enternal 5G EEE mode under TX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, direction=DIRECTION_TX, pkt_sizes=[30, 40, 50], mtu=1500)

    def test_extl_iperf_udp_eee_5g_pkt_sizes_30_40_1400(self):
        """
        @description: This test checks Enternal 5G EEE mode under bidirectional UDP traffic with payload length: 30, 1400 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 2 UPD iperf streams with payload of 30, 1400 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, pkt_sizes=[30, 40, 1400], mtu=1500)

    def test_extl_iperf_udp_eee_5g_pkt_sizes_30_8000(self):
        """
        @description: This test checks Enternal 5G EEE mode under bidirectional UDP traffic with payload length: 30, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 2 UPD iperf streams with payload of 30, 8000 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, pkt_sizes=[30, 8000], mtu=9000)

    def test_extl_iperf_udp_eee_5g_pkt_sizes_30_4000_8000_rx(self):
        """
        @description: This test checks Enternal 5G EEE mode under RX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, direction=DIRECTION_RX, pkt_sizes=[30, 4000, 8000], mtu=9000)

    def test_extl_iperf_udp_eee_5g_pkt_sizes_30_4000_8000_tx(self):
        """
        @description: This test checks Enternal 5G EEE mode under TX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, direction=DIRECTION_TX, pkt_sizes=[30, 4000, 8000], mtu=9000)

    def test_extl_iperf_udp_eee_10g_pkt_sizes_30_40_50_rx(self):
        """
        @description: This test checks Enternal 10G EEE mode under RX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, direction=DIRECTION_RX, pkt_sizes=[30, 40, 50], mtu=1500)

    def test_extl_iperf_udp_eee_10g_pkt_sizes_30_40_50_tx(self):
        """
        @description: This test checks Enternal 10G EEE mode under TX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, direction=DIRECTION_TX, pkt_sizes=[30, 40, 50], mtu=1500)

    def test_extl_iperf_udp_eee_10g_pkt_sizes_30_40_1400(self):
        """
        @description: This test checks Enternal 10G EEE mode under bidirectional UDP traffic with payload length: 30, 1400 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 2 UPD iperf streams with payload of 30, 1400 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, pkt_sizes=[30, 40, 1400], mtu=1500)

    def test_extl_iperf_udp_eee_10g_pkt_sizes_30_8000(self):
        """
        @description: This test checks Enternal 10G EEE mode under bidirectional UDP traffic with payload length: 30, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 2 UPD iperf streams with payload of 30, 8000 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, pkt_sizes=[30, 8000], mtu=9000)

    def test_extl_iperf_udp_eee_10g_pkt_sizes_30_4000_8000_rx(self):
        """
        @description: This test checks Enternal 10G EEE mode under RX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, direction=DIRECTION_RX, pkt_sizes=[30, 4000, 8000], mtu=9000)

    def test_extl_iperf_udp_eee_10g_pkt_sizes_30_4000_8000_tx(self):
        """
        @description: This test checks Enternal 10G EEE mode under TX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, direction=DIRECTION_TX, pkt_sizes=[30, 4000, 8000], mtu=9000)

    ###############################################################################
    # DIFFERENT BANDWIDTH TESTS ###################################################
    ###############################################################################

    def test_extl_different_bandwidth_rx_1g(self):
        """
        @description: This test checks Enternal 1G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 1G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_1G, direction=DIRECTION_RX)

    def test_extl_different_bandwidth_tx_1g(self):
        """
        @description: This test checks Enternal 1G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 1G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run TX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_1G, direction=DIRECTION_TX)

    def test_extl_different_bandwidth_rxtx_1g(self):
        """
        @description: This test checks Enternal 1G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 1G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RXTX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_1G, direction=DIRECTION_RXTX)

    def test_extl_different_bandwidth_rx_2_5g(self):
        """
        @description: This test checks Enternal 2.5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_2_5G, direction=DIRECTION_RX)

    def test_extl_different_bandwidth_tx_2_5g(self):
        """
        @description: This test checks Enternal 2.5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run TX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_2_5G, direction=DIRECTION_TX)

    def test_extl_different_bandwidth_rxtx_2_5g(self):
        """
        @description: This test checks Enternal 2.5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RXTX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_2_5G, direction=DIRECTION_RXTX)

    def test_extl_different_bandwidth_rx_5g(self):
        """
        @description: This test checks Enternal 5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 5G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_5G, direction=DIRECTION_RX)

    def test_extl_different_bandwidth_tx_5g(self):
        """
        @description: This test checks Enternal 5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 5G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run TX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_5G, direction=DIRECTION_TX)

    def test_extl_different_bandwidth_rxtx_5g(self):
        """
        @description: This test checks Enternal 5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 5G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RXTX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_5G, direction=DIRECTION_RXTX)

    def test_extl_different_bandwidth_rx_10g(self):
        """
        @description: This test checks Enternal 10G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 10G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_10G, direction=DIRECTION_RX)

    def test_extl_different_bandwidth_tx_10g(self):
        """
        @description: This test checks Enternal 10G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 10G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run TX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_10G, direction=DIRECTION_TX)

    def test_extl_different_bandwidth_rxtx_10g(self):
        """
        @description: This test checks Enternal 10G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 10G and set Enternal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RXTX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_10G, direction=DIRECTION_RXTX)

    ###############################################################################
    # PING FLOOD TESTS ############################################################
    ###############################################################################

    def test_extl_ping_flood_from_lkp_1g(self):
        """
        @description: This test checks Enternal 1G EEE mode during ping flood traffic.

        @steps:
        1. Enable EEE advertizement for 1G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Run ping flood traffic during 5 minutes.
            a. Every 5 seconds check that there are no MAC/PHY link drops.
        4. After traffic check that EEE is still negotiated.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_ping_flood_from_lkp_test(speed=LINK_SPEED_1G)

    def test_extl_ping_flood_from_lkp_2_5g(self):
        """
        @description: This test checks Enternal 2.5G EEE mode during ping flood traffic.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Run ping flood traffic during 5 minutes.
            a. Every 5 seconds check that there are no MAC/PHY link drops.
        4. After traffic check that EEE is still negotiated.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_ping_flood_from_lkp_test(speed=LINK_SPEED_2_5G)

    def test_extl_ping_flood_from_lkp_5g(self):
        """
        @description: This test checks Enternal 5G EEE mode during ping flood traffic.

        @steps:
        1. Enable EEE advertizement for 5G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Run ping flood traffic during 5 minutes.
            a. Every 5 seconds check that there are no MAC/PHY link drops.
        4. After traffic check that EEE is still negotiated.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_ping_flood_from_lkp_test(speed=LINK_SPEED_5G)

    def test_extl_ping_flood_from_lkp_10g(self):
        """
        @description: This test checks Enternal 10G EEE mode during ping flood traffic.

        @steps:
        1. Enable EEE advertizement for 10G and set Enternal EEE mode.
        2. Check that EEE is negotiated.
        3. Run ping flood traffic during 5 minutes.
            a. Every 5 seconds check that there are no MAC/PHY link drops.
        4. After traffic check that EEE is still negotiated.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_ping_flood_from_lkp_test(speed=LINK_SPEED_10G)

    # Internal PHY EEE mode
    ################################################################################
    # EEE NEGOTIATION TESTS ########################################################
    ################################################################################

    def test_intl_eee_negotiation_1g(self):
        """
        @description: This test checks Internal 1G EEE mode negotiation.

        @steps:
        1. In the loop:
            a. Enable EEE advertizement for 1G and set Internal EEE mode.
            b. Make sure that EEE is negotiated.
            c. Disable EEE advertisement for 1G.
            d. Make sure that EEE is not negotiated.

        @result: All checks are passed.
        @duration: 5 minutes.
        """
        self.run_test_eee_negotiation(speed=LINK_SPEED_1G, eee_mode='internal')

    def test_intl_eee_negotiation_2_5g(self):
        """
        @description: This test checks Internal 2.5G EEE mode negotiation.

        @steps:
        1. In the loop:
            a. Enable EEE advertizement for 2.5G and set Internal EEE mode.
            b. Make sure that EEE is negotiated.
            c. Disable EEE advertisement for 2.5G.
            d. Make sure that EEE is not negotiated.

        @result: All checks are passed.
        @duration: 5 minutes.
        """
        self.run_test_eee_negotiation(speed=LINK_SPEED_2_5G, eee_mode='internal')

    def test_intl_eee_negotiation_5g(self):
        """
        @description: This test checks Internal 5G EEE mode negotiation.

        @steps:
        1. In the loop:
            a. Enable EEE advertizement for 5G and set Internal EEE mode.
            b. Make sure that EEE is negotiated.
            c. Disable EEE advertisement for 5G.
            d. Make sure that EEE is not negotiated.

        @result: All checks are passed.
        @duration: 5 minutes.
        """
        self.run_test_eee_negotiation(speed=LINK_SPEED_5G, eee_mode='internal')

    def test_intl_eee_negotiation_10g(self):
        """
        @description: This test checks Internal 10G EEE mode negotiation.

        @steps:
        1. In the loop:
            a. Enable EEE advertizement for 10G and set Internal EEE mode.
            b. Make sure that EEE is negotiated.
            c. Disable EEE advertisement for 10G.
            d. Make sure that EEE is not negotiated.

        @result: All checks are passed.
        @duration: 5 minutes.
        """
        self.run_test_eee_negotiation(speed=LINK_SPEED_10G, eee_mode='internal')

    ###############################################################################
    # IPERF TESTS WITH LPI CHECK ##################################################
    ###############################################################################

    def test_intl_lpi_check_1g(self):
        """
        @description: This test checks LPI indication of Internal 1G EEE mode.

        @steps:
        1. Enable EEE advertizement for 1G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Check that LPI indication is detected.
        4. Run continuous TCP traffic.
            a. During 2 minutes check that LPI indication changes its status.
        5. After traffic check that EEE is still negotiated, LPI indication is enabled and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_test_lpi_checks(speed=LINK_SPEED_1G, eee_mode='internal')

    def test_intl_lpi_check_2_5g(self):
        """
        @description: This test checks LPI indication of Internal 2.5G EEE mode.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Check that LPI indication is detected.
        4. Run continuous TCP traffic.
            a. During 2 minutes check that LPI indication changes its status.
        5. After traffic check that EEE is still negotiated, LPI indication is enabled and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_test_lpi_checks(speed=LINK_SPEED_2_5G, eee_mode='internal')

    def test_intl_lpi_check_5g(self):
        """
        @description: This test checks LPI indication of Internal 5G EEE mode.

        @steps:
        1. Enable EEE advertizement for 5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Check that LPI indication is detected.
        4. Run continuous TCP traffic.
            a. During 2 minutes check that LPI indication changes its status.
        5. After traffic check that EEE is still negotiated, LPI indication is enabled and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_test_lpi_checks(speed=LINK_SPEED_5G, eee_mode='internal')

    def test_intl_lpi_check_10g(self):
        """
        @description: This test checks LPI indication of Internal 10G EEE mode.

        @steps:
        1. Enable EEE advertizement for 10G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Check that LPI indication is detected.
        4. Run continuous TCP traffic.
            a. During 2 minutes check that LPI indication changes its status.
        5. After traffic check that EEE is still negotiated, LPI indication is enabled and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_test_lpi_checks(speed=LINK_SPEED_10G, eee_mode='internal')

    ################################################################################
    # IPERF TCP TESTS ##############################################################
    ################################################################################

    def test_intl_iperf_tcp_eee_1g(self):
        """
        @description: This test checks Internal 1G EEE mode with TCP traffic load.

        @steps:
        1. Enable EEE advertizement for 1G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Run TCP traffic during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_tcp_test(speed=LINK_SPEED_1G, eee_mode='internal')

    def test_intl_iperf_tcp_eee_2_5g(self):
        """
        @description: This test checks Internal 2.5G EEE mode with TCP traffic load.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Run TCP traffic during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_tcp_test(speed=LINK_SPEED_2_5G, eee_mode='internal')

    def test_intl_iperf_tcp_eee_5g(self):
        """
        @description: This test checks Internal 5G EEE mode with TCP traffic load.

        @steps:
        1. Enable EEE advertizement for 5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Run TCP traffic during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_tcp_test(speed=LINK_SPEED_5G, eee_mode='internal')

    def test_intl_iperf_tcp_eee_10g(self):
        """
        @description: This test checks Internal 10G EEE mode with TCP traffic load.

        @steps:
        1. Enable EEE advertizement for 10G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Run TCP traffic during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no MAC/PHY link drops.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_tcp_test(speed=LINK_SPEED_10G, eee_mode='internal')

    ################################################################################
    # IPERF UDP TESTS ##############################################################
    ################################################################################

    def test_intl_iperf_udp_eee_1g_pkt_sizes_30_40_50_rx(self):
        """
        @description: This test checks Internal 1G EEE mode under RX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, direction=DIRECTION_RX, pkt_sizes=[30, 40, 50], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_1g_pkt_sizes_30_40_50_tx(self):
        """
        @description: This test checks Internal 1G EEE mode under TX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, direction=DIRECTION_TX, pkt_sizes=[30, 40, 50], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_1g_pkt_sizes_30_1400(self):
        """
        @description: This test checks Internal 1G EEE mode under bidirectional UDP traffic with payload length: 30, 1400 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 2 UPD iperf streams with payload of 30, 1400 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, pkt_sizes=[30, 1400], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_1g_pkt_sizes_30_8000(self):
        """
        @description: This test checks Internal 1G EEE mode under bidirectional UDP traffic with payload length: 30, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 2 UPD iperf streams with payload of 30, 8000 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, pkt_sizes=[30, 8000], mtu=9000,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_1g_pkt_sizes_30_4000_8000_rx(self):
        """
        @description: This test checks Internal 1G EEE mode under RX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, direction=DIRECTION_RX, pkt_sizes=[30, 4000, 8000], mtu=9000,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_1g_pkt_sizes_30_4000_8000_tx(self):
        """
        @description: This test checks Internal 1G EEE mode under TX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 1G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_1G, direction=DIRECTION_TX, pkt_sizes=[30, 4000, 8000], mtu=9000,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_2_5g_pkt_sizes_30_40_50_rx(self):
        """
        @description: This test checks Internal 2.5G EEE mode under RX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, direction=DIRECTION_RX, pkt_sizes=[30, 40, 50], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_2_5g_pkt_sizes_30_40_50_tx(self):
        """
        @description: This test checks Internal 2.5G EEE mode under TX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, direction=DIRECTION_TX, pkt_sizes=[30, 40, 50], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_2_5g_pkt_sizes_30_40_1400(self):
        """
        @description: This test checks Internal 2.5G EEE mode under bidirectional UDP traffic with payload length: 30, 1400 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 2 UPD iperf streams with payload of 30, 1400 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, pkt_sizes=[30, 40, 1400], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_2_5g_pkt_sizes_30_8000(self):
        """
        @description: This test checks Internal 2.5G EEE mode under bidirectional UDP traffic with payload length: 30, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 2 UPD iperf streams with payload of 30, 8000 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, pkt_sizes=[30, 8000], mtu=9000,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_2_5g_pkt_sizes_30_4000_8000_rx(self):
        """
        @description: This test checks Internal 2.5G EEE mode under RX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, direction=DIRECTION_RX, pkt_sizes=[30, 4000, 8000], mtu=9000,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_2_5g_pkt_sizes_30_4000_8000_tx(self):
        """
        @description: This test checks Internal 2.5G EEE mode under TX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_2_5G, direction=DIRECTION_TX, pkt_sizes=[30, 4000, 8000], mtu=9000,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_5g_pkt_sizes_30_40_50_rx(self):
        """
        @description: This test checks Internal 5G EEE mode under RX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, direction=DIRECTION_RX, pkt_sizes=[30, 40, 50], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_5g_pkt_sizes_30_40_50_tx(self):
        """
        @description: This test checks Internal 5G EEE mode under TX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, direction=DIRECTION_TX, pkt_sizes=[30, 40, 50], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_5g_pkt_sizes_30_40_1400(self):
        """
        @description: This test checks Internal 5G EEE mode under bidirectional UDP traffic with payload length: 30, 1400 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 2 UPD iperf streams with payload of 30, 1400 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, pkt_sizes=[30, 40, 1400], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_5g_pkt_sizes_30_8000(self):
        """
        @description: This test checks Internal 5G EEE mode under bidirectional UDP traffic with payload length: 30, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 2 UPD iperf streams with payload of 30, 8000 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, pkt_sizes=[30, 8000], mtu=9000,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_5g_pkt_sizes_30_4000_8000_rx(self):
        """
        @description: This test checks Internal 5G EEE mode under RX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, direction=DIRECTION_RX, pkt_sizes=[30, 4000, 8000], mtu=9000,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_5g_pkt_sizes_30_4000_8000_tx(self):
        """
        @description: This test checks Internal 5G EEE mode under TX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_5G, direction=DIRECTION_TX, pkt_sizes=[30, 4000, 8000], mtu=9000,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_10g_pkt_sizes_30_40_50_rx(self):
        """
        @description: This test checks Internal 10G EEE mode under RX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, direction=DIRECTION_RX, pkt_sizes=[30, 40, 50], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_10g_pkt_sizes_30_40_50_tx(self):
        """
        @description: This test checks Internal 10G EEE mode under TX UDP traffic with payload length: 30, 40, 50 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 3 UPD iperf streams with payload of 30, 40, 50 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, direction=DIRECTION_TX, pkt_sizes=[30, 40, 50], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_10g_pkt_sizes_30_40_1400(self):
        """
        @description: This test checks Internal 10G EEE mode under bidirectional UDP traffic with payload length: 30, 1400 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 1500. Run 2 UPD iperf streams with payload of 30, 1400 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, pkt_sizes=[30, 40, 1400], mtu=1500,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_10g_pkt_sizes_30_8000(self):
        """
        @description: This test checks Internal 10G EEE mode under bidirectional UDP traffic with payload length: 30, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 2 UPD iperf streams with payload of 30, 8000 bytes in RXTX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, pkt_sizes=[30, 8000], mtu=9000,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_10g_pkt_sizes_30_4000_8000_rx(self):
        """
        @description: This test checks Internal 10G EEE mode under RX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in RX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, direction=DIRECTION_RX, pkt_sizes=[30, 4000, 8000], mtu=9000,
                                eee_mode='internal')

    def test_intl_iperf_udp_eee_10g_pkt_sizes_30_4000_8000_tx(self):
        """
        @description: This test checks Internal 10G EEE mode under TX UDP traffic with payload length: 30, 4000, 8000 bytes.

        @steps:
        1. Enable EEE advertizement for 10G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Set mtu 9000. Run 3 UPD iperf streams with payload of 30, 4000, 8000 bytes in TX direction during 2 minutes.
        4. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        self.run_iperf_udp_test(speed=LINK_SPEED_10G, direction=DIRECTION_TX, pkt_sizes=[30, 4000, 8000], mtu=9000,
                                eee_mode='internal')

    ###############################################################################
    # DIFFERENT BANDWIDTH TESTS ###################################################
    ###############################################################################

    def test_intl_different_bandwidth_rx_1g(self):
        """
        @description: This test checks Internal 1G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 1G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_1G, direction=DIRECTION_RX, eee_mode='internal')

    def test_intl_different_bandwidth_tx_1g(self):
        """
        @description: This test checks Internal 1G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 1G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run TX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_1G, direction=DIRECTION_TX, eee_mode='internal')

    def test_intl_different_bandwidth_rxtx_1g(self):
        """
        @description: This test checks Internal 1G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 1G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RXTX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_1G, direction=DIRECTION_RXTX, eee_mode='internal')

    def test_intl_different_bandwidth_rx_2_5g(self):
        """
        @description: This test checks Internal 2.5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 2.5G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_2_5G, direction=DIRECTION_RX, eee_mode='internal')

    def test_intl_different_bandwidth_tx_2_5g(self):
        """
        @description: This test checks Internal 2.5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 2.5G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run TX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_2_5G, direction=DIRECTION_TX, eee_mode='internal')

    def test_intl_different_bandwidth_rxtx_2_5g(self):
        """
        @description: This test checks Internal 2.5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 2.5G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RXTX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_2_5G, direction=DIRECTION_RXTX, eee_mode='internal')

    def test_intl_different_bandwidth_rx_5g(self):
        """
        @description: This test checks Internal 5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 5G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_5G, direction=DIRECTION_RX, eee_mode='internal')

    def test_intl_different_bandwidth_tx_5g(self):
        """
        @description: This test checks Internal 5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 5G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run TX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_5G, direction=DIRECTION_TX, eee_mode='internal')

    def test_intl_different_bandwidth_rxtx_5g(self):
        """
        @description: This test checks Internal 5G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 5G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RXTX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_5G, direction=DIRECTION_RXTX, eee_mode='internal')

    def test_intl_different_bandwidth_rx_10g(self):
        """
        @description: This test checks Internal 10G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 10G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_10G, direction=DIRECTION_RX, eee_mode='internal')

    def test_intl_different_bandwidth_tx_10g(self):
        """
        @description: This test checks Internal 10G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 10G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run TX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_10G, direction=DIRECTION_TX, eee_mode='internal')

    def test_intl_different_bandwidth_rxtx_10g(self):
        """
        @description: This test checks Internal 10G EEE mode during some different traffic bandwidth.

        @steps:
        1. In the loop, every loop increase bandwidth by 5%:
            a. Enable EEE advertizement for 10G and set Internal EEE mode.
            b. Check that EEE is negotiated.
            c. Run RXTX UPD iperf stream with fixed bandwidth.
            d. After traffic check that EEE is still negotiated and there are no PHY reinitializations.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_test_different_bandwidth(speed=LINK_SPEED_10G, direction=DIRECTION_RXTX, eee_mode='internal')

    ###############################################################################
    # PING FLOOD TESTS ############################################################
    ###############################################################################

    def test_intl_ping_flood_from_lkp_1g(self):
        """
        @description: This test checks Internal 1G EEE mode during ping flood traffic.

        @steps:
        1. Enable EEE advertizement for 1G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Run ping flood traffic during 5 minutes.
            a. Every 5 seconds check that there are no MAC/PHY link drops.
        4. After traffic check that EEE is still negotiated.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_ping_flood_from_lkp_test(speed=LINK_SPEED_1G, eee_mode='internal')

    def test_intl_ping_flood_from_lkp_2_5g(self):
        """
        @description: This test checks Internal 2.5G EEE mode during ping flood traffic.

        @steps:
        1. Enable EEE advertizement for 2.5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Run ping flood traffic during 5 minutes.
            a. Every 5 seconds check that there are no MAC/PHY link drops.
        4. After traffic check that EEE is still negotiated.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_ping_flood_from_lkp_test(speed=LINK_SPEED_2_5G, eee_mode='internal')

    def test_intl_ping_flood_from_lkp_5g(self):
        """
        @description: This test checks Internal 5G EEE mode during ping flood traffic.

        @steps:
        1. Enable EEE advertizement for 5G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Run ping flood traffic during 5 minutes.
            a. Every 5 seconds check that there are no MAC/PHY link drops.
        4. After traffic check that EEE is still negotiated.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_ping_flood_from_lkp_test(speed=LINK_SPEED_5G, eee_mode='internal')

    def test_intl_ping_flood_from_lkp_10g(self):
        """
        @description: This test checks Internal 10G EEE mode during ping flood traffic.

        @steps:
        1. Enable EEE advertizement for 10G and set Internal EEE mode.
        2. Check that EEE is negotiated.
        3. Run ping flood traffic during 5 minutes.
            a. Every 5 seconds check that there are no MAC/PHY link drops.
        4. After traffic check that EEE is still negotiated.

        @result: All checks are passed.
        @duration: 6 minutes.
        """
        self.run_ping_flood_from_lkp_test(speed=LINK_SPEED_10G, eee_mode='internal')


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
