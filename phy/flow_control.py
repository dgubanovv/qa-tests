import copy
import os
import pytest
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hlh.mac import MAC
from hlh.phy import PHY, collect_phy_fifo_level
from infra.test_base import idparametrize, Iperf
from infra.test_base_phy import TestBasePhy
from perf.iperf_result import IperfResult
from tools.aqpkt import Aqsendp
from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_10G, ENABLE, DISABLE, INGRESS, EGRESS, MII_MODE_XFI_DIV2, MII_MODE_OCSGMII, RATE_ADAPTATION_UNKNOW, \
    RATE_ADAPTATION_PAUSE
from tools.constants import MII_MODE_SGMII, MII_MODE_XFI
from tools.constants import MTU_16000, DIRECTION_TX, DIRECTION_RX, SPEED_TO_MBITS
from tools.driver import Driver
from tools.iptables import IPTables
from tools.killer import Killer
from tools.utils import get_atf_logger
from trafficgen.traffic_gen import Packets, calc_pause_frames_per_second

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "flow_control_external_phy"


class TestPhyFlowControl(TestBasePhy):
    """
    @description: The TestPhyFlowControl test is dedicated to configure PHY to disable/enable pause frame generation
    and processing and verify pause frame counters after test finished to send traffic.

    @setup: Felicity <-> Dac cable <-> separate PHY <-> Eth cable <-> LKP
    """

    @classmethod
    def setup_class(cls):
        super(TestPhyFlowControl, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.dut_iface = cls.dut_ifconfig.get_conn_name()
            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()

            cls.dut_mac_address = cls.dut_ifconfig.get_mac_address()
            cls.lkp_mac_address = cls.lkp_ifconfig.get_mac_address()

            cls.iptables = IPTables(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname)

            cls.IPERF_ARGS = {
                'direction': None,
                'is_udp': False,
                'speed': None,
                'num_threads': 1,
                'num_process': 1,
                'ipv': 4,
                'criterion': IperfResult.SANITY,
                'bandwidth': 0,
                'buffer_len': 16000,
                'dut': cls.dut_hostname,
                'lkp': cls.lkp_hostname,
                'dut4': cls.DUT_IPV4_ADDR,
                'lkp4': cls.LKP_IPV4_ADDR,
                'time': 16
            }

            cls.dut_atltool = AtlTool(port=cls.dut_port)
            cls.lkp_atltool = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            cls.iptables = IPTables(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname)
            cls.iptables.clean()

            cls.dut_phy = PHY(phy_control=cls.phy_controls[0])
            cls.dut_mac = MAC(port=cls.dut_port, host=cls.dut_hostname)

            cls.lkp_phy = PHY(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_mac = MAC(port=cls.lkp_port, host=cls.lkp_hostname)

            cls.prev_mode = None

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestPhyFlowControl, self).setup_method(method)

    def teardown_method(self, method):
        super(TestPhyFlowControl, self).teardown_method(method)

        Killer().kill("iperf3")
        Killer(host=self.lkp_hostname).kill("iperf3")

        Killer().kill("aqsendp")
        Killer(host=self.lkp_hostname).kill("aqsendp")

    def precondition(self, speed):
        MAP_SPEED_TO_MODE = {
            LINK_SPEED_10G: MII_MODE_XFI,
            LINK_SPEED_5G: MII_MODE_XFI_DIV2,
            LINK_SPEED_2_5G: MII_MODE_OCSGMII,
            LINK_SPEED_1G: MII_MODE_SGMII,
            LINK_SPEED_100M: MII_MODE_SGMII
        }
        rate = RATE_ADAPTATION_UNKNOW

        # patch:
        #     europa not support PHI/2 mode, so
        #     instead XFI/2 using XFI with adaptation mode
        if self.dut_phy.is_europa():
            MAP_SPEED_TO_MODE[LINK_SPEED_5G] = MII_MODE_XFI
            rate = RATE_ADAPTATION_PAUSE

        phy_mode = MAP_SPEED_TO_MODE[speed]

        self.dut_phy.set_security_bit(speed=speed, state=ENABLE)
        self.dut_phy.set_mode(speed=speed, mode=phy_mode, rate=rate)

        self.lkp_phy.set_security_bit(speed=speed, state=ENABLE)

        self.dut_ifconfig.set_mtu(MTU_16000)
        self.lkp_ifconfig.set_mtu(MTU_16000)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_ifconfig.set_link_speed(speed, mac_sif_mode=phy_mode)

        assert speed == self.lkp_ifconfig.wait_link_up()
        assert speed == self.dut_ifconfig.wait_link_up()

        self.dut_phy.set_flow_control(state=DISABLE)
        self.lkp_phy.set_flow_control(state=DISABLE)

        log.info('PHY STATUS DUT: {}'.format(self.dut_phy.get_status()))
        log.info('PHY STATUS LKP: {}'.format(self.lkp_phy.get_status()))

        lkp_ip_address = self.lkp_ifconfig.get_ip_address()
        if isinstance(lkp_ip_address, list):
            lkp_ip_address = lkp_ip_address[0]

        assert self.ping(from_host='localhost', to_host=lkp_ip_address, number=4)

    def run_iperf_test(self, speed, direction, gen_pf='none', quanta=0xff, rate=200):
        iperf_args = copy.deepcopy(self.IPERF_ARGS)
        iperf_args["speed"] = speed
        iperf_args["direction"] = direction
        iperf_args["bandwidth"] = SPEED_TO_MBITS[speed]

        time.sleep(10)

        result = None

        for i in range(5):
            Killer().kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")

            Killer().kill("aqsendp")
            Killer(host=self.lkp_hostname).kill("aqsendp")

            log.info('Try iperf #{}'.format(i))
            iperf = Iperf(**iperf_args)
            iperf.run_async()
            time.sleep(2)

            if gen_pf != 'none':
                log.info('Send pause frames ---> quanta: 0x{:0X}    rate: {}'.format(quanta, rate))
                mac = self.lkp_mac_address if gen_pf == 'lkp' else self.dut_mac_address
                pause_frame_pkt = Packets.get_pause_frames_packets(src_mac=mac, quanta=quanta)
                host_run = self.dut_hostname if gen_pf == 'dut' else self.lkp_hostname
                iface = self.dut_iface if gen_pf == 'dut' else self.lkp_iface
                send_pf = Aqsendp(timeout=iperf_args['time'] - 4, rate=rate, iface=iface, host=host_run,
                                  packet=pause_frame_pkt)
                time.sleep(2)
                send_pf.run_async()

            direct = EGRESS if direction == DIRECTION_TX else INGRESS
            levels = collect_phy_fifo_level(self.dut_phy, direction=direct, timeout=iperf_args['time'])
            log.info('PHY FIFO LEVEL: {}'.format(['0x{:03x}'.format(e) for e in levels]))

            if gen_pf != 'none':
                send_pf.join(timeout=1)

            if iperf.join() == Iperf.IPERF_OK:
                result = iperf.get_performance()
                break

        if result:
            log.debug('+' * 120)
            for r in result:
                log.debug(r)
            log.debug('+' * 120)

        return result

    ##########################################################################################################

    def _send_pause_frames(self, gen_pf='dut', quanta=0xff, rate=200, timeout=10):
        log.info('Send pause frames ---> quanta: 0x{:0X}    rate: {}'.format(quanta, rate))
        mac = self.lkp_mac_address if gen_pf == 'lkp' else self.dut_mac_address
        pause_frame_pkt = Packets.get_pause_frames_packets(src_mac=mac, quanta=quanta)
        host_run = self.dut_hostname if gen_pf == 'dut' else self.lkp_hostname
        iface = self.dut_iface if gen_pf == 'dut' else self.lkp_iface
        send_pf = Aqsendp(count=timeout * rate, rate=rate, iface=iface, host=host_run, packet=pause_frame_pkt)
        send_pf.run()

    def _send_packet_frames(self, gen_pf='dut', quanta=0xff, rate=200, timeout=10):
        log.info('Send frames with rate: {}'.format(quanta, rate))
        src_mac = self.lkp_mac_address if gen_pf == 'lkp' else self.dut_mac_address
        dst_mac = self.dut_mac_address if gen_pf == 'lkp' else self.lkp_mac_address

        packets_args = {
            'mac_src': src_mac,
            'mac_dst': dst_mac,
            'pktsize': 512,
            'ipv': 4,
            'protocol': 'tcp'
        }

        pause_frame_pkt = Packets(**packets_args).to_str()

        host_run = self.dut_hostname if gen_pf == 'dut' else self.lkp_hostname
        iface = self.dut_iface if gen_pf == 'dut' else self.lkp_iface

        send_pf = Aqsendp(count=timeout * rate, rate=rate, iface=iface, host=host_run, packet=pause_frame_pkt)
        send_pf.run()

    @idparametrize('speed', [LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M])
    @idparametrize('typep', ['pause', 'packet', 'iperf'])
    def test_units_ing_dut(self, speed, typep):
        if speed not in self.supported_speeds:
            pytest.skip()

        self.precondition(speed=speed)
        self.dut_phy.set_fc_ingress_processing(state=ENABLE)
        self._read_and_print_before_stats()
        if typep == 'pause':
            self._send_pause_frames(gen_pf='dut', quanta=0xff, rate=100, timeout=5)
        elif typep == 'packet':
            self._send_packet_frames(gen_pf='dut', quanta=0xff, rate=100, timeout=5)
        else:
            self.run_iperf_test(speed=speed, direction=DIRECTION_RX)

        self._read_and_print_after_stats()

        log.info('PHY STATUS DUT: {}'.format(self.dut_phy.get_status()))
        log.info('PHY STATUS LKP: {}'.format(self.lkp_phy.get_status()))

        dut_phy_msm = self.dut_phy.get_counters_msm()
        lkp_phy_msm = self.lkp_phy.get_counters_msm()
        self._print_phy_counters(dut_phy_msm, lkp_phy_msm)

        if typep == 'pause':
            assert dut_phy_msm['MSM SIF Rx Pause Frame Counter'] == 500
            assert lkp_phy_msm['MSM LINE Rx Pause Frame Counter'] == 500
        else:
            assert dut_phy_msm['MSM SIF Rx Good Frame Counter'] >= 500
            assert lkp_phy_msm['MSM LINE Rx Good Frame Counter'] >= 500

    @idparametrize('speed', [LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M])
    def test_units_ing_lkp(self, speed):
        if speed not in self.supported_speeds:
            pytest.skip()

        self.precondition(speed=speed)
        self.dut_phy.set_fc_ingress_processing(state=ENABLE)
        self._read_and_print_before_stats()
        self._send_pause_frames(gen_pf='lkp', quanta=0xff, rate=100, timeout=5)
        self._read_and_print_after_stats()

        log.info('PHY STATUS DUT: {}'.format(self.dut_phy.get_status()))
        log.info('PHY STATUS LKP: {}'.format(self.lkp_phy.get_status()))

        dut_phy_msm = self.dut_phy.get_counters_msm()
        lkp_phy_msm = self.lkp_phy.get_counters_msm()
        self._print_phy_counters(dut_phy_msm, lkp_phy_msm)

        assert dut_phy_msm['MSM LINE Rx Pause Frame Counter'] == 500
        assert lkp_phy_msm['MSM SIF Rx Pause Frame Counter'] == 500

    @idparametrize('speed', [LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M])
    def test_units_eg_dut(self, speed):
        if speed not in self.supported_speeds:
            pytest.skip()

        self.precondition(speed=speed)
        self.dut_phy.set_fc_egress_processing(state=ENABLE)
        self._read_and_print_before_stats()
        self._send_pause_frames(gen_pf='dut', quanta=0xff, rate=100, timeout=5)
        self._read_and_print_after_stats()

        log.info('PHY STATUS DUT: {}'.format(self.dut_phy.get_status()))
        log.info('PHY STATUS LKP: {}'.format(self.lkp_phy.get_status()))

        dut_phy_msm = self.dut_phy.get_counters_msm()
        lkp_phy_msm = self.lkp_phy.get_counters_msm()
        self._print_phy_counters(dut_phy_msm, lkp_phy_msm)

        assert dut_phy_msm['MSM SIF Rx Pause Frame Counter'] == 500

    @idparametrize('speed', [LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M])
    def test_units_eg_lkp(self, speed):
        if speed not in self.supported_speeds:
            pytest.skip()

        self.precondition(speed=speed)
        self.dut_phy.set_fc_egress_processing(state=ENABLE)
        self._read_and_print_before_stats()
        self._send_pause_frames(gen_pf='lkp', quanta=0xff, rate=100, timeout=5)
        self._read_and_print_after_stats()

        log.info('PHY STATUS DUT: {}'.format(self.dut_phy.get_status()))
        log.info('PHY STATUS LKP: {}'.format(self.lkp_phy.get_status()))

        dut_phy_msm = self.dut_phy.get_counters_msm()
        lkp_phy_msm = self.lkp_phy.get_counters_msm()
        self._print_phy_counters(dut_phy_msm, lkp_phy_msm)

        assert dut_phy_msm['MSM LINE Rx Pause Frame Counter'] == 500
        assert lkp_phy_msm['MSM SIF Rx Pause Frame Counter'] == 500

    ##########################################################################################################

    def _print_phy_counters(self, dut_phy_msm, lkp_phy_msm):
        big_log = '\n'
        big_log += 'DUT MSM PHY:\n'
        big_log += '\n'
        for k in sorted(dut_phy_msm.keys()):
            big_log += '{:>50s}: {:>8} [{:>8x}]\n'.format(k, dut_phy_msm[k], dut_phy_msm[k])
        big_log += '\n'

        counters = self.dut_phy.get_counters_pcs()
        big_log += 'DUT PCS PHY:\n'
        big_log += '\n'
        for k in sorted(counters.keys()):
            big_log += '{:>50s}: {:>8} [{:>8x}]\n'.format(k, counters[k], counters[k])
        big_log += '\n'

        big_log += 'LKP MSM PHY:\n'
        big_log += '\n'
        for k in sorted(lkp_phy_msm.keys()):
            big_log += '{:>50s}: {:>8} [{:>8x}]\n'.format(k, lkp_phy_msm[k], lkp_phy_msm[k])
        big_log += '\n'

        counters = self.lkp_phy.get_counters_pcs()
        big_log += 'LKP PCS PHY:\n'
        big_log += '\n'
        for k in sorted(counters.keys()):
            big_log += '{:>50s}: {:>8} [{:>8x}]\n'.format(k, counters[k], counters[k])

        log.info(big_log)

    def _read_and_print_before_stats(self):
        self.dut_rx_mac_before, self.dut_tx_mac_before = self.dut_mac.get_counters_pause_frames()
        self.lkp_rx_mac_before, self.lkp_tx_mac_before = self.lkp_mac.get_counters_pause_frames()
        self.dut_rx_phy_before, self.dut_tx_phy_before = self.dut_phy.get_counters_pause_frames()
        self.lkp_rx_phy_before, self.lkp_tx_phy_before = self.lkp_phy.get_counters_pause_frames()

        log.info('BEFORE: ')
        log.info('  MAC: ')
        log.info('    DUT rx: {} tx: {}'.format(self.dut_rx_mac_before, self.dut_tx_mac_before))
        log.info('    LKP rx: {} tx: {}'.format(self.lkp_rx_mac_before, self.lkp_tx_mac_before))
        log.info('  PHY: ')
        log.info('    DUT rx: {} tx: {}'.format(self.dut_rx_phy_before, self.dut_tx_phy_before))
        log.info('    LKP rx: {} tx: {}'.format(self.lkp_rx_phy_before, self.lkp_tx_phy_before))

        dut_phy_msm = self.dut_phy.get_counters_msm()
        lkp_phy_msm = self.lkp_phy.get_counters_msm()
        self._print_phy_counters(dut_phy_msm, lkp_phy_msm)

    def _read_and_print_after_stats(self):
        self.dut_rx_mac_after, self.dut_tx_mac_after = self.dut_mac.get_counters_pause_frames()
        self.lkp_rx_mac_after, self.lkp_tx_mac_after = self.lkp_mac.get_counters_pause_frames()
        self.dut_rx_phy_after, self.dut_tx_phy_after = self.dut_phy.get_counters_pause_frames()
        self.lkp_rx_phy_after, self.lkp_tx_phy_after = self.lkp_phy.get_counters_pause_frames()

        log.info('AFTER: ')
        log.info('  MAC: ')
        log.info('    DUT rx: {} tx: {}'.format(self.dut_rx_mac_after, self.dut_tx_mac_after))
        log.info('    LKP rx: {} tx: {}'.format(self.lkp_rx_mac_after, self.lkp_tx_mac_after))
        log.info('  PHY: ')
        log.info('    DUT rx: {} tx: {}'.format(self.dut_rx_phy_after, self.dut_tx_phy_after))
        log.info('    LKP rx: {} tx: {}'.format(self.lkp_rx_phy_after, self.lkp_tx_phy_after))

    def subtest_phy_can_gen_pauseframes_to_mac(self, line):
        if line not in self.supported_speeds:
            pytest.skip()

        self.precondition(speed=line)

        self.dut_phy.set_fc_egress_generation(state=ENABLE)

        self._read_and_print_before_stats()

        self.run_iperf_test(speed=line, direction=DIRECTION_TX, gen_pf='lkp')

        self._read_and_print_after_stats()
        dut_phy_msm = self.dut_phy.get_counters_msm()
        lkp_phy_msm = self.lkp_phy.get_counters_msm()
        self._print_phy_counters(dut_phy_msm, lkp_phy_msm)

        assert self.dut_rx_mac_before < self.dut_rx_mac_after, 'DUT should have received pause frames'
        assert self.dut_tx_mac_before == self.dut_tx_mac_after, 'DUT should not send pause frames'
        assert self.lkp_rx_mac_before == self.lkp_rx_mac_after, 'LKP should not have received pause frames'
        assert self.lkp_tx_mac_before == self.lkp_tx_mac_after, 'LKP should not send pause frames'

    @idparametrize('speed', [LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M])
    def _test_pfm_gen_line_to_sif(self, speed):
        """
        @description: It should be possible enable egress (line -> sif) pause frame generation.

        @steps:
        1. configure PHY.
        2. run traffic
        3. check MAC counters

        @duration: 120 s.

        @requirements: PHY_MACSEC_FLOCONTROL_INGRESS_PAUSE_GENERATION_1,
        """
        self.subtest_phy_can_gen_pauseframes_to_mac(line=speed)

    ##########################################################################################################

    def subtest_phy_can_gen_pauseframes_to_lkp(self, line):
        if line not in self.supported_speeds:
            pytest.skip()

        self.precondition(speed=line)

        self.dut_phy.set_fc_ingress_generation(state=ENABLE)
        self.dut_phy.set_fc_egress_processing(state=ENABLE)

        self._read_and_print_before_stats()

        self.run_iperf_test(speed=line, direction=DIRECTION_RX, gen_pf='dut')

        self._read_and_print_after_stats()

        log.info('PHY STATUS DUT: {}'.format(self.dut_phy.get_status()))
        log.info('PHY STATUS LKP: {}'.format(self.lkp_phy.get_status()))

        dut_phy_msm = self.dut_phy.get_counters_msm()
        lkp_phy_msm = self.lkp_phy.get_counters_msm()
        self._print_phy_counters(dut_phy_msm, lkp_phy_msm)

        assert self.dut_rx_mac_before == self.dut_rx_mac_after, 'DUT should not have received pause frames'
        assert self.dut_tx_mac_before == self.dut_tx_mac_after, 'DUT should not send pause frames'
        assert self.lkp_rx_mac_before < self.lkp_rx_mac_after, 'LKP should have received pause frames'
        assert self.lkp_tx_mac_before == self.lkp_tx_mac_after, 'LKP should not send pause frames'

    @idparametrize('speed', [LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M])
    def test_pfm_gen_sif_to_line(self, speed):
        """
        @description: It should be possible enable ingress (sif -> line) pause frame generation.

        @steps:
        1. configure PHY.
        2. run traffic
        3. check MAC counters

        @duration: 120 s.

        @requirements: PHY_MACSEC_FLOCONTROL_EGRESS_PAUSE_GENERATION_1,
        """
        self.subtest_phy_can_gen_pauseframes_to_lkp(line=speed)

    ##########################################################################################################

    def subtest_phy_can_processing_pauseframes_from_mac(self, line):
        if line not in self.supported_speeds:
            pytest.skip()

        self.precondition(speed=line)
        self.dut_phy.set_fc_ingress_processing(state=ENABLE)
        self.lkp_phy.set_flow_control(state=ENABLE)

        self._read_and_print_before_stats()

        quanta = 0xfffe
        rate = int(calc_pause_frames_per_second(speed=line, timer_in_quantas=quanta) * 0.5)
        perf = self.run_iperf_test(speed=line, direction=DIRECTION_RX, gen_pf='dut', rate=rate, quanta=quanta)
        perf_max = max(perf[0].bandwidth)
        f_b = perf[0].bandwidth[0]
        l_b = perf[0].bandwidth[-1]

        self._read_and_print_after_stats()

        dut_phy_msm = self.dut_phy.get_counters_msm()
        lkp_phy_msm = self.lkp_phy.get_counters_msm()
        self._print_phy_counters(dut_phy_msm, lkp_phy_msm)

        assert perf_max > SPEED_TO_MBITS[line] * 0.70, 'Maximum speed of bandwidth must be with tolerance 70%'
        assert f_b > l_b, 'Bandwidth in the begin must be more that in the end'
        assert self.dut_rx_mac_before == self.dut_rx_mac_after, 'DUT should not have received pause frames'
        assert self.dut_tx_mac_before == self.dut_tx_mac_after, 'DUT should not send pause frames'
        assert self.lkp_rx_mac_before < self.lkp_rx_mac_after,  'LKP should have received pause frames'
        assert self.lkp_tx_mac_before == self.lkp_tx_mac_after, 'LKP should not send pause frames'

    @idparametrize('speed', [LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M])
    def test_pfm_proc_sif_to_line(self, speed):
        """
        @description: It should be possible enable ingress (line -> sif) pause frame processing.

        @steps:
        1. configure PHY.
        2. run traffic
        3. check MAC counters

        @duration: 120 s.

        @requirements: PHY_MACSEC_FLOCONTROL_INGRESS_PAUSE_PROCESSING_1,
        """
        self.subtest_phy_can_processing_pauseframes_from_mac(line=speed)

    ##########################################################################################################

    def subtest_phy_can_processing_pauseframes_from_lkp(self, line):
        if line not in self.supported_speeds:
            pytest.skip()

        self.precondition(speed=line)
        self.dut_phy.set_fc_egress_processing(state=ENABLE)
        self.lkp_phy.set_flow_control(state=DISABLE)

        self._read_and_print_before_stats()

        quanta = 0xfffe
        rate = int(calc_pause_frames_per_second(speed=line, timer_in_quantas=quanta) * 0.1)
        perf = self.run_iperf_test(speed=line, direction=DIRECTION_TX, gen_pf='lkp', quanta=quanta, rate=rate)
        perf_max = max(perf[0].bandwidth)
        f_b = perf[0].bandwidth[0]
        l_b = perf[0].bandwidth[-1]

        self._read_and_print_after_stats()

        dut_phy_msm = self.dut_phy.get_counters_msm()
        lkp_phy_msm = self.lkp_phy.get_counters_msm()
        self._print_phy_counters(dut_phy_msm, lkp_phy_msm)

        assert perf_max > SPEED_TO_MBITS[line] * 0.10, 'Maximum speed of bandwidth must be with tolerance 10%'
        assert f_b > l_b, 'Bandwidth in the begin must be more that in the end'
        assert self.dut_rx_mac_before < self.dut_rx_mac_after, 'DUT should have received pause frames'
        assert self.dut_tx_mac_before == self.dut_tx_mac_after, 'DUT should not send pause frames'
        assert self.lkp_rx_mac_before == self.lkp_rx_mac_after, 'LKP should not have received pause frames'
        assert self.lkp_tx_mac_before == self.lkp_tx_mac_after, 'LKP should not send pause frames'

    @idparametrize('speed', [LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M])
    def test_pfm_proc_line_to_sif(self, speed):
        """
        @description: It should be possible enable egress (sif -> line) pause frame processing.

        @steps:
        1. configure PHY.
        2. run traffic
        3. check MAC counters

        @duration: 120 s.

        @requirements: PHY_MACSEC_FLOCONTROL_EGRESS_PAUSE_PROCESSING_1,
        """
        self.subtest_phy_can_processing_pauseframes_from_lkp(line=speed)

    ##########################################################################################################

    def subtest_quanta_pauseframes(self, line, quanta):
        if line not in self.supported_speeds:
            pytest.skip()

        log.info('test: LINE: {}    SIF: {}    QUANTA: {:04x}'.format(line, MII_MODE_XFI, quanta))
        self.precondition(speed=line)
        self.dut_phy.set_fc_egress_processing(state=ENABLE)
        self.dut_phy.set_fc_ingress_processing(state=ENABLE)

        self._read_and_print_before_stats()

        rate = calc_pause_frames_per_second(speed=line, timer_in_quantas=quanta)
        perf = self.run_iperf_test(speed=line, direction=DIRECTION_TX, gen_pf='lkp', quanta=quanta, rate=rate / 2)
        iperf_avg = perf[0].get_avg_b()

        self._read_and_print_after_stats()

        dut_phy_msm = self.dut_phy.get_counters_msm()
        lkp_phy_msm = self.lkp_phy.get_counters_msm()
        self._print_phy_counters(dut_phy_msm, lkp_phy_msm)

        log.info('  IPERF AVG: {:.1f} Mbps'.format(iperf_avg))

        assert iperf_avg < (SPEED_TO_MBITS[line] * (5.0 / 8.0))

    @idparametrize('speed', [LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M])
    @idparametrize('quanta', [0xfff, 0x3fff, 0x7fff, 0xfffe])
    def test_quanta_pauseframes(self, speed, quanta):
        """
        @description: It should be possible set different values of quanta

        @steps:
        1. configure PHY.
        2. run traffic
        3. check that bandwidth of traffic changed

        @duration: 120 s.

        @requirements:
        """
        self.subtest_quanta_pauseframes(line=speed, quanta=quanta)

    ##########################################################################################################

    def subtest_threshold(self, line, threshold):
        if line not in self.supported_speeds:
            pytest.skip()

        log.info('test: LINE: {}    THRESHOLD: {:04x}'.format(line, threshold))
        self.precondition(speed=line)
        self.dut_phy.set_flow_control(state=ENABLE)
        self.dut_phy.set_fifo_threshold(direction=INGRESS, xon=threshold, xoff=threshold + 0x100)

        self._read_and_print_before_stats()

        perf = self.run_iperf_test(speed=line, direction=DIRECTION_RX, gen_pf='none')
        iperf_avg = perf[0].get_avg_b()

        self._read_and_print_after_stats()

        dut_phy_msm = self.dut_phy.get_counters_msm()
        lkp_phy_msm = self.lkp_phy.get_counters_msm()
        self._print_phy_counters(dut_phy_msm, lkp_phy_msm)

        log.info('  IPERF AVG: {:.1f} Mbps'.format(iperf_avg))

        assert self.dut_rx_mac_before == self.dut_rx_mac_after, 'DUT should not have received pause frames'
        assert self.dut_tx_mac_before == self.dut_tx_mac_after, 'DUT should not send pause frames'
        if threshold == 0x100:
            assert self.lkp_rx_mac_before < self.lkp_rx_mac_after, 'LKP should have received pause frames'
        else:
            assert self.lkp_rx_mac_before == self.lkp_rx_mac_after, 'LKP should have received pause frames'
        assert self.lkp_tx_mac_before == self.lkp_tx_mac_after, 'LKP should not send pause frames'

    @idparametrize('speed', [LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M])
    @idparametrize('threshold', [0x100, 0x1200])
    def test_fifo_threshold(self, speed, threshold):
        """
        @description: It should be possible configure FIFO with different values of threshold

        @steps:
        1. configure PHY.
        2. run traffic
        3. check MAC counters

        @duration: 120 s.

        @requirements:
        """
        self.subtest_threshold(line=speed, threshold=threshold)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
