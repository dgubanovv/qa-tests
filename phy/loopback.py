import os
import shutil
import sys
import time

import pytest


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hlh.mac import MAC
from hlh.phy import PHY
from tools.atltoolper import AtlTool
from tools.aqpkt import Aqsendp
from infra.test_base import idparametrize
from infra.test_base_phy import TestBasePhy
from trafficgen.traffic_gen import Packets
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_1G, LINK_SPEED_100M, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_10G, DISABLE, ENABLE, NO_LOOPBACK, SYSTEM_INTERFACE_SYSTEM_LOOPBACK, SYSTEM_INTERFACE_NETWORK_LOOPBACK, \
    NETWORK_INTERFACE_NETWORK_LOOPBACK, NETWORK_INTERFACE_SYSTEM_LOOPBACK, SYSTEM_SIDE_SHALLOW_LOOPBACK, LINE_SIDE_SHALLOW_LOOPBACK
from tools.driver import Driver
from tools.log import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "phy_loopback"


class TestPhyLoopback(TestBasePhy):
    PACKETS_COUNT = 4
    """
    @description: The TestPhyLoopback test is dedicated to configure loopback in PHY for all speeds.

    @setup: Nikki or Bermuda or Felicity <-> Dac cable <-> separate PHY
    """

    @classmethod
    def setup_class(cls):
        super(TestBasePhy, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            # cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            # cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            cls.dut_iface = cls.dut_ifconfig.get_conn_name()
            log.info('IFACE: {}'.format(cls.dut_iface))
            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()

            cls.dut_atltool = AtlTool(port=cls.dut_port)
            cls.lkp_atltool = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            cls.dut_phy = PHY(phy_control=cls.phy_controls[0])
            cls.dut_mac = MAC(port=cls.dut_port, host=cls.dut_hostname)

            cls.lkp_phy = PHY(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_mac = MAC(port=cls.lkp_port, host=cls.lkp_hostname)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestPhyLoopback, self).setup_method(method)

        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.dut_atltool.debug_buffer_enable(True)
            log.info('DUT DEBUG LOG: {}'.format(self.txt_log_file))

            self.lkp_atltool.debug_buffer_enable(True)
            self.lkp_atltool.enable_phy_logging(True)

    def teardown_method(self, method):
        super(TestPhyLoopback, self).teardown_method(method)

        if self.MCP_LOG:
            self.dut_atltool.enable_phy_logging(False)
            self.dut_atltool.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

            self.lkp_atltool.enable_phy_logging(False)
            self.lkp_bin_log_file, self.lkp_txt_log_file = self.lkp_atltool.debug_buffer_enable(False)
            shutil.copy(self.lkp_bin_log_file, self.test_log_dir)
            shutil.copy(self.lkp_txt_log_file, self.test_log_dir)

    def precondition(self, speed, loopback):
        if loopback not in [SYSTEM_SIDE_SHALLOW_LOOPBACK, LINE_SIDE_SHALLOW_LOOPBACK]:
            self.dut_phy.set_security_bit(speed=speed, state=DISABLE)
        else:
            self.dut_phy.set_security_bit(speed=speed, state=ENABLE)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_ifconfig.set_link_speed(speed)
        assert speed == self.dut_ifconfig.wait_link_up()
        assert speed == self.lkp_ifconfig.wait_link_up()

        time.sleep(2)

        self.dut_mac.set_flow_control(state=DISABLE)
        self.lkp_mac.set_flow_control(state=DISABLE)
        self.dut_phy.set_flow_control(state=DISABLE)
        self.lkp_phy.set_flow_control(state=DISABLE)

        time.sleep(5)

        self.dut_phy.set_loopback(loopback=loopback, speed=speed)

        time.sleep(1)

    def _read_and_print_before_stats_reg_frame(self):
        self.dut_rx_mac_before, self.dut_tx_mac_before = self.dut_mac.get_counters_reg_frames()
        self.lkp_rx_mac_before, self.lkp_tx_mac_before = self.lkp_mac.get_counters_reg_frames()

        log.info('BEFORE: ')
        log.info('  MAC: ')
        log.info('    DUT rx: {} tx: {}'.format(self.dut_rx_mac_before, self.dut_tx_mac_before))
        log.info('    LKP rx: {} tx: {}'.format(self.lkp_rx_mac_before, self.lkp_tx_mac_before))

    def _read_and_print_before_stats(self):
        if self.loopback in [SYSTEM_SIDE_SHALLOW_LOOPBACK, LINE_SIDE_SHALLOW_LOOPBACK]:
            return self._read_and_print_before_stats_reg_frame()

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

    def _read_and_print_after_stats_reg_frame(self):
        self.dut_rx_mac_after, self.dut_tx_mac_after = self.dut_mac.get_counters_reg_frames()
        self.lkp_rx_mac_after, self.lkp_tx_mac_after = self.lkp_mac.get_counters_reg_frames()

        log.info('AFTER: ')
        log.info('  MAC: ')
        log.info('    DUT rx: {} tx: {}'.format(self.dut_rx_mac_after, self.dut_tx_mac_after))
        log.info('    LKP rx: {} tx: {}'.format(self.lkp_rx_mac_after, self.lkp_tx_mac_after))

    def _read_and_print_after_stats(self):
        if self.loopback in [SYSTEM_SIDE_SHALLOW_LOOPBACK, LINE_SIDE_SHALLOW_LOOPBACK]:
            return self._read_and_print_after_stats_reg_frame()

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

    def run_test_loopback(self, speed, loopback):
        self.precondition(speed, loopback)

        self._read_and_print_before_stats()

        # send pause frames
        if loopback not in [SYSTEM_SIDE_SHALLOW_LOOPBACK, LINE_SIDE_SHALLOW_LOOPBACK]:
            pkts = Packets.get_pause_frames_packets(quanta=0xff)
        else:
            packets_args = {
                'ipv': 4,
                'ipv4_src': self.LKP_IPV4_ADDR,
                'ipv4_dst': self.DUT_IPV4_ADDR,
                'protocol': 'tcp',
                'pktsize': 64,
                'vlan_id': 0x22
            }

            pkts = Packets(**packets_args).to_str()
        # send_pf = Aqsendp(count=self.PACKETS_COUNT, rate=1, iface=self.dut_iface, host=self.dut_hostname, packet=pkts)
        # send_pf.run()
        # time.sleep(1)


        if loopback not in [SYSTEM_SIDE_SHALLOW_LOOPBACK, LINE_SIDE_SHALLOW_LOOPBACK]:
            send_pf = Aqsendp(count=self.PACKETS_COUNT, rate=1, iface=self.dut_iface, host=self.dut_hostname, packet=pkts)
            send_pf.run()
            time.sleep(1)
            self._read_and_print_after_stats()

            if loopback == NO_LOOPBACK:
                assert (self.lkp_rx_mac_after - self.lkp_rx_mac_before) == self.PACKETS_COUNT
            else:
                assert (self.dut_rx_mac_after - self.dut_rx_mac_before) == self.PACKETS_COUNT
        else:
            if loopback == SYSTEM_SIDE_SHALLOW_LOOPBACK:
                send_pf = Aqsendp(count=self.PACKETS_COUNT, rate=1, iface=self.dut_iface, host=self.dut_hostname, packet=pkts)
                send_pf.run()
                time.sleep(1)
                self._read_and_print_after_stats()
                assert (self.dut_rx_mac_after - self.dut_rx_mac_before) == self.PACKETS_COUNT
            elif loopback == LINE_SIDE_SHALLOW_LOOPBACK:
                send_pf = Aqsendp(count=self.PACKETS_COUNT, rate=1, iface=self.lkp_iface, host=self.lkp_hostname, packet=pkts)
                send_pf.run()
                time.sleep(1)
                self._read_and_print_after_stats()
                assert (self.lkp_rx_mac_after - self.lkp_rx_mac_before) == self.PACKETS_COUNT


    @idparametrize('speed', [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    @idparametrize('loopback', [NO_LOOPBACK, SYSTEM_INTERFACE_SYSTEM_LOOPBACK, SYSTEM_INTERFACE_NETWORK_LOOPBACK,
                            NETWORK_INTERFACE_SYSTEM_LOOPBACK, NETWORK_INTERFACE_NETWORK_LOOPBACK, SYSTEM_SIDE_SHALLOW_LOOPBACK,
                            LINE_SIDE_SHALLOW_LOOPBACK])
    def test_loopback(self, speed, loopback):
        """
        @description: This test checks that PHY loopback works correct

        @steps:
        1. Configure link.
        2. Configure loopback.
        3. Send pause frame packets.
        4. Check that amount of send packets and pause frames counter is equal.

        @result: All checks are passed.

        @requirements: PHY_MACSEC_LOOPBACK_5

        @duration: 30 seconds.
        """
        self.loopback = loopback

        if speed not in self.supported_speeds:
            pytest.skip()

        self.run_test_loopback(speed=speed, loopback=loopback)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
