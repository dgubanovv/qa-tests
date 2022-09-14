import os
import sys
import time

import pytest


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hlh.mac import MAC
from hlh.phy import PHY
from infra.test_base import idparametrize
from infra.test_base_phy import TestBasePhy
from tools.aqpkt import Aqsendp
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_1G, LINK_SPEED_100M, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_10G, MII_MODE_XFI, MII_MODE_XFI_DIV2, MII_MODE_OCSGMII, MII_MODE_SGMII, MII_MODE_USX, \
    RATE_ADAPTATION_PAUSE, RATE_ADAPTATION_UNKNOW
from tools.constants import DIRECTION_TX, DIRECTION_RX, ENABLE, DISABLE, EGRESS, INGRESS
from tools.driver import Driver
from tools.log import get_atf_logger
from trafficgen.traffic_gen import Packets

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "macsec_bypass"


class TestPhyBypass(TestBasePhy):
    """
    @description: The TestPhyBypass test is check bypass of different parts of PHY for all speeds.

    @setup: Felicity <-> Dac cable <-> separate PHY
    """
    PAUSE_FRAME_COUNT = 10

    @classmethod
    def setup_class(cls):
        super(TestPhyBypass, cls).setup_class()

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

            log.info('Interface    DUT: {:12s}     LKP: {:12s}'.format(cls.dut_iface, cls.lkp_iface))

            cls.dut_phy = PHY(phy_control=cls.phy_controls[0])
            cls.dut_mac = MAC(port=cls.dut_port, host=cls.dut_hostname)

            cls.lkp_phy = PHY(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_mac = MAC(port=cls.lkp_port, host=cls.lkp_hostname)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def precondition(self, speed, bypass, direction):
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

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_ifconfig.set_link_speed(speed, mac_sif_mode=phy_mode)

        assert self.dut_ifconfig.wait_link_up() == speed
        assert self.lkp_ifconfig.wait_link_up() == speed

        d = EGRESS if direction == DIRECTION_TX else INGRESS
        self.dut_phy.set_bypass_all_sec_block(direction=d, value=bypass)

        self.dut_mac.set_flow_control(state=DISABLE)
        self.lkp_mac.set_flow_control(state=DISABLE)

        self.dut_phy.set_flow_control(state=DISABLE)
        self.lkp_phy.set_flow_control(state=DISABLE)

        self.dut_phy.set_fc_processing(state=ENABLE)

        time.sleep(1)

        log.info('Bypass status: {}'.format(self.dut_phy.get_bypass_all_sec_block(direction=d)))


        assert self.ping(from_host='localhost', to_host=self.LKP_IPV4_ADDR, number=4)

    def send_pause_frame(self, direction):
        host = self.lkp_hostname if direction == DIRECTION_RX else self.dut_hostname
        iface = self.lkp_iface if direction == DIRECTION_RX else self.dut_iface

        pkts = Packets.get_pause_frames_packets(quanta=0xff)

        s = Aqsendp(packet=pkts, count=self.PAUSE_FRAME_COUNT, host=host, iface=iface)
        s.run()
        time.sleep(1)

    @idparametrize("s", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    @idparametrize("bypass", [ENABLE, DISABLE])
    @idparametrize("d", [DIRECTION_TX, DIRECTION_RX])
    def test_macsec_bypass(self, s, bypass, d):
        """
        @description: This test checks that macsec bypass works correct

        @steps:
        1. Configure link.
        2. Configure macsec sec bypass.
        3. Send pause frame packets.
        4. Make sure that pause frames are not processed by PHY if SEC bypass is enabled.
           If SEC bypass is disabled pause frames shall be processed.

        @result: All checks are passed.

        @requirements: PHY_MACSEC_BYPASS_3, PHY_MACSEC_BYPASS_4

        @duration: 30 seconds.
        """

        if s not in self.supported_speeds:
            pytest.skip()

        self.precondition(speed=s, bypass=bypass, direction=d)

        dut_rx_b, dut_tx_b = self.dut_mac.get_counters_pause_frames()
        lkp_rx_b, lkp_tx_b = self.lkp_mac.get_counters_pause_frames()

        self.send_pause_frame(direction=d)

        dut_rx, dut_tx = self.dut_mac.get_counters_pause_frames()
        lkp_rx, lkp_tx = self.lkp_mac.get_counters_pause_frames()

        dut_rx -= dut_rx_b
        dut_tx -= dut_tx_b
        lkp_rx -= lkp_rx_b
        lkp_tx -= lkp_tx_b

        log.info('Pause Frame Counters DUT: rx: {}    tx: {}'.format(dut_rx, dut_tx))
        log.info('Pause Frame Counters LKP: rx: {}    tx: {}'.format(lkp_rx, lkp_tx))
        direction = EGRESS if d == DIRECTION_TX else INGRESS
        log.info('Bypass status: {}'.format(self.dut_phy.get_bypass_all_sec_block(direction=direction)))

        rx = lkp_rx if d == DIRECTION_TX else dut_rx
        value = self.PAUSE_FRAME_COUNT if bypass == ENABLE else 0

        assert rx == value


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
