import os
import sys
import time
import shutil
from socket import *

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from infra.test_base import TestBase, idparametrize
from tools.aqpkt import Aqsendp, scapy_pkt_to_aqsendp_str
from tools.atltoolper import AtlTool
from tools.constants import CARD_NIKKI, LINK_STATE_UP, LINK_STATE_DOWN
from tools.driver import Driver
from tools.command import Command
from tools.utils import get_atf_logger
from tools.macsectool import MacsecTool
from scapy.all import Ether, IP, TCP, Dot1Q, Raw

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_datapath"


class TestDriverDatapath(TestBase):
    """
    @description: The datapath test.

    @setup: Two Aquantia devices connected back to back.
    """

    HEAD_RX_0_REG = 0x5b0c
    TAIL_RX_0_REG = 0x5b10
    RING_SIZE_RX_0_REG = 0x5b08
    HEADS = []
    for i in range(32):
        HEADS.append(HEAD_RX_0_REG + 0x20 * i)

    MACSEC_IFACE = "macsec0"
    DUT_IP_ADDRESS = "10.10.12.1"
    LKP_IP_ADDRESS = "10.10.12.2"

    @classmethod
    def setup_class(cls):
        super(TestDriverDatapath, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()
            cls.dut_ifconfig.set_link_state(LINK_STATE_UP)
            cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            cls.dut_ifconfig.wait_link_up()

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)

            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
            cls.dut_iface = cls.dut_ifconfig.get_conn_name()
            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()

            cls.NETMASK_DEC_FORMAT = 16
            cls.dut_macsec = MacsecTool(port=cls.dut_port)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def teardown_method(self, method):
        super(TestDriverDatapath, self).teardown_method(method)
        self.dut_ifconfig.set_link_up()
        self.dut_ifconfig.wait_link_up()

    def reset_driver(self):
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()

    def send_macsec_traffic(self, pkt_count, iface, host, pkt=None):
        if pkt is None:
            size = 100
            l2 = Ether(dst=self.dut_mac, src=self.lkp_mac)
            raw = Raw("\xff" * (size - len(l2)))
            pkt = l2 / raw

        aqsendp_pkt = scapy_pkt_to_aqsendp_str(pkt)
        lkp_aqsendp = Aqsendp(
            packet=aqsendp_pkt, count=pkt_count,
            host=host, iface=iface
        )

        lkp_aqsendp.run()

    def dump_macsec_cfg(self, cfg_name='dut_macsec.cfg'):
        self.dut_macsec.dump_conf(cfg_name)
        shutil.move(cfg_name, self.test_log_dir)

    def dump_macsec_yaml(self):
        shutil.copy('macsec.yaml', self.test_log_dir)

    def setup_linux_macsec(self, macsec_iface, key, tx_pn=1, rx_pn=1):
        Command(cmd='sudo ip link delete {}'.format(macsec_iface), host=self.lkp_hostname).run()
        Command(cmd='sudo ip a', host=self.lkp_hostname).run()
        res = Command(cmd='sudo ip link add link {} {} type macsec encrypt on protect on replay on window 0'.format(
                self.lkp_iface, macsec_iface), host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot add MacSec interface on LKP")
        res = Command(cmd='sudo ip macsec add {} tx sa 0 pn {} on key 01 {}'.format(macsec_iface, tx_pn, key),
                      host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot add TX SA to MacSec interface on LKP")
        res = Command(cmd='sudo ip macsec add {} rx address {} port 1'.
                      format(macsec_iface, self.dut_ifconfig.get_mac_address()), host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot add MacSec RX SC on LKP")
        res = Command(cmd='sudo ip macsec add {} rx address {} port 1 sa 0 pn {} on key 00 {}'.
                      format(macsec_iface, self.dut_ifconfig.get_mac_address(), rx_pn, key), host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot add RX SA to MacSec interface on LKP")
        res = Command(cmd='sudo ip link set dev {} up'.format(macsec_iface), host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot put up MacSec link on LKP")
        res = Command(cmd='sudo ifconfig {} {}/{}'.format(macsec_iface, self.LKP_IP_ADDRESS, self.NETMASK_DEC_FORMAT),
                      host=self.lkp_hostname).run()
        Command(cmd='ifconfig macsec0', host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot set IP address to MacSec interface on LKP")

    def test_pointer_head_and_tail(self):
        """
        @description: Ensure that initially driver head pointer 0, driver tail pointer equal ring size.

        @steps:
        1. Restart driver on DUT.
        2. If Os is linux wait link up.
        3. Read pointers head rx
        4. Read pointers tail rx
        5. Read ring size
        6. Check, that driver head pointer is 0.
        7. Check, that driver tail pointer equal ring size.

        @requirements DRV_DATAPATH_1
        @result: Driver head pointer is 0 and driver tail pointer equal ring size.
        @duration: 1 minutes.
        """
        self.reset_driver()
        for i in range(4):
            head_rx = self.dut_atltool_wrapper.readreg(self.HEAD_RX_0_REG + (i * 0x20)) & 0x00001fff
            tail_rx = self.dut_atltool_wrapper.readreg(self.TAIL_RX_0_REG + (i * 0x20)) & 0x00001fff
            ring_size = (self.dut_atltool_wrapper.readreg(self.RING_SIZE_RX_0_REG + (i * 0x20)) & 0x1fff) >> 3
            if ring_size != 0:
                assert head_rx == 0, "RING: {} head pointer not equal 0".format(i)
                assert tail_rx == (ring_size * 8) - 1, "RING: {} tail pointer not equal ring size".format(i)

    @idparametrize("prot", ["TCP", "IP"])
    def test_datapath_csum_error(self, prot):
        """
        @description: Ensure that head pointer and tail pointer change correctly when a packet with IP/TCP csum error
                      is received.
        @steps:
        1. Generate packet with csum error.
        2. Read driver head pointer for all rings.
        3. Send packets
        4. Read driver head pointer for all rings.
        5. Determine which ring the packets were received.
        6. Read pointers head rx for this ring
        7. Read pointers tail rx for this ring
        8. Check, that tail pointer equal current head pointer - 1

        @requirements DRV_DATAPATH_2, DRV_DATAPATH_3
        @result: Driver tail pointer equal current head pointer - 1.
        @duration: 10 seconds.
        """
        if self.dut_ops.is_linux():
            number_of_pac = 32
        else:
            number_of_pac = 1
        p = "f" * 64
        pac = Ether(dst="ff:ff:ff:ff:ff:ff", src="ff:ff:ff:ff:ff:ff") / IP() / TCP() / Raw(load=p.decode("hex"))

        pac[TCP if prot == "TCP" else IP].chksum = 0xffff
        aq_pkt = scapy_pkt_to_aqsendp_str(pac)
        aq_send_pkt = Aqsendp(host=self.lkp_hostname, count=number_of_pac, packet=aq_pkt)
        heads_before = {}
        heads_after = {}
        for i, val in enumerate(self.HEADS):
            heads_before[i] = self.dut_atltool_wrapper.readreg(val)
        aq_send_pkt.run()
        time.sleep(3)
        for i, val in enumerate(self.HEADS):
            heads_after[i] = self.dut_atltool_wrapper.readreg(val)
        for i in heads_before:
            if heads_before[i] != heads_after[i]:
                ring = i
                break
        assert ring != None
        log.info("Packet received by ring number {}".format(ring))

        head_rx = self.dut_atltool_wrapper.readreg(self.HEAD_RX_0_REG + (ring * 0x20)) & 0x00001fff
        tail_rx = self.dut_atltool_wrapper.readreg(self.TAIL_RX_0_REG + (ring * 0x20)) & 0x00001fff
        assert 0 < head_rx - tail_rx <= number_of_pac, "After traffic not correct value pointer head or tail"

    def test_datapath_fcs_error(self):
        """
        @description: Ensure that head pointer and tail pointer change correctly when a packet with FCS error
                      is received.
        @steps:
        1. Configure macsec on lkp.
        2. Configure macsec on dut.
        3. Read driver head pointer for all rings.
        4. Send traffic via macsec
        5. Read driver head pointer for all rings.
        6. Determine which ring the packets were received.
        7. Make sure received packet with FCS error.
        8. Read pointers head rx for this ring.
        9. Read pointers tail rx for this ring.
        10. Check, that tail pointer equal current head pointer - 1.

        @requirements DRV_DATAPATH_4
        @result: Driver tail pointer equal current head pointer - 1.
        @duration: 10 seconds.
        """
        if not self.dut_ops.is_windows() or not self.lkp_ops.is_linux():
            pytest.skip()
        if self.dut_fw_card not in CARD_NIKKI or self.lkp_fw_card not in CARD_NIKKI:
            pytest.skip()
        keys = [
            "73bd5434ca328f97b456568a67674000",
            "73bd5434ca328f97b456568a67674111",
        ]
        pkts_sent_1 = 10
        pkt_size = 100
        self.setup_linux_macsec(self.MACSEC_IFACE, keys[0])
        self.lkp_ifconfig.wait_link_up()
        add_new_rx_sa = 'sudo ip macsec add {} rx address {} port 1 sa 1 pn 1 on key 02 {}'.format(
            self.MACSEC_IFACE, self.dut_mac, keys[1])
        Command(cmd=add_new_rx_sa, host=self.lkp_hostname).run()

        macsec_yaml = MacsecTool.gen_config(self.dut_mac, self.lkp_mac, keys[0], keys[0], rx_pn=100)
        self.dut_macsec.configure(macsec_yaml)
        self.dump_macsec_cfg()
        self.dump_macsec_yaml()

        l2 = Ether(dst=self.dut_mac, src=self.lkp_mac)
        raw = Raw("\xff" * (pkt_size - len(l2)))
        pkt = l2 / raw

        heads_before = {}
        heads_after = {}
        for i, val in enumerate(self.HEADS):
            heads_before[i] = self.dut_atltool_wrapper.readreg(val)
        fcs_err_prev = self.dut_atltool_wrapper.get_msm_counters()['fcserr']
        self.send_macsec_traffic(pkts_sent_1, iface=self.MACSEC_IFACE, host=self.lkp_hostname, pkt=pkt)
        fcs_err_curr = self.dut_atltool_wrapper.get_msm_counters()['fcserr']
        assert fcs_err_curr > fcs_err_prev
        for i, val in enumerate(self.HEADS):
            heads_after[i] = self.dut_atltool_wrapper.readreg(val)
        for i in heads_before:
            if heads_before[i] != heads_after[i]:
                ring = i
                break
        assert ring != None
        log.info("Packet received by ring number {}".format(ring))

        head_rx = self.dut_atltool_wrapper.readreg(self.HEAD_RX_0_REG + (ring * 0x20)) & 0x00001fff
        tail_rx = self.dut_atltool_wrapper.readreg(self.TAIL_RX_0_REG + (ring * 0x20)) & 0x00001fff
        assert head_rx - 1 == tail_rx, "After traffic not correct value pointer head or tail"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])

