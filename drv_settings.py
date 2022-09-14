"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import csv
import ipaddress
import json
import numpy
import os
import time
import timeit
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import pytest
from scapy.all import Ether, Dot1Q, IP, UDP, TCP

from collections import OrderedDict
from hlh.register import Register
from tools.atltoolper import AtlTool
from tools.aqpkt import Aqsendp, scapy_pkt_to_aqsendp_str
from tools.command import Command
from tools.constants import LINK_SPEED_NO_LINK, LINK_STATE_UP, LINK_STATE_DOWN, FELICITY_CARDS, \
    DIRECTION_TX, DIRECTION_RX, DIRECTION_RXTX, SPEED_TO_MBITS, CARD_FIJI, CARD_ANTIGUA, CARD_NIKKI, \
    LINK_SPEED_AUTO, INTERRUPT_TYPE_LEGACY, INTERRUPT_TYPE_MSI, OFFLOADS_STATE_DSBL, OFFLOADS_STATE_TX, \
    OFFLOADS_STATE_RX, OFFLOADS_STATE_TX_RX, MTU_16000, MTU_DISABLED, LIN_PAUSE_SYMMETRIC, LIN_PAUSE_SYMMETRIC_RECEIVE, \
    LIN_PAUSE_NO, LIN_PAUSE_TRANSMIT

from tools.driver import Driver, DRV_TYPE_KO
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config
from tools.killer import Killer
from tools.ops import OpSystem
from tools.ping import ping
from tools.power import Power
from tools import pcontrol
from tools.scapy_tools import arping, ScapyTools
from tools.tcpdump import Tcpdump
from tools.utils import get_atf_logger
from perf.nuttcp import Nuttcp
from infra.test_base import TestBase, idparametrize

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_settings"


class TestDrvSettings(TestBase):
    """
    @description: The TestDrvSettings test is dedicated to verify Driver settings.

    @setup: Two Aquantia devices connected back to back.
    """
    PRVT_NW_DELAY = 20
    IPV4_GATEWAY = "192.168.0.1"
    NETMASK_IPV4 = "255.255.255.0"

    PREFIX_IPV6 = "64"
    PRVT_NW_CMD = "powershell -command \"& {&'Set-NetConnectionProfile' -NetworkCategory Private}\""

    IPERF_EXEC_TIME = 7
    STATE_DSBL = "Disable"
    STATE_ENBL = "Enable"
    STATE_ADAPTIVE = "adaptive"
    STATE_EXTREME = "extreme"
    STATE_HIGH = "high"
    STATE_LOW = "low"
    STATE_MEDIUM = "medium"
    STATE_OFF = "off"

    @classmethod
    def setup_class(cls):
        super(TestDrvSettings, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            if cls.dut_fw_card not in CARD_FIJI:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            if cls.lkp_fw_card not in CARD_FIJI:
                cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            insmod_args = None
            flashless_fw = None
            if "forwarding" in cls.dut_drv_version:
                insmod_args = "rx_linear=1"
            if cls.dut_fw_card not in CARD_FIJI and cls.dut_atltool_wrapper.is_secure_chips():
                flashless_fw = cls.dut_fw_version
            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname,
                                    insmod_args=insmod_args, flashless_fw=flashless_fw)
            if cls.platform is not None and 'Tehuti' in cls.platform:
                cls.lkp_driver = Driver(port=cls.lkp_port, version="latest", host=cls.lkp_hostname,
                                        drv_type=DRV_TYPE_KO)
            else:
                cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)

            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.DUT_IPV6_ADDR = cls.suggest_test_ip_address(cls.dut_port, cls.dut_hostname, ipv6=True)
            cls.LKP_IPV6_ADDR = cls.suggest_test_ip_address(cls.lkp_port, ipv6=True)
            cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port, cls.dut_hostname)
            cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port)

            # IPV4_GATEWAY setting on DUT is the workaround
            # For some reason Windows do not propagate ARP/NS affloads to the driver if gateway is not set
            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, cls.LKP_IPV4_ADDR)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.dut_ifconfig.set_ipv6_address(cls.DUT_IPV6_ADDR, cls.PREFIX_IPV6, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IPV6_ADDR, cls.PREFIX_IPV6, None)
            time.sleep(cls.LINK_CONFIG_DELAY)

            # Remove link local IPs
            ipv4 = cls.dut_ifconfig.get_ip_address()
            ipv6 = cls.dut_ifconfig.get_ip_address(ipv=6)

            for ip in ipv4:
                if ip != cls.DUT_IPV4_ADDR:
                    cls.dut_ifconfig.del_ip_address(ip)

            for ip in ipv6:
                if ip != str(ipaddress.ip_address(unicode(cls.DUT_IPV6_ADDR))):
                    cls.dut_ifconfig.del_ip_address(ip)

            cls.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            cls.dut_ifconfig.set_link_state(LINK_STATE_UP)
            cls.dut_ifconfig.wait_link_up()

            cls.dut_power = Power(host=cls.dut_hostname)
            cls.dut_ops = OpSystem(host=cls.dut_hostname)
            cls.lkp_ops = OpSystem()
            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
            cls.dut_iface = cls.dut_ifconfig.get_conn_name()
            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()
            cls.dut_nof_pci_lines = cls.dut_ifconfig.get_nof_pci_lines()
            cls.lkp_nof_pci_lines = cls.lkp_ifconfig.get_nof_pci_lines()

            cls.iperf_config = {
                'num_threads': 1,
                'num_process': 4,
                'ipv': 4,
                'buffer_len': 0,
                'is_udp': False,
                'is_eee': False,
                "time": 30,
                "speed": cls.supported_speeds[-1],
                'lkp': cls.dut_hostname,
                'lkp4': cls.DUT_IPV4_ADDR,
                'lkp6': cls.DUT_IPV6_ADDR,
                'dut4': cls.LKP_IPV4_ADDR,
                'dut6': cls.LKP_IPV6_ADDR
            }

            TestDrvSettings.result = None

            if cls.dut_fw_card == CARD_ANTIGUA:
                cls.fw_config = FirmwareA2Config(cls.dut_atltool_wrapper)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestDrvSettings, self).setup_method(method)

        if not self.is_host_alive_and_ready(self.dut_hostname):
            raise Exception("DUT is not online, can't perform test")

    def teardown_method(self, method):
        super(TestDrvSettings, self).teardown_method(method)

        self.bring_host_online(self.dut_hostname)

        # Hibernate off is not available for Linux
        if self.dut_ops.is_windows():
            self.dut_power.hibernate_off()

        # if self.dut_ops.is_windows():
        #     # Enable IPv6 binding back because ARP offload tests may disable it
        #     self.dut_ifconfig.bind_ipv6()

        if self.dut_ops.is_windows():
            self.dut_ifconfig.set_advanced_property("*PMARPOffload", "Enable")
            self.dut_ifconfig.set_advanced_property("*PMNSOffload", "Enable")
            self.dut_ifconfig.set_buffer_size(rx_size=512, tx_size=2048)
            self.dut_ifconfig.set_mtu(MTU_DISABLED)
            if self.dut_fw_card != CARD_FIJI:
                self.dut_ifconfig.set_interrupt_type(INTERRUPT_TYPE_LEGACY)
                self.dut_ifconfig.set_advanced_property("*InterruptModeration", self.STATE_ENBL)
                self.dut_ifconfig.set_advanced_property("ITR", self.STATE_ADAPTIVE)
                self.dut_ifconfig.set_advanced_property("VlanID", 0)
                self.dut_ifconfig.set_advanced_property("MonitorModeEnabled", "Disable")
                self.dut_ifconfig.set_flow_control(OFFLOADS_STATE_TX_RX)

        if self.dut_ops.is_linux():
            if "forwarding" in self.dut_drv_version:
                res = Command(cmd="sudo ethtool --set-priv-flags {} StripEtherPadding off".format(self.dut_iface),
                              host=self.dut_hostname).wait()
                if res["returncode"] != 0:
                    raise Exception("Ethtool failed")

            res = Command(cmd="sudo ethtool --set-priv-flags {} MediaDetect off".format(self.dut_iface),
                          host=self.dut_hostname).wait()
            if res["returncode"] != 0:
                raise Exception("Ethtool failed")
            self.dut_ifconfig.delete_macvlan_ifaces()
            self.dut_ifconfig.set_buffer_size(rx_size=2048, tx_size=4096)
            self.dut_ifconfig.set_flow_control(OFFLOADS_STATE_TX_RX)
            self.dut_ifconfig.delete_vlan_ifaces()

    def randomize_ipv6(self, init_adress):
        last_byte = init_adress.split(":")[7]
        last_byte = int(last_byte, 16) + 1
        last_byte_str = "0{:02x}".format(last_byte)

        return "{}:{}".format(init_adress[:-5], last_byte_str if len(last_byte_str) == 4 else last_byte_str[1:])

    def hibernate_dut(self, retry_interval=15):
        log.info("Hibernating DUT")
        self.dut_power.hibernate()
        if not self.poll_host_powered_off(self.dut_hostname, retry_interval=retry_interval):
            raise Exception("Couldn't hibernate DUT")
        log.info("DUT is hibernated")

    def set_offload_settings(self, arp_offload, ns_offload):
        self.dut_ifconfig.set_power_mgmt_settings(False, True, True)
        # Set wol settings to make sure FW keeps link up after hibernate
        self.dut_ifconfig.set_advanced_property("WakeOnPing", "Enable")
        self.dut_ifconfig.set_advanced_property("*WakeOnMagicPacket", "Enable")
        self.dut_ifconfig.set_advanced_property("*PMARPOffload", arp_offload)
        self.dut_ifconfig.set_advanced_property("*PMNSOffload", ns_offload)

        if self.lkp_fw_card in FELICITY_CARDS or self.dut_fw_card in FELICITY_CARDS:
            speed = self.supported_speeds[-1]
            self.dut_ifconfig.set_link_speed(speed)
            self.lkp_ifconfig.set_link_speed(speed)

        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        time.sleep(self.LINK_CONFIG_DELAY)

        if "win7" not in self.dut_ops.get_name().lower():
            res = Command(cmd=self.PRVT_NW_CMD, host=self.dut_hostname).run()
            assert res["returncode"] == 0, "Couldn't set network to private on DUT"

    def all_loopback_off(self):
        res = Command(cmd="sudo ethtool --set-priv-flags {} PKTSystemLoopback off".format(self.dut_iface),
                      host=self.dut_hostname).wait()
        if res["returncode"] != 0:
            raise Exception("Ethtool failed")

        res = Command(cmd="sudo ethtool --set-priv-flags {} DMASystemLoopback off".format(self.dut_iface),
                      host=self.dut_hostname).wait()
        if res["returncode"] != 0:
            raise Exception("Ethtool failed")

        res = Command(cmd="sudo ethtool --set-priv-flags {} DMANetworkLoopback off".format(self.dut_iface),
                      host=self.dut_hostname).wait()
        if res["returncode"] != 0:
            raise Exception("Ethtool failed")

        res = Command(cmd="sudo ethtool --set-priv-flags {} PHYInternalLoopback off".format(self.dut_iface),
                      host=self.dut_hostname).wait()
        if res["returncode"] != 0:
            raise Exception("Ethtool failed")

        res = Command(cmd="sudo ethtool --set-priv-flags {} PHYExternalLoopback off".format(self.dut_iface),
                      host=self.dut_hostname).wait()
        if res["returncode"] != 0:
            raise Exception("Ethtool failed")

        res = Command(cmd="sudo ethtool --set-priv-flags {} MediaDetect off".format(self.dut_iface),
                      host=self.dut_hostname).wait()
        if res["returncode"] != 0:
            raise Exception("Ethtool failed")

    def send_pkt_loopback_system(self):
        dut_scapy_tool = ScapyTools(port=self.dut_port, host=self.dut_hostname)
        dut_scapy_iface = dut_scapy_tool.get_scapy_iface()
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="ff:ff:ff:ff:ff:ff") / IP(dst=self.DUT_IPV4_ADDR) / TCP(
            dport=1111) / ("1234567890" * 5)
        sniffer = Tcpdump(port=self.dut_port, timeout=5, host=self.dut_hostname)
        sniffer.run_async()
        dut_scapy_tool.send_packet(pkt=pkt, iface=dut_scapy_iface)
        sniffed = sniffer.join(10)
        pkts = []
        for pkt in sniffed:
            if TCP in pkt and pkt[TCP].dport == 1111:
                pkts.append(pkt)
        assert len(pkts) == 2, "Loopback is not work"
        assert pkts[0] == pkts[1], "Loopback is not work"

    def send_pkt_loopback_network(self):
        lkp_scapy_tool = ScapyTools(port=self.lkp_port, host=self.lkp_hostname)
        lkp_scapy_iface = lkp_scapy_tool.get_scapy_iface()
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="ff:ff:ff:ff:ff:ff") / IP(dst=self.DUT_IPV4_ADDR) / TCP(
            dport=1111) / ("1234567890" * 5)
        sniffer = Tcpdump(port=self.lkp_port, timeout=5, host=self.lkp_hostname)
        sniffer.run_async()
        time.sleep(2)
        lkp_scapy_tool.send_packet(pkt=pkt, iface=lkp_scapy_iface)
        time.sleep(2)
        sniffed = sniffer.join(10)
        pkts = []
        for pkt in sniffed:
            if TCP in pkt and pkt[TCP].dport == 1111:
                pkts.append(pkt)
        assert len(pkts) == 2, "Loopback is not work"
        assert pkts[0] == pkts[1], "Loopback is not work"

    def get_advertised_flow_control_linux(self):
        cmd = "sudo ethtool  {} | grep 'Advertised pause frame use:'".format(self.lkp_iface)
        res = Command(cmd=cmd, host=self.lkp_hostname).run_join(5)
        assert res["returncode"] == 0

        cur_pause = res["output"][0].split(':')[1].strip()
        return (LIN_PAUSE_NO if cur_pause == "No" else \
                LIN_PAUSE_SYMMETRIC if cur_pause == "Symmetric" else \
                LIN_PAUSE_SYMMETRIC_RECEIVE if cur_pause == "Symmetric Receive-only" else \
                LIN_PAUSE_TRANSMIT if cur_pause == "Transmit-only" else None)

    def test_pkt_system_loopback(self):
        """
        @description: Check packet loopback system.

        @steps:
        1. Check that in registers loopback is off.
        2. Turn on loopback.
        3. Check that in registers loopback is on.
        4. Send packets from DUT
        5. Check that package send and receive on DUT

        @result: Package send and receive on DUT.
        @duration: 30 seconds.
        @requirements: DRV_LOOPBACK_1
        """
        if not self.dut_ops.is_linux():
            pytest.skip()
        self.dut_ifconfig.wait_link_up()
        self.all_loopback_off()
        reg_5000 = Register(self.dut_atltool_wrapper.readreg(0x5000))
        reg_7000 = Register(self.dut_atltool_wrapper.readreg(0x7000))
        assert reg_5000[8] == 0 and reg_5000[7] == 0, "Rx PKTSystemLoopback is on"
        assert reg_7000[8] == 0 and reg_7000[7] == 0, "Tx PKTSystemLoopback is on"
        try:
            res = Command(cmd="sudo ethtool --set-priv-flags {} PKTSystemLoopback on".format(self.dut_iface),
                          host=self.dut_hostname).wait()
            if res["returncode"] != 0:
                raise Exception("Ethtool failed")
            reg_5000 = Register(self.dut_atltool_wrapper.readreg(0x5000))
            reg_7000 = Register(self.dut_atltool_wrapper.readreg(0x7000))
            assert reg_5000[8] == 1 or reg_5000[7] == 1, "Tx PKTSystemLoopback is off"
            assert reg_7000[8] == 1 or reg_7000[7] == 1, "Rx PKTSystemLoopback is off"
            self.send_pkt_loopback_system()
        finally:
            self.all_loopback_off()

    def test_dma_system_loopback(self):
        """
        @description: Check dma loopback system.

        @steps:
        1. Check that in registers loopback is off.
        2. Turn on loopback.
        3. Check that in registers loopback is on.
        4. Send packets from DUT
        5. Check that package send and receive on DUT

        @result: Package send and receive on DUT.
        @duration: 30 seconds.
        @requirements: DRV_LOOPBACK_2
        """
        if not self.dut_ops.is_linux():
            pytest.skip()
        self.dut_ifconfig.wait_link_up()
        self.all_loopback_off()
        assert self.dut_atltool_wrapper.readreg(0x5000) & 0x40 == 0, "Rx DMASystemLoopback is on"
        assert self.dut_atltool_wrapper.readreg(0x7000) & 0x40 == 0, "Tx DMASystemLoopback is on"
        try:
            res = Command(cmd="sudo ethtool --set-priv-flags {} DMASystemLoopback on".format(self.dut_iface),
                          host=self.dut_hostname).wait()
            if res["returncode"] != 0:
                raise Exception("Ethtool failed")
            assert self.dut_atltool_wrapper.readreg(0x7000) & 0x40 == 0x40, "Tx DMASystemLoopback is off"
            assert self.dut_atltool_wrapper.readreg(0x5000) & 0x40 == 0x40, "Rx DMASystemLoopback is off"
            self.send_pkt_loopback_system()
        finally:
            self.all_loopback_off()

    def test_dma_network_loopback(self):
        """
        @description: Check dma loopback network.

        @steps:
        1. Check that in registers loopback is off.
        2. Turn on loopback.
        3. Check that in registers loopback is on.
        4. Send packets from LKP to DUT
        5. Check that package send and receive on LKP

        @result: Package send and receive on LKP.
        @duration: 30 seconds.
        @requirements: DRV_LOOPBACK_3
        """
        if not self.dut_ops.is_linux():
            pytest.skip()
        self.dut_ifconfig.wait_link_up()
        self.all_loopback_off()
        assert self.dut_atltool_wrapper.readreg(0x5000) & 0x10 == 0, "Rx DMANetworkLoopback is on"
        assert self.dut_atltool_wrapper.readreg(0x7000) & 0x10 == 0, "Tx DMANetworkLoopback is on"
        try:
            res = Command(cmd="sudo ethtool --set-priv-flags {} DMANetworkLoopback on".format(self.dut_iface),
                          host=self.dut_hostname).wait()
            if res["returncode"] != 0:
                raise Exception("Ethtool failed")
            assert self.dut_atltool_wrapper.readreg(0x7000) & 0x10 == 0x10, "Tx DMANetworkLoopback is off"
            assert self.dut_atltool_wrapper.readreg(0x5000) & 0x10 == 0x10, "Rx DMANetworkLoopback is off"
            assert self.dut_atltool_wrapper.readreg(0x5100) & 0x8 == 0x8, "Rx DMANetworkLoopback is off"
            assert self.dut_atltool_wrapper.readreg(0x5280) & 0x4 == 0x4, "Rx DMANetworkLoopback is off"
            assert self.dut_atltool_wrapper.readreg(0x7900) & 0x10 == 0, "Rx DMANetworkLoopback is off"
            self.send_pkt_loopback_network()
        finally:
            self.all_loopback_off()

    def test_phy_internal_loopback(self):
        """
        @description: Check phy internal loopback.

        @steps:
        1. Check that in registers loopback is off.
        2. Turn on loopback.
        3. Check that in registers loopback is on.

        @result: Register show correct information.
        @duration: 15 seconds.
        """
        if not self.dut_ops.is_linux() or self.dut_fw_card in FELICITY_CARDS or self.dut_fw_card == CARD_ANTIGUA:
            pytest.skip()
        self.dut_ifconfig.wait_link_up()
        self.all_loopback_off()
        assert self.dut_atltool_wrapper.readreg(0x36c) & 0x8000000 == 0, "PHYInternalLoopback is on"
        try:
            res = Command(cmd="sudo ethtool --set-priv-flags {} PHYInternalLoopback on".format(self.dut_iface),
                          host=self.dut_hostname).wait()
            if res["returncode"] != 0:
                raise Exception("Ethtool failed")
            time.sleep(3)
            assert self.dut_atltool_wrapper.readreg(0x36c) & 0x8000000 == 0x8000000, "PHYInternalLoopback is off"
            self.send_pkt_loopback_system()
        finally:
            self.all_loopback_off()

    def test_phy_external_loopback(self):
        """
        @description: Check phy external loopback.

        @steps:
        1. Check that in registers loopback is off.
        2. Turn on loopback.
        3. Check that in registers loopback is on.

        @result: Register show correct information.
        @duration: 15 seconds.
        """
        if not self.dut_ops.is_linux() or self.dut_fw_card in FELICITY_CARDS or self.dut_fw_card == CARD_ANTIGUA:
            pytest.skip()
        self.dut_ifconfig.wait_link_up()
        self.all_loopback_off()
        assert self.dut_atltool_wrapper.readreg(0x36c) & 0x4000000 == 0, "PHYExternalLoopback is on"
        try:
            res = Command(cmd="sudo ethtool --set-priv-flags {} PHYExternalLoopback on".format(self.dut_iface),
                          host=self.dut_hostname).wait()
            if res["returncode"] != 0:
                raise Exception("Ethtool failed")
            time.sleep(3)
            assert self.dut_atltool_wrapper.readreg(0x36c) & 0x4000000 == 0x4000000, "PHYExternalLoopback is off"
        finally:
            self.all_loopback_off()

    def test_media_detect(self):
        """
        @description: Check media detect.

        @steps:
        1. Check that in registers media detect is off.
        2. Turn on media detect.
        3. Check that in registers media detect is on.
        4. Suspending DUT
        5. Turn on DUT
        6. Check that in registers media detect is on.

        @result: Register show correct information.
        @duration: 15 seconds.
        """
        if not self.dut_ops.is_linux() or self.dut_fw_card in FELICITY_CARDS or self.dut_fw_card == CARD_ANTIGUA:
            pytest.skip()
        self.dut_ifconfig.wait_link_up()
        try:
            res = Command(cmd="sudo ethtool --set-priv-flags {} MediaDetect off".format(self.dut_iface),
                          host=self.dut_hostname).wait()
            if res["returncode"] != 0:
                raise Exception("Ethtool failed")
            assert self.dut_atltool_wrapper.readphyreg(0x1E, 0xC478) & 0x180 == 0, "Media detect enabled"
            res = Command(cmd="sudo ethtool --set-priv-flags {} MediaDetect on".format(self.dut_iface),
                          host=self.dut_hostname).wait()
            if res["returncode"] != 0:
                raise Exception("Ethtool failed")
            assert self.dut_atltool_wrapper.readphyreg(0x1E, 0xC478) & 0x180 == 0x180, "Media detect disabled"

            self.dut_power.suspend()
            time.sleep(3)
            pcontrol.PControl().power(self.dut_hostname, 500, 0)
            if not self.poll_host_alive_and_ready(self.dut_hostname, self.POWER_UP_TIMEOUT):
                raise Exception("Couldn't wake DUT up using power control")

            assert self.dut_atltool_wrapper.readphyreg(0x1E, 0xC478) & 0x180 == 0x180, "Media detect disabled \
                after sleep"
        finally:
            self.all_loopback_off()

    def test_phy_switched_to_low_power(self):
        """
        @description: Check phy switched to low power.

        @steps:
        1. Link down.
        2. Wait link down.
        3. Check SIF status in PHY.

        @result: System Iface should be low power.
        @duration: 30 seconds.
        @requirements: DRV_LINK_1
        """
        if not self.dut_ops.is_linux() or self.dut_fw_card in FELICITY_CARDS or self.dut_fw_card == CARD_ANTIGUA:
            pytest.skip()
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.wait_link_down()
        sif_status = self.dut_atltool_wrapper.readphyreg(0x4, 0xE812)
        systemIface = (sif_status >> 3) & 0x1F
        assert systemIface == 9

    def test_multicast_adresses(self):
        """
        @description: Check multicast adresses and macvlan.

        @steps:
        1. Link up.
        2. Add MACVLAN device
        3. Check that Unicast filters registers have valid values for macvlan and enabled multicast addresses.
        4. Remove MULTICAST flag.
        5. Check that Unicast filters registers have valid values for macvlan and disabled multicast filters.
        6. Set ALLMULTI flag.
        7. Check that Unicast filters registers have valid values for macvlan and disabled multicast filters and l2
            mc_accept_all is 0.
        8. Set MULTICAST flag
        9. Check that Unicast filters registers have valid values for macvlan and 0x5270.E (l2_mc_accept_all) is 1 and
            0x5250.10 (l2_mc_act0) is 1 and 0x5250.1F(l2_mc_en0) is 1.
        10. Clear MULTICAST flag
        11. Check that Unicast filters registers have valid values for macvlan and disabled multicast filters and
            0x5270.E (l2_mc_accept_all) is 0.

        @result: MULTICAST and MACVLAN works correctly.
        @duration: 1 minutes.
        @requirements: DRV_MULTICAST_1, DRV_MULTICAST_2
        """
        if not self.dut_ops.is_linux():
            pytest.skip()
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        multicast_address = '01:00:5e:00:00:01'

        def convert_reg_in_mac(reg):
            mac_str = str(reg)
            if mac_str[-1] == "L":
                return "{}:{}:{}:{}:{}:{}".format(
                    mac_str[-13:-11], mac_str[-11:-9], mac_str[-9:-7], mac_str[-7:-5], mac_str[-5:-3], mac_str[-3:-1])
            else:
                return "{}:{}:{}:{}:{}:{}".format(
                    mac_str[-12:-10], mac_str[-10:-8], mac_str[-8:-6], mac_str[-6:-4], mac_str[-4:-2], mac_str[-2:])

        def check_macvlan_multicast(mac_address):
            end = self.dut_atltool_wrapper.readreg(0x00005110)
            first = self.dut_atltool_wrapper.readreg(0x00005114)
            mac = hex((first << 32) | end)
            if convert_reg_in_mac(mac) == mac_address:
                return True
            end = self.dut_atltool_wrapper.readreg(0x00005118)
            first = self.dut_atltool_wrapper.readreg(0x0000511c)
            mac = hex((first << 32) | end)
            if convert_reg_in_mac(mac) == mac_address:
                return True
            end = self.dut_atltool_wrapper.readreg(0x00005120)
            first = self.dut_atltool_wrapper.readreg(0x00005124)
            mac = hex((first << 32) | end)
            if convert_reg_in_mac(mac) == mac_address:
                return True
            return False

        c = Command(cmd="sudo ip link add mymacvlan1 link {} type macvlan mode bridge".format(self.dut_iface),
                    host=self.dut_hostname)
        c.run()
        assert c.join()["returncode"] == 0
        c = Command(cmd="sudo ifconfig mymacvlan1 up", host=self.dut_hostname)
        c.run()
        assert c.join()["returncode"] == 0
        time.sleep(15)
        macvl = self.dut_ifconfig.get_mac_address(macvlan="mymacvlan1@{}".format(self.dut_iface))
        assert check_macvlan_multicast(macvl), "Unicast filters registers not have valid values for macvlan"
        assert check_macvlan_multicast(multicast_address), \
            "Unicast filters registers not have valid values for multicast addresses"
        c = Command(cmd="sudo ifconfig {} -multicast".format(self.dut_iface), host=self.dut_hostname)
        c.run()
        assert c.join()["returncode"] == 0
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        assert check_macvlan_multicast(macvl), "Unicast filters registers not have valid values for macvlan"
        assert check_macvlan_multicast(
            multicast_address) is False, "Unicast filters registers have valid values for multicast addresses"
        c = Command(cmd="sudo ifconfig {} allmulti".format(self.dut_iface), host=self.dut_hostname)
        c.run()
        assert c.join()["returncode"] == 0
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        assert check_macvlan_multicast(macvl), "Unicast filters registers not have valid values for macvlan"
        assert check_macvlan_multicast(
            multicast_address) is False, "Unicast filters registers have valid values for multicast addresses"
        assert self.dut_atltool_wrapper.readreg(0x00005270) & 0x4000 == 0
        c = Command(cmd="sudo ifconfig {} multicast".format(self.dut_iface), host=self.dut_hostname)
        c.run()
        assert c.join()["returncode"] == 0
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        assert check_macvlan_multicast(macvl), "Unicast filters registers not have valid values for macvlan"
        assert self.dut_atltool_wrapper.readreg(0x00005250) & 0x80010000 == 0x80010000
        assert self.dut_atltool_wrapper.readreg(0x00005270) & 0x4000 == 0x4000
        c = Command(cmd="sudo ifconfig {} -multicast".format(self.dut_iface), host=self.dut_hostname)
        c.run()
        assert c.join()["returncode"] == 0
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        assert check_macvlan_multicast(macvl), "Unicast filters registers not have valid values for macvlan"
        assert check_macvlan_multicast(
            multicast_address) is False, "Unicast filters registers not have valid values for multicast addresses"
        assert self.dut_atltool_wrapper.readreg(0x00005270) & 0x4000 == 0

    def test_cooperation_of_promisc_flag_and_vlan_functionality(self):
        """
        @description: Check a cooperation of PROMISC flag and VLAN functionality

        @steps:
        1. Configure 15 vlan on the interface.
        2. Check that VLAN-PROMISC is not set (0x5280.1 = 0)
        3. Set PROMISC flag.
        4. Check that VLAN-PROMISC is set (0x5280.1 = 1)
        5. Check that L2-PROMISC is set (0x5100.3 = 1)
        6. Remove PROMISC flag.
        7. Check VLAN-PROMISC and L2-PROMISC is not set (0x5280.1 = 0, 0x5100.3 = 0)
        8. Configure 16 vlans on the interface.
        9. Check that VLAN-PROMISC is set (0x5280.1 = 1)
        10.Set PROMISC flag.
        11.Check that VLAN-PROMISC is set (0x5280.1 = 1)
        12.Remove PROMISC flag
        13.Check that VLAN-PROMISC is set (0x5280.1 = 1)
        14.Set PROMISC flag.
        15.Check that VLAN-PROMISC is set (0x5280.1 = 1)
        16.Configure 1 vlan on the interface.
        17.Check that VLAN-PROMISC is set (0x5280.1 = 1)
        18.Delete 1 vlan on the interface
        19.Check that VLAN-PROMISC is set (0x5280.1 = 1)
        20.Set PROMISC flag.
        21.Check that VLAN-PROMISC is set (0x5280.1 = 1)
        22.Configure 16 vlans on the interface.
        23.Check that VLAN-PROMISC is set (0x5280.1 = 1)
        24.Delete 1 vlan on the interface.
        25.Check that VLAN-PROMISC is set (0x5280.1 = 1)

        @result: Correct a cooperation of PROMISC flag and VLAN functionality.
        @duration: 2 minutes.
        @requirements: DRV_VLAN_2, DRV_VLAN_3, DRV_VLAN_6
        """

        if not self.dut_ops.is_linux() or self.dut_fw_card == CARD_FIJI:
            pytest.skip("Not implemented")

        for number in range(1, 16):
            self.dut_ifconfig.create_vlan_iface(number)
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 0
        res = Command(cmd="sudo ifconfig {} promisc".format(self.dut_iface), host=self.dut_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Failed enable promisc")
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 2
        assert self.dut_atltool_wrapper.readreg(0x5100) & 0x8 == 8
        res = Command(cmd="sudo ifconfig {} -promisc".format(self.dut_iface), host=self.dut_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Failed disable promisc")
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 0
        assert self.dut_atltool_wrapper.readreg(0x5100) & 0x8 == 0

        self.dut_ifconfig.create_vlan_iface(16)
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 2
        res = Command(cmd="sudo ifconfig {} promisc".format(self.dut_iface), host=self.dut_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Failed enable promisc")
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 2
        res = Command(cmd="sudo ifconfig {} -promisc".format(self.dut_iface), host=self.dut_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Failed disable promisc")
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 2

        self.dut_ifconfig.delete_vlan_ifaces()
        res = Command(cmd="sudo ifconfig {} promisc".format(self.dut_iface), host=self.dut_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Failed enable promisc")
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 2
        self.dut_ifconfig.create_vlan_iface(1)
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 2
        self.dut_ifconfig.delete_vlan_ifaces()
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 2

        res = Command(cmd="sudo ifconfig {} promisc".format(self.dut_iface), host=self.dut_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Failed enable promisc")
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 2
        for number in range(1, 17):
            self.dut_ifconfig.create_vlan_iface(number)
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 2
        self.dut_ifconfig.delete_vlan_iface(1)
        assert self.dut_atltool_wrapper.readreg(0x5280) & 0x2 == 2

    def test_stripping_of_padding(self):
        """
        @description: Verify StripEtherPadding ethtool option.

        @steps:
        1. Enable stripping of padding using ethtool.
        2. Verify that 0x8 MSM register has correct value.

        @result: MSM is configured correctly.
        @duration: 10 seconds.
        """
        if "forwarding" not in self.dut_drv_version:
            pytest.skip()
        assert self.dut_atltool_wrapper.readmsmreg(0x00000008) & 0x20 == 0
        res = Command(cmd="sudo ethtool --set-priv-flags {} StripEtherPadding on".format(self.dut_iface),
                      host=self.dut_hostname).wait()
        if res["returncode"] != 0:
            raise Exception("Ethtool failed")
        self.dut_ifconfig.wait_link_up()
        assert self.dut_atltool_wrapper.readmsmreg(0x00000008) & 0x20 == 0x20

    @idparametrize("direction", [OFFLOADS_STATE_TX, OFFLOADS_STATE_RX, OFFLOADS_STATE_TX_RX, OFFLOADS_STATE_DSBL])
    def test_flow_control_reg(self, direction):
        """
        @description: Check driver flow control.
        @steps:
        1. In loop for TX, RX, TX/RX or disable value of flow control:
            a. Configure flow control
            b. Renegotiate link speed
            c. Check that register 0x36c/0x13014 has the correct value of flow control bit.

        @result: Register 0x36c/0x13014 has the correct value.
        @duration: 30 seconds.
        @requirements: DRV_FLOW_CONTROL_3, DRV_FLOW_CONTROL_4, DRV_FLOW_CONTROL_5, DRV_FLOW_CONTROL_6,
                       DRV_FLOW_CONTROL_7
        """
        if self.dut_fw_card in CARD_FIJI or self.lkp_fw_card in CARD_FIJI:
            pytest.skip("Not implemented")
        self.dut_ifconfig.set_link_speed(self.supported_speeds[-1])
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        self.dut_ifconfig.set_flow_control(direction)
        time.sleep(3)
        self.dut_ifconfig.set_link_speed(self.supported_speeds[-1])
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        val_1 = self.dut_ifconfig.get_flow_control()
        assert val_1 == direction

        if self.dut_fw_card in CARD_ANTIGUA:
            val = self.dut_atltool_wrapper.readreg(0x13014)
            val = (val >> 8) & 0x3
            if direction == OFFLOADS_STATE_TX_RX:
                assert val == 3
            elif direction == OFFLOADS_STATE_DSBL:
                assert val == 0
            elif direction == OFFLOADS_STATE_RX:
                assert val == 3
            elif direction == OFFLOADS_STATE_TX:
                assert val == 1
        else:
            val = self.dut_atltool_wrapper.readreg(0x36c)
            val = (val >> 3) & 0x3
            if direction == OFFLOADS_STATE_TX_RX:
                assert val == 1 or val == 3
            elif direction == OFFLOADS_STATE_DSBL:
                assert val == 0
            elif direction == OFFLOADS_STATE_RX:
                assert val == 3
            elif direction == OFFLOADS_STATE_TX:
                assert val == 2

    def run_flow_control_lkp(self, direction_dut, direction_lkp):
        self.dut_ifconfig.set_link_speed(self.supported_speeds[-1])
        self.dut_ifconfig.set_flow_control(direction_dut)
        self.lkp_ifconfig.set_flow_control(direction_lkp)
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        speed = self.dut_ifconfig.wait_link_up()

        lkp_pause = self.get_advertised_flow_control_linux()
        if all(pause in [OFFLOADS_STATE_TX_RX, OFFLOADS_STATE_RX] for pause in [direction_dut, direction_lkp]):
            assert lkp_pause == LIN_PAUSE_SYMMETRIC
        elif all(pause in [OFFLOADS_STATE_TX, OFFLOADS_STATE_DSBL] for pause in [direction_dut, direction_lkp]):
            assert lkp_pause == LIN_PAUSE_NO
        elif direction_dut == OFFLOADS_STATE_TX_RX and direction_lkp == OFFLOADS_STATE_TX:
            assert lkp_pause == LIN_PAUSE_TRANSMIT
        elif direction_dut == OFFLOADS_STATE_TX_RX and direction_lkp == OFFLOADS_STATE_RX:
            assert lkp_pause == LIN_PAUSE_SYMMETRIC
        elif direction_dut == OFFLOADS_STATE_TX and direction_lkp == OFFLOADS_STATE_RX:
            assert lkp_pause == LIN_PAUSE_SYMMETRIC_RECEIVE

    def test_flow_control_lkp_tx(self):
        """
        @description: Check FC settings for TX/TX

        @steps:
        1. Setup FC setting of TX/TX for both DUT/LKP
        2. Check advertised FC status

        @result: Advertised FC is disabled
        @duration: 30 seconds
        @requirements: DRV_ADV_FLOW_CONTROL_1
        """
        self.run_flow_control_lkp(OFFLOADS_STATE_TX, OFFLOADS_STATE_TX)

    def test_flow_control_lkp_rx(self):
        """
        @description: Check FC settings for dut RX/RX

        @steps:
        1. Setup FC setting of RX for DUT and RX for LKP
        2. Check advertised FC status

        @result: Advertised FC is symmetric
        @duration: 30 seconds
        @requirements: DRV_ADV_FLOW_CONTROL_2
        """
        self.run_flow_control_lkp(OFFLOADS_STATE_RX, OFFLOADS_STATE_RX)

    def test_flow_control_lkp_rx_tx(self):
        """
        @description: Check FC settings for RX/TX

        @steps:
        1. Setup FC setting of RX/TX for both DUT/LKP
        2. Check advertised FC status

        @result: Advertised FC is symmetric
        @duration: 30 seconds
        @requirements: DRV_ADV_FLOW_CONTROL_3
        """
        self.run_flow_control_lkp(OFFLOADS_STATE_TX_RX, OFFLOADS_STATE_TX_RX)

    def test_flow_control_lkp_dsbl(self):
        """
        @description: Check FC settings for disabled

        @steps:
        1. Setup FC setting of disabled for both DUT/LKP
        2. Check advertised FC status

        @result: Advertised FC is disabled
        @duration: 30 seconds
        @requirements: DRV_ADV_FLOW_CONTROL_4
        """
        self.run_flow_control_lkp(OFFLOADS_STATE_DSBL, OFFLOADS_STATE_DSBL)

    def test_flow_control_lkp_rx_tx_tx(self):
        """
        @description: Check FC settings for dut RX/TX and lkp TX

        @steps:
        1. Setup FC setting of RX/TX for DUT and TX for LKP
        2. Check advertised FC status

        @result: Advertised FC is Transmit-only
        @duration: 30 seconds
        @requirements: DRV_ADV_FLOW_CONTROL_5
        """
        self.run_flow_control_lkp(OFFLOADS_STATE_TX_RX, OFFLOADS_STATE_TX)

    def test_flow_control_lkp_rx_tx_rx(self):
        """
        @description: Check FC settings for dut RX/TX and lkp RX

        @steps:
        1. Setup FC setting of RX/TX for DUT and RX for LKP
        2. Check advertised FC status

        @result: Advertised FC is symmetric
        @duration: 30 seconds
        @requirements: DRV_ADV_FLOW_CONTROL_6
        """
        self.run_flow_control_lkp(OFFLOADS_STATE_TX_RX, OFFLOADS_STATE_RX)

    def test_flow_control_lkp_tx_rx(self):
        """
        @description: Check FC settings for dut TX and lkp RX

        @steps:
        1. Setup FC setting of TX for DUT and RX for LKP
        2. Check advertised FC status

        @result: Advertised FC is Symmetric Receive-only
        @duration: 30 seconds
        @requirements: DRV_ADV_FLOW_CONTROL_7
        """
        self.run_flow_control_lkp(OFFLOADS_STATE_TX, OFFLOADS_STATE_RX)

    def test_interrupt(self):
        """
        @description: Check Legacy and MSI Interupt types.

        @steps:
        1. In loop for 0x1 and 0xa Interrupt MSI type:
            a. Run iperf traffic with payload length 1600 bytes.
            b. Check MSI-X Enable status.
        2. Set Interupt type Legacy.
        3. Run iperf traffic with payload length 1600 bytes.
        4. Check MSI-X Enable status.

        @result: All checks are passed.
        @duration: 3 minutes.
        """
        if not self.dut_ops.is_windows() or self.dut_fw_card == CARD_FIJI:
            pytest.skip("Not implemented")

        def check_msi():
            res = Command(cmd="lspci -d 1d6a: -vvv", host=self.dut_hostname).run()
            for str in res["output"]:
                if "MSI-X: Enable+" in str:
                    return True
                elif "MSI-X: Enable-" in str:
                    return False
            return None

        speed = self.dut_ifconfig.wait_link_up()
        time.sleep(5)
        args = {'time': 5,
                'directon': DIRECTION_RXTX,
                'speed': speed,
                "bandwidth": SPEED_TO_MBITS[speed],
                'buffer_len': 1600,
                'lkp': self.dut_hostname,
                'dut': self.lkp_hostname,
                'lkp4': self.DUT_IPV4_ADDR,
                'lkp6': self.DUT_IPV6_ADDR,
                'dut4': self.LKP_IPV4_ADDR,
                'dut6': self.LKP_IPV6_ADDR}
        driver_version = self.dut_driver.release_version
        ver_major, ver_minor, ver_release, ver_build = [
            int(item) for item in driver_version.split('/')[-1].split('.')]

        if (ver_major >= 3) or (ver_major == 2 and ver_minor >= 1 and ver_release >= 18 and ver_build >= 0):
            message_number_limit = 0x12
        else:
            message_number_limit = 0xa
        for i in [0x1, message_number_limit]:
            self.dut_ifconfig.set_interrupt_type(INTERRUPT_TYPE_MSI, i)
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.dut_ifconfig.wait_link_up()
            self.run_iperf(**args)
            assert check_msi()

        self.dut_ifconfig.set_interrupt_type(INTERRUPT_TYPE_LEGACY)
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        self.run_iperf(**args)
        assert not check_msi()

    def run_nuttcp_interrupt(self, udp, buffer_len):
        def kill_nuttcp():
            Killer().kill("nuttcp")
            Killer(host=self.dut_hostname).kill("nuttcp")
        speed = self.supported_speeds[-1]
        self.dut_ifconfig.set_mtu(MTU_16000)
        self.lkp_ifconfig.set_mtu(MTU_16000)

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()

        args = {'time': self.IPERF_EXEC_TIME,
                "bandwidth": SPEED_TO_MBITS[speed],
                'is_udp': udp,
                'buffer_len': buffer_len,
                'lkp': self.dut_hostname,
                'dut': self.lkp_hostname,
                'lkp4': self.DUT_IPV4_ADDR,
                'dut4': self.LKP_IPV4_ADDR}

        # Run traffic with DIRECTION_RX
        args["direction"] = DIRECTION_RX
        self.cpu_monitor.run_async()
        # result = self.run_iperf(**args)
        n = Nuttcp(**args)
        for i in range(3):
            log.info('nuttcp #{}'.format(i))
            kill_nuttcp()
            n.run_async()
            res = n.join()
            if res:
                break
        else:
            raise Exception("Failed to run nuttcp 3 times")
        cpu = self.cpu_monitor.join(timeout=1)
        assert all(ban > 1 for ban in n.results[0].bandwidth)
        result_rx = {"bandwidths": numpy.mean(n.results[0].bandwidth),
                     "lost_packets": 0 if n.results[0].lost == [] else numpy.mean(n.results[0].lost),
                     "cpu": numpy.mean(cpu)}

        # Run traffic with DIRECTION_TX
        args["direction"] = DIRECTION_TX
        self.cpu_monitor.run_async()
        n = Nuttcp(**args)
        for i in range(3):
            log.info('nuttcp #{}'.format(i))
            kill_nuttcp()
            n.run_async()
            res = n.join()
            if res:
                break
        else:
            raise Exception("Failed to run nuttcp 3 times")
        cpu = self.cpu_monitor.join(timeout=1)
        assert all(ban > 1 for ban in n.results[0].bandwidth)
        result_tx = {"bandwidths": numpy.mean(n.results[0].bandwidth),
                     "lost_packets": 0 if n.results[0].lost == [] else numpy.mean(n.results[0].lost),
                     "cpu": numpy.mean(cpu)}

        # Run traffic with DIRECTION_RXTX
        args["direction"] = DIRECTION_RXTX
        self.cpu_monitor.run_async()
        n = Nuttcp(**args)
        for i in range(3):
            log.info('nuttcp #{}'.format(i))
            kill_nuttcp()
            n.run_async()
            res = n.join()
            if res:
                break
        else:
            raise Exception("Failed to run nuttcp 3 times")
        cpu = self.cpu_monitor.join(timeout=1)
        assert all(ban > 1 for ban in n.results[0].bandwidth)
        assert all(ban > 1 for ban in n.results[1].bandwidth)
        result_rxtx = {"bandwidths": "{}/{}".format(numpy.mean(n.results[0].bandwidth),
                       numpy.mean(n.results[1].bandwidth)),
                       "lost_packets": "{}/{}".format(
                           0 if n.results[0].lost == [] else numpy.mean(n.results[0].lost),
                           0 if n.results[1].lost == [] else numpy.mean(n.results[1].lost)),
                       "cpu": numpy.mean(cpu)}
        return result_rx, result_tx, result_rxtx

    def run_interrupt_moderation(self, state, status):
        if self.dut_ops.is_windows() and self.dut_fw_card != CARD_FIJI:
            if state == self.STATE_DSBL:
                self.dut_ifconfig.set_advanced_property("*InterruptModeration", state)
                param = state
            else:
                self.dut_ifconfig.set_advanced_property("*InterruptModeration", state)
                self.dut_ifconfig.set_advanced_property("ITR", status)
                param = "{}_{}".format(state, status)
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.dut_ifconfig.wait_link_up()

            interrupt_moderation_csv = os.path.join(self.test_log_dir, "interrupt_moderation_{}.csv".format(param))
            with open(interrupt_moderation_csv, 'wb') as csvfile:
                csv_writer = csv.writer(csvfile, delimiter=';', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                csv_writer.writerow(["Parametrs", "rxtx_bandwidths", "rxtx_lost_packets", "rxtx_cpu", "rx_bandwidths",
                                     "rx_lost_packets", "rx_cpu", "tx_bandwidths", "tx_lost_packets", "tx_cpu"])

                result_rx, result_tx, result_rxtx = self.run_nuttcp_interrupt(False, 0)
                csv_writer.writerow([str(item) for item in (param, result_rxtx["bandwidths"],
                                                            result_rxtx["lost_packets"], result_rxtx["cpu"],
                                                            result_rx["bandwidths"], result_rx["lost_packets"],
                                                            result_rx["cpu"],
                                                            result_tx["bandwidths"], result_tx["lost_packets"],
                                                            result_tx["cpu"])])
                buffer_len = 512
                while buffer_len < 16000:
                    params = "{}_{}-buf len".format(param, buffer_len)
                    result_rx, result_tx, result_rxtx = self.run_nuttcp_interrupt(True, buffer_len)
                    buffer_len = buffer_len + 1000
                    csv_writer.writerow([str(item) for item in (params, result_rxtx["bandwidths"],
                                                                result_rxtx["lost_packets"], result_rxtx["cpu"],
                                                                result_rx["bandwidths"], result_rx["lost_packets"],
                                                                result_rx["cpu"],
                                                                result_tx["bandwidths"], result_tx["lost_packets"],
                                                                result_tx["cpu"])])
        else:
            pytest.skip("Test Only For Windows")

    def test_interrupt_moderation_disable(self):
        """
        @description: Check disabled Interupt moderation.

        @steps:
        1. Set Interupt moderation to disabled.
        2. In loop different bandwidth length and RX, TX and RXTX direction:
            a. Run UDP traffic.
            b. Check traffic results.

        @result: All checks are passed.
        @duration: 25 minutes.
        """
        self.run_interrupt_moderation(self.STATE_DSBL, self.STATE_OFF)

    def test_interrupt_moderation_enable_off(self):
        """
        @description: Check enabled Interupt moderation. Interupt moderation rate: off.

        @steps:
        1. Set Interupt moderation to enabled.
        2. Set Interupt moderation rate to off.
        3. In loop different bandwidth length and RX, TX and RXTX direction:
            a. Run iperf3 traffic.
            b. Check traffic results.

        @result: All checks are passed.
        @duration: 25 minutes.
        """
        self.run_interrupt_moderation(self.STATE_ENBL, self.STATE_OFF)

    def test_interrupt_moderation_enable_low(self):
        """
        @description: Check enabled Interupt moderation. Interupt moderation rate: low.

        @steps:
        1. Set Interupt moderation to enabled.
        2. Set Interupt moderation rate to low.
        3. In loop different bandwidth length and RX, TX and RXTX direction:
            a. Run iperf3 traffic.
            b. Check traffic results.

        @result: All checks are passed.
        @duration: 25 minutes.
        """
        self.run_interrupt_moderation(self.STATE_ENBL, self.STATE_LOW)

    def test_interrupt_moderation_enable_extreme(self):
        """
        @description: Check enabled Interupt moderation. Interupt moderation rate: extreme.

        @steps:
        1. Set Interupt moderation to enabled.
        2. Set Interupt moderation rate to extreme.
        3. In loop different bandwidth length and RX, TX and RXTX direction:
            a. Run iperf3 traffic.
            b. Check traffic results.

        @result: All checks are passed.
        @duration: 25 minutes.
        """
        self.run_interrupt_moderation(self.STATE_ENBL, self.STATE_EXTREME)

    def test_interrupt_moderation_enable_medium(self):
        """
        @description: Check enabled Interupt moderation. Interupt moderation rate: medium.

        @steps:
        1. Set Interupt moderation to enabled.
        2. Set Interupt moderation rate to medium.
        3. In loop different bandwidth length and RX, TX and RXTX direction:
            a. Run iperf3 traffic.
            b. Check traffic results.

        @result: All checks are passed.
        @duration: 25 minutes.
        """
        self.run_interrupt_moderation(self.STATE_ENBL, self.STATE_MEDIUM)

    def test_interrupt_moderation_enable_adaptive(self):
        """
        @description: Check enabled Interupt moderation. Interupt moderation rate: adaptive.

        @steps:
        1. Set Interupt moderation to enabled.
        2. Set Interupt moderation rate to adaptive.
        3. In loop different bandwidth length and RX, TX and RXTX direction:
            a. Run iperf3 traffic.
            b. Check traffic results.

        @result: All checks are passed.
        @duration: 25 minutes.
        """
        self.run_interrupt_moderation(self.STATE_ENBL, self.STATE_ADAPTIVE)

    def test_interrupt_moderation_enable_high(self):
        """
        @description: Check enabled Interupt moderation. Interupt moderation rate: high.

        @steps:
        1. Set Interupt moderation to enabled.
        2. Set Interupt moderation rate to high.
        3. In loop different bandwidth length and RX, TX and RXTX direction:
            a. Run iperf3 traffic.
            b. Check traffic results.

        @result: All checks are passed.
        @duration: 25 minutes.
        """
        self.run_interrupt_moderation(self.STATE_ENBL, self.STATE_HIGH)

    def test_macvlan(self):
        if self.dut_ops.is_linux():
            try:
                promisc_mode_reg = 0x5100
                netmask = "255.255.255.0"
                dstmac = "01:01:01:01:01:01"
                ip_dut_base = "192.168.100.1"
                ip_lkp_base = "192.168.100.2"
                self.dut_ifconfig.del_ip_address(self.DUT_IPV4_ADDR)
                self.lkp_ifconfig.del_ip_address(self.LKP_IPV4_ADDR)
                self.dut_ifconfig.set_ip_address(ip_dut_base, netmask, self.LKP_IPV4_ADDR)
                self.lkp_ifconfig.set_ip_address(ip_lkp_base, netmask, None)
                self.dut_ifconfig.wait_link_up()
                for number in range(33):
                    ip_dut = '192.168.{}.1'.format(number)
                    ip_lkp = '192.168.{}.2'.format(number)

                    c = Command(cmd="sudo ip link add macvlan{} link {} type macvlan mode bridge".format(number,
                                self.dut_iface), host=self.dut_hostname)
                    c.run()
                    assert c.join()["returncode"] == 0
                    c = Command(cmd="sudo ifconfig macvlan{} {} netmask {} up".format(number, ip_dut, netmask),
                                host=self.dut_hostname)
                    c.run()
                    assert c.join()["returncode"] == 0
                    self.dut_ifconfig.wait_link_up()
                    self.lkp_ifconfig.set_ip_address(ip_lkp, netmask, None)
                    self.lkp_ifconfig.wait_link_up()
                    assert self.ping(from_host=self.lkp_hostname, to_host=ip_dut, src_addr=ip_lkp), 'ping failed'
                    scapy_tool = ScapyTools(port=self.lkp_port)
                    if number == 32:
                        assert scapy_tool.ping(dstip=ip_dut_base, srcip=ip_lkp_base, dstmac=dstmac) is True, \
                            'promisc mode does not turn on'
                        if self.dut_fw_card not in CARD_FIJI:
                            promisc = self.dut_atltool_wrapper.readreg(promisc_mode_reg) & 0x8
                            assert promisc == 8, "register did not include Promiscuous mode"
            finally:
                self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, self.LKP_IPV4_ADDR)
                self.lkp_ifconfig.set_ip_address(self.LKP_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, None)

        else:
            pytest.skip("test for Linux")

    def test_phy_thermal_settings(self):
        """
        @description: Check driver thermal shutdown settings.

        @steps:
        1. Get value of HIGH_TEMP_FAILURE_THRESHOLD by reading PHY register.
        2. Get value of HIGH_TEMP_WARNING_THRESHOLD by reading PHY register.
        3. Get value of LOW_TEMP_WARNING_THRESHOLD by reading PHY register.

        @result: Check that all thresholds have correct values.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip()

        if self.dut_fw_card in CARD_FIJI:
            pytest.skip("Skip for Fiji ")

        if self.dut_fw_card == CARD_ANTIGUA:
            """Test that driver after load sets correct PHY thermal shutdown settings"""
            HIGH_TEMP_FAILURE_THRESHOLD = (0, 0, 108)
            HIGH_TEMP_WARNING_THRESHOLD = (0, 0, 100)
            LOW_TEMP_WARNING_THRESHOLD = (0, 0, 80)

            # Check settings
            temp_treshold = self.fw_config.get_thermal_shutdown_threshold()

            dut_high_temp_fail = temp_treshold.shutdownTempThreshold
            dut_high_temp_warn = temp_treshold.warningHotTempThreshold
            dut_low_temp_warn = temp_treshold.warningColdTempThreshold

        else:
            if self.dut_ops.is_linux():
                pytest.xfail()
            """Test that driver after load sets correct PHY thermal shutdown settings"""
            HIGH_TEMP_FAILURE_THRESHOLD = (0x1E, 0xC421, 0x6C00)
            HIGH_TEMP_WARNING_THRESHOLD = (0x1E, 0xC423, 0x6400)
            LOW_TEMP_WARNING_THRESHOLD = (0x1E, 0xC424, 0x5000)

            # Check settings
            dut_high_temp_fail = self.dut_atltool_wrapper.readphyreg(
                HIGH_TEMP_FAILURE_THRESHOLD[0], HIGH_TEMP_FAILURE_THRESHOLD[1])
            dut_high_temp_warn = self.dut_atltool_wrapper.readphyreg(
                HIGH_TEMP_WARNING_THRESHOLD[0], HIGH_TEMP_WARNING_THRESHOLD[1])
            dut_low_temp_warn = self.dut_atltool_wrapper.readphyreg(
                LOW_TEMP_WARNING_THRESHOLD[0], LOW_TEMP_WARNING_THRESHOLD[1])

        assert dut_high_temp_fail == HIGH_TEMP_FAILURE_THRESHOLD[2], \
            "Driver set incorrect high temperature failure threshold"
        assert dut_high_temp_warn == HIGH_TEMP_WARNING_THRESHOLD[2], \
            "Driver set incorrect high temperature warning threshold"
        assert dut_low_temp_warn == LOW_TEMP_WARNING_THRESHOLD[2], \
            "Driver set incorrect low temperature warning threshold"

        # Check that thermal trigger is set to High-Temperature Failure
        th_sh_trigger = (self.dut_atltool_wrapper.readphyreg(0x1E, 0xC475) & 0xC000) >> 0xE
        assert th_sh_trigger == 2, "PHY thermal shutdown trigger is set to incorrect value: {}".format(th_sh_trigger)

        log.info("All thermal settings are correct")

    def test_thermal_shutdown_status(self):
        """
        @description: Check Thermal shutdown is enabled by driver.

        @steps:
        1. If A2 check thermal_shutdown status via driver interface.
        2. Check thermal_shutdown status in phy.
        3. Check default thresholds

        @result: All checks are passed.
        @duration: 5 sec.
        """

        if not OpSystem().is_windows():
            pytest.skip()
        if self.dut_fw_card in FELICITY_CARDS or self.dut_fw_card == CARD_FIJI:
            pytest.skip()

        if self.dut_fw_is_a2:
            thermal_shutdown = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.thermalControl")
            assert thermal_shutdown.shutdownEnable == 1

        reg_status = Register(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc478))
        assert reg_status[0xa] == 1

        shutdown_temp_threshold = 108
        warning_hot_temp_threshold = 100
        warning_cold_temp_threshold = 80

        temp_treshold = self.fw_config.get_thermal_shutdown_threshold()
        assert temp_treshold.shutdownTempThreshold == shutdown_temp_threshold,\
            "Incorrect default high temperature failure threshold. Expected: {}. Actual: {}.".\
            format(shutdown_temp_threshold, temp_treshold.shutdownTempThreshold)
        assert temp_treshold.warningHotTempThreshold == warning_hot_temp_threshold,\
            "Incorrect default high temperature warning threshold. Expected: {}. Actual: {}.".\
            format(warning_hot_temp_threshold, temp_treshold.warningHotTempThreshold)
        assert temp_treshold.warningColdTempThreshold == warning_cold_temp_threshold,\
            "Incorrect default low temperature warning threshold. Expected: {}. Actual: {}.".\
            format(warning_cold_temp_threshold, temp_treshold.warningColdTempThreshold)

    def test_wmi_thermal_info(self):
        """
        @description: Check driver thermal shutdown settings.

        @steps:
        1. Get Diagnostics Data via Windows driver.
        2. Chack that MAC Temperature has value from 20 to 120
        3. Chack that PHY Temperature has value from 20 to 120

        @result: All checks are passed.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip()

        if self.dut_fw_card in CARD_FIJI:
            pytest.skip("Skip for Fiji ")

        """Test that driver displays reasonable thermal info"""
        if not self.dut_ops.is_windows():
            pytest.skip("WMI is Windows feature only")

        wmi_class = 'Aq_DiagnosticsData'
        if self.dut_fw_card == CARD_ANTIGUA:
            # Thermal data has been separated from general diagnostics info and is
            # now available in a separate WMI class instance Aq_ThermalInformation
            wmi_class = 'Aq_ThermalInformation'

        res = Command(
            cmd="powershell \"Get-WmiObject -Namespace root\\wmi -Class {} "
                "| ConvertTo-Json -Depth 3\"".format(wmi_class),
            silent=True,
            host=self.dut_hostname
        ).run()
        if res["returncode"] != 0:
            raise Exception("Failed to get Diagnostics Data using Windows driver")

        j = json.loads("\n".join(res["output"]))

        if self.dut_fw_card == CARD_ANTIGUA:
            mac_temperature = 100 * 100
            phy_temperature = j['phyTemperature']
        else:
            mac_temperature = next(
                prop["Value"] for prop in j["thermalInfo"]["Properties"] if prop["Name"] == "macTemperature")
            log.info("Driver reported MAC temperature: {}.{}".format(mac_temperature // 100, mac_temperature % 100))
            phy_temperature = next(
                prop["Value"] for prop in j["thermalInfo"]["Properties"] if prop["Name"] == "phyTemperature")
            log.info("Driver reported PHY temperature: {}.{}".format(phy_temperature // 100, phy_temperature % 100))

        assert 20 * 100 < mac_temperature < 120 * 100
        assert 20 * 100 < phy_temperature < 120 * 100

    # ARP offload supports only one adress
    @idparametrize("status", ["Enable", "Disable"])
    def test_arp_offload(self, status):
        """
        @description: Check driver ARP offloads.

        @steps:
        1. In loop for Enabled and Disabled arp offloads state:
            a. Set driver offloads settings.
            b. Hibernate DUT.
            c. Send ARP request from LKP to DUT.
            d. Make sure that ARP requests are answered or not depending on offload state.

        @result: All checks are passed.
        @duration: 5 minutes.
        """
        if self.dut_ops.is_linux():
            pytest.skip("Skip for Linux")

        assert status in ["Enable", "Disable"]

        # if self.dut_ops.is_windows():
        #     # Disable IPv6 binding to make sure that Windows sends ARP OID_PM_ADD_PROTOCOL_OFFLOAD to the driver
        #     self.dut_ifconfig.unbind_ipv6()

        self.set_offload_settings(status, "Disable")

        self.hibernate_dut()

        if self.is_host_alive(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        if self.lkp_ifconfig.get_link_speed() == LINK_SPEED_NO_LINK:
            raise Exception("DUT didn't setup link after hibernation")

        macs = arping(self.lkp_port, self.DUT_IPV4_ADDR, self.LKP_IPV4_ADDR)

        if status == "Enable":
            assert len(macs) == 1, "Should have received 1 ARP reply, got {}: {}".format(len(macs), macs)

            reply_mac = macs[0].replace(macs[0][2], "").lower()
            expected_mac = self.dut_mac.replace(self.dut_mac[2], "").lower()
            assert reply_mac == expected_mac, "Received mac {} != DUT mac {}".format(macs[0], self.dut_mac)

            log.info("Received 1 correct ARP reply: {}, DUT mac: {}".format(macs[0], self.dut_mac))
        else:
            assert len(macs) == 0, "Got unexpected ARP reply: {}, DUT mac: {}".format(macs, self.dut_mac)
            log.info("Host {} didn't reply on ARP request as expected".format(self.dut_hostname))

    # NS offload support up to two adresses
    @idparametrize("status", ["Enable", "Disable"])
    def test_ns_offload(self, status):
        """
        @description: Check driver NS offloads.

        @steps:
        1. In loop for Enabled and Disabled arp offloads:
            a. Set driver offloads settings.
            b. Hibernate DUT.
            c. Send IPv6 NS requests from LKP to DUT.
            d. Check received packets.

        @result: All checks are passed.
        @duration: 1 minutes.
        """
        if self.dut_ops.is_linux():
            pytest.skip("Skip for Linux")

        self.set_offload_settings("Disable", status)

        ipv6 = self.dut_ifconfig.get_ip_address(ipv=6)
        for ip in ipv6:
            if ip != str(ipaddress.ip_address(unicode(self.DUT_IPV6_ADDR))):
                self.dut_ifconfig.del_ip_address(ip)

        time.sleep(self.LINK_CONFIG_DELAY)

        # Setting extra IPV6
        dut_ipv6 = self.randomize_ipv6(self.DUT_IPV6_ADDR)
        self.dut_ifconfig.set_ipv6_address(dut_ipv6, self.PREFIX_IPV6, None)
        time.sleep(self.LINK_CONFIG_DELAY)

        self.hibernate_dut()

        if self.is_host_alive(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        if self.lkp_ifconfig.get_link_speed() == LINK_SPEED_NO_LINK:
            raise Exception("DUT didn't setup link after hibernation")

        macs_1 = arping(self.lkp_port, self.DUT_IPV6_ADDR, self.LKP_IPV6_ADDR)
        macs_2 = arping(self.lkp_port, dut_ipv6, self.LKP_IPV6_ADDR)

        if status == "Enable":
            assert len(macs_1) == 1, "Should have received 1 NA reply, got {}: {}".format(len(macs_1), macs_1)
            assert len(macs_2) == 1, "Should have received 1 NA reply, got {}: {}".format(len(macs_2), macs_2)

            reply_mac_1 = macs_1[0].replace(macs_1[0][2], "").lower()
            reply_mac_2 = macs_2[0].replace(macs_2[0][2], "").lower()
            expected_mac = self.dut_mac.replace(self.dut_mac[2], "").lower()

            assert reply_mac_1 == expected_mac, "Received mac {} != DUT mac {}".format(reply_mac_1[0], self.dut_mac)
            assert reply_mac_2 == expected_mac, "Received mac {} != DUT mac {}".format(reply_mac_2[0], self.dut_mac)

            log.info("Received 1 correct NA reply: {}, DUT mac: {}".format(macs_1[0], self.dut_mac))
            log.info("Received 1 correct NA reply: {}, DUT mac: {}".format(macs_2[0], self.dut_mac))
        else:
            assert len(macs_1) == 0, "Got unexpected NA reply: {}, DUT mac: {}".format(macs_1, self.dut_mac)
            assert len(macs_2) == 0, "Got unexpected NA reply: {}, DUT mac: {}".format(macs_2, self.dut_mac)

            log.info("Host {} didn't reply on NS request as expected".format(self.dut_hostname))

    @idparametrize("buff_size", [128, 256, 512, 1024, 2048, 4096, 8184])
    def test_tx_buffer(self, buff_size):
        """
        @description: Check driver Transmit buffers.

        @steps:
        1. In loop for [128, 256, 512, 1024, 2048, 4096, 8184] values of TX buffer:
            a. Set TX buffer size via driver advanced settings.
            b. Run TCP traffic.

        @result: Check traffic results.
        @duration: 10 minutes.
        """
        self.dut_ifconfig.set_buffer_size(tx_size=buff_size, rx_size=2048)
        self.iperf_config['direction'] = DIRECTION_RX
        self.run_iperf(**self.iperf_config)

    @idparametrize("buff_size", [128, 256, 512, 1024, 2048, 4096, 8184])
    def test_rx_buffer(self, buff_size):
        """
        @description: Check driver Receive buffers.

        @steps:
        1. In loop for [128, 256, 512, 1024, 2048, 4096, 8184] values of RX buffers:
            a. Set RX buffer size via driver advanced settings.
            b. Run TCP traffic.

        @result: Check traffic results.
        @duration: 10 minutes.
        """
        self.dut_ifconfig.set_buffer_size(rx_size=buff_size, tx_size=4096)
        self.iperf_config['direction'] = DIRECTION_TX
        self.run_iperf(**self.iperf_config)

    def test_vlan_ping(self):
        """
        @description: This test performs ping check with tagged interfaces.

        @steps:
        1. Create vlan interfaces on both DUT and LKP using vlan id 10.
        2. Send ping via tagged interface.
        3. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 30 seconds.
        """
        if not (self.dut_ops.is_windows() and self.lkp_ops.is_linux()):
            pytest.skip("Skip: Windows on DUT and Linux on LKP are required.")

        if self.dut_fw_card in CARD_FIJI:
            pytest.skip("Not implemented in Fiji ")

        self.lkp_ifconfig.delete_vlan_ifaces()

        speed = LINK_SPEED_AUTO
        vlan_id = 10
        dut_ip = "192.168.10.1"
        lkp_ip = "192.168.10.2"
        netmask = "255.255.255.0"

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.set_advanced_property("*PriorityVLANTag", "2")
        self.dut_ifconfig.set_advanced_property("VlanID", vlan_id)
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.create_vlan_iface(vlan_id)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.dut_ifconfig.set_ip_address(dut_ip, netmask, gateway=None, vlan_id=None)
        self.lkp_ifconfig.set_ip_address(lkp_ip, netmask, gateway=None, vlan_id=vlan_id)
        time.sleep(5)
        self.dut_ifconfig.wait_link_up(vlan_id=None)

        assert ping(number=3, host=dut_ip, src_addr=lkp_ip)

    def test_vlan_monitor(self):
        """
        @description: Check VLan monitor mode option.

        @steps:
        1. Create vlan interfaces on both DUT and LKP using vlan id 10.
        2. Enable VLan monitor mode on DUT.
        3. Send UDP packet via tagged interface.
        4. Check received package has a Dot1Q layer.

        @result: Ping is passed.
        @duration: 30 seconds.
        """
        if not (self.dut_ops.is_windows() and self.lkp_ops.is_linux()):
            pytest.skip("Skip: Windows on DUT and Linux on LKP are required.")

        if self.dut_fw_card in CARD_FIJI:
            pytest.skip("Not implemented in Fiji ")

        self.lkp_ifconfig.delete_vlan_ifaces()

        speed = LINK_SPEED_AUTO
        vlan_id = 10
        dut_ip = "192.168.10.1"
        lkp_ip = "192.168.10.2"
        netmask = "255.255.255.0"

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)

        self.dut_ifconfig.set_advanced_property("*PriorityVLANTag", "2")
        self.dut_ifconfig.set_advanced_property("VlanID", vlan_id)
        self.dut_ifconfig.set_advanced_property("MonitorModeEnabled", "Enable")
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.create_vlan_iface(vlan_id)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.dut_ifconfig.set_ip_address(dut_ip, netmask, gateway=None, vlan_id=None)
        self.lkp_ifconfig.set_ip_address(lkp_ip, netmask, gateway=None, vlan_id=vlan_id)
        self.dut_ifconfig.wait_link_up(vlan_id=None)

        sniffer = Tcpdump(host=self.dut_hostname, port=self.dut_port, timeout=10)
        sniffer.run_async()

        l2 = Ether(dst=self.dut_mac, src=self.lkp_mac)
        l2 = l2 / Dot1Q(vlan=vlan_id)
        l3 = IP(dst=dut_ip, src=lkp_ip)
        l4 = UDP()
        pkt = l2 / l3 / l4
        sender = Aqsendp(count=1, packet=scapy_pkt_to_aqsendp_str(pkt))
        sender.run()

        packets = sniffer.join()

        got_packet = False
        for p in packets:
            if IP in p and p[IP].src == lkp_ip and Dot1Q in p and p[Dot1Q].vlan == vlan_id:
                got_packet = True
                break
        assert got_packet, 'VLAN packets not captured'

    def get_cable_diag_drv_linux(self, stats):
        # collect data from ethtool
        command = 'sudo ethtool -t {} online'.format(self.dut_iface)
        res = Command(cmd=command, host=self.dut_hostname).run()
        assert res['returncode'] == 0

        for line in res['output']:
            for p in stats:
                if p in line:
                    val = int(line.split()[-1])
                    stats[p]['drv'] = val

        # Check PHY Temp immediately after driver to minimize value deviation
        stats['PHY Temp']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc820) >> 8)

    def get_cable_diag_drv_windows(self, stats):
        cmd = 'powershell -command ' \
              '\"Get-WmiObject -Namespace root\\wmi -Class Aq_NetAdapter ' \
              '| Invoke-WmiMethod -Name ExecCableDiag ' \
              '| Select -ExpandProperty diagRes ' \
              '| Select -ExpandProperty pairs"'
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        assert res['returncode'] == 0, 'WMI ExecCableDiag Failed'

        assert len(res['output']) == 4, 'Incorrect number of lines'
        for i in range(4):
            pair = int(res['output'][i])
            stats['TDR status ' + 'ABCD'[i]]['drv'] = pair & 0xFF
            stats['TDR distance ' + 'ABCD'[i]]['drv'] = pair >> 8 & 0xFF
            stats['TDR far distance ' + 'ABCD'[i]]['drv'] = pair >> 16 & 0xFF

    def get_cable_diag_phy_nikki(self, stats):
        # init diag in PHY
        reg_diag_init = 0xc470
        reg_diag_status = 0xc831

        init = self.dut_atltool_wrapper.readphyreg(0x1e, reg_diag_init) | 0x0010
        self.dut_atltool_wrapper.writephyreg(0x1e, reg_diag_init, init)

        max_iter = 0
        init_time = 0
        while self.dut_atltool_wrapper.readphyreg(0x1e, reg_diag_status) & 0x8000:
            init_time += 0.1
            time.sleep(0.1)
            max_iter += 1
            if max_iter > 600:
                break

        log.info('Diagnostic time: {:.3f} s'.format(init_time))

        assert 0.2 <= init_time <= 60.0, "Cable diagnostics test failed to run."

        # collect data from phy registers
        # stats['PHY Temp']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc820) >> 8)
        phy_status = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc800))
        stats['TDR status A']['phy'] = (phy_status >> 12) & 7
        stats['TDR status B']['phy'] = (phy_status >> 8) & 7
        stats['TDR status C']['phy'] = (phy_status >> 4) & 7
        stats['TDR status D']['phy'] = phy_status & 7
        stats['TDR distance A']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc801) >> 8)
        stats['TDR distance B']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc803) >> 8)
        stats['TDR distance C']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc805) >> 8)
        stats['TDR distance D']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc807) >> 8)
        stats['TDR far distance A']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc806) & 255)
        stats['TDR far distance B']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc806) >> 8)
        stats['TDR far distance C']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc808) & 255)
        stats['TDR far distance D']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc808) >> 8)

        stats['SNR margin A']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1, 0x85))
        stats['SNR margin B']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1, 0x86))
        stats['SNR margin C']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1, 0x87))
        stats['SNR margin D']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1, 0x88))

        stats['DSP Cable Len']['phy'] = int(self.dut_atltool_wrapper.readphyreg(0x1e, 0xc884) & 255)

    def get_cable_diag_phy_antigua(self, stats):
        st = self.fw_config.get_cable_diag_status()
        transactId = st.transactId

        timeout = 30
        self.fw_config.run_cable_diag(timeout=timeout)

        is_ok = False
        start = timeit.default_timer()
        for i in range(timeout):
            time.sleep(1)
            st = self.fw_config.get_cable_diag_status()
            if st.transactId > transactId:
                is_ok = True
                break

        log.info('Cable diagnostics finished: {:.1f} sec'.format(timeit.default_timer() - start))
        assert is_ok, "TransactId not changed"
        assert st.status == 0, "Status must be zero"

        for i in range(4):
            stats['TDR status ' + 'ABCD'[i]]['phy'] = st.laneData[i].resultCode
            stats['TDR distance ' + 'ABCD'[i]]['phy'] = st.laneData[i].dist
            stats['TDR far distance ' + 'ABCD'[i]]['phy'] = st.laneData[i].farDist

        return stats

    def test_cable_diag(self):
        """
        @description: This subtest verifies driver cable diag test on Antigua and Nikki,
        include check for PHY temperature shown in test result.
        A1 and A2 support different features when it comes to self-tests/cable diag, i.e.:
            A2 doesn't support SNR;
            there is no 'online' way to get the cable length on A2 (only via full TDR cable diag);

        @steps:
        1. Get PHY Temp, DSP Cable Len, TDR, SNR via driver self test.
        1. Get PHY Temp, DSP Cable Len, TDR, SNR from PHY.
        3. Compare values.

        @result: All checks are passed.
        @duration: 20 sec.
        """
        if self.dut_ops.is_windows() and self.dut_fw_card != CARD_ANTIGUA:
            pytest.skip()

        if "forwarding" in self.dut_drv_version:
            pytest.skip()

        if self.dut_fw_card not in [CARD_ANTIGUA, CARD_NIKKI]:
            pytest.skip()

        stats = OrderedDict()
        stats['PHY Temp'] = {'drv': None, 'phy': None, 'diff': 2, 'status': None}
        stats['TDR status A'] = {'drv': None, 'phy': None, 'diff': 0, 'status': None}
        stats['TDR status B'] = {'drv': None, 'phy': None, 'diff': 0, 'status': None}
        stats['TDR status C'] = {'drv': None, 'phy': None, 'diff': 0, 'status': None}
        stats['TDR status D'] = {'drv': None, 'phy': None, 'diff': 0, 'status': None}
        stats['TDR distance A'] = {'drv': None, 'phy': None, 'diff': 2, 'status': None}
        stats['TDR distance B'] = {'drv': None, 'phy': None, 'diff': 2, 'status': None}
        stats['TDR distance C'] = {'drv': None, 'phy': None, 'diff': 2, 'status': None}
        stats['TDR distance D'] = {'drv': None, 'phy': None, 'diff': 2, 'status': None}
        stats['TDR far distance A'] = {'drv': None, 'phy': None, 'diff': 2, 'status': None}
        stats['TDR far distance B'] = {'drv': None, 'phy': None, 'diff': 2, 'status': None}
        stats['TDR far distance C'] = {'drv': None, 'phy': None, 'diff': 2, 'status': None}
        stats['TDR far distance D'] = {'drv': None, 'phy': None, 'diff': 2, 'status': None}

        if self.dut_fw_card != CARD_ANTIGUA:
            stats['DSP Cable Len'] = {'drv': None, 'phy': None, 'diff': 1, 'status': None}
            stats['SNR margin A'] = {'drv': None, 'phy': None, 'diff': 24, 'status': None}
            stats['SNR margin B'] = {'drv': None, 'phy': None, 'diff': 24, 'status': None}
            stats['SNR margin C'] = {'drv': None, 'phy': None, 'diff': 24, 'status': None}
            stats['SNR margin D'] = {'drv': None, 'phy': None, 'diff': 24, 'status': None}

        if self.dut_fw_card == CARD_ANTIGUA:
            self.get_cable_diag_phy_antigua(stats)
        else:
            self.get_cable_diag_phy_nikki(stats)

        if self.dut_ops.is_windows():
            self.get_cable_diag_drv_windows(stats)
            # stub
            stats['PHY Temp']['phy'] = 30
            stats['PHY Temp']['drv'] = 30
        else:
            self.get_cable_diag_drv_linux(stats)

        all_pass = True
        for key in stats:
            stats[key]['status'] = abs(stats[key]['drv'] - stats[key]['phy']) <= stats[key]['diff']
            msg = '{:31s}    DRV: {:5d}    PHY: {:5d}        RESULT: {}'.format(
                key, stats[key]['drv'], stats[key]['phy'], 'PASS' if stats[key]['status'] else 'FAIL')
            log.info(msg)
            all_pass &= stats[key]['status']

        assert all_pass, "Incorrect Cable Diag test result"


class TestLegacyInterruptsForwarding(TestBase):
    @classmethod
    def setup_class(cls):
        super(TestLegacyInterruptsForwarding, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def kill_nuttcp(self):
        Killer().kill("nuttcp")
        Killer(host=self.dut_hostname).kill("nuttcp")

    def run_nuttcp(self, udp, speed):
        args = {'time': 30,
                "bandwidth": SPEED_TO_MBITS[speed],
                'is_udp': udp,
                'lkp': self.dut_hostname,
                'dut': self.lkp_hostname,
                'lkp4': self.DUT_IPV4_ADDR,
                'dut4': self.LKP_IPV4_ADDR,
                'direction': DIRECTION_RX}

        n = Nuttcp(**args)
        for i in range(3):
            log.info('nuttcp #{}'.format(i))
            self.kill_nuttcp()
            n.run_async()
            res = n.join()
            if res:
                break
        else:
            raise Exception("Failed to run nuttcp 3 times")
        assert all(ban > 1 for ban in n.results[0].bandwidth)
        if not udp:
            result = {"bandwidths": n.results[0].bandwidth}
        else:
            result = {"bandwidths": n.results[0].bandwidth,
                      "lost_packets": n.results[0].lost}
        return result

    @idparametrize("count", [4, 6, 8])
    def test_tcp_max_queues_non_msi(self, count):
        """
        @description: Check tcp traffic with queues_non_msi.

        @steps:
        1. In loop for queues_non_msi in [4, 6, 8]:
            a. Insmod driver with max_queues_non_msi.
            b. Set ip address.
            c. Set link up.
            d. Start tcp traffic.
            f. Check that the speed is greater than 0 mb/sec

        @result: All checks are passed.
        @duration: 35 seconds.
        """
        if "forwarding" not in self.dut_drv_version:
            pytest.skip()
        self.dut_driver = Driver(port=self.dut_port, version=self.dut_drv_version, host=self.dut_hostname,
                                 insmod_args="msi=N max_queues_non_msi={}".format(count))
        self.dut_driver.install()

        self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, self.LKP_IPV4_ADDR)
        self.dut_ifconfig.set_ipv6_address(self.DUT_IPV6_ADDR, self.PREFIX_IPV6, None)
        time.sleep(self.LINK_CONFIG_DELAY)
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        speed = self.dut_ifconfig.wait_link_up()
        self.run_nuttcp(False, speed)

    @idparametrize("count", [4, 6, 8])
    def test_udp_max_queues_non_msi(self, count):
        """
        @description: Check udp traffic with queues_non_msi.

        @steps:
        1. In loop for queues_non_msi in [4, 6, 8]:
            a. Insmod driver with max_queues_non_msi.
            b. Set ip address.
            c. Set link up.
            d. Start tcp traffic.
            f. Check that the speed is greater than 0 mb/sec

        @result: All checks are passed.
        @duration: 35 seconds.
        """
        if "forwarding" not in self.dut_drv_version:
            pytest.skip()
        self.dut_driver = Driver(port=self.dut_port, version=self.dut_drv_version, host=self.dut_hostname,
                                 insmod_args="msi=N max_queues_non_msi={}".format(count))
        self.dut_driver.install()

        self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, self.LKP_IPV4_ADDR)
        self.dut_ifconfig.set_ipv6_address(self.DUT_IPV6_ADDR, self.PREFIX_IPV6, None)
        time.sleep(self.LINK_CONFIG_DELAY)

        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        speed = self.dut_ifconfig.wait_link_up()
        self.run_nuttcp(True, speed)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
