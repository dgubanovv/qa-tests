import os
import re
import shutil
import sys
import time

import pytest
from scapy.utils import wrpcap

from infra.test_base import TestBase, idparametrize
from tools.aqpkt import Aqsendp, scapy_pkt_to_aqsendp_str
from tools.atltool_fiji import AtlToolFiji
from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import CARD_FIJI, LINK_STATE_DOWN, LINK_STATE_UP, DIRECTION_RX, DIRECTION_TX, SPEED_TO_MBITS, \
    OFFLOADS_STATE_ON, OFFLOADS_STATE_OFF, OFFLOADS_STATE_DSBL, OFFLOADS_STATE_ENBL, OFFLOADS_STATE_TX, \
    OFFLOADS_STATE_RX, OFFLOADS_STATE_TX_RX, NFS_SERVER, MTU_1500, MTU_2000, MTU_4000, MTU_9000, MTU_16000, \
    LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M
from tools.driver import Driver, DRV_TYPE_KO
from tools.iptables import IPTables
from tools.ops import OpSystem
from tools.scapy_tools import ScapyTools, Ether, Dot1Q, IP, IPv6, TCP, UDP, ICMP, Raw, RandString
from tools.tcpdump import Tcpdump
from tools.tracepoint import Tracepoint
from tools.utils import get_atf_logger, upload_file, get_bus_dev_func

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_settings"


# ========= Offloads ========= #
L4_IP4_CHECKSUM = "l4_ip4_cheksum"
L4_IP6_CHECKSUM = "l4_ip6_cheksum"
TCP_IP4_CHECKSUM = "tcp_ip4_cheksum"
UDP_IP4_CHECKSUM = "udp_ip4_cheksum"
TCP_IP6_CHECKSUM = "tcp_ip6_cheksum"
UDP_IP6_CHECKSUM = "udp_ip6_cheksum"
IP4_CHECKSUM = "ip4_checksum"
LSO_V1_IP4 = "lso_v1_ip4"
LSO_V2_IP4 = "lso_v2_ip4"
LSO_V2_IP6 = "lso_v2_ip6"
RECEIVE_SIDE_SCALING = "receive_side_scaling"
RECV_SEGMENT_COALESCING_IP4 = "recv_segment_coalescing_IPv4"
RECV_SEGMENT_COALESCING_IP6 = "recv_segment_coalescing_IPv6"

TX_CHECKSUM = "tx_checksum"
RX_CHECKSUM = "rx_checksum"
LSO = "lso"
LRO = "lro"  # GRO is same as LRO
GSO = "gso"
RX_VLAN = "rxvlan"
TX_VLAN = "txvlan"
RX_VLAN_FILTER = 'rx-vlan-filter'

OFFLOADS = [L4_IP4_CHECKSUM, L4_IP6_CHECKSUM, IP4_CHECKSUM,
            LSO_V1_IP4, LSO_V2_IP4, LSO_V2_IP6, TX_CHECKSUM,
            RX_CHECKSUM, LSO, LRO, GSO, RECEIVE_SIDE_SCALING,
            RECV_SEGMENT_COALESCING_IP4, RECV_SEGMENT_COALESCING_IP6,
            TCP_IP4_CHECKSUM, UDP_IP4_CHECKSUM, TCP_IP6_CHECKSUM, UDP_IP6_CHECKSUM]

WIN_OFL = "win_ofl"
LINUX_OFL = "linux_ofl"
MAC_OFL = "mac_ofl"
FREEBSD_OFL = "freebsd_ofl"

# ========= Registers ========= #
CHK_SUM_RX_REG = 0x5580
CHK_SUM_TX_REG = 0x7800
LSO_REG = 0x7810
LRO_REG = 0x5590
RSS_REG = 0x54C0


class DrvOffloadsBase(TestBase):
    """
    @description: The DrvOffloadsBase test is dedicated to verify Driver offloads.

    @setup: Two Aquantia devices connected back to back.
    """
    IPV4_GATEWAY = "192.168.0.1"
    TO_RENAME_IFACE = """
ACTION==\"add\", SUBSYSTEM==\"net\", DRIVERS==\"?*\", ATTR{{address}}==\"{}\", NAME=\"{}\"
    """

    @classmethod
    def setup_class(cls):
        super(DrvOffloadsBase, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            if cls.dut_fw_card == CARD_FIJI and OpSystem().is_linux():
                cls.dut_mac = cls.dut_ifconfig.get_mac_address()
                log.info("Rename Fiji adapter interface name")
                bus, dev, func = get_bus_dev_func(cls.dut_port)
                if OpSystem().is_ubuntu():
                    name = "enx{}s{}".format(bus, dev)
                else:
                    name = "enp{}s{}".format(bus, dev)
                with open('/tmp/70-persistent-ipoib.rules', 'a') as f:
                    f.write(cls.TO_RENAME_IFACE.format(cls.dut_mac, name))
                command_dut_cp_to_home = Command(
                    cmd='sudo cp /tmp/70-persistent-ipoib.rules /etc/udev/rules.d/70-persistent-ipoib.rules')
                res = command_dut_cp_to_home.run_join(5)
                assert res["returncode"] == 0, 'Failed to make cp command'

            cls.install_firmwares()

            if cls.dut_fw_card not in CARD_FIJI:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)

            if cls.dut_fw_card not in CARD_FIJI and cls.dut_atltool_wrapper.is_secure_chips() and cls.dut_ops.is_linux():
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, flashless_fw=cls.dut_fw_version)
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            if 'Tehuti' in cls.platform:
                cls.lkp_driver = Driver(port=cls.lkp_port, version="latest",
                                        host=cls.lkp_hostname, drv_type=DRV_TYPE_KO)
            else:
                cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)

            cls.dut_driver.install()
            cls.lkp_driver.install()

            # IPV4_GATEWAY setting on DUT is the workaround
            # For some reason Windows do not propagate ARP/NS affloads to the driver if gateway is not set
            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, cls.LKP_IPV4_ADDR)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.dut_ifconfig.set_ipv6_address(cls.DUT_IPV6_ADDR, cls.PREFIX_IPV6, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IPV6_ADDR, cls.PREFIX_IPV6, None)
            cls.dut_ifconfig.wait_link_up()

            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
            cls.dut_iface = cls.dut_ifconfig.get_conn_name()
            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()

            # For UDP GSO
            cls.udpgso_bench_downloaded = False

            if cls.dut_fw_card in CARD_FIJI:
                if OpSystem().is_windows():
                    cls.dut_atltool_wrapper_fiji = AtlToolFiji()

            iptables = IPTables(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname)
            iptables.clean()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def run_offload(self, offload, state):
        self.dut_ifconfig.manage_offloads(offload, state)
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()

        curr_speed = self.dut_ifconfig.get_link_speed()
        args = {
            'num_threads': 4,
            'num_process': 1,
            'time': 15,
            'ipv': 4,
            'buffer_len': 65507,
            'window': "1k",
            'lkp': self.lkp_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'speed': curr_speed
        }

        if self.dut_fw_card in CARD_FIJI:
            from tools.usb_control import USBPowerMeterControl
            usb_power_meter_control = USBPowerMeterControl()
            usb_power_meter_control.run_async(self.dut_usb_connect, False, self.dut_port)

        self.run_iperf(**args)

        if self.dut_fw_card in CARD_FIJI:
            time.sleep(15)
            plot = usb_power_meter_control.join(self.dut_usb_connect, self.dut_port)
            if plot is not None:
                shutil.move(plot, self.test_log_dir)

    def get_offload_for_os(self, offload_name):
        assert offload_name in OFFLOADS

        map_ofl = {WIN_OFL: {L4_IP4_CHECKSUM: "*TCPUDPChecksumOffloadIPv4",
                             L4_IP6_CHECKSUM: "*TCPUDPChecksumOffloadIPv6",
                             IP4_CHECKSUM: "*IPChecksumOffloadIPv4",
                             TCP_IP4_CHECKSUM: "*TCPChecksumOffloadIPv4",
                             UDP_IP4_CHECKSUM: "*UDPChecksumOffloadIPv4",
                             TCP_IP6_CHECKSUM: "*TCPChecksumOffloadIPv6",
                             UDP_IP6_CHECKSUM: "*UDPChecksumOffloadIPv6",
                             LSO_V1_IP4: "*LsoV1IPv4",
                             LSO_V2_IP4: "*LsoV2IPv4",
                             LSO_V2_IP6: "*LsoV2IPv6",
                             RECEIVE_SIDE_SCALING: "*RSS",
                             RECV_SEGMENT_COALESCING_IP4: "*RscIPv4",
                             RECV_SEGMENT_COALESCING_IP6: "*RscIPv6"},

                   LINUX_OFL: {TX_CHECKSUM: "tx",
                               RX_CHECKSUM: "rx",
                               LSO: "tso",
                               LRO: "lro",
                               GSO: "gso"},

                   # MAC_OFL: {L4_IP4_CHECKSUM: None,
                             # L4_IP6_CHECKSUM: None,
                             # IP4_CHECKSUM: None,
                             # LSO_V1_IP4: None,
                             # LSO_V2_IP4: None,
                             # LSO_V2_IP6: None}

                   MAC_OFL: {TX_CHECKSUM: "tx",
                             RX_CHECKSUM: "rx",
                             LSO: "tso"},
                   FREEBSD_OFL: {TX_CHECKSUM: "txcsum",
                                 RX_CHECKSUM: "rxcsum",
                                 }
                   }

        return (map_ofl[WIN_OFL][offload_name] if self.dut_ops.is_windows() else \
                map_ofl[LINUX_OFL][offload_name] if self.dut_ops.is_linux() else \
                map_ofl[FREEBSD_OFL][offload_name] if self.dut_ops.is_freebsd() else \
                map_ofl[MAC_OFL][offload_name])


class TestWinOffloads(DrvOffloadsBase):
    # -------------------- Win offloads --------------------
    def setup_method(self, method):
        super(TestWinOffloads, self).setup_method(method)
        if sys.platform != "win32":
            pytest.skip("Windows only test")

    def teardown_method(self, method):
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP6_CHECKSUM), OFFLOADS_STATE_TX_RX)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP6_CHECKSUM), OFFLOADS_STATE_TX_RX)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP6_CHECKSUM), OFFLOADS_STATE_TX_RX)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
        if self.dut_fw_card != CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(RECEIVE_SIDE_SCALING), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(RECV_SEGMENT_COALESCING_IP6), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(RECV_SEGMENT_COALESCING_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)

    def test_receive_side_scaling_disable(self):
        """
        @description: Check disabled Driver receive side scaling.

        @steps:
        1. Disable receive side scaling via driver settings.
        2. Check that value of rss_rxq_en bit in RX Filter RSS Control Register (0x54C0) is equal to 0x0.
        3. Run TCP traffic.

        @result: MAC RSS Control Register has correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            pytest.skip()
        self.run_offload(self.get_offload_for_os(RECEIVE_SIDE_SCALING), OFFLOADS_STATE_DSBL)
        rss_reg = (self.dut_atltool_wrapper.readreg(RSS_REG) & 0x80000000)
        assert rss_reg == 0

    def test_receive_side_scaling_enable(self):
        """
        @description: Check enabled Driver receive side scaling.

        @steps:
        1. Enable receive side scaling via driver settings.
        2. Check that value of rss_rxq_en bit in RX Filter RSS Control Register (0x54C0) is equal to 0x1.
        3. Run TCP traffic.

        @result: MAC RSS Control Register has correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            pytest.skip()
        self.run_offload(self.get_offload_for_os(RECEIVE_SIDE_SCALING), OFFLOADS_STATE_ENBL)
        rss_reg = (self.dut_atltool_wrapper.readreg(RSS_REG) & 0x80000000)
        assert rss_reg == 0x80000000

    def test_recv_segment_coalescing_ip4_disable(self):
        """
        @description: Check disabled RX ipv4 segment coalescing.

        @steps:
        1. Disable RX ipv6 segment coalescing via driver settings.
        2. Disable RX ipv4 segment coalescing via driver settings.
        3. Check that RX Large Receive Offload Control Register (0x5590) is equal to 0x0.
        4. Run TCP traffic.

        @result: RX Large Receive Offload Control Register has correct value.
        @requirements: DRV_OFFLOAD_RSC_2, DRV_OFFLOAD_RSC_4
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            pytest.skip()
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(RECV_SEGMENT_COALESCING_IP6), OFFLOADS_STATE_ENBL)
        self.run_offload(self.get_offload_for_os(RECV_SEGMENT_COALESCING_IP4), OFFLOADS_STATE_DSBL)
        assert self.dut_atltool_wrapper.readreg(LRO_REG) == 0

    def test_recv_segment_coalescing_ip6_disable(self):
        """
        @description: Check disabled RX ipv6 segment coalescing.

        @steps:
        1. Disable RX ipv6 segment coalescing via driver settings.
        2. Disable RX ipv4 segment coalescing via driver settings.
        3. Check that RX Large Receive Offload Control Register (0x5590) is equal to 0x0.
        4. Run TCP traffic.

        @result: RX Large Receive Offload Control Register has correct value.
        @requirements: DRV_OFFLOAD_RSC_2, DRV_OFFLOAD_RSC_4
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            pytest.skip()
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(RECV_SEGMENT_COALESCING_IP4), OFFLOADS_STATE_ENBL)
        self.run_offload(self.get_offload_for_os(RECV_SEGMENT_COALESCING_IP6), OFFLOADS_STATE_DSBL)
        assert self.dut_atltool_wrapper.readreg(LRO_REG) == 0

    def test_recv_segment_coalescing_ip4_ipv6_enable(self):
        """
        @description: Check enabled RX ipv4/ipv6 segment coalescing.

        @steps:
        1. Enable RX ipv6 segment coalescing via driver settings.
        2. Enable RX ipv4 segment coalescing via driver settings.
        3. Check that RX Large Receive Offload Control Register (0x5590) is equal to 0xffffffff.
        4. Run TCP traffic.

        @result: RX Large Receive Offload Control Register has correct value.
        @requirements: DRV_OFFLOAD_RSC_1, DRV_OFFLOAD_RSC_3
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            pytest.skip()
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(RECV_SEGMENT_COALESCING_IP6), OFFLOADS_STATE_ENBL)
        self.run_offload(self.get_offload_for_os(RECV_SEGMENT_COALESCING_IP4), OFFLOADS_STATE_ENBL)
        assert self.dut_atltool_wrapper.readreg(LRO_REG) == 0xffffffff

    def test_tcpudp_ip4_tx(self):
        """
        @description: Check enabled TX TCP/UDP Checksum Offload (IPv4).

        @steps:
        1. Enable Large Send Offload V2 (IPV4) via driver settings.
        2. Enable Large Send Offload V2 (IPV6) via driver settings.
        3. Enable Large Send Offload V1 (IPV4) via driver settings.
        4. Disable TCP/UDP Checksum Offload (IPv6) via driver settings.
        5. Enable TX of TCP/UDP Checksum Offload (IPv4) via driver settings.
        6. Check that value of l4_chk_en bit in RX Protocol Offload Control Register (0x5580) is equal to 0x0.
        7. Check that value of l4_chk_en bit in TX Protocol Offload Control Register (0x7800) is equal to 0x1.
        8. Run TCP traffic.

        @result: RX and TX Protocol Offload Control Registers have correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_TX)
            self.run_offload(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_TX)
            reg = self.dut_atltool_wrapper_fiji.readreg(0x34) & 0x6
            assert reg == 0
            reg = self.dut_atltool_wrapper_fiji.readreg(0x35) & 0x6
            assert reg == 0x6
        else:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_ENBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_TX)
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x1) == 0
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x1) == 0x1

    def test_tcpudp_ip4_rx(self):
        """
        @description: Check enabled RX TCP/UDP Checksum Offload (IPv4).

        @steps:
        1. Disable Large Send Offload V2 (IPV4) via driver settings.
        2. Disable Large Send Offload V2 (IPV6) via driver settings.
        3. Disable Large Send Offload V1 (IPV4) via driver settings.
        4. Disable TCP/UDP Checksum Offload (IPv6) via driver settings.
        5. Enable RX of TCP/UDP Checksum Offload (IPv4) via driver settings.
        6. Check that value of l4_chk_en bit in RX Protocol Offload Control Register (0x5580) is equal to 0x1.
        7. Check that value of l4_chk_en bit in TX Protocol Offload Control Register (0x7800) is equal to 0x0.
        8. Run TCP traffic.

        @result: RX and TX Protocol Offload Control Registers have correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_RX)
            self.run_offload(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_RX)
            reg = self.dut_atltool_wrapper_fiji.readreg(0x34) & 0x6
            assert reg == 0x6
            reg = self.dut_atltool_wrapper_fiji.readreg(0x35) & 0x6
            assert reg == 0
        else:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_RX)
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x1) == 0x1
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x1) == 0

    def test_tcpudp_ip4_rx_tx(self):
        """
        @description: Check enabled RX/TX TCP/UDP Checksum Offload (IPv4).

        @steps:
        1. Enable Large Send Offload V2 (IPV4) via driver settings.
        2. Enable Large Send Offload V2 (IPV6) via driver settings.
        3. Enable Large Send Offload V1 (IPV4) via driver settings.
        4. Disable TCP/UDP Checksum Offload (IPv6) via driver settings.
        5. Enable RX and TX of TCP/UDP Checksum Offload (IPv4) via driver settings.
        6. Check that value of l4_chk_en bit in RX Protocol Offload Control Register (0x5580) is equal to 0x1.
        7. Check that value of l4_chk_en bit in TX Protocol Offload Control Register (0x7800) is equal to 0x1.
        8. Run TCP traffic.

        @result: RX and TX Protocol Offload Control Registers have correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.run_offload(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            reg = self.dut_atltool_wrapper_fiji.readreg(0x34) & 0x6
            assert reg == 0x6
            reg = self.dut_atltool_wrapper_fiji.readreg(0x35) & 0x6
            assert reg == 0x6
        else:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_ENBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x1) == 0x1
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x1) == 0x1

    def test_tcpudp_ip4_ip6_disable(self):
        """
        @description: Check disabled TCP/UDP Checksum Offload (IPv4 and IPv6).

        @steps:
        1. Disable Large Send Offload V2 (IPV4) via driver settings.
        2. Disable Large Send Offload V2 (IPV6) via driver settings.
        3. Disable Large Send Offload V1 (IPV4) via driver settings.
        4. Disable TCP/UDP Checksum Offload (IPv6) via driver settings.
        5. Disable TCP/UDP Checksum Offload (IPv4) via driver settings.
        6. Check that value of l4_chk_en bit in RX Protocol Offload Control Register (0x5580) is equal to 0x0.
        7. Check that value of l4_chk_en bit in TX Protocol Offload Control Register (0x7800) is equal to 0x0.
        8. Run TCP traffic.

        @result: RX and TX Protocol Offload Control Registers have correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            reg = self.dut_atltool_wrapper_fiji.readreg(0x34) & 0x66
            assert reg == 0
            reg = self.dut_atltool_wrapper_fiji.readreg(0x35) & 0x66
            assert reg == 0
        else:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP6_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x1) == 0
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x1) == 0

    def test_tcpudp_ip6_tx(self):
        """
        @description: Check enabled TX TCP/UDP Checksum Offload (IPv6).

        @steps:
        1. Enable Large Send Offload V2 (IPV4) via driver settings.
        2. Enable Large Send Offload V2 (IPV6) via driver settings.
        3. Enable Large Send Offload V1 (IPV4) via driver settings.
        4. Disable TCP/UDP Checksum Offload (IPv4) via driver settings.
        5. Enable TX TCP/UDP Checksum Offload (IPv6) via driver settings.
        6. Check that value of l4_chk_en bit in RX Protocol Offload Control Register (0x5580) is equal to 0x0.
        7. Check that value of l4_chk_en bit in TX Protocol Offload Control Register (0x7800) is equal to 0x1.
        8. Run TCP traffic.

        @result: RX and TX Protocol Offload Control Registers have correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(TCP_IP6_CHECKSUM), OFFLOADS_STATE_TX)
            self.run_offload(self.get_offload_for_os(UDP_IP6_CHECKSUM), OFFLOADS_STATE_TX)
            reg = self.dut_atltool_wrapper_fiji.readreg(0x34) & 0x60
            assert reg == 0
            reg = self.dut_atltool_wrapper_fiji.readreg(0x35) & 0x60
            assert reg == 0x60
        else:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_ENBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(L4_IP6_CHECKSUM), OFFLOADS_STATE_TX)
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x1) == 0x1
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x1) == 0

    def test_tcpudp_ip6_rx(self):
        """
        @description: Check enabled RX TCP/UDP Checksum Offload (IPv6).

        @steps:
        1. Disable Large Send Offload V2 (IPV4) via driver settings.
        2. Disable Large Send Offload V2 (IPV6) via driver settings.
        3. Disable Large Send Offload V1 (IPV4) via driver settings.
        4. Disable TCP/UDP Checksum Offload (IPv4) via driver settings.
        5. Enable RX TCP/UDP Checksum Offload (IPv6) via driver settings.
        6. Check that value of l4_chk_en bit in RX Protocol Offload Control Register (0x5580) is equal to 0x1.
        7. Check that value of l4_chk_en bit in TX Protocol Offload Control Register (0x7800) is equal to 0x0.
        8. Run TCP traffic.

        @result: RX and TX Protocol Offload Control Registers have correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(TCP_IP6_CHECKSUM), OFFLOADS_STATE_RX)
            self.run_offload(self.get_offload_for_os(UDP_IP6_CHECKSUM), OFFLOADS_STATE_RX)
            reg = self.dut_atltool_wrapper_fiji.readreg(0x34) & 0x60
            assert reg == 0x60
            reg = self.dut_atltool_wrapper_fiji.readreg(0x35) & 0x60
            assert reg == 0
        else:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(L4_IP6_CHECKSUM), OFFLOADS_STATE_RX)
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x1) == 0x1
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x1) == 0x0

    def test_tcpudp_ip6_rx_tx(self):
        """
        @description: Check enabled RX/TX TCP/UDP Checksum Offload (IPv6).

        @steps:
        1. Enable Large Send Offload V2 (IPV4) via driver settings.
        2. Enable Large Send Offload V2 (IPV6) via driver settings.
        3. Enable Large Send Offload V1 (IPV4) via driver settings.
        4. Disable TCP/UDP Checksum Offload (IPv4) via driver settings.
        5. Enable RX and TX TCP/UDP Checksum Offload (IPv6) via driver settings.
        6. Check that value of l4_chk_en bit in RX Protocol Offload Control Register (0x5580) is equal to 0x1.
        7. Check that value of l4_chk_en bit in TX Protocol Offload Control Register (0x7800) is equal to 0x1.
        8. Run TCP traffic.

        @result: RX and TX Protocol Offload Control Registers have correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(TCP_IP6_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.run_offload(self.get_offload_for_os(UDP_IP6_CHECKSUM), OFFLOADS_STATE_TX_RX)
            reg = self.dut_atltool_wrapper_fiji.readreg(0x34) & 0x60
            assert reg == 0x60
            reg = self.dut_atltool_wrapper_fiji.readreg(0x35) & 0x60
            assert reg == 0x60
        else:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_ENBL)

            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            self.run_offload(self.get_offload_for_os(L4_IP6_CHECKSUM), OFFLOADS_STATE_TX_RX)
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x1) == 0x1
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x1) == 0x1

    def test_ip4_checksum_rx(self):
        """
        @description: Check enabled RX IPv4 Checksum Offload.

        @steps:
        1. Disable Large Send Offload V2 (IPV4) via driver settings.
        2. Disable Large Send Offload V2 (IPV6) via driver settings.
        3. Disable Large Send Offload V1 (IPV4) via driver settings.
        4. Enable RX/TX TCP/UDP Checksum Offload (IPv4) via driver settings.
        5. Enable RX IPv4 Checksum Offload via driver settings.
        6. Check that value of ipv4_chk_en bit in RX Protocol Offload Control Register (0x5580) is equal to 0x1.
        7. Check that value of ipv4_chk_en bit in TX Protocol Offload Control Register (0x7800) is equal to 0x0.
        8. Run TCP traffic.

        @result: RX and TX Protocol Offload Control Registers have correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.run_offload(self.get_offload_for_os(IP4_CHECKSUM), OFFLOADS_STATE_RX)
            reg = self.dut_atltool_wrapper_fiji.readreg(0x34) & 0x1
            assert reg == 0x1
            reg = self.dut_atltool_wrapper_fiji.readreg(0x35) & 0x1
            assert reg == 0
        else:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.run_offload(self.get_offload_for_os(IP4_CHECKSUM), OFFLOADS_STATE_RX)
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x2) == 0x2
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x2) == 0x0

    def test_ip4_checksum_tx(self):
        """
        @description: Check enabled TX IPv4 Checksum Offload.

        @steps:
        1. Disable Large Send Offload V2 (IPV4) via driver settings.
        2. Disable Large Send Offload V2 (IPV6) via driver settings.
        3. Disable Large Send Offload V1 (IPV4) via driver settings.
        4. Enable RX/TX TCP/UDP Checksum Offload (IPv4) via driver settings.
        5. Enable TX IPv4 Checksum Offload via driver settings.
        6. Check that value of ipv4_chk_en bit in RX Protocol Offload Control Register (0x5580) is equal to 0x0.
        7. Check that value of ipv4_chk_en bit in TX Protocol Offload Control Register (0x7800) is equal to 0x1.
        8. Run TCP traffic.

        @result: RX and TX Protocol Offload Control Registers have correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.run_offload(self.get_offload_for_os(IP4_CHECKSUM), OFFLOADS_STATE_TX)
            reg = self.dut_atltool_wrapper_fiji.readreg(0x34) & 0x1
            assert reg == 0
            reg = self.dut_atltool_wrapper_fiji.readreg(0x35) & 0x1
            assert reg == 0x1
        else:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.run_offload(self.get_offload_for_os(IP4_CHECKSUM), OFFLOADS_STATE_TX)
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x2) == 0x0
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x2) == 0x2

    def test_ip4_checksum_rx_tx(self):
        """
        @description: Check enabled TX/RX IPv4 Checksum Offload.

        @steps:
        1. Disable Large Send Offload V2 (IPV4) via driver settings.
        2. Disable Large Send Offload V2 (IPV6) via driver settings.
        3. Disable Large Send Offload V1 (IPV4) via driver settings.
        4. Enable RX/TX TCP/UDP Checksum Offload (IPv4) via driver settings.
        5. Enable TX and RX IPv4 Checksum Offload via driver settings.
        6. Check that value of ipv4_chk_en bit in RX Protocol Offload Control Register (0x5580) is equal to 0x1.
        7. Check that value of ipv4_chk_en bit in TX Protocol Offload Control Register (0x7800) is equal to 0x1.
        8. Run TCP traffic.

        @result: RX and TX Protocol Offload Control Registers have correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.run_offload(self.get_offload_for_os(IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            reg = self.dut_atltool_wrapper_fiji.readreg(0x34) & 0x1
            assert reg == 0x1
            reg = self.dut_atltool_wrapper_fiji.readreg(0x35) & 0x1
            assert reg == 0x1
        else:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_ENBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.run_offload(self.get_offload_for_os(IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x2) == 0x2
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x2) == 0x2

    def test_ip4_checksum_disable(self):
        """
        @description: Check disabled TX/RX IPv4 Checksum Offload.

        @steps:
        1. Disable Large Send Offload V2 (IPV4) via driver settings.
        2. Disable Large Send Offload V2 (IPV6) via driver settings.
        3. Disable Large Send Offload V1 (IPV4) via driver settings.
        4. Enable RX/TX TCP/UDP Checksum Offload (IPv4) via driver settings.
        5. Disable IPv4 Checksum Offload via driver settings.
        6. Check that value of ipv4_chk_en bit in RX Protocol Offload Control Register (0x5580) is equal to 0x0.
        7. Check that value of ipv4_chk_en bit in TX Protocol Offload Control Register (0x7800) is equal to 0x0.
        8. Run TCP traffic.

        @result: RX and TX Protocol Offload Control Registers have correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TCP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(UDP_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.run_offload(self.get_offload_for_os(IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            reg = self.dut_atltool_wrapper_fiji.readreg(0x34) & 0x1
            assert reg == 0x0
            reg = self.dut_atltool_wrapper_fiji.readreg(0x35) & 0x1
            assert reg == 0x0
        else:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(L4_IP4_CHECKSUM), OFFLOADS_STATE_TX_RX)
            self.run_offload(self.get_offload_for_os(IP4_CHECKSUM), OFFLOADS_STATE_DSBL)
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x2) == 0
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x2) == 0

    def test_lso_v1_v2_ip4_ip6_disable(self):
        """
        @description: Check disabled Large Send Offload V1 and V2 (IPV4 and IPv6).

        @steps:
        1. Disable Large Send Offload V2 (IPV4) via driver settings.
        2. Disable Large Send Offload V2 (IPV6) via driver settings.
        3. Disable Large Send Offload V1 (IPV4) via driver settings.
        4. Check that value TX Large Send Offload Control Register (0x7810) is equal to 0x0.
        5. Run TCP traffic.

        @result: TX Large Send Offload Control Register has correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            pytest.skip()
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
        self.run_offload(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)
        assert self.dut_atltool_wrapper.readreg(LSO_REG) == 0x0

    def test_lso_v1_ip4_enable(self):
        """
        @description: Check enabled Large Send Offload V1 (IPV4).

        @steps:
        1. Disable Large Send Offload V2 (IPV4) via driver settings.
        2. Disable Large Send Offload V2 (IPV6) via driver settings.
        3. Enable Large Send Offload V1 (IPV4) via driver settings.
        4. Check that value TX Large Send Offload Control Register (0x7810) is equal to 0xffffffff.
        5. Run TCP traffic.

        @result: TX Large Send Offload Control Register has correct value.
        @duration: 1 minutes.
        """
        # Issue ATLDRV-733. LSO state in the driver is controlled by the OS network stack.
        # Sometimes it fails when OS did not enables it despite the fact that it enabled it via the
        # driver advanced settings.
        pytest.xfail()
        if self.dut_fw_card in CARD_FIJI:
            pytest.skip()
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
        self.run_offload(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_ENBL)
        assert self.dut_atltool_wrapper.readreg(LSO_REG) == 0xffffffff

    def test_lso_v2_ip4_enable(self):
        """
        @description: Check enabled Large Send Offload V2 (IPV4).

        @steps:
        1. Enable Large Send Offload V2 (IPV4) via driver settings.
        2. Disable Large Send Offload V2 (IPV6) via driver settings.
        3. Disable Large Send Offload V1 (IPV4) via driver settings.
        4. Check that value TX Large Send Offload Control Register (0x7810) is equal to 0xffffffff.
        5. Run TCP traffic.

        @result: TX Large Send Offload Control Register has correct value.
        @duration: 1 minutes.
        """
        # Issue ATLDRV-733. LSO state in the driver is controlled by the OS network stack.
        # Sometimes it fails when OS did not enables it despite the fact that it enabled it via the
        # driver advanced settings.
        pytest.xfail()
        if self.dut_fw_card in CARD_FIJI:
            pytest.skip()
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_DSBL)
        self.run_offload(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_ENBL)
        assert self.dut_atltool_wrapper.readreg(LSO_REG) == 0xffffffff

    def test_lso_v2_ip6_enable(self):
        """
        @description: Check enabled Large Send Offload V2 (IPV6).

        @steps:
        1. Disable Large Send Offload V2 (IPV4) via driver settings.
        2. Enable Large Send Offload V2 (IPV6) via driver settings.
        3. Disable Large Send Offload V1 (IPV4) via driver settings.
        4. Check that value TX Large Send Offload Control Register (0x7810) is equal to 0xffffffff.
        5. Run TCP traffic.

        @result: TX Large Send Offload Control Register has correct value.
        @duration: 1 minutes.
        """
        if self.dut_fw_card in CARD_FIJI:
            pytest.skip()
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V1_IP4), OFFLOADS_STATE_DSBL)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO_V2_IP4), OFFLOADS_STATE_DSBL)
        self.run_offload(self.get_offload_for_os(LSO_V2_IP6), OFFLOADS_STATE_ENBL)
        assert self.dut_atltool_wrapper.readreg(LSO_REG) == 0xffffffff


class TestLinuxOffloads(DrvOffloadsBase):
    # -------------------- Linux offloads --------------------
    def setup_method(self, method):
        super(TestLinuxOffloads, self).setup_method(method)
        if sys.platform == "win32":
            pytest.skip("Does not run on windows")

    def teardown_method(self, method):
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(RX_CHECKSUM), OFFLOADS_STATE_OFF)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TX_CHECKSUM), OFFLOADS_STATE_OFF)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LSO), OFFLOADS_STATE_OFF)
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(GSO), OFFLOADS_STATE_OFF)
        self.dut_ifconfig.manage_offloads(RX_VLAN, OFFLOADS_STATE_ON)
        self.dut_ifconfig.manage_offloads(TX_VLAN, OFFLOADS_STATE_ON)
        if self.dut_fw_card != CARD_FIJI:
            self.dut_ifconfig.manage_offloads(self.get_offload_for_os(LRO), OFFLOADS_STATE_ON)

    def test_tx_checksumming_on(self):
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(RX_CHECKSUM), OFFLOADS_STATE_OFF)
        self.run_offload(self.get_offload_for_os(TX_CHECKSUM), OFFLOADS_STATE_ON)
        if self.dut_fw_card not in CARD_FIJI:
            if "forwarding" not in self.dut_drv_version:
                assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x3) == 0x0
            else:
                assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x3) == 0x3
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x3) == 0x3

    def test_tx_checksumming_off(self):
        if self.dut_ops.is_mac():
            pytest.skip("Skip test for MAC because offloads are always on")

        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(RX_CHECKSUM), OFFLOADS_STATE_OFF)
        self.run_offload(self.get_offload_for_os(TX_CHECKSUM), OFFLOADS_STATE_OFF)
        if self.dut_fw_card not in CARD_FIJI:
            if "forwarding" not in self.dut_drv_version:
                assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x3) == 0x0
            else:
                assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x3) == 0x3
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x3) == 0x3

    def test_rx_checksumming_on(self):
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TX_CHECKSUM), OFFLOADS_STATE_OFF)
        self.run_offload(self.get_offload_for_os(RX_CHECKSUM), OFFLOADS_STATE_ON)
        if self.dut_fw_card not in CARD_FIJI:
            if "forwarding" not in self.dut_drv_version:
                assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x3) == 0x3
            else:
                assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x3) == 0x3
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x3) == 0x3

    def test_rx_checksumming_off(self):
        if self.dut_ops.is_mac():
            pytest.skip("Skip test for MAC because offloads are always on")

        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TX_CHECKSUM), OFFLOADS_STATE_OFF)
        self.run_offload(self.get_offload_for_os(RX_CHECKSUM), OFFLOADS_STATE_OFF)
        if self.dut_fw_card not in CARD_FIJI:
            if "forwarding" not in self.dut_drv_version:
                assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x3) == 0x0
            else:
                assert (self.dut_atltool_wrapper.readreg(CHK_SUM_RX_REG) & 0x3) == 0x3
            assert (self.dut_atltool_wrapper.readreg(CHK_SUM_TX_REG) & 0x3) == 0x3

    def test_lso_on(self):
        if "freebsd" in sys.platform:
            pytest.skip("Does not run on freebsd")
        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TX_CHECKSUM), OFFLOADS_STATE_ON)

        self.run_offload(self.get_offload_for_os(LSO), OFFLOADS_STATE_ON)
        if self.dut_fw_card not in CARD_FIJI and "forwarding" not in self.dut_drv_version:
            lso_reg = self.dut_atltool_wrapper.readreg(LSO_REG)
            assert lso_reg == 0xffffffff
        elif "forwarding" in self.dut_drv_version:
            lso_reg = self.dut_atltool_wrapper.readreg(LSO_REG)
            combined = []
            re_cnt = re.compile("Combined:\\t*([0-9]+)")
            cmd = Command(cmd='sudo ethtool -l {}'.format(self.dut_iface)).run()
            if cmd["returncode"] != 0:
                raise Exception("Failed to show channels")
            for line in cmd["output"]:
                m = re_cnt.match(line)
                if m is not None:
                    combined.append(int(m.group(1)))
            if combined == []:
                raise Exception("Failed to show channels")
            else:
                for i in range(min(combined)): assert(lso_reg & (1 << i) != 0)

    def test_lso_off(self):
        if "freebsd" in sys.platform:
            pytest.skip("Does not run on freebsd")
        if self.dut_ops.is_mac():
            pytest.skip("Skip test for MAC because offloads are always on")

        self.dut_ifconfig.manage_offloads(self.get_offload_for_os(TX_CHECKSUM), OFFLOADS_STATE_OFF)
        self.run_offload(self.get_offload_for_os(LSO), OFFLOADS_STATE_OFF)
        if self.dut_fw_card not in CARD_FIJI and "forwarding" not in self.dut_drv_version:
            lso_reg = self.dut_atltool_wrapper.readreg(LSO_REG)
            assert lso_reg == 0xffffffff
        elif "forwarding" in self.dut_drv_version:
            lso_reg = self.dut_atltool_wrapper.readreg(LSO_REG)
            combined = []
            re_cnt = re.compile("Combined:\\t*([0-9]+)")
            cmd = Command(cmd='sudo ethtool -l {}'.format(self.dut_iface)).run()
            if cmd["returncode"] != 0:
                raise Exception("Failed to show channels")
            for line in cmd["output"]:
                m = re_cnt.match(line)
                if m is not None:
                    combined.append(int(m.group(1)))
            if combined == []:
                raise Exception("Failed to show channels")
            else:
                for i in range(min(combined)): assert (lso_reg & (1 << i) != 0)

    def test_lro_on(self):
        """
        @description: Check lro offload.

        @steps:
        1. Enable LRO offload.
        2. Check that LRO offload is enabled(in 0x5590 register the value is 0xffffffff).
        3. Send three packages.
        4. Dump the traffic and check that the packages are coalesced.

        @result: LRO offload is enabled and packages are coalesced.
        @duration: 60 seconds.
        @requirements: DRV_OFFLOAD_LRO_1, DRV_OFFLOAD_LRO_3
        """
        if "freebsd" in sys.platform:
            pytest.skip("Does not run on freebsd")
        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Not implemented for Fiji")
        self.run_offload(self.get_offload_for_os(LRO), OFFLOADS_STATE_ON)
        lro_reg = self.dut_atltool_wrapper.readreg(LRO_REG)
        pac = 2000 * "f"
        p1 = Ether(dst=self.dut_mac, src=self.lkp_mac) / IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR,
                                                            flags=None) / \
             TCP(dport=5505, sport=3601, seq=0, flags=None) / Raw(load=pac.decode("hex"))
        p2 = Ether(dst=self.dut_mac, src=self.lkp_mac) / IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR,
                                                            flags=None) / \
             TCP(dport=5505, sport=3601, seq=1000, flags=None) / Raw(load=pac.decode("hex"))
        p3 = Ether(dst=self.dut_mac, src=self.lkp_mac) / IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR,
                                                            flags=None) / \
             TCP(dport=5505, sport=3601, seq=2000, flags=None) / Raw(load=pac.decode("hex"))
        aqsendp_pkt_1 = scapy_pkt_to_aqsendp_str(p1)
        aqsendp_pkt_2 = scapy_pkt_to_aqsendp_str(p2)
        aqsendp_pkt_3 = scapy_pkt_to_aqsendp_str(p3)
        pkts = [aqsendp_pkt_1, aqsendp_pkt_2, aqsendp_pkt_3]
        aqsendp = Aqsendp(count=3, host=self.lkp_hostname, packet=pkts)
        sniffer = Tcpdump(port=self.dut_port, timeout=5)
        sniffer.run_async()
        aqsendp.run()
        sniffed = sniffer.join(10)
        count = 0
        for pkt in sniffed:
            if pkt.haslayer("IP") and pkt["IP"].src == self.LKP_IPV4_ADDR and pkt["IP"].dst == self.DUT_IPV4_ADDR:
                count += 1
        assert count == 1, "Packets are not coalesced"

        if "forwarding" not in self.dut_drv_version:
            assert lro_reg == 0xffffffff
        elif "forwarding" in self.dut_drv_version:
            conn_name = self.dut_ifconfig.get_conn_name()
            combined = []
            re_cnt = re.compile("Combined:\\t*([0-9]+)")
            cmd = Command(cmd='sudo ethtool -l {}'.format(conn_name)).run()
            if cmd["returncode"] != 0:
                raise Exception("Failed to show channels")
            for line in cmd["output"]:
                m = re_cnt.match(line)
                if m is not None:
                    combined.append(int(m.group(1)))
            if combined == []:
                raise Exception("Failed to show channels")
            else:
                for i in range(min(combined)): assert (lro_reg & (1 << i) != 0)

    def test_workaround_lro_with_chsum_error(self):
        """
        @description: Check lro offload.

        @steps:
        1. Send three packages(in the third package corrupted check sum).
        2. Dump the traffic and check that dropped all LRO session.

        @result: Dropped all LRO session.
        @duration: 40 seconds.
        @requirements: DRV_OFFLOAD_LRO_4
        """
        if "freebsd" in sys.platform:
            pytest.skip("Does not run on freebsd")
        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Not implemented for Fiji")
        pac = 2000 * "f"
        p1 = Ether(dst=self.dut_mac, src=self.lkp_mac) / IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR,
                                                            flags=None) / \
             TCP(dport=5505, sport=3601, seq=0, flags=None) / Raw(load=pac.decode("hex"))
        p2 = Ether(dst=self.dut_mac, src=self.lkp_mac) / IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR,
                                                            flags=None) / \
             TCP(dport=5505, sport=3601, seq=1000, flags=None) / Raw(load=pac.decode("hex"))
        p3 = Ether(dst=self.dut_mac, src=self.lkp_mac) / IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR,
                                                            flags=None) / \
             TCP(dport=5505, sport=3601, seq=2000, flags=None, chksum=0xffff) / Raw(load=pac.decode("hex"))
        aqsendp_pkt_1 = scapy_pkt_to_aqsendp_str(p1)
        aqsendp_pkt_2 = scapy_pkt_to_aqsendp_str(p2)
        aqsendp_pkt_3 = scapy_pkt_to_aqsendp_str(p3)
        pkts = [aqsendp_pkt_1, aqsendp_pkt_2, aqsendp_pkt_3]
        aqsendp = Aqsendp(count=3, host=self.lkp_hostname, packet=pkts)
        sniffer = Tcpdump(port=self.dut_port, timeout=5)
        sniffer.run_async()
        aqsendp.run()
        sniffed = sniffer.join(10)
        for pkt in sniffed:
            if pkt.haslayer("IP") and pkt["IP"].src == self.LKP_IPV4_ADDR and pkt["IP"].dst == self.DUT_IPV4_ADDR:
                assert (len(pkt) - 54) < 3000, "Packets are coalesced"  # 54 header

    def test_lro_off(self):
        if "freebsd" in sys.platform:
            pytest.skip("Does not run on freebsd")
        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Not implemented for Fiji")
        self.run_offload(self.get_offload_for_os(LRO), OFFLOADS_STATE_OFF)
        lro_reg = self.dut_atltool_wrapper.readreg(LRO_REG)
        assert lro_reg == 0

    def test_gso_on(self):
        if "freebsd" in sys.platform:
            pytest.skip("Does not run on freebsd")
        if OpSystem().is_mac() and self.dut_fw_card == CARD_FIJI:
            pytest.skip("Not implemented for Fiji")
        self.run_offload(self.get_offload_for_os(GSO), OFFLOADS_STATE_ON)

    def test_gso_off(self):
        if "freebsd" in sys.platform:
            pytest.skip("Does not run on freebsd")
        if OpSystem().is_mac() and self.dut_fw_card == CARD_FIJI:
            pytest.skip("Not implemented for Fiji")
        self.run_offload(self.get_offload_for_os(GSO), OFFLOADS_STATE_OFF)

    def is_kernel_ver_more_4_18(self):
        res = Command(cmd='uname -r', host=self.dut_hostname).run()
        mj, mn = re.match(r'(\d+).(\d+).*', res["output"][0]).groups()
        return int(mj) > 4 or (int(mj) == 4 and int(mn) >= 18)

    @classmethod
    def dowload_udpgso_bench(cls):
        if not cls.udpgso_bench_downloaded:
            res = Command(cmd='scp aqtest@{}:/storage/export/tools/linux/udpgso_bench_tx .'.format(NFS_SERVER)).run()
            assert res['returncode'] == 0, 'Download udpgso_bench_tx failed'
            cls.udpgso_bench_downloaded = True

    def run_bench(self, buff_size, gso_size, timeout=None, messages=None):
        if timeout is None and messages is None:
            raise Exception("timeout or messages is required")

        if timeout is not None:
            timeou_cmd = 'timeout --preserve-status -s SIGINT {} '.format(timeout)
        else:
            timeou_cmd = ''

        if messages is not None:
            msg_cmd = '-M {} '.format(messages)
        else:
            msg_cmd = ''

        bench_cmd = 'cd qa-tests && sudo {}./udpgso_bench_tx -4 {}-D {} -u -s {} -S {} -a'.format(
            timeou_cmd, msg_cmd, self.LKP_IPV4_ADDR, buff_size, gso_size)

        res = Command(cmd=bench_cmd, host=self.dut_hostname).run()
        for line in res['output']:
            m = re.match('sum udp tx:\s+(\d+)\s.+', line)
            if m is not None:
                return int(m.group(1))
        return None

    @idparametrize("mtu", [MTU_1500, MTU_2000, MTU_4000, MTU_9000, MTU_16000])
    def test_udp_gso_size(self, mtu):
        if "freebsd" in sys.platform:
            pytest.skip("Does not run on freebsd")
        if not self.is_kernel_ver_more_4_18():
            pytest.skip('Minimum required kernel version 4.18')
        self.dowload_udpgso_bench()

        gso_size = mtu - 100
        buff_size = 65507
        offload = 'tx-udp-segmentation'

        sniffer = Tcpdump(host=self.lkp_hostname, port=self.lkp_port, timeout=10)

        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu)
        self.dut_ifconfig.wait_link_up()

        sniffer.run_async()

        self.dut_ifconfig.manage_offloads(offload, OFFLOADS_STATE_ON)
        self.run_bench(buff_size, gso_size, messages=10)

        packets = sniffer.join(10)

        wrpcap('packets.pcap', packets)
        shutil.move('packets.pcap', self.test_log_dir)

        for p in packets:
            if IP in p and p[IP].src == self.DUT_IPV4_ADDR and p[IP].dst == self.LKP_IPV4_ADDR:
                log.info('packet payload size: {}'.format(len(p[Raw])))
                if len(p[Raw]) > gso_size:
                    raise Exception('Wrong packet seize: {}, expected: {}'.format(len(p[Raw]), gso_size))

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    @idparametrize("mtu", [MTU_1500, MTU_2000, MTU_4000, MTU_9000, MTU_16000])
    def test_udp_gso_rate(self, speed, mtu):
        if "freebsd" in sys.platform:
            pytest.skip("Does not run on freebsd")
        if speed not in self.supported_speeds:
            pytest.skip()

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()

        if not self.is_kernel_ver_more_4_18():
            pytest.skip('Minimum required kernel version 4.18')
        self.dowload_udpgso_bench()

        gso_size = mtu - 100
        buff_size = 65507
        offload = 'tx-udp-segmentation'

        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu)
        self.dut_ifconfig.wait_link_up()

        self.dut_ifconfig.manage_offloads(offload, OFFLOADS_STATE_ON)
        enabele_rate = self.run_bench(buff_size, gso_size, timeout=5)

        self.dut_ifconfig.manage_offloads(offload, OFFLOADS_STATE_OFF)
        disable_rate = self.run_bench(buff_size, gso_size, timeout=5)

        assert enabele_rate >= disable_rate
        log.info('Enabele_rate: {} > Disable_rate: {}'.format(enabele_rate, disable_rate))

    def test_udp_gso_stress(self):
        if "freebsd" in sys.platform:
            pytest.skip("Does not run on freebsd")
        if not self.is_kernel_ver_more_4_18():
            pytest.skip('Minimum required kernel version 4.18')
        self.dowload_udpgso_bench()

        mtu = MTU_1500
        gso_size = mtu - 100
        buff_size = 65507

        speed = self.supported_speeds[-1]
        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)

        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu)
        self.dut_ifconfig.wait_link_up()

        stress_cmd = 'stress --cpu $(nproc) --io 4 --vm 4 --vm-bytes 1024M --timeout 10s'
        stress_th = Command(cmd=stress_cmd, host=self.dut_hostname)
        trace = Tracepoint(timeout=10, direction=DIRECTION_RX, name="atlantic", host=self.lkp_hostname)
        trace.run_async()
        stress_th.run_async()

        time.sleep(3)
        self.run_bench(buff_size, gso_size, messages=100)
        time.sleep(3)

        stress_th.join()
        descr = trace.join()

        err_count = 0
        for d in descr:
            if d['direction'] == 'rx':
                if d['rx_stat'] & 0x4 != 0:
                    # RX_STAT (Receive Status)
                    # Bit 2: TCP/UDP Checksum Error
                    log.info('rx_stat: {}'.format(d['rx_stat']))
                    err_count += 1

        assert err_count == 0

    def run_vlan_offload(self, offload, direction):
        if not (self.dut_ops.is_linux() and self.lkp_ops.is_linux()):
            pytest.skip()

        self.dut_ifconfig.delete_vlan_ifaces()
        self.lkp_ifconfig.delete_vlan_ifaces()

        vlan_id = 10
        speed = self.supported_speeds[-1]
        dut_ip = self.suggest_test_ip_address(str(RandString(10)))
        lkp_ip = self.suggest_test_ip_address(str(RandString(10)))
        netmask = self.DEFAULT_NETMASK_IPV4

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.create_vlan_iface(vlan_id)
        self.lkp_ifconfig.create_vlan_iface(vlan_id)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.dut_ifconfig.set_ip_address(dut_ip, netmask, gateway=None, vlan_id=vlan_id)
        self.lkp_ifconfig.set_ip_address(lkp_ip, netmask, gateway=None, vlan_id=vlan_id)
        speed = self.dut_ifconfig.wait_link_up(vlan_id=vlan_id)

        args = {
            'direction': direction,
            'speed': speed,
            'bandwidth': SPEED_TO_MBITS[speed],
            'num_threads': 1,
            'num_process': 1,
            'time': 27,
            'ipv': 4,
            'buffer_len': 0,
            'is_udp': True,
            'is_eee': False,
            'is_stat': False,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': lkp_ip,
            'dut4': dut_ip,
        }

        self.dut_ifconfig.manage_offloads(offload, OFFLOADS_STATE_ON)
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        self.run_iperf(**args)

        self.dut_ifconfig.manage_offloads(offload, OFFLOADS_STATE_OFF)
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        self.run_iperf(**args)

    def test_rx_vlan(self):
        self.run_vlan_offload(RX_VLAN, DIRECTION_RX)

    def test_tx_vlan(self):
        self.run_vlan_offload(TX_VLAN, DIRECTION_TX)

    def test_rx_vlan_filter(self):
        """
        @description: This subtest checks work of rx-vlan-filter offload

        @steps:
        1. Create VLan with vlan_id on DUT and LKP
        2. Enable rx-vlan-filter offload on DUT
        3. Check different test cases
            a. Offload enabled, send packets with Dot1Q].vlan == vlan_id, all packets recived
            b. Offload enabled, send packets with Dot1Q].vlan != vlan_id, all packets discarded
            c. Offload disabled, send packets with Dot1Q].vlan != vlan_id, all packets recived
            d. Offload enabled, send packets with Dot1Q].vlan != vlan_id, all packets discarded
            e. Offload enabled, send packets with Dot1Q].vlan == vlan_id, all packets recived

        @result: All checks passed
        @duration: 5 minutes.
        """

        if not (self.dut_ops.is_linux() and self.lkp_ops.is_linux()):
            pytest.skip()

        self.dut_ifconfig.delete_vlan_ifaces()
        self.lkp_ifconfig.delete_vlan_ifaces()

        vlan_id = 10
        speed = self.supported_speeds[-1]
        dut_ip = self.suggest_test_ip_address(str(RandString(10)))
        lkp_ip = self.suggest_test_ip_address(str(RandString(10)))
        netmask = self.DEFAULT_NETMASK_IPV4

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.create_vlan_iface(vlan_id)
        self.lkp_ifconfig.create_vlan_iface(vlan_id)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.dut_ifconfig.set_ip_address(dut_ip, netmask, gateway=None, vlan_id=vlan_id)
        self.lkp_ifconfig.set_ip_address(lkp_ip, netmask, gateway=None, vlan_id=vlan_id)
        self.dut_ifconfig.wait_link_up(vlan_id=vlan_id)

        test_cases = [
            (OFFLOADS_STATE_ON, 10, 10),
            (OFFLOADS_STATE_ON, 1, 0),
            (OFFLOADS_STATE_OFF, 1, 10),
        ]
        for case in test_cases:
            off_state, pkt_vlan_id, exp_count = case
            self.dut_ifconfig.manage_offloads(RX_VLAN_FILTER, off_state)
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.dut_ifconfig.wait_link_up()

            pkt = Ether(dst=self.dut_mac) / Dot1Q(vlan=pkt_vlan_id)
            pkt /= IP(src=lkp_ip, dst=dut_ip) / ICMP() / "Hello World"
            pkt_count, pkt_rate = 10, 100

            lkp_aqsendp = Aqsendp(
                packet=pkt, count=pkt_count, rate=pkt_rate,
                host=self.lkp_hostname, iface=self.lkp_iface
            )

            sniffer = Tcpdump(host=self.dut_hostname, port=self.dut_port, timeout=40, nopromisc=True)
            sniffer.run_async()
            time.sleep(30)

            lkp_aqsendp.run()

            dut_packets = sniffer.join(10)

            count = 0
            for p in dut_packets:
                if Dot1Q in p and p[Dot1Q].vlan == pkt_vlan_id and IP in p and p[IP].dst == dut_ip:
                    log.info('pkt_vlan_id: {} {}'.format(p[Dot1Q].vlan, p.summary()))
                    count += 1
            msg = 'Test case: rx-vlan-filter: {}, vlan_id: {}, pkt_vlan_id: {}, exp_count: {}, ' \
                  'actual_count: {}'.format(off_state, vlan_id, pkt_vlan_id, exp_count, count)
            assert exp_count == count, msg + ' FAILED'
            log.info(msg + ' PASSED')


class TestRxTxL4ChecksumOffloadWorkaround(DrvOffloadsBase):
    """
    @description: The TestRxTxL4ChecksumOffloadWorkaround verifies that the driver implements workaround for
    hardware bug in L4 checksum offload engine when the hardware calculates L4 checksum using padding also.

    @setup: Two Aquantia devices connected back to back.
    """

    @classmethod
    def setup_class(cls):
        super(TestRxTxL4ChecksumOffloadWorkaround, cls).setup_class()

        try:
            cls.dut_scapy_tool = ScapyTools(port=cls.dut_port)
            cls.lkp_scapy_tool = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.dut_scapy_iface = cls.dut_scapy_tool.get_scapy_iface()
            cls.lkp_scapy_iface = cls.lkp_scapy_tool.get_scapy_iface()
            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def run_udp_checksum_offload_workaround_test(self, direction, pkt_size, ipv):
        if ipv == 6:
            dut_ip = self.DUT_IPV6_ADDR
            lkp_ip = self.LKP_IPV6_ADDR
        else:
            dut_ip = self.DUT_IPV4_ADDR
            lkp_ip = self.LKP_IPV4_ADDR
        udp_port = 777
        server_file = "tmp.py"
        fail_msg = "Received good packet"
        pass_msg = "Received faulty packet"
        server_code = """
from socket import *
def server():
    host = '{}'
    port = {}
    addr = (host, port)
    udp_socket = socket(AF_INET{}, SOCK_DGRAM)
    udp_socket.bind(addr)
    data, addr = udp_socket.recvfrom(1024)
    if data[-1] == 'b':
        print '{}'
    else:
        print '{}'
    udp_socket.close()
server()
        """.format(dut_ip if direction == DIRECTION_RX else lkp_ip,
                   udp_port, "6" if ipv == 6 else "", fail_msg, pass_msg)

        with open(server_file, "w") as f:
            f.write(server_code)
        if direction == DIRECTION_TX:
            upload_file(self.lkp_hostname, server_file, server_file)

        server_cmd = Command(cmd="sudo python {}".format(server_file),
                             host=self.lkp_hostname if direction == DIRECTION_TX else None)
        server_cmd.run_async()

        time.sleep(3)

        if direction == DIRECTION_RX:
            src_mac = self.lkp_mac
            dst_mac = self.dut_mac
            src_ip = lkp_ip
            dst_ip = dut_ip
        else:
            src_mac = self.dut_mac
            dst_mac = self.lkp_mac
            src_ip = dut_ip
            dst_ip = lkp_ip

        pkt = Ether(dst=dst_mac, src=src_mac)
        if ipv == 6:
            pkt /= IPv6(dst=dst_ip, src=src_ip)
        else:
            pkt /= IP(dst=dst_ip, src=src_ip)
        pkt /= UDP(sport=udp_port, dport=udp_port)
        payload = "a" * (pkt_size - 14 - 20 - 8)
        good_pkt = pkt / Raw(payload + "b")  # good packet is be used to close server if faulty packet was not received
        faulty_pkt = pkt / Raw(payload[:-1])  # create packet with payload - 1 length
        faulty_pkt = faulty_pkt.__class__(str(faulty_pkt))  # calculate checksum
        faulty_pkt[UDP].remove_payload()  # remove short payload
        faulty_pkt /= Raw(payload)  # add payload, one byte is padding, but checksum and length will not be changed

        # Send good packet afterwards to make sure that server socket is closed
        # even if previous packet was not captured
        if direction == DIRECTION_RX:
            self.lkp_scapy_tool.send_packet(faulty_pkt, iface=self.lkp_scapy_iface)
            self.lkp_scapy_tool.send_packet(good_pkt, iface=self.lkp_scapy_iface)
        else:
            self.dut_scapy_tool.send_packet(faulty_pkt, iface=self.dut_scapy_iface)
            self.dut_scapy_tool.send_packet(good_pkt, iface=self.dut_scapy_iface)

        res = server_cmd.join(1)
        assert any("Received faulty packet" in line for line in res["output"]),\
            "Faulty packet was not received, i.e. it was dropped by kernel => workaround doesn't work"

    def run_tcp_checksum_offload_workaround_test(self, direction, pkt_size, ipv):
        if ipv == 6:
            dut_ip = self.DUT_IPV6_ADDR
            lkp_ip = self.LKP_IPV6_ADDR
        else:
            dut_ip = self.DUT_IPV4_ADDR
            lkp_ip = self.LKP_IPV4_ADDR
        tcp_port = 777

        if direction == DIRECTION_RX:
            sniffer = Tcpdump(port=self.dut_port, timeout=10, file="cap.pcap")
        else:
            sniffer = Tcpdump(port=self.lkp_port, host=self.lkp_hostname, timeout=10, file="cap.pcap")
        sniffer.run_async()

        if direction == DIRECTION_RX:
            src_mac = self.lkp_mac
            dst_mac = self.dut_mac
            src_ip = lkp_ip
            dst_ip = dut_ip
        else:
            src_mac = self.dut_mac
            dst_mac = self.lkp_mac
            src_ip = dut_ip
            dst_ip = lkp_ip

        pkt = Ether(dst=dst_mac, src=src_mac)
        if ipv == 6:
            pkt /= IPv6(dst=dst_ip, src=src_ip)
        else:
            pkt /= IP(dst=dst_ip, src=src_ip)
        pkt /= TCP(sport=tcp_port, dport=tcp_port, seq=10, ack=10, flags="S")
        payload = "a" * (pkt_size - 14 - 20 - 20)
        faulty_pkt = pkt / Raw(payload[:-1])
        faulty_pkt = faulty_pkt.__class__(str(faulty_pkt))  # calculate checksum
        faulty_pkt[TCP].remove_payload()  # remove short payload
        faulty_pkt /= Raw(payload)  # add payload, one byte is padding

        if direction == DIRECTION_RX:
            self.lkp_scapy_tool.send_packet(faulty_pkt, iface=self.lkp_scapy_iface)
        else:
            self.dut_scapy_tool.send_packet(faulty_pkt, iface=self.dut_scapy_iface)

        packets = sniffer.join()
        for p in packets:
            if direction == DIRECTION_RX:
                if p.haslayer(TCP):
                    if p[Ether].src.lower() == self.dut_mac.lower() and p[TCP].flags == 0x14:  # RST and ACK
                        break
            else:
                if p.haslayer(TCP):
                    if p[Ether].src.lower() == self.dut_mac.lower() and p[TCP].flags == 0x2 and \
                            p[TCP].chksum == faulty_pkt[TCP].chksum:  # original SYN
                        break
        else:
            raise Exception("Faulty packet was not received, i.e. it was dropped by kernel => workaround doesn't work")

    def test_udp_rx_checksum_offload_workaround_small_pkt_ipv4(self):
        """
        @description: Check that driver has L4 RX checksum offload workaround for invalid small UDP over IPv4 packet.

        @steps:
        1. Using system sockets create UDP server/client connection on DUT and LKP.
        2. From LKP send small UDP over IPv4 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on DUT.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_udp_checksum_offload_workaround_test(DIRECTION_RX, 60, 4)

    def test_udp_rx_checksum_offload_workaround_big_pkt_ipv4(self):
        """
        @description: Check that driver has L4 RX checksum offload workaround for invalid big UDP over IPv4 packet.

        @steps:
        1. Using system sockets create UDP server/client connection on DUT and LKP.
        2. From LKP send big UDP over IPv4 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on DUT.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_udp_checksum_offload_workaround_test(DIRECTION_RX, 500, 4)

    def test_udp_tx_checksum_offload_workaround_small_pkt_ipv4(self):
        """
        @description: Check that driver has L4 TX checksum offload workaround for invalid small UDP over IPv4 packet.

        @steps:
        1. Using system sockets create UDP server/client connection on DUT and LKP.
        2. From DUT send small UDP over IPv4 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on LKP.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_udp_checksum_offload_workaround_test(DIRECTION_TX, 60, 4)

    def test_udp_tx_checksum_offload_workaround_big_pkt_ipv4(self):
        """
        @description: Check that driver has L4 TX checksum offload workaround for invalid big UDP over IPv4 packet.

        @steps:
        1. Using system sockets create UDP server/client connection on DUT and LKP.
        2. From DUT send big UDP over IPv4 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on LKP.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_udp_checksum_offload_workaround_test(DIRECTION_TX, 500, 4)

    def test_tcp_rx_checksum_offload_workaround_small_pkt_ipv4(self):
        """
        @description: Check that driver has L4 RX checksum offload workaround for invalid small TCP over IPv4 packet.

        @steps:
        1. Using system sockets create TCP server/client connection on DUT and LKP.
        2. From LKP send small TCP over IPv4 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on DUT.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_tcp_checksum_offload_workaround_test(DIRECTION_RX, 60, 4)

    def test_tcp_rx_checksum_offload_workaround_big_pkt_ipv4(self):
        """
        @description: Check that driver has L4 RX checksum offload workaround for invalid big TCP over IPv4 packet.

        @steps:
        1. Using system sockets create TCP server/client connection on DUT and LKP.
        2. From LKP send big TCP over IPv4 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on DUT.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_tcp_checksum_offload_workaround_test(DIRECTION_RX, 500, 4)

    def test_tcp_tx_checksum_offload_workaround_small_pkt_ipv4(self):
        """
        @description: Check that driver has L4 TX checksum offload workaround for invalid small TCP over IPv4 packet.

        @steps:
        1. Using system sockets create TCP server/client connection on DUT and LKP.
        2. From DUT send small TCP over IPv4 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on LKP.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_tcp_checksum_offload_workaround_test(DIRECTION_TX, 60, 4)

    def test_tcp_tx_checksum_offload_workaround_big_pkt_ipv4(self):
        """
        @description: Check that driver has L4 TX checksum offload workaround for invalid big TCP over IPv4 packet.

        @steps:
        1. Using system sockets create TCP server/client connection on DUT and LKP.
        2. From DUT send big TCP over IPv4 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on LKP.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_tcp_checksum_offload_workaround_test(DIRECTION_TX, 500, 4)

    def test_udp_rx_checksum_offload_workaround_small_pkt_ipv6(self):
        """
        @description: Check that driver has L4 RX checksum offload workaround for invalid small UDP over IPv6 packet.

        @steps:
        1. Using system sockets create UDP server/client connection on DUT and LKP.
        2. From LKP send small UDP over IPv6 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on DUT.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_udp_checksum_offload_workaround_test(DIRECTION_RX, 60, 6)

    def test_udp_rx_checksum_offload_workaround_big_pkt_ipv6(self):
        """
        @description: Check that driver has L4 RX checksum offload workaround for invalid big UDP over IPv6 packet.

        @steps:
        1. Using system sockets create UDP server/client connection on DUT and LKP.
        2. From LKP send big UDP over IPv6 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on DUT.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_udp_checksum_offload_workaround_test(DIRECTION_RX, 500, 6)

    def test_udp_tx_checksum_offload_workaround_small_pkt_ipv6(self):
        """
        @description: Check that driver has L4 TX checksum offload workaround for invalid small UDP over IPv6 packet.

        @steps:
        1. Using system sockets create UDP server/client connection on DUT and LKP.
        2. From DUT send small UDP over IPv6 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on LKP.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_udp_checksum_offload_workaround_test(DIRECTION_TX, 60, 6)

    def test_udp_tx_checksum_offload_workaround_big_pkt_ipv6(self):
        """
        @description: Check that driver has L4 TX checksum offload workaround for invalid big UDP over IPv6 packet.

        @steps:
        1. Using system sockets create UDP server/client connection on DUT and LKP.
        2. From DUT send big UDP over IPv6 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on LKP.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_udp_checksum_offload_workaround_test(DIRECTION_TX, 500, 6)

    def test_tcp_rx_checksum_offload_workaround_small_pkt_ipv6(self):
        """
        @description: Check that driver has L4 RX checksum offload workaround for invalid small TCP over IPv6 packet.

        @steps:
        1. Using system sockets create TCP server/client connection on DUT and LKP.
        2. From LKP send small TCP over IPv6 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on DUT.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_tcp_checksum_offload_workaround_test(DIRECTION_RX, 60, 6)

    def test_tcp_rx_checksum_offload_workaround_big_pkt_ipv6(self):
        """
        @description: Check that driver has L4 RX checksum offload workaround for invalid big TCP over IPv6 packet.

        @steps:
        1. Using system sockets create TCP server/client connection on DUT and LKP.
        2. From LKP send big TCP over IPv6 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on DUT.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_tcp_checksum_offload_workaround_test(DIRECTION_RX, 500, 6)

    def test_tcp_tx_checksum_offload_workaround_small_pkt_ipv6(self):
        """
        @description: Check that driver has L4 TX checksum offload workaround for invalid small TCP over IPv6 packet.

        @steps:
        1. Using system sockets create TCP server/client connection on DUT and LKP.
        2. From DUT send small TCP over IPv6 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on LKP.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_tcp_checksum_offload_workaround_test(DIRECTION_TX, 60, 6)

    def test_tcp_tx_checksum_offload_workaround_big_pkt_ipv6(self):
        """
        @description: Check that driver has L4 TX checksum offload workaround for invalid big TCP over IPv6 packet.

        @steps:
        1. Using system sockets create TCP server/client connection on DUT and LKP.
        2. From DUT send big TCP over IPv6 packet with non-zero padding.
        3. Make sure that the packet is transfered to OS stack on LKP.

        @result: MAC checksum offload engine marked packet as invalid checksum however driver passed it to OS stack.
        @duration: 30 seconds.
        """
        self.run_tcp_checksum_offload_workaround_test(DIRECTION_TX, 500, 6)


if __name__ == "__main__":
    exec_list = [__file__, "-s", "-v"]
    pytest.main(exec_list)
