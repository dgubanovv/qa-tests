import os
import random
import shutil
import sys
import time

import pytest
from ipaddress import IPv6Address
sys_stdout = sys.stdout
from scapy.all import Ether, IP, ICMP, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, Raw
sys.stdout = sys_stdout

from tools.atltoolper import AtlTool
from tools.aqpkt import Aqsendp, scapy_pkt_to_aqsendp_str
from tools.constants import FELICITY_CARDS, LINK_SPEED_AUTO, LINK_SPEED_1G, MTU_1500, CARDS_FELICITY_BERMUDA
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvEthConfig, OffloadIpInfo
from tools.samba import Samba
from tools.tcpdump import Tcpdump
from tools.utils import get_atf_logger
from tools.virtual_network import VirtualHost

from infra.test_base import TestBase
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_ping_proxy"


class TestFW2xPingProxy(TestBase):
    """
    @description: The ping proxy test is dedicated to check ICMP / ICMPv6 offload in sleep proxy mode.
    It performs several ping checks in different network configurations.

    @setup: Two Aquantia devices connected back to back.
    """

    BEFORE_PING_DELAY = 15

    DUT_MAC = "00:17:b6:00:07:82"
    DUT_IP4_LIST = ["192.168.10.21", "192.168.10.22", "192.168.10.23"]
    DUT_IP4_MASK_LIST = [24, 24, 24]
    DUT_IP6_LIST = ["4000:0000:0000:0000:1601:bd17:0c02:1021",
                    "4000:0000:0000:0000:1601:bd17:0c02:1022",
                    "4000:0000:0000:0000:1601:bd17:0c02:1023",
                    "4000:0000:0000:0000:1601:bd17:0c02:1024"]
    DUT_IP6_MASK_LIST = [64, 64, 64]

    LKP_IP4 = "192.168.10.100"
    LKP_IP4_MASK = "255.255.255.0"
    LKP_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:1100"
    LKP_IP6_MASK = "64"

    # Constants for virtual network
    VIRTUAL_HOSTS = [VirtualHost("Host1", "192.168.1.2", "4001:0000:0000:0000:0000:0000:0000:0002"),
                     VirtualHost("Host2", "192.168.2.2", "4002:0000:0000:0000:0000:0000:0000:0002"),
                     VirtualHost("Host3", "192.168.3.2", "4003:0000:0000:0000:0000:0000:0000:0002")]
    DUT_VIRTUAL_IP4_LIST = ["10.1.0.2", "10.2.0.2", "10.3.0.2"]
    DUT_VIRTUAL_MSK_LIST = [16, 24, 28]
    DUT_VIRTUAL_IP6_LIST = ["1001:0000:0000:0000:0000:0000:0000:0002",
                            "1002:0000:0000:0000:0000:0000:0000:0002",
                            "1003:0000:0000:0000:0000:0000:0000:0002"]
    DUT_VIRTUAL_PRF_LIST = [56, 64, 72]

    @classmethod
    def setup_class(cls):
        super(TestFW2xPingProxy, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest")
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4, cls.LKP_IP4_MASK, None)

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            # Disable Samba to remove background multicast traffic which affects SerDes
            Samba(host=cls.lkp_hostname).stop()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestFW2xPingProxy, self).setup_method(method)
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in CARDS_FELICITY_BERMUDA)

        self.lkp_ifconfig.set_ipv6_address(self.LKP_IP6, self.LKP_IP6_MASK, None)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)

        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)
            self.lkp_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestFW2xPingProxy, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

            self.lkp_bin_log_file, self.lkp_txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.lkp_bin_log_file, self.test_log_dir)
            shutil.copy(self.lkp_txt_log_file, self.test_log_dir)

    def test_icmp_offload(self):
        """
        @description: Perform simple ping check in sleep proxy mode (IPv4 version).

        @steps:
        1. Configure DUT offload with multiple IPv4 addresses.
        2. Ping each DUT's IP from LKP (16 requests).
        3. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 80 seconds.
        """
        cfg = DrvEthConfig()
        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = len(self.DUT_IP4_LIST)
        cfg.ips.v4_addresses = self.DUT_IP4_LIST
        cfg.ips.v4_masks = self.DUT_IP4_MASK_LIST

        out_beton_filename = os.path.join(self.test_log_dir, "offload_ipv4.txt")
        cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        self.lkp_ifconfig.wait_link_up()

        time.sleep(self.BEFORE_PING_DELAY)

        for address in cfg.ips.v4_addresses:
            log.info("Ping {} from {}".format(address, self.LKP_IP4))
            assert self.ping(self.lkp_hostname, address, 16, ipv6=False, src_addr=self.LKP_IP4) is True, \
                "Failed to ping {} from {}".format(address, self.LKP_IP4)

    def test_ipv6_offload(self):
        """
        @description: Perform simple ping check in sleep proxy mode (IPv6 version).

        @steps:
        1. Configure DUT offload with multiple IPv6 addresses.
        2. Ping each DUT's IP from LKP (16 requests).
        3. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 90 seconds.
        """
        cfg = DrvEthConfig()
        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC

        cfg.ips = OffloadIpInfo()
        cfg.ips.v6_addr_count = len(self.DUT_IP6_LIST)
        cfg.ips.v6_addresses = self.DUT_IP6_LIST
        cfg.ips.v6_masks = self.DUT_IP6_MASK_LIST

        out_beton_filename = os.path.join(self.test_log_dir, "offload_ipv6.txt")
        cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        self.lkp_ifconfig.wait_link_up()

        time.sleep(self.BEFORE_PING_DELAY)

        for address in cfg.ips.v6_addresses:
            log.info("Ping {} from {}".format(address, self.LKP_IP6))
            assert self.ping(self.lkp_hostname, address, 16, ipv6=True, src_addr=self.LKP_IP6) is True, \
                "Failed to ping {} from {}".format(address, self.LKP_IP6)

    def test_small_fragmentated_pings(self):
        """
        @description: Perform ping check in sleep proxy mode with fragmented requests.

        @steps:
        1. Configure DUT offload with multiple IPv4 and IPv6 addresses.
        2. Set 200 MTU on LKP.
        3. Ping each DUT's IP from LKP (16 requests, length 500 bytes).
        4. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 80 seconds.
        """
        try:
            self.lkp_ifconfig.set_mtu(200)

            cfg = DrvEthConfig()
            cfg.version = 0
            cfg.len = 0x407  # not used
            cfg.mac = self.DUT_MAC

            cfg.ips = OffloadIpInfo()
            cfg.ips.v4_addr_count = min(2, len(self.DUT_IP4_LIST))
            cfg.ips.v4_addresses = self.DUT_IP4_LIST[:cfg.ips.v4_addr_count]
            cfg.ips.v4_masks = self.DUT_IP4_MASK_LIST[:cfg.ips.v4_addr_count]
            # cfg.ips.v6_addr_count = min(2, len(self.DUT_IP6_LIST))
            # cfg.ips.v6_addresses = self.DUT_IP6_LIST[:cfg.ips.v6_addr_count]
            # cfg.ips.v6_masks = self.DUT_IP6_MASK_LIST[:cfg.ips.v6_addr_count]

            out_beton_filename = os.path.join(self.test_log_dir, "offload_frag_pings.txt")
            cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

            self.lkp_ifconfig.wait_link_up()

            time.sleep(self.BEFORE_PING_DELAY)

            for address in cfg.ips.v4_addresses:
                log.info("Ping {} from {}".format(address, self.LKP_IP4))
                assert self.ping(
                    self.lkp_hostname, address, 16, ipv6=False, src_addr=self.LKP_IP4, payload_size=500, margin=20
                ) is True, "Ping {} from {} failed unexpectedly (first request fragment should be replied)".format(
                    address, self.LKP_IP4
                )

            # TODO: Linux won't let setting IPv6 to an interface with MTU lower than 1280
            # for address in cfg.ips.v6_addresses:
            #     log.info("Ping {} from {}".format(address, self.LKP_IP6))
            #     assert self.ping(self.lkp_hostname, address, 16, ipv6=True, src_addr=self.LKP_IP6, payload_size=500,
            #                      margin=10) is True, "Failed to ping {} from {}".format(address, self.LKP_IP6)
        finally:
            self.lkp_ifconfig.set_mtu(MTU_1500)

    def test_large_fragmentated_pings(self):
        """
        @description: Perform ping check in sleep proxy mode with fragmented requests.

        @steps:
        1. Configure DUT offload with multiple IPv4 and IPv6 addresses.
        2. Ping each DUT's IP from LKP (16 requests, length 5000 bytes).
        3. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 80 seconds.
        """
        cfg = DrvEthConfig()
        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = min(2, len(self.DUT_IP4_LIST))
        cfg.ips.v4_addresses = self.DUT_IP4_LIST[:cfg.ips.v4_addr_count]
        cfg.ips.v4_masks = self.DUT_IP4_MASK_LIST[:cfg.ips.v4_addr_count]
        cfg.ips.v6_addr_count = min(2, len(self.DUT_IP6_LIST))
        cfg.ips.v6_addresses = self.DUT_IP6_LIST[:cfg.ips.v6_addr_count]
        cfg.ips.v6_masks = self.DUT_IP6_MASK_LIST[:cfg.ips.v6_addr_count]

        out_beton_filename = os.path.join(self.test_log_dir, "offload_frag_pings.txt")
        cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        self.lkp_ifconfig.wait_link_up()

        time.sleep(self.BEFORE_PING_DELAY)

        for address in cfg.ips.v4_addresses:
            log.info("Ping {} from {}".format(address, self.LKP_IP4))
            assert self.ping(
                self.lkp_hostname, address, 16, ipv6=False, src_addr=self.LKP_IP4, payload_size=4000, margin=10
            ) is True, "Ping {} from {} failed unexpectedly (first request fragment should be replied)".format(
                address, self.LKP_IP4
            )

        for address in cfg.ips.v6_addresses:
            log.info("Ping {} from {}".format(address, self.LKP_IP6))
            assert self.ping(
                self.lkp_hostname, address, 16, ipv6=True, src_addr=self.LKP_IP6, payload_size=4000, margin=10
            ) is True, "Ping {} from {} failed unexpectedly (first request fragment should be replied)".format(
                address, self.LKP_IP4
            )

    def test_fragmentated_pings_serdes(self):
        """
        @description: Perform ping check in sleep proxy mode with fragmented requests while serdes is up.

        @steps:
        1. Configure DUT offload with multiple IPv4 and IPv6 addresses.
        2. Set link speed on LKP other than 100M. That way serdes will be up in sleep proxy mode.
        3. Ping each DUT's IP from LKP (16 requests, length 5000 bytes).
        4. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 80 seconds.
        """
        try:
            if self.lkp_fw_card in FELICITY_CARDS:
                lkp_speed = self.supported_speeds[-1]
            else:
                lkp_speed = LINK_SPEED_1G
            self.lkp_ifconfig.set_link_speed(lkp_speed)

            cfg = DrvEthConfig()
            cfg.version = 0
            cfg.len = 0x407  # not used
            cfg.mac = self.DUT_MAC

            cfg.ips = OffloadIpInfo()
            cfg.ips.v4_addr_count = min(2, len(self.DUT_IP4_LIST))
            cfg.ips.v4_addresses = self.DUT_IP4_LIST[:cfg.ips.v4_addr_count]
            cfg.ips.v4_masks = self.DUT_IP4_MASK_LIST[:cfg.ips.v4_addr_count]
            # cfg.ips.v6_addr_count = min(2, len(self.DUT_IP6_LIST))
            # cfg.ips.v6_addresses = self.DUT_IP6_LIST[:cfg.ips.v6_addr_count]
            # cfg.ips.v6_masks = self.DUT_IP6_MASK_LIST[:cfg.ips.v6_addr_count]

            out_beton_filename = os.path.join(self.test_log_dir, "offload_frag_pings.txt")
            cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

            self.lkp_ifconfig.wait_link_up()

            time.sleep(self.BEFORE_PING_DELAY)

            for address in cfg.ips.v4_addresses:
                log.info("Ping {} from {}".format(address, self.LKP_IP4))
                assert self.ping(
                    self.lkp_hostname, address, 16, ipv6=False, src_addr=self.LKP_IP4, payload_size=4000
                ) is True, "Ping {} from {} failed unexpectedly (first request fragment should be replied)".format(
                    address, self.LKP_IP4
                )
            # TODO: Linux - ping: bind icmp socket: Cannot assign requested address
            # for address in cfg.ips.v6_addresses:
            #     log.info("Ping {} from {}".format(address, self.LKP_IP6))
            #     assert self.ping(self.lkp_hostname, address, 16, ipv6=True, src_addr=self.LKP_IP6,
            #                      payload_size=4000) is True, "Failed to ping {} from {}".format(address, self.LKP_IP6)
        finally:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

    def test_ipv4_offload_multi_networks(self):
        """
        @description: Perform ping check in sleep proxy mode with multiple networks (IPv4 version).

        @steps:
        1. Configure DUT offload with multiple IPv4 addresses in different local networks.
        2. Set IP address on LKP for each local network.
        3. Ping each DUT's IP from LKP (4 requests).
        4. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 60 seconds.
        """
        DUT_IP4_1 = ["169.254.23.232", "169.254.23.233", "169.254.23.234"]
        DUT_MSK_1 = [16, 16, 16]
        LKP_IP4_1 = ["169.254.23.1"]
        LKP_MSK_1 = ["255.255.0.0"]

        DUT_IP4_2 = ["192.168.0.3", "192.168.0.4"]
        DUT_MSK_2 = [24, 24]
        LKP_IP4_2 = ["192.168.0.2"]
        LKP_MSK_2 = ["255.255.255.0"]

        DUT_IP4_3 = ["10.0.0.3"]
        DUT_MSK_3 = [28]
        LKP_IP4_3 = ["10.0.0.2"]
        LKP_MSK_3 = ["255.255.255.240"]

        cfg = DrvEthConfig()
        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = len(DUT_IP4_1) + len(DUT_IP4_2) + len(DUT_IP4_3)
        cfg.ips.v4_addresses = DUT_IP4_1 + DUT_IP4_2 + DUT_IP4_3
        cfg.ips.v4_masks = DUT_MSK_1 + DUT_MSK_2 + DUT_MSK_3

        out_beton_filename = os.path.join(self.test_log_dir, "offload_multi_ipv4.txt")
        cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        # Configure IPv4 on LKP
        for i in range(len(LKP_IP4_1)):
            self.lkp_ifconfig.set_ip_address(LKP_IP4_1[i], LKP_MSK_1[i], None)
        for i in range(len(LKP_IP4_2)):
            self.lkp_ifconfig.set_ip_address(LKP_IP4_2[i], LKP_MSK_2[i], None)
        for i in range(len(LKP_IP4_3)):
            self.lkp_ifconfig.set_ip_address(LKP_IP4_3[i], LKP_MSK_3[i], None)

        self.lkp_ifconfig.wait_link_up()

        time.sleep(self.BEFORE_PING_DELAY)

        for addr in DUT_IP4_1:
            log.info("Ping from {} to {} ...".format(LKP_IP4_1[0], addr))
            assert self.ping(self.lkp_hostname, addr, 4, ipv6=False, src_addr=LKP_IP4_1[0]) is True, \
                "Failed to ping {} from {}".format(addr, LKP_IP4_1[0])
        for addr in DUT_IP4_2:
            log.info("Ping from {} to {} ...".format(LKP_IP4_2[0], addr))
            assert self.ping(self.lkp_hostname, addr, 4, ipv6=False, src_addr=LKP_IP4_2[0]) is True, \
                "Failed to ping {} from {}".format(addr, LKP_IP4_2[0])
        for addr in DUT_IP4_3:
            log.info("Ping from {} to {} ...".format(LKP_IP4_3[0], addr))
            assert self.ping(self.lkp_hostname, addr, 4, ipv6=False, src_addr=LKP_IP4_3[0]) is True, \
                "Failed to ping {} from {}".format(addr, LKP_IP4_3[0])

    def test_ipv6_offload_multi_networks(self):
        """
        @description: Perform ping check in sleep proxy mode with multiple networks (IPv6 version).

        @steps:
        1. Configure DUT offload with multiple IPv6 addresses in different local networks.
        2. Set IP address on LKP for each local network.
        3. Ping each DUT's IP from LKP (4 requests).
        4. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 60 seconds.
        """
        DUT_IP6_1 = ["4000:0000:0000:0000:1601:bd17:0c02:2411",
                     "4000:0000:0000:0000:1601:bd17:0c02:2421",
                     "4000:0000:0000:0000:1601:bd17:0c02:2431"]
        DUT_PRF_1 = [64, 64, 64]
        LKP_IP6_1 = ["4000:0000:0000:0000:1601:bd17:0c02:2401"]
        LKP_PRF_1 = ["64"]

        DUT_IP6_2 = ["5000:0000:0000:0000:1601:bd17:0c02:2412",
                     "5000:0000:0000:0000:1601:bd17:0c02:2422"]
        DUT_PRF_2 = [72, 72, 72]
        LKP_IP6_2 = ["5000:0000:0000:0000:1601:bd17:0c02:2402"]
        LKP_PRF_2 = ["72"]

        DUT_IP6_3 = ["6000:0000:0000:0000:1601:bd17:0c02:2431"]
        DUT_PRF_3 = [80]
        LKP_IP6_3 = ["6000:0000:0000:0000:1601:bd17:0c02:2403"]
        LKP_PRF_3 = ["80"]

        cfg = DrvEthConfig()
        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC

        cfg.ips = OffloadIpInfo()
        cfg.ips.v6_addr_count = len(DUT_IP6_1) + len(DUT_IP6_2) + len(DUT_IP6_3)
        cfg.ips.v6_addresses = DUT_IP6_1 + DUT_IP6_2 + DUT_IP6_3
        cfg.ips.v6_masks = DUT_PRF_1 + DUT_PRF_2 + DUT_PRF_3

        out_beton_filename = os.path.join(self.test_log_dir, "offload_multi_ipv6.txt")
        cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        # Configure IPv6 on LKP
        for i in range(len(LKP_IP6_1)):
            self.lkp_ifconfig.set_ipv6_address(LKP_IP6_1[i], LKP_PRF_1[i], None)
        for i in range(len(LKP_IP6_2)):
            self.lkp_ifconfig.set_ipv6_address(LKP_IP6_2[i], LKP_PRF_2[i], None)
        for i in range(len(LKP_IP6_3)):
            self.lkp_ifconfig.set_ipv6_address(LKP_IP6_3[i], LKP_PRF_3[i], None)

        self.lkp_ifconfig.wait_link_up()

        time.sleep(20)

        # Verify IPv6 Offload
        for addr in DUT_IP6_1:
            log.info("Ping from {} to {} ...".format(LKP_IP6_1[0], addr))
            assert self.ping(self.lkp_hostname, addr, 4, ipv6=True, src_addr=LKP_IP6_1[0]) is True, \
                "Failed to ping {} from {}".format(addr, LKP_IP6_1[0])
        for addr in DUT_IP6_2:
            log.info("Ping from {} to {} ...".format(LKP_IP6_2[0], addr))
            assert self.ping(self.lkp_hostname, addr, 4, ipv6=True, src_addr=LKP_IP6_2[0]) is True, \
                "Failed to ping {} from {}".format(addr, LKP_IP6_2[0])
        for addr in DUT_IP6_3:
            log.info("Ping from {} to {} ...".format(LKP_IP6_3[0], addr))
            assert self.ping(self.lkp_hostname, addr, 4, ipv6=True, src_addr=LKP_IP6_3[0]) is True, \
                "Failed to ping {} from {}".format(addr, LKP_IP6_3[0])

    def test_ipv4_cross_network(self):
        """
        @description: Perform ping check in sleep proxy mode across multiple networks through routers (IPv6 version).

        @steps:
        1. Configure DUT offload with multiple IPv6 addresses in different networks.
        2. Configure virtual network on LKP. Create multiple virtual hosts each with its own router. All routers are
           connected to switch. DUT is also connected to the switch.
        3. Ping each DUT's IP from corresponding virtual host.
        4. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 80 seconds.
        """

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()
        eth_cfg.ips.v4_addr_count = len(self.DUT_VIRTUAL_IP4_LIST)
        eth_cfg.ips.v4_addresses = self.DUT_VIRTUAL_IP4_LIST
        eth_cfg.ips.v4_masks = self.DUT_VIRTUAL_MSK_LIST

        out_beton_filename = os.path.join(self.test_log_dir, "offload_ipv4_cross.txt")
        eth_cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        self.lkp_ifconfig.wait_link_up()

        time.sleep(20)  # TODO: this should be removed after ATLFW-421 is fixed

        def ping_from_lkp(src_mac, dst_mac, src_ip, dst_ip, nof_pings=1):
            log.info("Pinging from {} --- {} to {} --- {} on LKP".format(src_mac, src_ip, dst_mac, dst_ip))

            tcpdump = Tcpdump(port=self.lkp_port, host=self.lkp_hostname, timeout=nof_pings + 5)
            tcpdump.run_async()

            icmp_req = Ether(src=src_mac, dst=dst_mac)
            icmp_req /= IP(src=src_ip, dst=dst_ip)
            icmp_req /= ICMP()
            icmp_req /= Raw(load="ffffffffffffffffffffffffffffffffffff".decode("hex"))

            pstr = scapy_pkt_to_aqsendp_str(icmp_req)

            a = Aqsendp(packet=pstr, count=nof_pings, rate=1, host=self.lkp_hostname)
            a.run()

            packets = tcpdump.join()
            log.info("\n".join(["ALL packets:"] + ["{}: {}".format(p.time, p.summary()) for p in packets]))
            return packets

        for i, dst_ip in enumerate(self.DUT_VIRTUAL_IP4_LIST):
            src_ip = self.VIRTUAL_HOSTS[i].ipv4
            src_mac = "00:17:b6:{:02x}:{:02x}:{:02x}".format(
                random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

            nof_pings = 10
            packets = ping_from_lkp(src_mac, self.DUT_MAC, src_ip, dst_ip, nof_pings=nof_pings)

            nof_replies = 0
            for p in packets:
                if ICMP in p and p[ICMP].code == 0 and p[ICMP].type == 0:  # ICMP reply
                    assert p[Ether].src == self.DUT_MAC
                    assert p[Ether].dst == src_mac
                    assert p[IP].src == dst_ip
                    assert p[IP].dst == src_ip

                    nof_replies += 1
            assert nof_replies == nof_pings

    def test_ipv6_cross_network(self):
        """
        @description: Perform ping check in sleep proxy mode across multiple networks through routers (IPv6 version).

        @steps:
        1. Configure DUT offload with multiple IPv6 addresses in different networks.
        2. Configure virtual network on LKP. Create multiple virtual hosts each with its own router. All routers are
           connected to switch. DUT is also connected to the switch.
        3. Ping each DUT's IP from corresponding virtual host.
        4. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 80 seconds.
        """

        eth_cfg = DrvEthConfig()
        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC

        eth_cfg.ips = OffloadIpInfo()
        eth_cfg.ips.v6_addr_count = len(self.DUT_VIRTUAL_IP6_LIST)
        eth_cfg.ips.v6_addresses = self.DUT_VIRTUAL_IP6_LIST
        eth_cfg.ips.v6_masks = self.DUT_VIRTUAL_PRF_LIST

        out_beton_filename = os.path.join(self.test_log_dir, "offload_ipv6_cross.txt")
        eth_cfg.apply(self.dut_atltool_wrapper, out_beton_filename)

        self.lkp_ifconfig.wait_link_up()

        time.sleep(self.BEFORE_PING_DELAY)  # TODO: this should be removed after ATLFW-421 is fixed

        def ping_from_lkp(src_mac, dst_mac, src_ip6, dst_ip6, nof_pings=1):
            log.info("Pinging from {} --- {} to {} --- {} on LKP".format(src_mac, src_ip6, dst_mac, dst_ip6))

            tcpdump = Tcpdump(port=self.lkp_port, host=self.lkp_hostname, timeout=nof_pings + 5)
            tcpdump.run_async()

            icmp_req = Ether(src=src_mac, dst=dst_mac)
            icmp_req /= IPv6(src=src_ip6, dst=dst_ip6)
            icmp_req /= ICMPv6EchoRequest()

            pstr = scapy_pkt_to_aqsendp_str(icmp_req)

            a = Aqsendp(packet=pstr, count=nof_pings, rate=1, host=self.lkp_hostname)
            a.run()

            packets = tcpdump.join()
            log.info("\n".join(["ALL packets:"] + ["{}: {}".format(p.time, p.summary()) for p in packets]))
            return packets

        for i, dst_ip6 in enumerate(self.DUT_VIRTUAL_IP6_LIST):
            src_ip6 = self.VIRTUAL_HOSTS[i].ipv6
            src_mac = "00:17:b6:{:02x}:{:02x}:{:02x}".format(
                random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

            nof_pings = 10
            packets = ping_from_lkp(src_mac, self.DUT_MAC, src_ip6, dst_ip6, nof_pings=nof_pings)

            nof_replies = 0
            for p in packets:
                if ICMPv6EchoReply in p and \
                        p[ICMPv6EchoReply].code == 0 and \
                        p[ICMPv6EchoReply].type == 0x81:  # ICMPv6 reply
                    assert p[Ether].src == self.DUT_MAC
                    assert p[Ether].dst == src_mac
                    assert IPv6Address(unicode(p[IPv6].src)).exploded == IPv6Address(unicode(dst_ip6)).exploded
                    assert IPv6Address(unicode(p[IPv6].dst)).exploded == IPv6Address(unicode(src_ip6)).exploded

                    nof_replies += 1
            assert nof_replies == nof_pings


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
