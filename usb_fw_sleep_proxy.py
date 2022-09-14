"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import time

import pytest

from tools.command import Command
from tools.pactoolper import PacTool, CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, CAPS_AQ_USB_VENDOR_CMD_SLEEP_PROXY, \
    USB_POWER, USB_SLEEP_PROXY
from tools.constants import LINK_SPEED_AUTO, MTU_1500
from infra.test_base import TestBase, idparametrize
from tools.driver import Driver, DRV_TYPE_DIAG_WIN_USB
from tools.drv_iface_cfg import DrvUsbConfig
from tools.power import Power
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_usb_sleep_proxy"


class TestFWUsbSleepProxy(TestBase):
    AFTER_TURNOFF_DELAY = 30
    BEFORE_PING_DELAY = 15
    WAKE_COUNTER_DELAY = 5

    DUT_MAC = "00:17:b6:a1:a2:a3"
    DUT_IPs4 = ["192.168.0.3", "192.168.0.4", "192.168.0.5"]
    DUT_IPs6 = ["4000:0000:0000:0000:1601:bd17:0c02:2403",
                "4000:0000:0000:0000:1601:bd17:0c02:2413",
                "4000:0000:0000:0000:1601:bd17:0c02:2423",
                "4000:0000:0000:0000:1601:bd17:0c02:2433"]
    LKP_IP4 = "192.168.0.24"
    NETMASK_IP4 = "255.255.255.0"
    LKP_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2402"
    PREFIX_IP6 = "64"
    WAKEPORT = 13370

    SLEEP_PROXY_FLAG_MAGIC_PACKET = 2

    @classmethod
    def setup_class(cls):
        super(TestFWUsbSleepProxy, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG_WIN_USB, version=cls.dut_drv_version,
                                    host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver.install()
            cls.dut_power = Power(host=cls.dut_hostname)
            cls.dut_pactool = PacTool(port=cls.dut_port, host=cls.dut_hostname)

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4, cls.NETMASK_IP4, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6, cls.PREFIX_IP6, None)

        except Exception as e:
            log.exception(e)
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestFWUsbSleepProxy, cls).teardown_class()
        # Put wol on LKP back
        cmd = "sudo ethtool -s {} wol g".format(cls.lkp_iface)
        disable_cmd = Command(cmd=cmd)
        disable_cmd.run_join(10)

    def setup_method(self, method):
        super(TestFWUsbSleepProxy, self).setup_method(method)

        if not self.is_host_alive_and_ready(self.dut_hostname):
            raise Exception("DUT is not online, can't perform test")

        if not self.dut_driver.is_installed():
            self.dut_driver.install()

    def teardown_method(self, method):
        super(TestFWUsbSleepProxy, self).teardown_method(method)
        self.bring_host_online(self.dut_hostname)

    def hibernate_dut(self, retry_interval=15):
        log.info("Hibernating DUT")
        self.dut_power.hibernate()
        if not self.poll_host_powered_off(self.dut_hostname, retry_interval=retry_interval):
            raise Exception("Couldn't hibernate DUT")
        log.info("DUT is hibernated")

        time.sleep(self.AFTER_TURNOFF_DELAY)
        if self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        log.info("DUT is still hibernated after {} seconds of sleeping".format(self.AFTER_TURNOFF_DELAY))

        # Link should be UP on link partner
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed == self.supported_speeds[0]

    def run_test_with_offloads(self, ip_v4_address, ip_v6_address):
        eth_cfg = DrvUsbConfig()
        dut_mac_address = [int(m, 16) for m in self.DUT_MAC.split(":")]
        wol_bit = self.SLEEP_PROXY_FLAG_MAGIC_PACKET
        data = 0
        for i in range(len(eth_cfg.mac_octets)):
            eth_cfg.mac_octets[i] = dut_mac_address[i]
        eth_cfg.flags = wol_bit
        eth_cfg.wolPatternCount = 0
        for j in range(len(eth_cfg.wolPatterns)):
            for i in range(len(eth_cfg.wolPatterns[j].mask)):
                eth_cfg.wolPatterns[j].mask[i] = 0
            eth_cfg.wolPatterns[j].crc16 = 0
            eth_cfg.wolPatterns[j].crc32 = 0
        eth_cfg.linkUpTimeout = 0
        eth_cfg.linkDownTimeout = 0
        eth_cfg.ipv4Count = len(ip_v4_address)
        for i in range(eth_cfg.ipv4Count):
            eth_cfg.ipv4[i] = ip_v4_address[i]
        for i in range(eth_cfg.ipv4Count, len(eth_cfg.ipv4)):
            eth_cfg.ipv4[i] = 0
        eth_cfg.ipv6Count = len(ip_v6_address)
        for j in range(len(ip_v6_address)):
            for i in range(len(ip_v6_address[j])):
                eth_cfg.ipv6[j].ipv6[i] = ip_v6_address[j][i]
        data = eth_cfg.get_data()
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_SLEEP_PROXY,
                                              data=data, size=len(data))
        time.sleep(5)
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS,
                                              data=[0, 0, USB_SLEEP_PROXY | USB_POWER, 0], size=4)
        log.info('Wol for wake on magic packet and sleep proxy are configured')
        # Link should be UP on link partner
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed == self.supported_speeds[0]

        time.sleep(self.BEFORE_PING_DELAY)

    @idparametrize("hibernation", [False, True])
    def test_icmp_offload(self, hibernation):
        """
        @description: Perform simple ping check in sleep proxy mode (IPv4 version).

        @steps:
        1. Configure DUT offload with multiple IPv4 addresses.
        2. Ping each DUT's IP from LKP (16 requests).
        3. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 80 seconds.
        """
        ip_v4_addresses = []
        for i in range(len(self.DUT_IPs4)):
            addr = [int(m) for m in self.DUT_IPs4[i].split(".")]
            ip_v4_addresses.append(addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24)

        self.run_test_with_offloads(ip_v4_addresses, [])

        if hibernation:
            self.hibernate_dut()

        for address in self.DUT_IPs4:
            log.info("Ping {} from {}".format(address, self.LKP_IP4))
            assert self.ping(self.lkp_hostname, address, 16, ipv6=False, src_addr=self.LKP_IP4) is True, \
                "Failed to ping {} from {}".format(address, self.LKP_IP4)

    @idparametrize("hibernation", [False, True])
    def test_ipv6_offload(self, hibernation):
        """
        @description: Perform simple ping check in sleep proxy mode (IPv6 version).

        @steps:
        1. Configure DUT offload with multiple IPv6 addresses.
        2. Ping each DUT's IP from LKP (16 requests).
        3. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 90 seconds.
        """
        ip_v6_address = []
        for i in range(len(self.DUT_IPs6)):
            addr = [int(m, 16) for m in self.DUT_IPs6[i].split(":")]
            v6_addr = []
            for j in range(len(addr)):
                v6_addr.append((addr[j] & 0xff00) >> 8)
                v6_addr.append(addr[j] & 0x00ff)
            ip_v6_address.append(v6_addr)

        self.run_test_with_offloads([], ip_v6_address)

        if hibernation:
            self.hibernate_dut()

        for address in self.DUT_IPs6:
            log.info("Ping {} from {}".format(address, self.LKP_IP6))
            assert self.ping(self.lkp_hostname, address, 16, ipv6=True, src_addr=self.LKP_IP6) is True, \
                "Failed to ping {} from {}".format(address, self.LKP_IP6)

    @idparametrize("hibernation", [False, True])
    def test_small_fragmentated_pings(self, hibernation):
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

            ip_v4_addresses = []
            for i in range(len(self.DUT_IPs4)):
                addr = [int(m) for m in self.DUT_IPs4[i].split(".")]
                ip_v4_addresses.append(addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24)

            self.run_test_with_offloads(ip_v4_addresses, [])

            if hibernation:
                self.hibernate_dut()

            for address in self.DUT_IPs4:
                log.info("Ping {} from {}".format(address, self.LKP_IP4))
                assert self.ping(
                    self.lkp_hostname, address, 16, ipv6=False, src_addr=self.LKP_IP4, payload_size=500, margin=20
                ) is True, "Ping {} from {} failed unexpectedly (first request fragment should be replied)".format(
                    address, self.LKP_IP4
                )
        finally:
            self.lkp_ifconfig.set_mtu(MTU_1500)

    @idparametrize("hibernation", [False, True])
    def test_big_packets_drop_pings(self, hibernation):
        """
        @description: Perform ping check in sleep proxy mode after big packets.

        @steps:
        1. Configure DUT offload with multiple IPv4 and IPv6 addresses.
        2. Ping each DUT's IP from LKP (16 requests, length 5000 bytes).
        3. FW should drop these pings.
        4. Ping each DUT's IP from LKP (16 requests).
        5. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 80 seconds.
        """
        ip_v4_addresses = []
        for i in range(len(self.DUT_IPs4)):
            addr = [int(m) for m in self.DUT_IPs4[i].split(".")]
            ip_v4_addresses.append(addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24)

        self.run_test_with_offloads(ip_v4_addresses, [])

        if hibernation:
            self.hibernate_dut()

        for address in self.DUT_IPs4:
            log.info("Ping {} from {}".format(address, self.LKP_IP4))
            # Run 500 payload packets should be dropped
            self.ping(self.lkp_hostname, address, 16, ipv6=False, src_addr=self.LKP_IP4, payload_size=5000, margin=20)
            # Run small payload packets should be transfered
            assert self.ping(self.lkp_hostname, address, 16, ipv6=False, src_addr=self.LKP_IP4) is True, \
                "Failed to ping {} from {}".format(address, self.LKP_IP4)

    @idparametrize("hibernation", [False, True])
    def test_ipv4_offload_multi_networks(self, hibernation):
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
        LKP_IP4_1 = ["169.254.23.1"]
        LKP_MSK_1 = ["255.255.0.0"]

        DUT_IP4_2 = ["192.168.0.3", "192.168.0.4"]
        LKP_IP4_2 = ["192.168.0.2"]
        LKP_MSK_2 = ["255.255.255.0"]

        DUT_IP4_3 = ["10.0.0.3"]
        LKP_IP4_3 = ["10.0.0.2"]
        LKP_MSK_3 = ["255.255.255.240"]

        ip_v4_addresses = []
        for i in range(len(DUT_IP4_1)):
            addr = [int(m) for m in DUT_IP4_1[i].split(".")]
            ip_v4_addresses.append(addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24)
        for i in range(len(DUT_IP4_2)):
            addr = [int(m) for m in DUT_IP4_2[i].split(".")]
            ip_v4_addresses.append(addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24)
        addr = [int(m) for m in DUT_IP4_3[0].split(".")]
        ip_v4_addresses.append(addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24)

        # Configure IPv4 on LKP
        for i in range(len(LKP_IP4_1)):
            self.lkp_ifconfig.set_ip_address(LKP_IP4_1[i], LKP_MSK_1[i], None)
        for i in range(len(LKP_IP4_2)):
            self.lkp_ifconfig.set_ip_address(LKP_IP4_2[i], LKP_MSK_2[i], None)
        for i in range(len(LKP_IP4_3)):
            self.lkp_ifconfig.set_ip_address(LKP_IP4_3[i], LKP_MSK_3[i], None)

        self.run_test_with_offloads(ip_v4_addresses, [])

        if hibernation:
            self.hibernate_dut()

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


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
