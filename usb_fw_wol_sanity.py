"""
    THIS SCRIPT MUST BE EXECUTED ON LKP.
"""
import os
import time

import pytest

from tools.command import Command
from tools.pactoolper import PacTool, CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, CAPS_AQ_USB_VENDOR_CMD_SLEEP_PROXY, \
    USB_POWER, USB_SLEEP_PROXY
from tools.constants import LINK_SPEED_NO_LINK, LINK_STATE_DOWN, LINK_STATE_UP, LINK_SPEED_AUTO, LINK_SPEED_100M, \
    LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G
from infra.test_base import TestBase
from tools.driver import Driver, DRV_TYPE_DIAG_WIN_USB
from tools.drv_iface_cfg import DrvUsbConfig
from tools.power import Power
from tools.scapy_tools import ScapyTools
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_usb_wol_sanity"


class TestFWUsbWoL(TestBase):
    AFTER_TURNOFF_DELAY = 30
    BEFORE_PING_DELAY = 15
    WAKE_COUNTER_DELAY = 5

    DUT_MAC = "00:17:b6:a1:a2:a3"
    DUT_IPs4 = ["192.168.0.3", "192.168.0.4", "192.168.0.5"]
    DUT_IPs6 = ["4000:0000:0000:0000:1601:bd17:0c02:2403",
                "4000:0000:0000:0000:1601:bd17:0c02:2413",
                "4000:0000:0000:0000:1601:bd17:0c02:2423",
                "4000:0000:0000:0000:1601:bd17:0c02:2433",
                "4000:0000:0000:0000:1601:bd17:0c02:2443"]
    LKP_IP4 = "192.168.0.24"
    NETMASK_IP4 = "255.255.255.0"
    LKP_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2402"
    PREFIX_IP6 = "64"
    WAKEPORT = 13370

    SLEEP_PROXY_FLAG_NO_WOL = 0
    SLEEP_PROXY_FLAG_MAGIC_PACKET = 2
    SLEEP_PROXY_FLAG_LINK_UP = 4
    SLEEP_PROXY_FLAG_LINK_DOWN = 8


    @classmethod
    def setup_class(cls):
        super(TestFWUsbWoL, cls).setup_class()

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

            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()

            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()
            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4, cls.NETMASK_IP4, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6, cls.PREFIX_IP6, None)

        except Exception as e:
            log.exception(e)
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestFWUsbWoL, cls).teardown_class()
        # Put wol on LKP back
        cmd = "sudo ethtool -s {} wol g".format(cls.lkp_iface)
        disable_cmd = Command(cmd=cmd)
        disable_cmd.run_join(10)

    def setup_method(self, method):
        super(TestFWUsbWoL, self).setup_method(method)

        if not self.is_host_alive_and_ready(self.dut_hostname):
            raise Exception("DUT is not online, can't perform test")

        if not self.dut_driver.is_installed():
            self.dut_driver.install()

    def teardown_method(self, method):
        super(TestFWUsbWoL, self).teardown_method(method)
        self.bring_host_online(self.dut_hostname)

    def hibernate_dut(self, retry_interval=15):
        log.info("Hibernating DUT")
        self.dut_power.hibernate()
        if not self.poll_host_powered_off(self.dut_hostname, retry_interval=retry_interval):
            raise Exception("Couldn't hibernate DUT")
        log.info("DUT is hibernated")

    def test_magic_packet_only(self):
        """
        @description: Perform check that firmware wake up DUT after magic packet received.

        @steps:
        1. Setup autoneg link speed.
        2. Configure wol structure with only mac address and flag magic pkt enabled. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via magic packet.

        @result: FW detect magic packet and DUT wake up.
        @duration: 120 seconds.
        """
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_pactool.set_link_speed(LINK_SPEED_AUTO)
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed != LINK_SPEED_NO_LINK

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
        eth_cfg.ipv4Count = 0
        for i in range(len(eth_cfg.ipv4)):
            eth_cfg.ipv4[i] = 0
        eth_cfg.ipv6Count = 0
        for j in range(len(eth_cfg.ipv6)):
            for i in range(len(eth_cfg.ipv6[j].ipv6)):
                eth_cfg.ipv6[j].ipv6[i] = 0
        data = eth_cfg.get_data()
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_SLEEP_PROXY,
                                              data="{}".format(data), size=len(data))
        time.sleep(5)
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS,
                                              data=[0, 0, USB_SLEEP_PROXY | USB_POWER, 0], size=4)
        log.info('Wol for wake on magic packet is configured')
        time.sleep(5)
        # Link should be UP on link partner
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed == self.supported_speeds[0]

        self.run_dut_hibernate()
        log.info("Sending magic packet")
        self.lkp_scapy_tools.send_raw_magic_packet(self.DUT_MAC)
        self.check_dut_after_wake_up("magic packet")

    def run_test_on_link_change(self, wol_bit, link_state, new_link_state, link_speed=LINK_SPEED_AUTO):
        # Put wol on LKP down so it up 100M in low power mode
        real_speed = link_speed if link_speed != LINK_SPEED_AUTO else self.supported_speeds[-1]

        if real_speed not in self.supported_speeds:
            pytest.xfail()

        cmd = "sudo ethtool -s {} wol d".format(self.lkp_iface)
        disable_cmd = Command(cmd=cmd, host=self.lkp_hostname)
        disable_cmd.run_join(10)

        self.lkp_ifconfig.set_link_state(link_state)
        if link_state == LINK_STATE_DOWN:
            assert self.lkp_ifconfig.wait_link_down() == LINK_SPEED_NO_LINK
        else:
            self.dut_pactool.set_link_speed(link_speed)
            assert self.lkp_ifconfig.wait_link_up() == self.supported_speeds[0]

        eth_cfg = DrvUsbConfig()
        dut_mac_address = [int(m, 16) for m in self.DUT_MAC.split(":")]
        wol_bit = wol_bit
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
        eth_cfg.ipv4Count = 0
        for i in range(len(eth_cfg.ipv4)):
            eth_cfg.ipv4[i] = 0
        eth_cfg.ipv6Count = 0
        for j in range(len(eth_cfg.ipv6)):
            for i in range(len(eth_cfg.ipv6[j].ipv6)):
                eth_cfg.ipv6[j].ipv6[i] = 0
        data = eth_cfg.get_data()
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_SLEEP_PROXY,
                                              data="{}".format(data), size=len(data))
        time.sleep(5)
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS,
                                              data=[0, 0, USB_SLEEP_PROXY | USB_POWER, 0], size=4)
        log.info('Wol for wake on link down is configured')
        # Link should be UP on link partner
        if link_state == LINK_STATE_DOWN:
            assert self.lkp_ifconfig.wait_link_down() == LINK_SPEED_NO_LINK
        else:
            assert self.lkp_ifconfig.wait_link_up() == self.supported_speeds[0]

        self.hibernate_dut()

        time.sleep(self.AFTER_TURNOFF_DELAY)
        if self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        log.info("DUT is still hibernated after {} seconds of sleeping".format(self.AFTER_TURNOFF_DELAY))

        if link_state == LINK_STATE_DOWN:
            assert self.lkp_ifconfig.wait_link_down() == LINK_SPEED_NO_LINK, "DUT up link after hibernation"
        else:
            assert self.lkp_ifconfig.wait_link_up() != LINK_SPEED_NO_LINK, "DUT dropped link after hibernation"

        log.info("Put link state {} to wake up DUT".format(new_link_state))
        self.lkp_ifconfig.set_link_state(new_link_state)
        if link_state == LINK_STATE_DOWN:
            self.check_dut_after_wake_up("link change from state {} to state {}".format(link_state, new_link_state))
        else:
            self.check_dut_after_wake_up("link change from state {} \
with link speed {} to state {}".format(link_state, link_speed, new_link_state))

    def test_wake_on_link_up(self):
        """
        @description: Perform check that firmware wake up DUT after link change from link down to link up.

        @steps:
        1. Put link to down state.
        2. Configure wol structure with mac address, flag magic pkt and flag link up are enabled. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via link up.

        @result: FW detect link change and DUT wake up.
        @duration: 120 seconds.
        """
        wol_bit = self.SLEEP_PROXY_FLAG_MAGIC_PACKET | self.SLEEP_PROXY_FLAG_LINK_UP
        self.run_test_on_link_change(wol_bit=wol_bit, link_state=LINK_STATE_DOWN, new_link_state=LINK_STATE_UP)

    def test_100M_wake_on_link_down(self):
        """
        @description: Perform check that firmware wake up DUT after link change from 100M link to link down.

        @steps:
        1. Up 100M link.
        2. Configure wol structure with mac address, flag magic pkt and flag link up are enabled. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via link up.

        @result: FW detect link change and DUT wake up.
        @duration: 120 seconds.
        """
        wol_bit = self.SLEEP_PROXY_FLAG_MAGIC_PACKET | self.SLEEP_PROXY_FLAG_LINK_DOWN
        self.run_test_on_link_change(wol_bit=wol_bit, link_state=LINK_STATE_UP, new_link_state=LINK_STATE_DOWN,
                                     link_speed=LINK_SPEED_100M)

    def test_1G_wake_on_link_down(self):
        """
        @description: Perform check that firmware wake up DUT after link change from 1G link to link down.

        @steps:
        1. Up 1G link.
        2. Configure wol structure with mac address, flag magic pkt and flag link up are enabled. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via link up.

        @result: FW detect link change and DUT wake up.
        @duration: 120 seconds.
        """
        wol_bit = self.SLEEP_PROXY_FLAG_MAGIC_PACKET | self.SLEEP_PROXY_FLAG_LINK_DOWN
        self.run_test_on_link_change(wol_bit=wol_bit, link_state=LINK_STATE_UP, new_link_state=LINK_STATE_DOWN,
                                     link_speed=LINK_SPEED_1G)

    def test_2_5G_wake_on_link_down(self):
        """
        @description: Perform check that firmware wake up DUT after link change from 2.5G link to link down.

        @steps:
        1. Up 2.5G link.
        2. Configure wol structure with mac address, flag magic pkt and flag link up are enabled. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via link up.

        @result: FW detect link change and DUT wake up.
        @duration: 120 seconds.
        """
        wol_bit = self.SLEEP_PROXY_FLAG_MAGIC_PACKET | self.SLEEP_PROXY_FLAG_LINK_DOWN
        self.run_test_on_link_change(wol_bit=wol_bit, link_state=LINK_STATE_UP, new_link_state=LINK_STATE_DOWN,
                                     link_speed=LINK_SPEED_2_5G)

    def test_5G_wake_on_link_down(self):
        """
        @description: Perform check that firmware wake up DUT after link change from 5G link to link down.

        @steps:
        1. Up 5G link.
        2. Configure wol structure with mac address, flag magic pkt and flag link up are enabled. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via link up.

        @result: FW detect link change and DUT wake up.
        @duration: 120 seconds.
        """
        wol_bit = self.SLEEP_PROXY_FLAG_MAGIC_PACKET | self.SLEEP_PROXY_FLAG_LINK_DOWN
        self.run_test_on_link_change(wol_bit=wol_bit, link_state=LINK_STATE_UP, new_link_state=LINK_STATE_DOWN,
                                     link_speed=LINK_SPEED_5G)

    def run_dut_hibernate(self):
        self.hibernate_dut()
        time.sleep(self.AFTER_TURNOFF_DELAY)
        if self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT came back online spuriously before test")
        log.info("DUT is still hibernated after {} seconds of sleeping".format(self.AFTER_TURNOFF_DELAY))
        assert self.lkp_ifconfig.wait_link_up() != LINK_SPEED_NO_LINK, "DUT dropped link after hibernation"
        time.sleep(self.BEFORE_PING_DELAY)

    def check_dut_after_wake_up(self, filter_name):
        time.sleep(self.LED_TIMEOUT)
        if not self.is_host_powered_on(self.dut_hostname):
            raise Exception("DUT didn't light up power LED after {}".format(filter_name))
        log.info("DUT turned on after {}".format(filter_name))
        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("DUT didn't come back from hibernate after {}".format(filter_name))
        log.info("DUT woke up after {}".format(filter_name))

    def test_win_iface_1_filter(self):
        """
        @description: Perform check that firmware wake up DUT after pattern received.

        @steps:
        1. Up autoneg link speed.
        2. Configure wol structure with mask and crc for arp request. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via arp request.

        @result: FW receive arp request and DUT wake up.
        @duration: 120 seconds.
        """
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_pactool.set_link_speed(LINK_SPEED_AUTO)
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed != LINK_SPEED_NO_LINK

        eth_cfg = DrvUsbConfig()
        wol_bit = self.SLEEP_PROXY_FLAG_NO_WOL
        addr = [int(m) for m in self.DUT_IPs4[0].split(".")]
        ip_v4_addresses = [addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24]
        data = 0
        for i in range(len(eth_cfg.mac_octets)):
            eth_cfg.mac_octets[i] = 0
        eth_cfg.flags = wol_bit

        # ARP who has 192.168.0.3
        mask = [0x00, 0x30, 0x03, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        crc = 0x1479

        eth_cfg.wolPatternCount = 1
        for j in range(eth_cfg.wolPatternCount):
            for i in range(len(mask)):
                eth_cfg.wolPatterns[j].mask[i] = mask[i]
            eth_cfg.wolPatterns[j].crc16 = crc
            eth_cfg.wolPatterns[j].crc32 = 0
        for j in range(eth_cfg.wolPatternCount + 1, len(eth_cfg.wolPatterns)):
            for i in range(len(eth_cfg.wolPatterns[j].mask)):
                eth_cfg.wolPatterns[j].mask[i] = 0
            eth_cfg.wolPatterns[j].crc16 = 0
            eth_cfg.wolPatterns[j].crc32 = 0
        eth_cfg.linkUpTimeout = 0
        eth_cfg.linkDownTimeout = 0
        eth_cfg.ipv4Count = len(ip_v4_addresses)
        for i in range(eth_cfg.ipv4Count):
            eth_cfg.ipv4[i] = ip_v4_addresses[i]
            log.info(eth_cfg.ipv4[i])
        for i in range(eth_cfg.ipv4Count + 1, len(eth_cfg.ipv4)):
            eth_cfg.ipv4[i] = 0
        eth_cfg.ipv6Count = 0
        for j in range(len(eth_cfg.ipv6)):
            for i in range(len(eth_cfg.ipv6[j].ipv6)):
                eth_cfg.ipv6[j].ipv6[i] = 0
        data = eth_cfg.get_data()
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_SLEEP_PROXY,
                                              data="{}".format(data), size=len(data))
        time.sleep(5)
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS,
                                              data=[0, 0, USB_SLEEP_PROXY | USB_POWER, 0], size=4)
        log.info('Wol for wake on magic packet is configured')
        # Link should be UP on link partner
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed == self.supported_speeds[0]

        self.run_dut_hibernate()
        log.info("Sending ARP request from LKP")
        self.lkp_scapy_tools.arping(dstip=self.DUT_IPs4[0], srcip=self.LKP_IP4, dstmac=self.DUT_MAC,
                                    srcmac=self.lkp_mac, iface=None)
        self.check_dut_after_wake_up(filter_name="ARP request from LKP")

    def configure_win_iface_all_filters(self):
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_pactool.set_link_speed(LINK_SPEED_AUTO)
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed != LINK_SPEED_NO_LINK

        eth_cfg = DrvUsbConfig()
        wol_bit = self.SLEEP_PROXY_FLAG_NO_WOL
        addr = [int(m) for m in self.DUT_IPs4[0].split(".")]
        ip_v4_addresses = [addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24]
        data = 0
        for i in range(len(eth_cfg.mac_octets)):
            eth_cfg.mac_octets[i] = 0
        eth_cfg.flags = wol_bit

        # ARP who has 192.168.0.3
        mask_1 = [0x00, 0x30, 0x03, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        crc_1 = 0x1479
        # IPv4 TCP SYN anyone
        mask_2 = [0x00, 0x70, 0x80, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        crc_2 = 0x6f98
        # IPv6 TCP SYN anyone
        mask_3 = [0x00, 0x70, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        crc_3 = 0x7e53
        # Ping echo request to 192.168.0.3
        mask_4 = [0x00, 0x70, 0x80, 0xc0, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        crc_4 = 0x5830
        # Ping echo IPv6 request to 4000:0000:0000:0000:1601:bd17:0c02:2403
        mask_5 = [0x00, 0x70, 0x10, 0x00, 0xc0, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        crc_5 = 0x9c06
        # NS for 4000:0000:0000:0000:1601:bd17:0c02:2403
        mask_6 = [0x00, 0x70, 0x10, 0x00, 0xc0, 0xff, 0x7f, 0xc0, 0xff, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        crc_6 = 0x2e60
        # IPv4 UDP with port 13370
        mask_7 = [0x00, 0x70, 0x80, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        crc_7 = 0xfb90
        # IPv6 UDP with port 13370
        mask_8 = [0x00, 0x70, 0x10, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        crc_8 = 0x3280
        mask = [mask_1, mask_2, mask_3, mask_4, mask_5, mask_6, mask_7, mask_8]
        crc = [crc_1, crc_2, crc_3, crc_4, crc_5, crc_6, crc_7, crc_8]

        eth_cfg.wolPatternCount = len(mask)
        for j in range(len(mask)):
            for i in range(len(mask[j])):
                eth_cfg.wolPatterns[j].mask[i] = mask[j][i]
            eth_cfg.wolPatterns[j].crc16 = crc[j]
            eth_cfg.wolPatterns[j].crc32 = 0
        eth_cfg.linkUpTimeout = 0
        eth_cfg.linkDownTimeout = 0
        eth_cfg.ipv4Count = len(ip_v4_addresses)
        for i in range(eth_cfg.ipv4Count):
            eth_cfg.ipv4[i] = ip_v4_addresses[i]
            log.info(eth_cfg.ipv4[i])
        for i in range(eth_cfg.ipv4Count + 1, len(eth_cfg.ipv4)):
            eth_cfg.ipv4[i] = 0
        eth_cfg.ipv6Count = 0
        for j in range(len(eth_cfg.ipv6)):
            for i in range(len(eth_cfg.ipv6[j].ipv6)):
                eth_cfg.ipv6[j].ipv6[i] = 0
        data = eth_cfg.get_data()
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_SLEEP_PROXY,
                                              data="{}".format(data), size=len(data))
        time.sleep(5)
        self.dut_pactool.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS,
                                              data=[0, 0, USB_SLEEP_PROXY | USB_POWER, 0], size=4)
        log.info('Wol for wake on magic packet is configured')
        # Link should be UP on link partner
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed == self.supported_speeds[0]

    def test_win_iface_v4tcp_syn_filter(self):
        """
        @description: Perform check that firmware wake up DUT after different pattern received.

        @steps:
        1. Up autoneg link speed.
        2. Configure wol structure with 8(full configuration) mask and crc. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via ipv4 tcp syn pattern.

        @result: FW receive packet and DUT wake up.
        @duration: 600 seconds.
        """
        self.configure_win_iface_all_filters()
        filter_name = "IPv4 TCP SYN anyone"
        self.run_dut_hibernate()
        log.info("Checking filter #1: {}".format(filter_name))
        self.lkp_scapy_tools.wake_on_port(dstip=self.DUT_IPs4[0], srcip=self.LKP_IP4, dstmac=self.DUT_MAC, dport=12345,
                                          protocol="tcp", srcmac=self.lkp_mac, iface=self.lkp_scapy_iface)
        self.check_dut_after_wake_up(filter_name)

    def test_win_iface_v6tcp_syn_filter(self):
        """
        @description: Perform check that firmware wake up DUT after different pattern received.

        @steps:
        1. Up autoneg link speed.
        2. Configure wol structure with 8(full configuration) mask and crc. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via ipv6 tcp syn pattern.

        @result: FW receive packet and DUT wake up.
        @duration: 600 seconds.
        """
        self.configure_win_iface_all_filters()
        filter_name = "IPv6 TCP SYN anyone"
        self.run_dut_hibernate()
        log.info("Checking filter #2: {}".format(filter_name))
        self.lkp_scapy_tools.wake_on_port(dstip=self.DUT_IPs6[0], srcip=self.LKP_IP6, dstmac=self.DUT_MAC, dport=12345,
                                          protocol="tcp", srcmac=self.lkp_mac, iface=self.lkp_scapy_iface)
        self.check_dut_after_wake_up(filter_name)

    def test_win_iface_ping_filter(self):
        """
        @description: Perform check that firmware wake up DUT after different pattern received.

        @steps:
        1. Up autoneg link speed.
        2. Configure wol structure with 8(full configuration) mask and crc. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via ping pattern.

        @result: FW receive packet and DUT wake up.
        @duration: 600 seconds.
        """
        self.configure_win_iface_all_filters()
        filter_name = "Ping echo request to 192.168.0.3"
        self.run_dut_hibernate()
        log.info("Checking filter #3: {}".format(filter_name))
        self.lkp_scapy_tools.ping(dstip=self.DUT_IPs4[0], srcip=self.LKP_IP4, dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                  number=1, iface=self.lkp_scapy_iface)
        self.check_dut_after_wake_up(filter_name)

    def test_win_iface_v6ping_filter(self):
        """
        @description: Perform check that firmware wake up DUT after different pattern received.

        @steps:
        1. Up autoneg link speed.
        2. Configure wol structure with 8(full configuration) mask and crc. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via ipv6 ping pattern.

        @result: FW receive packet and DUT wake up.
        @duration: 600 seconds.
        """
        self.configure_win_iface_all_filters()
        filter_name = "Ping echo IPv6 request to 4000:0000:0000:0000:1601:bd17:0c02:2403"
        self.run_dut_hibernate()
        log.info("Checking filter #4: {}".format(filter_name))
        self.lkp_scapy_tools.ping(dstip=self.DUT_IPs6[0], srcip=self.LKP_IP6, dstmac=self.DUT_MAC, srcmac=self.lkp_mac,
                                  number=1, iface=self.lkp_scapy_iface)
        self.check_dut_after_wake_up(filter_name)

    def test_win_iface_arp_filter(self):
        """
        @description: Perform check that firmware wake up DUT after different pattern received.

        @steps:
        1. Up autoneg link speed.
        2. Configure wol structure with 8(full configuration) mask and crc. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via arp pattern.

        @result: FW receive packet and DUT wake up.
        @duration: 600 seconds.
        """
        self.configure_win_iface_all_filters()
        filter_name = "ARP who has 192.168.0.3"
        self.run_dut_hibernate()
        log.info("Checking filter #5: {}".format(filter_name))
        self.lkp_scapy_tools.arping(dstip=self.DUT_IPs4[0], srcip=self.LKP_IP4, dstmac=self.DUT_MAC,
                                    srcmac=self.lkp_mac, iface=self.lkp_scapy_iface)
        self.check_dut_after_wake_up(filter_name)

    def test_win_iface_ns_filter(self):
        """
        @description: Perform check that firmware wake up DUT after different pattern received.

        @steps:
        1. Up autoneg link speed.
        2. Configure wol structure with 8(full configuration) mask and crc. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via ns pattern.

        @result: FW receive packet and DUT wake up.
        @duration: 600 seconds.
        """
        self.configure_win_iface_all_filters()
        filter_name = "NS for 4000:0000:0000:0000:1601:bd17:0c02:2403"
        self.run_dut_hibernate()
        log.info("Checking filter #6: {}".format(filter_name))
        self.lkp_scapy_tools.arping(dstip=self.DUT_IPs6[0], srcip=self.LKP_IP6, dstmac=self.DUT_MAC,
                                    srcmac=self.lkp_mac, iface=self.lkp_scapy_iface)
        self.check_dut_after_wake_up(filter_name)

    def test_win_iface_v4udp_filter(self):
        """
        @description: Perform check that firmware wake up DUT after different pattern received.

        @steps:
        1. Up autoneg link speed.
        2. Configure wol structure with 8(full configuration) mask and crc. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via ipv4 udp pattern.

        @result: FW receive packet and DUT wake up.
        @duration: 600 seconds.
        """
        self.configure_win_iface_all_filters()
        filter_name = "IPv4 UDP with port 13370"
        self.run_dut_hibernate()
        log.info("Checking filter #7: {}".format(filter_name))
        self.lkp_scapy_tools.wake_on_port(dstip=self.DUT_IPs4[0], srcip=self.LKP_IP4, dstmac=self.DUT_MAC,
                                          dport=self.WAKEPORT, protocol="udp", srcmac=self.lkp_mac,
                                          iface=self.lkp_scapy_iface)
        self.check_dut_after_wake_up(filter_name)

    def test_win_iface_v6udp_filter(self):
        """
        @description: Perform check that firmware wake up DUT after different pattern received.

        @steps:
        1. Up autoneg link speed.
        2. Configure wol structure with 8(full configuration) mask and crc. Setup sleep proxy bit.
        3. Check that 100M link speed is up.
        4. Hibernate DUT.
        5. Wake up DUT via ipv6 udp pattern.

        @result: FW receive packet and DUT wake up.
        @duration: 600 seconds.
        """
        self.configure_win_iface_all_filters()
        filter_name = "IPv6 UDP with port 13370"
        self.run_dut_hibernate()
        log.info("Checking filter #8: {}".format(filter_name))
        self.lkp_scapy_tools.wake_on_port(dstip=self.DUT_IPs6[0], srcip=self.LKP_IP6, dstmac=self.DUT_MAC,
                                          dport=self.WAKEPORT, protocol="udp", srcmac=self.lkp_mac,
                                          iface=self.lkp_scapy_iface)
        self.check_dut_after_wake_up(filter_name)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
