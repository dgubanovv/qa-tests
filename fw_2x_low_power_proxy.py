import os
import shutil
import time
import timeit

import pytest

from tools.atltoolper import AtlTool
from tools.constants import FELICITY_CARDS, LINK_SPEED_AUTO
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvMessage, DrvEthConfig, OffloadIpInfo, DrvWinWoLConfig
from tools.scapy_tools import ScapyTools
from tools.samba import Samba
from tools.utils import get_atf_logger

from infra.test_base import TestBase
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_low_power_proxy"


class TestLowPowerSleep(TestBase):
    """
    @description: The low power sleep proxy test is dedicated to verify low power MAC/PHY state. The test is based
    on the ability of firmware control power gating of several internal chip components.

    @setup: Two Aquantia devices connected back to back.
    """

    AFTER_LINK_UP_DELAY = 45

    DUT_IPs4 = ["192.168.0.3",
                "192.168.0.4",
                "192.168.0.5"]
    LKP_IP4 = "192.168.0.2"
    NETMASK_IP4 = "255.255.255.0"
    MULTICAST_IP4 = "192.168.0.255"

    DUT_IPs6 = ["4000:0000:0000:0000:1601:bd17:0c02:2403",
                "4000:0000:0000:0000:1601:bd17:0c02:2413",
                "4000:0000:0000:0000:1601:bd17:0c02:2423",
                "4000:0000:0000:0000:1601:bd17:0c02:2433",
                "4000:0000:0000:0000:1601:bd17:0c02:2443",
                "4000:0000:0000:0000:1601:bd17:0c02:2453",
                "4000:0000:0000:0000:1601:bd17:0c02:2463"]
    LKP_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2402"
    PREFIX_IP6 = "64"

    DUT_MAC = "00:17:b6:00:07:82"

    @classmethod
    def setup_class(cls):
        super(TestLowPowerSleep, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4, cls.NETMASK_IP4, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6, cls.PREFIX_IP6, None)

            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()

            cls.atltool_wrapper = AtlTool(port=cls.dut_port)

            # Disable Samba to remove background multicast traffic which affects SerDes
            Samba(host=cls.lkp_hostname).stop()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestLowPowerSleep, cls).teardown_class()

    def setup_method(self, method):
        super(TestLowPowerSleep, self).setup_method(method)
        if self.dut_firmware.is_3x():
            # FW 3X requires kickstart after each configuration
            self.atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestLowPowerSleep, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        if self.MCP_LOG:
            self.atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

    def get_serdes_status(self):
        sys_iface_status = self.atltool_wrapper.readphyreg(0x4, 0xE812)
        sys_iface = (sys_iface_status & 0xF8) >> 3
        log.info("System Interface in Use: {}".format(sys_iface))
        return sys_iface != 9

    def test_serdes_is_up_60_secs_wol_win_iface(self):
        """
        @description: Check that serdes is up 60 seconds after link up in sleep proxy.

        @steps:
        1. Configure simple offload (MAC address only).
        2. Wait for link UP using PHY register.
        3. Read serdes status and check for how long it is up.

        @result: Serdes must be up for at least 54 seconds (60 seconds measurement error).
        """
        maj_ver, _, _ = self.atltool_wrapper.get_fw_version()

        log.info("Configuring offloads")
        eth_cfg = DrvEthConfig()

        eth_cfg.version = 0
        eth_cfg.len = 0x407  # not used
        eth_cfg.mac = self.DUT_MAC
        eth_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY
        eth_cfg.ips = OffloadIpInfo()

        eth_cfg.apply(self.atltool_wrapper, cleanup_fw=True)
        time.sleep(0.5)

        log.info("Configuring wake on lan")
        wol_cfg = DrvWinWoLConfig()

        wol_cfg.mac = self.DUT_MAC
        wol_cfg.magic_enabled = True
        wol_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | DrvMessage.CAPS_HI_WOL

        wol_cfg.apply(self.atltool_wrapper, cleanup_fw=False)
        time.sleep(1)

        log.info("Waiting for link up by reading Autoneg Status register")
        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time < 10.0:
            autoneg_status = self.atltool_wrapper.readphyreg(0x7, 0xC810)
            conn_state = (autoneg_status & 0x3E00) >> 9
            if conn_state == 4:
                log.info("Link is up at {}".format(self.lkp_ifconfig.get_link_speed()))
                break
            time.sleep(0.2)
        else:
            raise Exception("Sleep proxy didn't come up")

        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time < 54.0:
            if self.get_serdes_status() is False:
                if maj_ver == 3:
                    log.error("Serdes up time: {} seconds".format(timeit.default_timer() - start_time))
                    pytest.fail("FW 3.x didn't hold serdes for 60 seconds after sleep proxy link up")
                else:
                    log.info("FW {}.x held serdes {} seconds after sleep proxy link up".format(
                        maj_ver, timeit.default_timer() - start_time))
                    break
            time.sleep(0.2)
        log.info("Serdes uptime: {} seconds", timeit.default_timer() - start_time)

        time.sleep(10)
        assert self.get_serdes_status() is False, "Serdes didn't turn off after 60 seconds"
        log.info("Serdes turned off after 60 seconds")

    def test_ping_ipv4(self):
        """
        @description: This subtest performs low power state verification with IPv4 offloads.

        @steps:
        1. Configure IPv4 offloads.
        2. Wait for link UP.
        3. Make sure that SERDES is turned off.
        4. Send small ping requests.
        5. Make sure that SERDES is still turned off.
        6. Send big ping requests (513 bytes).
        7. Make sure that SERDES is turned ON.
        8. Sleep 15 seconds.
        9. Make sure that SERDES is turned off.

        @result: Small pings are answered, some of big ping reqests are not answered (due to turning SERDES on),
        SERDES is turned off if there are no big packets on line, SERDES is turned on after receiving packets with
        size more than 512 bytes.
        @duration: 3 minutes.
        """

        cfg = DrvEthConfig()
        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC

        ips = OffloadIpInfo()
        ips.v4_addr_count = len(self.DUT_IPs4)
        ips.v4_addresses = self.DUT_IPs4
        ips.v4_masks = [24] * len(self.DUT_IPs4)
        cfg.ips = ips
        log.info('Configuring IPv4 addresses: {}'.format(ips.v4_addresses))

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_ipv4.txt")
        cfg.apply(self.atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        log.info("Checking that SerDes is turned off")
        assert self.get_serdes_status() is False

        # verify IPv4 Offload
        for address in ips.v4_addresses:
            log.info('Ping from {} to {} ...'.format(self.lkp_hostname, address))
            assert self.ping(self.lkp_hostname, address, 10, ipv6=False, src_addr=self.LKP_IP4) is True

        log.info("Checking that SerDes is still turned off")
        assert self.get_serdes_status() is False

        log.info("Ping DUT with 557 packet size")
        # Total length was changed up to design
        # Payload size should be 557 - 14 (ethernet header) - 20 (IPv4 header) - 8 (ICMP header)
        self.ping(self.lkp_hostname, ips.v4_addresses[0], 10, ipv6=False, payload_size=557 - 14 - 20 - 8)

        log.info("Checking that SerDes is turned on")
        assert self.get_serdes_status() is True

        log.info("Sleeping 15 sec...")
        time.sleep(15)

        log.info("Checking SerDes is turned off")
        assert self.get_serdes_status() is False

    def test_ping_ipv6(self):
        """
        @description: This subtest performs low power state verification with IPv6 offloads.

        @steps:
        1. Configure IPv6 offloads.
        2. Wait for link UP.
        3. Make sure that SERDES is turned off.
        4. Send small ping requests.
        5. Make sure that SERDES is still turned off.
        6. Send big ping requests (513 bytes).
        7. Make sure that SERDES is turned ON.
        8. Sleep 15 seconds.
        9. Make sure that SERDES is turned off.

        @result: Small pings are answered, some of big ping reqests are not answered (due to turning SERDES on),
        SERDES is turned off if there are no big packets on line, SERDES is turned on after receiving packets with
        size more than 512 bytes.
        @duration: 3 minutes.
        """

        cfg = DrvEthConfig()
        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC

        ips = OffloadIpInfo()
        ips.v6_addr_count = len(self.DUT_IPs6)
        ips.v6_addresses = self.DUT_IPs6
        ips.v6_masks = [64] * len(self.DUT_IPs6)
        cfg.ips = ips
        log.info('Configuring IPv6 addresses: {}'.format(ips.v6_addresses))

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_ipv6.txt")
        cfg.apply(self.atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        log.info("Checking that SerDes is turned off")
        assert self.get_serdes_status() is False

        # verify IPv6 Offload
        for address in ips.v6_addresses:
            log.info('Ping from {} to {} ...'.format(self.lkp_hostname, address))
            assert self.ping(self.lkp_hostname, address, 10, ipv6=True, src_addr=self.LKP_IP6) is True

        log.info("Checking that SerDes is still turned off")
        assert self.get_serdes_status() is False

        log.info("Ping DUT with 557 packet size")
        # Total length was changed up to design
        # Payload size should be 557 - 14 (ethernet header) - 40 (IPv6 header) - 8 (ICMPv6 header)
        self.ping(self.lkp_hostname, ips.v6_addresses[0], 10, ipv6=True, payload_size=557 - 14 - 40 - 8)

        log.info("Checking that SerDes is turned on")
        assert self.get_serdes_status() is True

        log.info("Sleeping 15 sec...")
        time.sleep(15)

        log.info("Checking SerDes is turned off")
        assert self.get_serdes_status() is False

    def test_datapath_control(self):
        """
        @description: This subtest checks MDIO datapath control bit.

        @steps:
        1. Configure IP offload with MDIO datapath control bit set.
        2. Wait for link UP.
        3. Make sure that SERDES is turned on.
        4. Make sure ping works.

        @result: SerDes is always turned on, FW answers on ping requests.
        @duration: 3 minutes.
        """
        cfg = DrvEthConfig()
        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC
        cfg.flags = DrvEthConfig.FLAG_DATAPATH_CONTROL

        cfg.ips = OffloadIpInfo()
        cfg.ips.v4_addr_count = 1
        cfg.ips.v4_addresses = self.DUT_IPs4[:1]
        cfg.ips.v4_masks = [24]
        cfg.ips.v6_addr_count = 1
        cfg.ips.v6_addresses = self.DUT_IPs6[:1]
        cfg.ips.v6_masks = [64]

        beton_file = os.path.join(self.test_log_dir, "offload_datapath_control.txt")
        cfg.apply(self.atltool_wrapper, beton_file)

        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

        log.info("Checking that SerDes is turned on")
        assert self.get_serdes_status() is True

        for address in cfg.ips.v4_addresses:
            log.info("Ping {} from {}".format(address, self.lkp_hostname))
            assert self.ping(self.lkp_hostname, address, 10, ipv6=False, src_addr=self.LKP_IP4) is True
        for address in cfg.ips.v6_addresses:
            log.info("Ping {} from {}".format(address, self.lkp_hostname))
            assert self.ping(self.lkp_hostname, address, 10, ipv6=True, src_addr=self.LKP_IP6) is True


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
