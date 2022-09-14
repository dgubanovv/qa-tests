import os
import random
import time
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import pytest

from hlh.register import Register
from infra.test_base import TestBase, idparametrize
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.atltoolper import AtlTool
from tools.ctypes_struct_helper import dump_struct_log
from tools.constants import ENABLE, DISABLE, OFFLOADS_STATE_DSBL, OFFLOADS_STATE_TX, OFFLOADS_STATE_RX, \
    OFFLOADS_STATE_TX_RX, MTU_1500
from tools.command import Command
from tools.fw_a2_drv_iface_cfg import HOST_MODE_ACTIVE, SleepProxyOffload, \
    HOST_MODE_INVALID, HOST_MODE_SLEEP_PROXY, FirmwareA2Config
from tools.ifconfig import LINK_SPEED_100M, LINK_SPEED_AUTO, LINK_SPEED_NO_LINK, LINK_STATE_UP, LINK_STATE_DOWN, \
    KNOWN_LINK_SPEEDS
from tools.scapy_tools import ScapyTools
from tools.sniffer import Sniffer
from tools.utils import get_atf_logger, get_bus_dev_func
from scapy.all import Ether, IP, IPv6, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, Raw

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_ping_proxy"


class TestA2FWPingProxy(TestBase):
    DUT_MAC_ADDR = "00:17:b6:00:07:82"
    FW_REMOTE_MAC = "00:17:b6:33:44:91"

    FW_LOCAL_IP4 = [
        "169.254.23.11", "169.254.23.12", "169.254.23.13", "169.254.23.14",
        "169.254.23.15", "169.254.23.16", "169.254.23.17", "169.254.23.18"
    ]

    FW_REMOTE_IP4 = "169.254.23.21"

    FW_LOCAL_IP6 = [
        "4000:0000:0000:0000:1601:bd17:0c02:2403", "4000:0000:0000:0000:1601:bd17:0c02:2404",
        "4000:0000:0000:0000:1601:bd17:0c02:2405", "4000:0000:0000:0000:1601:bd17:0c02:2406",
        "4000:0000:0000:0000:1601:bd17:0c02:2407", "4000:0000:0000:0000:1601:bd17:0c02:2408",
        "4000:0000:0000:0000:1601:bd17:0c02:2409", "4000:0000:0000:0000:1601:bd17:0c02:2410",
        "4000:0000:0000:0000:1601:bd17:0c02:2411", "4000:0000:0000:0000:1601:bd17:0c02:2412",
        "4000:0000:0000:0000:1601:bd17:0c02:2413", "4000:0000:0000:0000:1601:bd17:0c02:2414",
        "4000:0000:0000:0000:1601:bd17:0c02:2415", "4000:0000:0000:0000:1601:bd17:0c02:2416",
        "4000:0000:0000:0000:1601:bd17:0c02:2417", "4000:0000:0000:0000:1601:bd17:0c02:2418"
    ]

    FW_REMOTE_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2503"

    @classmethod
    def setup_class(cls):
        super(TestA2FWPingProxy, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", host=cls.dut_hostname,
                                    drv_type=DRV_TYPE_DIAG)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.FW_REMOTE_IP4, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.FW_REMOTE_IP6, cls.PREFIX_IPV6, None)

            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.fw_config = FirmwareA2Config(cls.atltool_wrapper)

            cls.lkp_mac_addr = cls.lkp_ifconfig.get_mac_address()
            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()
            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestA2FWPingProxy, self).setup_method(method)
        self.atltool_wrapper.kickstart2()

    def test_ipv4_offload(self):
        """
        @description: Check ipv4 datapath in Sleep Proxy mode.

        @steps:
        1. Configure Sleep Proxy offloads.
        2. Put FW to Sleep Proxy mode.
        3. Check ipv4 datapath by ping from LKP.

        @result: Ping is passed.
        @duration: 2 minutes.
        """
        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.arp_responder = True
        sp_cfg.ipv4_offload.echo_responder = True
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        for address in sp_cfg.ipv4_offload.ipv4:
            assert self.ping(self.lkp_hostname, address, 16, ipv6=False, src_addr=self.FW_REMOTE_IP4), \
                "Failed to ping {} from {}".format(address, self.FW_REMOTE_IP4)

    def test_ipv4_wrong_mac(self):
        """
        @description: Check ipv4 datapath with fake MAC address.

        @steps:
        1. Configure Sleep Proxy offloads.
        2. Put FW to Sleep Proxy mode.
        3. Send ICMP packets with wrong MAC address from LKP.

        @result: No reply on ICMP packets.
        @duration: 2 minutes.
        """
        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.echo_responder = True
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        pkt = Ether(dst="00:17:B6:43:21:65", src=self.lkp_mac_addr) / \
            IP(dst=sp_cfg.ipv4_offload.ipv4[0], src=self.FW_REMOTE_IP4) / ICMP(type="echo-request")
        sniffer = Sniffer(port=self.lkp_port, timeout=5, count=1, filter="ether dst {}".format(self.lkp_mac_addr),
                          host=self.lkp_hostname)
        sniffer.run_async(iface=self.lkp_scapy_iface)
        time.sleep(5)
        self.lkp_scapy_tools.send_packet(pkt, iface=self.lkp_scapy_iface)
        packets = sniffer.join(5)

        assert len(packets) == 0, "FW answered on echo request with fake MAC address"

    def test_ipv6_offload(self):
        """
        @description: Check ipv6 datapath in Sleep Proxy mode.

        @steps:
        1. Configure Sleep Proxy offloads.
        2. Put FW to Sleep Proxy mode.
        3. Check ipv6 datapath by ping from LKP.

        @result: Ping is passed.
        @duration: 2 minutes.
        """
        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv6_offload.ns_responder = True
        sp_cfg.ipv6_offload.echo_responder = True
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        self.lkp_ifconfig.set_ipv6_address(self.FW_REMOTE_IP6, self.PREFIX_IPV6, None)

        for address in sp_cfg.ipv6_offload.ipv6:
            assert self.ping(self.lkp_hostname, address, 16, ipv6=True, src_addr=self.FW_REMOTE_IP6), \
                "Failed to ping {} from {}".format(address, self.FW_REMOTE_IP6)

    def test_ipv6_wrong_mac(self):
        """
        @description: Check ipv6 datapath with fake MAC address.

        @steps:
        1. Configure Sleep Proxy offloads.
        2. Put FW to Sleep Proxy mode.
        3. Send ICMPv6 packets with wrong MAC address from LKP.

        @result: No reply on ICMPv6 packets.
        @duration: 2 minutes.
        """
        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv6_offload.echo_responder = True
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        pkt = Ether(dst="00:17:B6:02:03:04", src=self.lkp_mac_addr) / \
            IPv6(dst=sp_cfg.ipv6_offload.ipv6[0], src=self.FW_REMOTE_IP6) / ICMPv6EchoRequest(id=0x0001)
        sniffer = Sniffer(port=self.lkp_port, timeout=5, count=1, filter="ether dst {}".format(self.lkp_mac_addr),
                          host=self.lkp_hostname)
        sniffer.run_async(iface=self.lkp_scapy_iface)
        time.sleep(5)
        self.lkp_scapy_tools.send_packet(pkt, iface=self.lkp_scapy_iface)
        packets = sniffer.join(5)

        assert len(packets) == 0, "FW answered on echo request with fake MAC address"

    def test_ignore_fragmented_ipv4(self):
        """
        @description: Check that FW is able to answer on fragmented pings.

        @steps:
        1. Configure Sleep Proxy offloads.
        2. Put FW to Sleep Proxy mode.
        3. Send fragmented ICMP packets from LKP.
        4. Configure Sleep Proxy offloads with ignore_fragmented enagled.
        5. Send fragmented ICMP packets from LKP.

        @result: FW answers on ICMP.
        @duration: 2 minutes.
        """
        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.arp_responder = True
        sp_cfg.ipv4_offload.echo_responder = True
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        # Check that FW is able to answer on fragmented pings
        packet = ScapyTools.get_echo_request_packet(srcmac=self.lkp_mac_addr, dstip=sp_cfg.ipv4_offload.ipv4[0],
                                                    srcip=self.FW_REMOTE_IP4, dstmac=self.DUT_MAC_ADDR, size=250)
        fragments = ScapyTools.fragment_packet(packet, 200)
        sniffer = Sniffer(port=self.lkp_port, timeout=3, count=1, filter="ether dst {}".format(self.lkp_mac_addr),
                          host=self.lkp_hostname)
        sniffer.run_async(iface=self.lkp_scapy_iface)
        time.sleep(1)
        self.lkp_scapy_tools.send_packet(fragments[0], iface=self.lkp_scapy_iface)
        packets = sniffer.join(5)

        assert len(packets) == 1, "Firmware didn't answer on fragmented ping"

        # Check that FW doesn't answer on fragmented pings with ignoreFragmented enabled
        link_control = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.operatingMode = HOST_MODE_INVALID
        self.fw_config.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.fw_config.confirm_shared_buffer_write()

        sp_cfg.ipv4_offload.ignore_fragmented = True

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR)
        self.lkp_ifconfig.wait_link_up()

        for address in sp_cfg.ipv4_offload.ipv4:
            packet = ScapyTools.get_echo_request_packet(srcmac=self.lkp_mac_addr, dstip=address,
                                                        srcip=self.FW_REMOTE_IP4, dstmac=self.DUT_MAC_ADDR, size=250)
            fragments = ScapyTools.fragment_packet(packet, 200)
            sniffer = Sniffer(port=self.lkp_port, timeout=3, count=1, filter="ether dst {}".format(self.lkp_mac_addr),
                              host=self.lkp_hostname)
            sniffer.run_async(iface=self.lkp_scapy_iface)
            time.sleep(1)
            self.lkp_scapy_tools.send_packet(fragments[0], iface=self.lkp_scapy_iface)
            packets = sniffer.join(5)
            assert len(packets) == 0, "Firmware answered on fragmented ping"

    def test_echo_truncate_ipv4(self):
        """
        @description: Check that FW is able to answer on pings with ipv4 echo trancated.

        @steps:
        1. Configure Sleep Proxy offloads.
        2. Put FW to Sleep Proxy mode.
        3. Send ICMP packets from LKP.
        4. Check answer from DUT.

        @result: FW answers on ICMP.
        @duration: 2 minutes.
        """
        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.arp_responder = True
        sp_cfg.ipv4_offload.echo_responder = True
        sp_cfg.ipv4_offload.echo_truncate = True
        sp_cfg.ipv4_offload.echo_max_len = random.randint(16, 32)
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        for address in sp_cfg.ipv4_offload.ipv4:
            packet = ScapyTools.get_echo_request_packet(srcmac=self.lkp_mac_addr, dstip=address,
                                                        srcip=self.FW_REMOTE_IP4, dstmac=self.DUT_MAC_ADDR, size=200)
            sniffer = Sniffer(port=self.lkp_port, timeout=3, count=1, filter="ether dst {}".format(self.lkp_mac_addr),
                              host=self.lkp_hostname)
            sniffer.run_async(iface=self.lkp_scapy_iface)
            time.sleep(1)
            self.lkp_scapy_tools.send_packet(packet, iface=self.lkp_scapy_iface)
            packets = sniffer.join(5)
            assert len(packets) == 1, "Firmware didn't answered fragmented ping"
            assert len(packets[0][Raw]) == sp_cfg.ipv4_offload.echo_max_len, "Payload length is incorrect"

    def test_echo_truncate_ipv6(self):
        """
        @description: Check that FW is able to answer on pings with ipv6 echo trancated.

        @steps:
        1. Configure Sleep Proxy offloads.
        2. Put FW to Sleep Proxy mode.
        3. Send ICMPv6 packets from LKP.
        4. Check answer from DUT.

        @result: FW answers on ICMPv6.
        @duration: 2 minutes.
        """
        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv6_offload.ns_responder = True
        sp_cfg.ipv6_offload.echo_responder = True
        sp_cfg.ipv6_offload.echo_truncate = True
        sp_cfg.ipv6_offload.echo_max_len = random.randint(16, 32)
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        for address in sp_cfg.ipv6_offload.ipv6:
            packet = ScapyTools.get_echo_request_packet(srcmac=self.lkp_mac_addr, dstip=address,
                                                        srcip=self.FW_REMOTE_IP6, dstmac=self.DUT_MAC_ADDR, size=200)
            sniffer = Sniffer(port=self.lkp_port, timeout=3, count=1, filter="ether dst {}".format(self.lkp_mac_addr),
                              host=self.lkp_hostname)
            sniffer.run_async(iface=self.lkp_scapy_iface)
            time.sleep(1)
            self.lkp_scapy_tools.send_packet(packet, iface=self.lkp_scapy_iface)
            packets = sniffer.join(5)
            assert len(packets) == 1, "Firmware didn't answered fragmented ping"
            assert len(packets[0][ICMPv6EchoReply].data) == sp_cfg.ipv6_offload.echo_max_len, \
                "Payload length is incorrect"

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
            sp_cfg = SleepProxyOffload()
            sp_cfg.ipv4_offload.arp_responder = True
            sp_cfg.ipv4_offload.echo_responder = True
            sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4
            # sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

            self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
            self.lkp_ifconfig.wait_link_up()

            for address in sp_cfg.ipv4_offload.ipv4:
                assert self.ping(self.lkp_hostname, address, 16, ipv6=False, src_addr=self.FW_REMOTE_IP4,
                                 payload_size=500, margin=20), \
                    "Failed to ping {} from {}".format(address, self.FW_REMOTE_IP4)

            # TODO: Linux won't let setting IPv6 to an interface with MTU lower than 1280
            # for address in sp_cfg.ipv6_offload.ipv6:
            #     assert self.ping(self.lkp_hostname, address, 16, ipv6=True, src_addr=self.FW_REMOTE_IP6,
            #                      payload_size=500, margin=20), \
            #         "Failed to ping {} from {}".format(address, self.FW_REMOTE_IP6)

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
        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.arp_responder = True
        sp_cfg.ipv4_offload.echo_responder = True
        sp_cfg.ipv4_offload.echo_truncate = True
        sp_cfg.ipv4_offload.echo_max_len = 32
        sp_cfg.ipv4_offload.ipv4 = self.FW_LOCAL_IP4

        sp_cfg.ipv6_offload.ns_responder = True
        sp_cfg.ipv6_offload.echo_responder = True
        sp_cfg.ipv6_offload.echo_truncate = True
        sp_cfg.ipv6_offload.echo_max_len = 32
        sp_cfg.ipv6_offload.ipv6 = self.FW_LOCAL_IP6

        self.fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR, os.path.join(self.test_log_dir, "config.txt"))
        self.lkp_ifconfig.wait_link_up()

        self.lkp_ifconfig.set_ipv6_address(self.FW_REMOTE_IP6, self.PREFIX_IPV6, None)

        for address in sp_cfg.ipv4_offload.ipv4:
            assert self.ping(self.lkp_hostname, address, 16, ipv6=False, src_addr=self.FW_REMOTE_IP4,
                             payload_size=4000, margin=10), \
                "Failed to ping {} from {}".format(address, self.FW_REMOTE_IP4)

        for address in sp_cfg.ipv6_offload.ipv6:
            assert self.ping(self.lkp_hostname, address, 16, ipv6=True, src_addr=self.FW_REMOTE_IP6,
                             payload_size=4000, margin=10), \
                "Failed to ping {} from {}".format(address, self.FW_REMOTE_IP6)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
