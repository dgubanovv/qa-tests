import os

import pytest

from infra.test_base import TestBase
from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, LINK_STATE_UP, CARD_FIJI
from tools.driver import Driver
from tools.ping import ping
from tools.tcpdump import Tcpdump
from tools.command import Command
from tools.utils import get_atf_logger, get_bus_dev_func
from tools.ifconfig import get_macos_network_adapter_name
from tools.scapy_tools import ScapyTools
from scapy.all import Ether, IP, TCP, Dot1Q, Raw

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "vlan"


class TestVlan(TestBase):
    """
    @description: The vlan test is dedicated to check vlan functionality of Linux driver.

    @setup: Two Aquantia devices connected back to back.
    """
    TO_RENAME_IFACE = """
ACTION==\"add\", SUBSYSTEM==\"net\", DRIVERS==\"?*\", ATTR{{address}}==\"{}\", NAME=\"{}\"
    """

    @classmethod
    def setup_class(cls):
        super(TestVlan, cls).setup_class()

        try:
            # Self protection, the test is implemented only for Linux
            assert cls.dut_ops.is_linux() or cls.dut_ops.is_mac() or cls.dut_ops.is_freebsd()
            assert cls.lkp_ops.is_linux() or cls.lkp_ops.is_freebsd()

            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            if cls.dut_fw_card == CARD_FIJI:
                cls.dut_mac = cls.dut_ifconfig.get_mac_address()
                log.info("Rename Fiji adapter interface name")
                bus, dev, func = get_bus_dev_func(cls.dut_port)
                if cls.dut_ops.is_ubuntu():
                    name = "enx{}s{}".format(bus, dev)
                else:
                    if cls.dut_ops.is_mac():
                        name = get_macos_network_adapter_name(cls.dut_port)
                    else:
                        name = "enp{}s{}".format(bus, dev)
                command_dut_cp_to_home = Command(
                    cmd='cp /etc/udev/rules.d/70-persistent-ipoib.rules ~/70-persistent-ipoib.rules')
                command_dut_cp_to_home.run_join(5)
                command_dut_cp_to_tmp = Command(
                    cmd='cp /etc/udev/rules.d/70-persistent-ipoib.rules /tmp/70-persistent-ipoib.rules')
                command_dut_cp_to_tmp.run_join(5)
                with open('/tmp/70-persistent-ipoib.rules', 'a') as f:
                    f.write(cls.TO_RENAME_IFACE.format(cls.dut_mac, name))
                command_dut_cp_to_home = Command(
                    cmd='sudo cp /tmp/70-persistent-ipoib.rules /etc/udev/rules.d/70-persistent-ipoib.rules')
                command_dut_cp_to_home.run_join(5)

            cls.install_firmwares()

            if cls.dut_fw_card not in CARD_FIJI:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            if cls.lkp_fw_card not in CARD_FIJI:
                cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            if cls.dut_fw_card not in CARD_FIJI and cls.dut_atltool_wrapper.is_secure_chips() and cls.dut_ops.is_linux():
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, flashless_fw=cls.dut_fw_version)
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestVlan, cls).teardown_class()
        if cls.dut_fw_card == CARD_FIJI:
            command_dut_cp_name_back = Command(
                cmd='sudo cp ~/70-persistent-ipoib.rules /etc/udev/rules.d/70-persistent-ipoib.rules')
            command_dut_cp_name_back.run_join(5)
            command_rm = Command(
                cmd='rm -rf ~/70-persistent-ipoib.rules')
            command_rm.run_join(5)

    def teardown_method(self, method):
        super(TestVlan, self).teardown_method(method)
        self.dut_ifconfig.delete_vlan_ifaces()
        self.lkp_ifconfig.delete_vlan_ifaces()

    def test_vlan_promisc_mode(self):
        """
        @description: check vlan promiscious mode

        @steps:
        1. check that vlan promiscious mode is enabled
        2. create frst vlan interface
        3. check that vlan promiscious mode is disabled
        4. create 16 vlan interfaces
        5. check that vlan promiscious mode is enabled

        @requirements: DRV_VLAN_1, DRV_VLAN_2, DRV_VLAN_3, DRV_VLAN_4, DRV_VLAN_5

        """
        if self.dut_fw_card == CARD_FIJI:
            pytest.skip("Not implemented for FIJI")
        lkp_scapy_tool = ScapyTools(port=self.lkp_port, host=self.lkp_hostname)
        lkp_scapy_iface = lkp_scapy_tool.get_scapy_iface()
        tcpdump = Tcpdump(host=self.dut_hostname, port=self.dut_port, timeout=20, nopromisc=True)
        dut_mac = self.dut_ifconfig.get_mac_address()
        lkp_mac = self.lkp_ifconfig.get_mac_address()
        netmask = "255.255.255.0"
        ip_dut_base = "192.168.100.1"
        ip_lkp_base = "192.168.100.2"
        self.dut_ifconfig.set_ip_address(ip_dut_base, netmask, self.LKP_IPV4_ADDR)
        self.lkp_ifconfig.set_ip_address(ip_lkp_base, netmask, None)
        self.dut_ifconfig.wait_link_up()
        pkt = Ether(dst=dut_mac, src=lkp_mac) / Dot1Q(vlan=25) / IP(dst=ip_dut_base, src=ip_lkp_base) / TCP(dport=5201, flags='S', seq=0) / Raw("1234567890\x0a" * 5)

        def send_p():
            tcpdump.run_async()
            lkp_scapy_tool.send_packet(pkt=pkt, iface=lkp_scapy_iface)
            packets = tcpdump.join()
            pac = []
            for p in packets:
                if IP in p and p[IP].src == ip_lkp_base and TCP in p and p[TCP].dport == 5201:
                    pac.append(p)
                    break

            return pac
        if not self.dut_ops.is_freebsd():
            # unload module 8021q to enable promiscious vlan
            Command(cmd="rmmod 8021q").run()
            assert len(send_p()) == 1
            Command(cmd="modprobe --first-time 8021q").run()

        for number in range(1, 17):
            log.info("Create {} vlan interface".format(number))
            ip_dut = '192.168.{}.1'.format(number)
            ip_lkp = '192.168.{}.2'.format(number)

            speed = LINK_SPEED_AUTO
            self.dut_ifconfig.set_link_speed(speed)
            self.lkp_ifconfig.set_link_speed(speed)
            self.dut_ifconfig.create_vlan_iface(number)
            self.lkp_ifconfig.create_vlan_iface(number)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=number)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=number)
            self.dut_ifconfig.set_ip_address(ip_dut, netmask, gateway=None, vlan_id=number)
            self.lkp_ifconfig.set_ip_address(ip_lkp, netmask, gateway=None, vlan_id=number)
            self.dut_ifconfig.wait_link_up(vlan_id=number)

            assert ping(number=4, host=ip_lkp, src_addr=ip_dut), 'ping failed'

            if number == 16:
                assert len(send_p()) == 1
            else:
                assert len(send_p()) == 0

    def test_ping(self):
        """
        @description: Perform simple ping check with tagged interfaces.

        @steps:
        1. Create vlan interfaces on both DUT and LKP using vlan id 10.
        2. Send ping via tagged interface
        3. Make sure all pings are answered.

        @result: Ping is passed.
        @duration: 30 seconds.
        """
        speed = LINK_SPEED_AUTO
        vlan_id = 10
        dut_ip = "192.168.10.1"
        lkp_ip = "192.168.10.2"
        netmask = "255.255.255.0"

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.create_vlan_iface(vlan_id)
        self.lkp_ifconfig.create_vlan_iface(vlan_id)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.dut_ifconfig.set_ip_address(dut_ip, netmask, gateway=None, vlan_id=vlan_id)
        self.lkp_ifconfig.set_ip_address(lkp_ip, netmask, gateway=None, vlan_id=vlan_id)
        self.dut_ifconfig.wait_link_up(vlan_id=vlan_id)

        assert ping(number=3, host=lkp_ip, src_addr=dut_ip)

    def test_ping_from_tagged_to_untagged(self):
        """
        @description: Check that traffic is not passed from tagged to untagged interface.

        @steps:
        1. Create vlan interface on DUT with vlan id 11.
        2. Do not create tagged interface on LKP.
        3. Send ping from tagged interface on DUT to untagged on LKP.
        4. Make sure that ping is failed.

        @result: Ping is failed.
        @duration: 30 seconds.
        """
        speed = LINK_SPEED_AUTO
        vlan_id = 11
        dut_ip = "192.168.11.1"
        lkp_ip = "192.168.11.2"
        netmask = "255.255.255.0"

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.create_vlan_iface(vlan_id)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.set_ip_address(dut_ip, netmask, gateway=None, vlan_id=vlan_id)
        self.lkp_ifconfig.set_ip_address(lkp_ip, netmask, gateway=None)
        self.dut_ifconfig.wait_link_up(vlan_id=vlan_id)

        assert not ping(number=3, host=lkp_ip, src_addr=dut_ip)

    def test_ping_several_vlans(self):
        """
        @description: Check that traffic is passed on multiple tagged interfaces.

        @steps:
        1. Create vlan interfaces on DUT and LKP with vlan ids 1 and 2.
        2. Send ping from all tagged interfaces.
        3. Make sure that ping is passed.

        @result: Ping is passed.
        @duration: 30 seconds.
        """
        speed = LINK_SPEED_AUTO
        vlan_id_1 = 1
        vlan_id_2 = 2
        dut_ip_1 = "192.168.1.1"
        dut_ip_2 = "192.168.2.1"
        lkp_ip_1 = "192.168.1.2"
        lkp_ip_2 = "192.168.2.2"
        netmask = "255.255.255.0"

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.create_vlan_iface(vlan_id_1)
        self.dut_ifconfig.create_vlan_iface(vlan_id_2)
        self.lkp_ifconfig.create_vlan_iface(vlan_id_1)
        self.lkp_ifconfig.create_vlan_iface(vlan_id_2)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id_1)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id_2)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id_1)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id_2)
        self.dut_ifconfig.set_ip_address(dut_ip_1, netmask, gateway=None, vlan_id=vlan_id_1)
        self.dut_ifconfig.set_ip_address(dut_ip_2, netmask, gateway=None, vlan_id=vlan_id_2)
        self.lkp_ifconfig.set_ip_address(lkp_ip_1, netmask, gateway=None, vlan_id=vlan_id_1)
        self.lkp_ifconfig.set_ip_address(lkp_ip_2, netmask, gateway=None, vlan_id=vlan_id_2)
        self.dut_ifconfig.wait_link_up(vlan_id=vlan_id_1)
        self.dut_ifconfig.wait_link_up(vlan_id=vlan_id_2)

        assert ping(number=3, host=lkp_ip_1, src_addr=dut_ip_1)
        assert ping(number=3, host=lkp_ip_2, src_addr=dut_ip_2)

    def test_max_vlan(self):
        """
        @description: Check min/max vlan ids.

        @steps:
        1. Try to create vlan ids 0, 4094, 4095.
        2. Make sure that vlans 0, 4094 are created successfully.
        3. Make sure that vlan id 4095 cannot be created.

        @result: Vlans 0-4094 .
        @duration: 30 seconds.
        """

        self.dut_ifconfig.create_vlan_iface(0 if not self.dut_ops.is_freebsd() else 1)
        self.dut_ifconfig.create_vlan_iface(4094 if not self.dut_ops.is_mac() else 4095)
        try:
            self.dut_ifconfig.create_vlan_iface(4095 if not self.dut_ops.is_mac()else 4096)
        except Exception:
            pass
        else:
            raise Exception("Vlan id 4095 is maximal value")

    def test_ping_several_vlans_from_one_to_another(self):
        """
        @description: Check that traffic is passed on multiple tagged interfaces.

        @steps:
        1. Create vlan interfaces on DUT and LKP with vlan ids 111 and 222.
        2. Send ping from 111 vlan to 222.
        3. Send ping from 222 vlan to 111.
        4. Make sure that ping is failed.

        @result: Ping is failed.
        @duration: 30 seconds.
        """
        speed = LINK_SPEED_AUTO
        vlan_id_1 = 111
        vlan_id_2 = 222
        dut_ip_1 = "192.168.111.1"
        dut_ip_2 = "192.168.222.1"
        lkp_ip_1 = "192.168.111.2"
        lkp_ip_2 = "192.168.222.2"
        netmask = "255.255.255.0"

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.create_vlan_iface(vlan_id_1)
        self.dut_ifconfig.create_vlan_iface(vlan_id_2)
        self.lkp_ifconfig.create_vlan_iface(vlan_id_1)
        self.lkp_ifconfig.create_vlan_iface(vlan_id_2)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id_1)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id_2)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id_1)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id_2)
        self.dut_ifconfig.set_ip_address(dut_ip_1, netmask, gateway=None, vlan_id=vlan_id_1)
        self.dut_ifconfig.set_ip_address(dut_ip_2, netmask, gateway=None, vlan_id=vlan_id_2)
        self.lkp_ifconfig.set_ip_address(lkp_ip_1, netmask, gateway=None, vlan_id=vlan_id_1)
        self.lkp_ifconfig.set_ip_address(lkp_ip_2, netmask, gateway=None, vlan_id=vlan_id_2)
        self.dut_ifconfig.wait_link_up(vlan_id=vlan_id_1)
        self.dut_ifconfig.wait_link_up(vlan_id=vlan_id_2)

        assert not ping(number=3, host=lkp_ip_1, src_addr=dut_ip_2)
        assert not ping(number=3, host=lkp_ip_2, src_addr=dut_ip_1)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
