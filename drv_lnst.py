import os
import time
import random
import pytest

from tools.atltoolper import AtlTool
from tools.ops import OpSystem
from tools.tracepoint import Tracepoint
from infra.test_base import TestBase
from tools.driver import Driver
from tools.utils import get_atf_logger
from tools.constants import LINK_STATE_UP, LINK_SPEED_AUTO, DIRECTION_RX, DIRECTION_TX, SPEED_TO_MBITS, \
    FELICITY_CARDS, CARD_FIJI
log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_lnst"


class TestDrvLnst(TestBase):
    L3L4_LOCATION = 32
    ETHERTYPE_LOCATION = 16
    VLAN_LOCATION = 0

    def setup_class(cls):
        super(TestDrvLnst, cls).setup_class()
        try:
            # Self protection, the test is implemented only for Linux
            assert OpSystem().is_linux()
            assert OpSystem(host=cls.lkp_hostname).is_linux()

            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            if cls.dut_fw_card not in CARD_FIJI:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            if cls.dut_atltool_wrapper.is_secure_chips() and cls.dut_ops.is_linux():
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, flashless_fw=cls.dut_fw_version)
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.dut_ifconfig.wait_link_up()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def teardown_method(self):
        self.dut_ifconfig.delete_vlan_ifaces()
        self.lkp_ifconfig.delete_vlan_ifaces()

    def test_vlan_rx(self):
        if self.lkp_fw_card in FELICITY_CARDS or self.dut_fw_card in FELICITY_CARDS:
            speed = self.supported_speeds[-1]
        else:
            speed = LINK_SPEED_AUTO
        vlan_id = random.randint(1, 99)
        dut_ip = "192.167.10.1"
        lkp_ip = "192.167.10.2"
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
        trace = Tracepoint(timeout=8, direction=DIRECTION_RX, name="atlantic")
        trace.run_async()
        time.sleep(1)
        assert self.ping(from_host=self.lkp_hostname, to_host=dut_ip, number=3, src_addr=lkp_ip)
        time.sleep(3)
        descr = trace.join()
        vlan_tci = -1
        vlan = -1
        for i in descr:
            if i['direction'] == 'rx_skb':
                if i['vlan_tci'] & 0x0fff == vlan_id:
                    vlan_tci = i['vlan_tci']
            if i['direction'] == 'rx':
                if i['vlan_tag'] == vlan_id:
                    vlan = i['vlan_tag']
        assert vlan_tci != -1 and vlan != -1

    def test_vlan_tx(self):
        if self.lkp_fw_card in FELICITY_CARDS or self.dut_fw_card in FELICITY_CARDS:
            speed = self.supported_speeds[-1]
        else:
            speed = LINK_SPEED_AUTO
        vlan_id = random.randint(1, 99)
        dut_ip = "192.167.10.1"
        lkp_ip = "192.167.10.2"
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
        trace = Tracepoint(timeout=8, direction=DIRECTION_TX, name="atlantic")
        trace.run_async()
        time.sleep(1)
        assert self.ping(from_host=self.dut_hostname, to_host=lkp_ip, number=3, src_addr=dut_ip)
        time.sleep(3)
        descr = trace.join()
        tx_cmd = -1
        vlan = -1
        for i in descr:
            if i['direction'] == 'tx':
                if i['tx_cmd'] & 0x1 == 1:
                    tx_cmd = i['tx_cmd']
            if i['direction'] == 'tx_context':
                if i['vlan_tag'] == vlan_id:
                    vlan = i['vlan_tag']
        assert tx_cmd != -1 and vlan != -1

    def parse_descr_for_rx(self, args):
        trace = Tracepoint(timeout=20, direction=DIRECTION_RX, name="atlantic")
        trace.run_async()
        time.sleep(2)
        self.run_iperf(**args)
        time.sleep(4)
        descr = trace.join()
        csum_level = 0
        ip_summed = 0
        for i in descr:
            if i['direction'] == "rx_skb":
                if i['csum_level'] == 1:
                    csum_level = 1
                if i['ip_summed'] == 1:
                    ip_summed = 1
        assert csum_level == 1 and ip_summed == 1

    def parse_descr_for_tx(self, args):
        trace = Tracepoint(timeout=20, direction=DIRECTION_TX, name="atlantic")
        trace.run_async()
        time.sleep(2)
        self.run_iperf(**args)
        time.sleep(4)
        descr = trace.join()
        tx_cmd = 0
        for i in descr:
            if i['direction'] == "tx":
                if (i['tx_cmd'] & 0x8) == 0x8:
                    tx_cmd = 1
        assert tx_cmd == 1

    def test_cso_tcp_rx(self):
        speed = self.dut_ifconfig.wait_link_up()
        args = {'time': 1,
                'directon': DIRECTION_RX,
                'speed': speed,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': self.LKP_IPV4_ADDR,
                'dut4': self.DUT_IPV4_ADDR}
        self.parse_descr_for_tx(args)

    def test_cso_udp_rx(self):
        speed = self.dut_ifconfig.wait_link_up()
        args = {'time': 3,
                'num_process': 1,
                'num_threads': 1,
                "bandwidth": SPEED_TO_MBITS[speed],
                'is_udp': True,
                'directon': DIRECTION_RX,
                'speed': speed,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': self.LKP_IPV4_ADDR,
                'dut4': self.DUT_IPV4_ADDR}
        self.parse_descr_for_rx(args)

    def test_cso_vlan_tcp_rx(self):
        if self.lkp_fw_card in FELICITY_CARDS or self.dut_fw_card in FELICITY_CARDS:
            speed = self.supported_speeds[-1]
        else:
            speed = LINK_SPEED_AUTO
        vlan_id = random.randint(1, 99)
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
        speed = self.dut_ifconfig.wait_link_up(vlan_id=vlan_id)
        args = {'time': 1,
                'directon': DIRECTION_RX,
                'speed': speed,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': lkp_ip,
                'dut4': dut_ip}
        self.parse_descr_for_rx(args)

    def test_cso_vlan_udp_rx(self):
        if self.lkp_fw_card in FELICITY_CARDS or self.dut_fw_card in FELICITY_CARDS:
            speed = self.supported_speeds[-1]
        else:
            speed = LINK_SPEED_AUTO
        vlan_id = random.randint(1, 99)
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
        speed = self.dut_ifconfig.wait_link_up(vlan_id=vlan_id)
        args = {'time': 3,
                'num_process': 1,
                'num_threads': 1,
                "bandwidth": SPEED_TO_MBITS[speed],
                'is_udp': True,
                'directon': DIRECTION_RX,
                'speed': speed,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': lkp_ip,
                'dut4': dut_ip}
        self.parse_descr_for_rx(args)

    def test_cso_tcp_tx(self):
        speed = self.dut_ifconfig.wait_link_up()
        args = {'time': 1,
                'directon': DIRECTION_TX,
                'speed': speed,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': self.LKP_IPV4_ADDR,
                'dut4': self.DUT_IPV4_ADDR}
        self.parse_descr_for_tx(args)

    def test_cso_udp_tx(self):
        speed = self.dut_ifconfig.wait_link_up()
        args = {'time': 3,
                'num_process': 1,
                'num_threads': 1,
                "bandwidth": SPEED_TO_MBITS[speed],
                'is_udp': True,
                'directon': DIRECTION_TX,
                'speed': speed,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': self.LKP_IPV4_ADDR,
                'dut4': self.DUT_IPV4_ADDR}
        self.parse_descr_for_tx(args)

    def test_cso_vlan_tcp_tx(self):
        if self.lkp_fw_card in FELICITY_CARDS or self.dut_fw_card in FELICITY_CARDS:
            speed = self.supported_speeds[-1]
        else:
            speed = LINK_SPEED_AUTO
        vlan_id = random.randint(1, 99)
        dut_ip = "192.167.10.1"
        lkp_ip = "192.167.10.2"
        netmask = "255.255.255.0"

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.create_vlan_iface(vlan_id)
        self.lkp_ifconfig.create_vlan_iface(vlan_id)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.dut_ifconfig.set_ip_address(dut_ip, netmask, gateway=None, vlan_id=vlan_id)
        self.lkp_ifconfig.set_ip_address(lkp_ip, netmask, gateway=None, vlan_id=vlan_id)
        speed = self.dut_ifconfig.wait_link_up(vlan_id=vlan_id)
        args = {'time': 1,
                'directon': DIRECTION_TX,
                'speed': speed,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': lkp_ip,
                'dut4': dut_ip}
        self.parse_descr_for_tx(args)

    def test_cso_vlan_udp_tx(self):
        if self.lkp_fw_card in FELICITY_CARDS or self.dut_fw_card in FELICITY_CARDS:
            speed = self.supported_speeds[-1]
        else:
            speed = LINK_SPEED_AUTO
        vlan_id = random.randint(1, 99)
        dut_ip = "192.167.10.1"
        lkp_ip = "192.167.10.2"
        netmask = "255.255.255.0"

        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.create_vlan_iface(vlan_id)
        self.lkp_ifconfig.create_vlan_iface(vlan_id)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=vlan_id)
        self.dut_ifconfig.set_ip_address(dut_ip, netmask, gateway=None, vlan_id=vlan_id)
        self.lkp_ifconfig.set_ip_address(lkp_ip, netmask, gateway=None, vlan_id=vlan_id)
        speed = self.dut_ifconfig.wait_link_up(vlan_id=vlan_id)
        args = {'time': 3,
                'num_process': 1,
                'num_threads': 1,
                "bandwidth": SPEED_TO_MBITS[speed],
                'is_udp': True,
                'directon': DIRECTION_TX,
                'speed': speed,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': lkp_ip,
                'dut4': dut_ip}
        self.parse_descr_for_tx(args)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
