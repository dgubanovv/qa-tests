import os
import re

import pytest

from infra.test_base import TestBase
from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import DIRECTION_TX, DIRECTION_RX
from tools.driver import Driver
from tools.utils import get_atf_logger
from tools.ping import ping

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_forwarding_rings"


class TestDrvForwardingRings(TestBase):
    """
    @description: The FWD ring test.

    @setup: Two Aquantia devices connected back to back.
    """

    HEAD_RX_0_REG = 0x5b0c
    HEADS_RX = []
    for i in range(32):
        HEADS_RX.append(HEAD_RX_0_REG + 0x20 * i)

    HEAD_TX_0_REG = 0x7c0c
    HEADS_TX = []
    for i in range(32):
        HEADS_TX.append(HEAD_TX_0_REG + 0x40 * i)

    def setup_class(cls):
        super(TestDrvForwardingRings, cls).setup_class()
        try:
            assert "forwarding" in cls.dut_drv_version
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, make_args="CONFIG_ATLFWD_FWD=y")
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.dut_ifconfig.wait_link_up()

            cls.dut_atltool = AtlTool(port=cls.dut_port)
            cls.lkp_atltool = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.permissions_file_fwdtool()
            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()

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
                'dut4': cls.LKP_IPV4_ADDR
            }

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @staticmethod
    def permissions_file_fwdtool():
        res = Command(cmd="sudo chmod 777 /x/qa/linux/aqpkt/atlfwdtool").run()
        if res["returncode"] != 0:
            raise Exception("Fwdtool failed")

    def request_ring(self, direction, ring_size, buffer_size, page_order, host):
        # usually page_order = 1
        ring_index = None
        dir_map = {DIRECTION_TX: 1, DIRECTION_RX: 0}
        res = Command(cmd="sudo atlfwdtool request_ring {} {} {} {}".format(dir_map[direction], ring_size, buffer_size,
                                                                            page_order), host=host).run()
        if res["returncode"] != 0:
            raise Exception("Failed to create fwd ring")
        for line in res["output"]:
            re_cnt = re.compile(r" *Ring index: ([0-9]+)", re.DOTALL)
            m = re_cnt.match(line)
            if m is not None:
                ring_index = m.group(1)
        assert ring_index is not None
        return ring_index

    def enable_ring(self, ring_index, host):
        res = Command(
            cmd="sudo atlfwdtool -v enable_ring {}".format(ring_index), host=host).run()
        if res["returncode"] != 0:
            raise Exception("Failed to enable fwd ring")

    def release_ring(self, ring_index, host):
        res = Command(
            cmd="sudo atlfwdtool -v release_ring {}".format(ring_index), host=host).run()
        if res["returncode"] != 0:
            raise Exception("Failed to release fwd ring")

    def force_tx_fwd(self, ring_index, host):
        res = Command(
            cmd="sudo atlfwdtool -v force_tx_via {}".format(ring_index), host=host).run()
        if res["returncode"] != 0:
            raise Exception("Failed to force via fwd ring")

    def force_rx_fwd(self, rx_queue, ip, host):
        res = Command(
            cmd="sudo ethtool -U enp1s0 flow-type ip4 dst-ip {} queue {} loc 39".format(ip, rx_queue), host=host).run()
        if res["returncode"] != 0:
            raise Exception("Failed to force in fwd ring")

    def disable_redirections(self, host):
        res = Command(
            cmd="sudo atlfwdtool -v disable_redirections", host=host).run()
        if res["returncode"] != 0:
            raise Exception("Failed to disable redirections")

    def disable_ring(self, ring_index, host):
        res = Command(
            cmd="sudo atlfwdtool -v disable_ring {}".format(ring_index), host=host).run()
        if res["returncode"] != 0:
            raise Exception("Failed to disable fwd ring")

    def get_rx_queue_index(self, ring_index, host):
        res = Command(
            cmd="atlfwdtool get_rx_queue_index {}".format(ring_index), host=host).run()
        if res["returncode"] != 0:
            raise Exception("Failed to get rx queue index")
        rx_queue = res["output"][0]
        return int(rx_queue)

    def get_tx_queue_index(self, ring_index, host):
        res = Command(
            cmd="atlfwdtool get_tx_queue_index {}".format(ring_index), host=host).run()
        if res["returncode"] != 0:
            raise Exception("Failed to get tx queue index")
        tx_queue = res["output"][0]
        return int(tx_queue)

    def request_event(self, ring_index, host):
        res = Command(cmd="sudo atlfwdtool request_event {}".format(ring_index), host=host).run()
        if res["returncode"] != 0:
            raise Exception("Failed to request event")

    def release_event(self, ring_index, host):
        res = Command(cmd="sudo atlfwdtool release_event {}".format(ring_index), host=host).run()
        if res["returncode"] != 0:
            raise Exception("Failed to release event")

    def test_without_fwd_ring(self):
        """
        @description: Check that FWD ring disabled by default.

        @steps:
        1. Read counters before traffic run.
        2. Starting ping.
        3. Read counters after traffic run.
        4. Check that traffic does not go through fwd ring.

        @result: Counter values are correct.
        @requirements: DRV_FWD_RINGS_3
        @duration: 10 seconds.
        """
        counters_prev = self.dut_statistics.get_drv_counters()
        assert ping(number=4, host=self.LKP_IPV4_ADDR, src_addr=self.DUT_IPV4_ADDR)
        counters_curr = self.dut_statistics.get_drv_counters()
        for k in counters_curr.keys():
            if k == "tx_packets":
                assert counters_prev[k] < counters_curr[k], "Packet was sent via fwd ring or not sent at all"
            if "tx_packets" in k and "fwd" in k:
                assert counters_prev[k] == counters_curr[k], "Traffic was sent through fwd ring"

    def test_ping_tx_fwd_ring(self):
        """
        @description: Check that fwd ring is turned on and traffic sent via fwd ring.

        @steps:
        1. Request ring.
        2. Enable ring.
        3. Force traffic via fwd ring.
        4. Read counters and head pointer before traffic run.
        5. Starting TCP traffic.
        6. Read counters and head pointer after traffic run.
        7. Check that traffic go through fwd ring.

        @result: Counter values are correct.
        @requirements: DRV_FWD_RINGS_1, DRV_FWD_RINGS_4, DRV_FWD_RINGS_7, DRV_FWD_RINGS_9
        @duration: 10 seconds.
        """
        ring_index = self.request_ring(DIRECTION_TX, 4096, 8192, 1, self.dut_hostname)
        self.enable_ring(ring_index, self.dut_hostname)
        self.force_tx_fwd(ring_index, self.dut_hostname)
        tx_queue = self.get_tx_queue_index(ring_index, self.dut_hostname)
        head_prev = self.dut_atltool.readreg(self.HEADS_TX[tx_queue])
        counters_prev = self.dut_statistics.get_drv_counters()
        assert ping(number=4, host=self.LKP_IPV4_ADDR, src_addr=self.DUT_IPV4_ADDR)
        counters_curr = self.dut_statistics.get_drv_counters()
        head_curr = self.dut_atltool.readreg(self.HEADS_TX[tx_queue])
        assert head_prev != head_curr, "Head pointer not change"
        for k in counters_curr.keys():
            if "tx_packets" in k and "fwd" in k:
                assert counters_prev[k] < counters_curr[k], "Traffic sent not through fwd ring"

    def test_disable_fwd_ring(self):
        """
        @description: Check that fwd ring is turned off.

        @steps:
        1. Request ring.
        1. Enable ring.
        2. Force traffic through fwdring.
        3. Disabled fwd ring.
        4. Read counters and head pointer before traffic run.
        5. Starting TCP traffic.
        6. Read counters and head pointer after traffic run.
        7. Check that traffic does not go through fwd ring.

        @result: Counter values are correct.
        @requirements: DRV_FWD_RINGS_5, DRV_FWD_RINGS_9
        @duration: 10 seconds.
        """
        ring_index = self.request_ring(DIRECTION_TX, 4096, 8192, 1, self.dut_hostname)
        self.enable_ring(ring_index, self.dut_hostname)
        self.force_tx_fwd(ring_index, self.dut_hostname)
        tx_queue = self.get_tx_queue_index(ring_index, self.dut_hostname)
        self.disable_redirections(self.dut_hostname)
        self.disable_ring(ring_index, self.dut_hostname)
        head_prev = self.dut_atltool.readreg(self.HEADS_TX[tx_queue])
        counters_prev = self.dut_statistics.get_drv_counters()
        assert ping(number=4, host=self.LKP_IPV4_ADDR, src_addr=self.DUT_IPV4_ADDR)
        head_curr = self.dut_atltool.readreg(self.HEADS_TX[tx_queue])
        assert head_prev == head_curr, "Head pointer change"
        counters_curr = self.dut_statistics.get_drv_counters()
        for k in counters_curr.keys():
            if "tx_packets" in k and "fwd" in k:
                assert counters_prev[k] == counters_curr[k], "Traffic sent through fwd ring"

    def test_ping_rx_fwd_ring(self):
        """
        @description: Check that fwd ring is turned on and traffic received in fwd ring.

        @steps:
        1. Request ring.
        2. Enable ring.
        3. Force traffic in fwdring
        4. Read counters and head pointer  before traffic run.
        5. Starting ping.
        6. Read counters and head pointer after traffic run.
        7. Check that traffic received in fwd ring.

        @result: Counter values are correct.
        @requirements: DRV_FWD_RINGS_2, DRV_FWD_RINGS_4, DRV_FWD_RINGS_6, DRV_FWD_RINGS_9
        @duration: 10 seconds.
        """
        ring_index = self.request_ring(DIRECTION_RX, 4096, 8192, 1, self.dut_hostname)
        self.enable_ring(ring_index, self.dut_hostname)
        rx_queue = self.get_rx_queue_index(ring_index, self.dut_hostname)
        self.force_rx_fwd(rx_queue, self.DUT_IPV4_ADDR, self.dut_hostname)
        head_prev = self.dut_atltool.readreg(self.HEADS_RX[rx_queue])
        counters_prev = self.dut_statistics.get_drv_counters()
        assert self.ping(self.lkp_hostname, self.DUT_IPV4_ADDR, 4, src_addr=self.LKP_IPV4_ADDR)
        counters_curr = self.dut_statistics.get_drv_counters()
        head_curr = self.dut_atltool.readreg(self.HEADS_RX[rx_queue])
        for k in counters_curr.keys():
            if "rx_packets" in k and "fwd" in k:
                assert counters_prev[k] < counters_curr[k], "Traffic sent not through fwd ring"
        assert head_prev != head_curr, "Head pointer not change"

    def test_msi_index_leak(self):
        """
        @description: Check that not allocate MSI index for Head Pointer writeback events.

        @steps:
        1. Request ring.
        2. 32 times Request and release event.
        3. Release ring

        @result: All request, release event and release ring - pass
        @duration: 20 seconds.
        """
        ring_index = self.request_ring(DIRECTION_TX, 64, 4096, 0, self.dut_hostname)
        for i in range(32):
            self.request_event(ring_index, self.dut_hostname)
            self.release_event(ring_index, self.dut_hostname)
        self.release_ring(ring_index, self.dut_hostname)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
