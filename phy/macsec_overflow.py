import copy
import os
import sys
import time
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from hlh.mac import MAC
from hlh.phy import PHY
from infra.test_base import idparametrize
from infra.test_base_phy import TestBasePhy
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G
from tools.constants import DIRECTION_RX, DIRECTION_TX, MTU_9000, MTU_1500, ENABLE, ENABLE_LINK, DISABLE
from tools.driver import Driver
from tools.killer import Killer
from perf.iperf import Iperf
from perf.iperf_result import IperfResult
from tools.iptables import IPTables
from tools.log import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "phy_macsec_overflow"


class TestPhyMacsecOverflow(TestBasePhy):
    # NORMAL_XON = 0x1000
    # NORMAL_XOFF = 0x2000

    SMALL_XON = 0x0
    SMALL_XOFF = 0x1

    @classmethod
    def setup_class(cls):
        super(TestPhyMacsecOverflow, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

            cls.IPERF_ARGS = {
                'direction': None,
                'speed': None,
                'num_threads': 1,
                'num_process': 2,
                'buffer_len': 0,
                'mss': 0,
                'ipv': 4,
                'criterion': IperfResult.SANITY,
                'bandwidth': 10000,
                'dut': cls.dut_hostname,
                'lkp': cls.lkp_hostname,
                'dut4': cls.DUT_IPV4_ADDR,
                'lkp4': cls.LKP_IPV4_ADDR,
                'time': 20,
                'is_udp': True
            }

            cls.iptables = IPTables(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname)
            cls.iptables.clean()

            cls.dut_phy = PHY(phy_control=cls.phy_controls[0])
            cls.dut_mac = MAC(port=cls.dut_port, host=cls.dut_hostname)

            cls.lkp_phy = PHY(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_mac = MAC(port=cls.lkp_port, host=cls.lkp_hostname)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestPhyMacsecOverflow, self).setup_method(method)
        Killer().kill("iperf3")
        Killer(host=self.lkp_hostname).kill("iperf3")

    def run_test_fifo_overflow_traffic_restoration(self, speed, direction, mtu, restore_timeout):
        self.dut_phy.set_security_bit(speed=speed, state=ENABLE)

        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu)

        self.dut_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.wait_link_up()

        assert speed == self.dut_ifconfig.wait_link_up()
        assert speed == self.lkp_ifconfig.wait_link_up()

        if direction == DIRECTION_RX:
            self.dut_mac.set_flow_control(state=ENABLE_LINK)
            self.dut_mac.set_pause_frames_threshold(xon=self.SMALL_XON, xoff=self.SMALL_XOFF)
            self.lkp_mac.set_flow_control(state=DISABLE)
        else:
            self.lkp_mac.set_flow_control(state=ENABLE_LINK)
            self.lkp_mac.set_pause_frames_threshold(xon=self.SMALL_XON, xoff=self.SMALL_XOFF)
            self.dut_mac.set_flow_control(state=DISABLE)

        self.dut_phy.set_flow_control(state=DISABLE)
        self.lkp_phy.set_flow_control(state=DISABLE)

        if direction == DIRECTION_RX:
            self.dut_phy.set_fc_egress_processing(state=ENABLE)
            self.dut_phy.set_fc_ingress_processing(state=DISABLE)
        else:
            self.dut_phy.set_fc_egress_processing(state=DISABLE)
            self.dut_phy.set_fc_ingress_processing(state=ENABLE)

        time.sleep(3)

        for i in range(3):
            Killer(host=self.dut_hostname).kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")

            iperf_args = copy.deepcopy(self.IPERF_ARGS)
            iperf_args["speed"] = speed
            iperf_args["direction"] = direction

            iperf_runner = Iperf(**iperf_args)
            iperf_runner.run()
            results = iperf_runner.get_performance()

            is_ok = True
            log.info("Server result:")
            for res in results:
                log.info(res)
                is_ok = False if res is None else is_ok

            if is_ok:
                break

        assert is_ok, "Failed several times run IPERF"

        self.dut_mac.set_pause_frames_generate_mode(state=DISABLE)
        time.sleep(restore_timeout)

        for i in range(3):
            Killer(host=self.dut_hostname).kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")

            iperf_runner = Iperf(**iperf_args)
            iperf_runner.run()
            results = iperf_runner.get_performance()

            is_ok = True
            log.info("Server result:")
            for res in results:
                log.info(res)
                is_ok = False if res is None else is_ok
                if is_ok:
                    res.check()
                    is_ok = is_ok if all([b > 50 for b in res.bandwidth]) else False

        assert is_ok, "Failed several times run IPERF"

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    @idparametrize("mode", ['sif_to_line', 'line_to_sif'])
    @idparametrize("mtu", [MTU_1500, MTU_9000])
    def test_overflow_traffic(self, speed, mode, mtu):
        if speed not in self.supported_speeds:
            pytest.skip()
        direction = DIRECTION_TX if mode == 'sif_to_line' else DIRECTION_RX
        self.run_test_fifo_overflow_traffic_restoration(speed, direction, mtu, 60)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
