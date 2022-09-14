import os
import pytest
import tools.ping
import time
import numpy
import collections

from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M, \
    DIRECTION_RXTX, DIRECTION_RX, DIRECTION_TX, CARD_FIJI, SPEED_TO_MBITS
from tools.utils import get_atf_logger
from infra.test_base import TestBase
from tools.driver import Driver, DRV_TYPE_CDC
from tools.iptables import IPTables
from perf.nuttcp import Nuttcp

log = get_atf_logger()

FC_OFF = "off"
FC_ON = "on"

SPEEDS = [LINK_SPEED_AUTO, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M]
DIRECTIONS = [DIRECTION_RX, DIRECTION_TX, DIRECTION_RXTX]


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "usb_iperf_throughput"


class TestUsbThroughput(TestBase):
    TMO = 10

    @classmethod
    def setup_class(cls):
        super(TestUsbThroughput, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.install_firmwares()

            if cls.dut_drv_cdc:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, drv_type=DRV_TYPE_CDC)
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)

            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)

            iptables = IPTables(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname)
            iptables.clean()

            if cls.dut_fw_card == CARD_FIJI and cls.dut_ops.is_windows():
                cls.dut_ifconfig.set_advanced_property("LowPower5G", "Disable")
                cls.dut_ifconfig.set_link_down()
                cls.dut_ifconfig.set_link_up()
                cls.dut_ifconfig.wait_link_up()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def run_nuttcp(self, dut_speed, lkp_speed, direction, fc):
        assert dut_speed in SPEEDS
        assert lkp_speed in SPEEDS
        assert direction in DIRECTIONS

        if dut_speed != LINK_SPEED_AUTO and dut_speed not in self.supported_speeds:
            pytest.skip()

        if lkp_speed != LINK_SPEED_AUTO and dut_speed not in self.supported_speeds:
            pytest.skip()

        if fc == FC_OFF:
            self.dut_ifconfig.set_media_options(options_to_set=["full-duplex"])
            self.lkp_ifconfig.set_media_options(["full-duplex"])
        elif fc == FC_ON:
            self.dut_ifconfig.set_media_options(options_to_set=["flow-control", "full-duplex"])
            self.lkp_ifconfig.set_media_options(["full-duplex", "flow-control"])

        if not self.dut_drv_cdc:
            self.dut_ifconfig.set_link_speed(dut_speed)

        self.lkp_ifconfig.set_link_speed(lkp_speed)
        lkp_cur_speed = self.lkp_ifconfig.wait_link_up()

        dut_cur_speed = (self.dut_ifconfig.get_link_speed() if not self.dut_drv_cdc else LINK_SPEED_AUTO)

        if not self.dut_drv_cdc:
            if 'Switch' not in self.platform:
                assert dut_cur_speed == lkp_cur_speed == (lkp_speed if dut_speed != LINK_SPEED_AUTO else self.supported_speeds[-1])
            else:
                assert dut_cur_speed == (dut_speed if dut_speed != LINK_SPEED_AUTO else self.supported_speeds[-1])
                assert lkp_cur_speed == (lkp_speed if lkp_speed != LINK_SPEED_AUTO else self.supported_speeds[-1])
        else:
            assert lkp_cur_speed == (lkp_speed if lkp_speed != LINK_SPEED_AUTO else self.supported_speeds[-1])

        time.sleep(3)
        assert tools.ping.ping(4, self.LKP_IPV4_ADDR, src_addr=self.DUT_IPV4_ADDR, margin=25) is True

        exp_rate = {LINK_SPEED_5G: 3100 if fc == FC_ON else 2300,
                    LINK_SPEED_2_5G: 2000 if fc == FC_ON else 1900,
                    LINK_SPEED_1G: 950 if fc == FC_ON else 900,
                    LINK_SPEED_100M: 95 if fc == FC_ON else 90,
                    LINK_SPEED_AUTO: 3100 if fc == FC_ON else 2300}

        # Expect low traffic on usb 2.0 and cdc
        if self.usb_2_0:
            exp_rate = {LINK_SPEED_1G: 330 if fc == FC_ON else 300,
                        LINK_SPEED_100M: 95 if fc == FC_ON else 90,
                        LINK_SPEED_AUTO: 330 if fc == FC_ON else 300}

        if self.dut_drv_cdc:
            exp_rate = {v: exp_rate[v] * 0.8 for v in exp_rate}

        args = {
         "dut": self.dut_hostname,
         "lkp": self.lkp_hostname,
         "dut4": self.DUT_IPV4_ADDR,
         "lkp4": self.LKP_IPV4_ADDR,
         "time": self.TMO,
         "bandwidth": 0,
         "is_udp": True,
         "direction": direction,
         "buffer_len": 9000 if fc == FC_ON or direction == DIRECTION_TX else 1500,
         "window": "4m"
        }

        n = Nuttcp(**args)
        n.run_async()
        n.join()

        if direction in [DIRECTION_TX, DIRECTION_RX]:
            bands = n.results[0].bandwidth
            lost = n.results[0].lost
        else:
            bands = collections.defaultdict(dict)
            bands['rx']['lost'] = n.results[0].lost
            bands['rx']['band'] = n.results[0].bandwidth

            bands['tx']['lost'] = n.results[1].lost
            bands['tx']['band'] = n.results[1].bandwidth

        msg = '\n'
        msg += '+ PARAMS: -------------------------------------------------------------------------------------- +\n'
        msg += '|  direction: {}\n'.format(direction)
        msg += '|  link: {}\n'.format(dut_speed)
        msg += '|  flow control: {}\n'.format(fc)
        msg += '|  perfomance: {}\n'.format("{}|{}".format(numpy.mean(bands['tx']['band']), numpy.mean(bands['rx']['band'])) \
                   if direction == DIRECTION_RXTX else "{}".format(numpy.mean(bands)))
        msg += '+ ---------------------------------------------------------------------------------------------- +\n'
        log.info(msg)

        if direction == DIRECTION_RXTX:
            if (dut_speed == LINK_SPEED_1G or LINK_SPEED_AUTO) and self.usb_2_0:
                assert bands['rx']['band'] + bands['tx']['band'] > exp_rate, 'Sum of rx and tx bandwidth can not be \
                                                                             less than {}'.format(exp_rate)
            else:
                assert numpy.mean(bands['tx']['band']) >= exp_rate[dut_speed]
                assert numpy.mean(bands['rx']['band']) >= exp_rate[dut_speed] * 0.87
        else:
            assert numpy.mean(bands) >= exp_rate[dut_speed]

    # 5G
    def test_5G_fc_on_tx(self):
        self.run_nuttcp(LINK_SPEED_5G, LINK_SPEED_5G, DIRECTION_TX, FC_ON)

    def test_5G_fc_on_tx_rx(self):
        self.run_nuttcp(LINK_SPEED_5G, LINK_SPEED_5G, DIRECTION_RXTX, FC_ON)

    def test_5G_fc_on_rx(self):
        self.run_nuttcp(LINK_SPEED_5G, LINK_SPEED_5G, DIRECTION_RX, FC_ON)

    def test_5G_fc_off_tx(self):
        self.run_nuttcp(LINK_SPEED_5G, LINK_SPEED_5G, DIRECTION_TX, FC_OFF)

    def test_5G_fc_off_tx_rx(self):
        self.run_nuttcp(LINK_SPEED_5G, LINK_SPEED_5G, DIRECTION_RXTX, FC_OFF)

    def test_5G_fc_off_rx(self):
        self.run_nuttcp(LINK_SPEED_5G, LINK_SPEED_5G, DIRECTION_RX, FC_OFF)

    # 2.5G
    def test_2_5G_fc_on_tx(self):
        self.run_nuttcp(LINK_SPEED_2_5G, LINK_SPEED_2_5G, DIRECTION_TX, FC_ON)

    def test_2_5G_fc_on_tx_rx(self):
        self.run_nuttcp(LINK_SPEED_2_5G, LINK_SPEED_2_5G, DIRECTION_RXTX, FC_ON)

    def test_2_5G_fc_on_rx(self):
        self.run_nuttcp(LINK_SPEED_2_5G, LINK_SPEED_2_5G, DIRECTION_RX, FC_ON)

    def test_2_5G_fc_off_tx(self):
        self.run_nuttcp(LINK_SPEED_2_5G, LINK_SPEED_2_5G, DIRECTION_TX, FC_OFF)

    def test_2_5G_fc_off_tx_rx(self):
        self.run_nuttcp(LINK_SPEED_2_5G, LINK_SPEED_2_5G, DIRECTION_RXTX, FC_OFF)

    def test_2_5G_fc_off_rx(self):
        self.run_nuttcp(LINK_SPEED_2_5G, LINK_SPEED_2_5G, DIRECTION_RX, FC_OFF)

    # 1G
    def test_1G_fc_on_tx(self):
        self.run_nuttcp(LINK_SPEED_1G, LINK_SPEED_1G, DIRECTION_TX, FC_ON)

    def test_1G_fc_on_tx_rx(self):
        self.run_nuttcp(LINK_SPEED_1G, LINK_SPEED_1G, DIRECTION_RXTX, FC_ON)

    def test_1G_fc_on_rx(self):
        self.run_nuttcp(LINK_SPEED_1G, LINK_SPEED_1G, DIRECTION_RX, FC_ON)

    def test_1G_fc_off_tx(self):
        self.run_nuttcp(LINK_SPEED_1G, LINK_SPEED_1G, DIRECTION_TX, FC_OFF)

    def test_1G_fc_off_tx_rx(self):
        self.run_nuttcp(LINK_SPEED_1G, LINK_SPEED_1G, DIRECTION_RXTX, FC_OFF)

    def test_1G_fc_off_rx(self):
        self.run_nuttcp(LINK_SPEED_1G, LINK_SPEED_1G, DIRECTION_RX, FC_OFF)

    # 100m
    def test_100m_fc_on_tx(self):
        self.run_nuttcp(LINK_SPEED_100M, LINK_SPEED_100M, DIRECTION_TX, FC_ON)

    def test_100m_fc_on_tx_rx(self):
        self.run_nuttcp(LINK_SPEED_100M, LINK_SPEED_100M, DIRECTION_RXTX, FC_ON)

    def test_100m_fc_on_rx(self):
        self.run_nuttcp(LINK_SPEED_100M, LINK_SPEED_100M, DIRECTION_RX, FC_ON)

    def test_100m_fc_off_tx(self):
        self.run_nuttcp(LINK_SPEED_100M, LINK_SPEED_100M, DIRECTION_TX, FC_OFF)

    def test_100m_fc_off_tx_rx(self):
        self.run_nuttcp(LINK_SPEED_100M, LINK_SPEED_100M, DIRECTION_RXTX, FC_OFF)

    def test_100m_fc_off_rx(self):
        self.run_nuttcp(LINK_SPEED_100M, LINK_SPEED_100M, DIRECTION_RX, FC_OFF)

    # AUTO
    def test_auto_fc_on_tx_rx(self):
        self.run_nuttcp(LINK_SPEED_AUTO, LINK_SPEED_AUTO, DIRECTION_RXTX, FC_ON)

    def test_auto_fc_off_tx_rx(self):
        self.run_nuttcp(LINK_SPEED_AUTO, LINK_SPEED_AUTO, DIRECTION_RXTX, FC_OFF)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
