import os
import time
import pytest

import numpy

from tools.command import Command
from tools.constants import LINK_STATE_UP, LINK_STATE_DOWN, USB_CONNECT_CSWITCH

from tools.driver import Driver
from tools.log import get_atf_logger
from tools.ops import OpSystem
from tools.traceview import Traceview
from infra.test_base import TestBase, idparametrize
from tools.usb_control import USBPowerMeterControl

log = get_atf_logger()

SS_ON = "Enable"
SS_OFF = "Disable"

def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "usb_selective_suspend"


class TestUsbSS(TestBase):
    TV_TIMEOUT = 90
    PING_COUNT = 4
    SS_RES = {}

    @classmethod
    def setup_class(cls):
        super(TestUsbSS, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

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

    def ss_handler(self, ss):
        self.dut_ifconfig.set_advanced_property("*SelectiveSuspend", ss)
        self.dut_ifconfig.set_advanced_property("*SSIdleTimeout", "2")

        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()

    def test_ss(self):
        """
        @description: Subtest performs testing of Selective Suspend feature.

        @steps:
        1. Enable SS on DUT.
        2. Check driver log for going host to SS
        3. Send ping.

        @result: SS record is present or not present in log.
        @duration: 10 minutes.
        """

        def run_ss(ss):
            if self.dut_usb_connect == USB_CONNECT_CSWITCH:
                usb_power_meter_control = USBPowerMeterControl()
                usb_power_meter_control.run_async(self.dut_usb_connect, False, self.dut_port, raw=True)

            self.ss_handler(ss)

            tv = Traceview(self.dut_drv_version, self.dut_driver.release_version)
            tv.start()

            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.dut_ifconfig.wait_link_up()

            time.sleep(self.TV_TIMEOUT)
            tv.stop()
            output = tv.parse()

            if ss == SS_ON:
                assert any("HAL> entering Selective Suspend..." in line for line in output)
            else:
                assert not any("HAL> entering Selective Suspend..." in line for line in output)

            assert self.ping(self.lkp_hostname, self.DUT_IPV4_ADDR, self.PING_COUNT)

            if self.dut_usb_connect == USB_CONNECT_CSWITCH:
                currs = usb_power_meter_control.join(self.dut_usb_connect, self.dut_port)
                log.info("MEASUREMENT COUNT AVG: {0:.4f}".format(numpy.mean(currs)))

            self.SS_RES[ss] = numpy.around(numpy.mean(currs), decimals=3)

        run_ss(SS_OFF)
        run_ss(SS_ON)

        assert self.SS_RES[SS_ON] <=  self.SS_RES[SS_OFF], "Bad currents for SS test:\n SS_ON == {}, SS_OFF == {}"\
                                                          .format(self.SS_RES[SS_ON], self.SS_RES[SS_OFF])


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
