import os
import time

import pytest

from perf.iperf_result import IperfResult
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_AUTO, DIRECTION_RX, DIRECTION_TX, DIRECTION_RXTX
from tools.cpu_monitor import CPUMonitor
from tools.driver import Driver, DRV_TYPE_MAC_CDC, DRV_TYPE_LIN_CDC
from perf.ftp import FTP
from tools.iptables import IPTables
from tools.ops import OpSystem
from tools.receive_segment_coalescing import ReceiveSegmentCoalescing
from tools.statistics import Statistics
from tools.test_configure import auto_configure
from tools.utils import get_atf_logger

from infra.test_base import TestBase, idparametrize

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "ftp"


class TestFTP(TestBase):
    @classmethod
    def setup_class(cls):
        super(TestFTP, cls).setup_class()

        cls.FTP_TIME = os.environ.get("FTP_TIME", 10)

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.log_local_dir = cls.working_dir

            cls.install_firmwares()

            if cls.dut_drv_cdc:
                if cls.dut_ops.is_mac():
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, drv_type=DRV_TYPE_MAC_CDC)
                elif cls.dut_ops.is_linux():
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, drv_type=DRV_TYPE_LIN_CDC)
                else:
                    raise Exception("CDC driver is not supported")
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)

            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port)
            cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)
            cls.NETMASK_IPV4 = "255.255.0.0"

            cls.DUT_IPV6_ADDR = cls.suggest_test_ip_address(cls.dut_port, None, True)
            cls.LKP_IPV6_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname, True)

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.dut_ifconfig.set_ipv6_address(cls.DUT_IPV6_ADDR, cls.DEFAULT_PREFIX_IPV6, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IPV6_ADDR, cls.DEFAULT_PREFIX_IPV6, None)

            cls.cpu_monitor = CPUMonitor()

            cls.dut_statistics = Statistics(port=cls.dut_port)

            cls.iptables = IPTables(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname)

            ReceiveSegmentCoalescing(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname).enable()

            cls.prev_speed = None
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @auto_configure
    def ftp_perf(self, **kwargs):

        direction = kwargs.get('direction', DIRECTION_RX)
        speed = kwargs.get('speed', None)
        ipv = kwargs.get('ipv', 4)

        if not self.dut_drv_cdc:
            self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        current_link_speed = self.lkp_ifconfig.wait_link_up()
        assert current_link_speed == speed, "{} == {}".format(current_link_speed, speed)

        time.sleep(3)
        # Workaroung for http://redmine.aquantia.com/issues/1397
        # There are no other way to fix it while we are testing 3.x kernel
        if ipv == 6:
            if self.dut_ops.is_linux():
                self.dut_ifconfig.set_ipv6_address(self.DUT_IPV6_ADDR, self.DEFAULT_PREFIX_IPV6, None)
            if self.lkp_ops.is_linux():
                self.lkp_ifconfig.set_ipv6_address(self.LKP_IPV6_ADDR, self.DEFAULT_PREFIX_IPV6, None)

        self.iptables.clean()
        time.sleep(3)

        FTP_ARGS = {
            'direction': direction,
            'timeout': self.FTP_TIME,
            'ipv': ipv,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }

        for i in range(3):
            log.info('ftp #{}'.format(i))
            self.cpu_monitor.run_async()

            ftp = FTP(**FTP_ARGS)
            result = ftp.run()

            if result != FTP.FTP_OK:
                continue

            results = ftp.get_performance()

            # print statistics
            for res in results:
                log.info(res)

            # check results
            for res in results:
                res.check(criterion=FTP_ARGS['criterion'])

            self.cpu_monitor.join(timeout=1)
            log.info(self.cpu_monitor.report())
            break
        else:
            raise Exception("Failed to run FTP 3 times")

    @idparametrize('speed', [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_AUTO])
    @idparametrize('d', [DIRECTION_TX, DIRECTION_RX])
    def test_ftp(self, speed, d):
        if d == DIRECTION_RX and OpSystem().is_windows():
            pytest.skip()
        self.ftp_perf(direction=d, speed=speed, ipv=4)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
