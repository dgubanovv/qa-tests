import os
import shutil
from time import sleep

import pytest

from perf.iperf import Iperf
from tools.command import Priority
from tools.cpu_monitor import CPUMonitor
from tools.iptables import IPTables
from tools.killer import Killer
from tools.prof import prof
from tools.receive_segment_coalescing import ReceiveSegmentCoalescing

if __package__ is None:
    import sys
    from os import path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from hload.heavyload import HeavyLoad
from infra.test_base import TestBase
from tools.constants import DIRECTION_RXTX, LINK_SPEED_10G
from tools.driver import Driver
from tools.log import get_atf_logger
from tools.ops import OpSystem

log = get_atf_logger()

def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "heavy_load"


class TestHeavyLoad(TestBase):

    @classmethod
    def setup_class(cls):
        super(TestHeavyLoad, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            with prof('install_firmwares'):
                cls.install_firmwares()

            with prof('dut.driver.install'):
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
                cls.dut_driver.install()

            with prof('lkp.driver.install'):
                cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
                cls.lkp_driver.install()

            with prof('set variable for TestHeavyLoad'):
                cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
                cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)
                cls.dut_ifconfig.set_ipv6_address(cls.DUT_IPV6_ADDR, cls.DEFAULT_PREFIX_IPV6, None)
                cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IPV6_ADDR, cls.DEFAULT_PREFIX_IPV6, None)

            cls.dut_ops = OpSystem()
            cls.lkp_ops = OpSystem(host=cls.lkp_hostname)

            ReceiveSegmentCoalescing(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname).enable()
            iptables = IPTables(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname)
            iptables.clean()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def iperf_with_heavyload(self, time, priority):

        Killer().kill("stress")

        shift = time / 10

        cpu_monitor = CPUMonitor()

        load = HeavyLoad(timeout=time - 2 * shift, priority=priority)

        args = {
            'priority': priority,
            'direction': DIRECTION_RXTX,
            'speed': LINK_SPEED_10G,
            'num_threads': 1,
            'num_process': 4,
            'time': time,
            'timeout': time * 3 / 2,
            'ipv': 4,
            'buffer_len': 0,
            'is_udp': False,
            'dut': self.dut_hostname,
            'lkp': self.lkp_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR
        }

        for i in range(5):
            Killer().kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")

            cpu_monitor.run_async()

            iperf = Iperf(**args)
            iperf.run_async()
            sleep(shift)

            load.run_async()
            sleep(time - 2 * shift)
            load.join()

            sleep(shift)

            result = iperf.join()

            cpu_monitor.join(timeout=1)

            if result != Iperf.IPERF_OK:
                continue

            results = iperf.get_performance()

            # print statistics
            for res in results:
                log.info(res)

            cpu_monitor.report()

            # check results
            for res in results:
                res.check()

            # write csv file
            with open('result.csv', 'wt') as f:

                mm = len(results[0].bandwidth)
                mm = min(mm, len(results[1].bandwidth)) if len(results) > 1 else mm

                for i in range(mm):
                    text = '{}'.format(i)
                    for k in range(len(results)):
                        text += ';{}'.format(results[k].bandwidth[i])
                    f.write(text + '\n')
            shutil.move('result.csv', self.test_log_dir)
            break
        else:
            raise Exception("Failed to run iperf 5 times")

    def test_traffic_1min_on_heavy_load_cpu_realtime(self):
        self.iperf_with_heavyload(1 * 60, Priority.REALTIME)

    def test_traffic_1min_on_heavy_load_cpu_low(self):
        self.iperf_with_heavyload(1 * 60, Priority.LOW)

    def test_traffic_1min_on_heavy_load_cpu_normal(self):
        self.iperf_with_heavyload(1 * 60, Priority.NORMAL)

    def test_traffic_1min_on_heavy_load_cpu_high(self):
        self.iperf_with_heavyload(1 * 60, Priority.HIGH)

    def test_traffic_10min_on_heavy_load_cpu_realtime(self):
        self.iperf_with_heavyload(10 * 60, Priority.REALTIME)

    def test_traffic_10min_on_heavy_load_cpu_low(self):
        self.iperf_with_heavyload(10 * 60, Priority.LOW)

    def test_traffic_10min_on_heavy_load_cpu_normal(self):
        self.iperf_with_heavyload(10 * 60, Priority.NORMAL)

    def test_traffic_10min_on_heavy_load_cpu_high(self):
        self.iperf_with_heavyload(10 * 60, Priority.HIGH)

    def test_traffic_5h_on_heavy_load_cpu_realtime(self):
        self.iperf_with_heavyload(5 * 60 * 60, Priority.REALTIME)

    def test_traffic_5h_on_heavy_load_cpu_low(self):
        self.iperf_with_heavyload(5 * 60 * 60, Priority.LOW)

    def test_traffic_5h_on_heavy_load_cpu_normal(self):
        self.iperf_with_heavyload(5 * 60 * 60, Priority.NORMAL)

    def test_traffic_5h_on_heavy_load_cpu_high(self):
        self.iperf_with_heavyload(5 * 60 * 60, Priority.HIGH)

    def test_traffic_10h_on_heavy_load_cpu_realtime(self):
        self.iperf_with_heavyload(10 * 60 * 60, Priority.REALTIME)

    def test_traffic_10h_on_heavy_load_cpu_low(self):
        self.iperf_with_heavyload(10 * 60 * 60, Priority.LOW)

    def test_traffic_10h_on_heavy_load_cpu_normal(self):
        self.iperf_with_heavyload(10 * 60 * 60, Priority.NORMAL)

    def test_traffic_10h_on_heavy_load_cpu_high(self):
        self.iperf_with_heavyload(10 * 60 * 60, Priority.HIGH)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
