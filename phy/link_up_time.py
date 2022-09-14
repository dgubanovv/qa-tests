import os
import shutil
import sys
import timeit
import random
import time
import pytest
#from scapy.utils import wrpcap


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hlh.mac import MAC, OPERATION_MODE_INVALID
from hlh.phy import PHY
from infra.test_base import idparametrize
from infra.test_base_phy import TestBasePhy
from tools.tcpdump import Tcpdump
from tools.constants import LINK_STATE_UP, ALL_LINK_SPEEDS, LINK_SPEED_AUTO, MAC_ATLANTIC2_A0, LINK_SPEED_10G
from tools.constants import LINK_SPEED_10M, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G
from tools.driver import Driver
from tools.log import get_atf_logger
from tools.test_configure import auto_configure
from tools.atltoolper import AtlTool

log = get_atf_logger()


class StatisticsLinkUpTime:
    MAXIMUM_LINKUP_TIME_IN_MS = {
        LINK_SPEED_10M: 3500,
        LINK_SPEED_100M: 4000,
        LINK_SPEED_1G: 4500,
        LINK_SPEED_2_5G: 5000,
        LINK_SPEED_5G: 5500,
        LINK_SPEED_10G: 6000
    }

    def __init__(self):
        self.statistics = {}
        self.iteration_log = []
        self.iter = 0

    def add(self, stats):
        speed = stats['speed']
        del stats['speed']
        if speed in self.statistics.keys():
            for k in stats.keys():
                self.statistics[speed][k].append(stats[k])
        else:
            self.statistics[speed] = {}
            for k in stats.keys():
                self.statistics[speed][k] = [stats[k]]

        msg = ' ITERATION# {:5d} '.format(self.iter)

        for k in stats.keys():
            msg += '  {}: {}'.format(k.upper(), stats[k])

        self.iteration_log.append(msg)
        self.iter += 1

    def report(self):
        for msg in self.iteration_log:
            log.info(msg)

        log.info('-' * 120)
        log.info('LINK UP TIME REPORT:')
        log.info('-' * 120)

        log.info('    SPEED       COUNT     AVG TRY       AVG TIME (ms)    MAX TIME (ms)')

        for speed in ALL_LINK_SPEEDS:
            if speed not in self.statistics.keys():
                continue

            count = len(self.statistics[speed]['lut'])
            avg = int(float(sum(self.statistics[speed]['lut'])) / float(count))
            retry = float(sum(self.statistics[speed]['retry'])) / float(count)
            max_time = max(self.statistics[speed]['lut'])

            log.info('     {:>4s}      {:6d}       {:5.2f}       {:8d}         {:8d}'.format(speed, count, retry, avg, max_time))
        log.info('-' * 120)

    def is_correct(self):
        is_test_pass = True
        log.info('-' * 120)
        log.info('LINK UP TIME CHECK:')
        log.info('-' * 120)
        for speed in ALL_LINK_SPEEDS:
            if speed not in self.statistics.keys():
                continue

            max_time = max(self.statistics[speed]['lut'])
            msg = 'FAIL' if max_time > self.MAXIMUM_LINKUP_TIME_IN_MS[speed] else 'PASS'
            is_test_pass = False if max_time > self.MAXIMUM_LINKUP_TIME_IN_MS[speed] else is_test_pass
            log.info(' SPEED: {:>4s}      {} ms < {} ms   ....    {}'.format(speed, max_time, self.MAXIMUM_LINKUP_TIME_IN_MS[speed], msg))

        log.info('-' * 120)
        log.info('TEST: {}'.format('PASS' if is_test_pass else 'FAIL'))
        log.info('-' * 120)
        return is_test_pass


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_link_up_time"


class TestPhyA2LinkUpTime(TestBasePhy):
    """
        @description: This tests checking time of link up and and ability switch speed between each other.

        @duration: 5 hours.
    """

    link_fixed = 'fixed'
    link_auto = 'auto'

    LINK_UP_TIME_COUNT = os.environ.get("LINK_UP_TIME_COUNT", 6)
    LINK_UP_TIME_SWITCH_COUNT = os.environ.get("LINK_UP_TIME_SWITCH_COUNT", 1)

    @classmethod
    def setup_class(cls):
        super(TestPhyA2LinkUpTime, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            cls.dut_iface = cls.dut_ifconfig.get_conn_name()
            cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()

            log.info('Interface    DUT: {:12s}     LKP: {:12s}'.format(cls.dut_iface, cls.lkp_iface))

            cls.dut_phy = PHY(port=cls.dut_port, host=cls.dut_hostname)
            cls.dut_mac = MAC(port=cls.dut_port, host=cls.dut_hostname, arch=MAC_ATLANTIC2_A0)

            cls.dut_atltool = AtlTool(port=cls.dut_port)
            cls.lkp_atltool = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestPhyA2LinkUpTime, self).setup_method(method)
        if self.MCP_LOG:
            self.lkp_atltool.debug_buffer_enable(True)
            self.lkp_atltool.enable_phy_logging(True)

    def teardown_method(self, method):
        super(TestPhyA2LinkUpTime, self).teardown_method(method)

        if self.MCP_LOG:
            self.lkp_atltool.enable_phy_logging(False)
            self.lkp_bin_log_file, self.lkp_txt_log_file = self.lkp_atltool.debug_buffer_enable(False)
            shutil.copy(self.lkp_bin_log_file, self.test_log_dir)
            shutil.copy(self.lkp_txt_log_file, self.test_log_dir)

    @auto_configure
    def run_test_link_up_time(self, speed, dut_link, lkp_link):
        assert dut_link in [self.link_fixed, self.link_auto]
        assert lkp_link in [self.link_fixed, self.link_auto]

        statistics = StatisticsLinkUpTime()

        self.dut_mac.set_operation_mode(mode=OPERATION_MODE_INVALID)
        self.dut_mac.stall_fw()

        lkp_speed = speed if lkp_link == self.link_fixed else LINK_SPEED_AUTO
        dut_speed = [speed] if dut_link == self.link_fixed else ALL_LINK_SPEEDS

        log.info('DUT: {}    LKP: {}'.format(dut_speed, lkp_speed))

        for iteration in range(self.LINK_UP_TIME_COUNT):
            self.lkp_ifconfig.set_link_speed(lkp_speed)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

            self.dut_phy.set_advertise(speeds=dut_speed)
            self.dut_phy.restart_autoneg()

            start = timeit.default_timer()
            self.dut_phy.wait_link_up()
            lut = int(1000 * (timeit.default_timer() - start))

            stats = self.dut_phy.get_link_status()
            stats['lut'] = lut
            stats['speed'] = speed
            statistics.add(stats)

            real_lkp_speed = self.lkp_ifconfig.wait_link_up()

            is_error = False if real_lkp_speed == speed else True
            is_error = False and is_error if stats['link'] == speed else True
            if is_error:
                fmt = '  {:>20s} : {}'
                log.error('Failed link up:')
                log.error(fmt.format('LKP speed', real_lkp_speed))
                log.error(fmt.format('DUT speed', stats['link']))
                log.error(fmt.format('Expected speed', speed))
                log.error(fmt.format('Link up time (ms)', lut))
                log.error(fmt.format('Status', stats['status']))
                log.error(fmt.format('Retry', stats['retry']))
                log.error(fmt.format('Downshift', stats['retry_downshift']))
                assert False

            sniffer = Tcpdump(host=self.lkp_hostname, port=self.lkp_port, timeout=10)

            sniffer.run_async()

            time.sleep(1)

            count = 128
            pkt_len = 256
            self.dut_phy.send_n_packets(speed, count=count, size=pkt_len)

            time.sleep(5)
            packets = sniffer.join()
            # wrpcap(os.path.join(self.test_log_dir, "packets.pcap"), packets)

            filtered_packets = [p for p in packets if len(p) == (pkt_len - 4)]
            log.info('Filtered packets: {}'.format(len(filtered_packets)))

            assert len(filtered_packets) == count, "datapath is broken"

        statistics.report()
        assert statistics.is_correct()
        self.dut_mac.unstall_fw()

    def run_test_lut_link_switch(self, dut_link, lkp_link):
        assert dut_link in [self.link_fixed, self.link_auto]
        assert lkp_link in [self.link_fixed, self.link_auto]

        all_supported_speeds = [speed for speed in ALL_LINK_SPEEDS if speed in self.supported_speeds]

        statistics = StatisticsLinkUpTime()
        self.dut_mac.stall_fw()

        for iteration in range(self.LINK_UP_TIME_SWITCH_COUNT * len(ALL_LINK_SPEEDS)):
            speed = all_supported_speeds[random.randint(0, len(all_supported_speeds) - 1)]
            lkp_speed = speed if lkp_link == self.link_fixed else LINK_SPEED_AUTO
            dut_speed = [speed] if dut_link == self.link_fixed else ALL_LINK_SPEEDS

            self.lkp_ifconfig.set_link_speed(lkp_speed)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

            self.dut_phy.set_advertise(speeds=dut_speed)
            self.dut_phy.restart_autoneg()

            start = timeit.default_timer()
            self.dut_phy.wait_link_up()
            lut = int(1000 * (timeit.default_timer() - start))

            stats = self.dut_phy.get_link_status()
            stats['lut'] = lut
            stats['speed'] = speed
            statistics.add(stats)

            real_lkp_speed = self.lkp_ifconfig.wait_link_up()

            is_error = False if real_lkp_speed == speed else True
            is_error = False and is_error if stats['link'] == speed else True
            if is_error:
                fmt = '  {:>20s} : {}'
                log.error('Failed link up:')
                log.error(fmt.format('LKP speed', real_lkp_speed))
                log.error(fmt.format('DUT speed', stats['link']))
                log.error(fmt.format('Expected speed', speed))
                log.error(fmt.format('Link up time (ms)', lut))
                log.error(fmt.format('Status', stats['status']))
                log.error(fmt.format('Retry', stats['retry']))
                log.error(fmt.format('Downshift', stats['retry_downshift']))
                assert False

            sniffer = Tcpdump(host=self.lkp_hostname, port=self.lkp_port, timeout=10)

            sniffer.run_async()

            time.sleep(1)

            count = 128
            pkt_len = 256
            self.dut_phy.send_n_packets(speed, count=count, size=pkt_len)

            time.sleep(5)
            packets = sniffer.join()
            # wrpcap(os.path.join(self.test_log_dir, "packets.pcap"), packets)

            filtered_packets = [p for p in packets if len(p) == (pkt_len - 4)]
            log.info('Filtered packets: {}'.format(len(filtered_packets)))

            assert len(filtered_packets) == count, "datapath is broken"

        statistics.report()
        assert statistics.is_correct()
        self.dut_mac.unstall_fw()

    def test_lut_switch_dut_fixed_lkp_auto(self):
        """
            @description: This test checking ability switch speed between each other.

            @steps:
                1. set link speed AUTO on LKP
                2. set link speed fixed on DUT (every time the fixed speed is new)
                3. measure link up time
                4. check data path (send several packets from LKP)
                5. check link up time less expected

            @result: link up time less expected and data path not broken.

            @requirements:

            @duration: 30 minutes.
        """

        self.run_test_lut_link_switch(dut_link=self.link_fixed, lkp_link=self.link_auto)

    def test_lut_switch_dut_fixed_lkp_fixed(self):
        """
            @description: This test checking ability switch speed between each other.

            @steps:
                1. set link speed fixed on LKP (every time the fixed speed is new)
                2. set link speed fixed on DUT (every time the fixed speed is new)
                3. measure link up time
                4. check data path (send several packets from LKP)
                5. check link up time less expected

            @result: link up time less expected and data path not broken.

            @requirements:

            @duration: 30 minutes.
        """

        self.run_test_lut_link_switch(dut_link=self.link_fixed, lkp_link=self.link_fixed)

    def test_lut_switch_dut_auto_lkp_fixed(self):
        """
            @description: This test checking ability switch speed between each other.

            @steps:
                1. set link speed fixed on LKP (every time the fixed speed is new)
                2. set link speed AUTO on DUT
                3. measure link up time
                4. check data path (send several packets from LKP)
                5. check link up time less expected

            @result: link up time less expected and data path not broken.

            @requirements:

            @duration: 30 minutes.
        """

        self.run_test_lut_link_switch(dut_link=self.link_auto, lkp_link=self.link_fixed)

    @idparametrize('speed', ALL_LINK_SPEEDS)
    def test_lut_dut_fixed_lkp_auto(self, speed):
        """
            @description: This test checking time of link up.

            @steps:
                1. set link speed AUTO on LKP
                2. set link speed fixed on DUT (every time the fixed speed is the same speed)
                3. measure link up time
                4. check data path (send several packets from LKP)
                5. check link up time less expected

            @result: link up time less expected and data path not broken.

            @requirements:

            @duration: 30 minutes.
        """

        self.run_test_link_up_time(speed=speed, dut_link=self.link_fixed, lkp_link=self.link_auto)

    @idparametrize('speed', ALL_LINK_SPEEDS)
    def test_lut_dut_fixed_lkp_fixed(self, speed):
        """
            @description: This test checking time of link up.

            @steps:
                1. set link speed fixed on LKP (every time the fixed speed is the same speed)
                2. set link speed fixed on DUT (every time the fixed speed is the same speed)
                3. measure link up time
                4. check data path (send several packets from LKP)
                5. check link up time less expected

            @result: link up time less expected and data path not broken.

            @requirements:

            @duration: 30 minutes.
        """
        self.run_test_link_up_time(speed=speed, dut_link=self.link_fixed, lkp_link=self.link_fixed)

    @idparametrize('speed', ALL_LINK_SPEEDS)
    def test_lut_dut_auto_lkp_fixed(self, speed):
        """
            @description: This test checking time of link up.

            @steps:
                1. set link speed fixed on LKP (every time the fixed speed is the same speed)
                2. set link speed AUTO on DUT
                3. measure link up time
                4. check data path (send several packets from LKP)
                5. check link up time less expected

            @result: link up time less expected and data path not broken.

            @requirements:

            @duration: 30 minutes.
        """
        self.run_test_link_up_time(speed=speed, dut_link=self.link_auto, lkp_link=self.link_fixed)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
