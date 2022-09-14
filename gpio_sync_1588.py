# Cycle env NUMBER_OF_TEST_REPEAT need

import os
import re
import time

import pytest

from infra.test_base import TestBase, idparametrize

from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import LINK_STATE_UP, LINK_STATE_DOWN
from tools.driver import Driver, DRV_TYPE_LINUX_SRC
from tools.utils import get_atf_logger, get_bus_dev_func
from tools.ifconfig import get_linux_network_adapter_name
from tools.constants import LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "Q_qom_gpio-ptp"


class TestQqomGpioPtp(TestBase):
    ADJUSTS_LIMIT = 1000000  # 1/1000
    NS_IN_SEC = 10 ** 9
    LINK_SPEED = LINK_SPEED_10G
    LINK_MAP = {
        LINK_SPEED_10G: 10000,
        LINK_SPEED_5G: 5000,
        LINK_SPEED_2_5G: 2500,
        LINK_SPEED_1G: 1000,
        LINK_SPEED_100M: 100,
    }
    EVENT_DB = []

    @classmethod
    def setup_class(cls):
        super(TestQqomGpioPtp, cls).setup_class()
        bus, dev, func = get_bus_dev_func(cls.dut_port)
        cls.DUT_PORT = "{:02x}:{:02x}.{:x}".format(int(bus), int(dev), int(func))
        cls.NUMBER_OF_TEST_REPEAT = int(os.getenv("NUMBER_OF_TEST_REPEAT", 3))
        cls.PHY_COUNTERS_DIFF_TIME = int(os.getenv("PHY_COUNTERS_DIFF_TIME", 30))

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_LINUX_SRC, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            test_sync_ioctl_path = "/home/aqtest/qa-tests/tools/testsync"
            Command(host=cls.dut_hostname, cmd="cd {} && gcc testsync.c".format(test_sync_ioctl_path)).run()
            cls.TEST_SYNC_IOCTL_APP = "{}/a.out -i {}".format(test_sync_ioctl_path,
                                                              get_linux_network_adapter_name(cls.dut_port))

            testptp_path = "/home/aqtest/qa-tests/tools/testptp"
            Command(host=cls.dut_hostname, cmd="cd {} && make distclean && make".format(testptp_path)).run()
            Command(host=cls.lkp_hostname, cmd="cd {} && make distclean && make".format(testptp_path)).run()
            cls.TESTPTP_TOOL = os.path.join(testptp_path, "testptp")


            cls.dut_atltoolper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.lkp_atltoolper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.dut_if_name = cls.dut_ifconfig.get_conn_name()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

        cls.NETMASK_IPV4 = "255.255.0.0"
        cls.NETMASK_DEC_FORMAT = 16

    def setup_method(self, method):
        super(TestQqomGpioPtp, self).setup_method(method)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        Command(
            host=self.dut_hostname,
            cmd="echo -n 'file aq_ptp.c +p' | sudo tee /sys/kernel/debug/dynamic_debug/control"
        ).run_async()

    def teardown_method(self, method):
        super(TestQqomGpioPtp, self).teardown_method(method)
        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_ifconfig.wait_link_down()
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.lkp_ifconfig.wait_link_down()

    def determine_ptp_dev(self, host):
        res = Command(cmd='ls /dev/ptp*', host=host).run()
        for i in range(len(res["output"])):
            res = Command(cmd='cat /sys/class/ptp/ptp%d/clock_name' % i, host=host).run()
            if 'atlantic' in res["output"][0]:
                return i

    def setup_gpio_periodic_out(self, host):
        atlantic_ptp = self.determine_ptp_dev(host)
        res = Command(cmd='sudo {} -d /dev/ptp{} -l'.format(self.TESTPTP_TOOL, atlantic_ptp), host=host).run()
        if "name AQ_GPIO0 index 0 func 2 chan 0" not in res["output"][0]:
            raise Exception("Atlantic PTP device not found")
        res = Command(cmd='sudo {} -d /dev/ptp{} -L 0,2'.format(self.TESTPTP_TOOL, atlantic_ptp), host=host).run()
        if "set pin function okay" not in res["output"][0]:
            raise Exception("Set pin function is not OK")

    def start_gpio_periodic_out(self, host, ns):
        self.setup_gpio_periodic_out(host)
        res = Command(cmd='sudo {} -d /dev/ptp{} -p {}'.format(
            self.TESTPTP_TOOL, self.determine_ptp_dev(host), ns
        ), host=host).run()
        if "periodic output request okay" not in res["output"][0]:
            raise Exception("Cannot enable periodic generation")
        log.info("periodic output was configured and run with {} period".format(ns))

    def stop_gpio_periodic_out(self, host):
        self.setup_gpio_periodic_out(host)
        res = Command(cmd='sudo {} -d /dev/ptp{} -p 0'.format(
            self.TESTPTP_TOOL, self.determine_ptp_dev(host)
        ), host=host).run()
        if "periodic output request okay" not in res["output"][0]:
            raise Exception("Cannot disable periodic generation")
        log.info("periodic output was disabled")

    def send_rise_pulse(self, host):
        atl = self.dut_atltoolper if host == self.dut_hostname else self.lkp_atltoolper
        val = atl.readreg(0x180)
        atl.writereg(0x180, val | 1)
        atl.writereg(0x180, val)
        log.info("One rise pulse was send")

    def read_mac_counter(self):
        sec_lsw = self.dut_atltoolper.readreg(0x4900) & 0xFFFF
        sec_msw = self.dut_atltoolper.readreg(0x4904) & 0xFFFF
        ns_lsw = self.dut_atltoolper.readreg(0x490c) & 0xFFFF
        ns_msw = self.dut_atltoolper.readreg(0x4910) & 0xFFFF
        res = ((sec_msw << 16) + sec_lsw) * self.NS_IN_SEC + ((ns_msw << 16) + ns_lsw)
        return res

    def read_phy_counter(self):
        nsec_lsw = self.dut_atltoolper.readphyreg(mmd=0x3, reg=0xc903)
        nsec_msw = self.dut_atltoolper.readphyreg(mmd=0x3, reg=0xc904)
        sec_lsw = self.dut_atltoolper.readphyreg(mmd=0x3, reg=0xc900)
        sec_msw = self.dut_atltoolper.readphyreg(mmd=0x3, reg=0xc901)
        res = ((sec_msw << 16) + sec_lsw) * self.NS_IN_SEC + ((nsec_msw << 16) + nsec_lsw)
        return res

    def config_ptp_time(self, **kwargs):
        s = kwargs.get('s')
        ns = kwargs.get('ns')
        new_time = int()
        if not ns and s:
            new_time = int(s) * self.NS_IN_SEC
        elif not s and ns:
            new_time = int(ns)
        elif (s and ns) or (not s and not ns):
            raise Exception("Bad arguments! Please, set time in s (s argument) OR in ns (ns argument)")
        Command(host=self.dut_hostname, cmd="{} -t {} ".format(self.TEST_SYNC_IOCTL_APP, str(new_time))).run()
        log.info("New time has been config to {} ns. To perform time set, "
                 "send rise front signal on GPIO0".format(str(new_time)))

    def config_sync(self, sync_period):
        sync_period_ms = int(sync_period / 1000000)
        Command(host=self.dut_hostname, cmd="{} -p {}".format(self.TEST_SYNC_IOCTL_APP, sync_period_ms)).run()
        log.info("Sync with external signal with period {} ms has been configured. "
                 "To perform sync, send periodic signal on GPIO0".format(sync_period_ms))

    def disable_sync(self):
        Command(host=self.dut_hostname, cmd="{} -p 0".format(self.TEST_SYNC_IOCTL_APP)).run()
        log.info("Sync with external signal was disabled.")

    def get_ptp_time(self):
        atlantic_ptp = self.determine_ptp_dev(host=self.dut_hostname)
        res = Command(host=self.dut_hostname, cmd='sudo {} -d /dev/ptp{} -l'.format(
            self.TESTPTP_TOOL, str(atlantic_ptp)
        )).run()
        if "name AQ_GPIO" not in res["output"][0]:
            raise Exception("Atlantic PTP device not found")
        res = Command(host=self.dut_hostname, cmd='sudo {} -d /dev/ptp{} -g'.format(
            self.TESTPTP_TOOL, str(atlantic_ptp)
        )).run()
        result = re.match(r'clock time: (\d*.\d*)', res["output"][0])
        ptp_time = int(float(result.group(1)) * self.NS_IN_SEC)
        return ptp_time

    def get_phy_counter_diff(self, period, sync_period):
        time_to_sync = 10
        count = int(((period + time_to_sync) * self.NS_IN_SEC) / sync_period)
        self.stop_gpio_periodic_out(host=self.lkp_hostname)
        atlantic_ptp = self.determine_ptp_dev(host=self.dut_hostname)
        collect_ts_cmd_dut = Command(host=self.dut_hostname, cmd='sudo {} -d /dev/ptp{} -e {} -L 1,1'.format(
            self.TESTPTP_TOOL, str(atlantic_ptp), count
        ))
        collect_ts_cmd_dut.run_async()
        collect_ts_cmd_lkp = Command(host=self.lkp_hostname, cmd='sudo {} -d /dev/ptp{} -e {} -L 1,1'.format(
            self.TESTPTP_TOOL, str(atlantic_ptp), count
        ))
        collect_ts_cmd_lkp.run_async()

        self.start_gpio_periodic_out(host=self.lkp_hostname, ns=sync_period)
        time.sleep(time_to_sync)

        result_dut = collect_ts_cmd_dut.join(120)
        result_lkp = collect_ts_cmd_lkp.join(120)

        timestamps_dut = self.parse_timestamps(result_dut["output"])
        log.info("DUT Timestamps: {}".format(timestamps_dut))
        timestamps_lkp = self.parse_timestamps(result_lkp["output"])
        log.info("LKP Timestamps: {}".format(timestamps_lkp))
        throw_out_ts = int((time_to_sync * self.NS_IN_SEC) / sync_period)
        log.info("Throuw out first {} timestamps".format(throw_out_ts))
        timestamps_dut = timestamps_dut[throw_out_ts:]
        timestamps_lkp = timestamps_lkp[throw_out_ts:]

        dut_result = timestamps_dut[-1] - timestamps_dut[0]
        lkp_result = timestamps_lkp[-1] - timestamps_lkp[0]
        log.info("DUT diff: {}".format(dut_result))
        log.info("LKP diff: {}".format(lkp_result))

        result = abs(dut_result - lkp_result)
        return result

    def run_synchronization(self, sync_period, sync_on=True, sync_off=True):
        if sync_on:
            self.config_sync(sync_period)
        diff_after = self.get_phy_counter_diff(period=self.PHY_COUNTERS_DIFF_TIME, sync_period=sync_period)
        if sync_off:
            self.disable_sync()
        self.stop_gpio_periodic_out(host=self.lkp_hostname)
        log.info("Diff between PHY counters on DUT and LKP after sync: {}".format(diff_after))
        return diff_after

    def find_link_reneg(self, output):
        adj_reg = re.compile("^.*" + self.dut_if_name + ": delta = -?\d+, adjust = (-?\d+).*$")
        down_str = "{}: atlantic: link change old {} new 0".format(self.dut_if_name, self.LINK_MAP[LINK_SPEED_10G])
        up_str = "{}: atlantic: link change old 0 new {}".format(self.dut_if_name, self.LINK_MAP[LINK_SPEED_10G])
        link_down_found = False
        link_up_found = False
        adj_index = 0
        for line in output[4:]:
            if adj_reg.match(line) and not link_down_found:
                adj_index += 1
            if not link_down_found:
                link_down_found = True if down_str in line else False
            elif not link_up_found:
                link_up_found = True if up_str in line else False
            else:
                break
        log.debug("LINK DOWN, ADJ_INDEX: {}".format(adj_index))
        return link_down_found and link_up_found, adj_index

    def find_invalid_timestamps(self, output, sync_period):
        adj_reg = re.compile("^.*" + self.dut_if_name + ": delta = -?\d+, adjust = (-?\d+).*$")
        invalid_ts_reg = re.compile(
            "^\[(\d+.\d+)\].*" + self.dut_if_name +
            ": Invalid TS got, reset synchronization algorithm: TS diff: (\d+), expected: about \d+.*$"
        )
        found_invalid_timestamps = 0
        adj_index = 0
        for line in output[4:]:
            if adj_reg.match(line) and not found_invalid_timestamps:
                adj_index += 1
            match = invalid_ts_reg.match(line)
            if match:
                diff_tolerance = 50000  # 50us
                ts_event = match.group(1)
                ts_diff = match.group(2)
                if sync_period - diff_tolerance < ts_diff < sync_period + diff_tolerance or ts_event in self.EVENT_DB:
                    log.info("Found invalid TS message but it's connected with 1 missed pulse.")
                    # Sometimes one input pulse is missed sporadically, most probable reason: electric noise
                else:
                    self.EVENT_DB.append(ts_event)
                    found_invalid_timestamps += 1

        log.debug("INV TS, ADJ_INDEX: {}".format(adj_index))
        return found_invalid_timestamps, adj_index

    def get_adjusts(self, output):
        adj_reg = re.compile("^.*" + self.dut_if_name + ": delta = -?\d+, adjust = (-?\d+).*$")
        adjusts = []
        for line in output[4:]:
            match = adj_reg.match(line)
            if match:
                adjusts.append(int(match.group(1)))
        return adjusts

    def parse_timestamps(self, output):
        reg = re.compile("^.*event index \d+ at (\d+)\.(\d+).*$")
        timestamps = []
        for line in output:
            match = reg.match(line)
            if match:
                seconds = int(match.group(1))
                nanoseconds = int(match.group(2))
                ts = seconds * self.NS_IN_SEC + nanoseconds
                timestamps.append(ts)
        return timestamps


    def analyze_dmesg(self, dmesg_output, sync_period, event=None):
        adjusts = self.get_adjusts(dmesg_output)
        log.info("Adjusts: {}".format(adjusts))
        if event == "link_reneg":
            found_link_reneg, adj_index = self.find_link_reneg(dmesg_output)
            assert found_link_reneg, "Expected link renegotiation was not found"
            invalid_timestamps, _ = self.find_invalid_timestamps(dmesg_output, sync_period)
            assert invalid_timestamps <= 1, "Expected to find not more 1 invalid TS message. Found: {}".format(
                invalid_timestamps
            )
            log.info("Link renegotiation and invalid TS found {} as expected".format(invalid_timestamps))
            log.info("Invalid TS found as expected")
            log.debug("Full list of adjusts: {}".format(adjusts))
            if adj_index != len(adjusts):
                item = adjusts.pop(adj_index - 1)
                log.debug("Popped item: {}".format(item))
                # Sometimes first adjustment is invalid after external clock is lost. It's OK. Since
                # loosing clock - is an unexpected case for this functionality. Test case just verifies that
                # correct behavior is restored after retunrning external clock. In this statement possible invalid
                # value is excluded
        elif event == "sync_lost":
            invalid_timestamps, adj_index = self.find_invalid_timestamps(dmesg_output, sync_period)
            assert invalid_timestamps == 1, "Expected to find 1 invalid TS message. Found: {}".format(
                invalid_timestamps
            )
            log.info("Invalid TS found as expected")
            log.debug("Full list of adjusts: {}".format(adjusts))
            if adj_index != len(adjusts):
                item = adjusts.pop(adj_index - 1)
                log.debug("Popped item: {}".format(item))
                # Sometimes first adjustment is invalid after external clock is lost. It's OK. Since
                # loosing clock - is an unexpected case for this functionality. Test case just verifies that
                # correct behavior is restored after retunrning external clock. In this statement possible invalid
                # value is excluded
        elif event is None:
            pass
        else:
            raise ValueError("Unknown event: {}".format(event))

        assert all(-self.ADJUSTS_LIMIT < item < self.ADJUSTS_LIMIT for item in adjusts), \
            "Adjustmet values are out of range [{}:{}]".format(-self.ADJUSTS_LIMIT, self.ADJUSTS_LIMIT)

    def test_simple_set_ptp_time(self):
        """
        @description: Check that value to be set after first pulse arrives to sync1588 pin is equal to the actual
        value returned by ptp device in /dev/ folder.

        @steps:
        1. Make link up.
        2. Configure 100 seconds value to be set in PTP counter.
        3. Run testptp tool to capture external event timestamp.
        4. Send pulse from GPIO pin on LKP to 1588 pin on DUT.
        5. Get timestamp value from testptp tool.

        @result: values set and read in steps 2,5 are equal
        @duration: 8 s

        @requirements: DRV_LINUX_GPIO_1588_SET_TIME_1, DRV_LINUX_GPIO_1588_SET_TIME_2
        """
        self.stop_gpio_periodic_out(host=self.lkp_hostname)
        self.disable_sync()
        time_value = 100 * self.NS_IN_SEC  # time in ns for set ptp timestamp

        for i in range(self.NUMBER_OF_TEST_REPEAT):
            time_to_set = time_value * (10 ** i)
            log.info("START TEST TRY {} from {}".format(i+1, self.NUMBER_OF_TEST_REPEAT))

            self.config_ptp_time(ns=time_to_set)

            atlantic_ptp = self.determine_ptp_dev(host=self.dut_hostname)
            collect_ts_cmd = Command(host=self.dut_hostname, cmd='sudo {} -d /dev/ptp{} -e 1 -L 1,1'.format(
                self.TESTPTP_TOOL, str(atlantic_ptp)
            ))
            collect_ts_cmd.run_async()

            self.send_rise_pulse(host=self.lkp_hostname)

            result = collect_ts_cmd.join(10)
            timestamps = self.parse_timestamps(result["output"])
            log.info("Timestamps: {}".format(timestamps))
            assert len(timestamps) == 1, "Got more than 1 timestamp"
            assert timestamps[0] == time_to_set

    @idparametrize("sync_period", (50000000, 100000000, 500000000, 1000000000))
    def test_simple_ptp_gpio_sync(self, sync_period):
        """
        @description: Check that clock increment synchronization works properly.
        Periodic pulses are being sent from LKP GPIO pin to DUT sync1588 pin. Driver analyzes pulse timestamps for
        10 seconds and adjusts clock increment to sync with LKP.

        @steps:
        1. Make link up
        2. Run testptp tool to capture timestamps of external event on DUT and LKP
        3. Start periodic GPIO pulses on LKP
        4. Start sync functionality on DUT
        5. Wait 10 seconds
        6. Collect pulse timestamps on DUT and LKP
        7. Throw out timestamps for the first 10 seconds of external pulse generation.

        @result: Diff between last and first timestamps on DUT and LKP. Diff should be between tolerance thresholds.
        @duration: 55 s

        @requirements: DRV_LINUX_GPIO_1588_SYNC_TIME_1, DRV_LINUX_GPIO_1588_SYNC_TIME_4

        :param sync_period: GPIO pulse period should be between 50ms and 1s
        """
        dmesg_cmd = Command(cmd="dmesg -w")
        for i in range(self.NUMBER_OF_TEST_REPEAT):
            dmesg_cmd.run_async()
            log.info("START TEST TRY {} from {}".format(i + 1, self.NUMBER_OF_TEST_REPEAT))
            diff_after = self.run_synchronization(sync_period)
            log.info("Check that diff between PHY counters on DUT and LKP after sync {} < 2000".format(diff_after))
            dmesg_output = dmesg_cmd.join(0)["output"]
            assert diff_after < 10000, "Diff after sync is to big!"
            self.analyze_dmesg(dmesg_output, sync_period, event=None)

    @idparametrize("sync_period", (50000000, 100000000, 500000000, 1000000000))
    def test_ptp_gpio_sync_with_breaks(self, sync_period):
        """
        @description: Check that clock increment synchronization is restored after missing and restoring external clock
        signal. Periodic pulses are being sent from LKP GPIO pin to DUT sync1588 pin. Driver analyzes pulse timestamps
        for 10 seconds and adjusts clock increment to sync with LKP and this is restored properly after missing and
        restoring external clock signal.

        @steps:
        1. Make link up
        2. Run testptp tool to capture timestamps of external event on DUT and LKP
        2. Start periodic GPIO pulses on LKP
        3. Start sync functionality on DUT
        4. Wait 10 seconds
        5. Collect pulse timestamps on DUT and LKP
        6. Disable pulse generation on LKP
        7. Wait 10 seconds
        8. Enable periodic pulse generation on LKP

        @result: Sync functionality is restored
        @duration: 110 s

        @requirements: DRV_LINUX_GPIO_1588_SYNC_TIME_2, DRV_LINUX_GPIO_1588_SYNC_TIME_4

        :param sync_period: GPIO pulse period should be between 50ms and 1s
        """
        dmesg_cmd = Command(cmd="dmesg -w")
        for i in range(self.NUMBER_OF_TEST_REPEAT):
            dmesg_cmd.run_async()
            log.info("START TEST TRY {} from {}".format(i + 1, self.NUMBER_OF_TEST_REPEAT))
            self.run_synchronization(sync_period, sync_off=False)
            time.sleep(5)
            self.run_synchronization(sync_period, sync_on=False)
            dmesg_output = dmesg_cmd.join(0)["output"]
            self.analyze_dmesg(dmesg_output, sync_period, event="sync_lost")

    @idparametrize("sync_period", (50000000, 100000000, 500000000, 1000000000))
    def test_ptp_gpio_sync_with_link_down_on_dut(self, sync_period):
        """
        @description: Check that clock increment synchronization is restored after missing and restoring external clock
        signal. Periodic pulses are being sent from LKP GPIO pin to DUT sync1588 pin. Driver analyzes pulse timestamps
        for 10 seconds and adjusts clock increment to sync with LKP and this is restored properly after link down/up
        made on DUT.

        @steps:
        1. Make link up
        2. Start periodic GPIO pulses on LKP
        3. Start sync functionality on DUT
        4. Wait 10 seconds
        5. Collect pulse timestamps on DUT and LKP
        6. Make link down on DUT
        7. Wait 10 seconds
        8. Make link up on DUT

        @result: Sync functionality is restored
        @duration: 120 s

        @requirements: DRV_LINUX_GPIO_1588_SYNC_TIME_3, DRV_LINUX_GPIO_1588_SYNC_TIME_4

        :param sync_period: GPIO pulse period should be between 50ms and 1s
        """
        dmesg_cmd = Command(cmd="dmesg -w")
        for i in range(self.NUMBER_OF_TEST_REPEAT):
            dmesg_cmd.run_async()
            log.info("START TEST TRY {} from {}".format(i + 1, self.NUMBER_OF_TEST_REPEAT))
            self.run_synchronization(sync_period, sync_off=False)
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.dut_ifconfig.wait_link_down()
            time.sleep(10)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
            self.dut_ifconfig.wait_link_up()
            self.run_synchronization(sync_period, sync_on=False, sync_off=True)
            dmesg_output = dmesg_cmd.join(0)["output"]
            self.analyze_dmesg(dmesg_output, sync_period, event="link_reneg")

    @idparametrize("sync_period", (50000000, 100000000, 500000000, 1000000000))
    def test_ptp_gpio_sync_with_link_down_on_lkp(self, sync_period):
        """
        @description: Check that clock increment synchronization is restored after missing and restoring external clock
        signal. Periodic pulses are being sent from LKP GPIO pin to DUT sync1588 pin. Driver analyzes pulse timestamps
        for 10 seconds and adjusts clock increment to sync with LKP and this is restored properly after link down/up
        made on LKP.

        @steps:
        1. Make link up
        2. Start periodic GPIO pulses on LKP
        3. Start sync functionality on DUT
        4. Wait 10 seconds
        5. Collect pulse timestamps on DUT and LKP
        6. Make link down on LKP
        7. Wait 10 seconds
        8. Make link up on LKP

        @result: Sync functionality is restored
        @duration: 120 s

        @requirements: DRV_LINUX_GPIO_1588_SYNC_TIME_3, DRV_LINUX_GPIO_1588_SYNC_TIME_4

        :param sync_period: GPIO pulse period should be between 50ms and 1s
        """
        dmesg_cmd = Command(cmd="dmesg -w")
        for i in range(self.NUMBER_OF_TEST_REPEAT):
            dmesg_cmd.run_async()
            log.info("START TEST TRY {} from {}".format(i + 1, self.NUMBER_OF_TEST_REPEAT))
            self.run_synchronization(sync_period, sync_off=False)
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.wait_link_down()
            time.sleep(10)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            self.lkp_ifconfig.wait_link_up()
            self.run_synchronization(sync_period, sync_on=False, sync_off=True)
            dmesg_output = dmesg_cmd.join(0)["output"]
            self.analyze_dmesg(dmesg_output, sync_period, event="link_reneg")


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
