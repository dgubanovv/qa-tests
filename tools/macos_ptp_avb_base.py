import os
import math
import tempfile
import time
import datetime
import shutil
import collections

import matplotlib

from tools.ptp import PTP

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import re

from infra.test_base import TestBase
from tools.driver import Driver
from tools.utils import get_atf_logger, download_file
from tools.power import Power
from perf import iperf
from tools import command
from tools import ifconfig
from tools import killer
from tools import virtual_audio

log = get_atf_logger()


AVB_SOURCE_VIRTUAL_AUDIO = "avbutil"
AVB_SOURCE_NONE = None


class TestMacPtpAvbBase(TestBase):

    LOG_FILE_ADDITIONAL_INFO_CMDS = [
        "echo Systems Info: > ",
        "system_profiler SPSoftwareDataType >> ",
        "echo Darwinup list: >> ",
        "darwinup list >> ",
        "echo Kext version: >> ",
        "kextstat | grep quan >> ",
        "echo Firmware version: >> ",
        "ioreg -l | grep IOFirm >> ",
        "echo Logs: >> ",
    ]
    CRITICAL_ERRORS = [
        "Invalid pdelay req timestamps",
        # "out of expected bounds",
        "outstanding packets",
    ]
    CRITICAL_COUNTERS = [
        "Transmitted PDelay Response Counter",
        "PDelay Response FollowUp Counter",
    ]
    GREP_OPTIONS = [
        "pDelayRaw",
        "Mean Confidence",
        "Median Confidence",
        "Min Confidence",
        "Max Confidence",
        "Confidence range",
        "Port Role",
    ]

    ROUND_TRIP_LIMIT = 1000
    PROP_DELAY_VARIATION_LIMIT = 100
    ERROR_TOLERANCE_TIME = datetime.timedelta(seconds=120)
    PRE_CHECK_TIME = 180
    STREAM_TIME = int(os.environ.get("DURATION", 1200))
    ROLE_LOG_INTERVAL = 60

    def teardown_method(self, method):
        super(TestMacPtpAvbBase, self).teardown_method(method)
        virtual_audio.disable_virtual_audio(self.dut_port)
        for cmd in self.to_kill:
            cmd.join(0)

    def setup_method(self, method):
        super(TestMacPtpAvbBase, self).setup_method(method)
        virtual_audio.disable_virtual_audio(self.dut_port)
        self.to_kill = []

    def start_roles_log(self, hostname, log_file, interval=2):
        script = 'while true; do date "+%H:%M:%S   %d/%m/%Y"; /dos/qa/macos/timesyncutil --validate | grep -A100' \
              ' +IOTimeSyncEthernetPort | grep "Port Role"; sleep {}; done > {}'.format(interval, log_file)
        cmd = "sudo -- sh -c '{}'".format(script)
        roles_cmd = command.Command(cmd=cmd, host=hostname)
        roles_cmd.run_async()
        self.to_kill.append(roles_cmd)
        return roles_cmd

    def get_roles_from_log(self, fileo):
        """Walk through the given log file object and search information about assigned roles"""
        re_port_role = re.compile('.*Port Role:\s*(\w+).*')
        roles = []
        for line in fileo:
            match = re_port_role.match(line)
            if match:
                roles.append(match.group(1))
        return roles

    def start_delay_log(self, hostname, log_file, interval=1):
        script = 'while true; do date "+%H:%M:%S   %d/%m/%Y"; /dos/qa/macos/timesyncutil --validate | grep -A100' \
              ' +IOTimeSyncEthernetPort | grep " Delay"; sleep {}; done > {}'.format(interval, log_file)
        cmd = "sudo -- sh -c '{}'".format(script)
        pdelay_cmd = command.Command(cmd=cmd, host=hostname)
        pdelay_cmd.run_async()
        self.to_kill.append(pdelay_cmd)
        return pdelay_cmd

    @staticmethod
    def get_timestamps_from_log_file(file_name):
        """Read timestamps from the log file"""
        ts_reg = re.compile(".*(\d+:\d+:\d+\s+\d+/\d+/\d+).*")
        timestamps = []
        with open(file_name, "r") as fileo:
            for line in fileo:
                match = ts_reg.match(line)
                if match:
                    timestamp = match.group(1)
                    timestamp = datetime.datetime.strptime(timestamp, "%H:%M:%S   %d/%m/%Y")
                    timestamps.append(timestamp)
        return timestamps

    def copy_to_test_dir(self, file_path):
        log.info("Copy file {} to: {}".format(file_path, self.test_log_dir))
        new_path = os.path.join(self.test_log_dir, os.path.basename(file_path))
        shutil.copy(file_path, new_path)

    def check_roles(self, *args):
        """Check that roles are stable basing on given log files"""

        dut_log_file, lkp_log_file, _, _ = args
        with open(dut_log_file, 'r') as dut_fileo:
            dut_roles = self.get_roles_from_log(dut_fileo)
            idx = []
            for role in ("Master", "Slave"):
                if role in dut_roles:
                    idx.append(dut_roles.index(role))
            dut_roles = dut_roles[max(idx):]
        log.debug("DUT ROLES: {}".format(dut_roles))
        lkp_roles = None
        if lkp_log_file is not None:
            with open(lkp_log_file, 'r') as lkp_fileo:
                lkp_roles = self.get_roles_from_log(lkp_fileo)
                idx = []
                for role in ("Master", "Slave"):
                    if role in lkp_roles:
                        idx.append(lkp_roles.index(role))
                lkp_roles = lkp_roles[max(idx):]
            log.debug("LKP ROLES: {}".format(lkp_roles))

        # Check that role was assigned on both sides
        assert len(dut_roles) > 0, "Role was not assigned on DUT"

        # Check that roles were not changed on both sudes during stream execution
        assert len(set(dut_roles)) == 1, "Role on DUT was changed"

        # Role must be "Master" or "Slave"
        assert dut_roles[0] in ["Master", "Slave"], "DUT role not Master or Slave"

        # Master cannot be on both sides
        # Slave can be on both sides in case of switch setup
        if lkp_roles is not None:
            assert len(lkp_roles) > 0, "Role was not assigned on LKP"
            assert len(set(lkp_roles)) == 1, "Role on LKP was changed"
            assert lkp_roles[0] in ["Master", "Slave"], "LKP role not Master or Slave"
            assert not (dut_roles[0] == "Master" and lkp_roles[0] == "Master"), "Master roles were assigned on DUT and LKP"

    def pre_check_roles(self, dut_log_file, lkp_log_file=None):
        """Check that the test can be continued after pre-check time"""
        with open(dut_log_file, 'r') as dut_fileo:
            dut_roles = self.get_roles_from_log(dut_fileo)
            idx = []
            for role in ("Master", "Slave"):
                if role in dut_roles:
                    idx.append(dut_roles.index(role))
            dut_roles = dut_roles[max(idx):]
        log.debug("DUT ROLES: {}".format(dut_roles))
        lkp_roles = None
        if lkp_log_file is not None:
            with open(lkp_log_file, 'r') as lkp_fileo:
                lkp_roles = self.get_roles_from_log(lkp_fileo)
                idx = []
                for role in ("Master", "Slave"):
                    if role in lkp_roles:
                        idx.append(lkp_roles.index(role))
                lkp_roles = lkp_roles[max(idx):]
            log.debug("LKP ROLES: {}".format(lkp_roles))

        # Check that role was assigned on both sides
        assert len(dut_roles) > 0, "Role was not assigned on DUT"
        assert "Master" in dut_roles or "Slave" in dut_roles

        if lkp_roles is not None:
            assert len(lkp_roles) > 0, "Role was not assigned on LKP"
            assert "Master" in lkp_roles or "Slave" in lkp_roles

            assert dut_roles[-1] != "Disabled" and lkp_roles[-1] != "Disabled"

    def check_delays(self, *args, **kwargs):
        """Check that round trip delay is always positive and below threshold"""
        _, _, dut_delay_log_file, lkp_delay_log_file = args

        regs = collections.OrderedDict([
            ("prop_delay", re.compile(".*\|\s+Propagation Delay:\s+(\d+).*")),
            ("max_prop_delay", re.compile(".*\|\s+Maximum Propagation Delay:\s+(\d+).*")),
            ("min_prop_delay", re.compile(".*\|\s+Minimum Propagation Delay:\s+(\d+).*")),
            ("max_raw_delay", re.compile(".*\|\s+Maximum Raw Delay:\s+(\d+).*")),
            ("min_raw_delay", re.compile(".*\|\s+Minimum Raw Delay:\s+(\d+).*")),

        ])
        results = collections.OrderedDict([(key, []) for key in regs.keys()])
        with open(dut_delay_log_file, 'r') as fileo:
            for line in fileo:
                for key, reg in regs.items():
                    match = reg.match(line)
                    if match:
                        value = int(match.group(1))
                        results[key].append(value)
                        break

        # Cat first 20 measurements
        results["prop_delay"] = results["prop_delay"][20:]
        results["max_prop_delay"] = results["max_prop_delay"][20:]
        results["min_prop_delay"] = results["min_prop_delay"][20:]
        results["max_raw_delay"] = results["max_raw_delay"][20:]
        results["min_raw_delay"] = results["min_raw_delay"][20:]

        max_prop_delay = max(results["prop_delay"])
        min_prop_delay = min(results["prop_delay"])
        avg_prop_delay = sum(results["prop_delay"])/len(results["prop_delay"])
        log.info("Max propagation delay: {}".format(max_prop_delay))
        log.info("Min propagation delay: {}".format(min_prop_delay))
        log.info("Avg propagation delay: {}".format(avg_prop_delay))
        log.info("Var propagation delay: {}".format(max_prop_delay - min_prop_delay))
        max_raw_delay = results["max_raw_delay"][-1]
        min_raw_delay = results["min_raw_delay"][-1]
        log.info("Max raw delay: {}".format(max_raw_delay))
        log.info("Min raw delay: {}".format(min_raw_delay))
        log.info("Var raw delay: {}".format(max_raw_delay - min_raw_delay))

        timestamps = self.get_timestamps_from_log_file(dut_delay_log_file)
        timestamps = timestamps[20:]
        for key in results.keys():
            results[key] = zip(timestamps, results[key])
        make_plot = kwargs.get("make_plot", True)
        if make_plot:
            output_folder = self.test_log_dir
            plot_path = os.path.join(output_folder, "delays_plot.png")
            self.make_round_trip_plot(results, plot_path)
        assert min_raw_delay >= 0, "Negative raw delay measurements were found"
        assert max_raw_delay < self.ROUND_TRIP_LIMIT, "Raw delay measurements > {} were found".format(
            self.ROUND_TRIP_LIMIT
        )
        assert max_prop_delay - min_prop_delay < self.PROP_DELAY_VARIATION_LIMIT, "Propagation delay variation " \
            "exceeds {}".format(self.PROP_DELAY_VARIATION_LIMIT)
        return results

    def make_round_trip_plot(self, results, output_file):
        """
        Draw a plot from the given results. Results should be provided as a dict where keys are used to draw legend,
        values must be lists of tuples of 2 elements: (x, y)
        """
        fig, ax = plt.subplots(nrows=1, ncols=1)
        ax.tick_params(labelsize=8)
        ax.grid(True)
        start_time = results["prop_delay"][0][0]
        max_y_values = []
        min_y_values = []
        max_x_values = []
        min_x_values = []
        for key in results.keys():
            x_results = [(ts - start_time).total_seconds() for ts, _ in results[key]]
            y_results = [round_trip for _, round_trip in results[key]]
            ax.plot(x_results, y_results, label=key)
            max_x_values.append(max(x_results))
            min_x_values.append(min(x_results))
            max_y_values.append(max(y_results))
            min_y_values.append(min(y_results))
            ax.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            if key == "pdelay_raw":
                ax.axhline(y=max(y_results), color='r', linestyle='-')
                ax.axhline(y=min(y_results), color='g', linestyle='-')
        min_y = min(min_x_values)
        max_y = max(max_y_values)
        min_x = min(min_x_values)
        max_x = max(max_x_values)
        xstep = int(max_x - min_x) / 40
        xstep = 1 if xstep == 0 else xstep
        ystep = (max_y - min_y) / 50
        ystep = 1 if ystep == 0 else ystep

        xx = np.arange(0, math.ceil(x_results[-1]) + xstep, xstep)
        yy = np.arange(min_y - ystep, max_y + ystep, ystep)
        ax.yaxis.label.set_size(40)
        ax.set_xticks(xx)
        ax.set_yticks(yy)

        fig.set_size_inches(40, 8)
        fig.savefig(output_file, dpi=300)
        plt.close(fig)


class TestMacPtpAvbBackToBack(TestMacPtpAvbBase):
    """
    Tests for PTP/AVB.

    This class implements test cases for the following scenarios:
    PTP + Iperf
    PTP + AVB via avbstreamrx/tx tools
    PTP + AVB via avbutil --virtual-audio tool
    PTP + AVB via avbstreamrx/tx tools + Iperf
    PTP + AVB via avbutil --virtual-audio tool + Iperf
    """
    SKIP_INSTALL = bool(os.environ.get("SKIP_INSTALL", False))
    RETRY_CNT = 3
    IPERF_RUN_TIME = 300
    IPERF_DURATION = TestMacPtpAvbBase.STREAM_TIME - 2 * IPERF_RUN_TIME # symmetric 5 minutes without iperf before perf and after
    SLEEP_AFTER_STREAM_STOPPING = 30
    COMMAND_TIMEOUT = 20

    @classmethod
    def setup_class(cls):
        super(TestMacPtpAvbBackToBack, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.dut_power = Power()
            cls.lkp_power = Power(host=cls.lkp_hostname)
            cls.NETMASK_IPV4 = "255.255.0.0"
            if not cls.state.skip_class_setup:
                if not cls.SKIP_INSTALL:
                    cls.install_firmwares()
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
                    cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
                    cls.lkp_driver.install()
                    cls.dut_driver.install()
    
                log.debug("WORKING_DIR: {}".format(cls.working_dir))
                cls.state.skip_class_setup = True
                cls.state.update()
            else:
                cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port)
                cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)
                if cls.LKP_IPV4_ADDR == cls.DUT_IPV4_ADDR:
                    octets = cls.LKP_IPV4_ADDR.split(".")
                    octets[-1] = str(int(octets[-1]) + 1)
                    cls.LKP_IPV4_ADDR = ".".join(octets)
                cls.dut_virtual_audio = virtual_audio.VirtualAudio(port=cls.dut_port)
                cls.lkp_virtual_audio = virtual_audio.VirtualAudio(host=cls.lkp_hostname, port=cls.lkp_port)
                cls.start_time = None

            cls.ptp = PTP(
                dut_hostname=cls.dut_hostname, dut_port=cls.dut_port, lkp_hostname=cls.lkp_hostname,
                lkp_port=cls.lkp_port,
            )
            
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def teardown_method(self, method):
        super(TestMacPtpAvbBackToBack, self).teardown_method(method)
        virtual_audio.VirtualAudio(host=self.lkp_hostname, port=self.lkp_port).disable_virtual_audio()

    def setup_method(self, method):
        super(TestMacPtpAvbBackToBack, self).setup_method(method)
        virtual_audio.VirtualAudio(host=self.lkp_hostname, port=self.lkp_port).disable_virtual_audio()

    def ptp_avb_bidir_get_log(self, link_speed, avb_source, packet_period=None, bg_iperf=False, nr_of_streams=1):
        """Run avbutil or avbstremrx/tx or timesync util and iperf using specified parameters"""
        if avb_source not in [AVB_SOURCE_VIRTUAL_AUDIO, AVB_SOURCE_NONE]:
            raise Exception(
                "Unknown avb source. Should be one of {}".format([AVB_SOURCE_VIRTUAL_AUDIO, AVB_SOURCE_NONE])
            )

        iperf_str = "iperf_" if bg_iperf else ""
        virtual_avb_str = "virtual_avb_" if avb_source == AVB_SOURCE_VIRTUAL_AUDIO else ""
        no_avb_str = "no_avb_" if avb_source == AVB_SOURCE_NONE else ""
        common_part = "{}_{}{}{}{}".format(link_speed, virtual_avb_str, no_avb_str, iperf_str, self.job_id)
        dut_roles_log_file = os.path.join("/tmp/", "dut_roles_log_{}.txt".format(common_part))
        lkp_roles_log_file = os.path.join("/tmp/", "lkp_roles_log_{}.txt".format(common_part))
        dut_delays_log_file = os.path.join("/tmp/", "dut_delays_log_{}.txt".format(common_part))
        lkp_delays_log_file = os.path.join("/tmp/", "lkp_delays_log_{}.txt".format(common_part))
        self.round_trip_plot_file = os.path.join("/tmp/", "round_trip_plot_{}.png".format(common_part))
        self.round_trip_plot_file_add = os.path.join("/tmp/", "round_trip_plot_additional_{}.png".format(common_part))

        if all(os.path.exists(item) for item in (dut_roles_log_file, lkp_roles_log_file)):
            log.info("Log files exist. Skipping stream execution.")
        else:
            if not self.state.skip_reboot:
                self.state.skip_reboot = True
                self.state.update()
                self.lkp_power.reboot()
                self.dut_power.reboot()
                time.sleep(30)
            else:
                self.state.skip_reboot = False
                self.state.update()

            self.dut_iface = self.dut_ifconfig.get_conn_name()
            self.lkp_iface = self.lkp_ifconfig.get_conn_name()
            log.debug('State tests after setup: {}'.format(self.state.tests))
            log.debug('State skip reboot after setup: {}'.format(self.state.skip_reboot))

            self.dut_ifconfig.set_link_speed(link_speed)
            self.lkp_ifconfig.set_link_speed(link_speed)
            self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.NETMASK_IPV4, None)
            self.lkp_ifconfig.set_ip_address(self.LKP_IPV4_ADDR, self.NETMASK_IPV4, None)
            self.dut_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)
            self.dut_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)
            self.dut_ifconfig.wait_link_up(self.COMMAND_TIMEOUT)

            # Create iperf entities
            dut_iperf_server = iperf.IperfServer(
                host=self.dut_hostname, time=self.IPERF_DURATION, ip_server=self.DUT_IPV4_ADDR, speed=link_speed
            )
            dut_iperf_client = iperf.IperfClient(
                host=self.dut_hostname, num_threads=4, ip_server=self.LKP_IPV4_ADDR, time=self.IPERF_DURATION
            )
            lkp_iperf_server = iperf.IperfServer(
                host=self.lkp_hostname, time=self.IPERF_DURATION, ip_server=self.LKP_IPV4_ADDR, speed=link_speed
            )
            lkp_iperf_client = iperf.IperfClient(
                host=self.lkp_hostname, num_threads=4, ip_server=self.DUT_IPV4_ADDR, time=self.IPERF_DURATION
            )

            # self.start_log_streaming(dut_roles_log_file, lkp_roles_log_file)
            TestMacPtpAvbBase.start_time = datetime.datetime.now()
            log.info("START TIME = {}".format(TestMacPtpAvbBase.start_time))

            if avb_source == AVB_SOURCE_VIRTUAL_AUDIO:
                self.dut_virtual_audio.enable_virtual_audio()
                time.sleep(10)
                if link_speed == ifconfig.LINK_SPEED_100M:
                    self.dut_virtual_audio.set_avb_device_config(virtual_audio.CONFIG_1_STREAM)
                else:
                    self.dut_virtual_audio.set_avb_device_config(virtual_audio.CONFIG_8_STREAMS)
            else:
                self.ptp.enable()
            time.sleep(2)
            dut_roles_cmd = self.start_roles_log(self.dut_hostname, dut_roles_log_file, 1)
            lkp_roles_cmd = self.start_roles_log(self.lkp_hostname, lkp_roles_log_file, 1)
            dut_delays_cmd = self.start_delay_log(self.dut_hostname, dut_delays_log_file, 1)
            lkp_delays_cmd = self.start_delay_log(self.lkp_hostname, lkp_delays_log_file, 1)

            log.info("Sleeping for {} seconds before checking preliminary results".format(self.PRE_CHECK_TIME))
            time.sleep(self.PRE_CHECK_TIME)

            download_file(self.lkp_hostname, lkp_roles_log_file, lkp_roles_log_file)
            download_file(self.lkp_hostname, lkp_delays_log_file, lkp_delays_log_file)

            self.copy_to_test_dir(dut_roles_log_file)
            self.copy_to_test_dir(lkp_roles_log_file)
            self.copy_to_test_dir(dut_delays_log_file)
            self.copy_to_test_dir(lkp_delays_log_file)
            self.pre_check_roles(dut_roles_log_file, lkp_roles_log_file)

            log.info("Sleeping for {} seconds".format(self.IPERF_RUN_TIME - self.PRE_CHECK_TIME))
            time.sleep(self.IPERF_RUN_TIME - self.PRE_CHECK_TIME)
            if bg_iperf:
                dut_iperf_server.run_async()
                lkp_iperf_server.run_async()
                lkp_iperf_client.run_async()
                dut_iperf_client.run_async()

            log.info("Sleeping for {} seconds".format(self.STREAM_TIME - self.IPERF_RUN_TIME))
            time.sleep(self.STREAM_TIME - self.IPERF_RUN_TIME)
            dut_roles_cmd.join(0)
            lkp_roles_cmd.join(0)
            dut_delays_cmd.join(0)
            lkp_delays_cmd.join(0)

            download_file(self.lkp_hostname, lkp_roles_log_file, lkp_roles_log_file)
            download_file(self.lkp_hostname, lkp_delays_log_file, lkp_delays_log_file)

            if avb_source == AVB_SOURCE_NONE:
                self.ptp.disable()
            if bg_iperf:
                log.info("Waiting for iperf to be finished")
                dut_iperf_client_result = dut_iperf_client.join(0)
                lkp_iperf_client_result = lkp_iperf_client.join(0)
                dut_iperf_server_result = dut_iperf_server.join(0)
                lkp_iperf_server_result = lkp_iperf_server.join(0)

                log.info("DUT IPERF CLIENT RESULT: {}".format(dut_iperf_client_result))
                log.info("LKP IPERF CLIENT RESULT: {}".format(lkp_iperf_client_result))
                log.info("DUT IPERF SERVER RESULT: {}".format(dut_iperf_server_result))
                log.info("LKP IPERF SERVER RESULT: {}".format(lkp_iperf_server_result))
            self.copy_to_test_dir(dut_roles_log_file)
            self.copy_to_test_dir(lkp_roles_log_file)
            self.copy_to_test_dir(dut_delays_log_file)
            self.copy_to_test_dir(lkp_delays_log_file)

        return dut_roles_log_file, lkp_roles_log_file, dut_delays_log_file, lkp_delays_log_file
