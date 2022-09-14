import copy
import math
import os
import re
import shutil
import time

import pytest

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import re

from infra.test_base import TestBase
from tools.command import Command
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, \
    LINK_SPEED_AUTO, VENDOR_MOTU
from tools.driver import Driver
from perf.iperf import Iperf
from tools.killer import Killer
from tools.utils import get_atf_logger, upload_file

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "ptp_linux"


class TestPtpLinux(TestBase):
    PTP4L_EXEC_TIME = 120
    PTP4L_STABILITY_EXEC_TIME = 60 * 60 * 5  # 5 hours
    # PTP4L_MASTER_OFFSET_EPS, PTP4L_FREQ_EPS, PTP4L_PATH_DELAY_VARIATION are measured on Intel cards
    PTP4L_MASTER_OFFSET_EPS = 120
    PTP4L_FREQ_EPS = 100
    PTP4L_PATH_DELAY_RAW_VARIATION = 160
    PTP4L_PATH_DELAY_FILTERED_VARIATION = 70
    PDELAY_ABSOLUTE_LIMIT = 1000
    MAX_NOF_OUT_OF_SYNCS = 10
    NUMBER_OF_SKIPPED_PDELAYS = 20
    NUMBER_OF_MASTER_OFFSETS = 20
    NUMBER_OF_SKIPPED_PPBS = 20
    MASTER_OFFSET_MIN_THRESHOLD = -1000
    MASTER_OFFSET_MAX_THRESHOLD = 1000
    FREQ_ADJ_VARIATION_LIMIT = 10000

    PTP4L_L2 = "L2"
    PTP4L_UDPv4 = "UDPv4"
    PTP4L_UDPv6 = "UDPv6"
    PTP4L_E2E = "E2E"
    PTP4L_P2P = "P2P"
    RE_PTP4L_STAT = re.compile(r"^ptp4l\[([0-9\.]+)\]: master "
                               "offset\s*([\-\+0-9]+)\s*s2\s*freq\s*([\-\+0-9]+)\s*path delay\s*([\-0-9]+)")
    RE_PTP4L_PDELAY = re.compile(r"^ptp4l\[([0-9\.]+)\]: delay\s*filtered\s*(-?\d+)\s*raw\s*(-?\d+)$")

    OFFSETS = {
        "100M": {
            "L2": {
                "E2E": (1350, 1300),
                "P2P": (1500, 1450),
            },
            "UDPv4": {
                "E2E": (2300, 2300),
                "P2P": (1600, 1600),
            }
        },
        "1G": {
            "L2": {
                "E2E": (200, 100),
                "P2P": (100, 0),
            },
            "UDPv4": {
                "E2E": (200, 100),
                "P2P": (1600, 1600),
            }
        },
        "2.5G": {
            "L2": {
                "E2E": (-300, -300),
                "P2P": (-500, -500),
            },
            "UDPv4": {
                "E2E": (-300, -300),
                "P2P": (-200, -200),
            }
        },
        "5G": {
            "L2": {
                "E2E": (-100, -100),
            },
        },
        "10G": {},
    }

    PDELAY_VARIATION_LIMIT = {
        "100M": 200,
        "1G": 160,
        "2.5G": 600,  # The worst variation. Known issue.
        "5G": 300,  # Too high variation. Known issue.
        "10G": 100,
    }


    PTP4L_DEFAULT_CONFIG = {
        # Default Data Set
        "gmCapable": 1, "twoStepFlag": 1, "slaveOnly": 0, "priority1": 128, "priority2": 128, "domainNumber": 0,
        "clockClass": 248, "clockAccuracy": 0xFE, "offsetScaledLogVariance": 0xFFFF, "free_running": 0,
        "freq_est_interval": 1,
        # Next options are deprecated
        # "dscp_event": 0, "dscp_general": 0,  # "utc_offset": 37,
        # Port Data Set
        "logAnnounceInterval": 1, "logSyncInterval": 1, "logMinDelayReqInterval": 0, "logMinPdelayReqInterval": 0,
        "announceReceiptTimeout": 3, "syncReceiptTimeout": 3, "delayAsymmetry": 0, "fault_reset_interval": 4,
        "neighborPropDelayThresh": 20000000,
        # Run time options
        "assume_two_step": 0, "logging_level": 7, "path_trace_enabled": 0, "follow_up_info": 0, "hybrid_e2e": 0,
        "tx_timestamp_timeout": 100, "use_syslog": 1, "verbose": 0, "summary_interval": 0, "kernel_leap": 1,
        "check_fup_sync": 0,
        # Servo Options
        "pi_proportional_const": 0.0, "pi_integral_const": 0.0, "pi_proportional_scale": 0.0,
        "pi_proportional_exponent": -0.3, "pi_proportional_norm_max": 0.7, "pi_integral_scale": 0.0,
        "pi_integral_exponent": 0.4, "pi_integral_norm_max": 0.3, "step_threshold": 0.0,
        "first_step_threshold": 0.00002, "max_frequency": 900000000, "clock_servo": "pi",
        "sanity_freq_limit": 200000000, "ntpshm_segment": 0,
        # Transport options
        "transportSpecific": 0x1, "ptp_dst_mac": "01:1B:19:00:00:00", "p2p_dst_mac": "01:80:C2:00:00:0E", "udp_ttl": 1,
        "udp6_scope": 0x0E, "uds_address": "/var/run/ptp4l",
        # Default interface options
        "network_transport": "UDPv4", "delay_mechanism": "E2E", "time_stamping": "hardware", "tsproc_mode": "filter",
        "delay_filter": "moving_median", "delay_filter_length": 10, "egressLatency": 0, "ingressLatency": 0,
        "boundary_clock_jbod": 0,
        # Clock description
        "productDescription": ";;", "revisionData": ";;", "manufacturerIdentity": "00:00:00", "userDescription": ";",
        "timeSource": 0xA0
    }

    SYNC_UP_TYME = 5  # Need to adjust this value
    GPTP_EXEC_TIME = 120
    GPTP_EXEC_TIME_STABILITY = 60 * 15
    GPTP_EXEC_TIME_LONGEVITY = 60 * 120
    MASTER_ROLE = "MASTER"
    SLAVE_ROLE = "SLAVE"
    GPTP_PATH_DELAY_VARIATION = 160

    @classmethod
    def setup_class(cls):
        super(TestPtpLinux, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.skip_dut_fw_install = not cls.is_dut_aquantia()
            cls.skip_lkp_fw_install = not cls.is_lkp_aquantia()

            cls.install_firmwares()

            Command(cmd="sudo modprobe ptp").run()
            if not (cls.is_lkp_motu() or cls.is_lkp_xmos()):
                Command(cmd="sudo modprobe ptp", host=cls.lkp_hostname).run()

            if cls.is_dut_aquantia():
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
                cls.dut_driver.install()
            if cls.is_lkp_aquantia():
                cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
                cls.lkp_driver.install()

            cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port)
            cls.DUT_IPV6_ADDR = cls.suggest_test_ip_address(cls.dut_port, None, True)
            cls.NETMASK_IPV4 = "255.255.0.0"

            if not (cls.is_lkp_motu() or cls.is_lkp_xmos()):
                cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)
                cls.LKP_IPV6_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname, True)

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            time.sleep(3)  # workaround for T2 intel adapter

            if not (cls.is_lkp_motu() or cls.is_lkp_xmos()):
                cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)
                time.sleep(3)  # workaround for T2 intel adapter

            cls.dut_ifconfig.set_ipv6_address(cls.DUT_IPV6_ADDR, cls.DEFAULT_PREFIX_IPV6, None)
            time.sleep(3)  # workaround for T2 intel adapter

            if not (cls.is_lkp_motu() or cls.is_lkp_xmos()):
                cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IPV6_ADDR, cls.DEFAULT_PREFIX_IPV6, None)
                time.sleep(3)  # workaround for T2 intel adapter

            Command(cmd="sudo iptables -I INPUT -p udp -m udp --dport 319 -j ACCEPT").run()
            Command(cmd="sudo iptables -I INPUT -p udp -m udp --dport 320 -j ACCEPT").run()
            if not (cls.is_lkp_motu() or cls.is_lkp_xmos()):
                Command(cmd="sudo iptables -I INPUT -p udp -m udp --dport 319 -j ACCEPT", host=cls.lkp_hostname).run()
                Command(cmd="sudo iptables -I INPUT -p udp -m udp --dport 320 -j ACCEPT", host=cls.lkp_hostname).run()

            Command(cmd="sudo ip6tables -I INPUT -p udp -m udp --dport 319 -j ACCEPT").run()
            Command(cmd="sudo ip6tables -I INPUT -p udp -m udp --dport 320 -j ACCEPT").run()
            if not (cls.is_lkp_motu() or cls.is_lkp_xmos()):
                Command(cmd="sudo ip6tables -I INPUT -p udp -m udp --dport 319 -j ACCEPT", host=cls.lkp_hostname).run()
                Command(cmd="sudo ip6tables -I INPUT -p udp -m udp --dport 320 -j ACCEPT", host=cls.lkp_hostname).run()

            cls.iperf_config = {
                'lkp_hostname': cls.lkp_hostname,
                'dut4': cls.DUT_IPV4_ADDR,
                'dut6': cls.DUT_IPV6_ADDR
            }

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def is_lkp_motu(cls):
        return cls.lkp_fw_card is None

    @classmethod
    def is_lkp_xmos(cls):
        # TODO: placeholder
        return False

    @classmethod
    def is_dut_intel(cls):
        return "intel" in cls.dut_fw_card.lower()

    @classmethod
    def is_lkp_intel(cls):
        if cls.lkp_fw_card is None:
            return False
        return "intel" in cls.lkp_fw_card.lower()

    @classmethod
    def is_dut_aquantia(cls):
        res = cls.is_dut_intel()
        return not res

    @classmethod
    def is_lkp_aquantia(cls):
        res = cls.is_lkp_motu()
        res |= cls.is_lkp_intel()
        return not res

    def setup_method(self, method):
        super(TestPtpLinux, self).setup_method(method)

        dut_killer = Killer()
        dut_killer.kill("gptp")
        dut_killer.kill("ptp4l")
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            lkp_killer = Killer(host=self.lkp_hostname)
            lkp_killer.kill("gptp")
            lkp_killer.kill("ptp4l")

    def get_ptp4l_cmd(self, iface, config_file):
        return "sudo ptp4l -i {} -m -f {}".format(iface, config_file)

    def get_gptp_cmd(self, iface, role):
        return "sudo gptp {} {} -E".format(iface, "-T" if role == self.MASTER_ROLE else "-L")

    def get_bmc_result(self, dut_output, lkp_output):
        is_master_found = False
        is_master_dut = False
        for line in dut_output:
            if "UNCALIBRATED to SLAVE" in line:
                is_master_found = True
                is_master_dut = False
                log.info("PTP master is DUT")
        for line in lkp_output:
            if "UNCALIBRATED to SLAVE" in line:
                is_master_found = True
                is_master_dut = True
                log.info("PTP master is LKP")

        if not is_master_found:
            for line in dut_output:
                if "LISTENING to GRAND_MASTER" in line or "LISTENING to MASTER" in line:
                    is_master_found = True
                    is_master_dut = True
                    log.info("PTP master is DUT")
            for line in lkp_output:
                if "LISTENING to GRAND_MASTER" in line or "LISTENING to MASTER" in line:
                    is_master_found = True
                    is_master_dut = False
                    log.info("PTP master is LKP")

        assert is_master_found is True
        return is_master_dut

    def make_plot(self, results, output_file):
        """
        Draw a plot from the given results. Results should be provided as a dict where keys are used to draw legend,
        values must be lists of tuples of 2 elements: (x, y)
        """
        fig, ax = plt.subplots(nrows=1, ncols=1)
        ax.tick_params(labelsize=8)
        ax.grid(True)
        start_time, _ = results[results.keys()[0]][0]
        max_y_values = []
        min_y_values = []
        max_x_values = []
        min_x_values = []
        for key in results.keys():
            x_results = [ts - start_time for ts, _ in results[key]]
            y_results = [round_trip for _, round_trip in results[key]]
            ax.plot(x_results, y_results, label=key)
            max_x_values.append(max(x_results))
            min_x_values.append(min(x_results))
            max_y_values.append(max(y_results))
            min_y_values.append(min(y_results))
            ax.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            if "pdelay" in key:
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

    def verify_slave_output(self, output, speed):
        do_check = False

        pdelays_plot_file = os.path.join(self.test_log_dir, "pdelays_plot.png")
        master_offsets_plot_file = os.path.join(self.test_log_dir, "master_offsets_plot.png")
        freqs_plot_file = os.path.join(self.test_log_dir, "ppbs_plot.png")

        path_delays_filtered = []
        path_delays_raw = []
        master_offsets = []
        freqs = []
        for line in output:
            if "FAULT_DETECTED" in line:
                raise Exception("Fault detected by ptp4l")
            if "UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED" in line:
                do_check = True
            if do_check is True:
                ptp_stat_match = self.RE_PTP4L_STAT.match(line)
                ptp_delay_match = self.RE_PTP4L_PDELAY.match(line)

                if ptp_stat_match:
                    _time, master_offset, freq, _ = map(lambda x: float(x), ptp_stat_match.groups())
                    master_offsets.append((_time, master_offset))
                    freqs.append((_time, freq))
                if ptp_delay_match:
                    _time, delay_filtered, delay_raw = map(lambda x: float(x), ptp_delay_match.groups())
                    path_delays_filtered.append((_time, delay_filtered))
                    path_delays_raw.append((_time, delay_raw))

        path_delays_filtered = path_delays_filtered[self.NUMBER_OF_SKIPPED_PDELAYS:]
        path_delays_raw = path_delays_raw[self.NUMBER_OF_SKIPPED_PDELAYS:]

        assert do_check is True, "PTP sync was not calibrated at all"

        plot_data = {
            "pdelay_raw": path_delays_raw,
            "pdelay_filtered": path_delays_filtered,
        }
        self.make_plot(plot_data, pdelays_plot_file)
        plot_data = {
            "master_offsets": master_offsets
        }
        self.make_plot(plot_data, master_offsets_plot_file)
        plot_data = {
            "ppbs": freqs
        }
        self.make_plot(plot_data, freqs_plot_file)

        raw_pdelays = [item for _, item in path_delays_raw]
        filtered_pdelays = [item for _, item in path_delays_filtered]
        
        raw_variation = max(raw_pdelays) - min(raw_pdelays)
        log.info("linuxptp raw path delays: {}".format(raw_pdelays))
        log.info("linuxptp raw path delays: min = {}, max = {}, variation = {}".format(
            min(raw_pdelays), max(raw_pdelays), raw_variation))

        filtered_variation = max(filtered_pdelays) - min(filtered_pdelays)
        log.info("linuxptp filtered path delays: {}".format(filtered_pdelays))
        log.info("linuxptp filtered path delays: min = {}, max = {}, variation = {}".format(
            min(filtered_pdelays), max(filtered_pdelays), filtered_variation))
        log.info("Master offsets: {}".format(master_offsets))
        log.info("Frequency adjustment parameters: {}".format(freqs))
        # pDelays checks
        assert all(item >= 0 for item in raw_pdelays), "Negative raw pDelay found"
        assert all(item >= 0 for item in filtered_pdelays), "Negative filtered pDelay found"
        assert raw_variation <= self.PDELAY_VARIATION_LIMIT[speed], "Too big raw path delay variation"
        assert filtered_variation <= self.PDELAY_VARIATION_LIMIT[speed], "Too big filtered path delay variation"
        assert all(0 < item < self.PDELAY_ABSOLUTE_LIMIT for item in raw_pdelays), "Some times raw pDelay value " \
            "is greater than {}".format(self.PDELAY_ABSOLUTE_LIMIT)

        master_offsets = [item for _, item in master_offsets[self.NUMBER_OF_MASTER_OFFSETS:]]
        assert all(
            self.MASTER_OFFSET_MIN_THRESHOLD < item < self.MASTER_OFFSET_MAX_THRESHOLD for item in master_offsets
        ), "After {} iterations master offset is out of thresholds: {}:{}".format(
            self.NUMBER_OF_MASTER_OFFSETS, self.MASTER_OFFSET_MIN_THRESHOLD, self.MASTER_OFFSET_MAX_THRESHOLD
        )
        freqs = [item for _, item in freqs[self.NUMBER_OF_SKIPPED_PPBS:]]
        freq_variation = max(freqs) - min(freqs)
        assert freq_variation < self.FREQ_ADJ_VARIATION_LIMIT, "Frequency adjustment parameter variation {} is " \
            "beyond the limit {}".format(freq_variation, self.FREQ_ADJ_VARIATION_LIMIT)

    def verify_master_output(self, output, speed):
        do_check = False

        pdelays_plot_file = os.path.join(self.test_log_dir, "pdelays_plot.png")

        path_delays_filtered = []
        path_delays_raw = []
        for line in output:
            print "!{}".format(line)
            if "FAULT_DETECTED" in line:
                raise Exception("Fault detected by ptp4l")
            if "LISTENING to GRAND_MASTER" in line or "LISTENING to MASTER" in line:
                do_check = True
            if do_check is True:
                ptp_delay_match = self.RE_PTP4L_PDELAY.match(line)
                if ptp_delay_match:
                    _time, delay_filtered, delay_raw = map(lambda x: float(x), ptp_delay_match.groups())
                    path_delays_filtered.append((_time, delay_filtered))
                    path_delays_raw.append((_time, delay_raw))

        path_delays_filtered = path_delays_filtered[self.NUMBER_OF_SKIPPED_PDELAYS:]
        path_delays_raw = path_delays_raw[self.NUMBER_OF_SKIPPED_PDELAYS:]

        assert do_check, "PTP sync was not calibrated at all"

        plot_data = {
            "pdelay_raw": path_delays_raw,
            "pdelay_filtered": path_delays_filtered,
        }
        self.make_plot(plot_data, pdelays_plot_file)

        raw_pdelays = [item for _, item in path_delays_raw]
        filtered_pdelays = [item for _, item in path_delays_filtered]

        raw_variation = max(raw_pdelays) - min(raw_pdelays)
        log.info("linuxptp raw path delays: {}".format(raw_pdelays))
        log.info("linuxptp raw path delays: min = {}, max = {}, variation = {}".format(
            min(raw_pdelays), max(raw_pdelays), raw_variation))

        filtered_variation = max(filtered_pdelays) - min(filtered_pdelays)
        log.info("linuxptp filtered path delays: {}".format(filtered_pdelays))
        log.info("linuxptp filtered path delays: min = {}, max = {}, variation = {}".format(
            min(filtered_pdelays), max(filtered_pdelays), filtered_variation))
        # pDelays checks
        assert all(item >= 0 for item in raw_pdelays), "Negative raw pDelay found"
        assert all(item >= 0 for item in filtered_pdelays), "Negative filtered pDelay found"
        assert raw_variation <= self.PDELAY_VARIATION_LIMIT[speed], "Too big raw path delay variation"
        assert filtered_variation <= self.PDELAY_VARIATION_LIMIT[speed], "Too big filtered path delay variation"
        assert all(0 < item < self.PDELAY_ABSOLUTE_LIMIT for item in raw_pdelays), \
            "Some times raw pDelay value is greater than {}".format(self.PDELAY_ABSOLUTE_LIMIT)

    def create_cfg_files(self, dut_cfg, lkp_cfg):
        local_file = "/home/aqtest/ptp4l.cfg"
        remote_dir = "~/"
        remote_file = "~/ptp4l.cfg"

        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            with open(local_file, "w") as f:
                f.write("[global]\n")
                for k, v in lkp_cfg.items():
                    f.write("{} {}\n".format(k, v))
            with open(local_file, "r") as f:
                log.info("LKP config file:\n{}".format(f.read()))
            upload_file(self.lkp_hostname, local_file, remote_dir)

        with open(local_file, "w") as f:
            f.write("[global]\n")
            for k, v in dut_cfg.items():
                f.write("{} {}\n".format(k, v))
        with open(local_file, "r") as f:
            log.info("DUT config file:\n{}".format(f.read()))
        return local_file, remote_file

    def remove_cfg_files(self, dut_local_file, lkp_remote_file):
        Command(cmd="sudo rm {}".format(dut_local_file)).run()
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            Command(cmd="sudo rm {}".format(lkp_remote_file), host=self.lkp_hostname).run()

    def save_output_to_file(self, output, file_name):
        with open(file_name, "w") as f:
            f.write("\n".join(output))

    def read_output_file(self, file_name):
        with open(file_name, "r") as f:
            return f.read().split("\n")

    def run_ptp4l_transport_sync(self, exec_time, transport, delay_mechanism, onestep, speed, is_iperf_run=False):
        dut_out = "dut_{}_{}_{}_{}_{}.txt".format(exec_time, transport, delay_mechanism, onestep, speed)
        lkp_out = "lkp_{}_{}_{}_{}_{}.txt".format(exec_time, transport, delay_mechanism, onestep, speed)

        if self.is_lkp_motu() or self.is_lkp_xmos():
            if delay_mechanism != "P2P":
                pytest.skip()
            if transport != "L2":
                pytest.skip()

        self.dut_ifconfig.set_link_speed(speed)
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        assert self.dut_ifconfig.wait_link_up() == speed

        if is_iperf_run and not (self.is_lkp_motu() or self.is_lkp_xmos()):
            self.iperf_config['speed'] = speed
            self.iperf_config['time'] = exec_time
            iperf = Iperf(**self.iperf_config)
            iperf.run_async()

        dut_ptp4l_config = copy.deepcopy(self.PTP4L_DEFAULT_CONFIG)
        lkp_ptp4l_config = copy.deepcopy(self.PTP4L_DEFAULT_CONFIG)
        dut_ptp4l_config["slaveOnly"] = 0
        lkp_ptp4l_config["slaveOnly"] = 1
        dut_ptp4l_config["logging_level"] = 7
        lkp_ptp4l_config["logging_level"] = 7
        dut_ptp4l_config["network_transport"] = transport
        lkp_ptp4l_config["network_transport"] = transport
        dut_ptp4l_config["delay_mechanism"] = delay_mechanism
        lkp_ptp4l_config["delay_mechanism"] = delay_mechanism
        dut_ptp4l_config["twoStepFlag"] = 0 if onestep is True else 1
        lkp_ptp4l_config["twoStepFlag"] = 0 if onestep is True else 1
        if self.is_lkp_motu() or self.is_lkp_xmos():
            dut_ptp4l_config["logSyncInterval"] = -3

        offsets_link = self.OFFSETS.get(speed, {})
        offsets_transport = offsets_link.get(transport, {})
        offsets_mechanism = offsets_transport.get(delay_mechanism, (0, 0))
        dut_ptp4l_config["egressLatency"], dut_ptp4l_config["ingressLatency"] = offsets_mechanism
        lkp_ptp4l_config["egressLatency"], lkp_ptp4l_config["ingressLatency"] = offsets_mechanism

        dut_config_path, lkp_config_path = self.create_cfg_files(dut_ptp4l_config, lkp_ptp4l_config)

        cmd_dut = Command(cmd=self.get_ptp4l_cmd(self.dut_ifconfig.get_conn_name(), dut_config_path))
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            cmd_lkp = Command(cmd=self.get_ptp4l_cmd(self.lkp_ifconfig.get_conn_name(), lkp_config_path),
                              host=self.lkp_hostname)

        cmd_dut.run_async()
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            cmd_lkp.run_async()
        log.info("Waiting {} seconds while ptp4l is running".format(exec_time))
        res_dut = cmd_dut.join(exec_time)
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            res_lkp = cmd_lkp.join(1)

        if is_iperf_run and not (self.is_lkp_motu() or self.is_lkp_xmos()):
            iperf.join()

        self.save_output_to_file(res_dut["output"], dut_out)
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            self.save_output_to_file(res_lkp["output"], lkp_out)
        self.remove_cfg_files(dut_config_path, lkp_config_path)
        return dut_out, lkp_out

    def get_output(self, exec_time, transport, delay_mechanism, onestep, speed, is_iperf_run=False):
        assert transport in [self.PTP4L_L2, self.PTP4L_UDPv4, self.PTP4L_UDPv6]

        if speed not in self.supported_speeds:
            pytest.skip()

        dut_out, lkp_out = self.run_ptp4l_transport_sync(
            exec_time, transport, delay_mechanism, onestep, speed, is_iperf_run)
        shutil.copy(dut_out, self.test_log_dir)
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            shutil.copy(lkp_out, self.test_log_dir)
            log.info("lkp ptp4l output: {}".format(lkp_out))
        log.info("dut ptp4l output: {}".format(dut_out))
        res_dut = self.read_output_file(dut_out)
        if self.is_lkp_motu() or self.is_lkp_xmos():
            res_lkp = [""]
        else:
            res_lkp = self.read_output_file(lkp_out)

        is_master_dut = self.get_bmc_result(res_dut, res_lkp)
        if is_master_dut is True:
            return res_dut, res_lkp
        else:
            return res_lkp, res_dut

    def run_ptp4l_transport_test(self, exec_time, transport, delay_mechanism, onestep, speed, is_iperf_run=False):
        # TODO: temporary do not run with motu and xmos
        # if self.is_lkp_xmos():
        #     pytest.skip()

        master_output, slave_output = self.get_output(
            exec_time, transport, delay_mechanism, onestep, speed, is_iperf_run
        )
        if (self.is_lkp_motu() or self.is_lkp_xmos()):
            self.verify_master_output(master_output, speed)
        else:
            self.verify_slave_output(slave_output, speed)

    def run_open_avnu_gptp_sync_test(self, exec_time, speed, dut_role):
        re_path_delay = re.compile(r".*Link delay: ([\-0-9]+).*", re.DOTALL)

        if speed not in self.supported_speeds:
            pytest.skip()



        self.dut_ifconfig.set_link_speed(speed)
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        else:
            if dut_role == self.SLAVE_ROLE:
                pytest.skip("Only master mode is supported with MOTU")
        assert self.dut_ifconfig.wait_link_up() == speed

        offsets_link = self.OFFSETS.get(speed, {})
        offsets_transport = offsets_link.get("L2", {})
        offsets_mechanism = offsets_transport.get("P2P", (0, 0))
        tx_offset, rx_offset = offsets_mechanism

        cmd_dut = Command(cmd=self.get_gptp_cmd(
            self.dut_ifconfig.get_conn_name(), dut_role
        ) + " -D 0,0,{},{} 2>&1".format(tx_offset, rx_offset))

        lkp_role = self.SLAVE_ROLE if dut_role == self.MASTER_ROLE else self.MASTER_ROLE
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            cmd_lkp = Command(cmd=self.get_gptp_cmd(
                self.lkp_ifconfig.get_conn_name(), lkp_role
            ) + " -D 0,0,{},{} 2>&1".format(tx_offset, rx_offset), host=self.lkp_hostname)

        cmd_dut.run_async()
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            cmd_lkp.run_async()
        log.info("Waiting {} seconds while gptp is running".format(exec_time))
        res_dut = cmd_dut.join(exec_time)
        if not (self.is_lkp_motu() or self.is_lkp_xmos()):
            res_lkp = cmd_lkp.join(1)

        def check_master_output(lines):
            master_check = False
            path_delays = []
            as_capable_path_delays = []
            fault = False
            as_capable = False

            for line in lines:
                if "Switching to Master" in line:
                    master_check = True
                    continue
                if "AsCapable: Enabled" in line:
                    as_capable = True
                    continue
                if as_capable is True:
                    m = re_path_delay.match(line)
                    if m is not None:
                        path_delays.append(int(m.group(1)))
                        if as_capable is True:
                            as_capable_path_delays.append(int(m.group(1)))
                    fault |= "ERROR" in line

            if as_capable is True:
                path_delays = as_capable_path_delays

            path_delays = path_delays[self.NUMBER_OF_SKIPPED_PDELAYS:]
            log.info("gPTP master output is {}".format("OK" if not fault else "NOK"))
            log.info("gPTP master path delays: {}".format(path_delays))
            log.info("gPTP master path delays: min = {}, max = {}, variation = {}".format(
                min(path_delays), max(path_delays), max(path_delays) - min(path_delays)))

            assert master_check, "PTP was not synchronized"
            assert as_capable, "PTP was not synchronized"

            return fault, path_delays

        def check_slave_output(lines):
            slave_check = False
            path_delays = []
            fault = False

            for line in lines:
                if "Switching to Slave" in line:
                    slave_check = True
                    continue
                if slave_check is True:
                    m = re_path_delay.match(line)
                    if m is not None:
                        path_delays.append(int(m.group(1)))
                    fault |= "ERROR" in line

            assert slave_check, "PTP was not synchronized"

            path_delays = path_delays[self.NUMBER_OF_SKIPPED_PDELAYS:]
            log.info("gPTP slave output is {}".format("OK" if not fault else "NOK"))
            log.info("gPTP slave path delays: {}".format(path_delays))
            if len(path_delays) > 0:
                log.info("gPTP slave path delays: min = {}, max = {}, variation = {}".format(
                    min(path_delays), max(path_delays), max(path_delays) - min(path_delays)))
            else:
                log.warning("Path delays are not reported by slave!")
            return fault, path_delays

        fault_master = False
        fault_slave = False
        path_delays_slave = None
        path_delays_master = None

        if dut_role == self.MASTER_ROLE:
            fault_master, path_delays_master = check_master_output(res_dut["output"])
        else:
            if self.is_lkp_motu() or self.is_lkp_xmos():
                fault_slave, path_delays_slave = check_master_output(res_dut["output"])
            else:
                fault_master, path_delays_master = check_master_output(res_lkp["output"])
                path_delays_master = path_delays_master[self.NUMBER_OF_SKIPPED_PDELAYS:]

        assert not fault_master
        assert not fault_slave

        if path_delays_slave is not None and len(path_delays_slave) > 10:
            assert all([path_delay > 0 for path_delay in path_delays_slave]), "Negative path delay observed"
            assert max(path_delays_slave) - min(path_delays_slave) <= self.PDELAY_VARIATION_LIMIT[speed],\
                "Too big path delay variation"
            assert max(path_delays_slave) <= self.PDELAY_ABSOLUTE_LIMIT, "Some times slave pDelay value " \
                "is greater than {}".format(self.PDELAY_ABSOLUTE_LIMIT)

        if path_delays_master is not None:
            assert all([path_delay > 0 for path_delay in path_delays_master]), "Negative path delay observed"
            assert max(path_delays_master) - min(path_delays_master) <= self.PDELAY_VARIATION_LIMIT[speed],\
                "Too big path delay variation"
            assert max(path_delays_master) <= self.PDELAY_ABSOLUTE_LIMIT, "Some times master pDelay value " \
                "is greater than {}".format(self.PDELAY_ABSOLUTE_LIMIT)

    # PTP4L TRANSPORT TESTS E2E, L2

    # def run_ptp4l_transport_test_iperf(self, exec_time, transport, delay_mechanism, onestep, speed):
    #     self.iperf_config['speed'] = speed
    #     self.iperf_config['time'] = exec_time,
    #     iperf = Iperf(**self.iperf_config)
    #     time.sleep(15)
    #     iperf.run_async()
    #     self.run_ptp4l_transport_test(exec_time, transport, delay_mechanism, onestep, speed, True)
    #     iperf.join()

    def test_ptp4l_network_transport_over_ethernet_e2e_100m_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_L2, self.PTP4L_E2E, False, LINK_SPEED_100M, True)

    def test_ptp4l_network_transport_over_ethernet_e2e_1g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_L2, self.PTP4L_E2E, False, LINK_SPEED_1G, True)

    def test_ptp4l_network_transport_over_ethernet_e2e_2_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_L2, self.PTP4L_E2E, False, LINK_SPEED_2_5G, True)

    def test_ptp4l_network_transport_over_ethernet_e2e_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_L2, self.PTP4L_E2E, False, LINK_SPEED_5G, True)

    def test_ptp4l_network_transport_over_ethernet_e2e_10g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_L2, self.PTP4L_E2E, False, LINK_SPEED_10G, True)

    # PTP4L TRANSPORT TESTS E2E, IPv4

    def test_ptp4l_network_transport_over_udp_ipv4_e2e_100m_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv4, self.PTP4L_E2E, False, LINK_SPEED_100M, True)

    def test_ptp4l_network_transport_over_udp_ipv4_e2e_1g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv4, self.PTP4L_E2E, False, LINK_SPEED_1G, True)

    def test_ptp4l_network_transport_over_udp_ipv4_e2e_2_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv4, self.PTP4L_E2E, False, LINK_SPEED_2_5G, True)

    def test_ptp4l_network_transport_over_udp_ipv4_e2e_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv4, self.PTP4L_E2E, False, LINK_SPEED_5G, True)

    def test_ptp4l_network_transport_over_udp_ipv4_e2e_10g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv4, self.PTP4L_E2E, False, LINK_SPEED_10G, True)

    # PTP4L TRANSPORT TESTS E2E, IPv6

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv6_e2e_100m_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv6, self.PTP4L_E2E, False, LINK_SPEED_100M, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv6_e2e_1g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv6, self.PTP4L_E2E, False, LINK_SPEED_1G, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv6_e2e_2_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv6, self.PTP4L_E2E, False, LINK_SPEED_2_5G, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv6_e2e_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv6, self.PTP4L_E2E, False, LINK_SPEED_5G, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv6_e2e_10g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv6, self.PTP4L_E2E, False, LINK_SPEED_10G, True)

    # PTP4L TRANSPORT TESTS P2P, L2

    def test_ptp4l_network_transport_over_ethernet_p2p_100m_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_L2, self.PTP4L_P2P, False, LINK_SPEED_100M, True)

    def test_ptp4l_network_transport_over_ethernet_p2p_1g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_L2, self.PTP4L_P2P, False, LINK_SPEED_1G, True)

    def test_ptp4l_network_transport_over_ethernet_p2p_2_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_L2, self.PTP4L_P2P, False, LINK_SPEED_2_5G, True)

    def test_ptp4l_network_transport_over_ethernet_p2p_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_L2, self.PTP4L_P2P, False, LINK_SPEED_5G, True)

    def test_ptp4l_network_transport_over_ethernet_p2p_10g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_L2, self.PTP4L_P2P, False, LINK_SPEED_10G, True)

    # PTP4L TRANSPORT TESTS P2P, IPv4

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv4_p2p_100m_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv4, self.PTP4L_P2P, False, LINK_SPEED_100M, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv4_p2p_1g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv4, self.PTP4L_P2P, False, LINK_SPEED_1G, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv4_p2p_2_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv4, self.PTP4L_P2P, False, LINK_SPEED_2_5G, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv4_p2p_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv4, self.PTP4L_P2P, False, LINK_SPEED_5G, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv4_p2p_10g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv4, self.PTP4L_P2P, False, LINK_SPEED_10G, True)

    # PTP4L TRANSPORT TESTS P2P, IPv6

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv6_p2p_100m_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv6, self.PTP4L_P2P, False, LINK_SPEED_100M, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv6_p2p_1g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv6, self.PTP4L_P2P, False, LINK_SPEED_1G, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv6_p2p_2_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv6, self.PTP4L_P2P, False, LINK_SPEED_2_5G, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv6_p2p_5g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv6, self.PTP4L_P2P, False, LINK_SPEED_5G, True)

    @pytest.mark.xfail
    def test_ptp4l_network_transport_over_udp_ipv6_p2p_10g_iperf(self):
        self.run_ptp4l_transport_test(self.PTP4L_EXEC_TIME, self.PTP4L_UDPv6, self.PTP4L_P2P, False, LINK_SPEED_10G, True)

    # def test_stability(self):
    #     self.run_ptp4l_transport_test(self.PTP4L_STABILITY_EXEC_TIME, self.PTP4L_L2,
    #                             self.PTP4L_E2E, False)

    # Fails on Intel X540/X550 because HWTSTAMP_TX_ONESTEP_SYNC is not supported
    # def test_ptp4l_network_transport_over_ethernet_e2e_onestep(self):
    #     self.run_ptp4l_transport_test(self.PTP4L_L2, self.PTP4L_E2E, True)

    # GPTP ALL SPEEDS

    def test_open_avnu_gptp_sync_100m_dut_master(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_100M, self.MASTER_ROLE)

    def test_open_avnu_gptp_sync_100m_dut_slave(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_100M, self.SLAVE_ROLE)

    def test_open_avnu_gptp_sync_1g_dut_master(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_1G, self.MASTER_ROLE)

    def test_open_avnu_gptp_sync_1g_dut_slave(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_1G, self.SLAVE_ROLE)

    @pytest.mark.xfail
    def test_open_avnu_gptp_sync_2_5g_dut_master(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_2_5G, self.MASTER_ROLE)

    @pytest.mark.xfail
    def test_open_avnu_gptp_sync_2_5g_dut_slave(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_2_5G, self.SLAVE_ROLE)

    def test_open_avnu_gptp_sync_5g_dut_master(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_5G, self.MASTER_ROLE)

    def test_open_avnu_gptp_sync_5g_dut_slave(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_5G, self.SLAVE_ROLE)

    def test_open_avnu_gptp_sync_10g_dut_master(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_10G, self.MASTER_ROLE)

    def test_open_avnu_gptp_sync_10g_dut_slave(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_10G, self.SLAVE_ROLE)

    # GPTP ALL SPEEDS STABILITY

    @pytest.mark.skipif("PTP_LINUX_STABILITY" not in os.environ, reason="It is stability test")
    def test_open_avnu_gptp_sync_100m_dut_master_stability(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME_STABILITY, LINK_SPEED_100M, self.MASTER_ROLE)

    @pytest.mark.skipif("PTP_LINUX_STABILITY" not in os.environ, reason="It is stability test")
    def test_open_avnu_gptp_sync_1g_dut_master_stability(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME_STABILITY, LINK_SPEED_1G, self.MASTER_ROLE)

    @pytest.mark.xfail
    @pytest.mark.skipif("PTP_LINUX_STABILITY" not in os.environ, reason="It is stability test")
    def test_open_avnu_gptp_sync_2_5g_dut_master_stability(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME_STABILITY, LINK_SPEED_2_5G, self.MASTER_ROLE)

    @pytest.mark.skipif("PTP_LINUX_STABILITY" not in os.environ, reason="It is stability test")
    def test_open_avnu_gptp_sync_5g_dut_master_stability(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME_STABILITY, LINK_SPEED_5G, self.MASTER_ROLE)

    @pytest.mark.skipif("PTP_LINUX_STABILITY" not in os.environ, reason="It is stability test")
    def test_open_avnu_gptp_sync_10g_dut_master_stability(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME_STABILITY, LINK_SPEED_10G, self.MASTER_ROLE)

    # GPTP ALL SPEEDS LONGEVITY

    @pytest.mark.skipif("PTP_LINUX_LONGEVITY" not in os.environ, reason="It is longevity test")
    def test_open_avnu_gptp_sync_100m_dut_master_longevity(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_100M, self.MASTER_ROLE)

    @pytest.mark.skipif("PTP_LINUX_LONGEVITY" not in os.environ, reason="It is longevity test")
    def test_open_avnu_gptp_sync_1g_dut_master_longevity(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_1G, self.MASTER_ROLE)

    @pytest.mark.xfail
    @pytest.mark.skipif("PTP_LINUX_LONGEVITY" not in os.environ, reason="It is longevity test")
    def test_open_avnu_gptp_sync_2_5g_dut_master_longevity(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_2_5G, self.MASTER_ROLE)

    @pytest.mark.skipif("PTP_LINUX_LONGEVITY" not in os.environ, reason="It is longevity test")
    def test_open_avnu_gptp_sync_5g_dut_master_longevity(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_5G, self.MASTER_ROLE)

    @pytest.mark.skipif("PTP_LINUX_LONGEVITY" not in os.environ, reason="It is longevity test")
    def test_open_avnu_gptp_sync_10g_dut_master_longevity(self):
        self.run_open_avnu_gptp_sync_test(self.GPTP_EXEC_TIME, LINK_SPEED_10G, self.MASTER_ROLE)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
