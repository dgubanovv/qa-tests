import json
import os
import socket
import time

from abc import ABCMeta, abstractmethod

from perf.iperf_result import IperfResult
from tools.command import Command
from tools.constants import ATF_TOOLS_DIR, DIRECTION_RX, DIRECTION_TX, DIRECTION_RXTX
from tools.ops import OpSystem
from tools.utils import get_atf_logger

log = get_atf_logger()


class FTPPerfBase(object):
    __metaclass__ = ABCMeta

    def __init__(self, **kwargs):
        self.port = kwargs.get("port", 10260)
        self.host = kwargs.get("host", "localhost")
        self.once = kwargs.get("once", True)

        self.server_ip = kwargs.get("server_ip", "localhost")
        self.timeout = kwargs.get("timeout", 10)

        self.ops = OpSystem(host=self.host)
        self.command = None

    def _parse_output(self, json_raw):
        try:
            jstr = "\n".join(json_raw)
            json_data = json.loads(jstr)
        except Exception:
            log.error("Failed to parse output:")
            log.error("JSON RAW:")
            log.debug('\n' + '=' * 120 + jstr + '=' * 120)

            json_data = {"start": {"version": "unknown", "timestamp": {"time": "", "timesecs": 0.0}},
                         "intervals": [], "end": {"sum_sent": {"seconds": 0.0, "bytes": 0},
                                                  "sum_received": {"seconds": 0.0, "bytes": 0}}}
        try:
            result_data = {"version": json_data["start"]["version"]}
            result_data["start"] = json_data["start"]

            bandwidths = []

            for interval in json_data["intervals"]:
                bits_per_second = 8 * interval["sum"]["bytes"] / interval["sum"]["seconds"]
                # bandwidths.append(bits_per_second / (1024.0 * 1024.0))
                bandwidths.append(bits_per_second / (1000.0 * 1000.0))

            if len(bandwidths) > 4:
                bandwidths = bandwidths[2:-2]

            bits_per_sec_avg = 8 * json_data["end"]["sum_received"]["bytes"] / json_data["end"]["sum_received"]["seconds"]
            bandwidth_avg = bits_per_sec_avg / (1000.0 * 1000.0)

            result_data["bandwidths"] = bandwidths
            result_data["bandwidth_avg"] = bandwidth_avg
        except Exception as e:
            log.exception('EXCEPTION: {}'.format(e))
            log.debug('json_data: {}'.format(json_data))
            result_data = {"result": "FAIL"}

        return result_data

    @abstractmethod
    def run_async(self):
        pass

    @abstractmethod
    def join(self, timeout=None):
        pass


class FTPPerfBaseClient(FTPPerfBase):
    def __init__(self, **kwargs):
        super(FTPPerfBaseClient, self).__init__(**kwargs)

        # prepare command for run
        if self.host in [None, "localhost", socket.gethostname()]:
            self.str_command = "python " + os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "../perf/ftp_perf.py") + " --json"
        else:
            self.str_command = "cd {} && python ../perf/ftp_perf.py --json".format(ATF_TOOLS_DIR)
        self.str_command += " -t {}".format(self.timeout)
        self.str_command += " -c {}".format(self.server_ip)

    def run_async(self):
        cmd = self.str_command + " -p {}".format(self.port)
        cmd = cmd.replace("\\", "/")
        self.command = Command(cmd=cmd, host=self.host, silent=True)
        self.command.run_async()

    def join(self, timeout=None):
        timeout = self.timeout if timeout is None else timeout

        res = self.command.join(timeout)
        data = self._parse_output(res["output"])

        ftp_result = IperfResult()

        try:
            ftp_result.version = data['version']
            ftp_result.client = '{}'.format(socket.gethostname() if self.host is None else self.host)
            ftp_result.system = ''
            ftp_result.speed = 0 # SPEED_TO_MBITS[self.supported_speeds[-1]]  # speed_in_mb
            ftp_result.bandwidth = data['bandwidths']
        except Exception as e:
            log.exception('Exception: {}'.format(e))
            log.debug('keys: {}'.format(data.keys()))
            log.debug('data: {}'.format(data))
            log.debug('result: {}'.format(ftp_result))
            return None

        return ftp_result


class FTPPerfBaseServer(FTPPerfBase):
    def __init__(self, **kwargs):
        super(FTPPerfBaseServer, self).__init__(**kwargs)
        self.SERVER_STARTUP_DELAY = 3

        # prepare command for run
        if self.host in [None, "localhost", socket.gethostname()]:
            self.str_command = "python " + os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "../perf/ftp_perf.py") + " -s"
        else:
            self.str_command = "cd {} && python ../perf/ftp_perf.py -s".format(ATF_TOOLS_DIR)
        self.str_command += " {}".format("-1" if self.once else "")

    def run_async(self):
        cmd = self.str_command + " -p {}".format(self.port)
        cmd = cmd.replace("\\", "/")
        self.command = Command(cmd=cmd, host=self.host)
        self.command.run_async()

        time.sleep(self.SERVER_STARTUP_DELAY)

    def join(self, timeout=None):
        timeout = self.timeout if timeout is None else timeout
        self.command.join(timeout)


class FTP:
    FTP_BROKEN = 0  # when perf finished with exitcode != 0
    FTP_OK = 1

    def __init__(self, **kwargs):
        try:
            self.args = kwargs
            self.direction = kwargs.get('direction', DIRECTION_TX)
            self.ipv = kwargs.get('ipv', 4)
            self.tolerance = kwargs.get('tolerance', 75)
            self.timeout = kwargs.get('timeout', 20)

            self.lkp = kwargs.get("lkp", None)
            self.dut = kwargs.get("dut", None)

            self.LKP_IPV4_ADDR = kwargs.get("lkp4", None)
            self.LKP_IPV6_ADDR = kwargs.get("lkp6", None)
            self.DUT_IPV4_ADDR = kwargs.get("dut4", None)
            self.DUT_IPV6_ADDR = kwargs.get("dut6", None)

            self.is_tx = True if self.direction == DIRECTION_TX or self.direction == DIRECTION_RXTX else False
            self.is_rx = True if self.direction == DIRECTION_RX or self.direction == DIRECTION_RXTX else False

            self.ip_server_lkp = self.LKP_IPV4_ADDR if self.ipv == 4 else self.LKP_IPV6_ADDR
            self.ip_server_dut = self.DUT_IPV4_ADDR if self.ipv == 4 else self.DUT_IPV6_ADDR

            self.results = []
            self.cresults = []
        except Exception as e:
            log.info('   kwargs: {}'.format(kwargs))
            log.info('     self: {}'.format(self.__dict__))
            log.info('exception: {}'.format(e))

    def run_async(self):
        # create
        if self.is_rx:
            self.ftp_server_dut = FTPPerfBaseServer(host=self.dut, **self.args)
            self.ftp_client_lkp = FTPPerfBaseClient(host=self.lkp, server_ip=self.ip_server_dut, **self.args)

        if self.is_tx:
            self.ftp_server_lkp = FTPPerfBaseServer(host=self.lkp, **self.args)
            self.ftp_client_dut = FTPPerfBaseClient(host=self.dut, server_ip=self.ip_server_lkp, **self.args)

        # run servers
        if self.is_rx:
            self.ftp_server_dut.run_async()

        # TX
        if self.is_tx:
            self.ftp_server_lkp.run_async()

        time.sleep(1)

        # run clients
        if self.is_rx:
            self.ftp_client_lkp.run_async()

        if self.is_tx:
            self.ftp_client_dut.run_async()

    def join(self, timeout=None):
        self.performance_results = []

        if timeout is None:
            timeout = self.timeout

        if self.is_rx:
            self.ftp_server_dut.join(timeout=timeout)
            self.performance_results.append(self.ftp_client_lkp.join(timeout=timeout))

        if self.is_tx:
            self.ftp_server_lkp.join(timeout=timeout)
            self.performance_results.append(self.ftp_client_dut.join(timeout=timeout))

        return FTP.FTP_BROKEN if None in self.performance_results else FTP.FTP_OK

    def run(self):
        self.run_async()
        return self.join(timeout=self.timeout + 5)

    def get_performance(self):
        return self.performance_results
