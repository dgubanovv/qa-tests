import os
import socket
import time

from iperf_client import IperfClient
from iperf_server import IperfServer

if __package__ is None:
    import sys
    from os import path

    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from tools.constants import DIRECTION_RX, DIRECTION_TX, DIRECTION_RXTX
from tools.utils import get_atf_logger, str_to_bool

log = get_atf_logger()


class Iperf:
    IPERF_BROKEN = 0  # when perf finished with exitcode != 0
    IPERF_OK = 1

    def __init__(self, **kwargs):
        try:
            self.args = kwargs
            self.direction = kwargs.get('direction', DIRECTION_RX)
            ipv = kwargs.get('ipv', 4)

            self.LKP_IPV4_ADDR = kwargs.get("lkp4", None)
            self.LKP_IPV6_ADDR = kwargs.get("lkp6", None)
            self.DUT_IPV4_ADDR = kwargs.get("dut4", None)
            self.DUT_IPV6_ADDR = kwargs.get("dut6", None)

            self.lkp = kwargs.get("lkp", None)
            self.dut = kwargs.get("dut", None)

            self.ip_server_lkp = self.LKP_IPV4_ADDR if ipv == 4 else self.LKP_IPV6_ADDR
            self.ip_server_dut = self.DUT_IPV4_ADDR if ipv == 4 else self.DUT_IPV6_ADDR
            self.is_tx = True if self.direction == DIRECTION_TX or self.direction == DIRECTION_RXTX else False
            self.is_rx = True if self.direction == DIRECTION_RX or self.direction == DIRECTION_RXTX else False

        except Exception as e:
            log.info('   kwargs: {}'.format(kwargs))
            log.info('     self: {}'.format(self.__dict__))
            log.info('exception: {}'.format(e))

    def run_async(self):
        # RX
        if self.is_rx:
            self.iperf_server_dut = IperfServer(host=self.dut, ip_server=self.ip_server_dut, **self.args)
            self.iperf_client_lkp = IperfClient(host=self.lkp, ip_server=self.ip_server_dut, **self.args)

        # TX
        if self.is_tx:
            self.iperf_server_lkp = IperfServer(host=self.lkp, ip_server=self.ip_server_lkp, **self.args)
            self.iperf_client_dut = IperfClient(host=self.dut, ip_server=self.ip_server_lkp, **self.args)

        # RX
        if self.is_rx:
            self.iperf_server_dut.run_async()

        # TX
        if self.is_tx:
            self.iperf_server_lkp.run_async()

        time.sleep(3)

        if self.is_rx:
            self.iperf_client_lkp.run_async()

        if self.is_tx:
            self.iperf_client_dut.run_async()


    def join(self):
        self.performance_results = []  # array of IperfResult

        if self.is_rx:
            self.performance_results.append(self.iperf_server_dut.join())
            self.iperf_client_lkp.join()

        if self.is_tx:
            self.performance_results.append(self.iperf_server_lkp.join())
            self.iperf_client_dut.join()

        return Iperf.IPERF_BROKEN if None in self.performance_results else Iperf.IPERF_OK

    def run(self):
        self.run_async()
        return self.join()

    def get_performance(self):
        return self.performance_results

    def get_config(self):
        is_udp = self.args.get('is_udp', False)
        config = {
            'speed': self.args.get('speed', 0),
            'machine': socket.gethostname() if self.dut is None else self.dut,
            'process': self.args.get("num_process", 1),
            'threads': 1 if is_udp else self.args.get("num_threads", 1),
            'protocol': "UDP" if is_udp else "TCP",
            'pktlen': self.args.get('buffer_len', 8192),
            'perf': 'unknown' if (len(self.performance_results) == 0 or not all(self.performance_results)) else self.performance_results[0].version,
            'setup': "fast" if str_to_bool(os.environ.get("PERFORMANCE_SETUP", "False")) else "slow",
        }
        return config
