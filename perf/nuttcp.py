import os
import re
import sys
import time
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.command import Command
from tools.constants import DIRECTION_RX, DIRECTION_TX, DIRECTION_RXTX
from tools.ops import OpSystem


class NuttcpServer(object):
    def __init__(self, **kwargs):
        self.host = kwargs.get('host', 'localhost')
        self.port = kwargs.get('port', 5000)  # -P

    def get_command(self):
        cmd = "nuttcp -S --nofork -1"
        if self.host not in [None, "localhost"] and OpSystem(host=self.host).is_windows():
            cmd = 'cmd /C"{}"'.format(cmd)
        return cmd

    def run_async(self):
        cmd = self.get_command()
        self.cmd = Command(cmd=cmd, host=self.host)
        self.cmd.run_async()

    def join(self, timeout=None):
        return self.cmd.join(timeout)


class NuttcpClient(object):
    def __init__(self, **kwargs):
        self.host = kwargs.get('host', 'localhost')
        self.port = kwargs.get('port', 5000)  # -P
        self.is_udp = kwargs.get('is_udp', False)  # -u
        self.time = kwargs.get('time', 17)  # -T
        self.buffer_len = kwargs.get('buffer_len', 0)  # -l
        self.num_threads = kwargs.get("num_threads", 1)  # -N
        self.ip_server = kwargs.get('ip_server', 'localhost')
        self.bandwidth = kwargs.get('bandwidth', 0)
        self.window = kwargs.get('window', 0)
        self.ipv = kwargs.get('ipv', 4)
        assert self.ipv == 4, "Not implemented"

    def get_command(self):
        cmd = "nuttcp -i1 -T{} -N{} -fparse ".format(self.time, self.num_threads)
        if self.bandwidth == 0:
            cmd += "-Ru "
        else:
            cmd += "-R{}m ".format(self.bandwidth)
        if self.is_udp:
            cmd += "-u "
        if self.buffer_len != 0:
            cmd += "-l{} ".format(self.buffer_len)
        if self.window != 0:
            cmd += "-w{} -ws{} ".format(self.window, self.window)
        cmd += self.ip_server

        if self.host not in [None, "localhost"] and OpSystem(host=self.host).is_windows():
            cmd = 'cmd /C"{}"'.format(cmd)
        return cmd

    def run_async(self):
        cmd = self.get_command()
        self.cmd = Command(cmd=cmd, host=self.host)
        self.cmd.run_async()

    def join(self, timeout=None):
        return self.cmd.join(timeout)


class NuttcpResult(object):
    def __init__(self, bands=None, losts=None):
        self.bandwidth = bands or []  # array of sum bandwidth
        self.lost = losts or []  # array of sum lost

    def __str__(self):
        msg = '\n'

        try:
            msg += 'bandwidth: {}\n'.format(self.bandwidth)
            msg += 'lost: {}\n'.format(self.lost)
        except Exception as e:
            msg = '{}'.format(e)

        return msg

class Nuttcp(object):
    def __init__(self, **kwargs):
        self.args = kwargs
        self.direction = kwargs.get('direction', DIRECTION_RX)
        ipv = kwargs.get('ipv', 4)

        self.lkp_ipv4_addr = kwargs.get("lkp4", None)
        self.lkp_ipv6_addr = kwargs.get("lkp6", None)
        self.dut_ipv4_addr = kwargs.get("dut4", None)
        self.dut_ipv6_addr = kwargs.get("dut6", None)

        self.lkp = kwargs.get("lkp", None)
        self.dut = kwargs.get("dut", None)

        self.ip_server_lkp = self.lkp_ipv4_addr if ipv == 4 else self.lkp_ipv6_addr
        self.ip_server_dut = self.dut_ipv4_addr if ipv == 4 else self.dut_ipv6_addr
        self.is_tx = self.direction in [DIRECTION_TX, DIRECTION_RXTX]
        self.is_rx = self.direction in [DIRECTION_RX, DIRECTION_RXTX]

    def run_async(self):
        if self.is_rx:
            self.nuttcp_server_dut = NuttcpServer(**self.args)
            self.nuttcp_client_lkp = NuttcpClient(host=self.lkp, ip_server=self.ip_server_dut, **self.args)

        if self.is_tx:
            self.nuttcp_server_lkp = NuttcpServer(host=self.lkp, **self.args)
            self.nuttcp_client_dut = NuttcpClient(ip_server=self.ip_server_lkp, **self.args)

        if self.is_rx:
            self.nuttcp_server_dut.run_async()

        if self.is_tx:
            self.nuttcp_server_lkp.run_async()

        time.sleep(3)

        if self.is_rx:
            self.nuttcp_client_lkp.run_async()

        if self.is_tx:
            self.nuttcp_client_dut.run_async()

    def parse_client_output(self, output):
        bands = []
        losts = []
        is_udp = self.args.get("is_udp", False)

        if not is_udp:
            re_line = re.compile(r".*rate_Mbps=([0-9\.]+).*", re.DOTALL)
        else:
            re_line = re.compile(r".*rate_Mbps=([0-9\.]+) .* data_loss=([0-9\.]+).*", re.DOTALL)

        for line in output:
            m = re_line.match(line)
            if m is not None:
                band = float(m.group(1))
                bands.append(band)
                if is_udp:
                    lost = float(m.group(2))
                    losts.append(lost)

        return bands, losts

    def join(self):
        is_ok = True
        timeout = self.args["time"] + 10
        self.results = []

        if self.is_rx:
            nuttcp_client_lkp_res = self.nuttcp_client_lkp.join(timeout)
            if nuttcp_client_lkp_res["returncode"] != 0:
                is_ok = False
            self.nuttcp_server_dut.join(0)
            if is_ok:
                rx_bands, rx_losts = self.parse_client_output(nuttcp_client_lkp_res["output"])
                self.results.append(NuttcpResult(rx_bands[2:], rx_losts[2:]))

        if self.is_tx:
            nuttcp_client_dut_res = self.nuttcp_client_dut.join(timeout)
            if nuttcp_client_dut_res["returncode"] != 0:
                is_ok = False
            self.nuttcp_server_lkp.join(0)
            if is_ok:
                tx_bands, tx_losts = self.parse_client_output(nuttcp_client_dut_res["output"])
                self.results.append(NuttcpResult(tx_bands[2:], tx_losts[2:]))

        return is_ok

# # EXAMPLE

# args = {
#     "dut": "at068-h81m",
#     "lkp": "at069-h81m",
#     "dut4": "192.168.0.68",
#     "lkp4": "192.168.0.69",
#     "time": 5,
#     "bandwidth": 666,
#     "ipv": 4,
#     "is_udp": True,
#     "direction": DIRECTION_RXTX,
#     "buffer_len": 1400,
#     "window": "4m"
# }

# n = Nuttcp(**args)
# n.run_async()
# n.join()
# print n.results
