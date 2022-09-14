if __package__ is None:
    import sys
    from os import path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from tools.command import Command, Priority
from tools.ops import OpSystem

class IperfClient:

    def __init__(self, **kwargs):
        self.host = kwargs.get('host', 'localhost')
        self.port = kwargs.get('port', 5201)
        self.ipv = kwargs.get('ipv', 4)
        self.time = kwargs.get('time', 17)
        self.timeout = kwargs.get('timeout', self.time + 30)
        self.priority = kwargs.get('priority', Priority.NORMAL)

        self.is_udp = kwargs.get('is_udp', False)
        self.bandwidth = kwargs.get('bandwidth', 0)
        self.ip_server = kwargs.get('ip_server', 'localhost')

        self.buffer_len = kwargs.get('buffer_len', 0)
        self.buffer_num_len = kwargs.get('buffer_num_len', None)
        self.bytes = kwargs.get('bytes', 0)
        self.packets = kwargs.get('packets', 0)
        self.window = kwargs.get('window', 0)
        self.mss = kwargs.get('mss', 0)

        self.num_process = kwargs.get("num_process", 1)
        self.num_threads = kwargs.get("num_threads", 1)

        self.str_command = 'iperf3 --format m --interval 1'
        if self.is_udp:
            self.str_command += ' --udp'
            if self.bandwidth > 0:
                if OpSystem().is_mac() and 'Fiji' in sys.platform:
                    self.str_command += ' --bandwidth {}M'.format(int(self.bandwidth) / self.num_threads)
                else:
                    self.str_command += ' --bandwidth {}M'.format(self.bandwidth)
        else:
            if self.num_threads > 1:
                self.str_command += ' --parallel {}'.format(self.num_threads)

        self.str_command += ' --client {}'.format(self.ip_server)

        if self.bytes > 0:
            self.str_command += ' --bytes {}'.format(self.bytes)
        elif self.packets > 0:
            self.str_command += ' --blockcount {}'.format(self.packets)
        else:
            self.str_command += ' --time {}'.format(self.time)

        self.str_command += ' -{}'.format(self.ipv)

        if self.window > 0:
            self.str_command += ' --window {}'.format(self.window)

        if self.buffer_len > 0 and self.buffer_num_len is None:
            self.str_command += ' --length {}'.format(self.buffer_len)

        if self.mss > 0:
            self.str_command += ' --set-mss {}'.format(self.mss)

    def run_async(self):
        self.commands = []
        for np in range(self.num_process):
            cmd = self.str_command + ' --port {}'.format(self.port + np)
            if self.buffer_num_len is not None:
                cmd = cmd + ' --length {}'.format(self.buffer_num_len[np])
            self.commands.append(Command(cmd=cmd, host=self.host, silent=True, priority=self.priority))

        for c in self.commands:
            c.run_async()

    def join(self, timeout=None):
        timeout = self.timeout if timeout is None else timeout

        for command in self.commands:
            command.join(timeout)
