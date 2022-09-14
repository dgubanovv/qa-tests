import json
import os
import socket
import time

from iperf_result import IperfResult
from tools.constants import SPEED_TO_MBITS, LINK_SPEED_AUTO

if __package__ is None:
    import sys
    from os import path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from tools.command import Command, Priority
from tools.utils import get_atf_logger

log = get_atf_logger()


def parse_iperf_output(raw):
    try:
        json_raw = [line.replace("\\n", "").replace("nan", "0").replace('\t', '') for line in raw]
        json_raw = ''.join(json_raw)
        json_raw = json_raw[json_raw.find('{'):]
        json_data = json.loads(json_raw)
        bandwidth = []  # Mbps
        lost = []  # percent

        for interval in json_data['intervals']:
            # calculate bandwidths
            bits = 8 * float(interval['sum']['bytes'])
            seconds = float(interval['sum']['seconds'])
            bits_per_second = (bits / seconds) if seconds > 0 else 0

            bandwidth.append(bits_per_second / (1000.0 * 1000.0))

            if 'lost_percent' in interval['sum'].keys():
                lost.append(float(interval['sum']['lost_percent']))

        if len(bandwidth) == 0:
            return {}

        return {
            'version': json_data['start']['version'],
            'system': json_data['start']['system_info'],
            'client': json_data['start']['accepted_connection']['host'],
            'bandwidth': bandwidth,
            'lost': lost
        }
    except Exception:
        pass

    return {}


class IperfServer:

    SERVER_STARTUP_DELAY = 1

    def __init__(self, **kwargs):

        self.supported_speeds = os.environ.get("SUPPORTED_SPEEDS", "100M,1G").split(',')

        self.host = kwargs.get('host', 'localhost')
        self.port = kwargs.get('port', 5201)
        self.once = kwargs.get('once', True)
        self.speed = kwargs.get('speed', 0)
        self.ip_server = kwargs.get('ip_server', 'localhost')
        self.priority = kwargs.get('priority', Priority.NORMAL)

        self.is_udp = kwargs.get('is_udp', False)
        self.num_process = kwargs.get("num_process", 1)
        self.time = kwargs.get('time', 17)
        self.timeout = kwargs.get('timeout', self.time + 30)

        self.str_command = 'iperf3 --format m --json --server {}'.format('-1' if self.once else '')
        self.str_command += ' -B {}'.format(self.ip_server)

    def run_async(self):
        self.commands = []
        for np in range(self.num_process):
            cmd = self.str_command + ' --port {}'.format(self.port + np)
            self.commands.append(Command(cmd=cmd, host=self.host, silent=True, priority=self.priority))

        for c in self.commands:
            c.run_async()

        time.sleep(self.SERVER_STARTUP_DELAY)

    def join(self, timeout=None):
        timeout = self.timeout if timeout is None else timeout

        iperf_result = IperfResult()

        for command in self.commands:
            result = command.join(timeout)
            if result is None:
                return None
            else:
                for line in result["output"]:
                    if "unable" in line:
                        return None

                data = parse_iperf_output(result["output"])
                if 'bandwidth' in data.keys():
                    try:
                        iperf_result.version = data['version']
                        iperf_result.client = '{}'.format(socket.gethostname() if self.host is None else self.host)
                        iperf_result.system = data['system']
                        speed_in_mb = SPEED_TO_MBITS[self.supported_speeds[-1]]

                        if not self.speed in SPEED_TO_MBITS.keys():
                            raise Exception('not {} in {}'.format(self.speed, SPEED_TO_MBITS.keys()))

                        speed_in_mb = speed_in_mb if self.speed == LINK_SPEED_AUTO else SPEED_TO_MBITS[self.speed]
                        iperf_result.speed = speed_in_mb
                        iperf_result.streams.append({'bandwidth': data['bandwidth'], 'lost': data['lost']})
                    except Exception as e:
                        log.exception('Exception: {}'.format(e))
                        log.debug('keys: {}'.format(data.keys()))
                        log.debug('data: {}'.format(data))
                        log.debug('result: {}'.format(iperf_result))
                        return None
                else:
                    return None

        # calculate sum of data
        iperf_result.bandwidth = []
        iperf_result.lost = []

        for s in iperf_result.streams:
            # bandwidth
            if len(iperf_result.bandwidth) == 0:
                iperf_result.bandwidth = s['bandwidth'][:]
            else:
                min_len = min(len(iperf_result.bandwidth), len(s['bandwidth']))
                for i in range(min_len):
                    iperf_result.bandwidth[i] += s['bandwidth'][i]

            # lost
            if len(iperf_result.lost) == 0:
                iperf_result.lost = s['lost'][:]
            else:
                for i in range(min(len(iperf_result.lost), len(s['lost']))):
                    iperf_result.lost[i] += s['lost'][i]

        for i in range(len(iperf_result.lost)):
            iperf_result.lost[i] /= float(len(iperf_result.streams))

        # crop
        if len(iperf_result.bandwidth) > 2:
            iperf_result.bandwidth = iperf_result.bandwidth[2:-1]
            iperf_result.lost = iperf_result.lost[2:-1]
            for s in iperf_result.streams:
                s['bandwidth'] = s['bandwidth'][2:-1]
                s['lost'] = s['lost'][2:-1]

        return iperf_result
