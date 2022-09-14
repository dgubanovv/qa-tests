import argparse
import re
import socket
from abc import abstractmethod, ABCMeta

from command import Command
from constants import ATF_TOOLS_DIR, DIRECTION_TX, DIRECTION_RX, DIRECTION_RXTX
from log import get_atf_logger
from utils import download_file

SCRIPT_STATUS_SUCCESS = "[TRACEPOINT-SUCCESS]"
SCRIPT_STATUS_FAILED = "[TRACEPOINT-FAILED]"

log = get_atf_logger()


class Tracepoint(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(TracepointLocal)
        else:
            return object.__new__(TracepointRemote)

    def __init__(self, **kwargs):
        self.direction = kwargs.get("direction", DIRECTION_RXTX)
        self.timeout = kwargs.get("timeout", 24 * 60 * 60)
        self.file = kwargs.get("file", None)
        self.name = kwargs.get("name", "atlantic")

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def run_async(self):
        pass

    @abstractmethod
    def join(self, timeout=None):
        pass

    def run_join(self, timeout=None):
        self.run_async()
        return self.join(timeout=timeout)

    def wait(self, timeout=None):
        self.run_join(timeout=timeout)

    @staticmethod
    def _get_dict(line):
        res = {}
        for n in line.replace(')', '').split(':')[-1].split():
            k, v = n.split('=')
            v = int(v, 16) if 'x' in v else int(v)
            res[k] = v

        return res

    def _get_descr(self, output):
        descriptors = []
        for name in output:
            if name == 'output':
                for line in output[name]:
                    if self.direction == DIRECTION_RXTX or self.direction == DIRECTION_RX:
                        if 'atlantic:aq_rx_descr' in line:
                            descr = {'direction': 'rx'}
                            descr.update(self._get_dict(line))
                            descriptors.append(descr)
                        elif 'atlantic:aq_produce_skb' in line:
                            descr = {'direction': 'rx_skb'}
                            descr.update(self._get_dict(line))
                            descriptors.append(descr)
                    if self.direction == DIRECTION_RXTX or self.direction == DIRECTION_TX:
                        if 'atlantic:aq_tx_descr' in line:
                            descr = {'direction': 'tx'}
                            descr.update(self._get_dict(line))
                            descriptors.append(descr)
                        elif 'atlantic:aq_tx_context_descr' in line:
                            descr = {'direction': 'tx_context'}
                            descr.update(self._get_dict(line))
                            descriptors.append(descr)
                return descriptors[:-1]

    def wrire_file(self, output):
        with open(self.file, 'w') as f:
            for name in output:
                if name == 'output':
                    for line in output[name]:
                        f.write("{}\n".format(line))


class TracepointLocal(Tracepoint):

    def __init__(self, **kwargs):
        super(TracepointLocal, self).__init__(**kwargs)
        self.descr = None

    def _get_tracepoint_command(self):
        cmd = "sudo timeout {} perf trace -a --no-syscalls --event '{}:aq_*'".format(self.timeout, self.name)
        return cmd

    def run(self):
        log.info("Starting tracepoint on localhost synchronously")
        cmd = self._get_tracepoint_command()
        res = Command(cmd=cmd).run()
        descr = self._get_descr(res)
        if self.file is not None:
            self.wrire_file(res)
        return descr

    def run_async(self):
        log.info("Starting tracepoint on localhost asynchronously")
        cmd = self._get_tracepoint_command()
        self.cmd = Command(cmd=cmd)
        self.cmd.run_async()
        log.info("Tracepoint has been started")

    def join(self, timeout=None):
        res = self.cmd.join(timeout=timeout)
        descr = self._get_descr(res)
        if self.file is not None:
            self.wrire_file(res)
        return descr


class TracepointRemote(Tracepoint):

    def __init__(self, **kwargs):
        super(TracepointRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]

    def _get_remote_tracepoint_command(self, remote_file=None):
        cmd = "cd {} && sudo python tracepoint.py -d {}".format(ATF_TOOLS_DIR, self.direction)
        cmd += " -t {}".format(self.timeout)
        cmd += " -n {}".format(self.name)
        if remote_file is not None:
            cmd += " -f {}".format(remote_file)
        return cmd

    def run(self):
        if self.file is not None:
            self.remote_file = "~/remote_tracepoint.txt"
            cmd = self._get_remote_tracepoint_command(remote_file=self.remote_file)
        else:
            cmd = self._get_remote_tracepoint_command()
        res = Command(cmd=cmd, host=self.host).run()
        descr = self._get_descr(res)
        if self.file is not None:
            download_file(self.host, self.remote_file, self.file)
            cmd = "rm {}".format(self.remote_file)
            Command(cmd=cmd, host=self.host).run_join(5)
        return descr

    def run_async(self):
        if self.file is not None:
            self.remote_file = "~/remote_tracepoint.txt"
            cmd = self._get_remote_tracepoint_command(remote_file=self.remote_file)
        else:
            cmd = self._get_remote_tracepoint_command()
        self.cmd = Command(cmd=cmd, host=self.host)
        self.cmd.run_async()
        log.info("Tracepoint has been started")

    def join(self, timeout=None):
        res = self.cmd.join(timeout=timeout)
        descr = self._get_descr(res)
        if self.file is not None:
            download_file(self.host, self.remote_file, self.file)
            cmd = "rm {}".format(self.remote_file)
            Command(cmd=cmd, host=self.host).run_join(5)
        return descr


class TracepointArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error("\n{}\n".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = TracepointArgumentParser()
    parser.add_argument("-d", "--direction", help="Direction", type=str, required=True, choices=[DIRECTION_TX,
                                                                                                 DIRECTION_RX,
                                                                                                 DIRECTION_RXTX])
    parser.add_argument("-t", "--timeout", help="Timeout in seconds", type=int, required=True)
    parser.add_argument("-n", "--name", help="Driver name", type=str, required=True)
    parser.add_argument("-f", "--file", help="File to write descr", type=str)
    args = parser.parse_args()

    try:
        if args.file is not None:
            if " " in args.file:
                raise Exception("Please specify file name without spaces")

        trace_point = Tracepoint(direction=args.direction, timeout=args.timeout, file=args.file, name=args.name)
        trace_point.run()
        if args.file is not None:
            log.info("Descriptors are saved to {} file".format(args.file))

    except Exception as e:
        log.exception(e)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
