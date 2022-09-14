import argparse
import socket
import time

from abc import abstractmethod, ABCMeta

from command import Command
from constants import ATF_TOOLS_DIR
from utils import download_file, remove_file, get_atf_logger

SCRIPT_STATUS_SUCCESS = "[SNIFFER-SUCCESS]"
SCRIPT_STATUS_FAILED = "[SNIFFER-FAILED]"

log = get_atf_logger()


class Sniffer(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(SnifferLocal)
        else:
            return object.__new__(SnifferRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]
        self.count = kwargs.get("count", 0)
        self.timeout = kwargs.get("timeout", None)
        self.filter = kwargs.get("filter", None)
        self.lfilter = kwargs.get("lfilter", None)

    def sniff_from_file(self, filename):
        from scapy.all import rdpcap
        return rdpcap(filename)

    @abstractmethod
    def run_async(self, callback=None, iface=None):
        pass

    @abstractmethod
    def join(self, timeout=None):
        pass

    def run_join(self, callback=None, iface=None, timeout=None):
        self.run_async(callback=callback, iface=iface)
        return self.join(timeout=timeout)

    def run(self, callback=None, iface=None):
        return self.run_join(callback=callback, iface=iface)


class SnifferLocal(Sniffer):
    def __init__(self, **kwargs):
        super(SnifferLocal, self).__init__(**kwargs)

    def run_async(self, callback=None, iface=None):
        from scapy.all import AsyncSniffer
        from scapy_tools import get_scapy_iface

        if iface is None:
            iface = get_scapy_iface(self.port)

        log.info("Starting sniffer on iface {} with port {}".format(iface, self.port))

        self.sniffer = AsyncSniffer(iface=iface, count=self.count, prn=callback, timeout=self.timeout,
                                    filter=self.filter, lfilter=self.lfilter)
        self.sniffer.start()

        # Thread actually takes some time to start (can't poll running right away)
        while not self.sniffer.running:
            time.sleep(0.000001)

    def join(self, timeout=None):
        self.sniffer.join(timeout=timeout)
        if self.sniffer.running:
            self.sniffer.stop()
        return self.sniffer.results


class SnifferRemote(Sniffer):
    def __init__(self, **kwargs):
        super(SnifferRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]

    def _get_remote_sniffer_command(self, iface, remote_file):
        cmd = "cd {} && sudo python sniffer.py -p {} -f {}".format(ATF_TOOLS_DIR, self.port, remote_file)
        if self.count is not None or self.count != 0:
            cmd += " -c {}".format(self.count)
        if self.timeout is not None:
            cmd += " -t {}".format(self.timeout)
        if self.filter is not None:
            cmd += " -b \"{}\"".format(self.filter)
        if self.lfilter is not None:
            raise NotImplementedError("TODO: implement cmd arg for lfilter")
        if iface is not None:
            cmd += " -i \"{}\"".format(iface)
        return cmd

    def run_async(self, callback=None, iface=None):
        if callback is not None:
            raise NotImplementedError("Offline mode and packet callback are not supported in remote sniffer")

        self.remote_file = "~/remote_capture.pcap"

        cmd = self._get_remote_sniffer_command(iface, self.remote_file)
        self.cmd = Command(cmd=cmd, host=self.host)
        self.cmd.run_async()

    def join(self, timeout=None):
        res = self.cmd.join(timeout=timeout)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to execute remote sniffer")
        if not any([SCRIPT_STATUS_SUCCESS in line for line in res["output"]]):
            raise Exception("Failed to execute remote sniffer")

        local_file = "remote_capture.pcap"

        download_file(self.host, self.remote_file, local_file)
        pkts = self.sniff_from_file(local_file)
        remove_file(local_file)

        Command(cmd="rm {}".format(self.remote_file), host=self.host).run_join(5)

        return pkts


class SnifferArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error("\n{}\n".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "%s: error: %s\n" % (self.prog, message))


if __name__ == "__main__":
    parser = SnifferArgumentParser()
    parser.add_argument("-p", "--port", help="PCI port", type=str, required=True)
    parser.add_argument("-t", "--timeout", help="Timeout in seconds", type=int)
    parser.add_argument("-c", "--count", help="Max number of packets", type=int)
    parser.add_argument("-f", "--file", help="File to dump packets to", type=str, default="remote_capture.pcap")
    parser.add_argument("-b", "--bpf", help="Berkley packet filter", type=str)
    parser.add_argument("-i", "--iface", help="Scapy interface name", type=str)
    args = parser.parse_args()

    try:
        if args.timeout is None and args.count is None:
            raise Exception("Either timeout or count must be specified")

        from scapy.all import wrpcap

        sniffer = Sniffer(port=args.port, timeout=args.timeout, count=args.count, filter=args.bpf)
        pkts = sniffer.run(iface=args.iface)
        wrpcap(args.file, pkts)
        log.info("Capture is saved to file '{}'".format(args.file))
    except Exception as e:
        log.exception(e)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
