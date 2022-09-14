import argparse
import re
import socket
import sys
import threading
import time
from abc import abstractmethod, ABCMeta

# Scapy steals stdout, keep it after import
import sys
sys_stdout = sys.stdout
from scapy.all import sniff as scapy_sniff
sys.stdout = sys_stdout

from command import Command
from constants import ATF_TOOLS_DIR
from ifconfig import get_conn_name
from log import get_atf_logger
from ops import OpSystem
from utils import remove_file, download_file

SCRIPT_STATUS_SUCCESS = "[TCPDUMP-SUCCESS]"
SCRIPT_STATUS_FAILED = "[TCPDUMP-FAILED]"

log = get_atf_logger()


class Tcpdump(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(TcpdumpLocal)
        else:
            return object.__new__(TcpdumpRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]
        self.count = kwargs.get("count", 0)
        self.timeout = kwargs.get("timeout", 24 * 60 * 60)
        self.file = kwargs.get("file", None)
        self.nopromisc = kwargs.get("nopromisc", None)

        self.delay_after_start = 3

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


class TcpdumpLocal(Tcpdump):

    def __init__(self, **kwargs):
        super(TcpdumpLocal, self).__init__(**kwargs)
        self.packets = None

    def _get_tshark_command(self, file):
        from utils import get_wmi_network_adapter
        adapter = get_wmi_network_adapter(self.port)
        dnet_iface = adapter.NetConnectionID
        log.info("Looking for dnet iface {}".format(dnet_iface))

        Command(cmd="sc stop npf").wait(timeout=20)
        Command(cmd="sc start npf").wait(timeout=20)

        time.sleep(5)

        res = Command(cmd="tshark -D").wait(timeout=10)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to obtain list of tshark interfaces")

        idx = -1
        re_idx_iface = re.compile(r"^([0-9]+)\. .* \((Ethernet[\s0-9]*)\).*", re.DOTALL)
        for line in res["output"]:
            if dnet_iface in line:
                m = re_idx_iface.match(line)
                if m is not None:
                    idx = int(m.group(1))
                    net_id = m.group(2)
                    if dnet_iface == net_id:
                        break
        else:
            raise Exception("Failed to find requested network to capture traffic")

        return "tshark -i {} -a duration:{} -F pcap -w {}".format(idx, self.timeout + self.delay_after_start, file)

    def _get_tcpdump_command(self, file):
        iface = get_conn_name(self.port)
        cmd = "sudo timeout {} tcpdump -i {} -B 524288 -w {}".format(self.timeout + self.delay_after_start,
                                                                     iface, file)
        if self.nopromisc:
            cmd += ' -p'

        if OpSystem().is_mac():
            cmd = "sudo gtimeout {}s {} ".format(self.timeout, cmd[15:])
        return cmd

    def _get_sniff_cmd(self, file):
        if sys.platform == 'win32':
            cmd = self._get_tshark_command(file)
        else:
            cmd = self._get_tcpdump_command(file)
        return cmd

    def run(self):
        delete_file = self.file is None
        cap_file = self.file if self.file is not None else "cap.pcap"

        cmd = self._get_sniff_cmd(cap_file)
        res = Command(cmd=cmd, live_output=True).run()  # Live output is needed for correct remote execution
        if res["returncode"] not in [0, 124]:
            raise Exception("Failed to run sniffing tool")
        packets = scapy_sniff(offline=cap_file)

        if delete_file:
            remove_file(cap_file)
        return packets

    def run_async(self):
        log.info("Starting tcpdump on localhost asynchronously")
        self.delete_file = self.file is None
        self.cap_file = self.file if self.file is not None else "cap.pcap"

        is_started_event = threading.Event()

        def callback(pattern):
            is_started_event.set()

        cmd = self._get_sniff_cmd(self.cap_file)
        self.cmd = Command(cmd=cmd)
        self.cmd.run_async([("Capturing on", callback), ("listening on", callback)])

        is_started = is_started_event.wait(180)  # Wait 180 seconds for start condition
        if not is_started:
            self.cmd.join(0)
            raise Exception("Failed to start tcpdump")

        time.sleep(self.delay_after_start)
        log.info("Tcpdump has been started")

    def join(self, timeout=None):
        self.cmd.join(timeout=timeout)
        packets = scapy_sniff(offline=self.cap_file)

        if self.delete_file:
            remove_file(self.cap_file)
        return packets


class TcpdumpRemote(Tcpdump):

    def __init__(self, **kwargs):
        super(TcpdumpRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]

    def _get_remote_tcpdump_command(self, remote_file):
        cmd = "cd {} && python tcpdump.py -p {}".format(ATF_TOOLS_DIR, self.port)
        if self.count is not None or self.count != 0:
            cmd += " -c {}".format(self.count)
        if self.timeout is not None:
            cmd += " -t {}".format(self.timeout)
        cmd += " -f {}".format(remote_file)
        if self.nopromisc:
            cmd += " --nopromisc"
        return cmd

    def run(self):
        remote_file = "~/remote_capture.pcap"
        cmd = self._get_remote_tcpdump_command(remote_file)
        Command(cmd=cmd, host=self.host).run()

        if self.file is not None:
            local_file = self.file
        else:
            local_file = "remote_capture.pcap"
        download_file(self.host, remote_file, local_file)
        packets = scapy_sniff(offline=local_file)
        if self.file is None:
            remove_file(local_file)
        cmd = "rm {}".format(remote_file)
        Command(cmd=cmd, host=self.host).run_join(5)
        return packets

    def run_async(self):
        self.remote_file = "~/remote_capture.pcap"
        cmd = self._get_remote_tcpdump_command(self.remote_file)
        self.cmd = Command(cmd=cmd, host=self.host)

        is_started_event = threading.Event()

        def callback(pattern):
            is_started_event.set()

        self.cmd.run_async([("Capturing on", callback), ("listening on", callback)])

        is_started = is_started_event.wait(180)  # Wait 180 seconds for start condition
        if not is_started:
            self.cmd.join(0)
            raise Exception("Failed to start tcpdump")

        time.sleep(self.delay_after_start)
        log.info("Tcpdump has been started")

    def join(self, timeout=None):
        self.cmd.join(timeout=timeout)

        if self.file is not None:
            local_file = self.file
        else:
            local_file = "remote_capture.pcap"
        download_file(self.host, self.remote_file, local_file)

        packets = scapy_sniff(offline=local_file)

        if self.file is None:
            remove_file(local_file)
        return packets


class TcpdumpArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error("\n{}\n".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "%s: error: %s\n" % (self.prog, message))


if __name__ == "__main__":
    parser = TcpdumpArgumentParser()
    parser.add_argument("-p", "--port", help="PCI port", type=str, required=True)
    parser.add_argument("-t", "--timeout", help="Timeout in seconds", type=int)
    parser.add_argument("-c", "--count", help="Number of packets to capture", type=int)
    parser.add_argument("-f", "--file", help="File to dump packets", type=str)
    parser.add_argument("--nopromisc", help="Don't put the interface into promiscuous mode",
                        action='store_true', default=False)
    args = parser.parse_args()

    try:
        if args.timeout is None and args.count is None:
            raise Exception("Either timeout or count must be specified")
        if args.file is not None:
            if " " in args.file:
                raise Exception("Please specify file name without spaces")
        tcpdump = Tcpdump(port=args.port, timeout=args.timeout, file=args.file, nopromisc=args.nopromisc)
        tcpdump.run()
        if args.file is not None:
            log.info("Capture is saved to {} file".format(args.file))
    except Exception as e:
        log.exception(e)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
