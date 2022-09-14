import socket
import sys
import threading
from abc import abstractmethod, ABCMeta

sys_stdout = sys.stdout
from scapy.all import sniff as scapy_sniff, Packet
sys.stdout = sys_stdout

from command import Command
from log import get_atf_logger
from utils import remove_file, download_file


log = get_atf_logger()


def scapy_pkt_to_aqsendp_str(p):
    s = ""
    for b in str(p):
        s += "{:02x}".format(ord(b))
    return s


class Aqdumpp(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(AqdumppLocal)
        else:
            return object.__new__(AqdumppRemote)

    def __init__(self, **kwargs):
        self.count = kwargs.get("count", -1)
        self.timeout = kwargs.get("timeout", -1)
        self.file = kwargs.get("file", None)
        self.iface = kwargs.get("iface", None)

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

    def _get_aqdumpp_cmd(self, file):
        cmd = "sudo aqdumpp "
        if self.count > 0:
            cmd += "-n {} ".format(self.count)
        if self.timeout > 0:
            cmd += "-t {} ".format(self.timeout)
        if self.iface is not None:
            cmd += "-i \"{}\" ".format(self.iface)
        cmd += "-w {}".format(file)
        return cmd


class AqdumppLocal(Aqdumpp):

    def __init__(self, **kwargs):
        super(AqdumppLocal, self).__init__(**kwargs)
        self.packets = None

    def run(self):
        delete_file = self.file is None
        cap_file = self.file if self.file is not None else "cap.pcap"

        cmd = self._get_aqdumpp_cmd(cap_file)
        res = Command(cmd=cmd, live_output=True).run()  # Live output is needed for correct remote execution
        if res["returncode"] not in [0, 124]:
            raise Exception("Failed to run sniffing tool")
        packets = scapy_sniff(offline=cap_file)

        if delete_file:
            remove_file(cap_file)
        return packets

    def run_async(self):
        log.info("Starting aqdumpp on localhost asynchronously")
        self.delete_file = self.file is None
        self.cap_file = self.file if self.file is not None else "cap.pcap"

        is_started_event = threading.Event()

        def callback(pattern):
            is_started_event.set()

        cmd = self._get_aqdumpp_cmd(self.cap_file)
        self.cmd = Command(cmd=cmd)
        self.cmd.run_async([("Capturing on", callback), ("listening on", callback)])

        is_started = is_started_event.wait(180)  # Wait 180 seconds for start condition
        if not is_started:
            self.cmd.join(0)
            raise Exception("Failed to start aqdumpp")

        log.info("Aqdumpp has been started")

    def join(self, timeout=None):
        self.cmd.join(timeout=timeout)
        packets = scapy_sniff(offline=self.cap_file)

        if self.delete_file:
            remove_file(self.cap_file)
        return packets


class AqdumppRemote(Aqdumpp):

    def __init__(self, **kwargs):
        super(AqdumppRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]

    def run(self):
        remote_file = "~/remote_capture.pcap"
        cmd = self._get_aqdumpp_cmd(remote_file)
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
        cmd = self._get_aqdumpp_cmd(self.remote_file)
        self.cmd = Command(cmd=cmd, host=self.host)

        is_started_event = threading.Event()

        def callback(pattern):
            is_started_event.set()

        self.cmd.run_async([("Capturing on", callback), ("listening on", callback)])

        is_started = is_started_event.wait(10)  # Wait 10 seconds for start condition
        if not is_started:
            self.cmd.join(0)
            raise Exception("Failed to start tcpdump")
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


class Aqsendp(object):
    def __init__(self, **kwargs):
        self.count = kwargs.get("count", None)
        self.timeout = kwargs.get("timeout", None)
        self.rate = kwargs.get("rate", None)
        self.iface = kwargs.get("iface", None)
        self.host = kwargs.get("host", None)
        self.inputfile = kwargs.get("inputfile", None)

        self.packet = kwargs.get("packet", None)
        if self.packet is not None and issubclass(self.packet.__class__, Packet):
            self.packet = scapy_pkt_to_aqsendp_str(self.packet)

    def get_command(self):
        assert self.count or self.timeout
        assert self.packet or self.inputfile

        cmd = "sudo aqsendp "
        if self.count:
            cmd += "-n {} ".format(self.count)
        if self.timeout:
            cmd += "-t {} ".format(self.timeout)
        if self.rate:
            cmd += "-r {} ".format(self.rate)
        if self.iface:
            cmd += "-i \"{}\" ".format(self.iface)
        if isinstance(self.packet, list):
            cmd += '-p "{}"'.format(';'.join(self.packet))
        else:
            cmd += '-p {}'.format(self.packet)

        return cmd

    def run(self):
        cmd = self.get_command()
        res = Command(cmd=cmd, host=self.host).run()
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Aqsendp failed")

    def run_async(self):
        cmd = self.get_command()
        self.cmd = Command(cmd=cmd, host=self.host)
        self.cmd.run_async()

    def join(self, timeout=None):
        res = self.cmd.join(timeout=timeout)
        self.cmd = None
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Aqsendp failed")

    def run_join(self, timeout=None):
        self.run_async()
        return self.join(timeout=timeout)

    def wait(self, timeout=None):
        self.run_join(timeout=timeout)


# a = Aqsendp(timeout=1, rate=5, packet="0017b6206ddd0017b6d09415080045000037000100004011f7d1c0a8", iface="eth0")
# a.run_async()
# a.join(2)
