import argparse
import os
import threading
import time
import timeit

from abc import abstractmethod, ABCMeta
from constants import ATF_TOOLS_DIR
from command import Command
from utils import get_atf_logger
from ops import OpSystem

log = get_atf_logger()

SCRIPT_STATUS_SUCCESS = "[AVBSTREAM-UTIL-SUCCESS]"
SCRIPT_STATUS_FAILED = "[AVBSTREAM-UTIL-FAILED]"

class AvbstreamUtil(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost":
            return object.__new__(AvbstreamUtilLocal)
        else:
            return object.__new__(AvbstreamUtilRemote)

    def __init__(self, **kwargs):
        self.iface = kwargs["iface"]
        self.packet_period = kwargs["packet_period"]
        self.side = kwargs["side"]
        self.id = kwargs.get("id", 0)
        self.output_file = kwargs.get("output_file", None)

    @abstractmethod
    def run_async(self):
        pass

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def join(self):
        pass

    @abstractmethod
    def run_join(self, timeout):
        pass


class AvbstreamUtilLocal(AvbstreamUtil):
    def __init__(self, **kwargs):
        super(AvbstreamUtilLocal, self).__init__(**kwargs)
        op_sys = OpSystem()
        if op_sys.is_mac():
            if self.side == "rx":
                avbstream = os.path.join(os.environ["ATF_TOOLS"], "avbstreamrx")
                awk = "| awk '{if(NR%1000 == 0)print}' "
            if self.side == "tx":
                avbstream = os.path.join(os.environ["ATF_TOOLS"], "avbstreamtx")
                awk = ""
        else:
            raise NotImplementedError()

        if self.output_file is not None:
            f_name = " > {}".format(self.output_file)
        else:
            f_name = ' 1> /dev/null'

        cmd = "{} --interface {} --packet-period {} --stream-id {} {}{}".format(
            avbstream, self.iface, self.packet_period, self.id, awk, f_name
        )
        self.command = Command(cmd=cmd)

    def run_async(self):
        return self.command.run_async()

    def run(self):
        return self.command.run()

    def join(self, timeout=None):
        return self.command.join(timeout=timeout)

    def run_join(self, timeout):
        return self.command.run_join(timeout)


class AvbstreamUtilRemote(AvbstreamUtil):
    def __init__(self, **kwargs):
        super(AvbstreamUtilRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        if self.output_file is not None:
            output_file = " -l {}".format(self.output_file)
        else:
            output_file = ""
        cmd = "cd {} && python avbstream.py -i {} -p {} -s {} -id {}{}".format(
            ATF_TOOLS_DIR, self.iface, self.packet_period, self.side, self.id, output_file
        )
        self.remote_cmd = Command(cmd=cmd, host=self.host)

    def run_async(self):
        return self.remote_cmd.run_async()

    def run(self):
        return self.remote_cmd.run()

    def join(self, timeout=None):
        return self.remote_cmd.join(timeout=timeout)

    def run_join(self, timeout):
        return self.remote_cmd.run_join(timeout)


class AvbstreamUtilArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("{}".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = AvbstreamUtilArgumentParser()
    parser.add_argument("-i", "--iface", help="Interface name, i.e. en1, ...",
                        type=str, required=True)
    parser.add_argument("-p", "--packet_period", help="Packet period time i.e 125000",
                        type=int, required=False, default=125000)
    parser.add_argument("-s", "--side", help="Rx or Tx side", choices=["rx", "tx"], default="rx")
    parser.add_argument("-l", "--log_file", help="Log file for stream logs")
    parser.add_argument("-id", "--stream_id", help="Stream id")

    args = parser.parse_args()

    try:
        avbstream = AvbstreamUtil(
            iface=args.iface, packet_period=args.packet_period, side=args.side, output_file=args.log_file,
            id=args.stream_id
        )
        avbstream.run()

    except Exception:
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
