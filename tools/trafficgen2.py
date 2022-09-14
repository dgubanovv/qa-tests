import argparse
import os
import socket
import threading
import time
import timeit

from abc import abstractmethod, ABCMeta
from constants import ATF_TOOLS_DIR
from command import Command
from utils import get_atf_logger, SpacedArgAction, upload_file

import sys
sys_stdout = sys.stdout
from scapy.all import *  # Support all kinds of packets
from scapy_tools import get_scapy_iface
sys.stdout = sys_stdout


log = get_atf_logger()

SCRIPT_STATUS_SUCCESS = "[TRAFFIC-GENERATOR-SUCCESS]"
SCRIPT_STATUS_FAILED = "[TRAFFIC-GENERATOR-FAILED]"
TRAFFIC_FILE_PATH = "traffic.capt"


class TrafficStream(object):
    STREAM_TYPE_BURST = "burst"
    STREAM_TYPE_CONTINUOUS = "continuous"
    STREAM_TYPE_FLOOD = "flood"

    def __init__(self):
        self.duration = 0
        self.delay = 0
        self.packets = []
        self.repeat = 0
        self.is_stop = False

    @classmethod
    def from_dict(cls, data):
        stream = cls()
        assert "packets" in data.keys()  # packet must be specified

        stream.duration = float(data["duration"])
        stream.delay = float(data["delay"])
        stream.repeat = float(data["repeat"])
        stream.packets = eval(data["packets"])
        return stream

    def to_dict(self):
        pkts = "["
        for p in self.packets:
            pkts += p.command().replace("'", "\\\"").replace("/", " // ") + ","
        pkts += "]"

        data = {
            "duration": self.duration,
            "delay": self.delay,
            "repeat": self.repeat,
            "packets": pkts
        }

        return data


class TrafficGenerator(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(TrafficGeneratorLocal)
        else:
            return object.__new__(TrafficGeneratorRemote)

    def __init__(self, **kwargs):
        self.streams = []
        self.port = kwargs["port"]
        self.file = None

    @abstractmethod
    def run_async(self):
        pass

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def join(self):
        pass

    def add_stream(self, stream):
        assert type(stream) is TrafficStream
        self.streams.append(stream)

    @abstractmethod
    def add_traffic_file(self, filename):
        pass

    @abstractmethod
    def remove_traffic_file(self, filename):
        pass

    def _streams_to_string(self):
        # TODO: this method is blocking
        # need a non-blocking method to run a background traffic
        streams = []
        for stream in self.streams:
            streams.append(stream.to_dict())

        ss = "["
        for stream_dict in streams:
            ss += "{"
            for k, v in stream_dict.items():
                ss += "'{}': '{}', ".format(k, v)
            ss = ss.rstrip(", ")
            ss += "}, "
        ss = ss.rstrip(", ")
        ss += "]"

        return ss


class TrafficGeneratorLocal(TrafficGenerator):
    def __init__(self, **kwargs):
        super(TrafficGeneratorLocal, self).__init__(**kwargs)
        self.iface = get_scapy_iface(self.port)

    def _run_stream(self, stream):
        try:
            assert len(stream.packets) != 0

            sock = conf.L2socket(iface=self.iface)
            raw_data = []
            for p in stream.packets:
                raw_data.append(bytes(p))

            start_time = timeit.default_timer()

            indx = 0
            packets_count = 0

            while True:
                if stream.duration > 0:
                    if start_time + stream.duration <= timeit.default_timer():
                        log.info('Traffic generator STOP! Reason: timeout')
                        break

                if stream.repeat > 0:
                    if indx >= stream.repeat:
                        log.info('Traffic generator STOP! Reason: maximum repeats')
                        break

                for i in range(len(stream.packets)):
                    sock.send(raw_data[i % len(raw_data)])
                    packets_count += 1
                    time.sleep(stream.delay)

                if stream.is_stop:
                    log.info('Traffic generator STOP! Reason: by request')
                    break

                indx += 1

            end_time = timeit.default_timer()
            log.info("End sending traffic stream, exec time = {:.3f} sec;  was sended {} packets".format(end_time - start_time, packets_count))

            sock.close()
        except Exception as e:
            log.exception('Exception in _run_stream -> {}'.format(e))
            raise e

    def run_async(self):
        self.stream_threads = []
        for stream in self.streams:
            stream.is_stop = False
            log.debug('TrafficGen.run_async')
            thr = threading.Thread(target=self._run_stream, args=(stream,))
            thr.daemon = True
            thr.start()
            self.stream_threads.append(thr)

    def join(self, timeout):
        for stream in self.streams:
            stream.is_stop = True
            log.debug('TrafficGen.join')

        for thread in self.stream_threads:
            thread.join(timeout=1)

    def run(self,timeout):
        log.debug('TrafficGen.run:')
        self.run_async()
        time.sleep(timeout)
        self.join(timeout=5)

    def add_traffic_file(self, filename=TRAFFIC_FILE_PATH):
        self.file = filename
        with open("tools/" + filename, "w+") as f:
            f.write(self._streams_to_string())

    def remove_traffic_file(self, filename=TRAFFIC_FILE_PATH):
        path = os.path.join(os.path.abspath(os.path.dirname(__file__)), filename)
        os.remove(path)
        self.file = None


class TrafficGeneratorRemote(TrafficGenerator):
    def __init__(self, **kwargs):
        super(TrafficGeneratorRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.remote_cmd = None

    def run_remote(self, async_mode=False, input_mode="streams"):
        if input_mode == "file":
            cmd = "cd {} && sudo python trafficgen2.py -p {} -f \"{}\"".format(ATF_TOOLS_DIR, self.port, self.file)
        else:
            cmd = "cd {} && sudo python trafficgen2.py -p {} -s \"{}\"".format(ATF_TOOLS_DIR, self.port, self._streams_to_string())
        self.remote_cmd = Command(cmd=cmd, host=self.host)
        if async_mode:
            self.remote_cmd.run_async()
        else:
            self.remote_cmd.run()

    def run_async(self):
        if self.file is not None:
            self.run_remote(async_mode=True, input_mode="file")
        else:
            self.run_remote(async_mode=True)

    def run(self):
        if self.file is not None:
            self.run_remote(async_mode=False, input_mode="file")
        else:
            self.run_remote(async_mode=False)

    def join(self):
        self.remote_cmd.join()

    def add_traffic_file(self, filename=TRAFFIC_FILE_PATH):
        self.file = filename
        with open("tools/" + filename, "w+") as f:
            f.write(self._streams_to_string())
        upload_file(self.host, "tools/" + filename, ATF_TOOLS_DIR)

    def remove_traffic_file(self, filename=TRAFFIC_FILE_PATH):
        # TODO works only for Linux. Need to Windows support
        if filename == TRAFFIC_FILE_PATH:
            filename = ATF_TOOLS_DIR + "/" + filename
        cmd = "rm -rf {}".format(filename)
        Command(cmd=cmd, host=self.host).wait(timeout=10)


class TrafficgenArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("{}".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = TrafficgenArgumentParser()
    parser.add_argument("-p", "--port", help="PCI port, i.e. pci0.00.0, ...",
                        type=str, required=True)
    parser.add_argument("-s", "--streams", help="Array of traffic streams (should be evaluated)",
                        type=str, action=SpacedArgAction, nargs='+')
    parser.add_argument("-f", "--file", help="File with array of traffic streams (should be evaluated)",
                        type=str, action=SpacedArgAction, nargs='+')
    args = parser.parse_args()

    try:
        if args.streams is not None and args.file is None:
            streams_arr = eval(args.streams.replace("//", "/"))
            traf_gen = TrafficGenerator(port=args.port)
            for stream_dict in streams_arr:
                traf_stream = TrafficStream.from_dict(stream_dict)
                traf_gen.add_stream(traf_stream)
            traf_gen.run()
        elif args.streams is None and args.file is not None:
            with open(args.file) as f:
                streams = f.read()
                streams_arr = eval(streams.replace("//", "/"))
                traf_gen = TrafficGenerator(port=args.port)
                for stream_dict in streams_arr:
                    traf_stream = TrafficStream.from_dict(stream_dict)
                    traf_gen.add_stream(traf_stream)
                traf_gen.run(timeout=(traf_stream.duration))
        elif args.streams is not None and args.file is not None:
            log.error("Only one parameter streams or file must be specified.")
            log.error(SCRIPT_STATUS_FAILED)
            exit(1)
        else:
            log.error("Streams or file must be specified")
            log.error(SCRIPT_STATUS_FAILED)
            exit(1)
    except Exception:
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)


# SOME EXAMPLES:

# eth = Ether(src="15:16:15:16:15:16", dst="17:17:17:17:17:17")
# ip1 = IP(src="192.168.0.1", dst="192.168.0.2")
# ip2 = IP(src="192.168.0.1", dst="192.168.0.3")
# icmp = ICMP()
# raw = Raw(load="ffffffffffffffffffffffffffffffff".decode("hex"))
# pkt1 = eth / ip1 / icmp / raw
# pkt2 = eth / ip2 / icmp / raw

# COMMAND LINE EXAMPLE
# sudo python trafficgen.py -p pci1.00.0 -s "[{'duration': '-1', 'nof_packets': '10', 'rate': '-1', 'type': 'burst', 'packets': ['Ether(src=\"15:16:15:16:15:16\", dst=\"17:17:17:17:17:17\") // IP(src=\"192.168.0.1\", dst=\"192.168.0.2\") // ICMP() // Raw(load=\"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\")'}, {'duration': '5', 'nof_packets': '-1', 'rate': '2', 'type': 'continuous', 'packet': 'Ether(src=\"15:16:15:16:15:16\", dst=\"17:17:17:17:17:17\") // IP(src=\"192.168.0.1\", dst=\"192.168.0.3\") // ICMP() // Raw(load=\"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\")']}]"
