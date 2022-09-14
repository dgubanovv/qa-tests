import argparse
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
        self.rate = -1  # packets per second (continuous)
        self.duration = -1  # continuous and flood
        self.nof_packets = -1  # continuous and burst
        self.delay = -1  # flood
        self.packets = []  # scapy packets

    @classmethod
    def from_dict(cls, data):
        stream = cls()

        assert type(data) is dict
        assert "type" in data.keys()  # stream type
        stream.type = data["type"]
        if stream.type == cls.STREAM_TYPE_BURST:
            stream.nof_packets = int(data["nof_packets"])
        elif stream.type == cls.STREAM_TYPE_CONTINUOUS:
            stream.nof_packets = int(data.get("nof_packets", -1))
            stream.duration = int(data.get("duration", -1))
            stream.rate = int(data["rate"])
            assert stream.nof_packets != -1 or stream.duration != -1
        elif stream.type == cls.STREAM_TYPE_FLOOD:
            stream.delay = float(data["delay"])
            stream.duration = int(data["duration"])
        else:
            raise Exception("Unknown stream type: {}".format(stream.type))
        assert "packets" in data.keys()  # packet must be specified

        stream.packets = eval(data["packets"])
        return stream

    def to_dict(self):
        pkts = "["
        for p in self.packets:
            pkts += p.command().replace("'", "\\\"").replace("/", " // ") + ","
        pkts += "]"
        data = {
            "type": self.type,
            "rate": self.rate,
            "nof_packets": self.nof_packets,
            "duration": self.duration,
            "delay": self.delay,
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
        self.iface = kwargs.get("iface", None)

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
        if self.iface is None:
            self.iface = get_scapy_iface(self.port)

    def _run_stream(self, stream):
        try:
            assert len(stream.packets) != 0

            sock = conf.L2socket(iface=self.iface)
            raw_data = []
            for p in stream.packets:
                raw_data.append(bytes(p))

            if stream.type == TrafficStream.STREAM_TYPE_BURST:
                log.info("Start sending {} traffic stream".format(stream.type))
                start_time = timeit.default_timer()
                for i in range(stream.nof_packets):
                    sock.send(raw_data[i % len(raw_data)])
                end_time = timeit.default_timer()
                log.info("End sending traffic stream, exec time = {} sec".format(end_time - start_time))
            elif stream.type == TrafficStream.STREAM_TYPE_CONTINUOUS:
                # TODO: Assume that packets are sent without latency
                pkt_delay = 1 / float(stream.rate)
                if stream.nof_packets != -1:
                    nof_packets = stream.nof_packets
                    if stream.duration != -1:
                        nof_packets_by_duration = stream.rate * stream.duration
                        if nof_packets_by_duration < nof_packets:
                            nof_packets = nof_packets_by_duration
                else:
                    nof_packets = stream.rate * stream.duration
                log.info("Start sending {} traffic stream".format(stream.type))
                start_time = timeit.default_timer()
                while nof_packets > 0:
                    sock.send(raw_data[nof_packets % len(raw_data)])  # TODO: this is a reversed send
                    time.sleep(pkt_delay)
                    nof_packets -= 1
                end_time = timeit.default_timer()
                log.info("End sending traffic stream, exec time = {} sec".format(end_time - start_time))
            elif stream.type == TrafficStream.STREAM_TYPE_FLOOD:
                log.info("Start sending {} traffic stream".format(stream.type))
                start_time = timeit.default_timer()
                nof_packets = stream.duration / stream.delay
                for i in range(int(nof_packets)):
                    sock.send(raw_data[i % len(raw_data)])
                    time.sleep(stream.delay)
                    if not i % 100:
                        if timeit.default_timer() - start_time > stream.duration:
                            break
                end_time = timeit.default_timer()
                log.info("End sending traffic stream, exec time = {} sec".format(end_time - start_time))
            sock.close()
        except Exception as e:
            log.exception('Exception in _run_stream -> {}'.format(e))
            raise e

    def run_async(self):
        self.stream_threads = []
        for stream in self.streams:
            thr = threading.Thread(target=self._run_stream, args=(stream,))
            thr.daemon = True
            thr.start()
            self.stream_threads.append(thr)

    def join(self, timeout=1000000):
        for thread in self.stream_threads:
            thread.join(timeout=timeout)

    def run(self, timeout=1000000):
        self.run_async()
        self.join(timeout=timeout)

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
        self.iface = kwargs.get("iface", None)
        self.remote_cmd = None

    def run_remote(self, async_mode=False, input_mode="streams", iface=None):
        if input_mode == "file":
            cmd = "cd {} && sudo python trafficgen.py -p {} -f \"{}\"".format(ATF_TOOLS_DIR, self.port, self.file)
        else:
            cmd = "cd {} && sudo python trafficgen.py -p {} -s \"{}\"".format(ATF_TOOLS_DIR, self.port, self._streams_to_string())

        if iface is not None:
            cmd += " -i {}".format(iface)

        self.remote_cmd = Command(cmd=cmd, host=self.host)
        if async_mode:
            self.remote_cmd.run_async()
        else:
            self.remote_cmd.run()

    def run_async(self):
        if self.file is not None:
            self.run_remote(async_mode=True, input_mode="file", iface=self.iface)
        else:
            self.run_remote(async_mode=True, iface=self.iface)

    def run(self):
        if self.file is not None:
            self.run_remote(async_mode=False, input_mode="file", iface=self.iface)
        else:
            self.run_remote(async_mode=False, iface=self.iface)

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
    parser.add_argument("-i", "--iface", help="scapy interface",
                        type=str, action=SpacedArgAction, nargs='+')
    args = parser.parse_args()

    try:
        if args.streams is not None and args.file is None:
            streams_arr = eval(args.streams.replace("//", "/"))
            traf_gen = TrafficGenerator(port=args.port, iface=args.iface)
            for stream_dict in streams_arr:
                traf_stream = TrafficStream.from_dict(stream_dict)
                traf_gen.add_stream(traf_stream)
            traf_gen.run()
        elif args.streams is None and args.file is not None:
            with open(args.file) as f:
                streams = f.read()
                streams_arr = eval(streams.replace("//", "/"))
                traf_gen = TrafficGenerator(port=args.port, iface=args.iface)
                for stream_dict in streams_arr:
                    traf_stream = TrafficStream.from_dict(stream_dict)
                    traf_gen.add_stream(traf_stream)
                traf_gen.run(timeout=(traf_stream.duration + 5))
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


# g = TrafficGenerator(port="pci1.00.0")

# s1 = TrafficStream()
# s1.type = TrafficStream.STREAM_TYPE_BURST
# s1.nof_packets = 10
# s1.packets = pkt1
# g.add_stream(s1)

# s2 = TrafficStream()
# s2.type = TrafficStream.STREAM_TYPE_CONTINUOUS
# s2.rate = 2
# s2.duration = 5
# s2.nof_packets = 5
# s2.packets = pkt2
# g.add_stream(s2)

# s3 = TrafficStream()
# s3.type = TrafficStream.STREAM_TYPE_CONTINUOUS
# s3.rate = 1
# s3.duration = 5
# s3.packets = pkt2
# g.add_stream(s3)

# g.run()

# s = trafficgen.TrafficStream()
# s.type = trafficgen.TrafficStream.STREAM_TYPE_BURST
# s.nof_packets = nof_packets
# s.packets = pkts
# tg.add_stream(s)
# tg.add_traffic_file()
# tg.run()
# tg.remove_traffic_file()

# COMMAND LINE EXAMPLE
# sudo python trafficgen.py -p pci1.00.0 -s "[{'duration': '-1', 'nof_packets': '10', 'rate': '-1', 'type': 'burst', 'packets': ['Ether(src=\"15:16:15:16:15:16\", dst=\"17:17:17:17:17:17\") // IP(src=\"192.168.0.1\", dst=\"192.168.0.2\") // ICMP() // Raw(load=\"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\")'}, {'duration': '5', 'nof_packets': '-1', 'rate': '2', 'type': 'continuous', 'packet': 'Ether(src=\"15:16:15:16:15:16\", dst=\"17:17:17:17:17:17\") // IP(src=\"192.168.0.1\", dst=\"192.168.0.3\") // ICMP() // Raw(load=\"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\")']}]"
# sudo python trafficgen.py -p pci9.00.0 -i macsec0 -f traffic.capt
