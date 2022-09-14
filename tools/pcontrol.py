import argparse
import socket
import struct
import sys
import timeit

from ifconfig import get_mgmt_iface
from utils import get_atf_logger, get_host_number

SCRIPT_STATUS_SUCCESS = "[PCONTROL-SUCCESS]"
SCRIPT_STATUS_FAILED = "[PCONTROL-FAILED]"

log = get_atf_logger()

UDP_GROUP = "225.0.0.37"
UDP_PORT = 24852

UDP_MAGIC = 0xC001

UDP_CMD = {
    "PING": 0x00,
    "RESET": 0x01,
    "POWER": 0x02,
    "OFF": 0x03,
    "STATUS": 0x04,
    "COLD": 0x05,
    "CH": 0x06,
    "GPIO": 0x07
}

UDP_STATUS = {
    "NACK": 0x80,
    "ACK": 0x81,
    "RES": 0x82,
    "HDD": 0x83,
    "LED": 0x84,
    "PWR": 0x85,
    "STB": 0x86,
    "VCC": 0x87,
    "CH": 0x88,
    "GPIO": 0x89
}

GPIO_ENABLE = 1
GPIO_DISABLE = 0

PIN_GPIO = 8


def check_host(func):
    def wrapper(*args, **kwargs):
        if isinstance(args[1], str):
            args_list = list(args)
            args_list[1] = get_host_number(args[1])
            args = tuple(args_list)

        return func(*args, **kwargs)

    return wrapper


class PControlPacket(object):
    def __init__(self, to_id=None, data=None):
        self.magic = UDP_MAGIC
        self.pid = 0
        self.from_id = 0
        self.to_id = to_id if to_id is not None else 0
        self.seen = 0
        if data is not None:
            self.len = len(data)
            self.data = data
        else:
            self.len = 0
            self.data = b""

    def to_string(self):
        return struct.pack("!IIIIIB", self.magic, self.pid, self.from_id, self.to_id, self.seen, self.len) + self.data

    @staticmethod
    def from_string(s):
        hdr_len = struct.calcsize("!IIIIIB")
        p = PControlPacket()

        p.magic, p.pid, p.from_id, p.to_id, p.seen, p.len = struct.unpack("!IIIIIB", s[:hdr_len])
        p.data = s[hdr_len:hdr_len + p.len]

        return p

    def dump(self):
        log.info("[PControl]")
        log.info("    magic   = 0x{:x}".format(self.magic))
        log.info("    pid     = {}".format(self.pid))
        log.info("    from_id = {}".format(self.from_id))
        log.info("    to_id   = {}".format(self.to_id))
        log.info("    seen    = {}".format(self.seen))
        log.info("    len     = {}".format(self.len))
        log.info("    data    = {} [{}]".format(self.data.encode("hex"), PControlPacket.get_command_name(
            struct.unpack("B", self.data[0])[0] if self.len else 0xFF)))

    @staticmethod
    def get_command_name(to_id):
        for name, val in UDP_CMD.iteritems():
            if val == to_id:
                return "UDP_CMD_{}".format(name)
        for name, val in UDP_STATUS.iteritems():
            if val == to_id:
                return "UDP_STATUS_{}".format(name)
        return "unknown"

    @staticmethod
    def get_ping_cmd_data():
        return struct.pack("B", UDP_CMD["PING"])

    @staticmethod
    def get_reset_cmd_data(length=200, delay=0):
        return struct.pack("!Bii", UDP_CMD["RESET"], length, delay)

    @staticmethod
    def get_power_cmd_data(length=200, delay=0):
        return struct.pack("!Bii", UDP_CMD["POWER"], length, delay)

    @staticmethod
    def get_off_cmd_data(length=10000, delay=0):
        return struct.pack("!Bii", UDP_CMD["OFF"], length, delay)

    @staticmethod
    def get_status_cmd_data():
        return struct.pack("B", UDP_CMD["STATUS"])

    @staticmethod
    def get_cold_cmd_data(length=10000, delay=0):
        return struct.pack("!Bii", UDP_CMD["COLD"], length, delay)

    @staticmethod
    def get_ch_cmd_data(channel=0, length=10000, delay=0):
        return struct.pack("!Biii", UDP_CMD["CH"], channel, length, delay)

    @staticmethod
    def get_gpio_cmd_data(gpio=0, on_off=0):
        return struct.pack("!Bii", UDP_CMD["GPIO"], gpio, on_off)


class PControl(object):
    PING_TIMEOUT = 2.0
    STATUS_TIMEOUT = 2.0

    def __init__(self):
        self.local_ip = get_mgmt_iface()[2]

    def get_udp_socket(self):
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Allow reuse of addresses
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Set multicast interface to local_ip
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.local_ip))

        # Set multicast time-to-live to 2...should keep our multicast packets from escaping the local network
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        # Construct a membership request...tells router what multicast group we want to subscribe to
        membership_request = socket.inet_aton(UDP_GROUP) + socket.inet_aton(self.local_ip)

        # Send add membership request to socket
        # See http://www.tldp.org/HOWTO/Multicast-HOWTO-6.html for explanation of sockopts
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership_request)

        # Bind socket to group to be able ro receive messages
        if sys.platform == "win32":
            sock.bind((self.local_ip, UDP_PORT))
        elif sys.platform == "darwin" or "freebsd" in sys.platform:
            sock.bind(("", UDP_PORT))
        else:
            sock.bind((UDP_GROUP, UDP_PORT))

        return sock

    def _send_pcontrol_packet(self, p, s=None):
        if s is None:
            sock = self.get_udp_socket()
        else:
            sock = s

        try:
            log.info("Sending next Power Control packet:")
            p.dump()
            sock.sendto(p.to_string(), (UDP_GROUP, UDP_PORT))
        finally:
            if s is None:
                sock.close()

    @check_host
    def ping(self, to_id):
        sock = self.get_udp_socket()

        try:
            sock.setblocking(False)

            p = PControlPacket(to_id, PControlPacket.get_ping_cmd_data())
            self._send_pcontrol_packet(p, sock)

            start_time = timeit.default_timer()
            while timeit.default_timer() - start_time < PControl.PING_TIMEOUT:
                try:
                    data = sock.recv(1024)
                except socket.error:
                    continue
                p = PControlPacket.from_string(data)
                if p.from_id == to_id and p.len > 0:
                    cmd = struct.unpack("B", p.data[0])[0]
                    if cmd == UDP_STATUS["ACK"]:
                        return True
                    elif cmd == UDP_STATUS["NACK"]:
                        return False
        finally:
            sock.close()

        return False

    @check_host
    def reset(self, to_id, length=200, delay=0):
        p = PControlPacket(to_id, PControlPacket.get_reset_cmd_data(length, delay))
        self._send_pcontrol_packet(p)

    @check_host
    def power(self, to_id, length=200, delay=0):
        p = PControlPacket(to_id, PControlPacket.get_power_cmd_data(length, delay))
        self._send_pcontrol_packet(p)

    @check_host
    def off(self, to_id, length=10000, delay=0):
        p = PControlPacket(to_id, PControlPacket.get_off_cmd_data(length, delay))
        self._send_pcontrol_packet(p)

    @check_host
    def status(self, to_id):
        sock = self.get_udp_socket()

        try:
            sock.setblocking(False)

            p = PControlPacket(to_id, PControlPacket.get_status_cmd_data())
            self._send_pcontrol_packet(p, sock)

            led_val = -1
            vcc_val = -1

            start_time = timeit.default_timer()
            while timeit.default_timer() - start_time < PControl.STATUS_TIMEOUT:
                try:
                    data = sock.recv(1024)
                except socket.error:
                    continue
                p = PControlPacket.from_string(data)
                if p.from_id == to_id and p.len > 1:
                    cmd, val = struct.unpack("BB", p.data[:2])
                    if cmd == UDP_STATUS["LED"]:
                        led_val = val
                    if cmd == UDP_STATUS["VCC"]:
                        vcc_val = val
                    if led_val >= 0 and vcc_val >= 0:
                        log.info("Power Control {}: LED = {}, VCC = {}".format(to_id, led_val, vcc_val))
                        return led_val, vcc_val
        finally:
            sock.close()

        raise Exception("Failed to get status of Power Control {} (it probably doesn't exist)".format(to_id))

    @check_host
    def cold(self, to_id, length=1000, delay=0):
        p = PControlPacket(to_id, PControlPacket.get_cold_cmd_data(length, delay))
        self._send_pcontrol_packet(p)

    @check_host
    def ch(self, to_id, channel=0, length=10000, delay=0):
        p = PControlPacket(to_id, PControlPacket.get_ch_cmd_data(channel, length, delay))
        self._send_pcontrol_packet(p)

    @check_host
    def gpio(self, to_id, gpio=0, on_off=0, check=True):
        p = PControlPacket(to_id, PControlPacket.get_gpio_cmd_data(gpio, on_off))

        if not check:
            self._send_pcontrol_packet(p)
            return

        sock = self.get_udp_socket()

        try:
            sock.setblocking(False)

            self._send_pcontrol_packet(p, sock)

            start_time = timeit.default_timer()
            while timeit.default_timer() - start_time < PControl.STATUS_TIMEOUT:
                try:
                    data = sock.recv(1024)
                except socket.error:
                    continue
                p = PControlPacket.from_string(data)
                if p.from_id == to_id and p.len > 2:
                    cmd, p_gpio, p_on_off = struct.unpack("BBB", p.data[:3])
                    if cmd == UDP_STATUS["GPIO"] and p_gpio == gpio:
                        log.info("Power Control {}: GPIO {} = {}".format(to_id, gpio, p_on_off))
                        return bool(p_on_off)
        finally:
            sock.close()

        raise Exception("Failed to set GPIO {} = {} on Power Control {} "
                        "(Power Control doesn't exist or firmware is old)".format(gpio, on_off, to_id))

    def listen(self, timeout=10):
        sock = self.get_udp_socket()

        try:
            sock.setblocking(False)
            start_time = timeit.default_timer()
            while timeit.default_timer() - start_time < timeout:
                try:
                    data = sock.recv(1024)
                except socket.error:
                    continue
                p = PControlPacket.from_string(data)
                p.dump()
        finally:
            sock.close()


class PcontrolArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("\n{}\n".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = PcontrolArgumentParser()
    parser.add_argument("-n", "--name", help="Host to perform action",
                        type=str, required=True)
    parser.add_argument("-c", "--command", help="Command to be performed",
                        choices=["reset", "power", "off", "cold", "status", "ping", "offch", "gpio"],
                        type=str, required=True)
    parser.add_argument("-l", "--length", help="Length of the command",
                        type=int, default=200)
    parser.add_argument("-d", "--delay", help="Delay before command",
                        type=int, default=0)
    parser.add_argument("--ch, --channel", dest="channel", help="Channel to turn off (for 12V module)",
                        type=int)
    args = parser.parse_args()

    try:
        p = PControl()

        if args.command == "ping":
            ping_status = p.ping(args.name)
            log.info("PING = {}".format(ping_status))
        elif args.command == "reset":
            p.reset(args.name, args.length, args.delay)
        elif args.command == "power":
            p.power(args.name, args.length, args.delay)
        elif args.command == "off":
            p.off(args.name, args.length, args.delay)
        elif args.command == "status":
            led_status = p.status(args.name)[0]
            log.info("LED = {}".format(led_status))
        elif args.command == "cold":
            p.cold(args.name, args.length, args.delay)
        elif args.command == "offch":
            if args.channel is None:
                raise Exception("To perform 'offch' command, channel must be specified")
            p.ch(args.name, args.channel, args.length, args.delay)
        elif args.command == "gpio":
            gpio_status = p.gpio(args.name, args.length, args.delay)
            log.info("GPIO = {}".format(gpio_status))
    except Exception as e:
        log.exception(e.message)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
