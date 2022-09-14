import argparse
import re
import sys

from command import Command
from ops import OpSystem
from utils import get_atf_logger

SCRIPT_STATUS_SUCCESS = "[PING-SUCCESS]"
SCRIPT_STATUS_FAILED = "[PING-FAILED]"

log = get_atf_logger()


def ping(number, host, ipv6=False, src_addr=None, payload_size=0, timeout=None, interval=None, margin=0, buffer=0):
    log.info("Sending {} ping requests from {} to {}".format(number, src_addr, host))
    if sys.platform == 'win32':
        ip_version = ' -6' if ipv6 else ' -4'
    else:
        ip_version = '6' if ipv6 else ''
    if src_addr is not None:
        if 'linux' in sys.platform:
            src_addr_param = ' -I {}'.format(src_addr)
        else:
            src_addr_param = ' -S {}'.format(src_addr)
    else:
        src_addr_param = ''
    number_param = '-n' if sys.platform == 'win32' else '-c'
    show_fails = ' -O' if 'linux' in sys.platform else ''
    if payload_size:
        if sys.platform == 'win32':
            length = ' -l {}'.format(payload_size)
        else:
            length = ' -s {}'.format(payload_size)
    else:
        length = ''

    if timeout is not None:
        timeout = float(timeout)
        if sys.platform == 'win32':
            timeout = ' -w {}'.format(timeout * 1000)
        elif sys.platform == 'darwin':
            timeout = ' -W {}'.format(timeout * 1000)
        else:
            timeout = ' -W {}'.format(timeout)
    else:
        timeout = ''

    sudo_required = ''
    if interval is not None:
        interval = float(interval)
        if interval < 0.2:
            sudo_required = 'sudo '
        if interval < 1 and "freebsd" in sys.platform:
            sudo_required = 'sudo '
        if sys.platform == 'win32':
            log.info("WARNING: Windows doesn't support ping interval. Interval between pings will be 1 second")
            interval = ''
        else:
            interval = ' -i {}'.format(interval)
    else:
        interval = ''

    buff = ''
    if OpSystem().is_linux():
        buffer = 0 if buffer is None else int(buffer)
        if buffer > 0:
            buff = ' -S {}'.format(buffer)

    cmd = "{sudo}ping{ip_version}{src_addr_param} {number_param} {number} " \
          "{length}{timeout}{show_fails}{interval}{buff} {host}".format(
                sudo=sudo_required,
                ip_version=ip_version,
                src_addr_param=src_addr_param,
                number_param=number_param,
                number=number,
                host=host,
                length=length,
                timeout=timeout,
                show_fails=show_fails,
                interval=interval,
                buff=buff
    )

    res = Command(cmd=cmd).run()
    if res["returncode"] != 0:
        return False

    if sys.platform == 'win32':
        re_win_lost = re.compile(r".*Lost = (\d+) \((\d+)% loss\).*", re.DOTALL)
        for line in res["output"]:
            # TODO: stupid Windows reports Lost = 0 even dest unreach received!
            if "timed out" in line or "unreachable" in line:
                log.info('Timed out or unreachable: {}'.format(line))
                return False
            m = re_win_lost.match(line)
            if m is not None:
                lost_percent = int(m.group(2))
                if lost_percent <= margin:
                    return True
    elif sys.platform == 'darwin' or "freebsd" in sys.platform:
        re_mac_lost = re.compile(r".*([\d.]+)% packet loss.*", re.DOTALL)
        for line in res["output"]:
            m = re_mac_lost.match(line)
            if m is not None:
                lost_percent = float(m.group(1))
                if lost_percent <= margin:
                    return True
    else:
        re_lin_lost = re.compile(r".* (\d+)% packet loss.*", re.DOTALL)
        for line in res["output"]:
            m = re_lin_lost.match(line)
            if m is not None:
                lost_percent = int(m.group(1))
                if lost_percent <= margin:
                    return True

    log.error("Ping failed")
    return False


class PingArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error("\n{}\n".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    try:
        parser = PingArgumentParser()
        parser.add_argument("-n", "--number", help="Number of ping requests",
                            type=int, default=1)
        parser.add_argument("host", nargs=1, help="Host to ping")
        parser.add_argument("--ipv6", help="Use IPv6", action="store_true")
        parser.add_argument("--src", help="Source IP address", type=str)
        parser.add_argument("-l", "--length", help="Payload length", type=int, default=0)
        parser.add_argument("-t", "--timeout", help="Timeout to wait for reply in seconds", default=None)
        parser.add_argument("-i", "--interval", default=None,
                            help="Time to wait before sending the next echo request in seconds")
        parser.add_argument("-m", "--margin", help="Margin of lost packets in percent", type=int, default=0)
        parser.add_argument("-S", "--buffer", help="Socket sndbuf", type=int, default=0)
        args = parser.parse_args()

        assert ping(args.number, args.host[0], args.ipv6, args.src,
                    args.length, args.timeout, args.interval, args.margin, args.buffer)
    except Exception:
        log.exception("Ping failed")
        log.info(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
