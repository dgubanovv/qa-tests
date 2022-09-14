import argparse
import os
import re
import requests
import socket
import sys
import timeit
import traceback

from command import Command
from abc import abstractmethod, ABCMeta
from constants import KNOWN_OSES, LINUX_OSES, QNX_OSES, OS_UNKNOWN, ATF_TOOLS_DIR, BOOTP_SERVER, \
    MAC_OSES, WIN_OSES, UBUNTU_OSES, CENTOS_OSES, RHEL_OSES, FREEBSD_OSES
from log import get_atf_logger

SCRIPT_STATUS_SUCCESS = "[OS-SUCCESS]"
SCRIPT_STATUS_FAILED = "[OS-FAILED]"

log = get_atf_logger()


# TODO: this method is copy-pasted from utils.py to avoid cyclic dependency
def get_url_response(url):
    log.info("GET request for URL: {}".format(url))
    response = requests.get(url)
    log.info("Response code = {}".format(response.status_code))
    if response.status_code != 200:
        raise Exception("Failed to request the URL")
    return response.content


def get_os_name():
    return os.environ["ATF_OS"]


def get_arch():
    ops = OpSystem()
    if ops.is_freebsd():
        return "64"
    cmd = Command(cmd="arch")
    cmd.run()
    res = cmd.join(1)
    if res["returncode"] != 0:
        raise Exception("Failed while getting arch")

    output = res["output"]
    if ops.is_windows():
        arch = ("64" if "x86_64" in output[0] else "32")
        return arch

    return output[0]


def request_os_restoration(os_name, bootp, hostname):
    if hostname is None or hostname == "localhost":
        host = socket.gethostname()
    else:
        host = hostname

    host_revision_url = "{}/revision_on_host.php?host={}&os={}".format(
        bootp, host, os_name)
    os_revision_on_host = int(get_url_response(host_revision_url))
    log.info("OS revision on host {} is {}".format(host, os_revision_on_host))

    os_revision_url = "{}/revision.php?os={}".format(bootp, os_name)
    os_latest_revision = int(get_url_response(os_revision_url))
    log.info("Latest OS {} revision is {}".format(os_name, os_latest_revision))

    if os_latest_revision > os_revision_on_host:
        action = "install"
    else:
        action = "restore"

    action_url = "{}/set.php?host={}&os={}&action={}".format(
        bootp, host, os_name, action)
    get_url_response(action_url)
    return action


class OpSystem(object):
    __metaclass__ = ABCMeta

    RE_OS_NAME = re.compile(".*OS = ([a-zA-Z0-9\.\-]+)", re.DOTALL)
    RE_ACTION = re.compile(".*Action = ([a-z]+)", re.DOTALL)

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host in [None, "localhost", socket.gethostname()]:
            return object.__new__(OpSystemLocal)
        else:
            return object.__new__(OpSystemRemote)

    def __init__(self, **kwargs):
        self.bootp = kwargs.get("bootp", BOOTP_SERVER)

    @abstractmethod
    def request_os_restoration(self, os_name_to_restore):
        pass

    @abstractmethod
    def get_name(self):
        pass

    def is_linux(self):
        return self.get_name() in LINUX_OSES

    def is_mac(self):
        return self.get_name() in MAC_OSES

    def is_windows(self):
        return self.get_name() in WIN_OSES

    def is_win10(self):
        return "Win10" in self.get_name()

    def is_win81(self):
        return "Win8.1" in self.get_name()

    def is_win8(self):
        return "Win8-" in self.get_name()

    def is_win7(self):
        return "Win7" in self.get_name()

    def get_arch(self):
        return self.get_name().split("-")[-1]

    def is_32_bit(self):
        return "32" == self.get_arch()

    def is_64_bit(self):
        return "64" == self.get_arch()

    def is_qnx(self):
        return self.get_name() in QNX_OSES

    def is_ubuntu(self):
        return self.get_name() in UBUNTU_OSES

    def is_centos(self):
        return self.get_name() in CENTOS_OSES

    def is_rhel(self):
        return self.get_name() in RHEL_OSES

    def is_freebsd(self):
        return self.get_name() in FREEBSD_OSES


class OpSystemLocal(OpSystem):
    def __init__(self, **kwargs):
        super(OpSystemLocal, self).__init__(**kwargs)

    def request_os_restoration(self, os_name_to_restore):
        return request_os_restoration(os_name_to_restore, self.bootp, None)

    def get_name(self):
        return get_os_name()


class OpSystemRemote(OpSystem):
    GET_NAME_CACHE_LIFETIME = 120

    def __init__(self, **kwargs):
        super(OpSystemRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.last_get_name_result = None

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).wait(60)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to execute remote command")
        if not any(SCRIPT_STATUS_SUCCESS in line for line in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote op system operation")
        return res["output"]

    def request_os_restoration(self, os_name_to_restore):
        cmd = "cd {} && python ops.py -c restore -s {} -b {} -n {}".format(ATF_TOOLS_DIR, os_name_to_restore,
                                                                           self.bootp, self.host)
        stdout = self.remote_exec(cmd)
        for line in stdout:
            m = self.RE_ACTION.match(line)
            if m is not None:
                return m.group(1)
        raise Exception("Failed to obtain restore action or regexp is not matched")

    def get_name(self):
        # Check cached value first
        if self.last_get_name_result is not None \
                and timeit.default_timer() - self.last_get_name_call < \
                self.GET_NAME_CACHE_LIFETIME \
                and self.last_get_name_result != OS_UNKNOWN:
            return self.last_get_name_result
        cmd = "cd {} && python ops.py -c getname".format(ATF_TOOLS_DIR)
        stdout = self.remote_exec(cmd)
        for line in stdout:
            m = self.RE_OS_NAME.match(line)
            if m is not None:
                os_name = m.group(1)
                self.last_get_name_call = timeit.default_timer()
                if os_name in KNOWN_OSES:
                    self.last_get_name_result = os_name
                else:
                    self.last_get_name_result = OS_UNKNOWN
                return self.last_get_name_result
        raise Exception("Failed to obtain OS name or regexp is not matched")


class OsArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error(SCRIPT_STATUS_FAILED)
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = OsArgumentParser()
    parser.add_argument("-c", "--command", help="Command to be performed", type=str, required=True,
                        choices=["restore", "getname"])
    parser.add_argument("-s", "--system", help="Operating System name", choices=KNOWN_OSES, type=str)
    parser.add_argument("-b", "--bootp", help="Bootp server url", type=str)
    parser.add_argument("-n", "--name", help="Host name", type=str)
    args = parser.parse_args()

    try:
        if args.command == "restore":
            if args.system is None or args.bootp is None:
                log.error("To restore system its name and bootp must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            action = request_os_restoration(args.system, args.bootp, args.name)
            log.info("Action = {}".format(action))
        elif args.command == "getname":
            os_name = get_os_name()
            log.info("OS = {}".format(os_name))
    except Exception as exc:
        traceback.print_exc(limit=10, file=sys.stderr)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
