import argparse
import socket
from abc import abstractmethod, ABCMeta

from command import Command
from ops import OpSystem
from utils import get_atf_logger

SCRIPT_STATUS_SUCCESS = "[KILLER-SUCCESS]"
SCRIPT_STATUS_FAILED = "[KILLER-FAILED]"

log = get_atf_logger()


class Killer(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(KillerLocal)
        else:
            return object.__new__(KillerRemote)

    @abstractmethod
    def kill(self, app, excludes=None):
        pass


class KillerLocal(Killer):

    def kill(self, app, excludes=None):
        if excludes is not None and "grep" not in excludes:
            excludes.append("grep")
        else:
            excludes = ["grep"]
        op_sys = OpSystem()
        if op_sys.is_linux() or op_sys.is_mac() or op_sys.is_freebsd():
            cmd = "sudo kill -9 `ps -ef | grep -i \"{}\"".format(app)
            for e in excludes:
                cmd += " | grep -v \"{}\"".format(e)
            cmd += " | awk '{{print $2}}'`"
        elif op_sys.is_windows():
            pid_cmd = "powershell \"gwmi Win32_Process | select ProcessId,ParentProcessId,CommandLine | " \
                      "ft -AutoSize | Out-String -Width 4096\" | grep -i \"{}\"".format(app)
            for e in excludes:
                pid_cmd += " | grep -v \"{}\"".format(e)
            pid_cmd += " | awk '{{print $1}}'"
            res = Command(cmd=pid_cmd).wait(5)
            cmd = "taskkill -F -T"
            for pid in res["output"]:
                cmd += " -PID {}".format(pid.strip())
        else:
            cmd = "slay `pidin | grep -i {} | awk '{{print $1}}'`".format(app)

        res = Command(cmd=cmd).wait(5)
        if res["reason"] != Command.REASON_OK:
            raise Exception("Failed to kill application {}".format(app))


class KillerRemote(Killer):
    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).wait(30)
        if res["reason"] != Command.REASON_OK or not any(SCRIPT_STATUS_SUCCESS in line for line in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote killer operation")
        return res

    def __init__(self, **kwargs):
        super(KillerRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]

    def kill(self, app, excludes=None):
        if excludes is not None and "python" not in excludes:
            excludes.append("python")
        else:
            excludes = ["python"]
        self.remote_exec("cd qa-tests/tools && python killer.py -c kill -a {} -e {}".format(app, ",".join(excludes)))


class KillerArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error("\n{}\n".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = KillerArgumentParser()
    parser.add_argument("-c", "--command", help="Command to be performed", type=str, required=True, choices=["kill"])
    parser.add_argument("-a", "--app", help="Application name", type=str)
    parser.add_argument("-e", "--excludes", help="Exclude applications", type=str)
    args = parser.parse_args()

    try:
        if args.command == "kill":
            if not args.app:
                log.error("To kill application it's name must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            if args.excludes is not None:
                excludes = args.excludes.split(",")
            else:
                excludes = None
            Killer().kill(args.app, excludes)
    except Exception:
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
