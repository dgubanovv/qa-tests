import argparse
import os
import socket
import sys
import subprocess
from abc import abstractmethod, ABCMeta

from command import Command
from constants import ATF_TOOLS_DIR
from utils import get_atf_logger

SCRIPT_STATUS_SUCCESS = "[POWER-SUCCESS]"
SCRIPT_STATUS_FAILED = "[POWER-FAILED]"

log = get_atf_logger()


def is_standby_available():
    if sys.platform == "win32":
        cmd = "powercfg -a"
        stdout = subprocess.check_output(cmd, shell=True)
        not_available_str = "The following sleep states are not available on this system:"
        not_available_pos = stdout.find(not_available_str)
        standby_pos = stdout.find("Standby (S3)")
        if standby_pos < not_available_pos:
            return True
        else:
            return False
    else:
        raise NotImplementedError("The functionality is not implemented")


def standby():
    if sys.platform == "win32":
        hibernate_off()

        if is_standby_available():
            os.system("rundll32.exe powrprof.dll,SetSuspendState Standby")
        else:
            raise Exception("Standby is not available on this system")
    else:
        raise NotImplementedError("The functionality is not implemented")


def hibernate():
    if sys.platform == "win32":
        os.system("powercfg /h on")
        os.system("powercfg /h /type full")
        os.system("powercfg /h /size 50")
        os.system("shutdown /h /f")
    elif sys.platform == "darwin":
        os.system("sudo pmset sleepnow")
    else:
        os.system("sudo systemctl hibernate")


def hibernate_off():
    if sys.platform == "win32":
        os.system("powercfg -h off")
    else:
        raise NotImplementedError("The functionality is not implemented")


def shutdown():
    if sys.platform == "win32":
        os.system("shutdown -s -t 0 -f")
    elif sys.platform == "darwin":
        os.system("sudo shutdown -h +0")
    else:
        os.system("sudo shutdown -P now")


def suspend():
    if "linux" in sys.platform:
        os.system("sudo systemctl suspend")
    elif sys.platform == "win32":
        os.system("RUNDLL32.EXE powrprof.dll,SetSuspendState 0,1,0")
    else:
        raise NotImplementedError("The functionality is not implemented")


def reboot():
    if sys.platform == "win32":
        os.system("shutdown -r -t 0 -f")
    else:
        os.system("sudo reboot")


class Power(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(PowerLocal)
        else:
            return object.__new__(PowerRemote)

    @abstractmethod
    def is_standby_available(self):
        pass

    @abstractmethod
    def standby(self):
        pass

    @abstractmethod
    def hibernate(self):
        pass

    @abstractmethod
    def hibernate_off(self):
        pass

    @abstractmethod
    def shutdown(self):
        pass

    @abstractmethod
    def suspend(self):
        pass

    @abstractmethod
    def reboot(self):
        pass


class PowerLocal(Power):
    def is_standby_available(self):
        return is_standby_available()

    def standby(self):
        log.info("Putting machine to Standby mode")
        standby()

    def hibernate(self):
        log.info("Hibernating machine")
        hibernate()

    def hibernate_off(self):
        log.info("Turning off hibernation on machine")
        hibernate_off()

    def shutdown(self):
        log.info("Shutting down machine")
        shutdown()

    def suspend(self):
        log.info("Suspending machine")
        suspend()

    def reboot(self):
        log.info("Rebooting machine")
        reboot()


class PowerRemote(Power):
    def __init__(self, **kwargs):
        super(PowerRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).wait(60)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to execute remote command")
        if not any(SCRIPT_STATUS_SUCCESS in line for line in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote power operation")
        return res["output"]

    def remote_exec_no_wait(self, cmd):
        Command(cmd=cmd, host=self.host).run_async()

    def is_standby_available(self):
        cmd = "cd {} && python power.py -c getstandbyavailable".format(ATF_TOOLS_DIR)
        stdout = self.remote_exec(cmd)
        if any("True" in line for line in stdout):
            return True
        else:
            return False

    def standby(self):
        log.info("Putting machine {} to Standby mode".format(self.host))
        cmd = "cd {} && python power.py -c standby".format(ATF_TOOLS_DIR)
        self.remote_exec_no_wait(cmd)

    def hibernate(self):
        log.info("Hibernating machine {}".format(self.host))
        cmd = "cd {} && python power.py -c hibernate".format(ATF_TOOLS_DIR)
        self.remote_exec_no_wait(cmd)

    def hibernate_off(self):
        log.info("Turning off hibernation on machine {}".format(self.host))
        cmd = "cd {} && python power.py -c hibernateoff".format(ATF_TOOLS_DIR)
        self.remote_exec(cmd)

    def shutdown(self):
        log.info("Shutting down machine {}".format(self.host))
        cmd = "cd {} && python power.py -c shutdown".format(ATF_TOOLS_DIR)
        self.remote_exec_no_wait(cmd)

    def suspend(self):
        log.info("Suspending machine {}".format(self.host))
        cmd = "cd {} && python power.py -c suspend".format(ATF_TOOLS_DIR)
        self.remote_exec_no_wait(cmd)

    def reboot(self):
        log.info("Rebooting machine {}".format(self.host))
        cmd = "cd {} && python power.py -c reboot".format(ATF_TOOLS_DIR)
        self.remote_exec_no_wait(cmd)


class PowerArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error(SCRIPT_STATUS_FAILED)
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = PowerArgumentParser()
    parser.add_argument("-c", "--command", help="Command to be performed",
                        choices=["getstandbyavailable", "standby", "hibernate", "shutdown", "reboot", "hibernateoff", "suspend"],
                        type=str, required=True)
    args = parser.parse_args()

    try:
        if args.command == "hibernate":
            hibernate()
        elif args.command == "hibernateoff":
            hibernate_off()
        elif args.command == "shutdown":
            shutdown()
        elif args.command == "reboot":
            reboot()
        elif args.command == "standby":
            standby()
        elif args.command == "suspend":
            suspend()
        elif args.command == "getstandbyavailable":
            log.info(is_standby_available())
    except Exception as e:
        log.exception("Power failed")
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
