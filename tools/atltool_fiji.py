import argparse
import socket
import sys
import re
from abc import abstractmethod, ABCMeta

from command import Command
import constants
from utils import get_atf_logger
if sys.platform == "win32":
    import wmi


log = get_atf_logger()


SCRIPT_STATUS_SUCCESS = "[ATLTOOLFIJI-SUCCESS]"
SCRIPT_STATUS_FAILED = "[ATLTOOLFIJI-FAILED]"


def auto_int(n):
    return int(n, 0)


class AtlToolFiji(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(AtlToolFijiLocal)
        else:
            return object.__new__(AtlToolFijiRemote)

    @abstractmethod
    def readregs(self, reg, count=1):
        pass

    def readreg(self, reg):
        pass


class AtlToolFijiLocal(AtlToolFiji):
    def __init__(self, **kwargs):
        self.wmi_adatper_obj = wmi.WMI(namespace='root/wmi').Aq_UsbNetAdapter()

    def readregs(self, reg, count=1):
        val = self.wmi_adatper_obj[0].ReadReg(count, reg)[0]
        log.info("REGISTERS: {}".format(val))
        return val

    def readreg(self, reg):
        val = self.wmi_adatper_obj[0].ReadReg(1, reg)[0]
        log.info("REGISTERS: {}".format(val))
        return val[0]


class AtlToolFijiRemote(AtlToolFiji):
    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).run()
        if res["returncode"] != 0 or not any(SCRIPT_STATUS_SUCCESS in s for s in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote atltool operation")
        return res["output"]

    def __init__(self, **kwargs):
        super(AtlToolFijiRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.cmd_start = "cd {} && sudo python atltool_fiji.py ".format(constants.ATF_TOOLS_DIR)

    def readregs(self, reg, count=1):
        cmd = self.cmd_start + "-c readregs -r 0x{:08x} -b {}".format(reg, count)
        output = self.remote_exec(cmd)
        for line in output:
            if "REGISTERS:" in line:
                reg = re.findall(r"\[(.*?)\]", line)
                return eval(reg[0])
        raise Exception("Failed to do remote readregs command")

    def readreg(self, reg):
        cmd = self.cmd_start + "-c readreg -r 0x{:08x}".format(reg)
        output = self.remote_exec(cmd)
        for line in output:
            if "REGISTERS:" in line:
                reg = re.findall(r"\[(.*?)\]", line)
                return eval(reg[0])
        raise Exception("Failed to do remote readreg command")


class AtlToolFijiArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("{}".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = AtlToolFijiArgumentParser()
    parser.add_argument("-c", "--command", help="Command to be performed", type=str, required=True,
                        choices=["readreg"])
    parser.add_argument("-r", "--register", help="Enter register", type=auto_int, required=True)
    parser.add_argument("-b", "--byte_count", help="Number of bytes actually read", type=int)

    args = parser.parse_args()

    try:
        atltool_fiji_wrapper = AtlToolFiji()

        if args.command == "readreg":
            atltool_fiji_wrapper.readreg(args.register)
        if args.command == "readregs":
            if args.byte_count is not None:
                atltool_fiji_wrapper.readregs(args.register, args.byte_count)
            else:
                raise Exception()

    except Exception:
        log.exception(SCRIPT_STATUS_FAILED)
        log.info(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
