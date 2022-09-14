import usb.core
import usb.util
import re
import argparse
from utils import get_atf_logger, get_win_usb_hw_ids

from abc import abstractmethod, ABCMeta
from constants import ATF_TOOLS_DIR
from command import Command

log = get_atf_logger()

SCRIPT_STATUS_SUCCESS = "[PACTOOL-SUCCESS]"
SCRIPT_STATUS_FAILED = "[PACTOOL-FAILED]"

BL = 0x0
MAC = 0x1

USB_CTRL_IN = 0xC0
USB_CTRL_OUT = 0x40


def readmacreg(reg, dev):
    reqType = USB_CTRL_IN
    bReq = MAC
    wVal = reg
    wIndex = 0x01
    data = 0x01
    r = dev.ctrl_transfer(reqType, bReq, wVal, wIndex, data)
    log.info("MAC register 0x{:02x} : 0x{:02x}".format(reg, r[0]))
    return r[0]


def writemacreg(reg, data, dev):
    reqType = USB_CTRL_OUT
    bReq = MAC
    wVal = reg
    wIndex = 0x01
    data = data
    r = dev.ctrl_transfer(reqType, bReq, wVal, wIndex, [data])


def readblreg(reg, dev):
    reqType = USB_CTRL_IN
    bReq = BL
    wVal = reg
    wIndex = 0x01
    data = 0x01
    r = dev.ctrl_transfer(reqType, bReq, wVal, wIndex, data)
    log.info("MAC register 0x{:02x} : 0x{:02x}".format(reg, r[0]))
    return r[0]


def writeblreg(reg, data, dev):
    reqType = USB_CTRL_OUT
    bReq = BL
    wVal = reg
    wIndex = 0x01
    data = data
    r = dev.ctrl_transfer(reqType, bReq, wVal, wIndex, [data])


def get_usb_dev(port):
    vid, did = get_win_usb_hw_ids(port)
    return usb.core.find(idVendor=int(vid, 16), idProduct=int(did, 16))


class PacificWrapper(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost":
            return object.__new__(PacificWrapperLocal)
        else:
            return object.__new__(PacificWrapperRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]
        self.dev = get_usb_dev(self.port)

    @abstractmethod
    def readmacreg(self, reg):
        pass

    @abstractmethod
    def writemacreg(self, reg, data):
        pass

    @abstractmethod
    def readblreg(self, reg):
        pass

    @abstractmethod
    def writeblreg(self, reg, data):
        pass


class PacificWrapperLocal(PacificWrapper):
    def __init__(self, **kwargs):
        super(PacificWrapperLocal, self).__init__(**kwargs)

    def readmacreg(self, reg):
        return readmacreg(reg, self.dev)

    def writemacreg(self, reg, data):
        log.info("Writing value 0x{:02x} to register 0x{:02x}".format(data, reg))
        return writemacreg(reg, data, self.dev)

    def readblreg(self, reg):
        return readblreg(reg, self.dev)

    def writeblreg(self, reg, data):
        log.info("Writing value 0x{:02x} to BL register 0x{:02x}".format(data, reg))
        return writeblreg(reg, data, self.dev)


class PacificWrapperRemote(PacificWrapper):
    def __init__(self, **kwargs):
        super(PacificWrapperRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.cmd_start = "cd {} && python pacaper.py -p {} ".format(ATF_TOOLS_DIR, self.port)

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).wait(30)
        if not any(SCRIPT_STATUS_SUCCESS in line for line in res["output"]) or res["returncode"] != 0 or \
                res["reason"] != Command.REASON_OK:
            log.error("Failed to execute command '{}' on host '{}', output:".format(cmd, self.host))
            log.debug("\n".join(["", "-" * 80] + res["output"] + ["-" * 80]))
            raise Exception("Failed to perform remote aeaaper operation")
        return res["output"]

    def readmacreg(self, reg):
        cmd = self.cmd_start + "-c  readmacreg -r 0x{:02x}".format(reg)
        output = self.remote_exec(cmd)
        re_reg_value = re.compile(".*0x[0-9a-z]+: (0x[0-9a-z]+).*", re.DOTALL)

        for line in output:
            m = re_reg_value.match(line)
            if m is not None:
                return int(m.group(1), 16)

        raise Exception("Failed to read register 0x{:02x} on host {}".format(reg, self.host))

    def writemacreg(self, reg, data):
        cmd = self.cmd_start + "-c  writemacreg -r 0x{:02x} -d 0x{:02x}".format(reg, data)
        self.remote_exec(cmd)

    def readblreg(self, reg):
        cmd = self.cmd_start + "-c  readblreg -r 0x{:02x}".format(reg)
        output = self.remote_exec(cmd)
        re_reg_value = re.compile(".*0x[0-9a-z]+: (0x[0-9a-z]+).*", re.DOTALL)

        for line in output:
            m = re_reg_value.match(line)
            if m is not None:
                return int(m.group(1), 16)

        raise Exception("Failed to read register 0x{:02x} on host {}".format(reg, self.host))

    def writeblreg(self, reg, data):
        cmd = self.cmd_start + "-c  writeblreg -r 0x{:02x} -d 0x{:02x}".format(reg, data)
        self.remote_exec(cmd)


class PacToolArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("{}".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    try:
        parser = PacToolArgumentParser()
        parser.add_argument("-p", "--port", type=str, required=True,
                            help="Connection port, ex: usb0.0019.0001")
        parser.add_argument("-c", "--command", type=str, required=True, help="Command to be performed",
                            choices=["readmacreg", "writemacreg", "readblreg", "writeblreg"])

        parser.add_argument("-r", "--reg", type=str, help="Register to write/read")
        parser.add_argument("-d", "--data", help="Data to write")

        args = parser.parse_args()
    except Exception:
        log.exception("Failed to parse pactool arguments")
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    try:
        pacaper = PacificWrapper(port=args.port)

        if args.command == "readmacreg":
            if not args.port or not args.reg:
                log.error("To read registers, port and adress should be provided")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            res = pacaper.readmacreg(int(args.reg, 16))
            log.info("Register 0x{:02x}: 0x{:02x}".format(args.reg, res))

        if args.command == "writemacreg":
            if not args.port or not args.reg or not args.data:
                log.error("To write registers, port and adress and data should be provided")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            res = pacaper.writemacreg(int(args.reg, 16), int(args.data, 16))

        if args.command == "readblreg":
            if not args.port or not args.reg:
                log.error("To read BL registers, port and adress should be provided")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            res = pacaper.readblreg(int(args.reg, 16))
            log.info("BL Register 0x{:02x}: 0x{:02x}".format(args.reg, res))

        if args.command == "writeblreg":
            if not args.port or not args.reg or not args.data:
                log.error("To write BL registers, port and adress and data should be provided")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            res = pacaper.writeblreg(int(args.reg, 16), int(args.data, 16))

    except Exception as exc:
        traceback.print_exc(limit=10, file=sys.stderr)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
