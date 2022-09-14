import argparse
import os
import re
import socket
import sys
import warnings

from abc import abstractmethod, ABCMeta

import constants

from command import Command
from utils import get_atf_logger, get_bus_dev_func, SpacedArgAction

USE_AEAA_WRAPPER = True

log = get_atf_logger()

# ----------------------------------------Import pactool---------------------------------------- #
if sys.platform == "win32":
    WHERE_PACTOOL = os.path.dirname(Command(cmd="where pactool.pyd").run()["output"][0].rstrip())
elif sys.platform == "darwin":
    WHERE_PACTOOL = "/dos/qa/macos/fwtools"
else:
    # TODO: hardcoded for now
    WHERE_PACTOOL = "/x/qa/linux/fwtools"
# Add path to python import search directories
sys.path.append(WHERE_PACTOOL)

if sys.platform != "darwin":
    import pactool

# ----------------------------------------Import pactool---------------------------------------- #

SCRIPT_STATUS_SUCCESS = "[PACTOOL-SUCCESS]"
SCRIPT_STATUS_FAILED = "[PACTOOL-FAILED]"
RE_DEVICE_USB_LIST = "Device [a-zA-Z0-9]+:[a-zA-Z0-9]+ .*bus {}, device ([0-9]+).* path: {}"

CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS = 0x61
CAPS_AQ_USB_VENDOR_CMD_SLEEP_PROXY = 0x60
CAPS_AQ_USB_VENDOR_CMD_LINK_STATUS = 0x35

CAPS_USB_LINK_SPEED = {
    constants.LINK_SPEED_NO_LINK: 0x0,
    constants.LINK_SPEED_100M: 0x1,
    constants.LINK_SPEED_1G: 0x2,
    constants.LINK_SPEED_2_5G: 0x4,
    constants.LINK_SPEED_5G: 0x8,
    constants.LINK_SPEED_AUTO: 0xf,
}

CAPS_USB_LINK_SPEED_TO_MBITS = {
    0x13: constants.LINK_SPEED_100M,
    0x11: constants.LINK_SPEED_1G,
    0x10: constants.LINK_SPEED_2_5G,
    0xf: constants.LINK_SPEED_5G,
}

USB_PAUSE = 0x1
USB_ASYMMETRIC_PAUSE = 0x2
USB_LOW_POWER = 0x4
USB_POWER = 0x8
USB_SLEEP_PROXY = 0x10


def auto_int(n):
    return int(n, 0)


class PacTool(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(PacToolLocal)
        else:
            return object.__new__(PacToolRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]

    @abstractmethod
    def readreg(self, reg):
        pass

    @abstractmethod
    def writereg(self, reg, value):
        pass

    @abstractmethod
    def readphyreg(self, mmd, reg):
        pass

    @abstractmethod
    def writephyreg(self, mmd, reg, value):
        pass

    @abstractmethod
    def control_transfer_in(self):
        pass

    @abstractmethod
    def control_transfer_out(self):
        pass

    @abstractmethod
    def set_link_speed(self):
        pass

    @abstractmethod
    def get_link_speed(self):
        pass


class PacToolLocal(PacTool):
    # REGEXP_CAPS_PHY_OPTS = re.compile(r".*([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+).*", re.DOTALL)

    def __init__(self, **kwargs):
        super(PacToolLocal, self).__init__(**kwargs)
        bus, dev, func = get_bus_dev_func(self.port)
        self.usbutil_port = "{:X}:{:X}".format(int(dev), int(func))
        with warnings.catch_warnings(record=True) as w:
            self.device_number = pactool.open_device(self.usbutil_port)
            if len(w) > 0 and next("Failed to detect PHY ID" in str(wrn.message) for wrn in w):
                self.phy_id_detected = False
            else:
                self.phy_id_detected = True

    def __del__(self):
        if pactool and hasattr(self, "device_number"):
            pactool.close_device(self.device_number)

    def readreg(self, reg):
        val = pactool.readreg(self.device_number, reg)
        log.info("Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
            reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))
        return val

    def writereg(self, reg, value):
        pactool.writereg(self.device_number, reg, value)
        log.info("Register 0x{:08x}: 0x{:08x} written".format(reg, value))

    def readphyreg(self, mmd, reg):
        val = pactool.readphyreg(self.device_number, mmd, reg)
        log.info("Register PHY 0 0x{:x}.0x{:x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
            mmd, reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))
        return val

    def writephyreg(self, mmd, reg, value):
        pactool.writephyreg(self.device_number, mmd, reg, value)
        log.info("Register PHY 0 0x{:x}.0x{:x}: 0x{:08x} written".format(mmd, reg, value))

    def control_transfer_in(self, vendor_cmd, size):
        val = pactool.control_transfer_in(self.device_number, vendor_cmd, size)
        log.info("Transfer from device: {}".format(val))
        return val

    def control_transfer_out(self, vendor_cmd, data, size):
        if size is None:
            size = len(data)
        pactool.control_transfer_out(self.device_number, vendor_cmd, data, size)
        log.info("Transfer data = {} to device using vendor command {}".format(data, vendor_cmd))

    def set_link_speed(self, speed, eee=False):
        log.info("Setting speed: {}".format(speed))
        data = self.control_transfer_in(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, size=4)
        data[0] = CAPS_USB_LINK_SPEED[speed]
        self.control_transfer_out(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_PHY_OPTS, data=data, size=4)

    def get_link_speed(self):
        log.info("Getting speed...")
        data = self.control_transfer_in(vendor_cmd=CAPS_AQ_USB_VENDOR_CMD_LINK_STATUS, size=2)
        speed = CAPS_USB_LINK_SPEED_TO_MBITS.get(data[0] & 0x7f, constants.LINK_SPEED_NO_LINK)
        log.info("Current link rate: {}".format(speed))
        return speed


class PacToolRemote(PacTool):
    RE_READREG = re.compile(r".*Register 0x[0-9A-Fa-f]+: (0x[0-9A-Fa-f]+) : [01 ]+", re.DOTALL)
    RE_READPHYREG = re.compile(r".*Register PHY [0-9-]+ 0x[0-9A-Fa-f]+.0x[0-9A-Fa-f]+: (0x[0-9A-Fa-f]+) : [01 ]+",
                               re.DOTALL)
    RE_CONTROL_TRANSFER_IN = re.compile(r".*Transfer: ([[0-9]+, [0-9]+, [0-9]+, [0-9]+])", re.DOTALL)
    RE_SPEED = re.compile(r".*Current link rate: (.+)", re.DOTALL)

    def __init__(self, **kwargs):
        super(PacToolRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.cmd_start = "cd {} && sudo python pactoolper.py -p {} ".format(constants.ATF_TOOLS_DIR, self.port)

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).run()
        if res["returncode"] != 0 or not any(SCRIPT_STATUS_SUCCESS in s for s in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote pactool operation")
        return res["output"]

    def readreg(self, reg):
        cmd = self.cmd_start + "-c readreg -r 0x{:x}".format(reg)
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_READREG.match(line)
            if m is not None:
                return int(m.group(1), 0)
        raise Exception("Failed to do remote readreg command")

    def writereg(self, reg, value):
        cmd = self.cmd_start + "-c writereg -r 0x{:x} -v 0x{:x}".format(reg, value)
        self.remote_exec(cmd)

    def readphyreg(self, mmd, reg):
        cmd = self.cmd_start + "-c readphyreg -r 0x{:x} 0x{:x}".format(mmd, reg)
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_READPHYREG.match(line)
            if m is not None:
                return int(m.group(1), 0)
        raise Exception("Failed to do remote readphyreg command")

    def writephyreg(self, mmd, reg, value):
        cmd = self.cmd_start + "-c writephyreg -r 0x{:x} 0x{:x} -v 0x{:x}".format(mmd, reg, value)
        self.remote_exec(cmd)

    def control_transfer_in(self, vendor_cmd, size):
        cmd = self.cmd_start + "-c control_transfer_in -cmd {} -s {}".format(vendor_cmd, size)
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_CONTROL_TRANSFER_IN.match(line)
            if m is not None:
                return m.group(1)
        raise Exception("Failed to do remote control_transfer_in command")

    def control_transfer_out(self, vendor_cmd, data, size):
        cmd = self.cmd_start + '-c control_transfer_out -cmd {} -d "{}"'.format(vendor_cmd, data)
        self.remote_exec(cmd)

    def set_link_speed(self, speed, eee=False):
        arguments = {
            "speed": speed
        }
        cmd = self.cmd_start + "-c set_link_speed -a \"{}\"".format(arguments)
        self.remote_exec(cmd)

    def get_link_speed(self):
        cmd = self.cmd_start + "-c get_link_speed"
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_SPEED.match(line)
            if m is not None:
                return m.group(1)
        raise Exception("Failed to do remote getlinkspeed command")


class PactoolArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("{}".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = PactoolArgumentParser()
    parser.add_argument("-p", "--port", help="PCI port, i.e. pci1.00.0, ...", type=str, required=True)
    parser.add_argument("-c", "--command", help="Command to be performed", type=str, required=True,
                        choices=["readreg",
                                 "writereg",
                                 "readphyreg",
                                 "writephyreg",
                                 "kickstart",
                                 "control_transfer_in",
                                 "control_transfer_out",
                                 "set_link_speed",
                                 "get_link_speed"])
    parser.add_argument("-r", "--register", help="MAC (1 integer) or PHY (2 integers) register", nargs="+",
                        type=auto_int)
    parser.add_argument("-v", "--value", help="Integer value (i.e. to write to register or memory address)",
                        type=auto_int)
    parser.add_argument("-cmd", "--vendor_cmd", help="Integer value of vendor command (i.e. 97 for AQ_USB_VENDOR_CMD_PHY_OPTS)",
                        type=auto_int)
    parser.add_argument("-d", "--data", help="Bit values, i.e. [2,0,0,4] for size = 4 bits", type=str,
                        action=SpacedArgAction, nargs="+")
    parser.add_argument("-s", "--size", help="Size in bytes", type=auto_int)
    parser.add_argument("-a", "--arguments", help="Additional arguments for command", type=str, action=SpacedArgAction,
                        nargs="+")

    args = parser.parse_args()

    try:
        pactool_wrapper = PacTool(port=args.port)

        if args.command == "readreg":
            if args.register is not None and len(args.register) == 1:
                pactool_wrapper.readreg(args.register[0])
            else:
                log.error("To read MAC register, it must be specified (1 int number)")
                log.info(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "writereg":
            if args.register is not None and len(args.register) == 1 and args.value is not None:
                pactool_wrapper.writereg(args.register[0], args.value)
            else:
                log.error("To write MAC register, register (1 int number) and value must be specified")
                log.info(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "readphyreg":
            if args.register is not None and len(args.register) == 2:
                pactool_wrapper.readphyreg(args.register[0], args.register[1])
            else:
                log.error("To read PHY register, it must be specified (2 int numbers)")
                log.info(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "writephyreg":
            if args.register is not None and len(args.register) == 2 and args.value is not None:
                pactool_wrapper.writephyreg(args.register[0], args.register[1], args.value)
            else:
                log.error("To write PHY register, register (2 int numbers) and value must be specified")
                log.info(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "control_transfer_in":
            if args.vendor_cmd is not None and args.size is not None:
                pactool_wrapper.control_transfer_in(args.vendor_cmd, args.size)
            else:
                log.error("To perform , register (2 int numbers) and value must be specified")
                log.info(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "control_transfer_out":
            if args.vendor_cmd is not None and args.data is not None:
                pactool_wrapper.control_transfer_out(args.vendor_cmd, eval(args.data), args.size)
            else:
                log.error("To perform , register (2 int numbers) and value must be specified")
                log.info(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "set_link_speed":
            if args.arguments is not None:
                arguments = eval(args.arguments)
            else:
                arguments = {}
            pactool_wrapper.set_link_speed(**arguments)
        elif args.command == "get_link_speed":
            pactool_wrapper.get_link_speed()

    except Exception:
        log.exception(SCRIPT_STATUS_FAILED)
        log.info(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
