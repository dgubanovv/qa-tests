import os
import shutil
import time
import timeit
import argparse
import socket
import re
import serial

import pytest

from command import Command
from abc import abstractmethod, ABCMeta
from atltoolper import AtlTool
from constants import LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_AUTO, LINK_STATE_DOWN, \
    LINK_STATE_UP, ATF_TOOLS_DIR
from utils import get_atf_logger

SCRIPT_STATUS_SUCCESS = "[LOM-SUCCESS]"
SCRIPT_STATUS_FAILED = "[LOM-FAILED]"


def auto_int(n):
    return int(n, 0)


log = get_atf_logger()


class LOM(object):
    # abstract base class for LOM operations
    # inheritors must implement read and write methods
    LOM_OFFSET_MAC_ADDRESS = [0, 0, 0, 0, 0, 0]
    LOM_OFFSET_ARP_IP_ADDRESS = [0, 0, 0, 0]
    LOM_OFFSET_RX_LEN = [0, 0]
    LOM_OFFSET_TX_LEN = [0, 0]

    LOM_OFFSET_WHO_AM_I = 0x0
    LOM_OFFSET_FW_VERSION = 0x1
    LOM_OFFSET_LOM_STATUS = 0x2
    LOM_OFFSET_INT_STATUS = 0x3
    LOM_OFFSET_LINK_STATUS = 0x4
    LOM_OFFSET_MAC_ADDRESS[0] = 0x5
    LOM_OFFSET_MAC_ADDRESS[1] = 0x6
    LOM_OFFSET_MAC_ADDRESS[2] = 0x7
    LOM_OFFSET_MAC_ADDRESS[3] = 0x8
    LOM_OFFSET_MAC_ADDRESS[4] = 0x9
    LOM_OFFSET_MAC_ADDRESS[5] = 0xA
    LOM_OFFSET_ARP_IP_ADDRESS[0] = 0x10
    LOM_OFFSET_ARP_IP_ADDRESS[1] = 0x11
    LOM_OFFSET_ARP_IP_ADDRESS[2] = 0x12
    LOM_OFFSET_ARP_IP_ADDRESS[3] = 0x13
    LOM_OFFSET_RX_LEN[0] = 0x200
    LOM_OFFSET_RX_LEN[1] = 0x201
    LOM_OFFSET_START_RX_PACKET_DATA = 0x202
    LOM_OFFSET_TX_LEN[0] = 0xA00
    LOM_OFFSET_TX_LEN[1] = 0xA01
    LOM_OFFSET_START_TX_PACKET_DATA = 0xA02

    def __init__(self, **kwargs):
        pass

    def read_data(self, offset, size=1):
        raise NotImplementedError

    def write_data(self, offset, values, size=1):
        raise NotImplementedError

    def LoM_enable(self):
        self.write_data(self.LOM_OFFSET_LOM_STATUS, [self.get_lom_status() | 0x1])

    def LoM_disable(self):
        self.write_data(self.LOM_OFFSET_LOM_STATUS, [self.get_lom_status() & 0xFE])
    
    def enable_arp(self):
        self.write_data(self.LOM_OFFSET_LOM_STATUS, [self.get_lom_status() | 0x02])

    def disable_arp(self):
        self.write_data(self.LOM_OFFSET_LOM_STATUS, [self.get_lom_status() & 0xFD])

    def get_lom_status(self):
        return self.read_data(self.LOM_OFFSET_LOM_STATUS)[0]

    def get_int_status(self):
        return self.read_data(self.LOM_OFFSET_INT_STATUS)[0]

    def get_link_status(self):
        return self.read_data(self.LOM_OFFSET_LINK_STATUS)[0]

    def enable_mcast_mac0(self):
        self.write_data(self.LOM_OFFSET_LOM_STATUS, [self.get_lom_status() | 0x04])

    def disable_mcast_mac0(self):
        self.write_data(self.LOM_OFFSET_LOM_STATUS, [self.get_lom_status() & 0xFB])

    def enable_mcast_mac1(self):
        self.write_data(self.LOM_OFFSET_LOM_STATUS, [self.get_lom_status() | 0x08])

    def disable_mcast_mac1(self):
        self.write_data(self.LOM_OFFSET_LOM_STATUS, [self.get_lom_status() & 0xF7])

    def enable_mcast_mac2(self):
        self.write_data(self.LOM_OFFSET_LOM_STATUS, [self.get_lom_status() | 0x10])

    def disable_mcast_mac2(self):
        self.write_data(self.LOM_OFFSET_LOM_STATUS, [self.get_lom_status() & 0xEF])

    def set_lom_mac_address(self, mac):
        mac_bytes = map(lambda x: int(x, 16), mac.split(':'))
        if 6 != len(mac_bytes):
            raise Exception("Incorrect MAC address format")
        self.write_data(self.LOM_OFFSET_MAC_ADDRESS[0], mac_bytes, size=len(mac_bytes))

    def set_lom_ip_address(self, ip):
        ip_bytes = map(lambda x: int(x), ip.split('.'))
        if 4 != len(ip_bytes):
            raise Exception("Incorrect format of IP address")
        self.write_data(self.LOM_OFFSET_ARP_IP_ADDRESS[0], ip_bytes, size=len(ip_bytes))

    @staticmethod
    def _hex_format(data):
        return "-".join("{:02X}".format(b) for b in data)


class LightsOutManagement(LOM):
    # This class should be used in tests - it automatically detects which interface to use:
    # mailbox, smbus or remote
    host = None
    port = None
    serial_port = None

    LOM_IP_ADDRESS = '10.20.30.40'
    LOM_MAC_ADDRESS = 'AC:10:DD:CC:BB:AA'

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        port = kwargs.get("port", None)
        serial_port = kwargs.get("serial_port", None)
        if serial_port:
            return object.__new__(LOMSmbus)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(LOMMailbox)
        else:
            return object.__new__(LOMRemote)

    def __init__(self, **kwargs):
        super(LightsOutManagement, self).__init__(**kwargs)
        self.host = kwargs.get("host", None)
        self.port = kwargs.get("port", None)
        self.serial_port = kwargs.get("serial_port", None)


class LOMSmbus(LightsOutManagement):
    def __init__(self, **kwargs):
        super(LOMSmbus, self).__init__(**kwargs)

    def write_data(self, offset, values, size=1):
        with serial.Serial(self.serial_port, 115200, timeout=3) as ser:
            ser.write([b'w', 5 + size, 0x32, 0x24, 2 + size, offset >> 8, offset & 0xFF] + values)
        log.info('>>> Written {} bytes of data to {} offset: {}'.format(size, hex(offset), values))

    def read_data(self, offset, size=1):
        log.info('<<< Reading {} bytes of data from {} offset'.format(size, hex(offset)))
        with serial.Serial(self.serial_port, 115200, timeout=3) as ser:
            w = ser.write([b's', 5, 0x32, 0x24, 0x02, offset >> 8, offset & 0xFF])
            q = ser.write([b'r', 0x32, 1 + size])
            r = ser.read(1 + size)
            assert len(r), "Error reading SMBus data"
            assert bytearray(r)[0] == 0x1F, "Error reading SMBus data"
            result = list(bytearray(r)[1:])
            log.info("HEX data: {}".format(self._hex_format(result)))
            log.info("Linearized data: {}".format(result))
            return result


class LOMMailbox(LightsOutManagement):
    DATA_REG_ADDR = 0x328
    MAILBOX_STATUS_ADDR = 0x33c
    MAILBOX_CONTROL_ADDR = 0x338
    MEM_ADDR_REG = 0x334

    OFFSET_REG_ADDR = 0x32C
    APPLY_REG_ADDR = 0x404
    APPLY_REG_VAL = 0x2

    LOM_OFFSET_FIXED_SHIFT = 0x80000000

    def __init__(self, **kwargs):
        super(LOMMailbox, self).__init__(**kwargs)
        self.dut_atltool_wrapper = AtlTool(port=self.port, host=self.host)

    def _wait_mailbox(self, time_limit):
        # Poll status register till mailbox complete tasks
        limit = timeit.default_timer() + time_limit
        while (timeit.default_timer() < limit):
            if self.dut_atltool_wrapper.readreg(self.MAILBOX_STATUS_ADDR) == self.dut_atltool_wrapper.readreg(
                    self.MAILBOX_CONTROL_ADDR):
                return 0
            time.sleep(0.1)
        return 1

    def read_data(self, offset, size=1):
        def _linearize(input_data):
            result = []
            for i in input_data:
                result.append((i >> 0x0) & 0xFF)
                result.append((i >> 0x8) & 0xFF)
                result.append((i >> 0x10) & 0xFF)
                result.append((i >> 0x18) & 0xFF)
            log.info("HEX data: {}".format(self._hex_format(result[1:])))
            log.info("Linearized data: {}".format(result[1:]))
            return result

        # offset - mem offset; Value - value to write; size - data size in BYTES
        log.info('<<< Reading {} bytes of data from {} offset'.format(size, hex(offset)))
        data = [0x100]
        data.append(((size + 4) << 1) + 0)
        data.append(((offset & 0xFF) << 0x18) | ((offset & 0xFF00) << 0x8) | 0x0224)

        for i in range(3):
            self.dut_atltool_wrapper.writereg(self.DATA_REG_ADDR, data[i])
            self.dut_atltool_wrapper.writereg(self.OFFSET_REG_ADDR, self.LOM_OFFSET_FIXED_SHIFT + (i * 4))
            self.dut_atltool_wrapper.writereg(self.APPLY_REG_ADDR, self.APPLY_REG_VAL)

        # Unlock mailbox
        self.dut_atltool_wrapper.writereg(self.MAILBOX_CONTROL_ADDR,
                                          self.dut_atltool_wrapper.readreg(self.MAILBOX_STATUS_ADDR) + 1)

        if 0 != self._wait_mailbox(3):
            raise Exception("Mailbox is busy")

        buf_addr = self.dut_atltool_wrapper.readreg(self.MEM_ADDR_REG)
        memory_data = self.dut_atltool_wrapper.readmem(buf_addr + 8, size + 1)
        return _linearize(memory_data)[1:size+1]

    def write_data(self, offset, values, size=1):
        # TODO: write several bytes as one transaction
        # offset - mem offset; Value - value to write; size - data size in BYTES
        def _write_byte(offset, value):
            data = [0x100]
            data.append(((1 + 4) << 1) + 1)
            data.append(((offset & 0xFF) << 0x18) | ((offset & 0xFF00) << 0x8) | ((1 + 2) << 8) | 0x24)
            data.append(value)

            for i in range((1 // 4) + 4):
                self.dut_atltool_wrapper.writereg(self.DATA_REG_ADDR, data[i])
                self.dut_atltool_wrapper.writereg(self.OFFSET_REG_ADDR, self.LOM_OFFSET_FIXED_SHIFT + (i * 4))
                self.dut_atltool_wrapper.writereg(self.APPLY_REG_ADDR, self.APPLY_REG_VAL)

            # Unlock mailbox
            self.dut_atltool_wrapper.writereg(self.MAILBOX_CONTROL_ADDR,
                                              self.dut_atltool_wrapper.readreg(self.MAILBOX_STATUS_ADDR) + 1)

            if 0 != self._wait_mailbox(3):
                raise Exception("Mailbox is busy")

        log.info('>>> Written {} bytes of data to {} offset: {}'.format(size, hex(offset), values))
        for b in range(size):
            _write_byte(offset+b, values[b])


class LOMRemote(LightsOutManagement):
    # class to use LOM mailbox on remote host
    # commands are executed via lom.py cmd interface
    RE_READMEM = re.compile(r".*Linearized data: \[(.+)\]", re.DOTALL)

    def __init__(self, **kwargs):
        super(LOMRemote, self).__init__(**kwargs)
        self.cmd_start = "cd {} && sudo python lom.py -p {} ".format(ATF_TOOLS_DIR, self.port)

    def remote_exec(self, cmd, silent=False):
        res = Command(cmd=cmd, host=self.host, silent=silent).run()
        log.info("Code: {}".format(res["returncode"]))
        if res["returncode"] != 0 or not any(SCRIPT_STATUS_SUCCESS in s for s in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote atltool operation")
        return res["output"]

    def exec_async(self, cmd, timeout=None):
        self.command = Command(cmd=cmd, host=self.host, timeout=timeout)
        self.command.run_async()
        return self

    def exec_join(self, timeout=None):
        return self.command.join(timeout)

    def read_data(self, offset, size=1):
        cmd = self.cmd_start + "-c read --offset 0x{:x} --size {}".format(offset, size)
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_READMEM.match(line)
            if m is not None:
                res = []
                tmp_str = ''
                for i in m.group(1).split('L'):
                    tmp_str = i.lstrip(', ')
                    if tmp_str != '':
                        res.append(int(tmp_str, base=0))
                return res
        raise Exception("Failed to do remote readreg command")

    def write_data(self, offset, values, size=1):
        v_txt = '"'
        for v in values:
            v_txt += str(v)
            v_txt += ' '
        v_txt = v_txt[:-1] + '"'
        cmd = self.cmd_start + '-c write --offset 0x{:x} --values {}'.format(offset, v_txt)
        self.remote_exec(cmd)


class LOMArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("{}".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = LOMArgumentParser()
    parser.add_argument("-p", "--port", help="PCI port, i.e. pci1.00.0, ...", type=str)
    parser.add_argument("-s", "--serial_port", help="Serial port with Arduino, i.e. /dev/ttyACM0", type=str)
    parser.add_argument("-c", "--command", help="Command to be performed", type=str, required=True,
                        choices=["read",
                                 "write",
                                 "setmac",
                                 "setip",
                                 "enable",
                                 "disable",
                                 "mdio_on",
                                 "mdio_off"])
    parser.add_argument("--mac", help="MAC address, i.e. AA:BB:CC:DD:EE:FF", type=str)
    parser.add_argument("--ip", help="IP address, i.e. 192.168.101.202", type=str)
    parser.add_argument("--offset", help="Offset value", type=auto_int)
    parser.add_argument("--values", help="Values", type=str)
    parser.add_argument("--size", help="Size of data in bytes", type=auto_int)
    args = parser.parse_args()

    if not args.port and not args.serial_port:
        raise Exception("PCI Port or Serial Port must be set")

    try:
        lom_wrapper = LightsOutManagement(port=args.port, serial_port=args.serial_port)

        if args.command == "read":
            log.info(str(lom_wrapper.read_data(args.offset, args.size)))
            log.info(SCRIPT_STATUS_SUCCESS)
            exit(0)
        elif args.command == "write":
            offset_delta = 0
            for i in args.values.split(' '):
                lom_wrapper.write_data(args.offset + offset_delta, [int(i)], 1)
                offset_delta += 1
            log.info(SCRIPT_STATUS_SUCCESS)
            exit(0)
        elif args.command == "setmac":
            lom_wrapper.set_lom_mac_address(args.mac)
            log.info(SCRIPT_STATUS_SUCCESS)
            exit(0)
        elif args.command == "setip":
            lom_wrapper.set_lom_ip_address(args.ip)
            log.info(SCRIPT_STATUS_SUCCESS)
            exit(0)
        elif args.command == "enable":
            lom_wrapper.LoM_enable()
            log.info(SCRIPT_STATUS_SUCCESS)
            exit(0)
        elif args.command == "disable":
            lom_wrapper.LoM_disable()
            log.info(SCRIPT_STATUS_SUCCESS)
            exit(0)
        elif args.command == "mdio_off":
            tmp_value = lom_wrapper.read_data(lom_wrapper.LOM_OFFSET_LOM_STATUS, 1)[0]
            tmp_value = tmp_value | 0x20
            lom_wrapper.write_data(lom_wrapper.LOM_OFFSET_LOM_STATUS, [tmp_value], 1)
            log.info(SCRIPT_STATUS_SUCCESS)
            exit(0)
        elif args.command == "mdio_on":
            tmp_value = lom_wrapper.read_data(lom_wrapper.LOM_OFFSET_LOM_STATUS, 1)[0]
            tmp_value = tmp_value & 0xDF
            lom_wrapper.write_data(lom_wrapper.LOM_OFFSET_LOM_STATUS, [tmp_value], 1)
            log.info(SCRIPT_STATUS_SUCCESS)
            exit(0)
        else:
            log.info('Unknown action is required')
            log.info(SCRIPT_STATUS_SUCCESS)
            exit(0)
    except Exception:
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
