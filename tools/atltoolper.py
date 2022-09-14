import argparse
import os
import platform
import re
import socket
import struct
import sys
import threading
import time
import timeit
import warnings
from abc import abstractmethod, ABCMeta
from collections import OrderedDict

import constants
import mcplog.mdbgtrace
import mcplog.eurdbgtrace

from command import Command
from debug import collect_debug_info
from mbuper import LINK_SPEED_TO_REG_VAL_MAP, REG_VAL_TO_LINK_SPEED_MAP, LINK_SPEED_TO_REG_VAL_MAP_2X, \
    REG_VAL_TO_LINK_SPEED_MAP_2X, REG_VAL_TO_LINK_SPEED_MAP_2X_ALL_AUTO, LINK_STATE_UP, LINK_CONTROL_TRANSACTION_ID
from ops import OpSystem
from utils import get_atf_logger, get_bus_dev_func, get_domain_bus_dev_func, SpacedArgAction, upload_file, \
    download_file, remove_file, \
    url_file_exists, get_url_response
from drv_iface_cfg import WAKE_REASON_OFFSET

USE_AEAA_WRAPPER = False

log = get_atf_logger()

# ----------------------------------------Import atltool---------------------------------------- #
if sys.platform == "win32":
    if platform.architecture()[0] == "64bit":
        WHERE_ATLTOOL = "X:/qa/windows/fwtools/64"
    else:
        WHERE_ATLTOOL = "X:/qa/windows/fwtools/32"
elif sys.platform == "darwin":
    WHERE_ATLTOOL = "/dos/qa/macos/fwtools"
elif "freebsd" in sys.platform:
    WHERE_ATLTOOL = "/x/qa/freebsd/fwtools"
else:
    # TODO: hardcoded for now
    WHERE_ATLTOOL = "/x/qa/linux/fwtools"
# Add path to python import search directories
sys.path.append(WHERE_ATLTOOL)

if sys.platform != "darwin" or (sys.platform == "darwin" and not USE_AEAA_WRAPPER):
    import atltool

if sys.platform == "darwin" and USE_AEAA_WRAPPER:
    import aeaaper

# ----------------------------------------Import atltool---------------------------------------- #

SCRIPT_STATUS_SUCCESS = "[ATLTOOL-SUCCESS]"
SCRIPT_STATUS_FAILED = "[ATLTOOL-FAILED]"


def auto_int(n):
    return int(n, 0)


class KickstartError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class AtlTool_PhyCtrl(object):
    def __init__(self, device_number):
        self.device_number = device_number

    def pifReadData(self, addr):
        mmd = (addr >> 16) & 0xFF
        reg = addr & 0xFFFF

        return atltool.readphyreg(self.device_number, mmd, reg)


class LocalArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise Exception("{}; {}".format(message, self.format_usage().rstrip()))


class AtlTool(object):
    __metaclass__ = ABCMeta

    PHY_LOGGING_MASK = 0x00002000

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            if sys.platform == "darwin" and USE_AEAA_WRAPPER:
                return object.__new__(AtlToolAeaaLocal)
            else:
                return object.__new__(AtlToolLocal)
        else:
            return object.__new__(AtlToolRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]
        self.silent = kwargs.get("silent", False)
        ops = OpSystem()
        if ops.is_linux():
            domain, bus, dev, func = get_domain_bus_dev_func(self.port)
            self.pciutil_port = "{:04x}-{:02x}:{:02x}.{:x}".format(domain, bus, dev, func)
        else:
            bus, dev, func = get_bus_dev_func(self.port)
            self.pciutil_port = "{:02x}:{:02x}.{:x}".format(int(bus), int(dev), int(func))
        self.out_cfg_file = None

    @abstractmethod
    def readreg(self, reg):
        pass

    @abstractmethod
    def writereg(self, reg, value):
        pass

    @abstractmethod
    def readregs(self, regs):
        pass

    def writeregs(self, reg_val_pairs):
        if self.out_cfg_file is not None:
            for reg, val in reg_val_pairs:
                self.out_cfg_file.write("writereg 0x{:08X} 0x{:08X}\n".format(reg, val))

    @abstractmethod
    def readphyreg(self, mmd, reg):
        pass

    @abstractmethod
    def writephyreg(self, mmd, reg, value):
        pass

    @abstractmethod
    def readmem(self, addr, size):
        pass

    @abstractmethod
    def readphymem(self, addr, size):
        pass

    @abstractmethod
    def writemem(self, offset, value):
        pass

    @abstractmethod
    def kickstart(self, reload_phy_fw=True, clx_for_flashless=None, force_flashless=False, use_phy_reset=False,
                  drv_prov=0):
        pass

    @abstractmethod
    def kickstart2(self, full_reset=False, fast_reset=False, skip_phy=False, force_flashless=False, clx_path=None):
        pass

    @abstractmethod
    def stall_a2_fw(self):
        pass

    @abstractmethod
    def unstall_a2_fw(self):
        pass

    def parse_beton(self, beton):
        READREG_CMD = ["readreg", "rr", "mac.readreg", "mac.rr", "mac.mcp.readreg", "mac.mcp.rr"]
        WRITEREG_CMD = ["writereg", "wr", "mac.writereg", "mac.wr", "mac.mcp.writereg", "mac.mcp.wr"]
        READPHYREG_CMD = ["readphyreg", "rpr", "mac.readphyreg", "mac.rpr", "mac.mcp.readphyreg", "mac.mcp.rpr"]
        WRITEPHYREG_CMD = ["writephyreg", "wpr", "mac.writephyreg", "mac.wpr", "mac.mcp.writephyreg", "mac.mcp.wpr"]
        READMEM_CMD = ["readmem", "mac.mcp.readmem"]
        PAUSE_CMD = ["pause"]

        executable_python = []

        for i, line in enumerate(beton):
            if line:
                params = line.split()

                try:
                    if params[0].startswith("#"):
                        continue
                    elif params[0] in READREG_CMD:
                        parser = LocalArgumentParser(prog="readreg")
                        parser.add_argument("reg", type=auto_int)
                        args = parser.parse_args(params[1:])
                        executable_python.append("self.readreg(0x{:x})".format(args.reg))
                    elif params[0] in WRITEREG_CMD:
                        parser = LocalArgumentParser(prog="writereg")
                        parser.add_argument("reg", type=auto_int)
                        parser.add_argument("val", type=auto_int)
                        args = parser.parse_args(params[1:])
                        executable_python.append("self.writereg(0x{:x}, 0x{:x})".format(args.reg, args.val))
                    elif params[0] in READPHYREG_CMD:
                        parser = LocalArgumentParser(prog="readphyreg")
                        parser.add_argument("mmd_reg", type=str, help="MMD.REG")
                        args = parser.parse_args(params[1:])
                        mmd, reg = map(auto_int, args.mmd_reg.split("."))
                        executable_python.append("self.readphyreg(0x{:x}, 0x{:x})".format(mmd, reg))
                    elif params[0] in WRITEPHYREG_CMD:
                        parser = LocalArgumentParser(prog="writephyreg")
                        parser.add_argument("mmd_reg", type=str, help="MMD.REG")
                        parser.add_argument("val", type=auto_int)
                        args = parser.parse_args(params[1:])
                        mmd, reg = map(auto_int, args.mmd_reg.split("."))
                        executable_python.append("self.writephyreg(0x{:x}, 0x{:x}, 0x{:x})".format(mmd, reg, args.val))
                    elif params[0] in READMEM_CMD:
                        parser = LocalArgumentParser(prog="readmem")
                        parser.add_argument("addr", type=auto_int)
                        parser.add_argument("-s", "--size", type=auto_int, default=4)
                        args = parser.parse_args(params[1:])
                        executable_python.append("self.readmem(0x{:x}, {})".format(args.addr, args.size))
                    elif params[0] in PAUSE_CMD:
                        parser = LocalArgumentParser(prog="pause")
                        parser.add_argument("amount", type=auto_int)
                        parser.add_argument("unit", choices=["s", "ms", "us"])
                        args = parser.parse_args(params[1:])
                        if args.unit == "s":
                            devision = 1.0
                        elif args.unit == "ms":
                            devision = 1000.0
                        else:
                            devision = 1000000.0
                        executable_python.append("time.sleep({})".format(args.amount / devision))
                    else:
                        raise Exception("Unknown command: {}".format(params[0]))
                except Exception as exc:
                    log.error("Error parsing line {} - '{}':".format(i + 1, line))
                    log.error(exc.message)
                    return None

        return "; ".join(executable_python)

    @abstractmethod
    def exec_beton(self, beton):
        pass

    @abstractmethod
    def exec_txt(self, beton_file):
        pass

    def get_fw_version(self):
        version = self.readreg(0x18)
        ver_major = version >> 24
        ver_minor = (version >> 16) & 0xff
        ver_release = version & 0xffff
        return ver_major, ver_minor, ver_release

    @abstractmethod
    def get_wake_counter_2x(self):
        pass

    @abstractmethod
    def get_wake_reason_2x(self):
        pass

    @abstractmethod
    def debug_buffer_enable(self, enable_flag, bin_path=None):
        pass

    @abstractmethod
    def read_phy_dbg_buffer(self, enable_flag, bin_path=None, txt_enable=True):
        pass

    def enable_phy_logging(self, enable_flag):
        """Enable PHY logging feature"""
        r36C = self.readreg(0x36C)
        if enable_flag:
            r36C |= self.PHY_LOGGING_MASK
        else:
            r36C &= ~self.PHY_LOGGING_MASK
        self.writereg(0x36C, r36C)

    @abstractmethod
    def dump_to_config_memory(self, data):
        pass

    @abstractmethod
    def get_mac_address(self):
        pass

    @abstractmethod
    def read_phy_dram(self):
        pass

    @abstractmethod
    def switchoff_eee_autodisable(self):
        pass

    @abstractmethod
    def get_mii(self):
        pass

    @abstractmethod
    def readmsmreg(self, addr):
        raise NotImplementedError()

    @abstractmethod
    def writemsmreg(self, reg, value):
        raise NotImplementedError()

    @abstractmethod
    def is_secure_chips(self):
        raise NotImplementedError()

    def set_link_control_2x(self, val):
        self.writereg(0x36C, val)

    def get_link_control_2x(self):
        return self.readreg(0x374)


class AtlToolAeaaLocal(AtlTool):
    def __init__(self, **kwargs):
        super(AtlToolAeaaLocal, self).__init__(**kwargs)
        self.aeaa_wrapper = aeaaper.AeaaWrapper(port=self.port)

    def readreg(self, reg):
        return self.aeaa_wrapper.readreg(reg)

    def writereg(self, reg, value):
        self.aeaa_wrapper.writereg(reg, value)

    def readregs(self, regs):
        raise NotImplementedError()

    def writeregs(self, reg_val_pairs):
        raise NotImplementedError()

    def readmem(self, addr, size):
        return self.aeaa_wrapper.readmem(addr, size)

    def writemem(self, offset, value):
        raise NotImplementedError()

    def readphyreg(self, mmd, reg):
        return self.aeaa_wrapper.readphyreg(mmd, reg)

    def writephyreg(self, mmd, reg, value):
        self.aeaa_wrapper.writephyreg(mmd, reg, value)

    def readphymem(self, addr, size):
        raise NotImplementedError()

    def kickstart(self, reload_phy_fw=True, clx_for_flashless=None, force_flashless=False, use_phy_reset=False,
                  drv_prov=0):
        raise NotImplementedError()

    def is_secure_chips(self):
        raise NotImplementedError()

    def kickstart2(self, full_reset=False, fast_reset=False, skip_phy=False, force_flashless=False, clx_path=None):
        raise NotImplementedError()

    def stall_a2_fw(self):
        raise NotImplementedError()

    def unstall_a2_fw(self):
        raise NotImplementedError()

    def exec_beton(self, beton):
        raise NotImplementedError()

    def exec_txt(self, beton_file):
        raise NotImplementedError()

    def get_wake_counter_2x(self):
        raise NotImplementedError()

    def get_wake_reason_2x(self):
        raise NotImplementedError()

    def debug_buffer_enable(self, enable_flag, bin_path=None):
        raise NotImplementedError()

    def read_phy_dbg_buffer(self, enable_flag, bin_path=None, txt_enable=True):
        raise NotImplementedError()

    def dump_to_config_memory(self, data):
        raise NotImplementedError()

    def get_mac_address(self):
        raise NotImplementedError()

    def switchoff_eee_autodisable(self):
        raise NotImplementedError()

    def get_mii(self):
        raise NotImplementedError()

    def read_phy_dram(self):
        raise NotImplementedError()

    def readmsmreg(self, addr):
        raise NotImplementedError()

    def writemsmreg(self, reg, value):
        raise NotImplementedError()

    def get_msm_counters(self):
        raise NotImplementedError()

    def load_efuse(self, first_dw, num_dw):
        raise NotImplementedError()


class AtlToolLocal(AtlTool):
    SCRATCHPAD_REG_START = 0x300

    MAC_ADDR_EFUSE_OFFSET = 40 * 4  # Dwords 40 and 41
    DEVICE_ID_EFUSE_OFFSET = 65 * 4  # Dwords 65 and 67

    WAKE_COUNTER_OFFSET = 0xD4

    def __init__(self, **kwargs):
        super(AtlToolLocal, self).__init__(**kwargs)
        with warnings.catch_warnings(record=True) as w:
            self.device_number = atltool.open_device(self.pciutil_port)
            if len(w) > 0 and next("Failed to detect PHY ID" in str(wrn.message) for wrn in w):
                self.phy_id_detected = False
            else:
                self.phy_id_detected = True

    def __del__(self):
        if atltool and hasattr(self, "device_number"):
            atltool.close_device(self.device_number)

    def readreg(self, reg):
        val = atltool.readreg(self.device_number, reg)
        if not self.silent:
            log.info("Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))
        return val

    def writereg(self, reg, value):
        atltool.writereg(self.device_number, reg, value)
        if not self.silent:
            log.info("Register 0x{:08x}: 0x{:08x} written".format(reg, value))

    def readregs(self, regs):
        vals = []
        for reg in regs:
            vals.append(self.readreg(reg))
        return vals

    def writeregs(self, reg_val_pairs):
        super(AtlToolLocal, self).writeregs(reg_val_pairs)

        for reg, val in reg_val_pairs:
            self.writereg(reg, val)

    def readphyreg(self, mmd, reg):
        val = atltool.readphyreg(self.device_number, mmd, reg)
        if not self.silent:
            log.info("Register PHY 0 0x{:x}.0x{:x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                mmd, reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))
        return val

    def writephyreg(self, mmd, reg, value):
        atltool.writephyreg(self.device_number, mmd, reg, value)
        if not self.silent:
            log.info("Register PHY 0 0x{:x}.0x{:x}: 0x{:08x} written".format(mmd, reg, value))

    def readmem(self, addr, size):
        mem = atltool.readmem(self.device_number, addr, size)
        log.info("Memory at 0x{:08x}: [{}]".format(addr, ", ".join("0x{:08x}".format(m) for m in mem)))
        return mem

    def writemem(self, offset, value):
        """
        Write MCP memory.

        Note: This option is not available for B1 chip revision. Writting MCP memory is locked.
        :param offset: MCP memory offset
        :param value: Single int value or list of int values.
        :return: None
        """
        if isinstance(value, list) and all(isinstance(item, int) for item in value):
            mem = value
        elif isinstance(value, int):
            mem = [value]
        else:
            raise ValueError("value should be either int or list of ints")
        atltool.writemem(self.device_number, offset, mem)
        log.info("Memory written at 0x{:08x}: [{}]".format(offset, ", ".join("0x{:08x}".format(m) for m in mem)))

    def stall_a2_fw(self):
        stall = self.readreg(0x404)
        self.writereg(0x404, stall | 0x1)

    def unstall_a2_fw(self):
        stall = self.readreg(0x404)
        self.writereg(0x404, stall & 0xfffffffe)

    def kickstart_flb(self, reload_phy_fw=True, use_phy_reset=False, drv_prov=0):
        # Kickstart has already been done, unstall MCP after applying driver provisioning
        if drv_prov > 0:
            self.writereg(0x404, 0x40e0)
            return

        # MAC FW is always reloaded
        # boot code is always reloaded
        assert use_phy_reset is False  # it must be always False, the code is left for history

        self.writereg(0x404, 0x40e1)
        # Let Felicity hardware to complete SMBUS transaction before Global software reset
        time.sleep(0.050)  # pause 50 ms

        # If SPI burst transaction was interrupted (before running the script), global software reset may not
        # clear SPI interface
        # Clean it up manualy before global reset
        nvrProv4 = self.readreg(0x53c)
        nvrProv4 |= 0x10
        self.writereg(0x53c, nvrProv4)

        reg_temp = self.readreg(0x0)
        reg_temp = (reg_temp & 0xBFFF) | 0x8000
        self.writereg(0x0, reg_temp)
        # time.sleep(0.010)  # pause 10 ms

        # Kickstart
        self.writereg(0x404, 0x80e0)
        self.writereg(0x32a8, 0x0)
        self.writereg(0x520, 1)
        # For the case SPI burst transaction was interrupted (by MCP reset above), reset SPI interface
        nvrProv4 = self.readreg(0x53c)
        nvrProv4reset = nvrProv4 | 0x10
        self.writereg(0x53c, nvrProv4reset)
        time.sleep(0.010)
        self.writereg(0x53c, nvrProv4)

        self.writereg(0x404, 0x180e0)
        for k in range(1000):
            flb_status = self.readreg(0x704)
            flb_status = flb_status & 0x10
            if flb_status != 0:
                break
            time.sleep(0.010)  # pause 10 ms
        if flb_status == 0:
            raise KickstartError("MAC kickstart failed")
        k *= 10
        log.info("MAC kickstart duration: {} ms".format(k))

        # If we want to apply driver provisioning later - don't do MCP reset
        if drv_prov < 0:
            self.writereg(0x404, 0x40e1)
        else:
            self.writereg(0x404, 0x80e0)
        # Let Felicity hardware to complete SMBUS transaction before Global software reset
        time.sleep(0.050)  # pause 50 ms
        self.writereg(0x3a0, 1)

        # PHY Kickstart
        if reload_phy_fw:
            log.info("Kickstarting PHY")
            pk_start = timeit.default_timer()
            if use_phy_reset:
                self.writephyreg(0x1e, 0x2681, 1)
            else:
                self.writephyreg(0x1e, 0xc001, 0x41)
                # This is to make sure reset will be triggered later with setting 1e.0.F, as rising edge is needed
                self.writephyreg(0x1e, 0x0, 0x0)
                self.writephyreg(0x1e, 0xc442, 0x1)
                # Reset PHY
                self.writephyreg(0x1e, 0xC3FE, 0x0)
                self.writephyreg(0x1e, 0x0, 0x8000)
                self.writephyreg(0x1e, 0xc001, 0x0)
            # Without this pause, we sometimes get 0xFFFF from MDIO
            # Anyway, I put another protection against this below
            time.sleep(0.030)  # pause 30 ms
            for k in range(3000):
                daisy_chain_status = self.readphyreg(0x1e, 0xC841)
                if daisy_chain_status != 0xFFFF:
                    daisy_chain_status = daisy_chain_status & 0x40
                    if daisy_chain_status != 0:
                        break
                time.sleep(0.010)  # pause 10 ms
            pk_end = timeit.default_timer()

            if daisy_chain_status == 0:
                raise KickstartError("PHY kickstart failed")
            log.info("PHY kickstart duration: {} ms".format(int((pk_end - pk_start) * 1000)))

        log.info("Performing global software reset")
        reg_temp = self.readreg(0x5000)
        reg_temp = reg_temp & 0xDFFFFFFF
        self.writereg(0x5000, reg_temp)
        reg_temp = self.readreg(0x7000)
        reg_temp = reg_temp & 0xDFFFFFFF
        self.writereg(0x7000, reg_temp)
        reg_temp = self.readreg(0x4000)
        reg_temp = reg_temp & 0xDFFFFFFF
        self.writereg(0x4000, reg_temp)
        reg_temp = self.readreg(0x0)
        reg_temp = (reg_temp & 0xBFFF) | 0x8000
        self.writereg(0x0, reg_temp)

    def kickstart_rbl(self, reload_phy_fw=True, clx_for_flashless=None, force_flashless=False, use_phy_reset=False,
                      drv_prov=0):
        # First part of kickstart - before applying driver provisioning
        if drv_prov <= 0:
            # MAC FW is always reloaded
            # boot code is always reloaded
            assert use_phy_reset is False  # it must be always False, the code is left for history

            self.writereg(0x404, 0x40e1)
            self.writereg(0x3a0, 1)
            self.writereg(0x32a8, 0x0)
            # MAC FW will reload PHY FW if 1E.1000.3 was cleaned
            if reload_phy_fw:
                log.info("Requesting MAC FW to reload PHY FW")
                if use_phy_reset:
                    self.writephyreg(0x1e, 0x2681, 1)
                else:
                    phy_control = self.readphyreg(0x1e, 0x1000)
                    phy_control &= 0xfffffff7
                    self.writephyreg(0x1e, 0x1000, phy_control)

            # Change RBL status so we can poll and know when boot completed (or entered flashless mode)
            # But don't reset it to 0, so script will never execute non-RBL branch
            self.writereg(0x388, 0xDEAD)

            # If SPI burst operation is in progress at the time when MCP is being stalled, next SPI interface
            # read request fails
            # Reset does not clear this state of SPI interface, so need  to reset it explicitly
            nvrProv4 = self.readreg(0x53c)
            nvrProv4 |= 0x10
            self.writereg(0x53c, nvrProv4)

            # Global software reset with cleaning all registers (this will restart RBL and reload MAC FW)
            log.info("Performing global software reset (restart RBL and reload MAC FW)")
            reg_temp = self.readreg(0x5000)
            reg_temp = reg_temp & 0xDFFFFFFF
            self.writereg(0x5000, reg_temp)
            reg_temp = self.readreg(0x7000)
            reg_temp = reg_temp & 0xDFFFFFFF
            self.writereg(0x7000, reg_temp)
            reg_temp = self.readreg(0x4000)
            reg_temp = reg_temp & 0xDFFFFFFF
            self.writereg(0x4000, reg_temp)
            reg_temp = self.readreg(0x0)
            reg_temp = (reg_temp & 0xFFFFBFFF) | 0x8000
            self.writereg(0x0, reg_temp)
            if force_flashless:
                log.info("Killing SPI interface (SPI clock div = 0) to force flashless mode")
                self.writereg(0x534, 0)

            # If we want to apply driver provisioning - stop kickstart here
            if drv_prov < 0:
                return

        # Second part of kickstart - after applying driver provisioning
        if drv_prov >= 0:
            self.writereg(0x404, 0x40e0)

            log.info("Waiting until RBL boot code completed")
            for k in range(1000):
                restart_completed = self.readreg(0x388)
                restart_completed = restart_completed & 0xFFFF
                if restart_completed != 0 and restart_completed != 0xDEAD:
                    break
                time.sleep(0.010)  # pause 10 ms
            if restart_completed == 0 or restart_completed == 0xDEAD:
                raise KickstartError("RBL restart failed")
            k *= 10
            log.info("RBL restart duration: {} ms".format(k))
            # Restore NVR interface
            if force_flashless:
                self.writereg(0x534, 0xA0)

            # We can perform flashless boot load here
            if restart_completed == 0xF1A7 and clx_for_flashless is not None:
                log.info("Loading FW from host: {}".format(clx_for_flashless))
                atltool.load_firmware(self.device_number, clx_for_flashless, 0)

    def kickstart(self, reload_phy_fw=True, clx_for_flashless=None, force_flashless=False, use_phy_reset=False,
                  drv_prov=0):
        # --------------------------------------------------------------------------------------------------------------
        # drv_prov = 0 - perform normal kickstart
        # drv_prov < 0 - perform first part of kickstart and stop to allow applying driver provisioning
        # drv_prov > 0 - resume kickstart after applying driver provisioning
        # --------------------------------------------------------------------------------------------------------------

        # --------------------------------------------------------------------------------------------------------------
        # If reload_phy_fw == True, check if PHY ID was detected.
        # If not, warn user and don't try to reset PHY
        if reload_phy_fw and self.phy_id_detected is False:
            log.warn("PHY ID wasn't detected during AtlTool initialization but PHY restart is requested. Skipping it")
            reload_phy_fw = False
        # --------------------------------------------------------------------------------------------------------------

        # MAC FW is always reloaded
        # boot code is always reloaded
        assert use_phy_reset is False  # it must be always False, the code is left for history

        log.info("Kickstarting MAC")

        for k in range(1000):
            flb_status = self.readreg(0x704)
            boot_exit_code = self.readreg(0x388)
            if flb_status != 0x06000000 or boot_exit_code != 0:
                break
            if k == 999:
                raise Exception("Neither RBL nor FLB started")

        if boot_exit_code != 0:
            rbl_enabled = True
        else:
            rbl_enabled = False

        if not rbl_enabled:
            log.info("RBL is not enabled")
            self.kickstart_flb(reload_phy_fw=reload_phy_fw, use_phy_reset=use_phy_reset, drv_prov=drv_prov)
        else:
            log.info("RBL is enabled")
            self.kickstart_rbl(reload_phy_fw=reload_phy_fw, clx_for_flashless=clx_for_flashless,
                               force_flashless=force_flashless, use_phy_reset=use_phy_reset, drv_prov=drv_prov)

        if drv_prov >= 0:
            for k in range(1000):
                restart_completed = self.readreg(0x18)
                if restart_completed != 0:
                    break
                time.sleep(0.010)  # pause 10 ms
            if restart_completed == 0 or restart_completed == 0xffffffff:
                raise KickstartError("FW restart failed")
            k *= 10
            log.info("Firmware restart duration: {} ms".format(k))

            time.sleep(3)  # to make sure Flash iface is not locked by reading from FW
            log.info("Kickstart is done")

    def kickstart2(self, full_reset=False, fast_reset=False, skip_phy=False, force_flashless=False, clx_path=None):
        """
        Not used flags:
        -g         Do <Chip Reset (0x3080)> instead of <Global Reset (0x3040)>.
        -s         Don't wait for PHY FW to start up.
        """
        run_cmd = 'sudo kickstart2 -d {} -v'.format(self.pciutil_port)

        if full_reset:
            run_cmd += ' -r'

        if fast_reset:
            run_cmd += ' -a'

        if skip_phy:
            run_cmd += ' -p'

        if force_flashless:
            if clx_path is None:
                raise KickstartError('Force flashless boot requested but clx file is not provided')
            run_cmd += ' -f -c {}'.format(clx_path)

        res = Command(cmd=run_cmd).run()
        if res["returncode"] != 0:
            raise KickstartError("Failed to perform kickstart2")
        return res["output"]

    def exec_beton(self, beton):
        executable_python = self.parse_beton(beton)
        if executable_python:
            exec (executable_python)
        else:
            raise Exception("Failed to parse beton script")

    def exec_txt(self, beton_file):
        with open(beton_file, "r") as f:
            beton = f.read().splitlines()
        self.exec_beton(beton)

    def get_wake_counter_2x(self):
        addr = self.readreg(0x360)
        addr += self.WAKE_COUNTER_OFFSET
        return self.readmem(addr, 4)[0]

    def get_wake_reason_2x(self):
        addr = self.readreg(0x360)
        addr += WAKE_REASON_OFFSET
        wake_reason = self.readmem(addr, 4)[0] >> 24
        return wake_reason

    def get_adapter_speed(self):
        globEfuseCustom = self.readphyreg(0x1E, 0xC896)
        _5gEnabled = (globEfuseCustom >> 0xD) & 1
        _10gEnabled = (globEfuseCustom >> 0xE) & 1
        return constants.LINK_SPEED_10G if _10gEnabled else \
            constants.LINK_SPEED_5G if _5gEnabled else constants.LINK_SPEED_2_5G

    def get_link_params(self):
        val = self.readreg(0x36c)
        downshift = val >> 24
        speed = REG_VAL_TO_LINK_SPEED_MAP.get((val >> 16) & 0xff, None)
        state = val & 0xffff
        return downshift, speed, state

    def set_link_params(self, speed, state, downshift_att=7):
        if downshift_att != -1:
            downshift_val = 1 << 3 | downshift_att
            val = downshift_val << 28 | LINK_SPEED_TO_REG_VAL_MAP[speed] << 16 | state
        else:
            val = LINK_SPEED_TO_REG_VAL_MAP[speed] << 16 | state

        self.writereg(0x368, val)
        if speed != constants.LINK_SPEED_AUTO and state == LINK_STATE_UP:
            for i in range(200):
                cur_val = self.readreg(0x36c)
                if cur_val == val:
                    return
                time.sleep(0.1)

            self.readreg(0x368)
            self.readreg(0x36C)
            self.readreg(0x370)
            self.readreg(0x374)

            raise Exception("Failed to set link speed {}, state 0x{:x}".format(speed, state))

    def get_link_params_2x(self):
        val = self.readreg(0x370)
        speed = REG_VAL_TO_LINK_SPEED_MAP_2X.get((val & 0xfff), None)  # check mask in caps.h, eCapsLo enum
        state_is_up = ((val & 0xfff) != 0x0)  # & 0xffff
        return speed, state_is_up

    def get_link_params_2x_auto(self, expected_speed):
        log.info("Waiting speed = {}".format(expected_speed))
        log.info("Polling (MBU) > readreg 0x370")
        for i in range(300):
            val = self.readreg(0x370)
            speed = REG_VAL_TO_LINK_SPEED_MAP_2X_ALL_AUTO.get((val & 0xfff), None)
            state_is_up = ((val & 0xfff) != 0x0)
            if speed == expected_speed:
                return speed, state_is_up
            time.sleep(0.1)

        self.readreg(0x368)
        self.readreg(0x36C)
        self.readreg(0x370)
        self.readreg(0x374)

        return speed, state_is_up

    def set_link_params_2x(self, speed, eee=False):
        log.info("Setting speed {}...".format(speed))

        val = LINK_SPEED_TO_REG_VAL_MAP_2X[speed]

        reg = 0x36C if eee else 0x368
        self.writereg(reg, val)

    def get_link_speed_2x(self):
        val = self.readreg(0x370)
        val &= 0xfff
        if val in REG_VAL_TO_LINK_SPEED_MAP_2X:
            return REG_VAL_TO_LINK_SPEED_MAP_2X[val]
        elif val in REG_VAL_TO_LINK_SPEED_MAP_2X_ALL_AUTO:
            return REG_VAL_TO_LINK_SPEED_MAP_2X_ALL_AUTO[val]
        else:
            raise Exception("Unknown link speed: 0x{:08x}".format(val))

    def transaction_id_is_set(self):
        val = self.readreg(0x36c)
        val = val & LINK_CONTROL_TRANSACTION_ID
        if val != 0:
            log.info("TRANSACTION_ID bit (0x80000000) is set")
        else:
            log.info("TRANSACTION_ID bit (0x80000000) is clear")
        return val

    def get_fw_statistics(self):
        addr = self.readreg(0x360)
        ver, transaction_id = self.readmem(addr, 8)
        return ver, transaction_id

    def get_efuse_shadow_memory_address(self):
        EFUSE_SHADOW_SCRATCHPAD_REG_FW1X = 0x1d
        EFUSE_SHADOW_SCRATCHPAD_REG_FW2X = 0x19

        mj, mi, rev = self.get_fw_version()

        scratch_reg = self.SCRATCHPAD_REG_START
        if mj == 1:
            scratch_reg += EFUSE_SHADOW_SCRATCHPAD_REG_FW1X * 4
        elif mj in [2, 3, 4]:
            scratch_reg += EFUSE_SHADOW_SCRATCHPAD_REG_FW2X * 4
        else:
            raise NotImplementedError()

        return self.readreg(scratch_reg) & 0x7fffffff

    def load_efuse(self, first_dw, num_dw):
        return atltool.load_efuse(self.device_number, first_dw, num_dw)

    def get_efuse(self, size=4):
        try:
            efuse_base_addr = self.get_efuse_shadow_memory_address()
        except NotImplementedError:
            efuse_base_addr = 0
        if efuse_base_addr != 0x0:
            efuse = self.readmem(efuse_base_addr, size)
        else:
            efuse = self.load_efuse(0, size // 4)
        return efuse

    def is_secure_chips(self):
        efuse = self.get_efuse(504)
        rbl = efuse[62]
        if rbl & 0x00027000 != 0x27000:
            log.info("Not secure chip")
            return False
        else:
            log.info("Secure chip")
            return True

    def get_mac_address(self):
        efuse_base_addr = self.get_efuse_shadow_memory_address()
        if efuse_base_addr != 0x0:
            dword0, dword1 = self.readmem(efuse_base_addr + self.MAC_ADDR_EFUSE_OFFSET, 8)
        else:
            dword0, dword1 = self.load_efuse(self.MAC_ADDR_EFUSE_OFFSET // 4, 2)

        mac = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
            (dword0 >> 24) & 0xFF,
            (dword0 >> 16) & 0xFF,
            (dword0 >> 8) & 0xFF,
            (dword0) & 0xFF,
            (dword1 >> 24) & 0xFF,
            (dword1 >> 16) & 0xFF
        )
        return mac

    def get_device_ids(self):
        efuse_base_addr = self.get_efuse_shadow_memory_address()
        if efuse_base_addr != 0x0:
            vend_dev_id, _, sub_vend_dev_id = self.readmem(efuse_base_addr + self.DEVICE_ID_EFUSE_OFFSET, 12)
        else:
            VEND_DEV_ID_NWL_REG = 0x0  # used for vid and did
            SUB_VEND_DEV_ID_NWL_REG = 0x2  # used for svid and ssid

            vend_dev_id = atltool.readnwlreg(self.device_number, VEND_DEV_ID_NWL_REG)
            sub_vend_dev_id = atltool.readnwlreg(self.device_number, SUB_VEND_DEV_ID_NWL_REG)

        vend_id = (vend_dev_id & 0x0000FFFF)
        dev_id = (vend_dev_id & 0xFFFF0000) >> 16
        subven_id = (sub_vend_dev_id & 0x0000FFFF)
        subsys_id = (sub_vend_dev_id & 0xFFFF0000) >> 16

        return vend_id, dev_id, subven_id, subsys_id

    def wait_link_up(self, timeout=25, retry_interval=1):
        log.info("Waiting for link UP")
        mj, _, __ = self.get_fw_version()
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            time.sleep(retry_interval)
            if mj == 1:
                _, speed, __ = self.get_link_params()
            else:
                speed = self.get_link_speed_2x()
            if speed != constants.LINK_SPEED_NO_LINK:
                log.info("Link is up at {}".format(speed))
                return speed

        collect_debug_info()

        raise Exception('Link is not up after timeout = {} sec.'.format(timeout))

    def wait_link_down(self, timeout=25, retry_interval=1):
        mj, _, __ = self.get_fw_version()
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            time.sleep(retry_interval)
            if mj == 1:
                _, speed, __ = self.get_link_params()
            else:
                speed = self.get_link_speed_2x()
            if speed == constants.LINK_SPEED_NO_LINK:
                return speed
        raise Exception('Link is not down after timeout = {} sec.'.format(timeout))

    def debug_buffer_enable(self, enable_flag, bin_path=None):
        """Start thread that reads binary MCP logs, converts them to text format and saves to output file"""
        if enable_flag:
            self.enable_logging = True

            if bin_path:
                self.bin_file_path = bin_path
            else:
                self.bin_file_path = time.strftime("mcp-%Y-%m-%d__%H-%M-%S.bin")
            self.txt_file_path = os.path.splitext(self.bin_file_path)[0] + ".log"

            def target_log_func():
                data = []
                with open(self.bin_file_path, "wb") as bin_fp, open(self.txt_file_path, "w") as txt_fp:
                    dbgtrace = mcplog.mdbgtrace.DebugTrace(phycontrol=AtlTool_PhyCtrl(self.device_number),
                                                           fw_v=self.get_fw_version()[0])

                    while self.enable_logging:
                        new_data = atltool.readlog(self.device_number)
                        bin_fp.write("".join(map(lambda x: struct.pack("H", x), new_data)))
                        bin_fp.flush()
                        data.extend(new_data)
                        outString, data, status = dbgtrace.printTrace(data)
                        if outString:
                            txt_fp.writelines([outString, "\n"])
                            txt_fp.flush()
                        # time.sleep(0.01)
                log.info("MCP logging thread stopped")

            self.logging_thread = threading.Thread(target=target_log_func)
            self.logging_thread.daemon = True
            self.logging_thread.start()
            log.info("MCP logging thread started")

            return self.bin_file_path, self.txt_file_path
        else:
            if self.enable_logging:
                self.enable_logging = False
                self.logging_thread.join(1)

                return self.bin_file_path, self.txt_file_path
            else:
                return None, None

    def read_phy_dbg_buffer(self, enable_flag, bin_path=None, txt_enable=True):
        """Start thread that reads binary PHY logs, converts them to text format and saves to output file"""
        if enable_flag:
            self.phy_logging_enabled = True

            if bin_path:
                self.phy_bin_file_path = bin_path
            else:
                self.phy_bin_file_path = time.strftime("phy_dbg_buf-%Y-%m-%d__%H-%M-%S.bin")
            self.phy_txt_file_path = os.path.splitext(self.phy_bin_file_path)[0] + ".log"

            def target_log_func():
                data = []
                with open(self.phy_bin_file_path, "wb") as bin_fp, open(self.phy_txt_file_path, "w") as txt_fp:
                    PHY_CTRL = AtlTool_PhyCtrl(self.device_number)

                    while self.phy_logging_enabled:
                        new_data = atltool.readphylog(self.device_number)
                        bin_fp.write("".join(map(lambda x: struct.pack("H", x), new_data)))
                        bin_fp.flush()
                        if txt_enable:
                            data.extend(new_data)
                            outString, data, status = mcplog.eurdbgtrace.printTrace(PHY_CTRL, data)
                            if outString:
                                txt_fp.writelines([outString, "\n"])
                                txt_fp.flush()
                        time.sleep(0.01)

            self.phy_logging_thread = threading.Thread(target=target_log_func)
            self.phy_logging_thread.daemon = True
            self.phy_logging_thread.start()
            log.info("PHY logging thread started")

            return self.phy_bin_file_path, self.phy_txt_file_path
        else:
            if getattr(self, "phy_logging_enabled", False):
                self.phy_logging_enabled = False
                self.phy_logging_thread.join(1)
                log.info("PHY logging thread stopped")

                return self.phy_bin_file_path, self.phy_txt_file_path
            else:
                return None, None

    def get_msm_counters(self):
        """Get MSM counters"""
        counters = OrderedDict([
            # Base
            ("txoct", 0), ("tx_gfm", 0), ("rxoct", 0), ("rx_gfm", 0),
            # Pause
            ("tx_pfm", 0), ("rx_pfm", 0),
            # Error
            ("txerr", 0), ("rxerr", 0), ("fcserr", 0), ("alerr", 0), ("tlerr", 0), ("irng_err", 0),
            # Vlan
            ("txvlan", 0), ("rxvlan", 0),
            # Unicast
            ("tx_ucastf", 0), ("tx_ucasto", 0), ("rx_ucastf", 0), ("rx_ucasto", 0),
            # Multicast
            ("tx_mcastf", 0), ("tx_mcasto", 0), ("rx_mcastf", 0), ("rx_mcasto", 0),
            # Broadcast
            ("tx_bcastf", 0), ("tx_bcasto", 0), ("rx_bcastf", 0), ("rx_bcasto", 0)
        ])
        counters.update(atltool.get_msm_counters(self.device_number))
        return counters

    def readmsmreg(self, addr):
        val = atltool.readmsmreg(self.device_number, addr)
        log.info("Register MSM 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
            addr, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))
        return val

    def writemsmreg(self, reg, value):
        atltool.writemsmreg(self.device_number, reg, value)
        log.info("Register MSM 0x{:08x}: 0x{:08x} written".format(reg, value))

    def dump_to_config_memory(self, data):
        def write_to_config_memory(data, ofs):
            self.writereg(0x328, data)
            self.writereg(0x32C, ofs)

            interrupt_reg = self.readreg(0x404)
            interrupt_reg |= 0x2
            self.writereg(0x404, interrupt_reg)

            start = timeit.default_timer()
            while timeit.default_timer() - start < 1.0:
                op_reg = self.readreg(0x32C)
                if (op_reg >> 0x1E) & 0x1:
                    return True
                time.sleep(0.0001)
            raise Exception("Failed to write DWORD to config memory")

        offset = 0x80000000
        for d in data:
            write_to_config_memory(d, offset)
            offset += 4

    def read_phy_dram(self):
        try:
            atltool.readphyreg(self.device_number, 0x1e, 0xc886)
        except atltool.AtltoolError:
            atltool.writereg(self.device_number, 0x3a0, 0x1)

        offset = atltool.readphyreg(self.device_number, 0x1, 0xc414)

        data = self.readphymem(offset, 768 * 4)

        log.info("PHY DRAM: [{}]".format(", ".join("0x{:08x}".format(val) for val in data)))

        return data

    def readphymem(self, addr, size):
        mem = []

        atltool.writephyreg(self.device_number, 0x1e, 0x203, addr & 0xFFFF)
        atltool.writephyreg(self.device_number, 0x1e, 0x202, (addr >> 16) & 0xFFFF)

        for i in range(size // 4):
            atltool.writephyreg(self.device_number, 0x1e, 0x200, 0x8000)

            start_time = timeit.default_timer()
            while timeit.default_timer() - start_time < 1.0:
                reg = atltool.readphyreg(self.device_number, 0x1e, 0x200)
                if reg & (1 << 8) == 0:
                    break

            lsw = atltool.readphyreg(self.device_number, 0x1e, 0x205)
            msw = atltool.readphyreg(self.device_number, 0x1e, 0x204)

            val = (msw << 16) | lsw
            mem.append(val)

        log.info("Memory at 0x{:08x}: [{}]".format(addr, ", ".join("0x{:08x}".format(m) for m in mem)))

        return mem

    def switchoff_eee_autodisable(self):
        reg = self.readreg(0x36c)
        self.writereg(0x36c, reg | 0x4000)
        self.writereg(0x36c, reg)

    def get_mii(self):
        sifStatus = atltool.readphyreg(0x4, 0xE812)
        systemIface = (sifStatus >> 3) & 0x1F
        if systemIface == 0:
            iface = constants.MII_BACKPLANE_KR
        elif systemIface == 1:
            iface = constants.MII_BACKPLANE_KX
        elif systemIface == 2:
            iface = constants.MII_MODE_XFI
        elif systemIface == 3:
            iface = constants.MII_MODE_USX_SGMII
        elif systemIface == 4:
            iface = constants.MII_XAUI
        elif systemIface == 5:
            iface = constants.MII_XAUI_PAUSE_BASED
        elif systemIface == 6:
            iface = constants.MII_MODE_SGMII
        elif systemIface == 7:
            iface = constants.MII_RXAUI
        elif systemIface == 8:
            iface = constants.MII_MAC
        elif systemIface == 9:
            iface = constants.MII_OFF
        else:
            raise Exception("Unknown System Iface")
        log.info("System Iface: {}".format(iface))
        return iface

    def read_bar4(self, address, size):
        return atltool.read_bar4(self.device_number, address, size)


class AtlToolRemote(AtlTool):
    RE_READREG = re.compile(r".*Register 0x[0-9A-Fa-f]+: (0x[0-9A-Fa-f]+) : [01 ]+", re.DOTALL)
    RE_READPHYREG = re.compile(r".*Register PHY [0-9-]+ 0x[0-9A-Fa-f]+.0x[0-9A-Fa-f]+: (0x[0-9A-Fa-f]+) : [01 ]+",
                               re.DOTALL)
    RE_READMEM = re.compile(r".*Memory at 0x[0-9A-Fa-f]+: (\[(?:0x[0-9A-Fa-f]+, )*0x[0-9A-Fa-f]+\])", re.DOTALL)
    RE_WAKE_COUNTER = re.compile(r".*Wake counter = ([0-9]+)")
    RE_WAKE_REASON = re.compile(r".*Wake reason = ([0-9]+)")
    RE_MAC_ADDRESS = re.compile(r".*MAC Address = (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})")
    RE_PHY_DRAM = re.compile(r".*PHY DRAM: (\[(?:0x[0-9A-Fa-f]+, )*0x[0-9A-Fa-f]+\])", re.DOTALL)
    RE_READMSMREG = re.compile(r".*Register MSM 0x[0-9A-Fa-f]+: (0x[0-9A-Fa-f]+) : [01 ]+", re.DOTALL)
    RE_EFUSE = re.compile(r".*eFuse data: (\[[0-9L\s,]+\])", re.DOTALL)
    RE_MII = re.compile(r".*System Iface: ([A-Za-z_]+)")

    def __init__(self, **kwargs):
        super(AtlToolRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.cmd_start = "cd {} && sudo python atltoolper.py -p {} ".format(constants.ATF_TOOLS_DIR, self.port)

    def remote_exec(self, cmd, silent=False):
        res = Command(cmd=cmd, host=self.host, silent=silent).run()
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

    def readregs(self, regs):
        cmd = self.cmd_start + "-c readregs -d \"[{}]\"".format(", ".join("0x{:08x}".format(reg) for reg in regs))
        output = self.remote_exec(cmd)
        vals = []
        for line in output:
            m = self.RE_READREG.match(line)
            if m is not None:
                vals.append(int(m.group(1), 0))
        if len(vals) != len(regs):
            raise Exception("Failed to do remote readregs command")
        return vals

    def writeregs(self, reg_val_pairs):
        super(AtlToolRemote, self).writeregs(reg_val_pairs)

        cmd = self.cmd_start + "-c writeregs -d \"[{}]\"".format(
            ", ".join("(0x{:08x}, 0x{:08x})".format(reg, val) for reg, val in reg_val_pairs))
        self.remote_exec(cmd, bool(self.out_cfg_file))

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

    def readmem(self, addr, size):
        cmd = self.cmd_start + "-c readmem -v 0x{:x} -s {}".format(addr, size)
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_READMEM.match(line)
            if m is not None:
                return eval(m.group(1))
        raise Exception("Failed to do remote readmem command")

    def readphymem(self, addr, size):
        cmd = self.cmd_start + "-c readphymem -v 0x{:x} -s {}".format(addr, size)
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_READMEM.match(line)
            if m is not None:
                return eval(m.group(1))
        raise Exception("Failed to do remote readmem command")

    def writemem(self, offset, value):
        raise NotImplemented

    def stall_a2_fw(self):
        raise NotImplemented

    def unstall_a2_fw(self):
        raise NotImplemented

    def kickstart(self, reload_phy_fw=True, clx_for_flashless=None, force_flashless=False, use_phy_reset=False,
                  drv_prov=0):
        assert use_phy_reset is False  # it must be always False, the code is left for history

        arguments = {
            "reload_phy_fw": reload_phy_fw,
            "force_flashless": force_flashless,
            "clx_for_flashless": clx_for_flashless.replace("\\", "\\\\") if clx_for_flashless else None
        }
        cmd = self.cmd_start + "-c kickstart -a \"{}\"".format(arguments)
        self.remote_exec(cmd)

    def kickstart2(self, full_reset=False, fast_reset=False, skip_phy=False, force_flashless=False, clx_path=None):
        arguments = {
            "full_reset": full_reset,
            "fast_reset": fast_reset,
            "skip_phy": skip_phy,
            "force_flashless": force_flashless,
            "clx_path": clx_path,
        }
        cmd = self.cmd_start + "-c kickstart2 -a \"{}\"".format(arguments)
        return self.remote_exec(cmd)

    def exec_beton(self, beton):
        cmd = self.cmd_start + "-c exec_beton -b \"[{}]\"".format(", ".join("'{}'".format(line) for line in beton))
        self.remote_exec(cmd)

    def exec_txt(self, beton_file, remote_file=None, file_to_upload=None):
        if remote_file is None:
            remote_file = "/tmp/remote_beton.txt"
        if file_to_upload is None:
            file_to_upload = "/tmp/remote_beton.txt"
        upload_file(self.host, beton_file, file_to_upload)
        cmd = self.cmd_start + "-c exec_txt -f {}".format(remote_file)
        return self.remote_exec(cmd)

    def get_wake_counter_2x(self):
        cmd = self.cmd_start + "-c getwakecounter2x"
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_WAKE_COUNTER.match(line)
            if m is not None:
                return int(m.group(1), 0)
        raise Exception("Failed to do remote getwakecounter2x command")

    def get_wake_reason_2x(self):
        cmd = self.cmd_start + "-c getwakereason2x"
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_WAKE_REASON.match(line)
            if m is not None:
                return int(m.group(1), 0)
        raise Exception("Failed to do remote getwakereason2x command")

    def debug_buffer_enable(self, enable_flag, bin_path=None):
        if enable_flag:
            if bin_path:
                self.bin_file_path = bin_path
            else:
                self.bin_file_path = time.strftime("mcp-%Y-%m-%d__%H-%M-%S.bin")
            self.txt_file_path = os.path.splitext(self.bin_file_path)[0] + ".log"

            cmd = self.cmd_start + "-c enablelogging -f ~/{}".format(self.bin_file_path)
            self.remote_log_cmd = Command(cmd=cmd, host=self.host)
            self.remote_log_cmd.run_async()
            log.info("MCP remote logging started")

            # Files don't exist yet, return None
            return None, None
        else:
            Command(cmd="cd {} && touch atltoolper_stop".format(constants.ATF_TOOLS_DIR), host=self.host).run()
            time.sleep(1)
            self.remote_log_cmd.join(0)

            bin_file = "remote_{}".format(self.bin_file_path)
            txt_file = "remote_{}".format(self.txt_file_path)

            download_file(self.host, "~/{}".format(self.bin_file_path), bin_file)
            download_file(self.host, "~/{}".format(self.txt_file_path), txt_file)

            Command(cmd="sudo rm {} {}".format(self.bin_file_path, self.txt_file_path), host=self.host).run()

            return bin_file, txt_file

    def read_phy_dbg_buffer(self, enable_flag, bin_path=None, txt_enable=True):
        if enable_flag:
            if bin_path:
                self.phy_bin_file_path = bin_path
            else:
                self.phy_bin_file_path = time.strftime("phy_dbg_buf-%Y-%m-%d__%H-%M-%S.bin")
            self.phy_txt_file_path = os.path.splitext(self.phy_bin_file_path)[0] + ".log"

            cmd = self.cmd_start + "-c enablephylogging -f ~/{}".format(self.phy_bin_file_path)
            self.remote_log_cmd = Command(cmd=cmd, host=self.host)
            self.remote_log_cmd.run_async()
            log.info("PHY remote logging started")

            # Files don't exist yet, return None
            return None, None
        else:
            Command(cmd="cd {} && touch atltoolper_phy_stop".format(constants.ATF_TOOLS_DIR), host=self.host).run()
            time.sleep(1)
            self.remote_log_cmd.join(0)

            bin_file = "remote_{}".format(self.phy_bin_file_path)
            txt_file = "remote_{}".format(self.phy_txt_file_path)

            download_file(self.host, "~/{}".format(self.phy_bin_file_path), bin_file)
            download_file(self.host, "~/{}".format(self.phy_txt_file_path), txt_file)

            Command(cmd="sudo rm {} {}".format(self.phy_bin_file_path, self.phy_txt_file_path), host=self.host).run()

            return bin_file, txt_file

    def dump_to_config_memory(self, data):
        cmd = self.cmd_start + "-c dumpconfig -d \"[{}]\"".format(", ".join("{}".format(d) for d in data))
        self.remote_exec(cmd)

    def get_mac_address(self):
        cmd = self.cmd_start + "-c getmacaddress"
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_MAC_ADDRESS.match(line)
            if m is not None:
                return m.group(1)
        raise Exception("Failed to do remote getmacaddress command")

    def read_phy_dram(self):
        cmd = self.cmd_start + "-c readphydram"
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_PHY_DRAM.match(line)
            if m is not None:
                return eval(m.group(1))
        raise Exception("Failed to do remote readphydram command")

    def readmsmreg(self, addr):
        cmd = self.cmd_start + "-c readmsmreg -r 0x{:x}".format(addr)
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_READMSMREG.match(line)
            if m is not None:
                return int(m.group(1), 0)
        raise Exception("Failed to do remote readreg command")

    def writemsmreg(self, addr, value):
        cmd = self.cmd_start + "-c writemsmreg -r 0x{:x} -v 0x{:x}".format(addr, value)
        self.remote_exec(cmd)

    def get_msm_counters(self):
        counters = {}
        cmd = self.cmd_start + "-c getmsmcounters"
        output = self.remote_exec(cmd)
        re_cnt = re.compile(r".*    ([a-zA-Z_]+) = ([0-9]+)$", re.DOTALL)
        for line in output:
            m = re_cnt.match(line)
            if m is not None:
                counters[m.group(1)] = int(m.group(2), 0)
        return counters

    def load_efuse(self, first_dw, num_dw):
        cmd = self.cmd_start + "-c loadefuse --value {} --size {}".format(first_dw, num_dw)
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_EFUSE.match(line)
            if m is not None:
                return eval(m.group(1))
        raise Exception("Failed to do remote load_efuse command")

    def switchoff_eee_autodisable(self):
        cmd = self.cmd_start + "-c switchoff_eee_autodisable".format()
        self.remote_exec(cmd)

    def get_mii(self):
        cmd = self.cmd_start + "-c get_mii".format()
        output = self.remote_exec(cmd)
        for line in output:
            m = self.RE_MII.match(line)
            if m is not None:
                return m.group(1)
        raise Exception("Failed get MII")

    def set_link_params_2x(self, speed, eee=False):
        cmd = self.cmd_start + "-c setlinkparams2x --speed {}".format(speed)
        if eee:
            cmd = cmd + " --eee {}".format(eee)
        self.remote_exec(cmd)

    def is_secure_chips(self):
        cmd = self.cmd_start + "-c securechips"
        output = self.remote_exec(cmd)
        secure = False
        for line in output:
            log.info("line:{}".format(line))
            if "Secure chip" in line:
                secure = True
        return secure


class AtlToolArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("{}".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = AtlToolArgumentParser()
    parser.add_argument("-p", "--port", help="PCI port, i.e. pci1.00.0, ...", type=str, required=True)
    parser.add_argument("-c", "--command", help="Command to be performed", type=str, required=True,
                        choices=["readreg",
                                 "writereg",
                                 "readregs",
                                 "writeregs",
                                 "readphyreg",
                                 "writephyreg",
                                 "readmem",
                                 "readphymem",
                                 "kickstart",
                                 "kickstart2",
                                 "exec_beton",
                                 "exec_txt",
                                 "getwakecounter2x",
                                 "getwakereason2x",
                                 "enablelogging",
                                 "dumpconfig",
                                 "getmacaddress",
                                 "enablephylogging",
                                 "readphydram",
                                 "readmsmreg",
                                 "writemsmreg",
                                 "loadefuse",
                                 "getmsmcounters",
                                 "switchoff_eee_autodisable",
                                 "get_mii",
                                 "setlinkparams2x",
                                 "securechips"])
    parser.add_argument("-r", "--register", help="MAC (1 integer) or PHY (2 integers) register", nargs="+",
                        type=auto_int)
    parser.add_argument("-v", "--value", help="Integer value (i.e. to write to register or memory address)",
                        type=auto_int)
    parser.add_argument("-s", "--size", help="Size in bytes", type=auto_int)
    parser.add_argument("-a", "--arguments", help="Additional arguments for command", type=str, action=SpacedArgAction,
                        nargs="+")
    parser.add_argument("-b", "--beton", help="Array of beton code lines (should be evaluated)", type=str,
                        action=SpacedArgAction, nargs="+")
    parser.add_argument("-d", "--data", help="Array of binary data (list of integers)", type=str,
                        action=SpacedArgAction, nargs="+")
    parser.add_argument("-f", "--file", help="File path", type=str)
    parser.add_argument("--speed", help="Speed", type=str)
    parser.add_argument("--eee", help="EEE True or False", type=str)
    args = parser.parse_args()

    try:
        atltool_wrapper = AtlTool(port=args.port)

        if args.command == "readreg":
            if args.register is not None and len(args.register) == 1:
                atltool_wrapper.readreg(args.register[0])
            else:
                log.error("To read MAC register, it must be specified (1 int number)")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "securechips":
            atltool_wrapper.is_secure_chips()
        elif args.command == "writereg":
            if args.register is not None and len(args.register) == 1 and args.value is not None:
                atltool_wrapper.writereg(args.register[0], args.value)
            else:
                log.error("To write MAC register, register (1 int number) and value must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "readregs":
            regs = eval(args.data)
            atltool_wrapper.readregs(regs)
        elif args.command == "writeregs":
            reg_val_pairs = eval(args.data)
            atltool_wrapper.writeregs(reg_val_pairs)
        elif args.command == "readphyreg":
            if args.register is not None and len(args.register) == 2:
                atltool_wrapper.readphyreg(args.register[0], args.register[1])
            else:
                log.error("To read PHY register, it must be specified (2 int numbers)")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "writephyreg":
            if args.register is not None and len(args.register) == 2 and args.value is not None:
                atltool_wrapper.writephyreg(args.register[0], args.register[1], args.value)
            else:
                log.error("To write PHY register, register (2 int numbers) and value must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "readmem":
            if args.value is None or args.size is None:
                log.error("To read MCP memory, value of address and size must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            atltool_wrapper.readmem(args.value, args.size)
        elif args.command == "readphymem":
            if args.value is None or args.size is None:
                log.error("To read PHY memory, value of address and size must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            atltool_wrapper.readphymem(args.value, args.size)
        elif args.command == "kickstart":
            if args.arguments is not None:
                arguments = eval(args.arguments)
            else:
                arguments = {}
            atltool_wrapper.kickstart(**arguments)
        elif args.command == "kickstart2":
            if args.arguments is not None:
                arguments = eval(args.arguments)
            else:
                arguments = {}
            atltool_wrapper.kickstart2(**arguments)
        elif args.command == "exec_beton":
            if args.beton is None:
                raise Exception("Beton code must be specified to execute it")
            beton = eval(args.beton)
            atltool_wrapper.exec_beton(beton)
        elif args.command == "exec_txt":
            if args.file is None:
                raise Exception("To execute txt script, file path must be specified")
            if os.path.exists(args.file):
                atltool_wrapper.exec_txt(args.file)
            elif url_file_exists(args.file):
                beton = get_url_response(args.file).splitlines()
                atltool_wrapper.exec_beton(beton)
            else:
                raise Exception("File or URl doesn't exist: {}".format(args.file))
        elif args.command == "getwakecounter2x":
            wake_counter = atltool_wrapper.get_wake_counter_2x()
            log.info("Wake counter = {}".format(wake_counter))
        elif args.command == "getwakereason2x":
            wake_reason = atltool_wrapper.get_wake_reason_2x()
            log.info("Wake reason = {}".format(wake_reason))
        elif args.command == "enablelogging":
            bin_file_path = args.file if args.file else time.strftime("mcp-%Y-%m-%d__%H-%M-%S.bin")
            txt_file_path = os.path.splitext(bin_file_path)[0] + ".log"

            stop_flag_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "atltoolper_stop")

            with open(bin_file_path, "ab") as bin_fp, open(txt_file_path, "a") as txt_fp:
                data = []

                dbgtrace = mcplog.mdbgtrace.DebugTrace(phycontrol=AtlTool_PhyCtrl(atltool_wrapper.device_number),
                                                       fw_v=atltool_wrapper.get_fw_version()[0])

                while not os.path.exists(stop_flag_file):
                    try:
                        new_data = atltool.readlog(atltool_wrapper.device_number)
                        bin_fp.write("".join(map(lambda x: struct.pack("H", x), new_data)))
                        bin_fp.flush()
                        data.extend(new_data)
                        outString, data, status = dbgtrace.printTrace(data)
                        if outString:
                            txt_fp.writelines([outString, "\n"])
                            txt_fp.flush()
                        # time.sleep(0.01)
                    except KeyboardInterrupt:
                        break

            tries = 5
            while tries > 0:
                remove_file(stop_flag_file)
                if not os.path.exists(stop_flag_file):
                    break
                time.sleep(0.5)
                tries -= 1

            if tries == 0:
                raise Exception("Couldn't remove stop flag file: {}".format(stop_flag_file))
        elif args.command == "dumpconfig":
            data = eval(args.data)
            atltool_wrapper.dump_to_config_memory(data)
        elif args.command == "getmacaddress":
            mac_address = atltool_wrapper.get_mac_address()
            log.info("MAC Address = {}".format(mac_address))
        elif args.command == "enablephylogging":
            bin_file_path = args.file if args.file else time.strftime("phy_dbg_buf-%Y-%m-%d__%H-%M-%S.bin")
            txt_file_path = os.path.splitext(bin_file_path)[0] + ".log"

            stop_flag_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "atltoolper_phy_stop")

            with open(bin_file_path, "ab") as bin_fp, open(txt_file_path, "a") as txt_fp:
                data = []

                PHY_CTRL = AtlTool_PhyCtrl(atltool_wrapper.device_number)

                while not os.path.exists(stop_flag_file):
                    try:
                        new_data = atltool.readphylog(atltool_wrapper.device_number)
                        bin_fp.write("".join(map(lambda x: struct.pack("H", x), new_data)))
                        bin_fp.flush()
                        data.extend(new_data)
                        outString, data, status = mcplog.eurdbgtrace.printTrace(PHY_CTRL, data)
                        if outString:
                            txt_fp.writelines([outString, "\n"])
                            txt_fp.flush()
                        # time.sleep(0.01)
                    except KeyboardInterrupt:
                        break

            tries = 5
            while tries > 0:
                remove_file(stop_flag_file)
                if not os.path.exists(stop_flag_file):
                    break
                time.sleep(0.5)
                tries -= 1

            if tries == 0:
                raise Exception("Couldn't remove stop flag file: {}".format(stop_flag_file))
        elif args.command == "readphydram":
            phy_dram = atltool_wrapper.read_phy_dram()
        elif args.command == "readmsmreg":
            if args.register is not None and len(args.register) == 1:
                atltool_wrapper.readmsmreg(args.register[0])
            else:
                log.error("To read MSM register, it must be specified (1 int number)")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "writemsmreg":
            if args.register is not None and len(args.register) == 1 and args.value is not None:
                atltool_wrapper.writemsmreg(args.register[0], args.value)
            else:
                log.error("To write MSM register, register (1 int number) and value must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
        elif args.command == "getmsmcounters":
            counters = atltool_wrapper.get_msm_counters()
            for k, v in counters.items():
                log.info("    {} = {}".format(k, v))
        elif args.command == "loadefuse":
            if args.value is None or args.size is None:
                log.error("To read efuse, value of first dword and number of dwords must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            dwords = atltool_wrapper.load_efuse(args.value, args.size)
            log.info("eFuse data: {}".format(dwords))
        elif args.command == "switchoff_eee_autodisable":
            atltool_wrapper.switchoff_eee_autodisable()
        elif args.command == "get_mii":
            atltool_wrapper.get_mii()
        elif args.command == "setlinkparams2x":
            if args.speed is None:
                log.error("Speed must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            if args.eee is None:
                atltool_wrapper.set_link_params_2x(args.speed)
            else:
                atltool_wrapper.set_link_params_2x(args.speed, args.eee)
    except Exception:
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
