import os
import re
import socket

from command import Command
from log import get_atf_logger
from utils import get_bus_dev_func

log = get_atf_logger()

is_running_on_dut = "LKP_HOSTNAME" in os.environ or "DUT_HOSTNAME" not in os.environ
dut_hostname = socket.gethostname() if is_running_on_dut else os.environ["DUT_HOSTNAME"]

lkp_hostname = None
if "LKP_HOSTNAME" in os.environ:
    lkp_hostname = os.environ["LKP_HOSTNAME"]
elif "DUT_HOSTNAME" in os.environ:
    lkp_hostname = socket.gethostname()


def print_mac_reg(reg, val):
    if val != "???":
        log.info("Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
            reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))
    else:
        log.info("Register 0x{:08x}: {}".format(reg, val))


def print_phy_reg(mmd, reg, val):
    if val != "???":
        log.info("Register PHY 0 0x{:02x}.0x{:04x}: 0x{:04x} : {:08b} {:08b}".format(
            mmd, reg, val, (val >> 8) & 0xFF, val & 0xFF))
    else:
        log.info("Register PHY 0 0x{:02x}.0x{:04x}: {}".format(mmd, reg, val))


def collect_mac_registers():
    re_reg = re.compile(r"Register .*: ([x0-9a-fA-F]+) : [01 ]+")

    def readreg(host, port, reg):
        bus, dev, func = map(int, get_bus_dev_func(port))
        res = Command(cmd="sudo atltool -d {:02x}:{:02x}.{:x} -rr 0x{:08x}".format(
            bus, dev, func, reg), host=host).wait(10)
        if res["returncode"] == 0:
            for line in res["output"]:
                m = re_reg.match(line)
                if m is not None:
                    val = int(m.group(1), 16)
                    break
            else:
                val = "???"
        else:
            val = "???"

        return val

    registers = [0x354, 0x358, 0x368, 0x36c, 0x370, 0x374, 0x380]

    dut_registers = None
    lkp_registers = None

    if os.environ["DUT_FW_CARD"] != "Fiji":
        dut_registers = []
        for reg in registers:
            dut_registers.append((reg, readreg(dut_hostname, os.environ["DUT_PORT"], reg)))

    if os.environ["LKP_FW_CARD"] != "Fiji" and lkp_hostname is not None:
        lkp_registers = []
        for reg in registers:
            lkp_registers.append((reg, readreg(lkp_hostname, os.environ["LKP_PORT"], reg)))

    return dut_registers, lkp_registers


def collect_phy_registers():
    re_reg = re.compile(r"Register PHY .*: ([x0-9a-fA-F]+) : [01 ]+")

    def readphyreg(host, port, mmd, reg):
        bus, dev, func = map(int, get_bus_dev_func(port))
        res = Command(cmd="sudo atltool -d {:02x}:{:02x}.{:x} -rpr 0x{:x}.0x{:x}".format(
            bus, dev, func, mmd, reg), host=host).wait(10)
        if res["returncode"] == 0:
            for line in res["output"]:
                m = re_reg.match(line)
                if m is not None:
                    val = int(m.group(1), 16)
                    break
            else:
                val = "???"
        else:
            val = "???"

        return val

    registers = [
        (0x7, 0xc810),
        (0x4, 0xe812)
    ]

    dut_registers = None
    lkp_registers = None

    if os.environ["DUT_FW_CARD"] not in ["Fiji", "Felicity"]:
        dut_registers = []
        for mmd, reg in registers:
            dut_registers.append((mmd, reg, readphyreg(dut_hostname, os.environ["DUT_PORT"], mmd, reg)))

    if os.environ["LKP_FW_CARD"] not in ["Fiji", "Felicity"] and lkp_hostname is not None:
        lkp_registers = []
        for mmd, reg in registers:
            lkp_registers.append((mmd, reg, readphyreg(lkp_hostname, os.environ["LKP_PORT"], mmd, reg)))

    return dut_registers, lkp_registers


def collect_counters():

    def readstat_dma_c(host):
        res = Command(cmd="sudo readstat -dma_c", host=host).wait(10)

    def readstat_msm_c(host):
        res = Command(cmd="sudo readstat -msm_c", host=host).wait(10)

    def readstat_phy_c(host):
        res = Command(cmd="sudo readstat -phy_c", host=host).wait(10)

    if os.environ["DUT_FW_CARD"] != "Fiji":
        log.info("!!! ========== ========== DUT DMA COUNTERS ========== ========== !!!")
        readstat_dma_c(dut_hostname)

        log.info("!!! ========== ========== DUT MSM COUNTERS ========== ========== !!!")
        readstat_msm_c(dut_hostname)

        if os.environ["DUT_FW_CARD"] != "Felicity":
            log.info("!!! ========== ========== DUT PHY COUNTERS ========== ========== !!!")
            readstat_phy_c(dut_hostname)

    if os.environ["LKP_FW_CARD"] != "Fiji":
        log.info("!!! ========== ========== LKP DMA COUNTERS ========== ========== !!!")
        readstat_dma_c(lkp_hostname)

        log.info("!!! ========== ========== LKP MSM COUNTERS ========== ========== !!!")
        readstat_msm_c(lkp_hostname)

        if os.environ["LKP_FW_CARD"] != "Felicity":
            log.info("!!! ========== ========== LKP PHY COUNTERS ========== ========== !!!")
            readstat_phy_c(lkp_hostname)


def collect_mcp_logs():
    def trace_mcp_log(host, port, enable_phy_log):
        bus, dev, func = map(int, get_bus_dev_func(port))
        cmd = "sudo python ~/qa-tests/tools/mcplog/readlog.py -p {:02x}:{:02x}.{:x} -t 5".format(bus, dev, func)
        if enable_phy_log:
            cmd += " --phy"
        Command(cmd=cmd, host=host).wait(10)

    if os.environ["DUT_FW_CARD"] != "Fiji":
        log.info("!!! ========== ========== DUT MCP LOG ========== ========== !!!")
        # trace_mcp_log(dut_hostname, os.environ["DUT_PORT"], os.environ["DUT_FW_CARD"] in ["Nikki", "Bermuda"])
        trace_mcp_log(dut_hostname, os.environ["DUT_PORT"], False)

    if os.environ["LKP_FW_CARD"] != "Fiji" and lkp_hostname is not None:
        log.info("!!! ========== ========== LKP MCP LOG ========== ========== !!!")
        # trace_mcp_log(lkp_hostname, os.environ["LKP_PORT"], os.environ["LKP_FW_CARD"] in ["Nikki", "Bermuda"])
        trace_mcp_log(lkp_hostname, os.environ["LKP_PORT"], False)


def collect_debug_info():
    # Simple self-checks
    if "DUT_PORT" not in os.environ:
        log.info("There is no DUT port, probably running not in ATF environment?!")
        return

    log.info("!!! ========== ========== BEGIN COLLECT DEBUG INFO ========== ========== !!!")
    dut_mac_registers, lkp_mac_registers = collect_mac_registers()
    dut_phy_registers, lkp_phy_registers = collect_phy_registers()

    if dut_mac_registers is not None:
        log.info("!!! ========== ========== DUT MAC REGISTERS ========== ========== !!!")
        for reg, val in dut_mac_registers:
            print_mac_reg(reg, val)

    if lkp_mac_registers is not None:
        log.info("!!! ========== ========== LKP MAC REGISTERS ========== ========== !!!")
        for reg, val in lkp_mac_registers:
            print_mac_reg(reg, val)

    if dut_phy_registers is not None:
        log.info("!!! ========== ========== DUT PHY REGISTERS ========== ========== !!!")
        for mmd, reg, val in dut_phy_registers:
            print_phy_reg(mmd, reg, val)

    if lkp_phy_registers is not None:
        log.info("!!! ========== ========== LKP PHY REGISTERS ========== ========== !!!")
        for mmd, reg, val in lkp_phy_registers:
            print_phy_reg(mmd, reg, val)

    collect_mcp_logs()
    collect_counters()
    log.info("!!! ========== ========== END COLLECT DEBUG INFO ========== ========== !!!")
