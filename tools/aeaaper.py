import argparse
import re
import struct
import time
import timeit
from abc import abstractmethod, ABCMeta

from command import Command
from constants import ATF_TOOLS_DIR
from ifconfig import get_macos_network_adapter_name
from utils import get_atf_logger, SpacedArgAction, download_file, remove_file

SCRIPT_STATUS_SUCCESS = "[AEAA-WRAPPER-SUCCESS]"
SCRIPT_STATUS_FAILED = "[AEAA-WRAPPER-FAILED]"

log = get_atf_logger()


class KickstartError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class AeaaWrapper(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost":
            return object.__new__(AeaaWrapperLocal)
        else:
            return object.__new__(AeaaWrapperRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]

    def _bin_file_to_int_list(self, file_path, byte_size):
        assert byte_size % 4 == 0
        data = []
        with open(file_path, "rb") as f:
            for _ in range(byte_size / 4):
                d, = struct.unpack("I", f.read(4))
                data.append(d)
        return data

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
    def readmem(self, addr, size):
        pass

    @abstractmethod
    def kickstart(self, reload_phy_fw=True, clx_for_flashless=None, force_flashless=False, use_phy_reset=False):
        pass


class AeaaWrapperLocal(AeaaWrapper):

    cached_iface = None
    cached_iface_last_check = 0
    CACHED_IFACE_TIMEOUT = 10

    def get_iface(self):
        if self.cached_iface is None or \
                timeit.default_timer() - self.cached_iface_last_check > self.CACHED_IFACE_TIMEOUT:
            self.cached_iface_last_check = timeit.default_timer()
            self.cached_iface = get_macos_network_adapter_name(self.port)
        return self.cached_iface

    def readreg(self, reg):
        iface = self.get_iface()
        res = Command(cmd="sudo aeaa_util bar0 -i {} 0x{:x}".format(iface, reg)).run()
        if res["returncode"] != 0:
            raise Exception("Failed to read register 0x{:x} via aeaa_util".format(reg))
        val = int(res["output"][0].rstrip(), 16)
        log.info("Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
            reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))
        return val

    def writereg(self, reg, value):
        iface = self.get_iface()
        res = Command(cmd="sudo aeaa_util bar0 -i {} 0x{:x} 0x{:x}".format(iface, reg, value)).run()
        if res["returncode"] != 0:
            raise Exception("Failed to write value 0x{:08x} to register 0x{:x} via aeaa_util".format(
                value, reg))
        log.info("Register 0x{:08x}: 0x{:08x} written".format(reg, value))

    def readphyreg(self, mmd, reg):
        iface = self.get_iface()
        res = Command(cmd="sudo aeaa_util mii -i {} 0x{:x} 0x{:x}".format(iface, mmd, reg)).run()
        if res["returncode"] != 0:
            raise Exception("Failed to read PHY register 0x{:x}.0x{:x} via aeaa_util".format(mmd. reg))
        val = int(res["output"][0].rstrip(), 16)
        log.info("Register PHY 0 0x{:x}.0x{:x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
            mmd, reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))
        return val

    def writephyreg(self, mmd, reg, value):
        iface = self.get_iface()
        res = Command(cmd="sudo aeaa_util mii -i {} 0x{:x} 0x{:x} 0x{:08x}".format(iface, mmd, reg, value)).run()
        if res["returncode"] != 0:
            raise Exception("Failed to write PHY register 0x{:x}.0x{:x} value 0x{:08x} via aeaa_util".format(
                mmd. reg, value))
        log.info("Register PHY 0 0x{:x}.0x{:x}: 0x{:08x} written".format(mmd, reg, value))

    def kickstart(self, reload_phy_fw=True, clx_for_flashless=None, force_flashless=False, use_phy_reset=False):
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

            self.writereg(0x404, 0x80e0)
            # Let Felicity hardware to complete SMBUS transaction before Global software reset
            time.sleep(0.050)  # pause 50 ms
            self.writereg(0x3a0, 1)

            # PHY Kickstart
            if reload_phy_fw:
                log.info("Kickstarting PHY")
                # Enable MDIO control clock. Due to all the operation through MDIO require it but aeaa_util
                # doesn't enables it. So it's workaround for aeaa_util behavior
                reg = self.readreg(0x280)
                reg &= ~0x4000
                self.writereg(0x280, reg)
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

                reg = self.readreg(0x280)
                reg |= 0x4000
                self.writereg(0x280, reg)
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

            for k in range(1000):
                restart_completed = self.readreg(0x18)
                if restart_completed != 0:
                    break
                time.sleep(0.010)  # pause 10 ms
            if restart_completed == 0:
                raise KickstartError("FW restart failed")
            k *= 10
            log.info("Firmware restart duration: {} ms".format(k))
        else:
            log.info("RBL is enabled")
            self.writereg(0x404, 0x40e1)
            self.writereg(0x3a0, 1)
            self.writereg(0x32a8, 0x0)
            # MAC FW will reload PHY FW if 1E.1000.3 was cleaned
            if reload_phy_fw:
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
                self.writereg(0x534, 0)
            self.writereg(0x404, 0x40e0)

            log.info("Wait until RBL boot code completed")
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

            """
            # We can perform flashless boot load here
            if restart_completed == 0xF1A7 and clx_for_flashless is not None:
                log.info("Loading FW from host: {}".format(clx_for_flashless))
                self.exec_beton('mac.loadfw -f {} -C 0xe2'.format(clx_for_flashless))
            """

            for k in range(1000):
                restart_completed = self.readreg(0x18)
                if restart_completed != 0:
                    break
                time.sleep(0.010)  # pause 10 ms
            if restart_completed == 0:
                raise KickstartError("FW restart failed")
            k *= 10
            log.info("FW restart duration: {} ms".format(k))

        time.sleep(3)  # to make sure Flash iface is not locked by reading from FW
        log.info("Kickstart is done")

    def nvram(self, file_path):
        iface = self.get_iface()

        # Disable adapter before burning FW
        res = Command(cmd="sudo ifconfig {} down".format(iface)).wait(10)
        if res["returncode"] != 0:
            raise Exception("Failed to disable adapter")

        cmd = 'sudo aeaa_util nvram -i {} -w "{}"'.format(iface, file_path)
        res = Command(cmd=cmd).run_join(600)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to burn firmware via aeaa_util")
        if not any(["Nvram update Successful" in line for line in res["output"]]):
            raise Exception("Nvram failed")
        for line in res["output"]:
            if "Unable to open" in line:
                raise Exception("Failed to burn firmware via aeaa_util")

        # Disable adapter before burning FW
        res = Command(cmd="sudo ifconfig {} up".format(iface)).wait(10)
        if res["returncode"] != 0:
            raise Exception("Failed to disable adapter")

    def readmem(self, addr, size):
        assert size % 4 == 0

        iface = self.get_iface()
        res = Command(cmd="sudo aeaa_util stats -i {} -m {} {}".format(iface, hex(addr), hex(size))).wait(10)
        if res["returncode"] != 0:
            raise Exception("Failed to read MCP memory")
        return self._bin_file_to_int_list("mcp_mem_file.bin", size)


class AeaaWrapperRemote(AeaaWrapper):
    def __init__(self, **kwargs):
        super(AeaaWrapperRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).wait(30)
        if not any(SCRIPT_STATUS_SUCCESS in line for line in res["output"]) or res["returncode"] != 0 or \
                res["reason"] != Command.REASON_OK:
            log.error("Failed to execute command '{}' on host '{}', output:".format(cmd, self.host))
            log.debug("\n".join(["", "-" * 80] + res["output"] + ["-" * 80]))
            raise Exception("Failed to perform remote aeaaper operation")
        return res["output"]

    def readreg(self, reg):
        cmd = "cd {} && python aeaaper.py -p {} -c readreg -r 0x{:x}".format(ATF_TOOLS_DIR, self.port, reg)
        output = self.remote_exec(cmd)
        re_reg_value = re.compile(".*Register 0x[0-9A-Fa-f]+: (0x[0-9A-Fa-f]+) : [01 ]+", re.DOTALL)
        for line in output:
            m = re_reg_value.match(line)
            if m is not None:
                return int(m.group(1), 16)
        raise Exception("Failed to read register 0x{:x} on host {}".format(reg, self.host))

    def writereg(self, addr, value):
        cmd = "cd {} && python aeaaper.py -p {} -c writereg -r 0x{:08x} -v 0x{:08x}".format(
            ATF_TOOLS_DIR, self.port, addr, value)
        self.remote_exec(cmd)

    def readphyreg(self, mmd, reg):
        cmd = "cd {} && python aeaaper.py -p {} -c readphyreg -m 0x{:x} -r 0x{:x}".format(
            ATF_TOOLS_DIR, self.port, mmd, reg)
        output = self.remote_exec(cmd)
        re_reg_value = re.compile(".*Register PHY [0-9]+ [0-9a-fxA-FX\.]+: ([0-9a-fxA-FX]+).*")
        for line in output:
            m = re_reg_value.match(line)
            if m is not None:
                return int(m.group(1), 16)
        raise Exception("Failed to read PHY register 0x{:x}.0x{:x} on host {}".format(mmd, reg, self.host))

    def writephyreg(self, mmd, reg, value):
        cmd = "cd {} && python aeaaper.py -p {} -c writephyreg -m 0x{:x} -r 0x{:x} -v 0x{:08x}".format(
            ATF_TOOLS_DIR, self.port, mmd, reg, value)
        self.remote_exec(cmd)

    def readmem(self, addr, size):
        cmd = "cd {} && python aeaaper.py -p {} -c readmem -v 0x{:x} -s 0x{:x}".format(
            ATF_TOOLS_DIR, self.port, addr, size)
        output = self.remote_exec(cmd)
        assert any("dumping to mcp_mem_file.bin" in line for line in output)
        remote_file = "~/qa-tests/tools/mcp_mem_file.bin"  # TODO: hardcoded path
        local_file = "mcp_mem_file.bin"
        download_file(self.host, remote_file, local_file)
        data = self._bin_file_to_int_list(local_file, size)
        remove_file(local_file)
        return data

    def kickstart(self, reload_phy_fw=True, clx_for_flashless=None, force_flashless=False, use_phy_reset=False):
        raise NotImplementedError()


class AeaaperArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("{}".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "%s: error: %s\n" % (self.prog, message))


if __name__ == "__main__":
    parser = AeaaperArgumentParser()
    parser.add_argument("-p", "--port", help="PCI port, i.e. pci0.00.0, ...", type=str, required=True)
    parser.add_argument("-c", "--command", type=str, required=True,
                        choices=["readreg", "writereg", "readphyreg", "writephyreg", "readmem", "kickstart", "nvram"],
                        help="Command to be performed")
    parser.add_argument("-r", "--reg", type=str, help="Register address")
    parser.add_argument("-m", "--mmd", type=str, help="MMD address")
    parser.add_argument("-v", "--value", help="Integer value (i.e. to write to register or memory address)")
    parser.add_argument("-s", "--size", help="Size in bytes")
    parser.add_argument("-f", "--file", type=str, help="CLX file path")
    parser.add_argument("-a", "--arguments", help="Additional arguments for command", type=str, action=SpacedArgAction,
                        nargs="+")
    args = parser.parse_args()

    try:
        aeaa_wrapper = AeaaWrapper(port=args.port)

        if args.command == "readreg":
            if args.reg is None or args.port is None:
                raise Exception("Port and reg must be specified to read register")
            aeaa_wrapper.readreg(int(args.reg, 16))
        if args.command == "writereg":
            if args.reg is None or args.port is None or args.value is None:
                raise Exception("Port, reg and value must be specified to write register")
            aeaa_wrapper.writereg(int(args.reg, 16), int(args.value, 16))
        if args.command == "readphyreg":
            if args.reg is None or args.mmd is None or args.port is None:
                raise Exception("Port, mmd and reg must be specified to read PHY register")
            aeaa_wrapper.readphyreg(int(args.mmd, 16), int(args.reg, 16))
        if args.command == "writephyreg":
            if args.reg is None or args.mmd is None or args.port is None or args.value is None:
                raise Exception("Port, mmd, reg and value must be specified to write PHY register")
            aeaa_wrapper.writephyreg(int(args.mmd, 16), int(args.reg, 16), int(args.value, 16))
        if args.command == "readmem":
            if args.value is None or args.size is None or args.port is None:
                raise Exception("Port, base address and size must be specified to read register")
            data = aeaa_wrapper.readmem(int(args.value, 16), int(args.size, 16))
            log.info("Memory at 0x{:08x}: [{}]".format(
                int(args.value, 16), ", ".join("0x{:08x}".format(m) for m in data)))
        if args.command == "kickstart":
            if args.arguments is not None:
                arguments = eval(args.arguments)
            else:
                arguments = {}
            aeaa_wrapper.kickstart(**arguments)
        if args.command == "nvram":
            if args.port is None or args.file is None:
                raise Exception("Port and file are needed to update firmware")
            aeaa_wrapper.nvram(args.file)
    except Exception:
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
