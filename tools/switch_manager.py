import argparse
import math
import re
import time

from abc import abstractmethod, ABCMeta

import telnet
from utils import get_atf_logger

log = get_atf_logger()

try:
    from _hardwareInterfaceFTDI import HW_Error, HW_Initialize, HW_DeviceList, HW_OpenAdapter, HW_CloseAdapter, \
        HW_Read32, HW_Write32
except Exception:
    log.warning("Failed to load _hardwareInterfaceFTDI.pyd")
    pass

SCRIPT_STATUS_SUCCESS = "[SWITCH-MANAGER-SUCCESS]"
SCRIPT_STATUS_FAILED = "[SWITCH-MANAGER-FAILED]"

SWITCH_VENDOR_CISCO = "Cisco"
SWITCH_VENDOR_AQUANTIA_SMBUS = "AquantiaSMBus"


class SwitchManager:
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        vendor = kwargs.get("vendor", None)
        if vendor == SWITCH_VENDOR_CISCO:
            return object.__new__(CiscoSwitchManager)
        if vendor == SWITCH_VENDOR_AQUANTIA_SMBUS:
            return object.__new__(AquantiaSMBusSwitchManager)
        else:
            raise Exception("Unknown switch vendor {}".format(vendor))

    def __init__(self, **kwargs):
        self.vendor = kwargs["vendor"]

    @abstractmethod
    def show_counters(self):
        pass

    @abstractmethod
    def get_debug_counters(self):
        pass

    @abstractmethod
    def get_mac_address_table(self):
        pass

    @abstractmethod
    def find_mac_table_entry(self):
        pass

    @abstractmethod
    def clear_mac_table(self):
        pass

    @abstractmethod
    def turn_off_spanning_tree(self):
        pass

    @abstractmethod
    def defcfg(self):
        pass

    @abstractmethod
    def reset(self):
        pass

    @abstractmethod
    def set_max_frame_size(self):
        pass

    @abstractmethod
    def get_mac_addrs_num(self):
        pass

    @abstractmethod
    def set_ager_time(self):
        pass

    @abstractmethod
    def set_ager_state(self):
        pass

    @abstractmethod
    def add_static_mac_entry(self):
        pass

    @abstractmethod
    def set_ingress_port_mirroring(self, from_port, to_port):
        pass

    @abstractmethod
    def set_egress_port_mirroring(self, from_port, to_port):
        pass

    @abstractmethod
    def set_egress_rate(self):
        pass

    @abstractmethod
    def enable_rate_shaper(self):
        pass


class CiscoSwitchManager(SwitchManager):
    def __init__(self, **kwargs):
        super(CiscoSwitchManager, self).__init__(**kwargs)
        self.host = kwargs.get("host", "cisco1.rdc-lab.marvell.com")
        self.user = kwargs.get("user", "admin")
        self.password = kwargs.get("password", "NetLohP@s$")

        vlan_id = 600
        log.info("Turning off spanning tree for {} vlan".format(vlan_id))
        self.turn_off_spanning_tree(vlan_id)

    @staticmethod
    def convert_mac_address(mac_address):
        """Convert MAC from AA:AA:AA:AA:AA:AA format to AAAA.AAAA.AAAA"""
        split_mac = mac_address.split(":")
        one_str = "".join(split_mac)
        return one_str[:4] + '.' + one_str[4:8] + '.' + one_str[8:]

    def show_counters(self):
        cmd = "show interfaces counters"
        return telnet.Telnet.send(cmd, self.host, self.user, self.password)

    def get_mac_address_table(self):
        cmd = "show mac address-table"
        mac_address_table = telnet.Telnet.send(cmd, self.host, self.user, self.password)
        split_table = mac_address_table.split("\n")
        pattern = re.compile("^[\s\S]+ (\S\S\S\S\.\S\S\S\S\.\S\S\S\S) +(STAT|DYNAM)IC +([\S]+)")
        result_dict = {}
        for entry in split_table:
            result = re.search(pattern, entry)
            if result is not None:
                result_dict.update({result.group(1): result.group(3)})
        return result_dict

    def find_mac_table_entry(self, mac_address, mac_table=None):
        if mac_table is None:
            mac_table = self.get_mac_address_table()
        if self.convert_mac_address(mac_address) in mac_table.keys():
            return mac_table[self.convert_mac_address(mac_address)]
        else:
            return None

    def clear_mac_table(self):
        raise NotImplementedError()

    def turn_off_spanning_tree(self, vlan_id):
        cmd = "no spanning-tree vlan {}".format(vlan_id)
        return telnet.Telnet.send(cmd, self.host, self.user, self.password, True)

    def defcfg(self):
        raise NotImplementedError()

    def get_debug_counters(self):
        raise NotImplementedError()

    def reset(self):
        raise NotImplementedError()

    def set_max_frame_size(self, port_idx, size):
        raise NotImplementedError()

    def get_mac_addrs_num(self):
        raise NotImplementedError()

    def set_ager_time(self):
        raise NotImplementedError()

    def set_ager_state(self):
        raise NotImplementedError()

    def add_static_mac_entry(self):
        raise NotImplementedError()

    def set_ingress_port_mirroring(self, from_port, to_port):
        raise NotImplementedError()

    def set_egress_port_mirroring(self, from_port, to_port):
        raise NotImplementedError()

    def set_egress_rate(self):
        raise NotImplementedError()

    def enable_rate_shaper(self):
        raise NotImplementedError()

class AquantiaSMBusSwitchManager(SwitchManager):
    REG_MSM_FRAME_CONTROL = 0x14
    REG_MSM_MAILBOX_ADDR_AND_CONTROL = 0x4400
    REG_MSM_MAILBOX_WRITE_DATA = 0x4404
    REG_MSM_MAILBOX_READ_DATA = 0x4408

    def __init__(self, **kwargs):
        super(AquantiaSMBusSwitchManager, self).__init__(**kwargs)

        self.smbus_device_index = 0
        self.smbus_device_address = 0x40
        self.is_smbus_adapter_opened = False

        self.init_smbus()

        self.nof_ports = kwargs.get("nof_ports", 4)

    def __del__(self):
        if self.is_smbus_adapter_opened:
            from _hardwareInterfaceFTDI import HW_CloseAdapter
            HW_CloseAdapter(self.smbus_device_index)
            self.is_smbus_adapter_opened = False

    def _mac_to_hex(self, addr):
        list = addr.split(":")
        iter_num = 40
        hex = 0
        for elem in list:
            hex += int(elem, 16) << iter_num
            iter_num -= 8
        return hex

    def destroy(self):
        if self.is_smbus_adapter_opened:
            HW_CloseAdapter(self.smbus_device_index)
            self.is_smbus_adapter_opened = False

    def init_smbus(self):
        res = HW_Initialize()
        if res != 1:
            log.error(HW_Error())
            raise Exception("SMBus: HW_Initialize() failed, returncode {}".format(res))

        res = HW_DeviceList()
        if len(res) != 2:
            raise Exception("SMBus: HW_DeviceList() failed, return data {}".format(res))

        res = HW_OpenAdapter(self.smbus_device_index)
        if res != 1:
            log.error(HW_Error())
            raise Exception("SMBus: HW_OpenAdapter({}) failed, returncode {}".format(self.smbus_device_index, res))

        self.is_smbus_adapter_opened = True

    def readreg(self, reg, silent=False):
        val = HW_Read32(self.smbus_device_index, self.smbus_device_address, reg)
        if not silent:
            log.info("Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))
        return val

    def writereg(self, reg, value, silent=False):
        HW_Write32(self.smbus_device_index, self.smbus_device_address, reg, value)
        if not silent:
            log.info("Register 0x{:08x}: 0x{:08x} written".format(reg, value))

    def readreg_msm(self, reg, idx):
        shift2_reg = reg >> 2
        rd_strobe = 0x2
        rd_strobe_addr = rd_strobe << 8 | shift2_reg
        shift0_addr = 0x408 | (idx << 12)
        shift1_addr = 0x400 | (idx << 12)
        self.writereg(shift1_addr, rd_strobe_addr, silent=True)
        val = self.readreg(shift0_addr, silent=True)
        log.info("MSM register 0x{:08x} IDX 0x{:01x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                 reg, idx, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))
        return val

    def writereg_msm(self, reg, value, idx):
        shift2_reg = reg >> 2
        wr_strobe = 0x1
        wr_strobe_addr = wr_strobe << 8 | shift2_reg
        shift0_addr = 0x404 | (idx << 12)
        shift1_addr = 0x400 | (idx << 12)
        self.writereg(shift0_addr, value, silent=True)
        self.writereg(shift1_addr, wr_strobe_addr, silent=True)
        log.info("MSM register 0x{:08x} IDX 0x{:01x}: 0x{:08x} written".format(reg, idx, value))

    def defcfg(self):
        # USX bypass
        self.writereg(0x318, 0xd00c)
        self.writereg(0x1318, 0xd00c)
        self.writereg(0x2318, 0xd00c)
        self.writereg(0x3318, 0xd00c)

        # MSM enable
        self.writereg(0x88, 0x94c0)
        self.writereg(0x3c, 0xa4c00000)
        self.writereg(0x38, 0x0000)
        self.writereg(0x1088, 0x94c0)
        self.writereg(0x103c, 0xa4c00000)
        self.writereg(0x1038, 0x0000)
        self.writereg(0x2088, 0x94c0)
        self.writereg(0x203c, 0xa4c00000)
        self.writereg(0x2038, 0x0000)
        self.writereg(0x3088, 0x94c0)
        self.writereg(0x303c, 0xa4c00000)
        self.writereg(0x3038, 0x0000)

        val = 0x00000c13
        self.writereg_msm(0x8, val, 0x0)
        self.writereg_msm(0x8, val, 0x1)
        self.writereg_msm(0x8, val, 0x2)
        self.writereg_msm(0x8, val, 0x3)

        # Switch STP Mode
        # self.writereg(0x84104, 0x0)
        # sleep(1)

        self.writereg(0x84104, 0xff)
        self.readreg(0x84104)
        self.writereg(0x84200, 0x0)  # Static port forward disable
        self.writereg(0x8420c, 0xe4)

        # CRC forward disable
        self.writereg(0x0410, 0x1)
        self.writereg_msm(0x8, val, 0x0)
        self.writereg(0x1410, 0x1)
        self.writereg_msm(0x8, val, 0x1)
        self.writereg(0x2410, 0x1)
        self.writereg_msm(0x8, val, 0x2)
        self.writereg(0x3410, 0x1)
        self.writereg_msm(0x8, val, 0x3)

        # Disable extraction
        self.writereg(0x84610, 0x0)

        # Set max frame size to 1600 bytes by default to allow default MTU 1500 working well
        for i in range(self.nof_ports):
            self.set_max_frame_size(i, 1600)

    def inject_packet(self):
        self.writereg(0x10000, 0x0)
        self.writereg(0x10004, 0x1)
        self.writereg(0x10008, 0x2)
        self.writereg(0x1000c, 0x3)
        self.writereg(0x10010, 0x4)
        self.writereg(0x10014, 0x5)
        self.writereg(0x10018, 0x6)
        self.writereg(0x1001c, 0x7)
        self.writereg(0x10020, 0x8)
        self.writereg(0x10024, 0x9)
        self.writereg(0x10028, 0xa)
        self.writereg(0x1002c, 0xb)
        self.writereg(0x10030, 0xc)
        self.writereg(0x10034, 0xd)
        self.writereg(0x10038, 0xe)
        self.writereg(0x1003c, 0xf)
        self.writereg(0x10040, 0xbf78eae4)

        self.writereg(0x84604, 0x44f)
        self.readreg(0x84600)

    def extraction_enable(self):
        self.writereg(0x84610, 0x8000)
        self.writereg(0x84618, 0x80000000)
        self.writereg(0x84614, 0x00000000)

    def extraction_disable(self):
        self.writereg(0x84610, 0x0)

    def extraction_read_packet(self):
        et_st = HW_Read32(self.smbus_device_index, self.smbus_device_address, 0x84608)

        cnt = (et_st >> 8) & 0xff
        log.info("In read {}".format(cnt))
        while (cnt > 0):
            log.info("count {}".format(cnt))
            self.readreg(0x84608)

            et_dsc = self.readreg(0x8460c)
            dsc_pt = et_dsc & (0x3)
            dsc_ln = (et_dsc >> 2) & (0x3fff)
            dsc_ad = (et_dsc >> 16) & (0xffff)

            st_ad = 0x20000 + (dsc_ad << 5) + (0 << 14)
            log.info("Start Add : {} Length : {} Port : ".format(dsc_ad, dsc_ln, dsc_pt))
            rd_cnt = (dsc_ln >> 2) + 1
            while (rd_cnt > 0):
                self.readreg(st_ad)
                st_ad = st_ad + 4
                rd_cnt = rd_cnt - 1
            et_st_wr = et_st | (0x2)
            self.writereg(0x84608, et_st_wr)
            cnt = cnt - 1

    def show_counters(self):
        raise NotImplementedError()

    def get_mac_address_table(self):
        hash_addr_1 = 0x30000
        hash_addr_2 = 0x34000
        hash_addr_3 = 0x38000

        i = 0
        mac_table = {key: [] for key in [0, 1, 2, 3]}

        while i < 4096:
            addr_1 = HW_Read32(self.smbus_device_index, self.smbus_device_address, hash_addr_1)
            addr_2 = HW_Read32(self.smbus_device_index, self.smbus_device_address, hash_addr_2)
            addr_3 = HW_Read32(self.smbus_device_index, self.smbus_device_address, hash_addr_3)
            if addr_1 != 0:
                port = int(math.log(addr_3 >> 16, 2))
                if (addr_3 & 0x2) >> 1 == 0:    # dynamic entry
                    if (addr_3 & 0xf) >> 2 == 0:
                        ager_state = "invalid"
                    else:
                        ager_state = "valid"
                else:                           # static entry
                    if addr_3 & 0x1 == 0:
                        ager_state = "invalid"
                    else:
                        ager_state = "valid"
                mac_address = "{0:012x}".format((addr_2 & 0xffff) << 32 | addr_1)
                mac_address = mac_address[:2] + ':' + mac_address[2:4] + ':' + mac_address[4:6] + ':' + mac_address[6:8] + ':' + mac_address[8:10] + ':' + mac_address[10:]
                mac_table[port].append((mac_address, ager_state))

            hash_addr_1 += 4
            hash_addr_2 += 4
            hash_addr_3 += 4
            i += 1

        return mac_table

    def find_mac_table_entry(self, mac_address, mac_table=None):
        if mac_table is None:
            mac_table = self.get_mac_address_table()

        for entry in mac_table.keys():
            for addr in mac_table[entry]:
                if addr[0] == mac_address and addr[1] == "valid":
                    return entry
        return None

    def get_mac_addrs_num(self, mac_table=None):
        if mac_table is None:
            mac_table = self.get_mac_address_table()

        count = 0
        for entry in mac_table.keys():
            for addr in mac_table[entry]:
                if addr[1] == "valid":
                    count += 1
        return count

    def clear_mac_table(self):
        self.writereg(0x84104, 0)       # set STP to blocking state to prevent packet flow
        self.writereg(0x84204, 0x8000)  # set ager time 200us (LSB)
        self.writereg(0x84208, 0)       # set ager time 200us (MSB)
        self.writereg(0x84200, 0x2)     # enable ager
        time.sleep(1)
        self.writereg(0x84200, 0)       # disable ager
        time.sleep(1)

        self.writereg(0x84104, 0xff)    # return STP back to forwarding state

    def set_ager_state(self, enabled=False):
        if enabled:
            self.writereg(0x84200, 0x2)
        else:
            self.writereg(0x84200, 0)

    def set_ager_time(self, timeout):
        timeout_1_ms = 0x2625a
        timeout *= timeout_1_ms
        msb = timeout >> 0x20
        lsb = timeout & 0xffffffff

        self.writereg(0x84204, lsb)
        self.writereg(0x84208, msb)

    def add_static_mac_entry(self, addr, port):
        addr = self._mac_to_hex(addr)
        addr_lsb = addr & 0xffffffff
        addr_msb = addr >> 32

        self.writereg(0x30000, addr_lsb)
        self.writereg(0x34000, addr_msb)
        hash = self.readreg(0x84210)
    #    result_addr_0 = 0x30000 + hash * 4
    #    result_addr_1 = 0x34000 + hash * 4
        result_addr_2 = 0x38000 + hash * 4

        port_map = 2**port
        state = 0x13
        entry_state = (port_map << 16) + state
        self.writereg(result_addr_2, entry_state)

    def add_static_mcast_entry(self, addr, ports):
        addr = self._mac_to_hex(addr)
        addr_lsb = addr & 0xffffffff
        addr_msb = addr >> 32

        self.writereg(0x30000, addr_lsb)
        self.writereg(0x34000, addr_msb)
        hash = self.readreg(0x84210)
        #    result_addr_0 = 0x30000 + hash * 4
        #    result_addr_1 = 0x34000 + hash * 4
        result_addr_2 = 0x38000 + hash * 4

        port_map = 2 ** ports
        state = 0x13
        entry_state = (port_map << 16) + state
        self.writereg(result_addr_2, entry_state)

    def turn_off_spanning_tree(self, vlan_id):
        raise NotImplementedError()

    def get_debug_counters(self):
        counters = {}
        for i in range(self.nof_ports):
            counters[i] = {}
        for i in range(self.nof_ports):
            counters[i]["msm_rx_good_frames"] = self.readreg_msm(0x88, i)
        for i in range(self.nof_ports):
            counters[i]["msm_tx_good_frames"] = self.readreg_msm(0x80, i)
        for i in range(self.nof_ports):
            counters[i]["loopback_state"] = hex(self.readreg_msm(0x8, i))
        for i in range(self.nof_ports):
            counters[i]["tkl_rx_good_frames"] = self.readreg(0x00a0 + 0x1000 * i)
        for i in range(self.nof_ports):
            counters[i]["tkl_rx_bad_frames"] = self.readreg(0x00a4 + 0x1000 * i)
        for i in range(self.nof_ports):
            counters[i]["tkl_tx_good_frames"] = self.readreg(0x0050 + 0x1000 * i)
        for i in range(self.nof_ports):
            counters[i]["tkl_tx_bad_frames"] = self.readreg(0x0054 + 0x1000 * i)
        for i in range(self.nof_ports):
            counters[i]["msm_tx_pfm"] = self.readreg_msm(0xa0, i)
        for i in range(self.nof_ports):
            counters[i]["msm_rx_pfm"] = self.readreg_msm(0xa8, i)
        return counters

    def reset(self):
        self.writereg(0x84000, 0x1)
        time.sleep(0.1)

    def set_max_frame_size(self, port_idx, size):
        self.writereg_msm(self.REG_MSM_FRAME_CONTROL, size, port_idx)

    def set_ingress_port_mirroring(self, from_port, to_port=None):
        # to_port = None means disable ingress mirroring
        log.info("Setting ingress port mirroring from port {} to port {}".format(from_port, to_port))
        mirror_base_addr = 0x84300
        addr = mirror_base_addr + from_port * 0x4
        old_val = self.readreg(addr)
        if to_port is not None:
            mirror_val = old_val | (1 << to_port)
        else:
            mirror_val = old_val & 0xfffffff0

        self.writereg(addr, mirror_val)

    def set_egress_port_mirroring(self, from_port, to_port=None):
        # to_port = None means disable ingress mirroring
        log.info("Setting egress port mirroring from port {} to port {}".format(from_port, to_port))
        mirror_base_addr = 0x84300
        addr = mirror_base_addr + from_port * 0x4
        old_val = self.readreg(addr)
        if to_port is not None:
            mirror_val = old_val | (1 << to_port << 16)
        else:
            mirror_val = old_val & 0xfff0ffff

        self.writereg(addr, mirror_val)

    def enable_rate_shaper(self):
        ps_control_reg = self.readreg(0x84400)
        ps_control_reg = ps_control_reg | 0b10000000
        self.writereg(0x84400, ps_control_reg)

    def set_egress_rate(self, rate_gbps, port_idx):
        rate_x = int(10 // rate_gbps)
        rate_y = 10 / rate_gbps - rate_x

        rate_y = rate_y * 0x4000    # 0x1000 maps to 0.25 coef. 0x1000/0.25=0x4000
        value = (int(rate_y) << 16) + rate_x
        self.writereg(0x84480 + port_idx * 4, value)


class SwitchManagerArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("{}".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = SwitchManagerArgumentParser()
    parser.add_argument("-c", "--command", help="Command to be performed", type=str, required=True,
                        choices=["readreg",
                                 "writereg",
                                 "readphyreg",
                                 "readregmsm",
                                 "writeregmsm",
                                 "defcfg",
                                 "dbgcnt",
                                 "injpkt",
                                 "reset",
                                 "mactable",
                                 "eten",
                                 "etdis",
                                 "extrpkt",
                                 "ager",
                                 "add",
                                 "scheduling"])
    parser.add_argument("-r", "--register", help="Register address")
    parser.add_argument("-v", "--value", help="Value to be written")
    parser.add_argument("-i", "--idx", help="MPI index", type=str)
    parser.add_argument("--vendor", help="Switch vendor", type=str, default=SWITCH_VENDOR_AQUANTIA_SMBUS)
    parser.add_argument("--nofports", help="Number of switch ports", type=str, default="0x4")
    parser.add_argument("-m", "--mode", help="MAC table mode - read, clear", type=str)
    parser.add_argument("-t", "--timeout", help="mac table ager timeout")
    parser.add_argument("-s", "--state", help="ager state")
    parser.add_argument("-a", "--address", help="mac address", type=str)
    parser.add_argument("-p", "--port", help="mapped port", type=int)
    parser.add_argument("--egressrate", help="egress rate Gbps", type=float, default=10)

    args = parser.parse_args()

    try:
        sm = SwitchManager(vendor=args.vendor)

        if args.command == "readreg":
            if args.register is None:
                log.error("To read register address must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            sm.readreg(int(args.register, 16))
        if args.command == "writereg":
            if args.register is None or args.value is None:
                log.error("To write register address and value must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            sm.writereg(int(args.register, 16), int(args.value, 16))
        if args.command == "readregmsm":
            if args.register is None or args.idx is None:
                log.error("To read MSM register address and idx must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            sm.readreg_msm(int(args.register, 16), int(args.idx, 16))
        if args.command == "writeregmsm":
            if args.register is None or args.value is None or args.idx is None:
                log.error("To write register address, idx and value must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            sm.writereg_msm(int(args.register, 16), int(args.value, 16), int(args.idx, 16))
        if args.command == "dbgcnt":
            counters = sm.get_debug_counters()
            for i in range(int(args.nofports, 16)):
                pcounters = counters[i]
                log.info("Port {} counters:".format(i))
                for k, v in pcounters.items():
                    log.info("    {} = {}".format(k, v))
        if args.command == "defcfg":
            sm.defcfg()
        if args.command == "injpkt":
            sm.inject_packet()
        if args.command == "reset":
            sm.reset()
        if args.command == "mactable":
            if args.mode is None:
                log.error("mode is not specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            if args.mode == "read":
                log.info(sm.get_mac_address_table())
            elif args.mode == "clear":
                log.info(sm.clear_mac_table())
            else:
                log.error("mode is not specified (read, clear)")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
        if args.command == "eten":
            sm.extraction_enable()
        if args.command == "etdis":
            sm.extraction_disable()
        if args.command == "extrpkt":
            sm.extraction_read_packet()
        if args.command == "ager":
            if args.timeout is not None:
                sm.set_ager_time(args.timeout)
            if args.state is not None:
                if args.state == '1':
                    sm.set_ager_state(True)
                elif args.state == '0':
                    sm.set_ager_state(False)
        if args.command == "add":
            if args.address is not None and args.port is not None:
                sm.add_static_mac_entry(args.address, args.port)
            else:
                log.error("address or port not specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
        if args.command == "scheduling":
            if args.port is not None and args.egressrate is not None:
                sm.set_egress_rate(args.egressrate, args.port)
            else:
                log.error("egress rate value or port not specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
    except Exception:
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
