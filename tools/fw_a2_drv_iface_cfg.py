import ctypes
import struct
import time
import timeit

from constants import LINK_SPEED_10M, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_10G, LINK_SPEED_AUTO, LINK_STATE_UP, LINK_SPEED_NO_LINK, LINK_SPEED_N2_5G, LINK_SPEED_N5G, ENABLE, \
    DISABLE
from fw_a2_drv_iface_structures import *
from ctypes_struct_helper import hal_reg_factory, read_struct_field, write_struct_field, dump_struct_log

from utils import get_atf_logger

log = get_atf_logger()


# COM_antigua_registers.pdf

# 6.11.85 Boot Status: Address 0x000033F0
Boot_Status = hal_reg_factory(0x000033F0, [
    ("eFUSE_TLVs", ctypes.c_uint32, 2),
    ("Boot_Mode", ctypes.c_uint32, 2),
    ("Boot_from_flash_enabled", ctypes.c_uint32, 2),
    ("Boot_from_flash_NCB0_status", ctypes.c_uint32, 2),
    ("Boot_from_flash_NCB1_status", ctypes.c_uint32, 2),
    ("Boot_from_host_enabled", ctypes.c_uint32, 2),
    ("Boot_from_host_status", ctypes.c_uint32, 2),
    ("Header_Verification_Status", ctypes.c_uint32, 2),
    ("Public_key_verification", ctypes.c_uint32, 2),
    ("Security_descriptor_load_status", ctypes.c_uint32, 2),
    ("Security_descriptor_verification_status", ctypes.c_uint32, 2),
    ("Serdes_FW_load_status", ctypes.c_uint32, 2),
    ("NCB_and_PCI_TLVs_enabled", ctypes.c_uint32, 2),
    ("NCB_TLV_status", ctypes.c_uint32, 2),
    ("MAC_FW_status", ctypes.c_uint32, 2),
    ("Overall_completion_status", ctypes.c_uint32, 2)
])

# 6.11.320 MCP/Host Shared Buffer Control 1: Address 0x00000E00


LINK_SPEED_TO_RATE_VAL_A2_MAP = {
    LINK_SPEED_NO_LINK: 0,
    LINK_SPEED_10M: 1,
    LINK_SPEED_100M: 2,
    LINK_SPEED_1G: 3,
    LINK_SPEED_2_5G: 4,
    LINK_SPEED_5G: 5,
    LINK_SPEED_10G: 6
}
LINK_SPEED_TO_HALF_DUPLEX_LINKOPTION_VAL_A2_MAP = {
    LINK_SPEED_10M: "rate_10M_hd",
    LINK_SPEED_100M: "rate_100M_hd",
    LINK_SPEED_1G: "rate_1G_hd",
}
LINK_SPEED_TO_LINKOPTION_VAL_A2_MAP = {
    LINK_SPEED_10M: "rate_10M",
    LINK_SPEED_100M: "rate_100M",
    LINK_SPEED_1G: "rate_1G",
    LINK_SPEED_2_5G: "rate_2P5G",
    LINK_SPEED_N2_5G: "rate_N2P5G",
    LINK_SPEED_5G: "rate_5G",
    LINK_SPEED_N5G: "rate_N5G",
    LINK_SPEED_10G: "rate_10G"
}

LINK_SPEED_TO_EEE_LINKOPTION_VAL_A2_MAP = {
    LINK_SPEED_100M: "eee_100M",
    LINK_SPEED_1G: "eee_1G",
    LINK_SPEED_2_5G: "eee_2P5G",
    LINK_SPEED_5G: "eee_5G",
    LINK_SPEED_10G: "eee_10G"
}

RATE_VAL_A2_TO_LINK_SPEED_MAP = {
    0: LINK_SPEED_NO_LINK,
    1: LINK_SPEED_10M,
    2: LINK_SPEED_100M,
    3: LINK_SPEED_1G,
    4: LINK_SPEED_2_5G,
    5: LINK_SPEED_5G,
    6: LINK_SPEED_10G
}


class WakeUpPattern(object):
    def __init__(self):
        self.mask = [0] * 4
        self.crc32 = 0


class WakeOnLanOffload(object):
    def __init__(self):
        self.wake_on_magic_packet = False
        self.wake_on_pattern = False
        self.wake_on_link_up = False
        self.wake_on_link_down = False
        self.wake_on_ping = False
        self.wake_on_timer = False
        self.link_up_timeout = 0
        self.link_down_timeout = 0
        self.timer = 0
        self.wake_up_patterns = [WakeUpPattern() for _ in range(8)]


class IPv4Offload(object):
    def __init__(self):
        self.arp_responder = False
        self.echo_responder = False
        self.igmp_client = False
        self.echo_truncate = False
        self.address_guard = False
        self.ignore_fragmented = False
        self.echo_max_len = 0
        self.ipv4 = ["0.0.0.0"] * 8


class IPv6Offload(object):
    def __init__(self):
        self.ns_responder = False
        self.echo_responder = False
        self.mld_client = False
        self.echo_truncate = False
        self.address_guard = False
        self.echo_max_len = 0
        self.ipv6 = ["0000:0000:0000:0000:0000:0000:0000:0000" for _ in range(16)]


class TCPPortOffload(object):
    def __init__(self):
        self.ports = [0] * 16


class UDPPortOffload(object):
    def __init__(self):
        self.ports = [0] * 16


class KASingleOffload(object):
    def __init__(self):
        self.operation_timeout = 0
        self.local_port = 0
        self.remote_port = 0
        self.remote_mac_addr = "00:00:00:00:00:00"
        self.win_size = 0
        self.seq_num = 0
        self.ack_num = 0
        self.local_ip = ""
        self.remote_ip = ""


class KAOffloadCommon(object):
    def __init__(self):
        self.retry_count = 0
        self.retry_interval = 0
        self.offloads = [KASingleOffload() for _ in range(16)]


class MDNSOffload(object):
    def __init__(self):
        self.rr_count = 0
        self.rr_buf_len = 0
        self.idx_offset = 0
        self.rr_offset = 0


class SleepProxyOffload(object):
    def __init__(self):
        self.wake_on_lan = WakeOnLanOffload()
        self.ipv4_offload = IPv4Offload()
        self.ipv6_offload = IPv6Offload()
        self.tcp_port_offload = TCPPortOffload()
        self.udp_port_offload = UDPPortOffload()
        self.ka4_offload = KAOffloadCommon()
        self.ka6_offload = KAOffloadCommon()
        for i in range(16):
            self.ka4_offload.offloads[i].local_ip = "0.0.0.0"
            self.ka4_offload.offloads[i].remote_ip = "0.0.0.0"
            self.ka6_offload.offloads[i].local_ip = "0000:0000:0000:0000:0000:0000:0000:0000"
            self.ka6_offload.offloads[i].remote_ip = "0000:0000:0000:0000:0000:0000:0000:0000"
        self.mdns_offload = MDNSOffload()

    def get_data(self):
        sleep_proxy = sleepProxy_t()

        # Wake On Lan field
        sleep_proxy.wakeOnLan.wakeOnMagicPacket = 1 if self.wake_on_lan.wake_on_magic_packet else 0
        sleep_proxy.wakeOnLan.wakeOnPattern = 1 if self.wake_on_lan.wake_on_pattern else 0
        sleep_proxy.wakeOnLan.wakeOnLinkUp = 1 if self.wake_on_lan.wake_on_link_up else 0
        sleep_proxy.wakeOnLan.wakeOnLinkDown = 1 if self.wake_on_lan.wake_on_link_down else 0
        sleep_proxy.wakeOnLan.wakeOnPing = 1 if self.wake_on_lan.wake_on_ping else 0
        sleep_proxy.wakeOnLan.wakeOnTimer = 1 if self.wake_on_lan.wake_on_timer else 0

        sleep_proxy.wakeOnLan.linkUpTimeout = self.wake_on_lan.link_up_timeout
        sleep_proxy.wakeOnLan.linkDownTimeout = self.wake_on_lan.link_down_timeout
        sleep_proxy.wakeOnLan.timer = self.wake_on_lan.timer

        for i in range(8):
            sleep_proxy.wakeOnLan.wakeUpPatterns[i].mask[0] = self.wake_on_lan.wake_up_patterns[i].mask[0]
            sleep_proxy.wakeOnLan.wakeUpPatterns[i].mask[1] = self.wake_on_lan.wake_up_patterns[i].mask[1]
            sleep_proxy.wakeOnLan.wakeUpPatterns[i].mask[2] = self.wake_on_lan.wake_up_patterns[i].mask[2]
            sleep_proxy.wakeOnLan.wakeUpPatterns[i].mask[3] = self.wake_on_lan.wake_up_patterns[i].mask[3]
            sleep_proxy.wakeOnLan.wakeUpPatterns[i].crc32 = self.wake_on_lan.wake_up_patterns[i].crc32

        # IPv4 Offload field
        sleep_proxy.ipv4Offload.arpResponder = 1 if self.ipv4_offload.arp_responder else 0
        sleep_proxy.ipv4Offload.echoResponder = 1 if self.ipv4_offload.echo_responder else 0
        sleep_proxy.ipv4Offload.igmpClient = 1 if self.ipv4_offload.igmp_client else 0
        sleep_proxy.ipv4Offload.echoTruncate = 1 if self.ipv4_offload.echo_truncate else 0
        sleep_proxy.ipv4Offload.addressGuard = 1 if self.ipv4_offload.address_guard else 0
        sleep_proxy.ipv4Offload.ignoreFragmentedEcho = 1 if self.ipv4_offload.ignore_fragmented else 0

        sleep_proxy.ipv4Offload.echoMaxLen = self.ipv4_offload.echo_max_len

        for i in range(8):
            ip_parts = map(int, self.ipv4_offload.ipv4[i].split("."))

            sleep_proxy.ipv4Offload.ipv4[i] = (ip_parts[3] << 24) | (ip_parts[2] << 16) | (ip_parts[1] << 8) | \
                                              ip_parts[0]

        # IPv6 Offload field
        sleep_proxy.ipv6Offload.nsResponder = 1 if self.ipv6_offload.ns_responder else 0
        sleep_proxy.ipv6Offload.echoResponder = 1 if self.ipv6_offload.echo_responder else 0
        sleep_proxy.ipv6Offload.mldClient = 1 if self.ipv6_offload.mld_client else 0
        sleep_proxy.ipv6Offload.echoTruncate = 1 if self.ipv6_offload.echo_truncate else 0
        sleep_proxy.ipv6Offload.addressGuard = 1 if self.ipv6_offload.address_guard else 0

        sleep_proxy.ipv6Offload.echoMaxLen = self.ipv6_offload.echo_max_len

        for i in range(16):
            ip_parts = map(lambda x: int(x, 16), self.ipv6_offload.ipv6[i].split(":"))

            sleep_proxy.ipv6Offload.ipv6[i][0] = ((ip_parts[1] & 0xFF00) << 8) | ((ip_parts[1] & 0x00FF) << 24) | \
                                                 ((ip_parts[0] & 0x00FF) << 8) | ((ip_parts[0] & 0xFF00) >> 8)
            sleep_proxy.ipv6Offload.ipv6[i][1] = ((ip_parts[3] & 0xFF00) << 8) | ((ip_parts[3] & 0x00FF) << 24) | \
                                                 ((ip_parts[2] & 0x00FF) << 8) | ((ip_parts[2] & 0xFF00) >> 8)
            sleep_proxy.ipv6Offload.ipv6[i][2] = ((ip_parts[5] & 0xFF00) << 8) | ((ip_parts[5] & 0x00FF) << 24) | \
                                                 ((ip_parts[4] & 0x00FF) << 8) | ((ip_parts[4] & 0xFF00) >> 8)
            sleep_proxy.ipv6Offload.ipv6[i][3] = ((ip_parts[7] & 0xFF00) << 8) | ((ip_parts[7] & 0x00FF) << 24) | \
                                                 ((ip_parts[6] & 0x00FF) << 8) | ((ip_parts[6] & 0xFF00) >> 8)

        # TCP Port Offload field
        for i in range(16):
            sleep_proxy.tcpPortOffload.ports[i] = ((self.tcp_port_offload.ports[i] & 0x00FF) << 8) | \
                                                  ((self.tcp_port_offload.ports[i] & 0xFF00) >> 8)

        # UDP Port Offload field
        for i in range(16):
            sleep_proxy.udpPortOffload.ports[i] = ((self.udp_port_offload.ports[i] & 0x00FF) << 8) | \
                                                  ((self.udp_port_offload.ports[i] & 0xFF00) >> 8)

        # KA4 Offload Field
        sleep_proxy.ka4Offload.retryCount = self.ka4_offload.retry_count
        sleep_proxy.ka4Offload.retryInterval = self.ka4_offload.retry_interval

        for i in range(16):
            mac_parts = map(lambda x: int(x, 16), self.ka4_offload.offloads[i].remote_mac_addr.split(":"))
            local_ip_parts = map(int, self.ka4_offload.offloads[i].local_ip.split("."))
            remote_ip_parts = map(int, self.ka4_offload.offloads[i].remote_ip.split("."))

            sleep_proxy.ka4Offload.offloads[i].operationTimeout = self.ka4_offload.offloads[i].operation_timeout
            _lp = self.ka4_offload.offloads[i].local_port
            sleep_proxy.ka4Offload.offloads[i].local_port = (_lp & 0x00FF) << 8 | (_lp & 0xFF00) >> 8
            _rp = self.ka4_offload.offloads[i].remote_port
            sleep_proxy.ka4Offload.offloads[i].remote_port = (_rp & 0x00FF) << 8 | (_rp & 0xFF00) >> 8

            sleep_proxy.ka4Offload.offloads[i].remote_mac_addr[0] = mac_parts[0]
            sleep_proxy.ka4Offload.offloads[i].remote_mac_addr[1] = mac_parts[1]
            sleep_proxy.ka4Offload.offloads[i].remote_mac_addr[2] = mac_parts[2]
            sleep_proxy.ka4Offload.offloads[i].remote_mac_addr[3] = mac_parts[3]
            sleep_proxy.ka4Offload.offloads[i].remote_mac_addr[4] = mac_parts[4]
            sleep_proxy.ka4Offload.offloads[i].remote_mac_addr[5] = mac_parts[5]

            sleep_proxy.ka4Offload.offloads[i].winSize = self.ka4_offload.offloads[i].win_size
            sleep_proxy.ka4Offload.offloads[i].seq_num = self.ka4_offload.offloads[i].seq_num
            sleep_proxy.ka4Offload.offloads[i].ack_num = self.ka4_offload.offloads[i].ack_num

            sleep_proxy.ka4Offload.offloads[i].local_ip = (local_ip_parts[3] << 24) | (local_ip_parts[2] << 16) | \
                                                          (local_ip_parts[1] << 8) | local_ip_parts[0]
            sleep_proxy.ka4Offload.offloads[i].remote_ip = (remote_ip_parts[3] << 24) | (remote_ip_parts[2] << 16) | \
                                                           (remote_ip_parts[1] << 8) | remote_ip_parts[0]

        # KA6 Offload Field
        sleep_proxy.ka6Offload.retryCount = self.ka6_offload.retry_count
        sleep_proxy.ka6Offload.retryInterval = self.ka6_offload.retry_interval

        for i in range(16):
            mac_parts = map(lambda x: int(x, 16), self.ka6_offload.offloads[i].remote_mac_addr.split(":"))
            local_ip_parts = map(lambda x: int(x, 16), self.ka6_offload.offloads[i].local_ip.split(":"))
            remote_ip_parts = map(lambda x: int(x, 16), self.ka6_offload.offloads[i].remote_ip.split(":"))

            sleep_proxy.ka6Offload.offloads[i].operationTimeout = self.ka6_offload.offloads[i].operation_timeout
            _lp = self.ka6_offload.offloads[i].local_port
            sleep_proxy.ka6Offload.offloads[i].local_port = (_lp & 0x00FF) << 8 | (_lp & 0xFF00) >> 8
            _rp = self.ka6_offload.offloads[i].remote_port
            sleep_proxy.ka6Offload.offloads[i].remote_port = (_rp & 0x00FF) << 8 | (_rp & 0xFF00) >> 8

            sleep_proxy.ka6Offload.offloads[i].remote_mac_addr[0] = mac_parts[0]
            sleep_proxy.ka6Offload.offloads[i].remote_mac_addr[1] = mac_parts[1]
            sleep_proxy.ka6Offload.offloads[i].remote_mac_addr[2] = mac_parts[2]
            sleep_proxy.ka6Offload.offloads[i].remote_mac_addr[3] = mac_parts[3]
            sleep_proxy.ka6Offload.offloads[i].remote_mac_addr[4] = mac_parts[4]
            sleep_proxy.ka6Offload.offloads[i].remote_mac_addr[5] = mac_parts[5]

            sleep_proxy.ka6Offload.offloads[i].winSize = self.ka6_offload.offloads[i].win_size
            sleep_proxy.ka6Offload.offloads[i].seq_num = self.ka6_offload.offloads[i].seq_num
            sleep_proxy.ka6Offload.offloads[i].ack_num = self.ka6_offload.offloads[i].ack_num

            sleep_proxy.ka6Offload.offloads[i].local_ip[0] = \
                ((local_ip_parts[1] & 0xFF00) << 8) | ((local_ip_parts[1] & 0x00FF) << 24) | \
                ((local_ip_parts[0] & 0x00FF) << 8) | ((local_ip_parts[0] & 0xFF00) >> 8)
            sleep_proxy.ka6Offload.offloads[i].local_ip[1] = \
                ((local_ip_parts[3] & 0xFF00) << 8) | ((local_ip_parts[3] & 0x00FF) << 24) | \
                ((local_ip_parts[2] & 0x00FF) << 8) | ((local_ip_parts[2] & 0xFF00) >> 8)
            sleep_proxy.ka6Offload.offloads[i].local_ip[2] = \
                ((local_ip_parts[5] & 0xFF00) << 8) | ((local_ip_parts[5] & 0x00FF) << 24) | \
                ((local_ip_parts[4] & 0x00FF) << 8) | ((local_ip_parts[4] & 0xFF00) >> 8)
            sleep_proxy.ka6Offload.offloads[i].local_ip[3] = \
                ((local_ip_parts[7] & 0xFF00) << 8) | ((local_ip_parts[7] & 0x00FF) << 24) | \
                ((local_ip_parts[6] & 0x00FF) << 8) | ((local_ip_parts[6] & 0xFF00) >> 8)

            sleep_proxy.ka6Offload.offloads[i].remote_ip[0] = \
                ((remote_ip_parts[1] & 0xFF00) << 8) | ((remote_ip_parts[1] & 0x00FF) << 24) | \
                ((remote_ip_parts[0] & 0x00FF) << 8) | ((remote_ip_parts[0] & 0xFF00) >> 8)
            sleep_proxy.ka6Offload.offloads[i].remote_ip[1] = \
                ((remote_ip_parts[3] & 0xFF00) << 8) | ((remote_ip_parts[3] & 0x00FF) << 24) | \
                ((remote_ip_parts[2] & 0x00FF) << 8) | ((remote_ip_parts[2] & 0xFF00) >> 8)
            sleep_proxy.ka6Offload.offloads[i].remote_ip[2] = \
                ((remote_ip_parts[5] & 0xFF00) << 8) | ((remote_ip_parts[5] & 0x00FF) << 24) | \
                ((remote_ip_parts[4] & 0x00FF) << 8) | ((remote_ip_parts[4] & 0xFF00) >> 8)
            sleep_proxy.ka6Offload.offloads[i].remote_ip[3] = \
                ((remote_ip_parts[7] & 0xFF00) << 8) | ((remote_ip_parts[7] & 0x00FF) << 24) | \
                ((remote_ip_parts[6] & 0x00FF) << 8) | ((remote_ip_parts[6] & 0xFF00) >> 8)

        # MDNS Offload field
        sleep_proxy.mdns.rrCount = self.mdns_offload.rr_count
        sleep_proxy.mdns.rrBufLen = self.mdns_offload.rr_buf_len
        sleep_proxy.mdns.idxOffset = self.mdns_offload.idx_offset
        sleep_proxy.mdns.rrOffset = self.mdns_offload.rr_offset

        return sleep_proxy


# pauseQuanta Offload field
class PauseQuanta(object):
    def __init__(self):
        self.quanta_10M = 0
        self.threshold_10M = 0
        self.quanta_100M = 0
        self.threshold_100M = 0
        self.quanta_1G = 0
        self.threshold_1G = 0
        self.quanta_2P5G = 0
        self.threshold_2P5G = 0
        self.quanta_5G = 0
        self.threshold_5G = 0
        self.quanta_10G = 0
        self.threshold_10G = 0


class PauseQuantaOffload(object):
    def __init__(self):
        self.pause_traffic_class = [PauseQuanta() for _ in range(8)]

    def get_data(self):
        pause_quanta_type = pauseQuanta_t * 8
        pause_quanta = pause_quanta_type()

        for i in range(8):
            pause_quanta[i].quanta_10M = self.pause_traffic_class[i].quanta_10M
            pause_quanta[i].threshold_10M = self.pause_traffic_class[i].threshold_10M
            pause_quanta[i].quanta_100M = self.pause_traffic_class[i].quanta_100M
            pause_quanta[i].threshold_100M = self.pause_traffic_class[i].threshold_100M
            pause_quanta[i].quanta_1G = self.pause_traffic_class[i].quanta_1G
            pause_quanta[i].threshold_1G = self.pause_traffic_class[i].threshold_1G
            pause_quanta[i].quanta_2P5G = self.pause_traffic_class[i].quanta_2P5G
            pause_quanta[i].threshold_2P5G = self.pause_traffic_class[i].threshold_2P5G
            pause_quanta[i].quanta_5G = self.pause_traffic_class[i].quanta_5G
            pause_quanta[i].threshold_5G = self.pause_traffic_class[i].threshold_5G
            pause_quanta[i].quanta_10G = self.pause_traffic_class[i].quanta_10G
            pause_quanta[i].threshold_10G = self.pause_traffic_class[i].threshold_10G

        return pause_quanta


class FirmwareA2Config(object):
    MIF_SHARED_BUFFER_ADDR = 0x10000
    MIF_SHARED_BUFFER_IN_ADDR = 0x12000
    MIF_SHARED_BUFFER_OUT_ADDR = 0x13000

    def __init__(self, atltool_wrapper):
        self.atltool_wrapper = atltool_wrapper

        # Add driver interface structures to globals, so ctypes_struct_helper module could find them
        import __builtin__
        __builtin__.DRIVER_INTERFACE_IN = DRIVER_INTERFACE_IN
        __builtin__.DRIVER_INTERFACE_OUT = DRIVER_INTERFACE_OUT

    def read_drv_iface_struct_field(self, path):
        if path.startswith("DRIVER_INTERFACE_IN"):
            return read_struct_field(self.atltool_wrapper, path=path, base_offset=self.MIF_SHARED_BUFFER_IN_ADDR)
        elif path.startswith("DRIVER_INTERFACE_OUT"):
            return read_struct_field(self.atltool_wrapper, path=path, base_offset=self.MIF_SHARED_BUFFER_OUT_ADDR)
        else:
            raise Exception("Wrong driver interface struct path: {}".format(path))

    def write_drv_iface_struct_field(self, path, data, out_file_name=None):
        if out_file_name is not None:
            self.atltool_wrapper.out_cfg_file = open(out_file_name, "a")
            self.atltool_wrapper.silent = True

        try:
            if path.startswith("DRIVER_INTERFACE_IN"):
                return write_struct_field(self.atltool_wrapper, path=path, data=data,
                                        base_offset=self.MIF_SHARED_BUFFER_IN_ADDR)
            elif path.startswith("DRIVER_INTERFACE_OUT"):
                return write_struct_field(self.atltool_wrapper, path=path, data=data,
                                        base_offset=self.MIF_SHARED_BUFFER_OUT_ADDR)
            else:
                raise Exception("Wrong driver interface struct path: {}".format(path))
        finally:
            if out_file_name is not None:
                self.atltool_wrapper.out_cfg_file.close()
                self.atltool_wrapper.out_cfg_file = None
                self.atltool_wrapper.silent = False

    def confirm_shared_buffer_write(self, out_file_name=None):
        if out_file_name is not None:
            with open(out_file_name, "a") as out_cfg_file:
                out_cfg_file.write("writereg 0x00000E00 0x00000001\n")

        shared_buff_ctrl_1 = self.atltool_wrapper.readreg(0xE00)
        if shared_buff_ctrl_1 == 0:
            self.atltool_wrapper.writereg(0xE00, 0x1)
            start = timeit.default_timer()
            while timeit.default_timer() - start < 0.1:
                shared_buff_ctrl_1 = self.atltool_wrapper.readreg(0xE00)
                if shared_buff_ctrl_1 == 0:
                    return True
            raise Exception("Shared buffer is busy longer than 0.1 second, Reg 0xE04 = 0x{:08x}".format(self.atltool_wrapper.readreg(0xE04)))
        else:
            raise Exception("Shared buffer is busy, Reg 0xE04 = 0x{:08x}".format(self.atltool_wrapper.readreg(0xE04)))

    def configure_pause_quanta(self, fc_cfg, flow_control_mode=True, out_file_name=None):
        pause_quanta = fc_cfg.get_data()
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.pauseQuanta", pause_quanta, out_file_name)

        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.operatingMode = HOST_MODE_ACTIVE
        link_control.flowControlMode = 1 if flow_control_mode else 0
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control, out_file_name)

        self.confirm_shared_buffer_write(out_file_name)

        log.info("Pause quanta configuration applied")

    def configure_sleep_proxy(self, sp_cfg, mac_addr, out_file_name=None):
        mac_addr_parts = map(lambda x: int(x, 16), mac_addr.split(":"))
        mac_addr = macAddress_t()
        mac_addr[0] = mac_addr_parts[0]
        mac_addr[1] = mac_addr_parts[1]
        mac_addr[2] = mac_addr_parts[2]
        mac_addr[3] = mac_addr_parts[3]
        mac_addr[4] = mac_addr_parts[4]
        mac_addr[5] = mac_addr_parts[5]
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.macAddress", mac_addr, out_file_name)

        sleep_proxy = sp_cfg.get_data()
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.sleepProxyConfig", sleep_proxy, out_file_name)

        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.operatingMode = HOST_MODE_SLEEP_PROXY
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control, out_file_name)

        self.confirm_shared_buffer_write(out_file_name)

        log.info("Sleep proxy configuration applied")

    def get_fw_link_speed(self):
        fw_link_status = self.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.linkStatus")
        fw_link_speed = RATE_VAL_A2_TO_LINK_SPEED_MAP[fw_link_status.linkRate]
        return fw_link_speed

    def get_fw_link_state(self):
        fw_link_status = self.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.linkStatus")
        return fw_link_status.linkState

    def get_fw_eee_status(self):
        fw_link_status = self.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.linkStatus")
        return fw_link_status.eee

    def get_pause_rx_tx_status(self):
        fw_link_status = self.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.linkStatus")
        return fw_link_status.pauseRx, fw_link_status.pauseTx

    def get_fw_wol_status(self, silent=True):
        if silent:
            self.atltool_wrapper.silent = True

        try:
            wol_status = self.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.wolStatus")
        finally:
            if silent:
                self.atltool_wrapper.silent = False

        log.debug("Current wake count: {}".format(wol_status.wakeCount))
        log.debug("Current wake reason: {}".format(wol_status.wakeReason))

        return wol_status

    def __clean_link_speed_bits(self, link_option):
        speed_bits = LINK_SPEED_TO_LINKOPTION_VAL_A2_MAP.values() + LINK_SPEED_TO_EEE_LINKOPTION_VAL_A2_MAP.values() + LINK_SPEED_TO_HALF_DUPLEX_LINKOPTION_VAL_A2_MAP.values()
        for option_speed in speed_bits:
            setattr(link_option, option_speed, 0)
        return link_option

    def set_fw_mtu(self, mtu_value):
        log.info("Requested FW mtu: {}".format(mtu_value))
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.mtu", mtu_value)
        self.confirm_shared_buffer_write()

    def set_link_speed(self, speed, eee=False, half_duplex=False):
        log.info("Setting speed through FW {}...".format(speed))
        link_option = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions")
        link_option = self.__clean_link_speed_bits(link_option)
        if speed != LINK_SPEED_NO_LINK:
            if speed == LINK_SPEED_AUTO:
                speed = LINK_SPEED_TO_LINKOPTION_VAL_A2_MAP.keys()
            elif not isinstance(speed, list):
                speed = [speed]

            option_speeds = [LINK_SPEED_TO_LINKOPTION_VAL_A2_MAP[selected_speed] for selected_speed in speed]
            if eee:
                for selected_speed in speed:
                    option_speeds.append(LINK_SPEED_TO_EEE_LINKOPTION_VAL_A2_MAP[selected_speed])
            elif half_duplex:
                option_speeds = [LINK_SPEED_TO_HALF_DUPLEX_LINKOPTION_VAL_A2_MAP[selected_speed] for selected_speed in speed]

            for option_speed in option_speeds:
                setattr(link_option, option_speed, 1)

        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions", link_option)

    def set_downshift(self, state):
        log.info("Requested downshist: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_option = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions")
        link_option.downshift = state
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions", link_option)
        self.confirm_shared_buffer_write()

    def set_downshift_retry(self, value):
        log.info("Requested downshist retry: {}".format(value))
        if value > 0xf:
            raise Exception('Max value downshift retry 15')
        link_option = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions")
        link_option.downshiftRetry = value
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions", link_option)
        self.confirm_shared_buffer_write()

    def set_internal_loopback(self, state):
        log.info("Requested internal loopback: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_option = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions")
        link_option.internalLoopback = state
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions", link_option)
        self.confirm_shared_buffer_write()

    def set_external_loopback(self, state):
        log.info("Requested external loopback: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_option = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions")
        link_option.externalLoopback = state
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions", link_option)
        self.confirm_shared_buffer_write()

    def set_pause_rx_tx(self, pauseRx=False, pauseTx=False):
        link_option = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions")
        link_option.pauseRx = 1 if pauseRx else 0
        link_option.pauseTx = 1 if pauseTx else 0
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions", link_option)

    def set_minimal_link_speed(self, state):
        log.info("Requested minimal link speed: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_option = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions")
        link_option.minimalLinkSpeed = state
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions", link_option)
        self.confirm_shared_buffer_write()

    def set_link_state(self, state):
        log.info("Requested link state: {}".format(state))
        state = 1 if state == LINK_STATE_UP else 0
        link_option = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions")
        link_option.linkUp = state
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkOptions", link_option)

    def get_thermal_shutdown_state(self):
        thermal_shutdown = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.thermalControl")
        return thermal_shutdown.shutdownEnable

    def get_thermal_shutdown_threshold(self):
        thermal_shutdown = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.thermalControl")
        log.info("ShutdownTempThreshold: {}".format(thermal_shutdown.shutdownTempThreshold))
        log.info("WarningHotTempThreshold: {}".format(thermal_shutdown.warningHotTempThreshold))
        log.info("WarningColdTempThreshold: {}".format(thermal_shutdown.warningColdTempThreshold))

        return thermal_shutdown

    def get_mac_health_monitor(self):
        mac_health_monitor = self.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.macHealthMonitor")

        log.info("MacHeartbeat: {}".format(mac_health_monitor.macHeartBeat))
        log.info("MacTemperature: {}".format(mac_health_monitor.macTemperature))
        log.info("MacFault: {}".format(mac_health_monitor.macFault))
        log.info("MacReady: {}".format(mac_health_monitor.macReady))
        log.info("MacFaultCode: {}".format(mac_health_monitor.macFaultCode))

        return mac_health_monitor

    def get_phy_health_monitor(self):
        phy_health_monitor = self.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.phyHealthMonitor")

        log.info("PhyHeartbeat: {}".format(phy_health_monitor.phyHeartBeat))
        log.info("PhyTemperature: {}".format(phy_health_monitor.phyTemperature))
        log.info("PhyHotWarning: {}".format(phy_health_monitor.phyHotWarning))
        log.info("PhyFault: {}".format(phy_health_monitor.phyFault))
        log.info("PhyReady: {}".format(phy_health_monitor.phyReady))
        log.info("PhyFaultCode: {}".format(phy_health_monitor.phyFaultCode))

        return phy_health_monitor

    def set_link_control_mode(self, mode):
        log.info("Requested link control mode: {}".format(mode))
        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.operatingMode = mode
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.confirm_shared_buffer_write()

    def set_promscuous_mode_state(self, state):
        log.info("Requested link promscuous mode: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.promiscuousMode = state
        link_control.operatingMode = HOST_MODE_ACTIVE
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.confirm_shared_buffer_write()

    def set_padding_removal_rx(self, state):
        log.info("Requested FramePaddingRemovalRx: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.enableFramePaddingRemovalRx = state
        link_control.operatingMode = HOST_MODE_ACTIVE
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.confirm_shared_buffer_write()

    def set_crc_forwarding_state(self, state):
        log.info("Requested crc forwarding: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.enableCrcForwarding = state
        link_control.operatingMode = HOST_MODE_ACTIVE
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.confirm_shared_buffer_write()

    def set_tx_padding_state(self, state):
        log.info("Requested tx padding: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.enableTxPadding = state
        link_control.operatingMode = HOST_MODE_ACTIVE
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.confirm_shared_buffer_write()

    def set_control_frame_state(self, state):
        log.info("Requested control frame: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.controlFrameEnable = state
        link_control.operatingMode = HOST_MODE_ACTIVE
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.confirm_shared_buffer_write()

    def set_discard_errored_frames(self, state):
        log.info("Requested discard errored frames: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.discardErroredFrames = state
        link_control.operatingMode = HOST_MODE_ACTIVE
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.confirm_shared_buffer_write()

    def set_disable_length_check_state(self, state):
        log.info("Requested disable length check: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.disableLengthCheck = state
        link_control.operatingMode = HOST_MODE_ACTIVE
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.confirm_shared_buffer_write()

    def set_priority_flow_control_state(self, state):
        log.info("Requested priority flow control: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.flowControlMode = state
        link_control.operatingMode = HOST_MODE_ACTIVE
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.confirm_shared_buffer_write()

    def set_discard_short_frames_state(self, state):
        log.info("Requested discard short frames: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.discardShortFrames = state
        link_control.operatingMode = HOST_MODE_ACTIVE
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.confirm_shared_buffer_write()

    def set_disable_crc_corruption_state(self, state):
        log.info("Requested disable crc corruption: {}".format(state))
        state = 1 if state == ENABLE else 0
        link_control = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl")
        link_control.disableCrcCorruption = state
        link_control.operatingMode = HOST_MODE_ACTIVE
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.linkControl", link_control)
        self.confirm_shared_buffer_write()

    def set_thermal_shutdown_threshold(self, shutdown_temperature, warning_temperature, cold_temperature):
        log.info("Requested thermal shutdown threshold:")
        log.info("ShutdownTempThreshold: {}".format(shutdown_temperature))
        log.info("WarningHotTempThreshold: {}".format(warning_temperature))
        log.info("WarningColdTempThreshold: {}".format(cold_temperature))

        thermal_shutdown = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.thermalControl")
        thermal_shutdown.shutdownTempThreshold = shutdown_temperature
        thermal_shutdown.warningHotTempThreshold = warning_temperature
        thermal_shutdown.warningColdTempThreshold = cold_temperature
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.thermalControl", thermal_shutdown)
        self.confirm_shared_buffer_write()

    def set_thermal_shutdown_state(self, state):
        log.info("Requested thermal shutdown state: {}".format(state))
        state = 1 if state == ENABLE else 0
        thermal_shutdown = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.thermalControl")
        thermal_shutdown.shutdownEnable = state
        thermal_shutdown.warningEnable = state
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.thermalControl", thermal_shutdown)
        self.confirm_shared_buffer_write()

    def get_link_statistics(self):
        link_statistcs = self.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.stats")
        link_stat = link_statistcs.link
        return {"link_up": link_stat.linkUp, "link_down": link_stat.linkDown}

    def get_msm_statistics(self):
        msm_statistcs = self.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.stats")
        msm_stat = msm_statistcs.msm
        return {"tx_unicast_octets": msm_stat.txUnicastOctets,
                "tx_multicast_octets": msm_stat.txMulticastOctets,
                "tx_broadcast_octets": msm_stat.txBroadcastOctets,
                "rx_unicast_octets": msm_stat.rxUnicastOctets,
                "rx_multicast_octets": msm_stat.rxMulticastOctets,
                "rx_broadcast_octets": msm_stat.rxBroadcastOctets,
                "tx_unicast_frames": msm_stat.txUnicastFrames,
                "tx_multicast_frames": msm_stat.txMulticastFrames,
                "tx_broadcast_frames": msm_stat.txBroadcastFrames,
                "tx_errors": msm_stat.txErrors,
                "rx_unicast_frames": msm_stat.rxUnicastFrames,
                "rx_multicast_frames": msm_stat.rxMulticastFrames,
                "rx_broadcast_frames": msm_stat.rxBroadcastFrames,
                "rx_dropped_frames": msm_stat.rxDroppedFrames,
                "rx_error_frames": msm_stat.rxErrorFrames,
                "tx_good_frames": msm_stat.txGoodFrames,
                "rx_good_frames": msm_stat.rxGoodFrames
                }

    def wait_link_up(self, timeout=25, retry_interval=1):
        log.info("Waiting for link UP")
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            speed = self.get_fw_link_speed()
            if speed != LINK_SPEED_NO_LINK:
                log.info("Link is up at {}".format(speed))
                return speed
            time.sleep(retry_interval)

        raise Exception('Link is not up after timeout = {} sec.'.format(timeout))

    def write_mdns_records(self, mdns_records, idx_offset, rr_ofset, file_to_save_record=None):
        offsets = []
        data_bytes = bytearray()
        for mdns_record in mdns_records:
            log.info("Applying mDNS record: ")
            log.info(mdns_record)
            offsets.append(len(data_bytes))
            data_bytes += mdns_record.to_bytes()

        if file_to_save_record is not None:
            log.info("MDNS records saved to file: {}".format(file_to_save_record))
            with open(file_to_save_record, "wb") as f:
                f.write(data_bytes)

        while len(data_bytes) % 4:
            data_bytes.append(0)

        dword_array = [struct.unpack("<L", data_bytes[i:i + 4])[0]
                       for i in range(0, len(data_bytes), 4)]

        # write idx offsets to idx offset location
        log.info("Writing mDNS idx offsets")
        for i, offset in enumerate(offsets):
            self.atltool_wrapper.writereg(self.MIF_SHARED_BUFFER_ADDR + idx_offset + i * 4, offset)

        log.info("Writing mDNS records")
        # write records to records offset location
        for i, dword in enumerate(dword_array):
            self.atltool_wrapper.writereg(self.MIF_SHARED_BUFFER_ADDR + rr_ofset + i * 4, dword)

    def run_cable_diag(self, timeout=30):
        log.info("Run cable diag")
        cable_diag = self.read_drv_iface_struct_field("DRIVER_INTERFACE_IN.cableDiagControl")
        cable_diag.startDiag = 1
        cable_diag.waitTimeoutSec = timeout
        self.write_drv_iface_struct_field("DRIVER_INTERFACE_IN.cableDiagControl", cable_diag)
        self.confirm_shared_buffer_write()
        self.set_link_control_mode(HOST_MODE_ACTIVE)

    def get_cable_diag_status(self):
        cable_diag_status = self.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.cableDiagStatus")
        return cable_diag_status


if __name__ == "__main__":
    from atltoolper import AtlTool

    # Add driver interface structures to globals, so ctypes_struct_helper module could find them
    import __builtin__
    __builtin__.DRIVER_INTERFACE_IN = DRIVER_INTERFACE_IN
    __builtin__.DRIVER_INTERFACE_OUT = DRIVER_INTERFACE_OUT

    fw_config = FirmwareA2Config(AtlTool(port="pci1.00.0"))

    ####################################################################################################################
    # Put your manual experiments here
    ####################################################################################################################

    MAC_ADDR = "00:17:B6:01:02:03"
    IP4_ADDR = [
        "192.168.0.3", "192.168.0.4", "192.168.0.5", "192.168.0.6",
        "192.168.0.7", "192.168.0.8", "192.168.0.9", "192.168.0.10"
    ]
    IP6_ADDR = [
        "4000:0000:0000:0000:1601:bd17:0c02:2403", "4000:0000:0000:0000:1601:bd17:0c02:2404",
        "4000:0000:0000:0000:1601:bd17:0c02:2405", "4000:0000:0000:0000:1601:bd17:0c02:2406",
        "4000:0000:0000:0000:1601:bd17:0c02:2407", "4000:0000:0000:0000:1601:bd17:0c02:2408",
        "4000:0000:0000:0000:1601:bd17:0c02:2409", "4000:0000:0000:0000:1601:bd17:0c02:2410",
        "4000:0000:0000:0000:1601:bd17:0c02:2411", "4000:0000:0000:0000:1601:bd17:0c02:2412",
        "4000:0000:0000:0000:1601:bd17:0c02:2413", "4000:0000:0000:0000:1601:bd17:0c02:2414",
        "4000:0000:0000:0000:1601:bd17:0c02:2415", "4000:0000:0000:0000:1601:bd17:0c02:2416",
        "4000:0000:0000:0000:1601:bd17:0c02:2417", "4000:0000:0000:0000:1601:bd17:0c02:2418"
    ]

    sp_cfg = SleepProxyOffload()

    sp_cfg.ipv4_offload.arp_responder = True
    sp_cfg.ipv4_offload.echo_responder = True
    sp_cfg.ipv4_offload.ipv4 = IP4_ADDR

    sp_cfg.ipv6_offload.ns_responder = True
    sp_cfg.ipv6_offload.echo_responder = True
    sp_cfg.ipv6_offload.ipv6 = IP6_ADDR

    fw_config.configure_sleep_proxy(sp_cfg, MAC_ADDR, "output.txt")
