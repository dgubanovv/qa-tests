import os
import time
import timeit
import ctypes
import array
from abc import abstractmethod, ABCMeta

from utils import get_atf_logger

log = get_atf_logger()

WAKE_REASON_UNKNOWN = 0x00
WAKE_REASON_PANIC = 0x01
WAKE_REASON_MAGIC_PACKET = 0x02
WAKE_REASON_LINK = 0x03
WAKE_REASON_OTHER = 0x04
WAKE_REASON_REASSEMBLE = 0x05
WAKE_REASON_NAME_GUARD = 0x06
WAKE_REASON_ADDR_GUARD = 0x07
WAKE_REASON_PING = 0x08
WAKE_REASON_SYN = 0x09
WAKE_REASON_UDP = 0x0A
WAKE_REASON_FILTER = 0x0B
WAKE_REASON_TCPKA = 0x0C

WAKE_REASON_OFFSET = 0x7f


class OffloadKa(object):
    def __init__(self, timeout=0, local_port=0, remote_port=0, remote_mac_address="", win_size=0, seq_num=0, ack_num=0,
                 local_ip="", remote_ip=""):
        self.timeout = timeout
        self.local_port = local_port
        self.remote_port = remote_port
        self.remote_mac_address = remote_mac_address
        self.win_size = win_size
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.local_ip = local_ip
        self.remote_ip = remote_ip

    def __str__(self):
        res = "    Timeout = {}\n".format(self.timeout)
        res += "    Local port = {}\n".format(self.local_port)
        res += "    Remote port = {}\n".format(self.remote_port)
        res += "    Remote MAC address = {}\n".format(self.remote_mac_address)
        res += "    Window size = {}\n".format(self.win_size)
        res += "    Seq number = {}\n".format(self.seq_num)
        res += "    Ack number = {}\n".format(self.ack_num)
        res += "    Local IP = {}\n".format(self.local_ip)
        res += "    Remote IP = {}\n".format(self.remote_ip)
        return res


class MdnsRr(object):
    RRT_SRV = 33
    RRT_TXT = 16
    RRT_PTR = 12
    RRT_A = 1
    RRT_AAAA = 28

    ETH_MDNS_RR_TYPE_PTR = 0
    ETH_MDNS_RR_TYPE_SRV = 1
    ETH_MDNS_RR_TYPE_TXT = 2

    def __init__(self):
        self.type = 0
        self.question = ""
        self.answer = ""
        self.txt = ""
        self.srv = None
        self.tail = None

    @property
    def question_length(self):
        return len(self.question)

    @property
    def answer_length(self):
        return len(self.answer)

    @property
    def txt_length(self):
        return len(self.txt)

    @property
    def SIZEOF(self):
        size = self.question_length + 1  # 1 is end of string char
        size += 1  # 1 is first num of chars number
        size += 10  # size of tail
        if self.tail.type == MdnsRr.ETH_MDNS_RR_TYPE_TXT:
            if self.tail.rd_len > 1:
                size += 1  # txt len
                size += self.txt_length
                size += 1
                # print "!! txt", self.txt
        elif self.tail.type == MdnsRr.ETH_MDNS_RR_TYPE_PTR:
            size += self.answer_length + 1  # 1 is end of string char
            size += 1  # 1 is first num of chars number
        elif self.tail.type == MdnsRr.ETH_MDNS_RR_TYPE_SRV:
            if self.tail.rd_len >= 7:
                size += 2 + 2 + 2  # weight, port and priority
                size += self.answer_length + 1  # 1 is end of string char
                size += 1  # 1 is first num of chars number
        return size

    def __str__(self):
        if self.tail.type == MdnsRr.ETH_MDNS_RR_TYPE_TXT:
            res = "    Type = ETH_MDNS_RR_TYPE_TXT\n"
            res += "    Question = '{}'\n".format(self.question)
            res += "    Txt = '{}'\n".format(self.txt)
        elif self.tail.type == MdnsRr.ETH_MDNS_RR_TYPE_PTR:
            res = "    Type = ETH_MDNS_RR_TYPE_PTR\n"
            res += "    Question = '{}'\n".format(self.question)
            res += "    Answer = '{}'\n".format(self.answer)
        elif self.tail.type == MdnsRr.ETH_MDNS_RR_TYPE_SRV:
            res = "    Type = ETH_MDNS_RR_TYPE_SRV\n"
            res += "    Question = '{}'\n".format(self.question)
            res += "    Answer = '{}'\n".format(self.answer)
            if self.tail.rd_len >= 7:
                res += "    SRV weight = '{}'\n".format(self.srv.weight)
                res += "    SRV port = '{}'\n".format(self.srv.port)
                res += "    SRV priority = '{}'\n".format(self.srv.priority)
        res += "    Class = {}\n".format(self.tail.class_)
        res += "    Ttl = {}\n".format(self.tail.ttl)
        res += "    RD len = {}\n".format(self.tail.rd_len)
        return res

    @staticmethod
    def get_drv_iface_txt_rr(question, answer, ttl=4500):
        mdns_rr = MdnsRr()
        mdns_rr.tail = MdnsRrTail()
        mdns_rr.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_TXT
        mdns_rr.tail.class_ = 1
        mdns_rr.tail.ttl = ttl
        mdns_rr.question = question
        mdns_rr.txt = answer
        mdns_rr.tail.rd_len = mdns_rr.txt_length + 2
        return mdns_rr

    @staticmethod
    def get_drv_iface_ptr_rr(question, answer, ttl=4500):
        mdns_rr = MdnsRr()
        mdns_rr.tail = MdnsRrTail()
        mdns_rr.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_PTR
        mdns_rr.tail.class_ = 1
        mdns_rr.tail.ttl = ttl
        mdns_rr.question = question
        mdns_rr.answer = answer
        mdns_rr.tail.rd_len = mdns_rr.answer_length + 2 # first part size + terminating byte
        return mdns_rr

    @staticmethod
    def get_drv_iface_srv_rr(question, answer, ttl=120, priority=0, weight=0, port=0, class_=1):
        mdns_rr = MdnsRr()
        mdns_rr.tail = MdnsRrTail()
        mdns_rr.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_SRV
        mdns_rr.tail.class_ = class_
        mdns_rr.tail.ttl = ttl
        mdns_rr.question = question
        mdns_rr.answer = answer
        mdns_rr.srv = MdnsRdataSrv()
        mdns_rr.srv.priority = priority
        mdns_rr.srv.weight = weight
        mdns_rr.srv.port = port
        # rd_len = answer_length 2 + 2 + 2 + 1 + 1 (priority + weight + port + first part size + terminating byte)
        mdns_rr.tail.rd_len = mdns_rr.answer_length + 8
        return mdns_rr

    def to_bytes(self):
        data_bytes = bytearray()
        name_domains = self.question.split(".")
        for nd in name_domains:
            data_bytes.append(len(nd))
            for ch in nd:
                data_bytes.append(ord(ch))

        data_bytes.append(0x0)

        type_ = MdnsRr.RRT_TXT
        if self.tail.type == MdnsRr.ETH_MDNS_RR_TYPE_PTR:
            type_ = MdnsRr.RRT_PTR
        elif self.tail.type == MdnsRr.ETH_MDNS_RR_TYPE_SRV:
            type_ = MdnsRr.RRT_SRV
        data_bytes.append(type_ >> 8 & 0xff)
        data_bytes.append(type_ & 0xff)

        data_bytes.append(self.tail.class_ >> 8 & 0xff)
        data_bytes.append(self.tail.class_ & 0xff)

        data_bytes.append(self.tail.ttl >> 24 & 0xff)
        data_bytes.append(self.tail.ttl >> 16 & 0xff)
        data_bytes.append(self.tail.ttl >> 8 & 0xff)
        data_bytes.append(self.tail.ttl & 0xff)

        data_bytes.append(self.tail.rd_len >> 8 & 0xff)
        data_bytes.append(self.tail.rd_len & 0xff)

        if self.tail.type == MdnsRr.ETH_MDNS_RR_TYPE_TXT:
            if self.tail.rd_len > 1:
                texts = self.txt.split(".")
                for single_text in texts:
                    data_bytes.append(len(single_text))
                    for ch in single_text:
                        data_bytes.append(ord(ch))
                data_bytes.append(0x0)
        elif self.tail.type == MdnsRr.ETH_MDNS_RR_TYPE_PTR:
            if self.tail.rd_len > 0:
                name_domains = self.answer.split(".")
                for nd in name_domains:
                    data_bytes.append(len(nd))
                    for ch in nd:
                        data_bytes.append(ord(ch))
                data_bytes.append(0x0)
        elif self.tail.type == MdnsRr.ETH_MDNS_RR_TYPE_SRV:
            data_bytes.append(self.srv.priority >> 8 & 0xff)
            data_bytes.append(self.srv.priority & 0xff)
            data_bytes.append(self.srv.weight >> 8 & 0xff)
            data_bytes.append(self.srv.weight & 0xff)
            data_bytes.append(self.srv.port >> 8 & 0xff)
            data_bytes.append(self.srv.port & 0xff)
            name_domains = self.answer.split(".")
            for nd in name_domains:
                data_bytes.append(len(nd))
                for ch in nd:
                    data_bytes.append(ord(ch))
            data_bytes.append(0x0)

        return data_bytes


class MdnsRdataSrv(object):
    def __init__(self):
        self.weight = 0
        self.port = 0
        self.priority = 0


class MdnsRrTail(object):
    def __init__(self):
        self.class_ = 0
        self.type = 0
        self.ttl = 0
        self.rd_len = 0


class OffloadIpInfo(object):
    SIZEOF = 20

    def __init__(self):
        self.v4_addr_count = 0
        self.v4_addresses = []
        self.v4_masks = []
        self.v6_addr_count = 0
        self.v6_addresses = []
        self.v6_masks = []

    @property
    def v4_local_addr_count(self):
        return len(self.v4_addresses)

    @property
    def v6_local_addr_count(self):
        return len(self.v6_addresses)

    def __str__(self):
        res = "V4 local address count = 0x{:02x}\n".format(self.v4_local_addr_count)
        res += "V4 address count = 0x{:02x}\n".format(self.v4_addr_count)
        res += "V4 addresses = {}\n".format(str(self.v4_addresses))
        res += "V4 masks = {}\n".format(self.v4_masks)
        res += "V6 local address count = 0x{:02x}\n".format(self.v6_local_addr_count)
        res += "V6 address count = 0x{:02x}\n".format(self.v6_addr_count)
        res += "V6 addresses = {}\n".format(str(self.v6_addresses))
        res += "V6 masks = {}\n".format(self.v6_masks)
        return res


class OffloadPortInfo(object):
    SIZEOF = 12

    def __init__(self):
        self.udp_ports = []
        self.tcp_ports = []

    @property
    def udp_port_count(self):
        return len(self.udp_ports)

    @property
    def tcp_port_count(self):
        return len(self.tcp_ports)

    def __str__(self):
        res = "UDP port count = 0x{:02x}\n".format(self.udp_port_count)
        res += "TCP port count = 0x{:02x}\n".format(self.tcp_port_count)
        res += "UDP ports = {}\n".format(str(self.udp_ports))
        res += "TCP ports = {}\n".format(str(self.tcp_ports))
        return res


class OffloadKaInfo(object):
    SIZEOF = 20

    def __init__(self):
        self.retry_count = 0
        self.retry_interval = 0
        self.v4_kas = []
        self.v6_kas = []

    @property
    def v4_ka_count(self):
        return len(self.v4_kas)

    @property
    def v6_ka_count(self):
        return len(self.v6_kas)

    def __str__(self):
        res = "V4 KA count = 0x{:02x}\n".format(self.v4_ka_count)
        res += "V6 KA count = 0x{:02x}\n".format(self.v6_ka_count)
        res += "Retry count = 0x{:02x}\n".format(self.retry_count)
        res += "Retry interval = 0x{:02x}\n".format(self.retry_interval)
        if self.v4_ka_count > 0:
            res += "KA V4 array:\n"
            for i in range(self.v4_ka_count):
                res += str(self.v4_kas[i])
                if i < self.v4_ka_count - 1:
                    res += "    ---\n"
        if self.v6_ka_count > 0:
            res += "KA V6 array:\n"
            for i in range(self.v6_ka_count):
                res += str(self.v6_kas[i])
                if i < self.v6_ka_count - 1:
                    res += "    ---\n"
        return res


class OffloadRrInfo(object):
    SIZEOF = 16

    def __init__(self):
        self.entries = []

    @property
    def count(self):
        return len(self.entries)

    @property
    def buf_len(self):
        return sum([entry.SIZEOF for entry in self.entries])

    def __str__(self):
        res = "RR count = 0x{:02x}\n".format(self.count)
        res += "RR buffer length = 0x{:02x}\n".format(self.buf_len)
        res += "RR array:\n"
        for i in range(self.count):
            res += str(self.entries[i])
            if i < self.count - 1:
                res += "    ---\n"
        return res


class ConfigMemory(object):
    BASE_ADDRESS = 0x80000000

    DATA_REG = 0x328
    ADDRESS_REG = 0x32C
    OP_REG = 0x404

    @staticmethod
    def write_dword(mbu_wrapper, address, value):
        mbu_wrapper.writereg(ConfigMemory.DATA_REG, value)
        mbu_wrapper.writereg(ConfigMemory.ADDRESS_REG, ConfigMemory.BASE_ADDRESS | address)

        interrupt_reg = mbu_wrapper.readreg(ConfigMemory.OP_REG)
        interrupt_reg |= 0x2
        mbu_wrapper.writereg(ConfigMemory.OP_REG, interrupt_reg)

        start = timeit.default_timer()
        while timeit.default_timer() - start < 1.0:
            op_reg = mbu_wrapper.readreg(ConfigMemory.ADDRESS_REG)
            if (op_reg >> 0x1E) & 0x1:
                return True
            time.sleep(0.0001)
        raise Exception("Failed to write DWORD to config memory")


class SettingsMemory(object):
    BASE_ADDRESS = 0x20000000

    DATA_REG = 0x328
    ADDRESS_REG = 0x32C
    OP_REG = 0x404

    @staticmethod
    def write_dword(mbu_wrapper, address, value):
        mbu_wrapper.writereg(SettingsMemory.DATA_REG, value)
        mbu_wrapper.writereg(SettingsMemory.ADDRESS_REG, SettingsMemory.BASE_ADDRESS | address)

        interrupt_reg = mbu_wrapper.readreg(SettingsMemory.OP_REG)
        interrupt_reg |= 0x2
        mbu_wrapper.writereg(SettingsMemory.OP_REG, interrupt_reg)

        start = timeit.default_timer()
        while timeit.default_timer() - start < 1.0:
            op_reg = mbu_wrapper.readreg(SettingsMemory.ADDRESS_REG)
            if (op_reg >> 0x1E) & 0x1:
                return True
            time.sleep(0.0001)
        raise Exception("Failed to write DWORD to config memory")


class FWStatistics(object):
    RESERVED1_OFS = 0x0000
    PHY_FAULT_CODE_OFS = 0x004E
    PHY_TEMPERATURE_OFS = 0x0050
    CABLE_LENGTH_OFS = 0x0052
    RESERVED_OFS = 0x0053
    CABLE_DIAG_DATA_OFS = 0x0054
    RESERVED2_OFS = 0x0064
    WAKE_REASON_OFS = 0x007F
    BIG_PACKET_LENGTH_COUNTER_OFS = 0x0080
    NIC_CAPS_LO_OFS = 0x0084
    NIC_CAPS_HIGH_OFS = 0x0088
    RESERVED3_OFS = 0x008C
    RESERVED4_OFS = 0x00AC
    LINK_COPPER_UP_DOWN_COUNT = 0x00B8
    LINK_SYSTEM_UP_DOWN_COUNT = 0x00BC
    LINK_REPORT_UP_DOWN_COUNT = 0x00C0
    LINK_HOST_REQUEST_UP_DOWN_COUNT = 0x00C4
    LINK_HOST_REQUEST_SLEEP_SEMAPHORE_ISSUES_COUNT = 0x00C8
    LINK_HOST_ADVERTISE_RESET_COUNT = 0x00CC
    LINK_FAST_RETRAIN_BLOCK_LOCK_COUNT = 0x00D0
    WAKE_EVENT_COUNTER_OFS = 0x00D4
    EEE_LINK_DROPS_COUNTER_1_OFS = 0x00D8
    EEE_LINK_DROPS_COUNTER_2_OFS = 0x00DC
    EEE_LINK_FAILURE_COUNTER_OFS = 0x00E0
    EEE_STATE_MACHINE_COUNTER_1_OFS = 0x00E4
    EEE_STATE_MACHINE_COUNTER_2_OFS = 0x00E8
    EEE_STATE_MACHINE_COUNTER_3_OFS = 0x00EC
    EEE_STATE_MACHINE_COUNTER_4_OFS = 0x00F0
    EEE_STATE_MACHINE_COUNTER_5_OFS = 0x00F4
    EEE_STATE_MACHINE_COUNTER_6_OFS = 0x00F8
    EEE_STATE_MACHINE_COUNTER_7_OFS = 0x00FC
    EEE_STATE_MACHINE_COUNTER_8_OFS = 0x0100
    EEE_STATE_MACHINE_COUNTER_9_OFS = 0x0104
    TX_STUCK_COUNT = 0x0108
    SETTINGS_ADDRESS_OFS = 0x010C
    SETTINGS_LENGTH_OFS = 0x0110
    CAPS_EX_OFS = 0x0114
    GPIO_PIN_OFS = 0x0118
    PCIE_AER_REGS_OFS = 0x0124


class FWSettings(object):
    MTU_OFS = 0x00
    DOWNSHIFT_RETRY_COUNT_OFS = 0x04
    LINK_PAUSE_FRAME_QUANTA_100M_OFS = 0x08
    LINK_PAUSE_FRAME_THRESHOLD_100M_OFS = 0x0C
    LINK_PAUSE_FRAME_QUANTA_1G_OFS = 0x10
    LINK_PAUSE_FRAME_THRESHOLD_1G_OFS = 0x14
    LINK_PAUSE_FRAME_QUANTA_2P5G_OFS = 0x18
    LINK_PAUSE_FRAME_THRESHOLD_2P5G_OFS = 0x1C
    LINK_PAUSE_FRAME_QUANTA_5G_OFS = 0x20
    LINK_PAUSE_FRAME_THRESHOLD_5G_OFS = 0x24
    LINK_PAUSE_FRAME_QUANTA_10G_OFS = 0x28
    LINK_PAUSE_FRAME_THRESHOLD_10G_OFS = 0x2C
    PFC_QUANTA_CLASS_0_OFS = 0x30
    PFC_THRESHOLD_CLASS_0_OFS = 0x34
    PFC_QUANTA_CLASS_1_OFS = 0x38
    PFC_THRESHOLD_CLASS_1_OFS = 0x3C
    PFC_QUANTA_CLASS_2_OFS = 0x40
    PFC_THRESHOLD_CLASS_2_OFS = 0x44
    PFC_QUANTA_CLASS_3_OFS = 0x48
    PFC_THRESHOLD_CLASS_3_OFS = 0x4C
    PFC_QUANTA_CLASS_4_OFS = 0x50
    PFC_THRESHOLD_CLASS_4_OFS = 0x54
    PFC_QUANTA_CLASS_5_OFS = 0x58
    PFC_THRESHOLD_CLASS_5_OFS = 0x5C
    PFC_QUANTA_CLASS_6_OFS = 0x60
    PFC_THRESHOLD_CLASS_6_OFS = 0x64
    PFC_QUANTA_CLASS_7_OFS = 0x68
    PFC_THRESHOLD_CLASS_7_OFS = 0x6C
    EEE_LINK_DOWN_TIMEOUT_OFS = 0x70
    EEE_LINK_UP_TIMEOUT_OFS = 0x74
    EEE_MAX_LINK_DROPS_OFS = 0x78
    EEE_RATES_MASK_OFS = 0x7C
    WAKE_TIMER_OFS = 0x80
    THERMAL_SHUTDOWN_OFF_TEMP_OFS = 0x84
    THERMAL_SHUTDOWN_WARNING_TEMP_OFS = 0x88
    THERMAL_SHUTDOWN_COLD_TEMP_OFS = 0x8C
    MSM_OPTIONS_OFS = 0x90
    DAC_CABLE_SERDES_MODES_OFS = 0x94
    MEDIA_DETECT_OFS = 0x98
    WOL_EX_OFS = 0x9C

    class WolEx(object):
        WAKE_ON_LINK_KEEP_RATE = 0x01
        WAKE_ON_MAGIC_RESTORE_RATE = 0x02


class DrvMessage(object):
    __metaclass__ = ABCMeta

    msg_id = 0x0

    CAPS_HI_RESERVED1 = 0x00000001
    CAPS_HI_10BASET_EEE = 0x00000002
    CAPS_HI_RESERVED2 = 0x00000004
    CAPS_HI_PAUSE = 0x00000008
    CAPS_HI_ASYMMETRIC_PAUSE = 0x00000010
    CAPS_HI_100BASETX_EEE = 0x00000020
    CAPS_HI_RESERVED3 = 0x00000040
    CAPS_HI_RESERVED4 = 0x00000080
    CAPS_HI_1000BASET_FD_EEE = 0x00000100
    CAPS_HI_2P5GBASET_FD_EEE = 0x00000200
    CAPS_HI_5GBASET_FD_EEE = 0x00000400
    CAPS_HI_10GBASET_FD_EEE = 0x00000800
    CAPS_HI_FW_REQUEST = 0x00001000
    CAPS_HI_PHY_LOG = 0x00002000
    CAPS_HI_EEE_AUTO_DISABLE = 0x00004000
    CAPS_HI_PFC = 0x00008000
    CAPS_HI_WAKE_ON_LINK = 0x00010000
    CAPS_HI_CABLE_DIAG = 0x00020000
    CAPS_HI_TEMPERATURE = 0x00020000
    CAPS_HI_DOWNSHIFT = 0x00080000
    CAPS_HI_PTP_AVB_EN = 0x00100000
    CAPS_HI_THERMAL_SHUTDOWN = 0x00200000
    CAPS_HI_LINK_DROP = 0x00400000
    CAPS_HI_SLEEP_PROXY = 0x00800000
    CAPS_HI_WOL = 0x01000000
    CAPS_HI_MAC_STOP = 0x02000000
    CAPS_HI_EXT_LOOPBACK = 0x04000000
    CAPS_HI_INT_LOOPBACK = 0x08000000
    CAPS_HI_EFUSE_AGENT = 0x10000000
    CAPS_HI_WOL_TIMER = 0x20000000
    CAPS_HI_STATISTICS = 0x40000000
    CAPS_HI_TRANSACTION_ID = 0x80000000

    SMBUS_WRITE_REQUEST_MASK = 0x00004000
    SMBUS_WRITE_REQUEST_SHIFT = 14
    SMBUS_READ_REQUEST_MASK = 0x00002000
    SMBUS_READ_REQUEST_SHIFT = 13

    def __init__(self):
        self.caps = 0

    @abstractmethod
    def get_data(self):
        pass

    def get_beton(self):
        beton = []
        offset = 0x80000000

        beton.append("writereg 0x0328 0x{:08x}".format(self.msg_id))
        beton.append("writereg 0x032C 0x{:08x}".format(offset))
        beton.append("writereg 0x0404 0x00000002")
        offset += 4

        data = self.get_data()
        for d in data:
            beton.append("writereg 0x0328 0x{:08x}".format(d))
            beton.append("writereg 0x032C 0x{:08x}".format(offset))
            beton.append("writereg 0x0404 0x00000002")
            offset += 4

        beton.append("writereg 0x036C 0x{:08x}".format(self.caps))

        return beton

    def apply(self, mbu_wrapper, out_beton_filename=None, cleanup_fw=True):
        """Apply FW settings to the chip using MBU and save script to file"""
        data = [self.msg_id, ] + self.get_data()

        if out_beton_filename:
            offset = 0x80000000
            with open(out_beton_filename, "w") as beton_file:
                if cleanup_fw:
                    beton_file.write("writereg 0x36C 0x00000000\n")
                    beton_file.write("pause 2 s\n\n")

                for d in data:
                    beton_file.write("writereg 0x328 0x{:08X}\n".format(d))
                    beton_file.write("writereg 0x32C 0x{:08X}\n".format(offset))
                    beton_file.write("writereg 0x404 0x{:08X}\n\n".format(2))
                    offset += 4

                beton_file.write("writereg 0x36C 0x{:08X}".format(self.caps))

        if cleanup_fw:
            log.info("Cleaning-up FW configuration commit command (writereg 0x36C 0x00000000)...")
            mbu_wrapper.writereg(0x36C, 0x0)
            time.sleep(2)

        mbu_wrapper.dump_to_config_memory(data)

        log.info("Commit FW configuration...")
        mbu_wrapper.writereg(0x36C, self.caps)
        log.info("Configured")


class DrvEthConfig(DrvMessage):
    msg_id = 0x05

    FLAG_DATAPATH_CONTROL = 0x00000001

    def __init__(self):
        super(DrvEthConfig, self).__init__()
        self.caps = self.CAPS_HI_SLEEP_PROXY
        self.version = 0
        self.len = 0
        self.mac = ""
        self.flags = 0
        self.ips = None
        self.ports = OffloadPortInfo()
        self.kas = OffloadKaInfo()
        self.rrs = OffloadRrInfo()

    @staticmethod
    def get_byte(ind, data):
        i = ind // 4
        o = ind - i * 4
        return data[i] >> (8 * o) & 0xff

    @staticmethod
    def from_beton(file):
        if not os.path.isfile(file):
            raise Exception("File {} doesn't exist".format(file))
        with open(file, "r") as f:
            lines = f.readlines()
        if lines is None or len(lines) == 0:
            raise Exception("File {} is empty".format(file))

        data = []
        for line in lines:
            if "writereg 0x0328" in line:
                datax = line.rstrip("\r\n")[16:]
                v = int(datax, 16)
                data.append(v)

        if data[0] != 0x5:
            raise Exception("First param in data is not a command 0x5")

        data = data[1:]

        cfg = DrvEthConfig()

        cfg.version = data[0]
        cfg.len = data[1]

        mac_high = data[2]
        mac_low = data[3]
        cfg.mac = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
            mac_high & 0xff,
            mac_high >> 8 & 0xff,
            mac_high >> 16 & 0xff,
            mac_high >> 24 & 0xff,
            mac_low & 0xff,
            mac_low >> 8 & 0xff)

        ips = OffloadIpInfo()
        v4_local_addr_count = data[4] & 0xff
        ips.v4_addr_count = data[4] >> 8 & 0xff
        v6_local_addr_count = data[4] >> 16 & 0xff
        ips.v6_addr_count = data[4] >> 24 & 0xff

        v4_addr_offset = data[5]
        v4_mask_offset = data[6]
        v6_addr_offset = data[7]
        v6_mask_offset = data[8]
        for i in range(v4_local_addr_count):
            baddr = 4 * 4 + v4_addr_offset + i * 4
            ip1 = DrvEthConfig.get_byte(baddr, data)
            ip2 = DrvEthConfig.get_byte(baddr + 1, data)
            ip3 = DrvEthConfig.get_byte(baddr + 2, data)
            ip4 = DrvEthConfig.get_byte(baddr + 3, data)
            ip = "{}.{}.{}.{}".format(ip1, ip2, ip3, ip4)
            ips.v4_addresses.append(ip)

        baddr = 4 * 4 + v4_mask_offset
        for i in range(v4_local_addr_count):
            ips.v4_masks.append(DrvEthConfig.get_byte(baddr + i, data))

        for i in range(v6_local_addr_count):
            baddr = 4 * 4 + v6_addr_offset + i * 16
            ip1 = DrvEthConfig.get_byte(baddr, data)
            ip2 = DrvEthConfig.get_byte(baddr + 1, data)
            ip3 = DrvEthConfig.get_byte(baddr + 2, data)
            ip4 = DrvEthConfig.get_byte(baddr + 3, data)
            ip5 = DrvEthConfig.get_byte(baddr + 4, data)
            ip6 = DrvEthConfig.get_byte(baddr + 5, data)
            ip7 = DrvEthConfig.get_byte(baddr + 6, data)
            ip8 = DrvEthConfig.get_byte(baddr + 7, data)
            ip9 = DrvEthConfig.get_byte(baddr + 8, data)
            ip10 = DrvEthConfig.get_byte(baddr + 9, data)
            ip11 = DrvEthConfig.get_byte(baddr + 10, data)
            ip12 = DrvEthConfig.get_byte(baddr + 11, data)
            ip13 = DrvEthConfig.get_byte(baddr + 12, data)
            ip14 = DrvEthConfig.get_byte(baddr + 13, data)
            ip15 = DrvEthConfig.get_byte(baddr + 14, data)
            ip16 = DrvEthConfig.get_byte(baddr + 15, data)

            ip = "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}".format(
                ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8, ip9, ip10, ip11, ip12, ip13, ip14, ip15, ip16)
            ips.v6_addresses.append(ip)

        baddr = 4 * 4 + v6_mask_offset
        for i in range(v6_local_addr_count):
            ips.v6_masks.append(DrvEthConfig.get_byte(baddr + i, data))

        cfg.ips = ips

        ports = OffloadPortInfo()
        udp_port_count = data[9] & 0xffff
        tcp_port_count = data[9] >> 16 & 0xffff
        udp_port_offset = data[10]
        tcp_port_offset = data[11]
        for i in range(udp_port_count):
            baddr = 9 * 4 + udp_port_offset + i * 2
            ph = DrvEthConfig.get_byte(baddr, data)
            pl = DrvEthConfig.get_byte(baddr + 1, data)
            p = ph << 8 | pl
            ports.udp_ports.append(p)
        for i in range(tcp_port_count):
            baddr = 9 * 4 + tcp_port_offset + i * 2
            ph = DrvEthConfig.get_byte(baddr, data)
            pl = DrvEthConfig.get_byte(baddr + 1, data)
            p = ph << 8 | pl
            ports.tcp_ports.append(p)

        cfg.ports = ports

        kas = OffloadKaInfo()
        v4_ka_count = data[12] & 0xffff
        v6_ka_count = data[12] >> 16 & 0xffff
        kas.retry_count = data[13]
        kas.retry_interval = data[14]
        v4_ka_offset = data[15]
        v6_ka_offset = data[16]
        for i in range(v4_ka_count):
            v4_ka = OffloadKa()
            baddr = 12 * 4 + v4_ka_offset + i * 32
            tmo1 = DrvEthConfig.get_byte(baddr, data)
            tmo2 = DrvEthConfig.get_byte(baddr + 1, data)
            tmo3 = DrvEthConfig.get_byte(baddr + 2, data)
            tmo4 = DrvEthConfig.get_byte(baddr + 3, data)
            v4_ka.timeout = tmo4 << 24 | tmo3 << 16 | tmo2 << 8 | tmo1
            p1 = DrvEthConfig.get_byte(baddr + 4, data)
            p2 = DrvEthConfig.get_byte(baddr + 5, data)
            v4_ka.local_port = p2 << 8 | p1
            p1 = DrvEthConfig.get_byte(baddr + 6, data)
            p2 = DrvEthConfig.get_byte(baddr + 7, data)
            v4_ka.remote_port = p2 << 8 | p1
            m1 = DrvEthConfig.get_byte(baddr + 8, data)
            m2 = DrvEthConfig.get_byte(baddr + 9, data)
            m3 = DrvEthConfig.get_byte(baddr + 10, data)
            m4 = DrvEthConfig.get_byte(baddr + 11, data)
            m5 = DrvEthConfig.get_byte(baddr + 12, data)
            m6 = DrvEthConfig.get_byte(baddr + 13, data)
            v4_ka.remote_mac_address = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(m6, m5, m4, m3, m2, m1)
            w1 = DrvEthConfig.get_byte(baddr + 14, data)
            w2 = DrvEthConfig.get_byte(baddr + 15, data)
            v4_ka.win_size = w2 << 8 | w1
            s1 = DrvEthConfig.get_byte(baddr + 16, data)
            s2 = DrvEthConfig.get_byte(baddr + 17, data)
            s3 = DrvEthConfig.get_byte(baddr + 18, data)
            s4 = DrvEthConfig.get_byte(baddr + 19, data)
            v4_ka.seq_num = s4 << 24 | s3 << 16 | s2 << 8 | s1
            a1 = DrvEthConfig.get_byte(baddr + 20, data)
            a2 = DrvEthConfig.get_byte(baddr + 21, data)
            a3 = DrvEthConfig.get_byte(baddr + 22, data)
            a4 = DrvEthConfig.get_byte(baddr + 23, data)
            v4_ka.ack_num = a4 << 24 | a3 << 16 | a2 << 8 | a1
            i1 = DrvEthConfig.get_byte(baddr + 24, data)
            i2 = DrvEthConfig.get_byte(baddr + 25, data)
            i3 = DrvEthConfig.get_byte(baddr + 26, data)
            i4 = DrvEthConfig.get_byte(baddr + 27, data)
            # v4_ka.local_ip = "{}.{}.{}.{}".format(i1, i2, i3, i4)
            v4_ka.local_ip = "{}.{}.{}.{}".format(i4, i3, i2, i1)
            i1 = DrvEthConfig.get_byte(baddr + 28, data)
            i2 = DrvEthConfig.get_byte(baddr + 29, data)
            i3 = DrvEthConfig.get_byte(baddr + 30, data)
            i4 = DrvEthConfig.get_byte(baddr + 31, data)
            # v4_ka.remote_ip = "{}.{}.{}.{}".format(i1, i2, i3, i4)
            v4_ka.remote_ip = "{}.{}.{}.{}".format(i4, i3, i2, i1)
            kas.v4_kas.append(v4_ka)
        for i in range(v6_ka_count):
            v6_ka = OffloadKa()
            baddr = 12 * 4 + v6_ka_offset + i * 32
            tmo1 = DrvEthConfig.get_byte(baddr, data)
            tmo2 = DrvEthConfig.get_byte(baddr + 1, data)
            tmo3 = DrvEthConfig.get_byte(baddr + 2, data)
            tmo4 = DrvEthConfig.get_byte(baddr + 3, data)
            v6_ka.timeout = tmo4 << 24 | tmo3 << 16 | tmo2 << 8 | tmo1
            p1 = DrvEthConfig.get_byte(baddr + 4, data)
            p2 = DrvEthConfig.get_byte(baddr + 5, data)
            v6_ka.local_port = p2 << 8 | p1
            p1 = DrvEthConfig.get_byte(baddr + 6, data)
            p2 = DrvEthConfig.get_byte(baddr + 7, data)
            v6_ka.remote_port = p2 << 8 | p1
            m1 = DrvEthConfig.get_byte(baddr + 8, data)
            m2 = DrvEthConfig.get_byte(baddr + 9, data)
            m3 = DrvEthConfig.get_byte(baddr + 10, data)
            m4 = DrvEthConfig.get_byte(baddr + 11, data)
            m5 = DrvEthConfig.get_byte(baddr + 12, data)
            m6 = DrvEthConfig.get_byte(baddr + 13, data)
            v6_ka.remote_mac_address = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(m1, m2, m3, m4, m5, m6)
            w1 = DrvEthConfig.get_byte(baddr + 14, data)
            w2 = DrvEthConfig.get_byte(baddr + 15, data)
            v6_ka.win_size = w2 << 8 | w1
            s1 = DrvEthConfig.get_byte(baddr + 16, data)
            s2 = DrvEthConfig.get_byte(baddr + 17, data)
            s3 = DrvEthConfig.get_byte(baddr + 18, data)
            s4 = DrvEthConfig.get_byte(baddr + 19, data)
            v6_ka.seq_num = s4 << 24 | s3 << 16 | s2 << 8 | s1
            a1 = DrvEthConfig.get_byte(baddr + 20, data)
            a2 = DrvEthConfig.get_byte(baddr + 21, data)
            a3 = DrvEthConfig.get_byte(baddr + 22, data)
            a4 = DrvEthConfig.get_byte(baddr + 23, data)
            v6_ka.ack_num = a4 << 24 | a3 << 16 | a2 << 8 | a1
            ip1 = DrvEthConfig.get_byte(baddr + 24, data)
            ip2 = DrvEthConfig.get_byte(baddr + 25, data)
            ip3 = DrvEthConfig.get_byte(baddr + 26, data)
            ip4 = DrvEthConfig.get_byte(baddr + 27, data)
            ip5 = DrvEthConfig.get_byte(baddr + 28, data)
            ip6 = DrvEthConfig.get_byte(baddr + 29, data)
            ip7 = DrvEthConfig.get_byte(baddr + 30, data)
            ip8 = DrvEthConfig.get_byte(baddr + 31, data)
            ip9 = DrvEthConfig.get_byte(baddr + 32, data)
            ip10 = DrvEthConfig.get_byte(baddr + 33, data)
            ip11 = DrvEthConfig.get_byte(baddr + 34, data)
            ip12 = DrvEthConfig.get_byte(baddr + 35, data)
            ip13 = DrvEthConfig.get_byte(baddr + 36, data)
            ip14 = DrvEthConfig.get_byte(baddr + 37, data)
            ip15 = DrvEthConfig.get_byte(baddr + 38, data)
            ip16 = DrvEthConfig.get_byte(baddr + 39, data)
            v6_ka.local_ip = "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}".format(
                ip2, ip1, ip4, ip3, ip6, ip5, ip8, ip7, ip10, ip9, ip12, ip11, ip14, ip13, ip16, ip15)
            ip1 = DrvEthConfig.get_byte(baddr + 40, data)
            ip2 = DrvEthConfig.get_byte(baddr + 41, data)
            ip3 = DrvEthConfig.get_byte(baddr + 42, data)
            ip4 = DrvEthConfig.get_byte(baddr + 43, data)
            ip5 = DrvEthConfig.get_byte(baddr + 44, data)
            ip6 = DrvEthConfig.get_byte(baddr + 45, data)
            ip7 = DrvEthConfig.get_byte(baddr + 46, data)
            ip8 = DrvEthConfig.get_byte(baddr + 47, data)
            ip9 = DrvEthConfig.get_byte(baddr + 48, data)
            ip10 = DrvEthConfig.get_byte(baddr + 49, data)
            ip11 = DrvEthConfig.get_byte(baddr + 50, data)
            ip12 = DrvEthConfig.get_byte(baddr + 51, data)
            ip13 = DrvEthConfig.get_byte(baddr + 52, data)
            ip14 = DrvEthConfig.get_byte(baddr + 53, data)
            ip15 = DrvEthConfig.get_byte(baddr + 54, data)
            ip16 = DrvEthConfig.get_byte(baddr + 55, data)
            v6_ka.remote_ip = "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}".format(
                ip2, ip1, ip4, ip3, ip6, ip5, ip8, ip7, ip10, ip9, ip12, ip11, ip14, ip13, ip16, ip15)
            kas.v6_kas.append(v6_ka)

        cfg.kas = kas

        rrs = OffloadRrInfo()
        rr_count = data[17]
        rr_idx_offset = data[19]
        rr_idx_offsets = []
        for i in range(rr_count):
            baddr = 17 * 4 + rr_idx_offset + i * 4
            o1 = DrvEthConfig.get_byte(baddr, data)
            o2 = DrvEthConfig.get_byte(baddr + 1, data)
            o3 = DrvEthConfig.get_byte(baddr + 2, data)
            o4 = DrvEthConfig.get_byte(baddr + 3, data)
            o = o4 << 24 | o3 << 16 | o2 << 8 | o1
            rr_idx_offsets.append(o)
        rr_buf_offset = data[20]

        def read_domain_name(data, offset):
            name = []
            redirect = None
            baddr = offset
            ch = DrvEthConfig.get_byte(baddr, data)
            # smth = ""
            # for i in range(50):
            #     smth += chr(DrvEthConfig.get_byte(baddr + i, data))
            # print "!!!", smth

            while ch != 0x00:
                baddr += 1
                if ch >= 0xc0:
                    if redirect is None:
                        redirect = baddr
                    ch2 = DrvEthConfig.get_byte(baddr, data)
                    offset = (ch - 0xc0) << 8 | ch2
                    baddr = 17 * 4 + rr_buf_offset + offset
                else:
                    for i in range(ch):
                        name.append(chr(DrvEthConfig.get_byte(baddr + i, data)))
                    name.append('.')
                    baddr += ch
                ch = DrvEthConfig.get_byte(baddr, data)

            return "".join(name[:-1]), redirect

        for i in range(rr_count):
            # name, redirect = read_domain_name(data, rr_idx_offsets[i])
            name, redirect = read_domain_name(data, 17 * 4 + rr_idx_offsets[i])
            # print "|{}|{}|".format(name, len(name))
            if redirect is None:
                baddr = 17 * 4 + rr_idx_offsets[i] + len(name) + 2
            else:
                baddr = redirect + 1
            tail = MdnsRrTail()
            t1 = DrvEthConfig.get_byte(baddr, data)
            t2 = DrvEthConfig.get_byte(baddr + 1, data)
            tail.type = t1 << 8 | t2
            c1 = DrvEthConfig.get_byte(baddr + 2, data)
            c2 = DrvEthConfig.get_byte(baddr + 3, data)
            tail.class_ = c1 << 8 | c2
            tt1 = DrvEthConfig.get_byte(baddr + 4, data)
            tt2 = DrvEthConfig.get_byte(baddr + 5, data)
            tt3 = DrvEthConfig.get_byte(baddr + 6, data)
            tt4 = DrvEthConfig.get_byte(baddr + 7, data)
            tail.ttl = tt1 << 24 | tt2 << 16 | tt3 << 8 | tt4
            r1 = DrvEthConfig.get_byte(baddr + 8, data)
            r2 = DrvEthConfig.get_byte(baddr + 9, data)
            # print "{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}".format(t1, t2, c1, c2, tt1, tt2, tt3, tt4, r1, r2)
            tail.rd_len = r1 << 8 | r2

            tail_offset = 10
            mdns_rr = MdnsRr()
            mdns_rr.tail = tail
            mdns_rr.question = name
            if mdns_rr.tail.type == MdnsRr.RRT_TXT:
                mdns_rr.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_TXT
                if tail.rd_len > 1:
                    txt = ""
                    txt_len = DrvEthConfig.get_byte(baddr + tail_offset, data)
                    for i in range(txt_len):
                        ch = DrvEthConfig.get_byte(baddr + tail_offset + 1 + i, data)
                        txt += chr(ch)
                    mdns_rr.txt = txt
            elif mdns_rr.tail.type == MdnsRr.RRT_PTR:
                mdns_rr.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_PTR
                if tail.rd_len > 0:
                    mdns_rr.answer, _ = read_domain_name(data, baddr + tail_offset)
            elif mdns_rr.tail.type == MdnsRr.RRT_SRV:
                mdns_rr.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_SRV
                rdata_srv_len = 7
                if tail.rd_len >= rdata_srv_len:
                    rdata_srv = MdnsRdataSrv()
                    pr1 = DrvEthConfig.get_byte(baddr + tail_offset, data)
                    pr2 = DrvEthConfig.get_byte(baddr + tail_offset + 1, data)
                    rdata_srv.priority = pr1 << 8 | pr2
                    w1 = DrvEthConfig.get_byte(baddr + tail_offset + 2, data)
                    w2 = DrvEthConfig.get_byte(baddr + tail_offset + 3, data)
                    rdata_srv.weight = w1 << 8 | w2
                    p1 = DrvEthConfig.get_byte(baddr + tail_offset + 4, data)
                    p2 = DrvEthConfig.get_byte(baddr + tail_offset + 5, data)
                    rdata_srv.port = p1 << 8 | p2

                    mdns_rr.answer, _ = read_domain_name(data, baddr + tail_offset + 6)
                    mdns_rr.srv = rdata_srv

            rrs.entries.append(mdns_rr)

        cfg.rrs = rrs

        return cfg

    def get_data(self):
        data = []
        data_offset = OffloadIpInfo.SIZEOF + OffloadPortInfo.SIZEOF + OffloadKaInfo.SIZEOF + OffloadRrInfo.SIZEOF

        data.append(self.version)
        data.append(self.len)  # TODO: not used

        macs = self.mac.split(":")
        m1 = int(macs[3], 16) << 24 | int(macs[2], 16) << 16 | int(macs[1], 16) << 8 | int(macs[0], 16)
        m2 = (self.flags & 0xFF) << 16 | int(macs[5], 16) << 8 | int(macs[4], 16)
        data.append(m1)
        data.append(m2)

        ip_counts = self.ips.v6_addr_count << 24 | self.ips.v6_local_addr_count << 16 | self.ips.v4_addr_count << 8 | self.ips.v4_local_addr_count
        data.append(ip_counts)

        ip_v4_addresses_offset = data_offset
        data.append(ip_v4_addresses_offset)
        ip_v4_mask_offset = ip_v4_addresses_offset + self.ips.v4_local_addr_count * 4
        data.append(ip_v4_mask_offset)
        ip_v6_addresses_offset = ip_v4_mask_offset + self.ips.v4_local_addr_count * 1
        data.append(ip_v6_addresses_offset)
        ip_v6_mask_offset = ip_v6_addresses_offset + self.ips.v6_local_addr_count * 16
        data.append(ip_v6_mask_offset)

        port_count = self.ports.tcp_port_count << 16 | self.ports.udp_port_count
        data.append(port_count)
        udp_ports_offset = ip_v6_mask_offset + self.ips.v6_local_addr_count * 1 - OffloadIpInfo.SIZEOF
        data.append(udp_ports_offset)
        tcp_ports_offset = udp_ports_offset + self.ports.udp_port_count * 2
        data.append(tcp_ports_offset)

        ka_count = self.kas.v6_ka_count << 16 | self.kas.v4_ka_count
        data.append(ka_count)
        data.append(self.kas.retry_count)
        data.append(self.kas.retry_interval)
        v4_ka_offset = tcp_ports_offset + self.ports.tcp_port_count * 2 - OffloadPortInfo.SIZEOF
        data.append(v4_ka_offset)
        v6_ka_offset = v4_ka_offset + self.kas.v4_ka_count * 32
        data.append(v6_ka_offset)

        data.append(self.rrs.count)
        data.append(self.rrs.buf_len)
        rridx_offset = v6_ka_offset + self.kas.v6_ka_count * 56 - OffloadKaInfo.SIZEOF
        data.append(rridx_offset)
        rrbuf_offset = rridx_offset + self.rrs.count * 4
        data.append(rrbuf_offset)

        # create byte array
        bytes = bytearray()
        for v4_addr in self.ips.v4_addresses:
            ipb = v4_addr.split(".")
            for b in ipb:
                bytes.append(int(b))
        for m in self.ips.v4_masks:
            bytes.append(int(m))
        for v6_addr in self.ips.v6_addresses:
            ipv6arr = bytearray()
            for ipb in v6_addr.split(":"):
                ipb1 = ipb[0:2]
                ipb2 = ipb[2:4]
                ipv6arr.append(int(ipb1, 16))
                ipv6arr.append(int(ipb2, 16))

            # TODO: can refactor code below since bytes should not be swapped
            bytes.append(ipv6arr[0])
            bytes.append(ipv6arr[1])
            bytes.append(ipv6arr[2])
            bytes.append(ipv6arr[3])

            bytes.append(ipv6arr[4])
            bytes.append(ipv6arr[5])
            bytes.append(ipv6arr[6])
            bytes.append(ipv6arr[7])

            bytes.append(ipv6arr[8])
            bytes.append(ipv6arr[9])
            bytes.append(ipv6arr[10])
            bytes.append(ipv6arr[11])

            bytes.append(ipv6arr[12])
            bytes.append(ipv6arr[13])
            bytes.append(ipv6arr[14])
            bytes.append(ipv6arr[15])

        for m in self.ips.v6_masks:
            bytes.append(int(m))

        for port in self.ports.udp_ports:
            bytes.append(port >> 8)
            bytes.append(port & 0xff)

        for port in self.ports.tcp_ports:
            # print "!!!", port, port >> 8, port & 0xff
            bytes.append(port >> 8)
            bytes.append(port & 0xff)

        for v4_ka in self.kas.v4_kas:
            bytes.append(v4_ka.timeout & 0xff)
            bytes.append(v4_ka.timeout >> 8 & 0xff)
            bytes.append(v4_ka.timeout >> 16 & 0xff)
            bytes.append(v4_ka.timeout >> 24 & 0xff)
            bytes.append(v4_ka.local_port & 0xff)
            bytes.append(v4_ka.local_port >> 8 & 0xff)
            bytes.append(v4_ka.remote_port & 0xff)
            bytes.append(v4_ka.remote_port >> 8 & 0xff)
            macs = v4_ka.remote_mac_address.split(":")
            for mac in macs:
                bytes.append(int(mac, 16))
            bytes.append(v4_ka.win_size & 0xff)
            bytes.append(v4_ka.win_size >> 8 & 0xff)
            bytes.append(v4_ka.seq_num & 0xff)
            bytes.append(v4_ka.seq_num >> 8 & 0xff)
            bytes.append(v4_ka.seq_num >> 16 & 0xff)
            bytes.append(v4_ka.seq_num >> 24 & 0xff)
            bytes.append(v4_ka.ack_num & 0xff)
            bytes.append(v4_ka.ack_num >> 8 & 0xff)
            bytes.append(v4_ka.ack_num >> 16 & 0xff)
            bytes.append(v4_ka.ack_num >> 24 & 0xff)
            ipb = v4_ka.local_ip.split(".")[::-1]
            for b in ipb:
                bytes.append(int(b))
            ipb = v4_ka.remote_ip.split(".")[::-1]
            for b in ipb:
                bytes.append(int(b))

        for v6_ka in self.kas.v6_kas:
            bytes.append(v6_ka.timeout & 0xff)
            bytes.append(v6_ka.timeout >> 8 & 0xff)
            bytes.append(v6_ka.timeout >> 16 & 0xff)
            bytes.append(v6_ka.timeout >> 24 & 0xff)
            bytes.append(v6_ka.local_port & 0xff)
            bytes.append(v6_ka.local_port >> 8 & 0xff)
            bytes.append(v6_ka.remote_port & 0xff)
            bytes.append(v6_ka.remote_port >> 8 & 0xff)
            macs = v6_ka.remote_mac_address.split(":")
            for mac in macs:
                bytes.append(int(mac, 16))
            bytes.append(v6_ka.win_size & 0xff)
            bytes.append(v6_ka.win_size >> 8 & 0xff)
            bytes.append(v6_ka.seq_num & 0xff)
            bytes.append(v6_ka.seq_num >> 8 & 0xff)
            bytes.append(v6_ka.seq_num >> 16 & 0xff)
            bytes.append(v6_ka.seq_num >> 24 & 0xff)
            bytes.append(v6_ka.ack_num & 0xff)
            bytes.append(v6_ka.ack_num >> 8 & 0xff)
            bytes.append(v6_ka.ack_num >> 16 & 0xff)
            bytes.append(v6_ka.ack_num >> 24 & 0xff)
            v6_local_hex = v6_ka.local_ip.replace(":", "").decode("hex")
            for i in range(4):
                bytes.extend(v6_local_hex[4 * i:4 * i + 2][::-1])
                bytes.extend(v6_local_hex[4 * i + 2:4 * i + 4][::-1])
            v6_remote_hex = v6_ka.remote_ip.replace(":", "").decode("hex")
            for i in range(4):
                bytes.extend(v6_remote_hex[4 * i:4 * i + 2][::-1])
                bytes.extend(v6_remote_hex[4 * i + 2:4 * i + 4][::-1])

        for i in range(self.rrs.count):
            mdns_rr_offset = rridx_offset + 4 * len(self.rrs.entries)
            if i > 0:
                for j in range(i):
                    mdns_rr_offset += self.rrs.entries[j].SIZEOF
            bytes.append(mdns_rr_offset & 0xff)
            bytes.append(mdns_rr_offset >> 8 & 0xff)
            bytes.append(mdns_rr_offset >> 16 & 0xff)
            bytes.append(mdns_rr_offset >> 24 & 0xff)

        for mdns_rr in self.rrs.entries:
            bytes += mdns_rr.to_bytes()

        val = 0
        for i in range(len(bytes)):
            if (i % 4 == 0 and i != 0):
                data.append(val)
                val = 0
            val |= bytes[i] << 8 * (i % 4)
            # print "!!! {:02x} {:08x}".format(bytes[i], val)
        data.append(val)

        for d in data:
            if d > 0xffffffff:
                raise Exception("Smth goes wrong")

        return data

    def __str__(self):
        res = "Driver ethernet configuration:\n\n"
        res += "Version = 0x{:02x}\n".format(self.version)
        res += "Length = 0x{:02x}\n".format(self.len)
        res += "MAC address = {}\n".format(self.mac)
        res += "\nOffload IP configuration:\n\n"
        res += str(self.ips)
        res += "\nOffload PORT configuration:\n\n"
        res += str(self.ports)
        res += "\nOffload KA configuration:\n\n"
        res += str(self.kas)
        res += "\nOffload RR configuration:\n\n"
        res += str(self.rrs)
        return res

    def set_standard_ips(self, ipv4_count=3, ipv6_count=5):
        self.ips = OffloadIpInfo()
        self.ips.v4_addr_count = ipv4_count
        self.ips.v4_addresses = ["169.254.23.232", "169.254.23.231", "169.254.23.230"][:ipv4_count]
        self.ips.v4_masks = [16, 16, 16][:ipv4_count]
        log.info('Configuring IPv4 addresses: {}'.format(self.ips.v4_addresses))
        self.ips.v6_addr_count = ipv6_count
        self.ips.v6_addresses = ['4000:0000:0000:0000:1601:bd17:0c02:2400',
                                 '4000:0000:0000:0000:1601:bd17:0c02:2436',
                                 '4000:0000:0000:0000:1601:bd17:0c02:2431',
                                 '4000:0000:0000:0000:1601:bd17:0c02:2412',
                                 '4000:0000:0000:0000:1601:bd17:0c02:2404',
                                 ][:ipv6_count]
        self.ips.v6_masks = [64, 64, 64, 64, 64][:ipv6_count]
        log.info('Configuring IPv6 addresses: {}'.format(self.ips.v6_addresses))


class DrvMsgWoLAddPattern(object):
    def __init__(self):
        self.mask = [0, ] * 16
        self.crc = 0


class DrvWinWoLConfig(DrvMessage):
    msg_id = 0x0e

    def __init__(self):
        super(DrvWinWoLConfig, self).__init__()
        self.caps = self.CAPS_HI_WOL
        self.mac = ""
        self.magic_enabled = False
        self.filters = []
        self.link_up_enabled = False
        self.link_down_enabled = False
        self.link_up_timeout = 10000
        self.link_down_timeout = 10000

    def get_data(self):
        data = []

        magic_enabled_int = 1 if self.magic_enabled else 0
        filter_count = len(self.filters)

        macs = self.mac.split(":")

        mac1 = int(macs[3], 16) << 24 | int(macs[2], 16) << 16 | int(macs[1], 16) << 8 | int(macs[0], 16)
        mac2 = filter_count << 24 | magic_enabled_int << 16 | int(macs[5], 16) << 8 | int(macs[4], 16)
        data.append(mac1)
        data.append(mac2)

        if len(self.filters) > 8:
            raise Exception("Can't configure more than 8 filters")

        for i, filter in enumerate(self.filters):
            mask1 = filter.mask[3] << 24 | filter.mask[2] << 16 | filter.mask[1] << 8 | filter.mask[0]
            mask2 = filter.mask[7] << 24 | filter.mask[6] << 16 | filter.mask[5] << 8 | filter.mask[4]
            mask3 = filter.mask[11] << 24 | filter.mask[10] << 16 | filter.mask[9] << 8 | filter.mask[8]
            mask4 = filter.mask[15] << 24 | filter.mask[14] << 16 | filter.mask[13] << 8 | filter.mask[12]

            data.append(mask1)
            data.append(mask2)
            data.append(mask3)
            data.append(mask4)

            data.append(filter.crc)

        if len(self.filters) < 8:
            data.extend([0] * 5 * (8 - len(self.filters)))

        link_up_enabled_int = 1 if self.link_up_enabled else 0
        link_down_enabled_int = 1 if self.link_down_enabled else 0

        link_enabled_ints = 0 | link_down_enabled_int << 8 | link_up_enabled_int
        data.append(link_enabled_ints)

        data.append(self.link_up_timeout)
        data.append(self.link_down_timeout)

        return data


class DrvWakeByTimerConfig(DrvMessage):
    msg_id = 0x18

    def __init__(self):
        super(DrvWakeByTimerConfig, self).__init__()
        self.caps = self.CAPS_HI_WOL_TIMER
        self.timeout = 10000

    def get_data(self):
        return [self.timeout]


class DrvDownshiftConfig(DrvMessage):
    msg_id = 0x15

    def __init__(self):
        super(DrvDownshiftConfig, self).__init__()
        self.caps = self.CAPS_HI_DOWNSHIFT
        self.retry_count = 7

    def get_data(self):
        return [self.retry_count]


class DrvThermalShutdownConfig(DrvMessage):
    msg_id = 0x17

    def __init__(self):
        super(DrvThermalShutdownConfig, self).__init__()
        self.caps = self.CAPS_HI_THERMAL_SHUTDOWN
        self.shutdown_temperature = 108
        self.warning_temperature = 100
        self.cold_temperature = 80

    def get_data(self):
        return [self.cold_temperature << 16 | self.warning_temperature << 8 | self.shutdown_temperature]


class DrvEEEStateMachineConfig(DrvMessage):
    msg_id = 0x16

    DEFAULT_LINK_DOWN_TIMEOUT = 10000  # 10 seconds
    DEFAULT_LINK_UP_TIMEOUT = 8 * 60 * 60 * 1000  # 8 hours
    DEFAULT_MAX_LINK_DROPS = 1
    DEFAULT_FEATURE_MASK = 0x10 | 0x8 | 0x2 | 0x1  # 1G, 2.5G, 5G and 10G

    def __init__(self):
        super(DrvEEEStateMachineConfig, self).__init__()
        self.caps = self.CAPS_HI_1000BASET_FD_EEE | self.CAPS_HI_EEE_AUTO_DISABLE  # enables EEE and feature
        self.link_down_timeout = self.DEFAULT_LINK_DOWN_TIMEOUT
        self.link_up_timeout = self.DEFAULT_LINK_UP_TIMEOUT
        self.max_link_drops = self.DEFAULT_MAX_LINK_DROPS
        self.feature_mask = self.DEFAULT_FEATURE_MASK

    def get_data(self):
        return [self.link_down_timeout, self.link_up_timeout, self.max_link_drops, self.feature_mask]


class FWSmbusReadRequest(DrvMessage):
    msg_id = 0x0

    def __init__(self, device_id, address, size=4):
        super(FWSmbusReadRequest, self).__init__()
        self.device_id = device_id
        self.address = address
        self.size = size

    def get_data(self):
        return [self.device_id, self.address, self.size]

    def request_data(self, mbu_wrapper):
        data = [self.msg_id, ] + self.get_data()

        # Put the SMBUS_READ_REQUEST config structure into the config memory
        mbu_wrapper.dump_to_config_memory(data)

        # Toggle the 0x368.SMBUS_READ_REQUEST bit
        smbus_ctrl = mbu_wrapper.readreg(0x368)
        if smbus_ctrl & DrvMessage.SMBUS_READ_REQUEST_MASK:
            smbus_ctrl &= ~DrvMessage.SMBUS_READ_REQUEST_MASK
        else:
            smbus_ctrl |= DrvMessage.SMBUS_READ_REQUEST_MASK
        mbu_wrapper.writereg(0x368, smbus_ctrl)

        # Poll 0x370 until 0x370.SMBUS_READ_REQUEST matches 0x368.SMBUS_READ_REQUEST
        start = timeit.default_timer()
        read_success = False
        while timeit.default_timer() - start < 1.0:
            smbus_status = mbu_wrapper.readreg(0x370)
            if (smbus_status & DrvMessage.SMBUS_READ_REQUEST_MASK) == (smbus_ctrl & DrvMessage.SMBUS_READ_REQUEST_MASK):
                read_success = True
                break
            time.sleep(0.0001)
        if not read_success:
            raise Exception("Failed to read data from SMBUS")

        # Read the SMBUS_READ_RESPONSE structure from the config memory
        config_memory_addr = mbu_wrapper.readreg(0x334)
        res = mbu_wrapper.readmem(config_memory_addr, 8 + self.size)
        if res[1] != 0:
            raise Exception("Failed to read data from SMBUS. Return code = {}".format(res[1]))
        return res[2:]


class FWSmbusWriteRequest(DrvMessage):
    msg_id = 0x0

    def __init__(self, device_id, address, size, data):
        super(FWSmbusWriteRequest, self).__init__()
        self.device_id = device_id
        self.address = address
        self.size = size
        self.data = data

    def get_data(self):
        res = [self.device_id, self.address, self.size]
        res.extend(self.data)
        return res

    def send_data(self, mbu_wrapper):
        data = [self.msg_id, ] + self.get_data()

        # Put the SMBUS_WRITE_REQUEST config structure into the config memory
        mbu_wrapper.dump_to_config_memory(data)

        # Toggle the 0x368.SMBUS_WRITE_REQUEST bit
        smbus_ctrl = mbu_wrapper.readreg(0x368)
        if smbus_ctrl & DrvMessage.SMBUS_WRITE_REQUEST_MASK:
            smbus_ctrl &= ~DrvMessage.SMBUS_WRITE_REQUEST_MASK
        else:
            smbus_ctrl |= DrvMessage.SMBUS_WRITE_REQUEST_MASK
        mbu_wrapper.writereg(0x368, smbus_ctrl)

        # Poll 0x370 until 0x370.SMBUS_WRITE_REQUEST matches 0x368.SMBUS_WRITE_REQUEST
        start = timeit.default_timer()
        read_success = False
        while timeit.default_timer() - start < 1.0:
            smbus_status = mbu_wrapper.readreg(0x370)
            if (smbus_status & DrvMessage.SMBUS_WRITE_REQUEST_MASK) == (
                    smbus_ctrl & DrvMessage.SMBUS_WRITE_REQUEST_MASK):
                read_success = True
                break
            time.sleep(0.0001)
        if not read_success:
            raise Exception("Failed to read data from SMBUS")

        # Read the SMBUS_WRITE_RESPONSE structure from the config memory
        config_memory_addr = mbu_wrapper.readreg(0x334)
        res = mbu_wrapper.readmem(config_memory_addr, 8)
        if res[1] != 0:
            raise Exception("Failed to read data from SMBUS. Return code = {}".format(res[1]))


# with open("/home/iloz/bet.txt", "r") as f:
#     lines = f.readlines()
# prev_addr = 0
# data = []
# for line in lines:
#     if "writereg 0x032C" in line:
#         addr = int(line.rstrip("\r\n")[16:], 16)
#         if prev_addr != 0:
#             diff = addr - prev_addr
#             prev_addr = addr
#         else:
#             prev_addr = addr
#     if "writereg 0x0328" in line:
#         datax = line.rstrip("\r\n")[16:]
#         print datax
#         v = int(datax, 16)
#         b3 = v >> 24 & 0xff
#         b2 = v >> 16 & 0xff
#         b1 = v >> 8 & 0xff
#         b0 = v & 0xff
#         data.append(b0)
#         data.append(b1)
#         data.append(b2)
#         data.append(b3)
#
#
# ba = bytearray(data)
# with open("/home/iloz/cfg.bin", "wb") as f:
#     f.write(ba)

# cfg = DrvEthConfig.from_beton("/home/iloz/offload.txt")
# print cfg


class DrvFreqAgjustment(DrvMessage):
    DEFAULT_NSEC_MAC = 3
    DEFAULT_FRAC_MAC = 0x33333333
    DEFAULT_NSEC_PHY = 6
    DEFAULT_FRAC_PHY = 0x40000000
    DEFAULT_NS_ADJ_MAC = 300000
    DEFAULT_FRAC_ADJ_MAC = 0

    def __init__(self):
        super(DrvFreqAgjustment, self).__init__()
        self.msg_id = 0x12
        self.caps = self.CAPS_HI_FW_REQUEST
        self.ns_mac = self.DEFAULT_NSEC_MAC
        self.fns_mac = self.DEFAULT_FRAC_MAC
        self.ns_phy = self.DEFAULT_NSEC_PHY
        self.fns_phy = self.DEFAULT_FRAC_PHY
        self.ns_mac_adj = self.DEFAULT_NS_ADJ_MAC
        self.fns_mac_adj = self.DEFAULT_FRAC_ADJ_MAC

    def get_data(self):
        return [self.ns_mac, self.fns_mac, self.ns_phy, self.fns_phy, self.ns_mac_adj, self.fns_mac_adj]


class WolPatternUsbStructure(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('mask', ctypes.c_uint8 * 16),
        ('crc16', ctypes.c_uint16),
        ('crc32', ctypes.c_uint32),
    ]


class Ipv6UsbStructure(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('ipv6', ctypes.c_uint8 * 16),
    ]


class DrvUsbConfig(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('mac_octets', ctypes.c_uint8 * 6),
        ('flags', ctypes.c_uint8),
        ('wolPatternCount', ctypes.c_uint8),
        ('wolPatterns', WolPatternUsbStructure * 8),
        ('linkUpTimeout', ctypes.c_uint32),
        ('linkDownTimeout', ctypes.c_uint32),
        ('ipv4Count', ctypes.c_uint8),
        ('ipv4', ctypes.c_uint32 * 8),
        ('ipv6Count', ctypes.c_uint8),
        ('ipv6', Ipv6UsbStructure * 4),
    ]

    def get_data(self):
        return array.array("B", buffer(self)[:]).tolist()


if __name__ == "__main__":
    DUT_IPs4 = ["192.168.0.3",
                "192.168.0.4",
                "192.168.0.5"]
    LKP_IP4 = "192.168.0.2"
    NETMASK_IP4 = "255.255.255.0"
    MULTICAST_IP4 = "192.168.0.255"

    DUT_IPs6 = ["4000:0000:0000:0000:1601:bd17:0c02:2403",
                "4000:0000:0000:0000:1601:bd17:0c02:2413",
                "4000:0000:0000:0000:1601:bd17:0c02:2423",
                "4000:0000:0000:0000:1601:bd17:0c02:2433",
                "4000:0000:0000:0000:1601:bd17:0c02:2443"]
    LKP_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2402"
    PREFIX_IP6 = "64"

    DUT_MAC = "00:17:b6:00:07:82"
    DUT_WOL_MAC = "11:22:33:44:55:66"
    FAKE_MAC = "00:00:de:ad:fa:ce"

    cfg = DrvEthConfig()

    cfg.version = 0
    cfg.len = 0x407
    cfg.mac = DUT_MAC
    cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY
    log.info("Configuring MAC address: {}".format(cfg.mac))

    cfg.ips = OffloadIpInfo()
    cfg.ips.v4_addr_count = 3
    cfg.ips.v4_addresses = DUT_IPs4[:3]
    cfg.ips.v4_masks = [24] * 3
    log.info("Configuring IPv4 addresses: {}".format(cfg.ips.v4_addresses))
    cfg.ips.v6_addr_count = 5
    cfg.ips.v6_addresses = DUT_IPs6[:5]
    cfg.ips.v6_masks = [64] * 5
    log.info("Configuring IPv6 addresses: {}".format(cfg.ips.v6_addresses))

    rrs = OffloadRrInfo()
    mdns_rr = MdnsRr()
    mdns_rr.tail = MdnsRrTail()
    mdns_rr.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_SRV
    mdns_rr.tail.class_ = 32769
    mdns_rr.tail.ttl = 120
    mdns_rr.question = "iMac (2)._smb._tcp.local"
    mdns_rr.answer = "iMac-3.local"
    mdns_rr.srv = MdnsRdataSrv()
    mdns_rr.srv.priority = 0
    mdns_rr.srv.weight = 48385
    mdns_rr.srv.port = 0
    mdns_rr.tail.rd_len = 8
    log.info('Configuring mDNS SRV record: class = {}, TTL = {}, question = "{}", answer = "{}"'
             ''.format(mdns_rr.tail.class_, mdns_rr.tail.ttl, mdns_rr.question, mdns_rr.answer))

    rrs.entries.append(mdns_rr)
    cfg.rrs = rrs

    for i, line in enumerate(cfg.get_beton()):
        print line
        if (i + 1) % 3 == 0:
            print ""

if __name__ == '__main__2':
    eth_cfg = DrvEthConfig()
    eth_cfg.version = 0
    eth_cfg.len = 0x407
    eth_cfg.mac = "00:17:b6:00:07:82"
    eth_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY

    ips = OffloadIpInfo()
    ips.v4_addresses = ["192.168.0.3"]
    ips.v4_masks = [24]
    ips.v6_addresses = ["4000:0000:0000:0000:1601:bd17:0c02:2403"]
    ips.v6_masks = [64]

    eth_cfg.ips = ips

    print "\n".join(eth_cfg.get_beton())

    print "\n----------------------------------------\n"

    wol_cfg = DrvWinWoLConfig()

    wol_cfg.mac = "11:22:33:44:55:66"
    wol_cfg.magic_enabled = True

    wol_cfg.caps = DrvMessage.CAPS_HI_WOL | DrvMessage.CAPS_HI_SLEEP_PROXY

    # IPv4 TCP SYN anyone
    filter = DrvMsgWoLAddPattern()
    filter.mask = [0x00, 0x70, 0x80, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    filter.crc = 0x6f98
    wol_cfg.filters.append(filter)

    # IPv6 TCP SYN anyone
    filter = DrvMsgWoLAddPattern()
    filter.mask = [0x00, 0x70, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    filter.crc = 0x7e53
    wol_cfg.filters.append(filter)

    # Ping echo request to 192.168.0.3
    filter = DrvMsgWoLAddPattern()
    filter.mask = [0x00, 0x70, 0x80, 0xc0, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    filter.crc = 0x5830
    wol_cfg.filters.append(filter)

    # Ping echo IPv6 request to 4000:0000:0000:0000:1601:bd17:0c02:2403
    filter = DrvMsgWoLAddPattern()
    filter.mask = [0x00, 0x70, 0x10, 0x00, 0xc0, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    filter.crc = 0x9c06
    wol_cfg.filters.append(filter)

    # ARP who has 192.168.0.3
    filter = DrvMsgWoLAddPattern()
    filter.mask = [0x00, 0x30, 0x03, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    filter.crc = 0x1479
    wol_cfg.filters.append(filter)

    # NS for 4000:0000:0000:0000:1601:bd17:0c02:2403
    filter = DrvMsgWoLAddPattern()
    filter.mask = [0x00, 0x70, 0x10, 0x00, 0xc0, 0xff, 0x7f, 0xc0, 0xff, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    filter.crc = 0x2e60
    wol_cfg.filters.append(filter)

    # IPv4 UDP with port 13370
    filter = DrvMsgWoLAddPattern()
    filter.mask = [0x00, 0x70, 0x80, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    filter.crc = 0xfb90
    wol_cfg.filters.append(filter)

    # IPv6 UDP with port 13370
    filter = DrvMsgWoLAddPattern()
    filter.mask = [0x00, 0x70, 0x10, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    filter.crc = 0x3280
    wol_cfg.filters.append(filter)

    wol_cfg.link_up_enabled = True
    wol_cfg.link_down_enabled = True

    wol_cfg.link_up_timeout = 10000
    wol_cfg.link_down_timeout = 10000

    print "\n".join(wol_cfg.get_beton())

if __name__ == '__main__2':
    cfg = DrvEthConfig()

    cfg.version = 0
    cfg.len = 0x407
    cfg.mac = "00:17:b6:00:07:82"

    ips = OffloadIpInfo()
    ips.v4_addr_count = 2
    ips.v4_addresses = ["169.254.23.232", "169.254.23.231", "169.254.23.230"]
    ips.v4_masks = [16, 16, 16]
    ips.v6_addr_count = 7
    ips.v6_addresses = ['4000:0000:0000:0000:1601:bd17:0c02:2400', '4000:0000:0000:0000:1601:bd17:0c02:2436']
    ips.v6_masks = [64, 64]

    cfg.ips = ips

    ports = OffloadPortInfo()
    ports.udp_ports = [6896, 3453]
    ports.tcp_ports = [22, 445, 5900, 548, 9]

    cfg.ports = ports

    kas = OffloadKaInfo()
    kas.v4_kas = []
    kas.v6_kas = []
    kas.retry_count = 3
    kas.retry_interval = 3

    v4_ka = OffloadKa()
    v4_ka.timeout = 2
    v4_ka.local_port = 22
    v4_ka.remote_port = 22
    v4_ka.remote_mac_address = "00:17:b6:33:44:91"
    v4_ka.win_size = 1000
    v4_ka.seq_num = 2456
    v4_ka.ack_num = 1212
    v4_ka.local_ip = "169.254.23.232"
    v4_ka.remote_ip = "169.254.23.111"

    kas.v4_kas.append(v4_ka)

    v4_ka_2 = OffloadKa()
    v4_ka_2.timeout = 2
    v4_ka_2.local_port = 22
    v4_ka_2.remote_port = 22
    v4_ka_2.remote_mac_address = "00:17:b6:33:44:22"
    v4_ka_2.win_size = 8000
    v4_ka_2.seq_num = 9987
    v4_ka_2.ack_num = 10203
    v4_ka_2.local_ip = "169.254.23.231"
    v4_ka_2.remote_ip = "169.254.23.99"

    kas.v4_kas.append(v4_ka_2)

    v6_ka = OffloadKa()
    v6_ka.timeout = 5
    v6_ka.local_port = 5555
    v6_ka.remote_port = 5556
    v6_ka.remote_mac_address = "00:17:b6:33:44:92"
    v6_ka.win_size = 2000
    v6_ka.seq_num = 5000
    v6_ka.ack_num = 6000
    v6_ka.local_ip = "4000:0000:0000:0000:1601:bd17:0c02:2400"
    v6_ka.remote_ip = "4000:0000:0000:0000:1601:bd17:0c02:2424"

    kas.v6_kas.append(v6_ka)

    v6_ka_2 = OffloadKa()
    v6_ka_2.timeout = 10
    v6_ka_2.local_port = 7777
    v6_ka_2.remote_port = 7778
    v6_ka_2.remote_mac_address = "00:17:b6:33:44:92"
    v6_ka_2.win_size = 2000
    v6_ka_2.seq_num = 5000
    v6_ka_2.ack_num = 6000
    v6_ka_2.local_ip = "4000:0000:0000:0000:1601:bd17:0c02:2400"
    v6_ka_2.remote_ip = "4000:0000:0000:0000:1601:bd17:0c02:2487"

    kas.v6_kas.append(v6_ka_2)

    cfg.kas = kas

    rrs = OffloadRrInfo()

    mdns_rr = MdnsRr()
    mdns_rr.tail = MdnsRrTail()
    mdns_rr.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_TXT
    mdns_rr.tail.class_ = 4000
    mdns_rr.tail.ttl = 4009
    mdns_rr.question = "ololo.question.txt.local"
    mdns_rr.txt = "ololo.txt.local"
    mdns_rr.tail.rd_len = mdns_rr.txt_length + 1

    rrs.entries.append(mdns_rr)

    mdns_rr_2 = MdnsRr()
    mdns_rr_2.tail = MdnsRrTail()
    mdns_rr_2.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_PTR
    mdns_rr_2.tail.class_ = 8000
    mdns_rr_2.tail.ttl = 8001
    mdns_rr_2.question = "ololo.question.ptr.local"
    mdns_rr_2.answer = "ololo.answer.ptr.local"
    mdns_rr_2.tail.rd_len = mdns_rr_2.answer_length + 1

    rrs.entries.append(mdns_rr_2)

    mdns_rr_3 = MdnsRr()
    mdns_rr_3.tail = MdnsRrTail()
    mdns_rr_3.tail.type = MdnsRr.ETH_MDNS_RR_TYPE_SRV
    mdns_rr_3.tail.class_ = 32769
    mdns_rr_3.tail.ttl = 120
    mdns_rr_3.question = "iMac (2)._smb._tcp.local"
    mdns_rr_3.answer = "iMac-3.local"
    mdns_rr_3.srv = MdnsRdataSrv()
    mdns_rr_3.srv.priority = 0
    mdns_rr_3.srv.weight = 48385
    mdns_rr_3.srv.port = 0
    mdns_rr_3.tail.rd_len = 8

    rrs.entries.append(mdns_rr_3)

    cfg.rrs = rrs

    data = cfg.get_data()
    for d in data:
        print "0x" + "{:08x}".format(d).upper()

    beton = cfg.get_beton()
    with open("d:/mbu/scripts/offload.txt", "w") as f:
        # with open("/home/iloz/offload.txt", "w") as f:
        for b in beton:
            f.write("{}\n".format(b))
