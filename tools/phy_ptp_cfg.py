import os
import sys
import time

LINK_SPEED_100M = "100M"
LINK_SPEED_1G = "1G"
LINK_SPEED_2_5G = "2.5G"
LINK_SPEED_5G = "5G"
LINK_SPEED_10G = "10G"

PHY_PTP_PLL_NUMBER = 1
PTP_THRESHOLD = 7

RATE_10G = 0
RATE_5G = 1
RATE_5GSR = 2
RATE_2G5 = 3
RATE_1G = 4
RATE_100M = 5
RATE_INVALID = 0xff

MAX_PKT_SIZE_IN_BASE_TC = 1280
PTP_EXTRA_PKT_DELAY_100M = 512
PTP_EXTRA_PKT_DELAY_1G = 256
PTP_EXTRA_PKT_DELAY_10G = 128


run_all = 0
stop_main_for_avb = 0x1
stop_main_for_ptp = 0x2
stop_all_for_ptp = 0x4
stop_avb_mask = 0x4
stop_main_mask = 0x7
run_bit = 0x8
run_after_avb = 0x9
run_after_ptp = 0xe

PcsPtpEgressVendorProvisioning26_ADR = 0x000046EC
PcsPtpEgressVendorProvisioning20_ADR = 0x000046D4


def dobin(n):
    digs = []
    s = ''
    if n < 0:
        s = '-'
        n = -n
    while True:
        digs.append(str(n % 2))
        n /= 2
        if not n:
            break
    if s:
        digs.append(s)
    digs.reverse()
    return ''.join(digs)


class PhyAccess(object):
    def __init__(self, **kwargs):
        self.pa = None

    def readphyreg(self, mmd, addr, silent=True):
        raise NotImplementedError()

    def writephyreg(self, mmd, addr, val, silent=True):
        raise NotImplementedError()

    def writephyregrmw(self, reg_mmd, reg_address, mask, value, silent=False):
        val = self.readphyreg(reg_mmd, reg_address, silent)
        val &= mask
        val |= value
        val = self.writephyreg(reg_mmd, reg_address, val, silent)

    def is_rhea(self):
        if "PHY" in os.environ:
            return os.environ["PHY"].lower() == "rhea"
        elif "PHY_TYPE" in os.environ:
            return os.environ["PHY_TYPE"].lower() == "rhea"
        return False


class PhyAccessAtltool(PhyAccess):
    def __init__(self, **kwargs):
        self.pa = kwargs["atltool"]

    def readphyreg(self, mmd, addr, silent=True):
        return self.pa.readphyreg(mmd, addr)

    def writephyreg(self, mmd, addr, val):
        self.pa.writephyreg(mmd, addr, val, silent=True)


class PhyAccessBer(PhyAccess):
    def __init__(self, **kwargs):
        if "paber" in kwargs:
            self.pa = kwargs["paber"]
        else:
            self.validation_path = kwargs["validation_path"]
            self.board = kwargs["board"]
            self.phyid = kwargs["phyid"]

            # sys.path.append(os.path.join(self.validation_path, "Testscripts/BER"))
            # sys.path.append(os.path.join(self.validation_path, "common/PlatformDrivers"))

            common_dir = os.path.join(self.validation_path, "common")
            sys.path.append(common_dir)
            sys.path.append(os.path.join(common_dir, 'PlatformDrivers'))
            sys.path.append(os.path.join(common_dir, 'InstrumentDrivers'))

            import phyaccess

            self.pa = phyaccess.PhyAccess.create(self.board, self.phyid)
            self.readphyreg(0x1e, 0xc886, silent=True)  # read any register to cleanup pending bytes

    def readphyreg(self, mmd, addr, silent=False):
        reg_addr = mmd << 16 | addr
        val = self.pa.pifReadData(reg_addr)
        if not silent:
            print "Register PHY %d 0x%x.0x%x: 0x%04x : %s %s" % (
                self.phyid, mmd, addr, val, dobin((val >> 8) & 0xFF).zfill(8), dobin(val & 0xFF).zfill(8))
        return val

    def writephyreg(self, mmd, addr, val, silent=False):
        reg_addr = mmd << 16 | addr
        self.pa.pifWriteData(reg_addr, val)
        if not silent:
            print "Register PHY %d 0x%x.0x%x: 0x%04x written" % (self.phyid, mmd, addr, val)


class PtpFiltersDefaultDisableConfig(object):

    # PTP/SNTP configuration constants for self.ptp_ntp_sntp_cfg0
    PTP_NTP_SNTP_CLIENT = 0
    PTP_NTP_SNTP_SERVER = 1

    # PTP/SNTP configuration constants for self.ptp_ntp_sntp_cfg1
    PTP_NTP_SNTP_EGRESS = 0
    PTP_NTP_SNTP_INGRESS = 1

    # IPv6 IEEE 1588 configuration constants for self.ipv6_filter_cfg
    PTP_IPV6_IEEE_1588_OFF = 0
    PTP_IPV6_IEEE_1588_FF0X_181 = 1
    PTP_IPV6_IEEE_1588_FF02_6B = 2
    PTP_IPV6_IEEE_1588_CUSTOM = 4

    # IPv6 IEEE 1588 configuration constants for self.ipv4_filter_cfg
    PTP_IPV4_IEEE_1588_OFF = 0
    PTP_IPV4_IEEE_1588_129 = 1
    PTP_IPV4_IEEE_1588_130_132 = 2
    PTP_IPV4_IEEE_1588_107 = 4
    PTP_IPV4_IEEE_1588_CUSTOM = 8

    # L2 filter configuration constants for self.l2_filter_cfg
    PTP_L2_IEEE_1588_OFF = 0
    PTP_L2_IEEE_1588_0 = 1
    PTP_L2_IEEE_1588_1 = 2
    PTP_L2_CUSTOM = 4

    # L2 eth type filter configuration constants for self.l2_eth_type_filter_cfg
    PTP_L2_ETH_OFF = 0
    PTP_L2_ETH_IEEE_1588 = 1
    PTP_L2_ETH_CUSTOM = 2

    # UDP port configuration constants for self.udp_port_cfg
    PTP_1588_PORT_OFF = 0
    PTP_1588_PORT_319_NTP_SNTP_PORT_123 = 1
    PTP_1588_PORT_320_NTP_SNTP_PORT_NONE = 2
    PTP_1588_PORT_CUSTOM = 4

    def __init__(self):
        self.vlan_support = False
        self.ipv6_udp = False
        self.ipv4_udp = False
        self.l2_ptp = False
        self.ptp_ntp_sntp_cfg0 = None
        self.ptp_ntp_sntp_cfg1 = None
        self.ptp_fifo_backpreassure = False
        self.ptp_ntp_sntp = False
        self.ptp_1588v2 = False
        self.ptp_1588v1 = False
        self.ipv6_filter_cfg = None
        self.ipv4_filter_cfg = None
        self.l2_filter_cfg = None
        self.l2_eth_type_filter_cfg = None
        self.udp_port_cfg = self.PTP_1588_PORT_OFF
        self.ptp_1588v2_2steps_sync = False
        self.ptp_1588v2_match_domain = False
        self.ieee_1588_ver = 0x0
        self.ntp_sntp_ver = 0x0
        self.ethertype = 0x0
        self.mac_dest_addr = "00:00:00:00:00:00"
        self.ipv4_dest_addr = "0.0.0.0"
        self.ipv6_dest_addr = "0000:0000:0000:0000:0000:0000:0000:0000"
        self.udp_dest_port = 0x0
        self.ieee_1588v2_domain = 0x0

        # RHEA stuff
        self.avtp = False  # prov1
        self.l2_avtp_eth_type_filter_cfg = 0x1  # prov2
        self.ieee_1588v2_pdelay_followup_enable = False  # prov3
        self.ieee_1588v2_followup_enable = False  # prov3

    def _apply(self, pa, base_addr):
        prov_1 = 0x0
        prov_1 |= 0x1 if self.ptp_1588v1 else 0x0  # Enable IEEE 1588 Version 1
        prov_1 |= 0x1 << 0x1 if self.ptp_1588v2 else 0x0 << 0x1  # Enable IEEE 1588 Version 2
        if pa.is_rhea():
            prov_1 |= (0x1 << 0x2) if self.avtp else (0x0 << 0x2)
        prov_1 |= 0x1 << 0x4 if self.ptp_ntp_sntp else 0x0 << 0x4  # Enable NTP/SNTP
        prov_1 |= 0x1 << 0x5 if self.ptp_fifo_backpreassure else 0x0 << 0x5  # PTP FIFO ready enable
        prov_1 |= (self.ptp_ntp_sntp_cfg0 | self.ptp_ntp_sntp_cfg1 << 0x1) << 0x8  # NTP/SNTP configuration (bit 0: 0=client, 1=server, bit 1: 0=egress, 1=ingress)
        prov_1 |= 0x1 << 0xc if self.l2_ptp else 0x0 << 0xc  # Enable Ethernet encapsulated IEEE1588 packet
        prov_1 |= 0x1 << 0xd if self.ipv4_udp else 0x0 << 0xd  # Enable IPv4/UDP encapsulated IEEE1588 or NTP/SNTP packet
        prov_1 |= 0x1 << 0xe if self.ipv6_udp else 0x0 << 0xe  # Enable IPv6/UDP encapsulated IEEE1588 or NTP/SNTP packet
        prov_1 |= 0x1 << 0xf if self.vlan_support else 0x0 << 0xf  # Enable VLAN tagging for IEEE1588 or NTP/SNTP packet

        prov_2 = 0x0
        prov_2 |= self.l2_eth_type_filter_cfg  # Enable Ethertype matching for Ethernet encapsulated IEEE1588 packet; bit 0: 0x88F7; bit 1: user-defined
        if pa.is_rhea():
            prov_2 |= (self.l2_avtp_eth_type_filter_cfg << 0x2)
        prov_2 |= self.l2_filter_cfg << 0x4  # Enable MAC destination address matching for IEEE1588; bit 0: 01-1B-19-00-00-00; bit 1: 01-80-C2-00-00-0E; bit 2: user-defined
        prov_2 |= self.ipv4_filter_cfg << 0x8  # Enable IPv4 destination address matching for IEEE1588; bit 0: 224.0.1.129; bit 1: 224.0.1.130-132; bit 2: 224.0.0.107; bit 3: user-defined
        prov_2 |= self.ipv6_filter_cfg << 0xc  # Enable IPv6 destination address matching for IEEE1588; bit 0: FF0X:0:0:0:0:0:0:181 (X: 0x0 to 0xF); bit 1: FF02:0:0:0:0:0:0:6B; bit 2: user-defined

        prov_3 = 0x0
        prov_3 |= self.udp_port_cfg  # Enable UDP destination port matching for IEEE 1588 or NTP/SNTP; bit 0: 319 for IEEE1588, or 123 for NTP/SNTP; bit 1: 320 for IEEE1588, not used for NTP/SNTP
        prov_3 |= 0x1 << 0x4 if self.ptp_1588v2_match_domain else 0x0 << 0x4  # Enable domain matching for IEEE1588v2
        prov_3 |= 0x1 << 0x5 if self.ptp_1588v2_2steps_sync else 0x0 << 0x5  # Set  to  1  to  consider  the  two-step flag for IEEE1588v2 (or PTP_ASSIST for IEEE1588v1)
        if pa.is_rhea():
            prov_3 |= (0x1 << 0x6) if self.ieee_1588v2_pdelay_followup_enable else (0x0 << 0x6)
            prov_3 |= (0x1 << 0x7) if self.ieee_1588v2_followup_enable else (0x0 << 0x7)
        prov_3 |= self.ieee_1588_ver << 0x8  # Latest version of IEEE1588
        prov_3 |= self.ntp_sntp_ver << 0xc  # Version of NTP/SNTP

        mac_dest_addr_arr = map(lambda x: int(x, 16), self.mac_dest_addr.split(":"))
        mac_dest_addr_0_15 = (mac_dest_addr_arr[4] << 8) | mac_dest_addr_arr[5]
        mac_dest_addr_16_31 = (mac_dest_addr_arr[2] << 8) | mac_dest_addr_arr[3]
        mac_dest_addr_32_47 = (mac_dest_addr_arr[0] << 8) | mac_dest_addr_arr[1]

        ipv4_dest_addr_array = map(lambda x: int(x, 10), self.ipv4_dest_addr.split("."))
        ipv4_dest_addr_lsw = (ipv4_dest_addr_array[2] << 8) | ipv4_dest_addr_array[3]
        ipv4_dest_addr_msw = (ipv4_dest_addr_array[0] << 8) | ipv4_dest_addr_array[1]

        ipv6_dest_addr_array = map(lambda x: int(x, 16), self.ipv6_dest_addr.split(":"))

        # 0xC620/0xE600; Vendor Provisioning 1
        pa.writephyreg(0x3, base_addr + 0x0, prov_1)
        # 0xC621/0xE601; Vendor Provisioning 2
        pa.writephyreg(0x3, base_addr + 0x1, prov_2)
        # 0xC622/0xE602; Vendor Provisioning 3
        pa.writephyreg(0x3, base_addr + 0x2, prov_3)
        # 0xC623/0xE603; Vendor Provisioning 4
        pa.writephyreg(0x3, base_addr + 0x3, self.ethertype)
        # 0xC624/0xE604; Vendor Provisioning 5
        pa.writephyreg(0x3, base_addr + 0x4, mac_dest_addr_0_15)
        # 0xC625/0xE605; Vendor Provisioning 6
        pa.writephyreg(0x3, base_addr + 0x5, mac_dest_addr_16_31)
        # 0xC626/0xE606; Vendor Provisioning 7
        pa.writephyreg(0x3, base_addr + 0x6, mac_dest_addr_32_47)
        # 0xC627/0xE607; Vendor Provisioning 8
        pa.writephyreg(0x3, base_addr + 0x7, ipv4_dest_addr_lsw)
        # 0xC628/0xE608; Vendor Provisioning 9
        pa.writephyreg(0x3, base_addr + 0x8, ipv4_dest_addr_msw)
        # 0xC629/0xE609; Vendor Provisioning 10
        pa.writephyreg(0x3, base_addr + 0x9, ipv6_dest_addr_array[7])
        # 0xC62A/0xE60A; Vendor Provisioning 11
        pa.writephyreg(0x3, base_addr + 0xa, ipv6_dest_addr_array[6])
        # 0xC62B/0xE60B; Vendor Provisioning 12
        pa.writephyreg(0x3, base_addr + 0xb, ipv6_dest_addr_array[5])
        # 0xC62C/0xE60C; Vendor Provisioning 13
        pa.writephyreg(0x3, base_addr + 0xc, ipv6_dest_addr_array[4])
        # 0xC62D/0xE60D; Vendor Provisioning 14
        pa.writephyreg(0x3, base_addr + 0xd, ipv6_dest_addr_array[3])
        # 0xC62E/0xE60E; Vendor Provisioning 15
        pa.writephyreg(0x3, base_addr + 0xe, ipv6_dest_addr_array[2])
        # 0xC62F/0xE60F; Vendor Provisioning 16
        pa.writephyreg(0x3, base_addr + 0xf, ipv6_dest_addr_array[1])
        # 0xC630/0xE610; Vendor Provisioning 17
        pa.writephyreg(0x3, base_addr + 0x10, ipv6_dest_addr_array[0])
        # 0xC631/0xE611; Vendor Provisioning 18
        pa.writephyreg(0x3, base_addr + 0x11, self.udp_dest_port)
        # 0xC632/0xE612; Vendor Provisioning 19
        pa.writephyreg(0x3, base_addr + 0x12, self.ieee_1588v2_domain)

    def apply(self, pa):
        raise NotImplementedError()


class PtpFiltersEgressEnableConfig(PtpFiltersDefaultDisableConfig):
    def __init__(self):
        super(PtpFiltersEgressEnableConfig, self).__init__()

        self.vlan_support = False
        self.ipv6_udp = False
        self.ipv4_udp = False
        self.l2_ptp = True
        self.ptp_ntp_sntp_cfg0 = self.PTP_NTP_SNTP_SERVER
        self.ptp_ntp_sntp_cfg1 = self.PTP_NTP_SNTP_EGRESS
        self.ptp_fifo_backpreassure = True
        self.ptp_ntp_sntp = False
        self.ptp_1588v2 = True
        self.ptp_1588v1 = False
        self.ipv6_filter_cfg = self.PTP_IPV6_IEEE_1588_OFF
        self.ipv4_filter_cfg = self.PTP_IPV4_IEEE_1588_OFF
        self.l2_filter_cfg = self.PTP_L2_IEEE_1588_0 | self.PTP_L2_IEEE_1588_1
        self.l2_eth_type_filter_cfg = self.PTP_L2_ETH_IEEE_1588
        self.udp_port_cfg = self.PTP_1588_PORT_319_NTP_SNTP_PORT_123 | self.PTP_1588_PORT_320_NTP_SNTP_PORT_NONE
        self.ptp_1588v2_2steps_sync = True
        self.ptp_1588v2_match_domain = False
        self.ieee_1588_ver = 0x2
        self.ntp_sntp_ver = 0x3
        self.ethertype = 0x0

    def apply(self, pa):
        print "Applying egress filter configuration"
        self._apply(pa, 0xC620)


class PtpFiltersIngressEnableConfig(PtpFiltersDefaultDisableConfig):
    def __init__(self):
        super(PtpFiltersIngressEnableConfig, self).__init__()

        self.vlan_support = False
        self.ipv6_udp = False
        self.ipv4_udp = False
        self.l2_ptp = True
        self.ptp_ntp_sntp_cfg0 = self.PTP_NTP_SNTP_SERVER
        self.ptp_ntp_sntp_cfg1 = self.PTP_NTP_SNTP_INGRESS
        self.ptp_fifo_backpreassure = True
        self.ptp_ntp_sntp = False
        self.ptp_1588v2 = True
        self.ptp_1588v1 = False
        self.ipv6_filter_cfg = self.PTP_IPV6_IEEE_1588_OFF
        self.ipv4_filter_cfg = self.PTP_IPV4_IEEE_1588_OFF
        self.l2_filter_cfg = self.PTP_L2_IEEE_1588_0 | self.PTP_L2_IEEE_1588_1
        self.l2_eth_type_filter_cfg = self.PTP_L2_ETH_IEEE_1588
        self.udp_port_cfg = self.PTP_1588_PORT_319_NTP_SNTP_PORT_123 | self.PTP_1588_PORT_320_NTP_SNTP_PORT_NONE
        self.ptp_1588v2_2steps_sync = True
        self.ptp_1588v2_match_domain = False
        self.ieee_1588_ver = 0x2
        self.ntp_sntp_ver = 0x3
        self.ethertype = 0x0

    def apply(self, pa):
        print "Applying ingress filter configuration"
        self._apply(pa, 0xE600)


class PtpTimestampingDefaultDisableConfig(object):
    PKT_ACT_NONE = 0
    PKT_ACT_CAPTURE = 1
    PKT_ACT_CAPTURE_AND_FORWARD = 3

    TS_ACT_NONE = 0
    TS_ACT_OVERWRITE = 1
    TS_ACT_APPEND = 2
    TS_ACT_REMOVE = 3

    OFFSET_ACT_ADD = 0
    OFFSET_ACT_SUBTRACT = 1

    COR_ACT_NO_CHANGE = 0
    COR_ACT_COR_P_TS_M_TSAPP_P_OF = 1
    COR_ACT_CORRECTION_PLUS_OFFSET = 2
    COR_ACT_TS_M_TS_OF = 3
    COR_ACT_CORRECTION_PLUS_TIMESTAMP_PLUS_OFFSET = 4
    COR_ACT_CORRECTION_MINUS_TIMESTAMP_PLUS_OFFSET = 5

    def __init__(self):
        self.cor_offset_sign = self.OFFSET_ACT_ADD  # 0x3.0xC633 / 0x3.0xE613
        self.ts_offset_sign = self.OFFSET_ACT_ADD  # 0x3.0xC633 / 0x3.0xE613
        self.byteswap = False  # 0x3.0xC633 / 0x3.0xE613
        self.ts_ns_offset = 0
        self.ts_frac_sec_offset = 0
        self.cor_offset = 0

        self.ieee1588v2_pkt_act = {
            "sync": self.PKT_ACT_NONE,
            "delay": self.PKT_ACT_NONE,
            "pdelay": self.PKT_ACT_NONE,
            "presp": self.PKT_ACT_NONE,
            "user": self.PKT_ACT_NONE,
            "gen": self.PKT_ACT_NONE
        }

        self.ntp_ts_act = self.TS_ACT_NONE
        self.ntp_pkt_act = {
            "non_ctrl": self.PKT_ACT_NONE,
            "ctrl_and_priv": self.PKT_ACT_NONE
        }

        self.cor_frac_ns_ts_en = False
        self.cor_clear_ts_en = False
        self.fcs_append_en = False
        self.udp_append_format = False
        self.udp_append_en = False
        self.udp_checksum_en = False
        self.pkt_pipeline_threshold = 7
        self.pkt_pause = False
        self.pkt_size_lim = False
        self.ieee1588v1_ts_act = {
            "sync": self.TS_ACT_NONE,
            "other": self.TS_ACT_NONE
        }
        self.ieee1588v1_pkt_act = {
            "sync": self.PKT_ACT_NONE,
            "other": self.PKT_ACT_NONE,
            "general": self.PKT_ACT_NONE
        }

        self.stacked_vlan_id = 0x8100
        self.ieee1588v2_cor_act = {
            "sync": self.COR_ACT_NO_CHANGE,
            "delay": self.COR_ACT_NO_CHANGE,
            "pdelay": self.COR_ACT_NO_CHANGE,
            "presp": self.COR_ACT_NO_CHANGE,
            "user": self.COR_ACT_NO_CHANGE,
        }

        self.ieee1588v2_ts_act = {
            "sync": self.TS_ACT_NONE,
            "delay": self.TS_ACT_NONE,
            "pdelay": self.TS_ACT_NONE,
            "presp": self.TS_ACT_NONE,
            "user": self.TS_ACT_NONE,
        }

        self.ieee1588v2_msg_type = 0
        self.ieee1588v2_msg_mask = 0

        self.pkt_ifg_threshold = 0x7

        self.gap_fifo_bypass = False
        self.pkt_rdy_thr = 0x7

        # RHEA stuff
        self.tx_mac_fifo_cor_enable = False  # prov41
        self.tx_mac_fifo_cor = 0x3  # prov41
        self.tx_mac_fifo_base = 0xa  # prov41
        self.pkt_max_threshold = 0x8  # prov30
        self.pkt_rdy_latency = 0x4  # prov40
        self.ts_extraction_option = False  # prov32
        self.pkt_extraction_option = 0x0  # prov32
        self.avtp_subtype = 0xff  # prov38

    def _configure_timestamp_offset(self, pa, base_addr):
        # addr = 0xC633 if base_addr == PcsPtpEgressVendorProvisioning20_ADR else 0xE613

        val = 0x1 if self.byteswap else 0x0
        val |= (self.ts_offset_sign << 0x2)
        val |= (self.cor_offset_sign << 0x3)
        # 0xC633/0xE613; Vendor Provisioning 20
        pa.writephyreg(0x3, base_addr + 0, val)
        # 0xC634/0xE614; Vendor Provisioning 21; Time Stamp Nanosecond Offset [F:0]
        pa.writephyreg(0x3, base_addr + 1, self.ts_ns_offset)
        # 0xC635/0xE615; Vendor Provisioning 22; Time Stamp Nanosecond Offset [F:0]
        pa.writephyreg(0x3, base_addr + 2, self.ts_frac_sec_offset & 0xffff)
        # 0xC636/0xE616; Vendor Provisioning 23; Time Stamp Fractional Second Offset LSW [F:0]
        pa.writephyreg(0x3, base_addr + 3, (self.ts_frac_sec_offset >> 16) & 0xffff)
        # 0xC637/0xE617; Vendor Provisioning 24; Correction Offset LSW [F:0]
        pa.writephyreg(0x3, base_addr + 4, self.cor_offset & 0xffff)
        # 0xC638/0xE618; Vendor Provisioning 25; Correction Offset MSW [1F:10]
        pa.writephyreg(0x3, base_addr + 5, (self.cor_offset >> 16) & 0xffff)
        # Toggle bit 0x2
        pa.writephyreg(0x3, base_addr + 0, val & ~0x2)
        pa.writephyreg(0x3, base_addr + 0, val | 0x2)
        pa.writephyreg(0x3, base_addr + 0, val & ~0x2)

    # TODO: remove
    def _val2field(self, x, y_width, y_shift):
        return x & (((1 << y_width) - 1) << y_shift)

    def _configure_timestamping(self, pa, base_addr):
        prov26 = (self.ieee1588v2_pkt_act["sync"] & 0x3) << 0
        prov26 |= (self.ieee1588v2_pkt_act["delay"] & 0x3) << 2
        prov26 |= (self.ieee1588v2_pkt_act["pdelay"] & 0x3) << 4
        prov26 |= (self.ieee1588v2_pkt_act["presp"] & 0x3) << 6
        prov26 |= (self.ieee1588v2_pkt_act["user"] & 0x3) << 8
        prov26 |= (self.ieee1588v2_pkt_act["gen"] & 0x3) << 10

        macPhyPtpEgressNtpSntpPacketAction_SHIFT = 8
        macPhyPtpEgressNtpSntpPacketAction_WIDTH = 4
        macPhyPtpEgressNtpSntpTimeStampAction_SHIFT = 12
        macPhyPtpEgressNtpSntpTimeStampAction_WIDTH = 2
        prov27 = self._val2field(self.ntp_pkt_act["non_ctrl"] << 0,
                                 macPhyPtpEgressNtpSntpPacketAction_WIDTH,
                                 macPhyPtpEgressNtpSntpPacketAction_SHIFT)
        prov27 |= self._val2field(self.ntp_pkt_act["ctrl_and_priv"] << 2,
                                  macPhyPtpEgressNtpSntpPacketAction_WIDTH,
                                  macPhyPtpEgressNtpSntpPacketAction_SHIFT)
        prov27 |= self._val2field(self.ntp_ts_act,
                                  macPhyPtpEgressNtpSntpTimeStampAction_WIDTH,
                                  macPhyPtpEgressNtpSntpTimeStampAction_SHIFT)

        macPhyPtpEgressUdpChecksumEnable_SHIFT = 0
        macPhyPtpEgressUdpChecksumEnable_WIDTH = 1
        macPhyPtpEgressUdpAppendEnable_SHIFT = 1
        macPhyPtpEgressUdpAppendEnable_WIDTH = 1
        macPhyPtpEgressUdpAppendFormat_SHIFT = 2
        macPhyPtpEgressUdpAppendFormat_WIDTH = 1
        macPhyPtpEgressCrcAppendEnable_SHIFT = 3
        macPhyPtpEgressCrcAppendEnable_WIDTH = 1
        macPhyPtpEgressCorrectionClearTimestampEnable_SHIFT = 4
        macPhyPtpEgressCorrectionClearTimestampEnable_WIDTH = 1
        macPhyPtpEgressCorrectionFractionalNanosecondTimestampEnable_SHIFT = 5
        macPhyPtpEgressCorrectionFractionalNanosecondTimestampEnable_WIDTH = 1
        prov28 = self._val2field(self.udp_checksum_en,
                                 macPhyPtpEgressUdpChecksumEnable_WIDTH,
                                 macPhyPtpEgressUdpChecksumEnable_SHIFT)
        prov28 |= self._val2field(self.udp_append_en,
                                  macPhyPtpEgressUdpAppendEnable_WIDTH,
                                  macPhyPtpEgressUdpAppendEnable_SHIFT)
        prov28 |= self._val2field(self.udp_append_format,
                                  macPhyPtpEgressUdpAppendFormat_WIDTH,
                                  macPhyPtpEgressUdpAppendFormat_SHIFT)
        prov28 |= self._val2field(self.fcs_append_en,
                                  macPhyPtpEgressCrcAppendEnable_WIDTH,
                                  macPhyPtpEgressCrcAppendEnable_SHIFT)
        prov28 |= self._val2field(self.cor_clear_ts_en,
                                  macPhyPtpEgressCorrectionClearTimestampEnable_WIDTH,
                                  macPhyPtpEgressCorrectionClearTimestampEnable_SHIFT)
        prov28 |= self._val2field(self.cor_frac_ns_ts_en,
                                  macPhyPtpEgressCorrectionFractionalNanosecondTimestampEnable_WIDTH,
                                  macPhyPtpEgressCorrectionFractionalNanosecondTimestampEnable_SHIFT)

        macPhyPtpEgressPacketPipelineThreshold_SHIFT = 0
        macPhyPtpEgressPacketPipelineThreshold_WIDTH = 4
        prov30 = self._val2field(self.pkt_pipeline_threshold,
                                 macPhyPtpEgressPacketPipelineThreshold_WIDTH,
                                 macPhyPtpEgressPacketPipelineThreshold_SHIFT)
        if pa.is_rhea():
            prov30 |= (self.pkt_max_threshold & 0xf) << 0x8

        macPhyPtpEgressPacketSizeLimit_SHIFT = 0
        macPhyPtpEgressPacketSizeLimit_WIDTH = 1
        macPhyPtpEgressPacketPause_SHIFT = 1
        macPhyPtpEgressPacketPause_WIDTH = 1
        prov32 = self._val2field(self.pkt_size_lim,
                                 macPhyPtpEgressPacketSizeLimit_WIDTH,
                                 macPhyPtpEgressPacketSizeLimit_SHIFT)
        prov32 |= self._val2field(self.pkt_pause,
                                  macPhyPtpEgressPacketPause_WIDTH,
                                  macPhyPtpEgressPacketPause_SHIFT)
        if pa.is_rhea():
            prov32 |= (0x1 << 0x2) if self.ts_extraction_option else (0x0 << 0x2)
            prov32 |= (self.pkt_extraction_option & 0xf) << 0x4

        prov34 = (self.ieee1588v1_pkt_act["sync"] & 0x3) << 0
        prov34 |= (self.ieee1588v1_pkt_act["other"] & 0x3) << 0
        prov34 |= (self.ieee1588v1_pkt_act["general"] & 0x3) << 0
        prov34 |= (self.ieee1588v1_ts_act["sync"] & 0x3) << 0
        prov34 |= (self.ieee1588v1_ts_act["other"] & 0x3) << 0

        prov35 = self.stacked_vlan_id & 0xffff

        prov36 = (self.ieee1588v2_cor_act["sync"] & 0x7) << 0
        prov36 |= (self.ieee1588v2_cor_act["delay"] & 0x7) << 3
        prov36 |= (self.ieee1588v2_cor_act["pdelay"] & 0x7) << 6
        prov36 |= (self.ieee1588v2_cor_act["presp"] & 0x7) << 9
        prov36 |= (self.ieee1588v2_cor_act["user"] & 0x7) << 12

        prov37 = (self.ieee1588v2_ts_act["sync"] & 0x3) << 0
        prov37 |= (self.ieee1588v2_ts_act["delay"] & 0x3) << 2
        prov37 |= (self.ieee1588v2_ts_act["pdelay"] & 0x3) << 4
        prov37 |= (self.ieee1588v2_ts_act["presp"] & 0x3) << 6
        prov37 |= (self.ieee1588v2_ts_act["user"] & 0x3) << 8

        macPhyPtpEgress1588Version2MessageType_SHIFT = 0
        macPhyPtpEgress1588Version2MessageType_WIDTH = 4
        prov38 = self._val2field(self.ieee1588v2_msg_type,
                                 macPhyPtpEgress1588Version2MessageType_WIDTH,
                                 macPhyPtpEgress1588Version2MessageType_SHIFT)
        if pa.is_rhea():
            prov38 |= (self.avtp_subtype & 0xff) << 0x8

        macPhyPtpEgress1588Version2MessageMask_SHIFT = 0
        macPhyPtpEgress1588Version2MessageMask_WIDTH = 4
        prov39 = self._val2field(self.ieee1588v2_msg_mask,
                                 macPhyPtpEgress1588Version2MessageMask_WIDTH,
                                 macPhyPtpEgress1588Version2MessageMask_SHIFT)

        macPhyPtpEgressPacketIfgThreshold_SHIFT = 0
        macPhyPtpEgressPacketIfgThreshold_WIDTH = 4
        prov40 = self._val2field(self.pkt_ifg_threshold,
                                 macPhyPtpEgressPacketIfgThreshold_WIDTH,
                                 macPhyPtpEgressPacketIfgThreshold_SHIFT)
        if pa.is_rhea():
            prov40 |= (self.pkt_rdy_latency & 0x7) << 0x8

        macPhyPtpEgressPacketReadyThreshold_SHIFT = 0
        macPhyPtpEgressPacketReadyThreshold_WIDTH = 4
        macPhyEgrPtpEgressGapFifoBypass_SHIFT = 4
        macPhyEgrPtpEgressGapFifoBypass_WIDTH = 1

        prov41 = self._val2field(self.pkt_rdy_thr,
                                 macPhyPtpEgressPacketReadyThreshold_WIDTH,
                                 macPhyPtpEgressPacketReadyThreshold_SHIFT)
        prov41 |= self._val2field(self.gap_fifo_bypass,
                                  macPhyEgrPtpEgressGapFifoBypass_WIDTH,
                                  macPhyEgrPtpEgressGapFifoBypass_SHIFT)
        if pa.is_rhea():
            prov41 |= (0x1 << 0x5) if self.tx_mac_fifo_cor_enable else (0x0 << 0x5)
            prov41 |= (self.tx_mac_fifo_cor & 0x3) << 0x6
            prov41 |= (self.tx_mac_fifo_base & 0xff) << 0x8

        # if base_addr == PcsPtpEgressVendorProvisioning26_ADR:
        #     prov26addr = 0xC639
        # else:
        #     prov26addr = 0xE619

        pa.writephyreg(0x3, base_addr + 0, prov26)
        pa.writephyreg(0x3, base_addr + 1, prov27)
        pa.writephyreg(0x3, base_addr + 2, prov28)
        pa.writephyreg(0x3, base_addr + 4, prov30)
        pa.writephyreg(0x3, base_addr + 6, prov32)
        pa.writephyreg(0x3, base_addr + 8, prov34)
        pa.writephyreg(0x3, base_addr + 9, prov35)
        pa.writephyreg(0x3, base_addr + 10, prov36)
        pa.writephyreg(0x3, base_addr + 11, prov37)
        pa.writephyreg(0x3, base_addr + 12, prov38)
        pa.writephyreg(0x3, base_addr + 13, prov39)
        pa.writephyreg(0x3, base_addr + 14, prov40)
        pa.writephyreg(0x3, base_addr + 15, prov41)

    def apply(self, pa):
        raise NotImplementedError()


class PtpTimestampingEgressEnableConfig(PtpTimestampingDefaultDisableConfig):
    def __init__(self):
        super(PtpTimestampingEgressEnableConfig, self).__init__()

        self.ieee1588v2_pkt_act = {
            "sync": self.PKT_ACT_CAPTURE_AND_FORWARD,
            "delay": self.PKT_ACT_CAPTURE_AND_FORWARD,
            "pdelay": self.PKT_ACT_CAPTURE_AND_FORWARD,
            "presp": self.PKT_ACT_CAPTURE_AND_FORWARD,
            "user": self.PKT_ACT_CAPTURE_AND_FORWARD,
            "gen": self.PKT_ACT_CAPTURE_AND_FORWARD
        }

        self.pkt_rdy_lat = 4

    def apply(self, pa):
        print "Applying egress timestamp offset"
        self._configure_timestamp_offset(pa, 0xC633)
        print "Applying egress timestamping"
        self._configure_timestamping(pa, 0xC639)


class PtpTimestampingIngressEnableConfig(PtpTimestampingDefaultDisableConfig):
    def __init__(self):
        super(PtpTimestampingIngressEnableConfig, self).__init__()

        self.ieee1588v2_pkt_act = {
            "sync": self.PKT_ACT_CAPTURE_AND_FORWARD,
            "delay": self.PKT_ACT_CAPTURE_AND_FORWARD,
            "pdelay": self.PKT_ACT_CAPTURE_AND_FORWARD,
            "presp": self.PKT_ACT_CAPTURE_AND_FORWARD,
            "user": self.PKT_ACT_CAPTURE_AND_FORWARD,
            "gen": self.PKT_ACT_CAPTURE_AND_FORWARD
        }

        self.pkt_rdy_lat = 4

    def apply(self, pa):
        print "Applying ingress timestamp offset"
        self._configure_timestamp_offset(pa, 0xE613)
        print "Applying ingress timestamping"
        self._configure_timestamping(pa, 0xE619)


class SecDefaultDisableConfig(object):
    def __init__(self):
        self.bypass_mss = False
        self.bypass_parser = False

    def apply(self, pa):
        raise NotImplementedError()


class SecEgressEnableConfig(object):
    def __init__(self):
        super(SecEgressEnableConfig, self).__init__()

    def apply(self, pa):
        print "Applying egress SEC configuration"

        val = pa.readphyreg(0x1e, 0x4000)
        if self.bypass_mss:
            val |= 1 << 0xa
        else:
            val &= ~(1 << 0xa)
        pa.writephyreg(0x1e, 0x4000, val)

        val = pa.readphyreg(0x1e, 0x4140)
        if self.bypass_parser:
            val |= 1 << 0xf
        else:
            val &= ~(1 << 0xf)
        pa.writephyreg(0x1e, 0x4140, val)


class SecIngressEnableConfig(object):
    def __init__(self):
        super(SecIngressEnableConfig, self).__init__()

    def apply(self, pa):
        print "Applying ingress SEC configuration"

        val = pa.readphyreg(0x1e, 0x7000)
        if self.bypass_mss:
            val |= 1 << 0xa
        else:
            val &= ~(1 << 0xa)
        pa.writephyreg(0x1e, 0x7000, val)

        val = pa.readphyreg(0x1e, 0x7140)
        if self.bypass_parser:
            val |= 1 << 0xf
        else:
            val &= ~(1 << 0xf)
        pa.writephyreg(0x1e, 0x7140, val)


class PtpConfig(object):
    def __init__(self, **kwargs):
        self.speed = kwargs.get("speed", LINK_SPEED_10G)
        # self.ptp_ts_stat = {
        #     "tps_state": 0x0,
        #     "ptp_tc": 0x2
        # }

    # def _set_mac_reg_bit(self, reg_address, bit_num, value):
    #     assert value in [0, 1]
    #     val = self.atltool.readreg(reg_address)
    #     val = (val & ~(1 << bit_num)) | value << bit_num
    #     val = self.atltool.writereg(reg_address, val)

    # def _set_mac_rmw(self, reg_address, mask, value):
    #     val = self.atltool.readreg(reg_address)
    #     val &= mask
    #     val |= value
    #     val = self.atltool.writereg(reg_address, val)

    # def _set_phy_reg_bit(self, reg_mmd, reg_address, bit_num, value):
    #     assert value in [0, 1]
    #     val = self.atltool.readphyreg(reg_mmd, reg_address)
    #     val = (val & ~(1 << bit_num)) | value << bit_num
    #     val = self.atltool.writephyreg(reg_mmd, reg_address, val)

    # def enable_hw_block(self):
    #     val = self.atltool.readreg(0x4600)
    #     # PTP Reset; Default 0; Set to 1 to hold all internal logic under reset
    #     # PTP clock enable; Default 1; Enables clock when = 1
    #     # PTP Bypass Master Enable; Default 1; Set to 1 to bypass the entire PTP module. When this is set, PTP Bypass Section Enable is ignored.
    #     val |= 0x8000 | 0x10 | 0x1
    #     val = self.atltool.writereg(0x4600, val)

    #     # Remove reset bit
    #     self._set_mac_reg_bit(0x4600, 0, 0)

    #     # # Disable MSS
    #     # # SEC Egress Bypass MSS Enable; Default 0; When this bit is set to 1, egress MSS block is bypassed, i.e. egress PTP data is sent to the line side MAC without encryption.
    #     # self._set_phy_reg_bit(0x1e, 0x4000, 0xb, 1)
    #     # # SEC Ingress Bypass MSS Enable; Default 0; When this bit is set to 1, ingress MSS block is bypassed, i.e. the line side MAC Rx data is sent to ingress PTP without decryption.
    #     # self._set_phy_reg_bit(0x1e, 0x7000, 0xb, 1)

    #     # Enable PTP clock
    #     val = self.atltool.readphyreg(0x1e, 0xc012)
    #     # PKT Clock Enable; Default 0; ---
    #     # PKT Clock Enable; Default 0; ---
    #     val |= 0x8 | 0x4
    #     self.atltool.writephyreg(0x1e, 0xc012, val)

    #     # Set clock reference and disable PTP bypass
    #     val = self.atltool.readphyreg(0x3, 0xc600)
    #     # PTP Bypass Enable;
    #     val &= 0xfffc
    #     self.atltool.writephyreg(0x3, 0xc600, val)

    #     # PCS PTP Vendor Provisioning 19: Address 3.C612; A:9; PTP Control Clock Select; 01 = PLL1/5; Default 0x0
    #     self.atltool.writephyreg(0x3, 0xc612, PHY_PTP_PLL_NUMBER << 9)

    #     self._set_phy_rmw(3, 0xC647, ~(0xf), PTP_THRESHOLD)  # ptpEgressPacketIfgThreshold # 03.C647.3:0
    #     self._set_phy_rmw(3, 0xE627, ~(0xf), PTP_THRESHOLD)  # ptpIngressPacketIfgThreshold # 03.E627.3:0
    #     self._set_phy_rmw(3, 0xC63D, ~(0xf), PTP_THRESHOLD)  # ptpEgressPacketPipelineThreshold # 03.C63D.3:0
    #     self._set_phy_rmw(3, 0xE61D, ~(0xf), PTP_THRESHOLD)  # ptpIngressPacketPipelineThreshold # 03.E61D.3:0
    #     self._set_phy_rmw(3, 0xC648, ~(0xf | 0x10), PTP_THRESHOLD)  # ptpEgressPacketReadyThreshold # 03.C648.3:0
    #     self._set_phy_rmw(3, 0xE628, ~(0xf | 0x10), PTP_THRESHOLD)  # ptpEgressPacketReadyThreshold # 03.E628.3:0
    #     self._set_phy_rmw(3, 0xC620, ~(0x20), 0x20)  # ptpEgressBackPressureEnable # 03.C620.5
    #     self._set_phy_rmw(3, 0xE600, ~(0x20), 0x20)  # ptpIngressBackPressureEnable # 03.E600.5

    def _enable_phy_ptp_block(self, pa):
        # Enable PTP clock
        val = pa.readphyreg(0x1e, 0xc012)
        # PKT Clock Enable; Default 0; ---
        # PKT Clock Enable; Default 0; ---
        val |= 0x8 | 0x4
        pa.writephyreg(0x1e, 0xc012, val)

        # Set clock reference and disable PTP bypass
        val = pa.readphyreg(0x3, 0xc600)
        val &= 0xfffc
        pa.writephyreg(0x3, 0xc600, val)

        # PCS PTP Vendor Provisioning 19: Address 3.C612; A:9; PTP Control Clock Select; 01 = PLL1/5; Default 0x0
        pa.writephyreg(0x3, 0xc612, PHY_PTP_PLL_NUMBER << 9)

        # pa.writephyregrmw(3, 0xC647, ~(0xf), PTP_THRESHOLD)  # ptpEgressPacketIfgThreshold # 03.C647.3:0
        # pa.writephyregrmw(3, 0xE627, ~(0xf), PTP_THRESHOLD)  # ptpIngressPacketIfgThreshold # 03.E627.3:0
        # pa.writephyregrmw(3, 0xC63D, ~(0xf), PTP_THRESHOLD)  # ptpEgressPacketPipelineThreshold # 03.C63D.3:0
        # pa.writephyregrmw(3, 0xE61D, ~(0xf), PTP_THRESHOLD)  # ptpIngressPacketPipelineThreshold # 03.E61D.3:0
        # pa.writephyregrmw(3, 0xC648, ~(0xf | 0x10), PTP_THRESHOLD)  # ptpEgressPacketReadyThreshold # 03.C648.3:0
        # pa.writephyregrmw(3, 0xE628, ~(0xf | 0x10), PTP_THRESHOLD)  # ptpEgressPacketReadyThreshold # 03.E628.3:0
        # pa.writephyregrmw(3, 0xC620, ~(0x20), 0x20)  # ptpEgressBackPressureEnable # 03.C620.5
        # pa.writephyregrmw(3, 0xE600, ~(0x20), 0x20)  # ptpIngressBackPressureEnable # 03.E600.5

    def _configure_phy_ptp_rate(self, pa):
        if self.speed not in [LINK_SPEED_2_5G, LINK_SPEED_5G]:
            if self.speed == LINK_SPEED_100M:
                phy_mode = 0x3
            elif self.speed == LINK_SPEED_1G:
                phy_mode = 0x2
            else:
                phy_mode = 0x0

            val = pa.readphyreg(0x3, 0xc600)
            val &= 0xfcff  # clear PTP speed mode, 00 is for 100M, 1G and 10G
            val |= 0x1 << 0xe  # enable local PHY mode
            val |= phy_mode << 0xc  # set local PHY mode
            pa.writephyreg(0x3, 0xc600, val)
        else:
            val = pa.readphyreg(0x3, 0xc600)
            val &= 0x8fff  # clear local PHY mode
            if self.speed == LINK_SPEED_2_5G:
                val |= 0x300
            else:
                val |= 0x200

            pa.writephyreg(0x3, 0xc600, val)

    def _configure_phy_ptp_clock(self, pa):
        if pa.is_rhea():
            # PLL1 is 125 MHz on Rhea
            ns_inc = 8
            fns_inc = 0
        else:
            CLOCK_NS_INC = 6
            CLOCK_NS_150_INC = 6
            CLOCK_FNS_INC = 0x3fffff9c  # (1000000000 - EXT_CLOCK_HZ*CLOCK_NS_INC)
            CLOCK_FNS_150_INC = 0x3fffff9c  # 0x40000000 - 4 ppm to avoid accumulator issue

            if self.speed in [LINK_SPEED_100M, LINK_SPEED_1G]:
                ns_inc = CLOCK_NS_150_INC
                fns_inc = CLOCK_FNS_150_INC
            else:
                ns_inc = CLOCK_NS_INC
                fns_inc = CLOCK_FNS_INC

        pa.writephyreg(0x3, 0xc60b, ns_inc)
        pa.writephyreg(0x3, 0xc60c, fns_inc & 0xffff)
        pa.writephyreg(0x3, 0xc60d, (fns_inc >> 16) & 0xffff)
        pa.writephyreg(0x3, 0xc60e, 0x0)
        pa.writephyreg(0x3, 0xc612, PHY_PTP_PLL_NUMBER << 9)

        # Toggle bit 0x3 of 0x3.0xc60a register
        val = pa.readphyreg(0x3, 0xc60a)
        pa.writephyreg(0x3, 0xc60a, val & ~0x8)
        pa.writephyreg(0x3, 0xc60a, val | 0x8)
        pa.writephyreg(0x3, 0xc60a, val & ~0x8)

    def apply(self, pa):
        print "Configuring PHY PTP block"
        self._enable_phy_ptp_block(pa)
        print "Configuring PHY PTP rate"
        self._configure_phy_ptp_rate(pa)
        print "Configuring PHY PTP clock"
        self._configure_phy_ptp_clock(pa)

    # def _bytes_in_ns(self, ps):
    #     if self.speed == LINK_SPEED_1G:
    #         return 8 * ps
    #     if self.speed == LINK_SPEED_100M:
    #         return 80 * (ps)
    #     if self.speed == LINK_SPEED_2_5G:
    #         return 16 * (ps) / 5
    #     if self.speed == LINK_SPEED_5G:
    #         return 8 * (ps) / 5
    #     return 4 * (ps) / 5

    # def _delay_in_ns(self, ps):
    #     if self.speed == LINK_SPEED_1G:
    #         return self._bytes_in_ns(ps + PTP_EXTRA_PKT_DELAY_1G)
    #     if self.speed == LINK_SPEED_100M:
    #         return self._bytes_in_ns(ps + PTP_EXTRA_PKT_DELAY_100M)
    #     return self._bytes_in_ns(ps + PTP_EXTRA_PKT_DELAY_10G)

    # def _control_tps_gates(self, tps_state):
    #     if tps_state & run_bit:
    #         self.ptp_ts_stat["tps_state"] &= ~tps_state
    #     else:
    #         self.ptp_ts_stat["tps_state"] |= tps_state

    #     if self.ptp_ts_stat["tps_state"] & stop_main_mask:
    #         main_cr = 0
    #     else:
    #         main_cr = 0x10001
    #     self.atltool.writereg(0x7110, main_cr)

    # def config_ts_redirect(self):
    #     delay_in_ns = self._delay_in_ns(MAX_PKT_SIZE_IN_BASE_TC)
    #     dbg_ctrl = self.atltool.readreg(0x30c)  # Global Microprocessor Scratch Pad 4: Address 0x0000030C
    #     if dbg_ctrl & 0xffff:
    #         delay_in_ns = self._delay_in_ns(dbg_ctrl & 0xffff)

    #     # 0x7100 TX Packet Scheduler Data TC Control Register 1; data_tc_arb_mode 1:0, 1=Weighted-Strict Priority (WSP)
    #     self._set_mac_rmw(0x7100, 0x3, 0x1)

    #     # ??????????????????????????????? second time
    #     # 0x7100 TX Packet Scheduler Data TC Control Register 1; data_tc_arb_mode 1:0, 1=Weighted-Strict Priority (WSP)
    #     self._set_mac_rmw(0x7100, 0x3, 0x1)

    #     # 0x7900; tx_tc_mode 8; 0=8 TCs (each with 4 queues); 1=4 TCs (each with 8 queues)
    #     val = (self.atltool.readreg(0x7900) & 0x100) >> 8
    #     if val:
    #         tc_count = 4
    #     else:
    #         tc_count = 8
    #     self.ptp_ts_stat["q_tc"] = 32 // tc_count

    #     self._control_tps_gates(run_all)

    #     reg = 0x7400 + (self.ptp_ts_stat["ptp_tc"] * self.ptp_ts_stat["q_tc"]) * 0x10
    #     self._set_mac_rmw(reg, 0xfc000000, 0x3c << 26)

    #     self.ptp_ts_stat["ipg_before_ptp_in_ns"] = delay_in_ns


# from atltoolper import AtlTool
# a = AtlTool(port="pci1.00.0")

# pa = PhyAccessAtltool(atltool=a)

# cfg = PtpFiltersEgressEnableConfig()
# cfg.apply(pa)
# print "END OF PtpFiltersEgressEnableConfig.apply()"
# ptc = PtpTimestampingEgressEnableConfig(a)
# pc = PtpConfig(a, speed=LINK_SPEED_10G)
# pc.configure_timestamp_offset(ptc, PcsPtpEgressVendorProvisioning20_ADR)
# pc.configure_timestamping(ptc, PcsPtpEgressVendorProvisioning26_ADR)
# pc.config_ts_redirect()


# a.writereg(0x7118, 0x1)
# time.sleep(1)
# pa.extract_egress_ts()
