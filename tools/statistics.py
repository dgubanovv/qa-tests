import argparse
import re
import socket
import sys
from abc import abstractmethod, ABCMeta

if sys.platform == "win32":
    import wmi

from atltoolper import AtlTool
from command import Command
from constants import ATF_TOOLS_DIR, PHY_EUROPA, MAC_ATLANTIC1_B0
from ops import OpSystem
from utils import get_atf_logger
from ifconfig import get_conn_name


SCRIPT_STATUS_SUCCESS = "[STATISTICS-SUCCESS]"
SCRIPT_STATUS_FAILED = "[STATISTICS-FAILED]"

log = get_atf_logger()


class Statistics(object):
    __metaclass__ = ABCMeta

    # PHY STATISTISCS, (mmd, lsw, lsw_mask, lsw_shift, msw, msw_mask, msw_shift), if msw is not applicable it's -1
    PHY_VERSION = "PHY FW version"
    PHY_PROV_VER = "PHY prov versions"
    PHY_LINK_ATTEMPTS = "PHY Link attempts"
    PHY_SNR_MRG_A = "PHY SNR margin A"
    PHY_SNR_MRG_B = "PHY SNR margin B"
    PHY_SNR_MRG_C = "PHY SNR margin C"
    PHY_SNR_MRG_D = "PHY SNR margin D"
    PHY_ROLE = "PHY role"
    PHY_CABLE_LEN = "PHY Cable length"
    PHY_AVG_LDPC_ITER = "PHY Avg LDPC iterations"
    PHY_CRC8_ERRORS = "PHY CRC-8 errors"
    PHY_CORR_LDPC_FRAMES = "PHY Corrected LDPC frames"
    PHY_UNCORR_LDPC_FRAMES = "PHY Uncorrected LDPC frames"
    PHY_UNCORR_BURSTS_2_FRAMES = "PHY Uncorrected bursts of 2 LDPC frames"
    PHY_UNCORR_BURSTS_3_FRAMES = "PHY Uncorrected bursts of 3 LDPC frames"
    PHY_UNCORR_BURSTS_4_FRAMES = "PHY Uncorrected bursts of 4 LDPC frames"
    PHY_UNCORR_BURSTS_5P_FRAMES = "PHY Uncorrected bursts of 5+ LDPC frames"
    PHY_ERRORED_FRAMES = "PHY Errored LDPC frames"
    PHY_ERRORED_BLOCKS = "PHY Errored 65B blocks"
    PHY_RSI_GOOD_FRAMES = "PHY RSI good frames"
    PHY_RSI_BAD_FRAMES = "PHY RSI bad frames"
    PHY_TSI_GOOD_FRAMES = "PHY TSI good frames"
    PHY_TSI_BAD_FRAMES = "PHY TSI bad frames"
    PHY_TKL_GOOD_FRAMES = "PHY TKL good frames"
    PHY_TKL_BAD_FRAMES = "PHY TKL bad frames"
    PHY_RKL_GOOD_FRAMES = "PHY RKL good frames"
    PHY_RKL_BAD_FRAMES = "PHY RKL bad frames"
    PHY_TPL_GOOD_FRAMES = "PHY TPL good frames"
    PHY_TPL_BAD_FRAMES = "PHY TPL bad frames"
    PHY_RPL_GOOD_FRAMES = "PHY RPL good frames"
    PHY_RPL_BAD_FRAMES = "PHY RPL bad frames"
    PHY_MACSEC_INGRESS_OVERFLOW = "PHY MACSEC ingress overflow"
    PHY_MACSEC_EGRESS_OVERFLOW = "PHY MACSEC egress overflow"

    PHY_ALL_STATS = [PHY_VERSION, PHY_PROV_VER, PHY_LINK_ATTEMPTS, PHY_SNR_MRG_A, PHY_SNR_MRG_B, PHY_SNR_MRG_C,
                     PHY_SNR_MRG_D, PHY_ROLE, PHY_CABLE_LEN, PHY_AVG_LDPC_ITER, PHY_CRC8_ERRORS, PHY_CORR_LDPC_FRAMES,
                     PHY_UNCORR_LDPC_FRAMES, PHY_UNCORR_BURSTS_2_FRAMES, PHY_UNCORR_BURSTS_3_FRAMES,
                     PHY_UNCORR_BURSTS_4_FRAMES, PHY_UNCORR_BURSTS_5P_FRAMES, PHY_ERRORED_FRAMES, PHY_ERRORED_BLOCKS,
                     PHY_RSI_GOOD_FRAMES, PHY_RSI_BAD_FRAMES, PHY_TSI_GOOD_FRAMES, PHY_TSI_BAD_FRAMES,
                     PHY_TKL_GOOD_FRAMES, PHY_TKL_BAD_FRAMES, PHY_RKL_GOOD_FRAMES, PHY_RKL_BAD_FRAMES,
                     PHY_TPL_GOOD_FRAMES, PHY_TPL_BAD_FRAMES, PHY_RPL_GOOD_FRAMES, PHY_RPL_BAD_FRAMES,
                     PHY_MACSEC_INGRESS_OVERFLOW, PHY_MACSEC_EGRESS_OVERFLOW]

    PHY_ERROR_STATS = [PHY_CRC8_ERRORS, PHY_UNCORR_LDPC_FRAMES, PHY_UNCORR_BURSTS_2_FRAMES,
                       PHY_UNCORR_BURSTS_3_FRAMES, PHY_UNCORR_BURSTS_4_FRAMES, PHY_UNCORR_BURSTS_5P_FRAMES,
                       PHY_ERRORED_FRAMES, PHY_ERRORED_BLOCKS, PHY_RSI_BAD_FRAMES, PHY_TSI_BAD_FRAMES,
                       PHY_TKL_BAD_FRAMES, PHY_RKL_BAD_FRAMES, PHY_TPL_BAD_FRAMES, PHY_RPL_BAD_FRAMES,
                       PHY_MACSEC_INGRESS_OVERFLOW, PHY_MACSEC_EGRESS_OVERFLOW]

    PHY_STATISTICS_MAP = {
        PHY_EUROPA: {
            PHY_VERSION: (0x1e, 0x0020, 0xffff, 0, -1, -1, 0),  # TODO: always zero
            PHY_PROV_VER: (0x1e, 0xc885, 0xff, 0, -1, -1, 0),  # TODO: always zero
            PHY_LINK_ATTEMPTS: (0x7, 0xe830, 0xf000, 12, -1, -1, 0),
            PHY_SNR_MRG_A: (0x1, 0x85, 0x7fff, 0, -1, -1, 0),
            PHY_SNR_MRG_B: (0x1, 0x86, 0x7fff, 0, -1, -1, 0),
            PHY_SNR_MRG_C: (0x1, 0x87, 0x7fff, 0, -1, -1, 0),
            PHY_SNR_MRG_D: (0x1, 0x88, 0x7fff, 0, -1, -1, 0),
            PHY_CABLE_LEN: (0x1e, 0xc884, 0xffff, 0, -1, -1, 0),
            PHY_AVG_LDPC_ITER: (0x3, 0xe808, 0xffff, 0, -1, -1, 0),
            PHY_CRC8_ERRORS: (0x3, 0xe810, 0xffff, 0, 0xe811, 0x1f, 0),
            PHY_CORR_LDPC_FRAMES: (0x3, 0xe816, 0xffff, 0, 0xe817, 0xffff, 0),
            PHY_UNCORR_LDPC_FRAMES: (0x3, 0xe820, 0xffff, 0, 0xe821, 0xffff, 0),
            PHY_UNCORR_BURSTS_2_FRAMES: (0x3, 0xe822, 0xffff, 0, 0xe823, 0xf, 0),
            PHY_UNCORR_BURSTS_3_FRAMES: (0x3, 0xe824, 0xffff, 0, 0xe825, 0xf, 0),
            PHY_UNCORR_BURSTS_4_FRAMES: (0x3, 0xe826, 0xffff, 0, 0xe827, 0xf, 0),
            PHY_UNCORR_BURSTS_5P_FRAMES: (0x3, 0xe828, 0xffff, 0, 0xe829, 0xf, 0),
            PHY_ERRORED_FRAMES: (0x3, 0x21, 0x3f00, 8, -1, -1, 0),
            PHY_ERRORED_BLOCKS: (0x3, 0x21, 0xff, 0, -1, -1, 0),
            PHY_RSI_GOOD_FRAMES: (0x1d, 0xd313, 0xffff, 0, 0xd314, 0x3ff, 0),
            PHY_RSI_BAD_FRAMES: (0x1d, 0xd315, 0xffff, 0, 0xd316, 0x3ff, 0),
            PHY_TSI_GOOD_FRAMES: (0x1d, 0xd292, 0xffff, 0, 0xd293, 0x3ff, 0),
            PHY_TSI_BAD_FRAMES: (0x1d, 0xd294, 0xffff, 0, 0xd295, 0x3ff, 0),
            PHY_TKL_GOOD_FRAMES: (0x3, 0xc860, 0xffff, 0, 0xc861, 0x3ff, 0),
            PHY_TKL_BAD_FRAMES: (0x3, 0xc862, 0xffff, 0, 0xc863, 0x3ff, 0),
            PHY_RKL_GOOD_FRAMES: (0x3, 0xe860, 0xffff, 0, 0xe861, 0x3ff, 0),
            PHY_RKL_BAD_FRAMES: (0x3, 0xe862, 0xffff, 0, 0xe863, 0x3ff, 0),
            PHY_TPL_GOOD_FRAMES: (0x3, 0xc820, 0xffff, 0, 0xc821, 0x3ff, 0),
            PHY_TPL_BAD_FRAMES: (0x3, 0xc822, 0xffff, 0, 0xc823, 0x3ff, 0),
            PHY_RPL_GOOD_FRAMES: (0x3, 0xe812, 0xffff, 0, 0xe813, 0x3ff, 0),
            PHY_RPL_BAD_FRAMES: (0x3, 0xe814, 0xffff, 0, 0xe815, 0x3ff, 0),
            PHY_MACSEC_INGRESS_OVERFLOW: (0xa, 0x90, 0xff00, 8, -1, -1, 0),
            PHY_MACSEC_EGRESS_OVERFLOW: (0xa, 0x90, 0x00ff, 0, -1, -1, 0),
        }
    }

    MAC_RX_DMA_GOOD_PACKETS = "MAC RX DMA good packets"
    MAC_RX_DMA_GOOD_OCTETS = "MAC RX DMA good octets"
    MAC_RX_LOOPBACK_GOOD_PACKETS = "MAC RX loopback good packets"
    MAC_RX_DMA_DROP_PACKETS = "MAC RX DMA drop packets"
    MAC_RX_LRO_COALESCED_PACKETS = "MAC RX LRO coalesced packets"
    MAC_RX_LRO_COALESCED_OCTETS = "MAC RX LRO coalesced octets"
    MAC_RX_LRO_COALESCED_EVENTS = "MAC RX LRO coalesced events"
    MAC_RX_LRO_ABORTS = "MAC RX LRO coalesced aborts"
    MAC_RX_FILTER_MEM_PARITY_ERRORS = "MAC RX filter memory parity errors"
    MAC_RX_FILTER_MEM_OVERFLOWS = "MAC RX filter memory overflows"
    MAC_RX_FILTER_LOOPBACK_MEM_PARITY_ERRORS = "MAC RX filter loopback memory parity errors"
    MAC_RX_FILTER_SOP_ERRORS = "MAC RX filter SOP errors"
    MAC_RX_FILTER_RX_ERRORS = "MAC RX filter RX errors"
    MAC_TX_DMA_GOOD_PACKETS = "MAC TX DMA good packets"
    MAC_TX_DMA_GOOD_OCTETS = "MAC TX DMA good octets"
    MAC_TX_LOOPBACK_GOOD_PACKETS = "MAC TX loopback good packets"

    MAC_TKL_GOOD_FRAMES = "MAC TKL good frames"
    MAC_TKL_BAD_FRAMES = "MAC TKL bad frames"
    MAC_RKL_GOOD_FRAMES = "MAC RKL good frames"
    MAC_RKL_BAD_FRAMES = "MAC RKL bad frames"
    MAC_RKL_ERRORED_BLOCK_COUNTER = "MAC RKL errored blocks"
    MAC_RKL_BER_COUNTER = "MAC RKL BER counter"
    MAC_RKL_TEST_PATTERN_ERROR_COUNTER = "MAC RKL test pattern error counter"
    MAC_KAN_RX_PMD_TRAINING_CONTROL_CHANNEL_ERROR_COUNTER = "MAC KAN RX PMD training control channel error counter"
    MAC_KAN_RX_PMD_TRAINING_MARKER_ERROR_COUNTER = "MAC KAN RX PMD training marker error counter"
    MAC_KAN_AN_RX_DME_ERROR_COUNTER = "MAC KAN AN RX DME error counter"
    MAC_KAN_RX_PMD_TRAINING_PRBS_ERROR_COUNTER = "MAC KAN RX PMD training PRBS error counter"
    MAC_TSI_GOOD_FRAMES = "MAC TSI good frames"
    MAC_TSI_BAD_FRAMES = "MAC TSI bad frames"
    MAC_TSI_FALSE_CARRIER_COUNTER = "MAC TSI false carrier counter"
    MAC_RSI_BAD_FRAMES = "MAC RSI bad frames"
    MAC_RSI_GOOD_FRAMES = "MAC RSI good frames"
    MAC_RSI_FALSE_CARRIER_COUNTER = "MAC RSI false carrier counter"
    MAC_RSI_RX_LINE_COLLISION_COUNTER = "MAC RSI RX line collision counter"
    MAC_RSI_COLLISION_COUNTER = "MAC RSI collision counter"
    MAC_RSI_RX_RUNT_FRAME_COUNTER = "MAC RSI RX runt frame counter"
    MAC_RSI_RX_FRAME_ALIGNMENT_ERRORS = "MAC RSI RX frame alignment errors"
    MAC_USX_HEADER_CRC_ERRORS = "MAC USX header CRC errors"

    MAC_ERROR_STATS = [MAC_RX_DMA_DROP_PACKETS, MAC_RX_FILTER_MEM_PARITY_ERRORS,
                       MAC_RX_FILTER_MEM_OVERFLOWS, MAC_RX_FILTER_LOOPBACK_MEM_PARITY_ERRORS, MAC_RX_FILTER_SOP_ERRORS,
                       MAC_RX_FILTER_RX_ERRORS, MAC_TKL_BAD_FRAMES, MAC_RKL_BAD_FRAMES, MAC_RKL_ERRORED_BLOCK_COUNTER,
                       MAC_RKL_TEST_PATTERN_ERROR_COUNTER, MAC_KAN_RX_PMD_TRAINING_CONTROL_CHANNEL_ERROR_COUNTER,
                       MAC_KAN_RX_PMD_TRAINING_MARKER_ERROR_COUNTER, MAC_KAN_AN_RX_DME_ERROR_COUNTER,
                       MAC_KAN_RX_PMD_TRAINING_PRBS_ERROR_COUNTER, MAC_TSI_BAD_FRAMES, MAC_TSI_FALSE_CARRIER_COUNTER,
                       MAC_RSI_BAD_FRAMES, MAC_RSI_FALSE_CARRIER_COUNTER, MAC_RSI_RX_LINE_COLLISION_COUNTER,
                       MAC_RSI_COLLISION_COUNTER, MAC_RSI_RX_RUNT_FRAME_COUNTER, MAC_RSI_RX_FRAME_ALIGNMENT_ERRORS]
    # MAC_RX_LRO_ABORTS is not an error.
    # MAC_USX_HEADER_CRC_ERRORS is a HW problem.

    MAC_COUNTERS_MAP = {
        MAC_ATLANTIC1_B0: {
            MAC_RX_DMA_GOOD_PACKETS: (0x6800, 0xffffffff, 0, 0x6804, 0xffffffff, 0),
            MAC_RX_DMA_GOOD_OCTETS: (0x6808, 0xffffffff, 0, 0x680c, 0xffffffff, 0),
            MAC_RX_LOOPBACK_GOOD_PACKETS: (0x6810, 0xffffffff, 0, 0x6814, 0xffffffff, 0),
            MAC_RX_DMA_DROP_PACKETS: (0x6818, 0xffffffff, 0, -1, -1, 0),
            MAC_RX_LRO_COALESCED_PACKETS: (0x6820, 0xffffffff, 0, 0x6824, 0xffffffff, 0),
            MAC_RX_LRO_COALESCED_OCTETS: (0x6828, 0xffffffff, 0, 0x682c, 0xffffffff, 0),
            MAC_RX_LRO_COALESCED_EVENTS: (0x6830, 0xffffffff, 0, 0x6834, 0xffffffff, 0),
            MAC_RX_LRO_ABORTS: (0x6838, 0xffffffff, 0, 0x683c, 0xffffffff, 0),
            MAC_RX_FILTER_MEM_PARITY_ERRORS: (0x6e00, 0xffffffff, 0, -1, -1, 0),
            MAC_RX_FILTER_MEM_OVERFLOWS: (0x6e04, 0xffffffff, 0, -1, -1, 0),
            MAC_RX_FILTER_LOOPBACK_MEM_PARITY_ERRORS: (0x6e08, 0xffffffff, 0, -1, -1, 0),
            MAC_RX_FILTER_SOP_ERRORS: (0x6e0c, 0xffffffff, 0, -1, -1, 0),
            MAC_RX_FILTER_RX_ERRORS: (0x6e10, 0xffffffff, 0, -1, -1, 0),
            MAC_TX_DMA_GOOD_PACKETS: (0x8800, 0xffffffff, 0, 0x8804, 0xffffffff, 0),
            MAC_TX_DMA_GOOD_OCTETS: (0x8808, 0xffffffff, 0, 0x880c, 0xffffffff, 0),
            MAC_TX_LOOPBACK_GOOD_PACKETS: (0x8810, 0xffffffff, 0, 0x8814, 0xffffffff, 0),

            MAC_TKL_GOOD_FRAMES: (0x4050, 0x3ffffff, 0, -1, -1, 0),
            MAC_TKL_BAD_FRAMES: (0x4054, 0x3ffffff, 0, -1, -1, 0),
            MAC_RKL_GOOD_FRAMES: (0x40a0, 0x3ffffff, 0, -1, -1, 0),
            MAC_RKL_BAD_FRAMES: (0x40a4, 0x3ffffff, 0, -1, -1, 0),
            MAC_RKL_ERRORED_BLOCK_COUNTER: (0x40a8, 0xff0000, 0x10, -1, -1, 0),
            MAC_RKL_BER_COUNTER: (0x40a8, 0x3f, 0, -1, -1, 0),
            MAC_RKL_TEST_PATTERN_ERROR_COUNTER: (0x40ac, 0xffff, 0, -1, -1, 0),
            MAC_KAN_RX_PMD_TRAINING_CONTROL_CHANNEL_ERROR_COUNTER: (0x4134, 0xffff0000, 0x10, -1, -1, 0),
            MAC_KAN_RX_PMD_TRAINING_MARKER_ERROR_COUNTER: (0x4134, 0xffff, 0, -1, -1, 0),
            MAC_KAN_AN_RX_DME_ERROR_COUNTER: (0x4138, 0xffff0000, 0x10, -1, -1, 0),
            MAC_KAN_RX_PMD_TRAINING_PRBS_ERROR_COUNTER: (0x4138, 0xffff, 0, -1, -1, 0),
            MAC_TSI_GOOD_FRAMES: (0x4194, 0x3ffffff, 0, -1, -1, 0),
            MAC_TSI_BAD_FRAMES: (0x4198, 0x3ffffff, 0, -1, -1, 0),
            MAC_TSI_FALSE_CARRIER_COUNTER: (0x419c, 0xff0000, 0x10, -1, -1, 0),
            MAC_RSI_BAD_FRAMES: (0x4274, 0x3ffffff, 0, -1, -1, 0),
            MAC_RSI_GOOD_FRAMES: (0x4278, 0x3ffffff, 0, -1, -1, 0),
            MAC_RSI_FALSE_CARRIER_COUNTER: (0x427c, 0xff, 0, -1, -1, 0),
            MAC_RSI_RX_LINE_COLLISION_COUNTER: (0x4280, 0x3fff00, 8, -1, -1, 0),
            MAC_RSI_COLLISION_COUNTER: (0x4280, 0xff, 0, -1, -1, 0),
            MAC_RSI_RX_RUNT_FRAME_COUNTER: (0x4284, 0xffff, 0, -1, -1, 0),
            MAC_RSI_RX_FRAME_ALIGNMENT_ERRORS: (0x4288, 0xffff, 0, -1, -1, 0),
            MAC_USX_HEADER_CRC_ERRORS: (0x4368, 0xffff, 0, -1, -1, 0),
        }
    }

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(StatisticsLocal)
        else:
            return object.__new__(StatisticsRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]

    @abstractmethod
    def get_eee_statistics(self):
        pass

    @abstractmethod
    def get_drv_counters(self):
        pass

    @abstractmethod
    def get_mac_counters(self):
        pass

    @abstractmethod
    def get_phy_statistics(self):
        pass


class StatisticsLocal(Statistics):
    def get_drv_counters(self):
        ops = OpSystem()
        if ops.is_windows():
            cnts = {}
            win_stat = wmi.WMI(namespace='StandardCimv2').MSFT_NetAdapterStatisticsSettingData()
            iface = get_conn_name(self.port)
            for stat in win_stat:
                if stat.Name == iface:
                    cnts["ReceivedBytes"] = stat.ReceivedBytes
                    cnts["ReceivedUnicastBytes"] = stat.ReceivedUnicastBytes
                    cnts["ReceivedUnicastPackets"] = stat.ReceivedUnicastPackets
                    cnts["SentBytes"] = stat.SentBytes
                    cnts["SentUnicastBytes"] = stat.SentUnicastBytes
                    cnts["SentUnicastPackets"] = stat.SentUnicastPackets
                    cnts["OutboundDiscardedPackets"] = stat.OutboundDiscardedPackets
                    cnts["OutboundPacketErrors"] = stat.OutboundPacketErrors
                    cnts["ReceivedPacketErrors"] = stat.ReceivedPacketErrors
            return cnts
        elif ops.is_linux():
            iface = get_conn_name(self.port)
            cmd = "sudo ethtool -S {}".format(iface)
            res = Command(cmd=cmd, silent=True).run_join(5)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Getting counters failed")

            cnts = {}
            re_cnt = re.compile(r" *([a-zA-Z\[\]0-9_ ]+): ([0-9]+)", re.DOTALL)
            for line in res["output"]:
                m = re_cnt.match(line)
                if m is not None:
                    cname = m.group(1)
                    cval = int(m.group(2), 0)
                    cnts[cname] = cval
            return cnts
        elif ops.is_mac():
            raise NotImplementedError()

    def get_eee_statistics(self, is_print=True):
        a = AtlTool(port=self.port)
        data = {}
        statistics_base_addr = a.readreg(0x360)
        data["LINK_DROPS_DURING_STABILITY_TIMER"] = a.readmem(statistics_base_addr + 0xd8, 4)[0]
        data["LINK_DROPS_AFTER_STABILITY_TIMER"] = a.readmem(statistics_base_addr + 0xdc, 4)[0]
        data["EEE_FAILURES"] = a.readmem(statistics_base_addr + 0xe0, 4)[0]
        data["EEE_STATE_LINK_DOWN"] = a.readmem(statistics_base_addr + 0xe8, 4)[0]

        if is_print:
            for k, v in data.items():
                log.info("{} = {}".format(k, v))

        return data

    def get_mac_counters(self):
        a = AtlTool(port=self.port)
        mac = MAC_ATLANTIC1_B0  # TODO: hardcoded
        cnts = {}

        for k, (lsw, lsw_mask, lsw_shift, msw, msw_mask, msw_shift) in self.MAC_COUNTERS_MAP[mac].items():
            cnts[k] = a.readreg(lsw) & lsw_mask
            cnts[k] = cnts[k] >> abs(lsw_shift) if lsw_shift > 0 else cnts[k] << abs(lsw_shift)
            if msw != -1:
                m = (a.readreg(msw) & msw_mask)
                m = m >> abs(msw_shift) if msw_shift > 0 else m << abs(msw_shift)
                m <<= 16
                cnts[k] |= m

        return cnts

    def get_phy_statistics(self):
        a = AtlTool(port=self.port)
        phy = PHY_EUROPA  # TODO: hardcoded
        stats = {}

        for k, (mmd, lsw, lsw_mask, lsw_shift, msw, msw_mask, msw_shift) in self.PHY_STATISTICS_MAP[phy].items():
            stats[k] = a.readphyreg(mmd, lsw) & lsw_mask
            stats[k] = stats[k] >> abs(lsw_shift) if lsw_shift > 0 else stats[k] << abs(lsw_shift)
            if msw != -1:
                m = (a.readphyreg(mmd, msw) & msw_mask)
                m = m >> abs(msw_shift) if msw_shift > 0 else m << abs(msw_shift)
                m <<= 16
                stats[k] |= m

            # Additional manipulations

            if k in [self.PHY_SNR_MRG_A, self.PHY_SNR_MRG_B, self.PHY_SNR_MRG_C, self.PHY_SNR_MRG_D]:
                stats[k] /= 10.0

            if k == self.PHY_AVG_LDPC_ITER:
                stats[k] /= 4096.0

        if phy == PHY_EUROPA:
            # Read PHY role
            reg_val = a.readphyreg(0x7, 0x21)
            phy_role_raw = (reg_val >> 14) & 1
            stats[self.PHY_ROLE] = "Master" if phy_role_raw == 1 else "Slave"

        return stats


class StatisticsRemote(Statistics):
    def __init__(self, **kwargs):
        super(StatisticsRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).wait(60)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to execute remote command")
        if not any(SCRIPT_STATUS_SUCCESS in line for line in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote op system operation")
        return res["output"]

    def get_drv_counters(self):
        cmd = "cd {} && python statistics.py -p {} -c getdrvcounters ".format(ATF_TOOLS_DIR, self.port)
        stdout = self.remote_exec(cmd)

        cnts = {}
        re_cnt = re.compile(r".*\|    ([a-zA-Z\[\]0-9 ]+) = ([0-9]+)", re.DOTALL)
        for line in stdout:
            m = re_cnt.match(line)
            if m is not None:
                cname = m.group(1)
                cval = int(m.group(2), 0)
                cnts[cname] = cval
        return cnts

    def get_eee_statistics(self):
        raise NotImplemented()

    def get_mac_counters(self):
        cmd = "cd {} && sudo python statistics.py -p {} -c getmaccounters ".format(ATF_TOOLS_DIR, self.port)
        stdout = self.remote_exec(cmd)

        cnts = {}
        re_cnt = re.compile(r".*\|    ([a-zA-Z\[\]0-9 ]+) = ([0-9]+)", re.DOTALL)
        for line in stdout:
            m = re_cnt.match(line)
            if m is not None:
                cname = m.group(1)
                cval = int(m.group(2), 0)
                cnts[cname] = cval
        return cnts

    def get_phy_statistics(self):
        cmd = "cd {} && sudo python statistics.py -p {} -c getphystatistics ".format(ATF_TOOLS_DIR, self.port)
        stdout = self.remote_exec(cmd)

        stats = {}
        re_stat = re.compile(r".*\|    ([a-zA-Z0-9\+ \-]+) = ([0-9a-zA-Z\.]+)", re.DOTALL)
        for line in stdout:
            m = re_stat.match(line)
            if m is not None:
                sname = m.group(1)
                try:
                    sval = int(m.group(2), 0)
                except Exception:
                    try:
                        sval = float(m.group(2))
                    except Exception:
                        sval = m.group(2)
                stats[sname] = sval
        return stats


class StatisticsArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error(SCRIPT_STATUS_FAILED)
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = StatisticsArgumentParser()
    parser.add_argument("-t", "--time", help="Number of seconds to collect data", type=float)
    parser.add_argument("-i", "--interval", help="Interval in seconds", type=float)
    parser.add_argument("-p", "--port", help="PCI port, i.e. pci0.00.0, ...", type=str, required=True)
    parser.add_argument("--pid", help="Process ID", type=int)
    parser.add_argument("-c", "--command", help="Command to be performed", type=str,
                        choices=["getphystatistics", "getdrvcounters", "getmaccounters"])
    args = parser.parse_args()

    try:
        s = Statistics(port=args.port)

        if args.command == "getphystatistics":
            if args.port is None:
                log.error("To get PHY statistics port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            stats = s.get_phy_statistics()
            for k in sorted(stats.keys()):
                # log.info("|    {} = {}".format(k, hex(stats[k]) if type(stats[k]) in [int, long] else stats[k]))
                log.info("|    {} = {}".format(k, stats[k]))
        if args.command == "getdrvcounters":
            if args.port is None:
                log.error("To get driver counters port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            cnts = s.get_drv_counters()
            for k in sorted(cnts.keys()):
                # log.info("|    {} = {}".format(k, hex(stats[k]) if type(stats[k]) in [int, long] else stats[k]))
                log.info("|    {} = {}".format(k, cnts[k]))
        if args.command == "getmaccounters":
            if args.port is None:
                log.error("To get MAC counters port must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            cnts = s.get_mac_counters()
            for k in sorted(cnts.keys()):
                # log.info("|    {} = {}".format(k, hex(stats[k]) if type(stats[k]) in [int, long] else stats[k]))
                log.info("|    {} = {}".format(k, cnts[k]))
    except Exception:
        log.exception("Statistics failed")
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
