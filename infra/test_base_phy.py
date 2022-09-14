from test_base import TestBase
from tools.atltoolper import AtlTool
from tools.constants import FELICITY_CARDS
from tools.log import get_atf_logger

log = get_atf_logger()


def print_statistics(counters):
    try:
        log.debug('STATS: ')
        for k in sorted(counters.keys()):
            log.debug('    {:>55s}: {}'.format(k, counters[k]))
    except Exception as e:
        log.debug('Exception[print_stats]: {}'.format(e))


class TestBasePhy(TestBase):

    @classmethod
    def setup_class(cls):
        super(TestBasePhy, cls).setup_class()

        try:
            pass
        except Exception:
            log.exception("Failed while setting up class")

    def readphyreg(self, mmd, reg, phy_id=0):
        """This is method wrapper to adopt tests for execution on different setups.
        Usage of that method allows execution on DUT devices with internal PHY (like LilNikki or Bermuda cards) and
        on separate PHYs (for example Felicity + Rhea minipod).
        """
        if self.dut_phy_board_name is not None:
            val = self.phy_controls[phy_id].phyAccess.pifReadData(mmd << 16 | reg)
            log.info("Register PHY {} 0x{:x}.0x{:x}: 0x{:04x} : {:08b} {:08b}".format(
                phy_id, mmd, reg, val & 0xffff, (val >> 8) & 0xFF, val & 0xFF))
            return val
        else:
            if self.dut_fw_card in FELICITY_CARDS:
                raise Exception("Have no idea wheter PHY is present or not")
            if not hasattr(self, "dut_atltool"):
                self.dut_atltool = AtlTool(port=self.dut_port, host=self.dut_hostname)
            return self.dut_atltool.readphyreg(mmd, reg)

    def writephyreg(self, mmd, reg, value, phy_id=0):
        """This is method wrapper to adopt tests for execution on different setups.
        Usage of that method allows execution on DUT devices with internal PHY (like LilNikki or Bermuda cards) and
        on separate PHYs (for example Felicity + Rhea minipod).
        """
        if self.dut_phy_board_name is not None:
            self.phy_controls[phy_id].phyAccess.pifWriteData(mmd << 16 | reg, value)
            log.info("Register PHY {} 0x{:x}.0x{:x}: 0x{:04x} written".format(phy_id, mmd, reg, value & 0xffff))
        else:
            if self.dut_fw_card in FELICITY_CARDS:
                raise Exception("Have no idea wheter PHY is present or not")
            if not hasattr(self, "dut_atltool"):
                self.dut_atltool = AtlTool(port=self.dut_port, host=self.dut_hostname)
            return self.dut_atltool.writephyreg(mmd, reg, value)

    def read_phy_counters(self, phy_id=-1):
        from sifControls import SifCounters
        phy_ctl = self.phy_control if phy_id == -1 else self.phy_control[phy_id]
        sif_counters = SifCounters(phy_ctl)

        keys = ["RPL", "TPL", "RKL0", "TKL0", "RSI1", "TSI1", "MAC-IG-TX", "MAC-IG-RX", "MAC-EG-TX", "MAC-EG-RX",
         "MAC-IG-PAUSE-TX", "MAC-IG-PAUSE-RX", "MAC-EG-PAUSE-TX", "MAC-EG-PAUSE-RX", "MAC-IG-TX-ERR", "MAC-IG-RX-ERR"]

        curr_stat = {}
        for k in keys:
            curr_stat['{}-good'.format(k)] = sif_counters.getSifCounter(k, 'GOOD')
            curr_stat['{}-bad'.format(k)] = sif_counters.getSifCounter(k, 'BAD')

        return curr_stat
