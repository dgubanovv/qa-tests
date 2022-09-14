import time
import timeit

from hlh.register import Register
from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_10G, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M, LINK_SPEED_10M, \
    SYSTEM_INTERFACE_SYSTEM_LOOPBACK, SYSTEM_INTERFACE_NETWORK_LOOPBACK, NETWORK_INTERFACE_SYSTEM_LOOPBACK, \
    NETWORK_INTERFACE_NETWORK_LOOPBACK, NO_LOOPBACK, RATE_ADAPTATION_NO, RATE_ADAPTATION_USX, RATE_ADAPTATION_PAUSE, \
    RATE_ADAPTATION_UNKNOW, SYSTEM_SIDE_SHALLOW_LOOPBACK, LINE_SIDE_SHALLOW_LOOPBACK, LINK_SPEED_NO_LINK, ALL_LINK_SPEEDS
from tools.constants import ENABLE, DISABLE, EGRESS, INGRESS
from tools.constants import MII_MODE_XFI, MII_MODE_XFI_SGMII, MII_MODE_XFI_DIV2, MII_MODE_OCSGMII, MII_MODE_USX, \
    MII_MODE_SGMII, EGRESS, INGRESS
from tools.log import get_atf_logger

MAP_SPEED_TO_PHY_REG = {
    LINK_SPEED_10G: 0x31f,
    LINK_SPEED_5G: 0x31e,
    LINK_SPEED_2_5G: 0x31d,
    LINK_SPEED_1G: 0x31c,
    LINK_SPEED_100M: 0x31b,
    LINK_SPEED_10M: 0x31a
}

MAP_CONNECT_RATE = {
    0x0: LINK_SPEED_10M,
    0x1: LINK_SPEED_100M,
    0x2: LINK_SPEED_1G,
    0x3: LINK_SPEED_10G,
    0x4: LINK_SPEED_2_5G,
    0x5: LINK_SPEED_5G,
}

MAP_PAIR_STATUS = {
    0b000: 'OK',
    0b001: 'Short to Pair +1',
    0b010: 'Short to Pair +2',
    0b011: 'Short to Pair +3',
    0b100: 'Short Circuit (<  30 Om)',
    0b101: 'Low  Mismatch (<  85 Om)',
    0b110: 'High Mismatch (> 115 Om)',
    0b111: 'Open  Circuit (> 300 Om)'
}

MAP_CONNECTION_STATE = {
    0x00: 'Inactive',
    0x01: 'Cable diagnostics',
    0x02: 'Autonegotiation',
    0x03: 'Training',
    0x04: 'Connected',
    0x05: 'Fail',
    0x06: 'Test Mode',
    0x07: 'Loopback Mode',
    0x08: 'Low Power Mode',
    0x09: 'Connected Wake-On-LAN Mode',
    0x0A: 'System Calibrating',
    0x0B: 'Cable Disconnected',
}

MAP_COUNTERS_AND_REGISTERS_MSM = {
    'MSM SIF Tx Good Frame Counter': [0x1e, 0x6040, 0x1e, 0x6041],
    'MSM SIF Rx Good Frame Counter': [0x1e, 0x6044, 0x1e, 0x6045],

    'MSM SIF Rx FCS Error Counter': [0x1e, 0x6048, 0x1e, 0x6049],
    'MSM SIF Alignment Error Counter': [0x1e, 0x604C, 0x1e, 0x604D],

    'MSM SIF Tx Pause Frame Counter': [0x1e, 0x6050, 0x1e, 0x6051],
    'MSM SIF Rx Pause Frame Counter': [0x1e, 0x6054, 0x1e, 0x6055],

    'MSM SIF Tx Error Counter': [0x1e, 0x607C, 0x1e, 0x607D],
    'MSM SIF Rx Error Counter': [0x1e, 0x60C8, 0x1e, 0x60C9],

    'MSM LINE Tx Good Frame Counter': [0x1e, 0x9040, 0x1e, 0x9041],
    'MSM LINE Rx Good Frame Counter': [0x1e, 0x9044, 0x1e, 0x9045],

    'MSM LINE Rx FCS Error Counter': [0x1e, 0x9048, 0x1e, 0x9049],
    'MSM LINE Rx Alignment Error Counter': [0x1e, 0x904c, 0x1e, 0x904d],

    'MSM LINE Tx Pause Frame Counter': [0x1e, 0x9050, 0x1e, 0x9051],
    'MSM LINE Rx Pause Frame Counter': [0x1e, 0x9054, 0x1e, 0x9055],

    'MSM LINE Tx Error Counter': [0x1e, 0x907C, 0x1e, 0x907D],
    'MSM LINE Rx Error Counter': [0x1e, 0x90C8, 0x1e, 0x90C9],
}

MAP_COUNTERS_AND_REGISTERS_PCS = {
    'Good Frame Counter(10G TPL)': [0x3, 0xC820, 0x3, 0xC821],
    'Bad Frame Counter(10G TPL)': [0x3, 0xC822, 0x3, 0xC823],
    'Good Fragment Counter(10G TPL)': [0x3, 0xC824, 0x3, 0xC825],
    'Bad Fragment Counter(10G TPL)': [0x3, 0xC826, 0x3, 0xC827],

    'Good Frame Counter(TKL0)': [0x3, 0xC860, 0x3, 0xC861],
    'Bad Frame Counter(TKL0)': [0x3, 0xC862, 0x3, 0xC863],
    'Good Fragment Counter(TKL0)': [0x3, 0xC876, 0x3, 0xC877],
    'Bad Fragment Counter(TKL0)': [0x3, 0xC878, 0x3, 0xC879],

    'Good Frame Counter(XGS SGMII SYS TX)': [0x3, 0xC895, 0x3, 0xC896],
    'Good Frame Counter(XGS SGMII NET TX)': [0x3, 0xC897, 0x3, 0xC898],
    'Bad Frame Counter(XGS SGMII SYS TX)': [0x3, 0xC899, 0x3, 0xC89A],
    'Bad Frame Counter(XGS SGMII NET TX)': [0x3, 0xC89B, 0x3, 0xC89C],

    'Fragment Alignment Counter(XGS SGMII SYS TX)': [0x3, 0xC89D, 0x3, 0xC89E],

    'Good Frame Counter(XGS SGMII SYS RX)': [0x3, 0xC8A9, 0x3, 0xC8AA],
    'Good Frame Counter(XGS SGMII NET RX)': [0x3, 0xC8AB, 0x3, 0xC8AC],
    'Bad Frame Counter(XGS SGMII SYS RX)': [0x3, 0xC8AD, 0x3, 0xC8AE],
    'Bad Frame Counter(XGS SGMII NET RX)': [0x3, 0xC8AF, 0x3, 0xC8B0],

    'Frame FCS Error Counter(USX0 TX)': [0x3, 0xC8C8, 0x3, 0xC8C9],
    'Frame No CRC Error Counter(USX0 TX)': [0x3, 0xC8CA, 0x3, 0xC8CB],
    'Frame No FCS Error Counter(USX0 TX)': [0x3, 0xC8CC, 0x3, 0xC8CD],
    'Frame CRC Error Counter(USX0 TX)': [0x3, 0xC8CE, 0x3, 0xC8CF],

    'Frame FCS Error Counter(USX0 RX)': [0x3, 0xC8D8, 0x3, 0xC8D9],
    'Frame No CRC Error Counter(USX0 RX)': [0x3, 0xC8DA, 0x3, 0xC8DB],
    'Frame No FCS Error Counter(USX0 RX)': [0x3, 0xC8DC, 0x3, 0xC8DD],
    'Frame CRC Error Counter(USX0 RX)': [0x3, 0xC8DE, 0x3, 0xC8DF],

    'Express Frame FCS Error Counter(USX0 TX)': [0x3, 0xC8E0, 0x3, 0xC8E1],
    'No Express Frame FCS Error Counter(USX0 TX)': [0x3, 0xC8E2, 0x3, 0xC8E3],
    'Pre-emptable Frame FCS Error Counter(USX0 TX)': [0x3, 0xC8E4, 0x3, 0xC8E5],
    'No Pre-emptable Frame FCS Error Counter(USX0 TX)': [0x3, 0xC8E6, 0x3, 0xC8E7],

    'Express Frame FCS Error Counter(USX0 RX)': [0x3, 0xC8E8, 0x3, 0xC8E9],
    'No Express Frame FCS Error Counter(USX0 RX)': [0x3, 0xC8EA, 0x3, 0xC8EB],
    'Pre-emptable Frame FCS Error Counter(USX0 RX)': [0x3, 0xC8EC, 0x3, 0xC8ED],
    'No Pre-emptable Frame FCS Error Counter(USX0 RX)': [0x3, 0xC8EE, 0x3, 0xC8EF],

    'Good Frame Counter(10G RPL)': [0x3, 0xE812, 0x3, 0xE813],
    'Bad Frame Counter(10G RPL)': [0x3, 0xE814, 0x3, 0xE815],
    'Good Fragment Counter(10G RPL)': [0x3, 0xE82C, 0x3, 0xE82D],
    'Bad Fragment Counter(10G RPL)': [0x3, 0xE82E, 0x3, 0xE82F],

    'Good Frame Counter(RKL0)': [0x3, 0xE860, 0x3, 0xE861],
    'Bad Frame Counter(RKL0)': [0x3, 0xE862, 0x3, 0xE863],
    'Good Fragment Counter(RKL0)': [0x3, 0xE890, 0x3, 0xE891],
    'Bad Fragment Counter(RKL0)': [0x3, 0xE892, 0x3, 0xE893],

    'TSI SGMII RX Good Frame': [0x1D, 0xD292, 0x1D, 0xD293],
    'TSI SGMII RX Bad Frame': [0x1D, 0xD294, 0x1D, 0xD295],
    'TSI SGMII RX Good Fragment': [0x1D, 0xD2A0, 0x1D, 0xD2A1],
    'TSI SGMII RX Bad Fragment': [0x1D, 0xD2A2, 0x1D, 0xD2A3],

    'RSI SGMII TX Good Frame': [0x1D, 0xD313, 0x1D, 0xD314],
    'RSI SGMII TX Bad Frame': [0x1D, 0xD315, 0x1D, 0xD316],
    'RSI SGMII TX Good Fragment': [0x1D, 0xD320, 0x1D, 0xD321],
    'RSI SGMII TX Bad Fragment': [0x1D, 0xD322, 0x1D, 0xD323],

    'XTP RX Good Frame': [0x04, 0xD817, 0x04, 0xD818],
    'XTP RX Bad Frame': [0x04, 0xD815, 0x04, 0xD816],
}

MAP_SERDES_MODE = {0: MII_MODE_XFI, 3: MII_MODE_SGMII, 4: MII_MODE_OCSGMII, 6: MII_MODE_XFI_DIV2}

LOW_POWER = 'low_power'
NORMAL_POWER = 'normal_power'

RHEA = 'rhea'
CALYPSO = 'calypso'
EUROPA = 'europa'
ANTIGUA = 'antigua'
UNKNOWN = 'unknown'

ALL_PHY_ARCH = [EUROPA, CALYPSO, RHEA, ANTIGUA]

log = get_atf_logger()


class PHY:
    def __init__(self, port=None, host=None, phy_control=None, arch=UNKNOWN):
        if arch == UNKNOWN:
            arch = RHEA
        assert arch in ALL_PHY_ARCH
        self.arch = arch

        self.phy_control = phy_control
        if self.phy_control is not None:
            self.MAP_SPEED_TO_RMAP_OBJECT = {
                LINK_SPEED_100M: self.phy_control.rmap.glb.GlobalSystemConfigurationFor100M(),
                LINK_SPEED_1G: self.phy_control.rmap.glb.GlobalSystemConfigurationFor1G(),
                LINK_SPEED_2_5G: self.phy_control.rmap.glb.GlobalSystemConfigurationFor_2_5g(),
                LINK_SPEED_5G: self.phy_control.rmap.glb.GlobalSystemConfigurationFor_5g(),
                LINK_SPEED_10G: self.phy_control.rmap.glb.GlobalSystemConfigurationFor10G()
            }
        if self.phy_control is None:
            self.host = host
            self.atltool = AtlTool(port=port, host=host, silent=True)
        self.tg = {'mode': 0x0, 'source': 'sif'}

    def get_status(self):
        data = {
            'name': self.get_name(),
            'link': self.get_link_speed(),
        }

        speed = data['link']
        if speed != LINK_SPEED_NO_LINK:
            data['mii'] = self.get_mii(speed)
            data['macsec'] = self.get_security_bit_state(speed)
            data['fc egress processing'] = self.get_fc_egress_processing_state()
            data['fc egress generation'] = self.get_fc_egress_generation_state()
            data['fc ingress processing'] = self.get_fc_ingress_processing_state()
            data['fc ingress generation'] = self.get_fc_ingress_generation_state()

        status = '\n'
        for k in sorted(data.keys()):
            status += '{:>50s}: {}\n'.format(k, data[k])
        return status

    def read_chip_id(self):
        if self.phy_control is None:
            chip_id = Register(self.atltool.readphyreg(0x1e, 0x0021))
        else:
            reg = self.phy_control.rmap.glb.GlobalChipIdentification().chipIdentification
            chip_id = Register(reg.readValue(self.phy_control))
        return chip_id[0:0xf]

    def is_rhea(self):
        return True if self.read_chip_id() == 0x113c else False

    def is_calypso(self):
        return True if self.read_chip_id() in [0x111c, 0x111e] else False

    def is_europa(self):
        return True if self.read_chip_id() in [0x107, 0xc107] else False

    def is_antigua(self):
        return True if self.read_chip_id() in [0x0] else False  # FIXME:

    def set_advertise(self, speeds=[]):
        if self.phy_control is None:
            adv = Register(self.atltool.readphyreg(0x7, 0x0020))
            adv[0xC] = 0  # 10G
            adv[0x8] = 0  # 5G EUR-B0 only
            adv[0x7] = 0  # 2.5G EUR-B0 only
            self.atltool.writephyreg(0x7, 0x0020, adv.get())

            adv = Register(self.atltool.readphyreg(0x7, 0xC400))
            adv[0xF] = 0  # 1G Full-duplex
            adv[0xE] = 0  # 1G Half-duplex
            adv[0xB] = 0  # 5GN
            adv[0xA] = 0  # 2.5GN
            self.atltool.writephyreg(0x7, 0xC400, adv.get())

            adv = Register(self.atltool.readphyreg(0x7, 0x0010))
            adv[0x8] = 0  # 100M Full-Duplex
            adv[0x7] = 0  # 100M
            adv[0x6] = 0  # 10M Full-Duplex
            adv[0x5] = 0  # 10M
            self.atltool.writephyreg(0x7, 0x0010, adv.get())

            for speed in speeds:
                if speed == LINK_SPEED_10M:
                    adv = Register(self.atltool.readphyreg(0x7, 0x0010))
                    adv[0x6] = 1  # 10M Full-Duplex
                    adv[0x5] = 1  # 10M
                    self.atltool.writephyreg(0x7, 0x0010, adv.get())
                elif speed == LINK_SPEED_100M:
                    adv = Register(self.atltool.readphyreg(0x7, 0x0010))
                    adv[0x8] = 1  # 100M Full-Duplex
                    adv[0x7] = 1  # 100M
                    self.atltool.writephyreg(0x7, 0x0010, adv.get())
                elif speed == LINK_SPEED_1G:
                    adv = Register(self.atltool.readphyreg(0x7, 0xC400))
                    adv[0xF] = 1  # 1G Full-duplex
                    adv[0xE] = 1  # 1G Half-duplex
                    self.atltool.writephyreg(0x7, 0xC400, adv.get())
                elif speed == LINK_SPEED_2_5G:
                    adv = Register(self.atltool.readphyreg(0x7, 0xC400))
                    adv[0xA] = 1  # 2.5GN
                    self.atltool.writephyreg(0x7, 0xC400, adv.get())
                    adv = Register(self.atltool.readphyreg(0x7, 0x0020))
                    adv[0x7] = 1  # 2.5G EUR-B0 only
                    self.atltool.writephyreg(0x7, 0x0020, adv.get())
                elif speed == LINK_SPEED_5G:
                    adv = Register(self.atltool.readphyreg(0x7, 0xC400))
                    adv[0xB] = 1  # 5GN
                    self.atltool.writephyreg(0x7, 0xC400, adv.get())
                    adv = Register(self.atltool.readphyreg(0x7, 0x0020))
                    adv[0x8] = 1  # 5G EUR-B0 only
                    self.atltool.writephyreg(0x7, 0x0020, adv.get())
                elif speed == LINK_SPEED_10G:
                    adv = Register(self.atltool.readphyreg(0x7, 0x0020))
                    adv[0xC] = 1  # 10G
                    self.atltool.writephyreg(0x7, 0x0020, adv.get())
        else:
            raise NotImplementedError()

    def get_name(self):
        name = str(hex(self.read_chip_id()))
        name = RHEA if self.is_rhea() else name
        name = CALYPSO if self.is_calypso() else name
        name = EUROPA if self.is_europa() else name
        name = ANTIGUA if self.is_antigua() else name
        return name

    def __wait_processing_operation(self, reg0, reg1, bit, value, timeout_in_sec=30):
        is_completed = False
        for _ in range(timeout_in_sec * 100):
            reg = Register(self.atltool.readphyreg(reg0, reg1))
            if reg[bit] == value:
                is_completed = True
                break
            else:
                time.sleep(0.01)
        return is_completed

    def __wait_clear_bit(self, reg0, reg1, bit, timeout_in_sec=30):
        return self.__wait_processing_operation(reg0, reg1, bit, 0, timeout_in_sec)

    def __wait_set_bit(self, reg0, reg1, bit, timeout_in_sec=30):
        return self.__wait_processing_operation(reg0, reg1, bit, 1, timeout_in_sec)

    def wait_link_up(self):
        is_completed = self.__wait_clear_bit(0x1E, 0xC831, 0xF)
        assert is_completed, 'Autonegotiation is not completed'

        is_completed = self.__wait_set_bit(0x7, 0x1, 0x5) and self.__wait_set_bit(0x7, 0xE000, 0x2)
        if not is_completed:
            reg = Register(self.atltool.readphyreg(0x7, 0xC810))
            current_state = MAP_CONNECTION_STATE[reg[0x9:0xD]]
        assert is_completed, 'TIMEOUT (30 secs). Link was not up. Current state: {}'.format(current_state)

    def restart_autoneg(self):
        if self.phy_control is None:
            autoneg = Register(self.atltool.readphyreg(0x7, 0x0))
            autoneg[9] = 1
            self.atltool.writephyreg(0x7, 0x0, autoneg.get())
        else:
            # touch autoneg register 07.0000.9 -> 1
            self.phy_control.rmap.ang.AutonegotiationStandardControl_1().restartAutonegotiation.rmw(self.phy_control, 1)
            start = timeit.default_timer()

            correct_flag = False
            for _ in range(1000):
                value = self.phy_control.rmap.ang.AutonegotiationStandardStatus_1().linkStatus.readValue(self.phy_control)
                if value == 0:
                    correct_flag = True
                    break

            link_down_time = int(1000 * (timeit.default_timer() - start)) if correct_flag else -1

            # wait PHY link up 07.0001.2 == 1 - link is up; 0 - no link
            correct_flag = False
            for _ in range(10000):
                time.sleep(0.001)
                value = self.phy_control.rmap.ang.AutonegotiationStandardStatus_1().linkStatus.readValue(self.phy_control)
                if value == 1:
                    correct_flag = True
                    break

            link_up_time = int(1000 * (timeit.default_timer() - start)) if correct_flag else -1

            return link_down_time, link_up_time

    def get_mii(self, speed):
        assert speed in ALL_LINK_SPEEDS

        if self.phy_control is None:
            reg = MAP_SPEED_TO_PHY_REG[speed]
            sec_reg = Register(self.atltool.readphyreg(0x1E, reg))

            if sec_reg[7:8] == 1:
                return MII_MODE_USX
            else:
                return MAP_SERDES_MODE[sec_reg[0:2]]
        else:
            reg = self.MAP_SPEED_TO_RMAP_OBJECT[speed]

            if reg.rateAdaptationMethod.readValue(self.phy_control) == 1:
                return MII_MODE_USX
            else:
                val = reg.serdesMode.readValue(self.phy_control)
                return MAP_SERDES_MODE[val]

    def set_mode(self, speed, mode, rate=RATE_ADAPTATION_UNKNOW):
        assert speed in ALL_LINK_SPEEDS
        assert mode in [MII_MODE_XFI, MII_MODE_XFI_SGMII, MII_MODE_XFI_DIV2, MII_MODE_OCSGMII, MII_MODE_USX, MII_MODE_SGMII]

        value = {
            MII_MODE_XFI: 0x0,
            MII_MODE_XFI_DIV2: 0x6,
            MII_MODE_OCSGMII: 0x4,
            MII_MODE_SGMII: 0x3,
            MII_MODE_USX: 0x0
        }[mode]

        r = 0x0
        r = 0x1 if rate == RATE_ADAPTATION_USX else r
        r = 0x2 if rate == RATE_ADAPTATION_PAUSE else r

        if self.phy_control is None:
            reg = MAP_SPEED_TO_PHY_REG[speed]

            sec_reg = Register(self.atltool.readphyreg(0x1E, reg))
            sec_reg[0:2] = value

            if rate != RATE_ADAPTATION_UNKNOW:
                sec_reg[7:8] = r

            self.atltool.writephyreg(0x1E, reg, sec_reg.get())
        else:
            sec = self.MAP_SPEED_TO_RMAP_OBJECT[speed]

            sec.serdesMode.rmw(self.phy_control, value)

            if rate != RATE_ADAPTATION_UNKNOW:
                sec.rateAdaptationMethod.rmw(self.phy_control, r)

    def set_security_bit(self, speed, state):
        assert state in [ENABLE, DISABLE]
        assert speed in ALL_LINK_SPEEDS

        st = 0x1 if state == ENABLE else 0x0
        if self.phy_control is None:
            reg = MAP_SPEED_TO_PHY_REG[speed]

            sec_reg = Register(self.atltool.readphyreg(0x1E, reg))
            sec_reg[9] = st
            self.atltool.writephyreg(0x1E, reg, sec_reg.get())

        else:
            sec = self.MAP_SPEED_TO_RMAP_OBJECT[speed].securityEnable

            sec.rmw(self.phy_control, st)
            time.sleep(1)

            log.info("GlobalSystemConfigurationFor100M: {}".format(sec.readValue(self.phy_control)))

    def get_security_bit_state(self, speed):
        assert speed in ALL_LINK_SPEEDS

        if self.phy_control is None:
            reg = MAP_SPEED_TO_PHY_REG[speed]

            sec_reg = Register(self.atltool.readphyreg(0x1E, reg))
            state = sec_reg[9]
        else:
            sec = self.MAP_SPEED_TO_RMAP_OBJECT[speed].securityEnable
            state = sec.readValue(self.phy_control)

        return ENABLE if state == 0x1 else DISABLE

    def set_bypass_all_sec_block(self, direction, value):
        st = 0x1 if value == ENABLE else 0x0
        if self.phy_control is None:
            reg = 0x4000 if direction == EGRESS else 0x7000
            sec_reg = Register(self.atltool.readphyreg(0x1E, reg))
            sec_reg[0xC] = st
            self.atltool.writephyreg(0x1E, reg, sec_reg.get())
        else:
            if direction == INGRESS:
                bypass_value = self.phy_control.rmap.secing.SecIngressControlRegister_1().secIngressBypassEnable
            elif direction == EGRESS:
                bypass_value = self.phy_control.rmap.seceg.SecEgressControlRegister_1().secEgressBypassEnable
            bypass_value.rmw(self.phy_control, st)

    def get_bypass_all_sec_block(self, direction):
        if self.phy_control is None:
            reg = 0x4000 if direction == EGRESS else 0x7000
            sec_reg = Register(self.atltool.readphyreg(0x1E, reg))
            return ENABLE if sec_reg[0xC] == 1 else DISABLE
        else:
            if direction == INGRESS:
                bypass_value = self.phy_control.rmap.secing.SecIngressControlRegister_1().secIngressBypassEnable
            elif direction == EGRESS:
                bypass_value = self.phy_control.rmap.seceg.SecEgressControlRegister_1().secEgressBypassEnable
            return ENABLE if bypass_value.readValue(self.phy_control) == 1 else DISABLE

    def get_fc_ingress_processing_state(self):
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1E, 0x7140))
            state = reg[0]
        else:
            pp = self.phy_control.rmap.secing.SecIngressPauseControlRegister_1().secIngressPauseProcessingDisable
            state = pp.readValue(self.phy_control)

        return DISABLE if state == 0x1 else ENABLE

    def get_fc_ingress_generation_state(self):
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1E, 0x7149))
            state = reg[6]
        else:
            pg = self.phy_control.rmap.secing.SecIngressPauseControlRegister_10().secIngressPauseFrameDisable
            state = pg.readValue(self.phy_control)

        return DISABLE if state == 0x1 else ENABLE

    def set_fc_ingress_processing(self, state):
        assert state in [ENABLE, DISABLE]

        st = 0x0 if state == ENABLE else 0x1
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1E, 0x7140))
            reg[0] = st
            self.atltool.writephyreg(0x1E, 0x7140, reg.get())
        else:
            pp = self.phy_control.rmap.secing.SecIngressPauseControlRegister_1().secIngressPauseProcessingDisable
            pp.rmw(self.phy_control, st)

    def set_fc_ingress_generation(self, state):
        assert state in [ENABLE, DISABLE]

        st = 0x0 if state == ENABLE else 0x1
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1E, 0x7149))
            reg[6] = st
            self.atltool.writephyreg(0x1E, 0x7149, reg.get())
        else:
            pg = self.phy_control.rmap.secing.SecIngressPauseControlRegister_10().secIngressPauseFrameDisable
            pg.rmw(self.phy_control, st)

    def get_fc_egress_processing_state(self):
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1E, 0x4140))
            state = reg[0]
        else:
            pp = self.phy_control.rmap.seceg.SecEgressPauseControlRegister_1().secEgressPauseProcessingDisable
            state = pp.readValue(self.phy_control)

        return DISABLE if state == 0x1 else ENABLE

    def get_fc_egress_generation_state(self):
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1E, 0x4149))
            state = reg[6]
        else:
            pg = self.phy_control.rmap.seceg.SecEgressPauseControlRegister_10().secEgressPauseFrameDisable
            state = pg.readValue(self.phy_control)

        return DISABLE if state == 0x1 else ENABLE

    def set_fc_egress_processing(self, state):
        assert state in [ENABLE, DISABLE]

        st = 0x0 if state == ENABLE else 0x1
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1E, 0x4140))
            reg[0] = st
            self.atltool.writephyreg(0x1E, 0x4140, reg.get())
        else:
            pp = self.phy_control.rmap.seceg.SecEgressPauseControlRegister_1().secEgressPauseProcessingDisable
            pp.rmw(self.phy_control, st)

    def set_fc_egress_generation(self, state):
        assert state in [ENABLE, DISABLE]

        st = 0x0 if state == ENABLE else 0x1
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1E, 0x4149))
            reg[6] = st
            self.atltool.writephyreg(0x1E, 0x4149, reg.get())
        else:
            pg = self.phy_control.rmap.seceg.SecEgressPauseControlRegister_10().secEgressPauseFrameDisable
            pg.rmw(self.phy_control, st)

    def set_fc_processing(self, state):
        self.set_fc_egress_processing(state=state)
        self.set_fc_ingress_processing(state=state)

    def set_fc_generation(self, state):
        self.set_fc_egress_generation(state=state)
        self.set_fc_ingress_generation(state=state)

    def set_flow_control(self, state=DISABLE):
        self.set_fc_generation(state=state)
        self.set_fc_processing(state=state)

    def set_fifo_threshold(self, direction, xon=None, xoff=None):
        assert direction in [INGRESS, EGRESS]

        if self.phy_control is None:
            if direction == INGRESS:
                if xon is not None:
                    self.atltool.writephyreg(0x1E, 0x7008, xon)
                if xoff is not None:
                    self.atltool.writephyreg(0x1E, 0x7006, xoff)
            elif direction == EGRESS:
                if xon is not None:
                    self.atltool.writephyreg(0x1E, 0x4008, xon)
                if xoff is not None:
                    self.atltool.writephyreg(0x1E, 0x4006, xoff)
        else:
            if direction == INGRESS:
                if xon is not None:
                    t = self.phy_control.rmap.secing.SecIngressXoffControlRegister_3().secIngressXonFifoThreshold
                    t.rmw(self.phy_control, xon)
                if xoff is not None:
                    t = self.phy_control.rmap.secing.SecIngressXoffControlRegister_1().secIngressXoffFifoThreshold
                    t.rmw(self.phy_control, xoff)
            elif direction == EGRESS:
                if xon is not None:
                    t = self.phy_control.rmap.seceg.SecEgressXoffControlRegister_3().secEgressXonFifoThreshold
                    t.rmw(self.phy_control, xon)
                if xoff is not None:
                    t = self.phy_control.rmap.seceg.SecEgressXoffControlRegister_1().secEgressXoffFifoThreshold
                    t.rmw(self.phy_control, xoff)

    def get_fifo_level(self, direction):
        assert direction in [EGRESS, INGRESS]

        if self.phy_control is None:
            reg = {EGRESS: 0x4009, INGRESS: 0x7009}[direction]
            return self.atltool.readphyreg(0x1E, reg)
        else:
            if direction == EGRESS:
                fifo = self.phy_control.rmap.seceg.SecEgressFcFifoStatusRegister().secEgressFcFifoLevel
            elif direction == INGRESS:
                fifo = self.phy_control.rmap.secing.SecIngressFcFifoStatusRegister().secIngressFcFifoLevel
            else:
                raise Exception('Unsupported direction')
            return fifo.readValue(self.phy_control)

    def get_counters_pause_frames(self):
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1, 0x4020))
            reg[16:31] = self.atltool.readphyreg(0x1, 0x4021)
            egress = reg.get()

            reg = Register(self.atltool.readphyreg(0x1, 0x7020))
            reg[16:31] = self.atltool.readphyreg(0x1, 0x7021)
            ingress = reg.get()
        else:
            reg = Register(self.phy_control.rmap.secing.SecIngressLinkPauseFrameCounterRegister_1().secIngressLinkPauseFrameCounterLSW.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.secing.SecIngressLinkPauseFrameCounterRegister_2().secIngressLinkPauseFrameCounterMSW.readValue(self.phy_control)
            ingress = reg.get()

            reg = Register(self.phy_control.rmap.seceg.SecEgressLinkPauseFrameCounterRegister_1().secEgressLinkPauseFrameCounterLSW.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.seceg.SecEgressLinkPauseFrameCounterRegister_2().secEgressLinkPauseFrameCounterMSW.readValue(self.phy_control)
            egress = reg.get()

        return ingress, egress

    def get_counters_msm(self):
        if self.phy_control is None:
            d = {}
            for k in MAP_COUNTERS_AND_REGISTERS_MSM.keys():
                regs = MAP_COUNTERS_AND_REGISTERS_MSM[k]
                reg = Register(self.atltool.readphyreg(regs[0], regs[1]))
                reg[16:31] = self.atltool.readphyreg(regs[2], regs[3])
                d[k] = reg.get()
        else:
            d = {}

            reg = Register(self.phy_control.rmap.msmsys.MsmSystemTxGoodFramesCounterRegister_1().msmSystemTxGoodFramesCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmsys.MsmSystemTxGoodFramesCounterRegister_2().msmSystemTxGoodFramesCounter_1.readValue(self.phy_control)
            d['MSM SIF Tx Good Frame Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmsys.MsmSystemRxGoodFramesCounterRegister_1().msmSystemRxGoodFramesCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmsys.MsmSystemRxGoodFramesCounterRegister_2().msmSystemRxGoodFramesCounter_1.readValue(self.phy_control)
            d['MSM SIF Rx Good Frame Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmsys.MsmSystemRxFcsErrorsCounterRegister_1().msmSystemFcsErrorCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmsys.MsmSystemRxFcsErrorsCounterRegister_2().msmSystemFcsErrorCounter_1.readValue(self.phy_control)
            d['MSM SIF Rx FCS Error Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmsys.MsmSystemRxAlignmentErrorsCounterRegister_1().msmSystemAlignmentErrorCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmsys.MsmSystemRxAlignmentErrorsCounterRegister_2().msmSystemAlignmentErrorCounter_1.readValue(self.phy_control)
            d['MSM SIF Alignment Error Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmsys.MsmSystemTxPauseFramesCounterRegister_1().msmSystemTxPauseFramesCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmsys.MsmSystemTxPauseFramesCounterRegister_2().msmSystemTxPauseFramesCounter_1.readValue(self.phy_control)
            d['MSM SIF Tx Pause Frame Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmsys.MsmSystemRxPauseFramesCounterRegister_1().msmSystemRxPauseFramesCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmsys.MsmSystemRxPauseFramesCounterRegister_2().msmSystemRxPauseFramesCounter_1.readValue(self.phy_control)
            d['MSM SIF Rx Pause Frame Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmsys.MsmSystemRxErrorsCounterRegister_1().msmSystemRxErrorsCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmsys.MsmSystemRxErrorsCounterRegister_2().msmSystemRxErrorsCounter_1.readValue(self.phy_control)
            d['MSM SIF Rx Error Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmsys.MsmSystemTxErrorsCounterRegister_1().msmSystemTxErrorsCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmsys.MsmSystemTxErrorsCounterRegister_2().msmSystemTxErrorsCounter_1.readValue(self.phy_control)
            d['MSM SIF Tx Error Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmline.MsmLineTxGoodFramesCounterRegister_1().msmLineTxGoodFramesCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmline.MsmLineTxGoodFramesCounterRegister_2().msmLineTxGoodFramesCounter_1.readValue(self.phy_control)
            d['MSM LINE Tx Good Frame Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmline.MsmLineRxGoodFramesCounterRegister_1().msmLineRxGoodFramesCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmline.MsmLineRxGoodFramesCounterRegister_2().msmLineRxGoodFramesCounter_1.readValue(self.phy_control)
            d['MSM LINE Rx Good Frame Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmline.MsmLineRxFcsErrorsCounterRegister_1().msmLineFcsErrorCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmline.MsmLineRxFcsErrorsCounterRegister_2().msmLineFcsErrorCounter_1.readValue(self.phy_control)
            d['MSM LINE Rx FCS Error Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmline.MsmLineRxAlignmentErrorsCounterRegister_1().msmLineAlignmentErrorCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmline.MsmLineRxAlignmentErrorsCounterRegister_2().msmLineAlignmentErrorCounter_1.readValue(self.phy_control)
            d['MSM LINE Rx Alignment Error Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmline.MsmLineTxPauseFramesCounterRegister_1().msmLineTxPauseFramesCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmline.MsmLineTxPauseFramesCounterRegister_2().msmLineTxPauseFramesCounter_1.readValue(self.phy_control)
            d['MSM LINE Tx Pause Frame Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmline.MsmLineRxPauseFramesCounterRegister_1().msmLineRxPauseFramesCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmline.MsmLineRxPauseFramesCounterRegister_2().msmLineRxPauseFramesCounter_1.readValue(self.phy_control)
            d['MSM LINE Rx Pause Frame Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmline.MsmLineTxErrorsCounterRegister_1().msmLineTxErrorsCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmline.MsmLineTxErrorsCounterRegister_2().msmLineTxErrorsCounter_1.readValue(self.phy_control)
            d['MSM LINE Tx Error Counter'] = reg.get()

            reg = Register(self.phy_control.rmap.msmline.MsmLineRxErrorsCounterRegister_1().msmLineRxErrorsCounter_0.readValue(self.phy_control))
            reg[16:31] = self.phy_control.rmap.msmline.MsmLineRxErrorsCounterRegister_2().msmLineRxErrorsCounter_1.readValue(self.phy_control)
            d['MSM LINE Rx Error Counter'] = reg.get()

        return d

    def get_counters_pcs(self):
        if self.phy_control is None:
            d = {}
            for k in MAP_COUNTERS_AND_REGISTERS_PCS.keys():
                regs = MAP_COUNTERS_AND_REGISTERS_PCS[k]
                reg = Register(self.atltool.readphyreg(regs[0], regs[1]))
                reg[16:31] = self.atltool.readphyreg(regs[2], regs[3])
                d[k] = reg.get()
        else:
            d = {}

            """
            'Fragment Alignment Counter(XGS SGMII SYS TX)': [0x3, 0xC89D, 0x3, 0xC89E],

            'Frame FCS Error Counter(USX0 TX)': [0x3, 0xC8C8, 0x3, 0xC8C9],
            'Frame No CRC Error Counter(USX0 TX)': [0x3, 0xC8CA, 0x3, 0xC8CB],
            'Frame No FCS Error Counter(USX0 TX)': [0x3, 0xC8CC, 0x3, 0xC8CD],
            'Frame CRC Error Counter(USX0 TX)': [0x3, 0xC8CE, 0x3, 0xC8CF],

            'Frame FCS Error Counter(USX0 RX)': [0x3, 0xC8D8, 0x3, 0xC8D9],
            'Frame No CRC Error Counter(USX0 RX)': [0x3, 0xC8DA, 0x3, 0xC8DB],
            'Frame No FCS Error Counter(USX0 RX)': [0x3, 0xC8DC, 0x3, 0xC8DD],
            'Frame CRC Error Counter(USX0 RX)': [0x3, 0xC8DE, 0x3, 0xC8DF],

            'Express Frame FCS Error Counter(USX0 TX)': [0x3, 0xC8E0, 0x3, 0xC8E1],
            'No Express Frame FCS Error Counter(USX0 TX)': [0x3, 0xC8E2, 0x3, 0xC8E3],
            'Pre-emptable Frame FCS Error Counter(USX0 TX)': [0x3, 0xC8E4, 0x3, 0xC8E5],
            'No Pre-emptable Frame FCS Error Counter(USX0 TX)': [0x3, 0xC8E6, 0x3, 0xC8E7],

            'Express Frame FCS Error Counter(USX0 RX)': [0x3, 0xC8E8, 0x3, 0xC8E9],
            'No Express Frame FCS Error Counter(USX0 RX)': [0x3, 0xC8EA, 0x3, 0xC8EB],
            'Pre-emptable Frame FCS Error Counter(USX0 RX)': [0x3, 0xC8EC, 0x3, 0xC8ED],
            'No Pre-emptable Frame FCS Error Counter(USX0 RX)': [0x3, 0xC8EE, 0x3, 0xC8EF],

            """

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_1().tkl0FrameCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_2().tkl0FrameCounterMSW.readValue(self.phy_control)
                d['Good Frame Counter(10G TPL)'] = reg.get()
            except AttributeError as e:
                pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_3().tkl0FrameErrorCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_4().tkl0FrameErrorCounterMSW.readValue(self.phy_control)
                d['Bad Frame Counter(10G TPL)'] = reg.get()
            except AttributeError as e:
                pass

            if self.is_rhea():
                try:
                    reg = Register(self.phy_control.rmap.pcs.PcsTransmitVendorMcrcNoErrorFrameCounter_1().tplMcrcNoErrorFrameCounterLSW.readValue(self.phy_control))
                    reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitVendorMcrcNoErrorFrameCounter_2().tplMcrcNoErrorFrameCounterMSW.readValue(self.phy_control)
                    d['Good Fragment Counter(10G TPL)'] = reg.get()
                except AttributeError as e:
                    pass

                try:
                    reg = Register(self.phy_control.rmap.pcs.PcsTransmitVendorMcrcErrorFrameCounter_1().tplMcrcErrorFrameCounterLSW.readValue(self.phy_control))
                    reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitVendorMcrcErrorFrameCounter_2().tplMcrcErrorFrameCounterMSW.readValue(self.phy_control)
                    d['Bad Fragment Counter(10G TPL)'] = reg.get()
                except AttributeError as e:
                    pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_1().tkl0FrameCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_2().tkl0FrameCounterMSW.readValue(self.phy_control)
                d['Good Frame Counter(TKL0)'] = reg.get()
            except AttributeError as e:
                pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_3().tkl0FrameErrorCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_4().tkl0FrameErrorCounterMSW.readValue(self.phy_control)
                d['Bad Frame Counter(TKL0)'] = reg.get()
            except AttributeError as e:
                pass

            if self.is_rhea():
                try:
                    reg = Register(self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_23().tkl0FragmentCounterLSW.readValue(self.phy_control))
                    reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_24().tkl0FragmentCounterMSW.readValue(self.phy_control)
                    d['Good Fragment Counter(TKL0)'] = reg.get()
                except AttributeError as e:
                    pass


                try:
                    reg = Register(self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_25().tkl0FragmentErrorCounterLSW.readValue(self.phy_control))
                    reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitTkl0VendorState_26().tkl0FragmentErrorCounterMSW.readValue(self.phy_control)
                    d['Bad Fragment Counter(TKL0)'] = reg.get()
                except AttributeError as e:
                    pass
            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_22().xgsSgmiiSystemTxFrameCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_23().xgsSgmiiSystemTxFrameCounterMSW.readValue(self.phy_control)
                d['Good Frame Counter(XGS SGMII SYS TX)'] = reg.get()
            except AttributeError as e:
                pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_24().xgsSgmiiNetworkTxFrameCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_25().xgsSgmiiNetworkTxFrameCounterMSW.readValue(self.phy_control)
                d['Good Frame Counter(XGS SGMII NET TX)'] = reg.get()
            except AttributeError as e:
                pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_26().xgsSgmiiSystemTxFrameErrorCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_27().xgsSgmiiSystemTxFrameErrorCounterMSW.readValue(self.phy_control)
                d['Bad Frame Counter(XGS SGMII SYS TX)'] = reg.get()
            except AttributeError as e:
                pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_28().xgsSgmiiNetworkTxFrameErrorCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_29().xgsSgmiiNetworkTxFrameErrorCounterMSW.readValue(self.phy_control)
                d['Bad Frame Counter(XGS SGMII NET TX)'] = reg.get()
            except AttributeError as e:
                pass


            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_42().xgsSgmiiSystemFrameCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_43().xgsSgmiiSystemFrameCounterMSW.readValue(self.phy_control)
                d['Good Frame Counter(XGS SGMII SYS RX)'] = reg.get()
            except AttributeError as e:
                pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_44().xgsSgmiiNetworkFrameCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_45().xgsSgmiiNetworkFrameCounterMSW.readValue(self.phy_control)
                d['Good Frame Counter(XGS SGMII NET RX)'] = reg.get()
            except AttributeError as e:
                pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_46().xgsSgmiiSystemFrameErrorCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_47().xgsSgmiiSystemFrameErrorCounterMSW.readValue(self.phy_control)
                d['Bad Frame Counter(XGS SGMII SYS RX)'] = reg.get()
            except AttributeError as e:
                pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_48().xgsSgmiiNetworkFrameErrorCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsTransmitXgsVendorState_49().xgsSgmiiNetworkFrameErrorCounterMSW.readValue(self.phy_control)
                d['Bad Frame Counter(XGS SGMII NET RX)'] = reg.get()
            except AttributeError as e:
                pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsReceiveVendorFcsNoErrorFrameCounter_1().rplFcsNoErrorFrameCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsReceiveVendorFcsNoErrorFrameCounter_2().rplFcsNoErrorFrameCounterMSW.readValue(self.phy_control)
                d['Good Frame Counter(10G RPL)'] = reg.get()
            except AttributeError as e:
                pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsReceiveVendorFcsErrorFrameCounter_1().rplFcsErrorFrameCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsReceiveVendorFcsErrorFrameCounter_2().rplFcsErrorFrameCounterMSW.readValue(self.phy_control)
                d['Bad Frame Counter(10G RPL)'] = reg.get()
            except AttributeError as e:
                pass

            if self.is_rhea():
                try:
                    reg = Register(self.phy_control.rmap.pcs.PcsReceiveVendorMcrcNoErrorFrameCounter_1().rplMcrcNoErrorFrameCounterLSW.readValue(self.phy_control))
                    reg[16:26] = self.phy_control.rmap.pcs.PcsReceiveVendorMcrcNoErrorFrameCounter_2().rplMcrcNoErrorFrameCounterMSW.readValue(self.phy_control)
                    d['Good Fragment Counter(10G RPL)'] = reg.get()
                except AttributeError as e:
                    pass

                try:
                    reg = Register(self.phy_control.rmap.pcs.PcsReceiveVendorMcrcErrorFrameCounter_1().rplMcrcErrorFrameCounterLSW.readValue(self.phy_control))
                    reg[16:26] = self.phy_control.rmap.pcs.PcsReceiveVendorMcrcErrorFrameCounter_2().rplMcrcErrorFrameCounterMSW.readValue(self.phy_control)
                    d['Bad Fragment Counter(10G RPL)'] = reg.get()
                except AttributeError as e:
                    pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsReceiveRkl0VendorState_1().rkl0GoodFrameCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsReceiveRkl0VendorState_2().rkl0GoodFrameCounterMSW.readValue(self.phy_control)
                d['Good Frame Counter(RKL0)'] = reg.get()
            except AttributeError as e:
                pass

            try:
                reg = Register(self.phy_control.rmap.pcs.PcsReceiveRkl0VendorState_3().rkl0BadFrameCounterLSW.readValue(self.phy_control))
                reg[16:26] = self.phy_control.rmap.pcs.PcsReceiveRkl0VendorState_4().rkl0BadFrameCounterMSW.readValue(self.phy_control)
                d['Bad Frame Counter(RKL0)'] = reg.get()
            except AttributeError as e:
                pass

            if self.is_rhea():
                try:
                    reg = Register(self.phy_control.rmap.pcs.PcsReceiveRkl0McrcState_1().rkl0FragmentCounterLSW.readValue(self.phy_control))
                    reg[16:26] = self.phy_control.rmap.pcs.PcsReceiveRkl0McrcState_2().rkl0FragmentCounterMSW.readValue(self.phy_control)
                    d['Good Fragment Counter(RKL0)'] = reg.get()
                except AttributeError as e:
                    pass

                try:
                    reg = Register(self.phy_control.rmap.pcs.PcsReceiveRkl0McrcState_3().rkl0FragmentErrorCounterLSW.readValue(self.phy_control))
                    reg[16:26] = self.phy_control.rmap.pcs.PcsReceiveRkl0McrcState_4().rkl0FragmentErrorCounterMSW.readValue(self.phy_control)
                    d['Bad Fragment Counter(RKL0)'] = reg.get()
                except AttributeError as e:
                    pass

        return d

    def set_loopback(self, speed, loopback):
        assert loopback in [NO_LOOPBACK, SYSTEM_INTERFACE_SYSTEM_LOOPBACK, SYSTEM_INTERFACE_NETWORK_LOOPBACK,
                            NETWORK_INTERFACE_SYSTEM_LOOPBACK, NETWORK_INTERFACE_NETWORK_LOOPBACK, SYSTEM_SIDE_SHALLOW_LOOPBACK,
                            LINE_SIDE_SHALLOW_LOOPBACK]
        assert speed in ALL_LINK_SPEEDS

        if self.phy_control is None:
            if loopback == LINE_SIDE_SHALLOW_LOOPBACK:
                secegresscontrolregister_1 = Register(self.atltool.readphyreg(0x1E, 0x4000))
                secegresscontrolregister_1[13] = 1
                self.atltool.writephyreg(0x1E, 0x4000, secegresscontrolregister_1.get())
            else:
                raise NotImplementedError()
        else:
            phy_loopback = self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_ReservedVendorProvisioning_5().loopbackControl
            phy_rate = self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_ReservedVendorProvisioning_5().rate

            TBL = {
                LINK_SPEED_100M: 0x01,
                LINK_SPEED_1G: 0x02,
                LINK_SPEED_10G: 0x03,
                LINK_SPEED_2_5G: 0x04,
                LINK_SPEED_5G: 0x05,
            }

            if loopback not in [SYSTEM_SIDE_SHALLOW_LOOPBACK, LINE_SIDE_SHALLOW_LOOPBACK]:
                st = {
                    NO_LOOPBACK: 0x00,
                    SYSTEM_INTERFACE_SYSTEM_LOOPBACK: 0x01,
                    SYSTEM_INTERFACE_NETWORK_LOOPBACK: 0x03,
                    NETWORK_INTERFACE_SYSTEM_LOOPBACK: 0x09,
                    NETWORK_INTERFACE_NETWORK_LOOPBACK: 0x0B,
                }[loopback]

            phy_rate.rmw(self.phy_control, TBL[speed])
            if loopback == SYSTEM_SIDE_SHALLOW_LOOPBACK:
                phy_loopback.rmw(self.phy_control, 0x00)
                time.sleep(1)
                # phy_shallow_loopback_egr = self.phy_control.rmap.seceg.SecEgressControlRegister_1().secEgressShallowLoopbackEnable
                phy_shallow_loopback_egr = self.phy_control.rmap.secing.SecIngressControlRegister_1().secIngressShallowLoopbackEnable
                phy_shallow_loopback_egr.rmw(self.phy_control, 0x1)
                time.sleep(1)
                log.info("secEgressShallowLoopbackEnable: {}".format(phy_shallow_loopback_egr.readValue(self.phy_control)))
            elif loopback == LINE_SIDE_SHALLOW_LOOPBACK:
                phy_loopback.rmw(self.phy_control, 0x00)
                time.sleep(1)
                # phy_shallow_loopback_ing = self.phy_control.rmap.secing.SecIngressControlRegister_1().secIngressShallowLoopbackEnable
                phy_shallow_loopback_ing = self.phy_control.rmap.seceg.SecEgressControlRegister_1().secEgressShallowLoopbackEnable
                phy_shallow_loopback_ing.rmw(self.phy_control, 0x1)
                time.sleep(1)
                log.info("secIngressShallowLoopbackEnable: {}".format(phy_shallow_loopback_ing.readValue(self.phy_control)))
            else:
                phy_loopback.rmw(self.phy_control, st)

    def set_power_mode(self, power_mode):
        assert self.is_antigua(), "Supported only Antigua"
        assert power_mode in [LOW_POWER, NORMAL_POWER]
        st = 0 if power_mode == NORMAL_POWER else 1

        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1E, 0x0000))
            reg[0xB] = st
            self.atltool.writephyreg(0x1E, 0x0000, reg.get())
        else:
            raise NotImplementedError()

    def run_cable_diagnostics(self):
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1E, 0xC470))
            reg[0:1] = 2  # set cable diagnostic baud (200M baud)
            reg[4] = 1  # init cable diagnostics
            self.atltool.writephyreg(0x1E, 0xC470, reg.get())

            st = timeit.default_timer()
            is_completed = self.__wait_clear_bit(0x1E, 0xC831, 0xF) and self.__wait_clear_bit(0x1E, 0xC470, 0x4)
            st = (timeit.default_timer() - st) * 1000
            return st if is_completed else -1
        else:
            raise NotImplementedError()

    def get_cable_diagnostics_data(self):
        data = {pair: {} for pair in 'ABCD'}

        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1E, 0xC806))
            data['A']['far_distance'] = reg[0x0:0x7]
            data['B']['far_distance'] = reg[0x8:0xF]

            reg = Register(self.atltool.readphyreg(0x1E, 0xC808))
            data['C']['far_distance'] = reg[0x0:0x7]
            data['D']['far_distance'] = reg[0x8:0xF]

            # in m
            data['A']['reflection'] = Register(self.atltool.readphyreg(0x1E, 0xC801))[0x0:0x7]
            data['B']['reflection'] = Register(self.atltool.readphyreg(0x1E, 0xC803))[0x0:0x7]
            data['C']['reflection'] = Register(self.atltool.readphyreg(0x1E, 0xC805))[0x0:0x7]
            data['D']['reflection'] = Register(self.atltool.readphyreg(0x1E, 0xC807))[0x0:0x7]

            # in dB
            data['A']['margin'] = (self.atltool.readphyreg(0x01, 0x0085) - 0x8000) / 2580.0
            data['B']['margin'] = (self.atltool.readphyreg(0x01, 0x0086) - 0x8000) / 2580.0
            data['C']['margin'] = (self.atltool.readphyreg(0x01, 0x0087) - 0x8000) / 2580.0
            data['D']['margin'] = (self.atltool.readphyreg(0x01, 0x0088) - 0x8000) / 2580.0

            reg = Register(self.atltool.readphyreg(0x1E, 0xC800))
            data['A']['status'] = MAP_PAIR_STATUS[reg[0xC:0xE]]
            data['B']['status'] = MAP_PAIR_STATUS[reg[0x8:0xA]]
            data['C']['status'] = MAP_PAIR_STATUS[reg[0x4:0x6]]
            data['D']['status'] = MAP_PAIR_STATUS[reg[0x0:0x2]]
        else:
            raise NotImplementedError()

        return data

    def get_temperature(self):
        if self.phy_control is None:
            return self.atltool.readphyreg(0x1E, 0xC820) / 256.0
        else:
            raise NotImplementedError()

    def get_cable_length(self):
        if self.phy_control is None:
            return Register(self.atltool.readphyreg(0x1E, 0xC884))[0x0:0x7]
        else:
            raise NotImplementedError()

    def send_n_packets(self, speed, count, size):
        assert self.is_antigua(), "Support Antigua only"
        if self.phy_control is None:
            rate = {
                LINK_SPEED_10M: 0x0,
                LINK_SPEED_100M: 0x0,
                LINK_SPEED_1G: 0x0,
                LINK_SPEED_2_5G: 0x3,
                LINK_SPEED_5G: 0x2,
                LINK_SPEED_10G: 0x0
            }[speed]

            # XTP PHY CLOCK ENABLE (ANTIGUA only)
            reg = Register(self.atltool.readphyreg(0x1E, 0xC2F1))
            reg[0] = 1
            self.atltool.writephyreg(0x1E, 0xC2F1, reg.get())

            # TX XTP PHY DATA (ANTIGUA only)
            reg = Register(self.atltool.readphyreg(0x1E, 0xC2F5))
            reg[0:1] = 1
            self.atltool.writephyreg(0x1E, 0xC2F5, reg.get())

            # XTP AQRate MODE
            reg = Register(self.atltool.readphyreg(0x3, 0xC4AE))
            reg[0:2] = 0  # 10G; rate
            self.atltool.writephyreg(0x3, 0xC4AE, reg.get())

            # configure generator
            reg = Register(self.atltool.readphyreg(0x4, 0xD806))
            reg[0x0:0x1] = 0  # 0 - single shot; 1 - continuous - packet generator
            reg[0x4:0x5] = 0  # 0 - single shot; 1 - continuous - packet checker
            reg[0x8:0xA] = 0  # 0 - all zeroes packet payload mode
            reg[0xC:0xD] = 0  # 0 - fixed packet length mode
            reg[0xE:0xF] = 0  # 0 - fixed packet IFG mode
            self.atltool.writephyreg(0x4, 0xD806, reg.get())

            # count of packets
            reg = Register(self.atltool.readphyreg(0x4, 0xD80C))
            reg[0x0:0xF] = count
            self.atltool.writephyreg(0x4, 0xD80C, reg.get())

            # max packet len
            reg = Register(self.atltool.readphyreg(0x4, 0xD80A))
            reg[0x0:0xF] = size
            self.atltool.writephyreg(0x4, 0xD80A, reg.get())

            # min packet len
            reg = Register(self.atltool.readphyreg(0x4, 0xD809))
            reg[0x0:0xF] = size
            self.atltool.writephyreg(0x4, 0xD809, reg.get())

            # mmd select configuration
            reg = Register(self.atltool.readphyreg(0x1E, 0xC009))
            reg[0] = 1
            self.atltool.writephyreg(0x1E, 0xC009, reg.get())

            # start
            reg = Register(self.atltool.readphyreg(0x1E, 0x0403))
            reg[0:3] = 0xF
            reg[4] = 1
            self.atltool.writephyreg(0x1E, 0x0403, reg.get())

            time.sleep(1)

            # stop
            reg = Register(self.atltool.readphyreg(0x1E, 0x0403))
            reg[4] = 0
            self.atltool.writephyreg(0x1E, 0x0403, reg.get())
        else:
            raise NotImplementedError()

    def get_link_status(self):
        if self.phy_control is None:
            stats = {}

            reg = Register(self.atltool.readphyreg(0x7, 0xC800))
            stats['link'] = MAP_CONNECT_RATE[reg[0x1:0x3]]
            stats['connect_type'] = 'Full-Duplex' if reg[0] == 1 else 'Half-Duplex'

            reg = Register(self.atltool.readphyreg(0x7, 0xC810))
            stats['status'] = MAP_CONNECTION_STATE[reg[0x9:0xD]]

            reg = Register(self.atltool.readphyreg(0x7, 0xE830))
            stats['retry'] = reg[0xC:0xF]

            reg = Register(self.atltool.readphyreg(0x7, 0xC400))
            stats['retry_downshift'] = reg[0x0:0x3]

            return stats
        else:
            raise NotImplementedError()

    def get_link_speed(self):
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x1e, 0xC831))
            if reg[0xA] == 0x1:
                return LINK_SPEED_10G
            elif reg[6] == 0x1:
                return LINK_SPEED_5G
            elif reg[5] == 0x1:
                return LINK_SPEED_2_5G
            elif reg[9] == 0x1:
                return LINK_SPEED_1G
            elif reg[8] == 0x1:
                return LINK_SPEED_100M
            elif reg[4] == 0x1:
                return LINK_SPEED_10M
            else:
                return LINK_SPEED_NO_LINK
        else:
            status = self.phy_control.rmap.glb.GlobalGeneralStatus_2()
            if status.link_100Mb_sConnectionStatus.readValue(self.phy_control) == 0x1:
                return LINK_SPEED_100M
            elif status.link_1Gb_sConnectionStatus.readValue(self.phy_control) == 0x1:
                return LINK_SPEED_1G
            elif status.link_2_5Gb_sConnectionStatus.readValue(self.phy_control) == 0x1:
                return LINK_SPEED_2_5G
            elif status.link_5Gb_sConnectionStatus.readValue(self.phy_control) == 0x1:
                return LINK_SPEED_5G
            elif status.link_10Gb_sConnectionStatus.readValue(self.phy_control) == 0x1:
                return LINK_SPEED_10G
            else:
                return LINK_SPEED_NO_LINK

    def configure_traffic_generator(self, **kwargs):
        """
            Configure traffic generator

        Keyword arguments:
            rate -- Set rate
            pkt_ifg_mode -- IFG mode
            pkt_len_mode -- Length mode
            pkt_payload_mode -- Payload mode
            pkt_gen_mode -- Generation mode
            pkt_checker_mode -- Checker mode
        """

        # self.tg['mode'] = kwargs.get('packet_mode', 0x0)
        # self.tg['source'] = kwargs.get('source', 'sif')
        #
        # if self.phy_control is None:
        #     reg = Register(self.atltool.readphyreg(0x4, 0xD806))
        # else:
        #     pass

        self.tg['source'] = kwargs.get('source', 'sif')
        self.tg['rate'] = kwargs.get('rate', LINK_SPEED_100M)
        self.tg['pkt_ifg_mode'] = kwargs.get('pkt_ifg_mode', 0x0)
        self.tg['pkt_len_mode'] = kwargs.get('pkt_len_mode', 0x0)
        self.tg['pkt_payload_mode'] = kwargs.get('pkt_payload_mode', 0x1)
        self.tg['pkt_gen_mode'] = kwargs.get('pkt_gen_mode', 0x0)
        self.tg['pkt_checker_mode'] = kwargs.get('pkt_checker_mode', 0x0)
        self.tg['pkt_number'] = kwargs.get('pkt_number', 0xa)

        rate = {
            LINK_SPEED_10M: 0x6,
            LINK_SPEED_100M: 0x1,
            LINK_SPEED_1G: 0x2,
            LINK_SPEED_2_5G: 0x4,
            LINK_SPEED_5G: 0x5,
            LINK_SPEED_10G: 0x3
        }[self.tg['rate']]

        log.info('Setting packet gen config:\n')
        # log.info('rate: [{:>8}]'.format(self.tg['rate']))
        # log.info('pkt_ifg_mode: [{:>8}]'.format(self.tg['pkt_ifg_mode']))
        # log.info('pkt_len_mode: [{:>8}]'.format(self.tg['pkt_len_mode']))
        # log.info('pkt_payload_mode: [{:>8}]'.format(self.tg['pkt_payload_mode']))
        # log.info('pkt_gen_mode: [{:>8}]'.format(self.tg['pkt_gen_mode']))
        big_log = '\n'
        for k in sorted(self.tg.keys()):
            big_log += '{:>50s}: {:>8}\n'.format(k, self.tg[k])
        big_log += '\n'
        log.info(big_log)

        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x4, 0xC444))
            reg[0:2] = rate
            self.atltool.writephyreg(0x4, 0xC444, reg.get())

            reg = Register(self.atltool.readphyreg(0x4, 0xD806))
            reg[14:15] = self.tg['pkt_ifg_mode']
            reg[12:13] = self.tg['pkt_len_mode']
            reg[8:10] = self.tg['pkt_payload_mode']
            reg[4:5] = self.tg['pkt_checker_mode']
            reg[0:1] = self.tg['pkt_gen_mode']
            self.atltool.writephyreg(0x4, 0xD806, reg.get())
        else:
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_ReservedVendorProvisioning_5().rate.rmw(self.phy_control, rate)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_7().packetLengthMode.rmw(self.phy_control, self.tg['pkt_len_mode'])
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_7().packetPayloadMode.rmw(self.phy_control, self.tg['pkt_payload_mode'])
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_7().packetIfgMode.rmw(self.phy_control, self.tg['pkt_ifg_mode'])
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_7().packetGeneratorMode.rmw(self.phy_control, self.tg['pkt_gen_mode'])
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_7().packetCheckerMode.rmw(self.phy_control, self.tg['pkt_checker_mode'])

            # If single shot, then config number of packets for use
            if self.tg['pkt_checker_mode'] == 0x0 and self.tg['pkt_gen_mode'] == 0x0:
                self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_13().packetNumber.rmw(self.phy_control, self.tg['pkt_number'])

            # Other defaults
            self.phy_control.rmap.glb.GlobalAntiguaMiniSifControl_3().lineClockSel.rmw(self.phy_control, 0x0)
            self.phy_control.rmap.glb.GlobalAntiguaMiniSifControl_4().phyInputSel.rmw(self.phy_control, 0x0)

            self.phy_control.rmap.glb.GlobalAntiguaMiniSifControl_1().xtpPhyClockEnable.rmw(self.phy_control, 0x1)
            self.phy_control.rmap.glb.GlobalAntiguaMiniSifControl_5().txRateAdjInputSel.rmw(self.phy_control, 0x1)
            self.phy_control.rmap.glb.GlobalAntiguaMiniSifControl_2().xtpPhyClockSel.rmw(self.phy_control, 0x0)

            self.phy_control.rmap.pcs.PcsTransmitXgsVendorProvisioning_13().xgsMacRxFifoReset.rmw(self.phy_control, 0x1)
            time.sleep(0.5)
            self.phy_control.rmap.pcs.PcsTransmitXgsVendorProvisioning_13().xgsMacRxFifoReset.rmw(self.phy_control, 0x0)

            self.phy_control.rmap.pcs.PcsTransmitXgsVendorProvisioning_12().xgsMacTxFifoReset.rmw(self.phy_control, 0x1)
            time.sleep(0.5)
            self.phy_control.rmap.pcs.PcsTransmitXgsVendorProvisioning_12().xgsMacTxFifoReset.rmw(self.phy_control, 0x0)

            self.phy_control.rmap.pcs.PcsTransmitXgmVendorProvisioning_1().xtpAqrateMode.rmw(self.phy_control, 0x0)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_6().testPatternDataPathPatternEnable.rmw(self.phy_control, 0x1)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_1().testPatternSynchronizationThreshold.rmw(self.phy_control, 0xa)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_1().testPatternInvert.rmw(self.phy_control, 0x1)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_1().test_patternExtendedSelect.rmw(self.phy_control, 0x1)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_8().packetMinimumIfg.rmw(self.phy_control, 0xc)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_9().packetMaximumIfg.rmw(self.phy_control, 0xf)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_10().packetMinimumLengthLSW.rmw(self.phy_control, 0x40)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_12().packetMaximumLengthMSW.rmw(self.phy_control, 0x0)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_11().packetMaximumLengthLSW.rmw(self.phy_control, 0x5dc)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_12().packetMaximumLengthMSW.rmw(self.phy_control, 0x0)

            time.sleep(0.5)

            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_1().testPatternSynchronizationThreshold.rmw(self.phy_control, 0xa)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_1().testPatternInvert.rmw(self.phy_control, 0x1)
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_VendorDebug_1().test_patternExtendedSelect.rmw(self.phy_control, 0x1)

    def traffic_check(self):
        log.info("Verifying packets via packet cheker")
        passed = True

        if self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_TestPatternErrorStatus_1().removedPacketPayloadError.readValue(self.phy_control) == 0x1:
            log.info("Payload Error")
            passed = False

        if self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_TestPatternErrorStatus_1().removedSequenceNumberError.readValue(self.phy_control) == 0x1:
            log.info("Sequence Number Error")
            passed = False

        if self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_TestPatternErrorStatus_1().removedPacketEthertypeOrLengthError.readValue(self.phy_control) == 0x1:
            log.info("PacketEthertypeOrLengthError Error")
            passed = False

        if self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_TestPatternErrorStatus_1().removedPacketDestinationAddressError.readValue(self.phy_control) == 0x1:
            log.info("PacketDestinationAddress Error")
            passed = False

        if self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_TestPatternErrorStatus_1().removedPacketSourceAddressError.readValue(self.phy_control) == 0x1:
            log.info("PacketSourceAddress Error")
            passed = False

        assert passed

    def start_traffic_gen(self):
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x4, 0xC444))
            reg[5] = 0x1
            self.atltool.writephyreg(0x4, 0xC444, reg.get())
        else:
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_ReservedVendorProvisioning_5().mdiPacketGeneration.rmw(self.phy_control, 0x1)
            return 'rate: {}   mdiPacketGeneration:{}'.format(self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_ReservedVendorProvisioning_5().rate.readValue(self.phy_control),
                                  self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_ReservedVendorProvisioning_5().mdiPacketGeneration.readValue(self.phy_control))

    def stop_traffic_gen(self):
        if self.phy_control is None:
            reg = Register(self.atltool.readphyreg(0x4, 0xC444))
            reg[5] = 0x0
            self.atltool.writephyreg(0x4, 0xC444, reg.get())
        else:
            self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_ReservedVendorProvisioning_5().mdiPacketGeneration.rmw(self.phy_control, 0x0)

        # traffic_gen_done = self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_TestPatternErrorStatus_1().removedPacketGeneratorDone
        # traffic_checker_done = self.phy_control.rmap.pxs.PhyXS_Transmit_xauiRx_TestPatternErrorStatus_1().removedPacketCheckerDone

def collect_phy_fifo_level(phy, direction, timeout=10):
    levels = []
    for _ in range(timeout):
        levels.append(phy.get_fifo_level(direction=direction))
        time.sleep(1)
    return levels
