import time
from abc import ABCMeta
import sys
import os

from tools.fw_a2_drv_iface_cfg import FirmwareA2Config

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hlh.register import Register
from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_NO_LINK, LINK_SPEED_10M, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G
from tools.constants import LINK_SPEED_5G, LINK_SPEED_10G
from tools.constants import LINK_STATE_UP, LINK_STATE_DOWN
from tools.constants import DISABLE, ENABLE, ENABLE_LINK, ENABLE_PRIORITY
from tools.constants import MAC_ATLANTIC2_A0, MAC_ATLANTIC1_A0

HARDWARE_ACCESS_FW = 'firmware'
HARDWARE_ACCESS_DRV = 'driver'


ALL_MAC_TYPES = [MAC_ATLANTIC1_A0, MAC_ATLANTIC2_A0]


class MAC(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        arch = kwargs.get('arch', MAC_ATLANTIC1_A0)
        assert arch in ALL_MAC_TYPES, "Unknown MAC !!!"

        if arch == MAC_ATLANTIC1_A0:
            return object.__new__(MAC_A1)
        elif arch == MAC_ATLANTIC2_A0:
            return object.__new__(MAC_A2)

    def __init__(self, **kwargs):
        self.port = kwargs.get("port", None)
        self.host = kwargs.get("host", None)
        assert self.port is not None
        assert self.host is not None

        self.atltool = AtlTool(port=self.port, host=self.host)

    def get_chip_id(self):
        return self.atltool.readreg(0x10)


MAP_LINK_STATUS = {
    0x6: LINK_SPEED_10G,
    0x5: LINK_SPEED_5G,
    0x4: LINK_SPEED_2_5G,
    0x3: LINK_SPEED_1G,
    0x2: LINK_SPEED_100M,
    0x1: LINK_SPEED_10M,
    0x0: LINK_SPEED_NO_LINK
}

OPERATION_MODE_INVALID = 'invalid'
OPERATION_MODE_ACTIVE = 'active'
OPERATION_MODE_SLEEP_PROXY = 'sleep proxy'
OPERATION_MODE_LOW_POWER = 'low power'
OPERATION_MODE_SHUTDOWN = 'shutdown'

MAP_OPERATING_MODE = {
    OPERATION_MODE_INVALID: 0,
    OPERATION_MODE_ACTIVE: 1,
    OPERATION_MODE_SLEEP_PROXY: 2,
    OPERATION_MODE_LOW_POWER: 3,
    OPERATION_MODE_SHUTDOWN: 4
}

ALL_OPERATING_MODE = [
    OPERATION_MODE_INVALID,
    OPERATION_MODE_ACTIVE,
    OPERATION_MODE_SLEEP_PROXY,
    OPERATION_MODE_LOW_POWER,
    OPERATION_MODE_SHUTDOWN
]


class MAC_A2(MAC):

    def __init__(self, **kwargs):
        super(MAC_A2, self).__init__(**kwargs)
        self.fw_config = FirmwareA2Config(atltool_wrapper=self.atltool)

    def stall_fw(self):
        reg = Register(self.atltool.readreg(0x404))
        reg[0] = 1
        self.atltool.writereg(0x404, reg.get())

        reg = Register(self.atltool.readreg(0x3A0))
        reg[0] = 1
        self.atltool.writereg(0x3A0, reg.get())

    def unstall_fw(self):
        reg = Register(self.atltool.readreg(0x404))
        reg[0] = 0
        self.atltool.writereg(0x404, reg.get())

    def set_link_speed(self, speed):
        self.fw_config.set_link_speed(speed)
        # map_speed_adv = {
        #     LINK_SPEED_10M: [0x8],
        #     LINK_SPEED_100M: [0x9],
        #     LINK_SPEED_1G: [0xA],
        #     LINK_SPEED_2_5G: [0xB, 0xC],
        #     LINK_SPEED_5G: [0xD, 0xE],
        #     LINK_SPEED_10G: [0xF]
        # }
        # reg = Register(self.atltool.readreg(0x12018))
        # reg[0x8:0xF] = 0  # disable all speeds
        # for r in map_speed_adv[speed]:
        #     reg[r] = 1
        # self.atltool.writereg(0x12018, reg.get())

    def set_operation_mode(self, mode):
        assert mode in ALL_OPERATING_MODE
        reg = Register(self.atltool.readreg(0x12010))
        reg[0:4] = MAP_OPERATING_MODE[mode]
        self.atltool.writereg(0x12010, reg.get())

    def set_link_state(self, state):
        assert state in [LINK_STATE_DOWN, LINK_STATE_UP]

        reg = Register(self.atltool.readreg(0x12018))
        reg[0] = 1 if state == LINK_STATE_UP else 0
        self.atltool.writereg(0x12018, reg.get())

        reg = Register(self.atltool.readreg(0xE00))
        reg[0] = 1
        reg[1] = 1
        self.atltool.writereg(0xE00, reg.get())

    def wait_link_up(self):
        correct_flag = False
        for i in range(10000):
            time.sleep(0.001)
            value = Register(self.atltool.readreg(0x13014))
            if value[0:3] == 1:
                correct_flag = True
                break

        if correct_flag:
            return MAP_LINK_STATUS[Register(self.atltool.readreg(0x13014))[4:7]]
        else:
            return LINK_SPEED_NO_LINK

        pass


class MAC_A1(MAC):
    def set_pause_frames_generate_mode(self, state):
        assert state in [ENABLE, DISABLE, ENABLE_LINK, ENABLE_PRIORITY]
        st = {DISABLE: 0x0, ENABLE_LINK: 0x1, ENABLE_PRIORITY: 0x2, ENABLE: 0x3}[state]
        reg = Register(self.atltool.readreg(0x5700))
        reg[4:5] = st
        self.atltool.writereg(0x5700, reg.get())

    def set_pause_frames_processing(self, state):
        assert state in [ENABLE, DISABLE, ENABLE_LINK, ENABLE_PRIORITY]
        st = 0x1 if state == DISABLE else 0x0
        reg = Register(self.atltool.readmsmreg(0x8))
        reg[8] = st
        self.atltool.writemsmreg(0x8, reg.get())

    def set_pause_frames_threshold(self, xon=None, xoff=None):
        if xon is not None:
            val = Register(self.atltool.readreg(0x5714))
            val[0:0xd] = (xon & 0x3fff)
            self.atltool.writereg(0x5714, val.get())
        if xoff is not None:
            val = Register(self.atltool.readreg(0x5714))
            val[0x10:0x1d] = (xoff & 0x3fff)
            self.atltool.writereg(0x5714, val.get())

    def set_flow_control(self, state):
        self.set_pause_frames_generate_mode(state)
        self.set_pause_frames_processing(state)

    def get_counters_pause_frames(self):
        rx = self.atltool.readmsmreg(0xA8)
        tx = self.atltool.readmsmreg(0xA0)
        return rx, tx

    def get_counters_reg_frames(self):
        # With VLAN
        rx = self.atltool.readmsmreg(0xc8)
        tx = self.atltool.readmsmreg(0xc0)
        return rx, tx
