import array
import collections
import os
import random
import re
import shutil
import struct
import time
import timeit

import pytest

from infra.test_base import TestBase, idparametrize
from scapy.all import Ether, Raw
from tools.aqpkt import Aqsendp, scapy_pkt_to_aqsendp_str
from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import LINK_STATE_UP, LINK_STATE_DOWN, FELICITY_CARDS
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvMessage, DrvDownshiftConfig, FWStatistics, FWSettings, SettingsMemory, \
    DrvEEEStateMachineConfig, FWSmbusReadRequest, DrvEthConfig, OffloadIpInfo, DrvWinWoLConfig, DrvThermalShutdownConfig
from tools.ifconfig import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, \
    LINK_SPEED_AUTO, LINK_SPEED_NO_LINK, get_expected_speed, KNOWN_LINK_SPEEDS
from tools.mbuper import LINK_CONTROL_TRANSACTION_ID, LINK_CONTROL_LINK_DROP, LINK_CONTROL_SLEEP_PROXY, \
    LINK_CONTROL_WOL, LINK_CONTROL_TPO2, LINK_CONTROL_PTP_AVB
from tools.samba import Samba
from tools.utils import get_atf_logger, get_bus_dev_func

from tools.mbuper import LINK_SPEED_TO_REG_VAL_MAP_2X

from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_sanity"


class TestFw2xSanity(TestBase):
    DEFAULT_LINK_CHECKS = 3
    BEFORE_PING_DELAY = 10
    LINK_CONTROL_DELAY = 5

    HIGH_TEMP_FAILURE_THRESHOLD = (0x1e, 0xc421, 0x6c00)
    LOW_TEMP_FAILURE_THRESHOLD = (0x1e, 0xc422, 0x0000)
    HIGH_TEMP_WARNING_THRESHOLD = (0x1e, 0xc423, 0x3c00)
    LOW_TEMP_WARNING_THRESHOLD = (0x1e, 0xc424, 0x0a00)

    TEMP_THRESHOLD = [("High Temp Failure Threshold", HIGH_TEMP_FAILURE_THRESHOLD),
                      ("Low Temp Failure Threshold", LOW_TEMP_FAILURE_THRESHOLD),
                      ("High Temp Warning Threshold", HIGH_TEMP_WARNING_THRESHOLD),
                      ("Low Temp Warning Threshold", LOW_TEMP_WARNING_THRESHOLD)]

    EEE_STATEMACHINE_MASK = {LINK_SPEED_1G: 0x10, LINK_SPEED_2_5G: 0x8, LINK_SPEED_5G: 0x2, LINK_SPEED_10G: 0x1}

    PCI_SPEED_MAP = {
        1: "PCI Gen 1 (2.5 GT/s)",
        2: "PCI Gen 2 (5.0 GT/s)",
        3: "PCI Gen 3 (8.0 GT/s)"
    }

    DEFAULT_SETTING_OFS = collections.OrderedDict([
        (FWSettings.MTU_OFS, 0x3FE0),
        (FWSettings.DOWNSHIFT_RETRY_COUNT_OFS, 0x04),
        (FWSettings.LINK_PAUSE_FRAME_QUANTA_100M_OFS, 0xFF00),
        (FWSettings.LINK_PAUSE_FRAME_QUANTA_1G_OFS, 0xFF00),
        (FWSettings.LINK_PAUSE_FRAME_QUANTA_2P5G_OFS, 0xFF00),
        (FWSettings.LINK_PAUSE_FRAME_QUANTA_5G_OFS, 0xFF00),
        (FWSettings.LINK_PAUSE_FRAME_QUANTA_10G_OFS, 0xFF00),
        (FWSettings.PFC_QUANTA_CLASS_0_OFS, 0xFF00),
        (FWSettings.PFC_QUANTA_CLASS_1_OFS, 0xFF00),
        (FWSettings.PFC_QUANTA_CLASS_2_OFS, 0xFF00),
        (FWSettings.PFC_QUANTA_CLASS_3_OFS, 0xFF00),
        (FWSettings.PFC_QUANTA_CLASS_4_OFS, 0xFF00),
        (FWSettings.PFC_QUANTA_CLASS_5_OFS, 0xFF00),
        (FWSettings.PFC_QUANTA_CLASS_6_OFS, 0xFF00),
        (FWSettings.PFC_QUANTA_CLASS_7_OFS, 0xFF00),
        (FWSettings.EEE_LINK_DOWN_TIMEOUT_OFS, 0x2710),
        (FWSettings.EEE_LINK_UP_TIMEOUT_OFS, 0x01B77400),
        (FWSettings.EEE_MAX_LINK_DROPS_OFS, 0x1),
        (FWSettings.EEE_RATES_MASK_OFS, 0),
        (FWSettings.WAKE_TIMER_OFS, 60000),
        (FWSettings.THERMAL_SHUTDOWN_OFF_TEMP_OFS, 108),
        (FWSettings.THERMAL_SHUTDOWN_WARNING_TEMP_OFS, 100),
        (FWSettings.THERMAL_SHUTDOWN_COLD_TEMP_OFS, 80),
        (FWSettings.MSM_OPTIONS_OFS, 0),
        (FWSettings.DAC_CABLE_SERDES_MODES_OFS, 0xC6AB2)
    ])

    @classmethod
    def setup_class(cls):
        super(TestFw2xSanity, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest")
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            cls.dut_atltool_wrapper.kickstart(reload_phy_fw=cls.dut_fw_card not in FELICITY_CARDS)

            # Disable WOL on LKP to avoid problem with link down on Linux
            cls.lkp_ifconfig.set_power_mgmt_settings(False, False, False)

            log.info("Getting PCI bridge capabilities")
            bus, dev, func = map(lambda x: int(x), get_bus_dev_func(cls.dut_port))
            cls.dut_pci_addr = "{:02x}:{:02x}.{:x}".format(bus, dev, func)
            res = Command(cmd="lspci -t").run_join(10)
            if res["returncode"] != 0:
                raise Exception("Failed to get PCI tree")
            re_pci_bridge = re.compile(r"^.*\+.*\-(.*)\-\[{:02x}\]\-+{:02x}\.{:x}".format(bus, dev, func))
            for line in res["output"]:
                m = re_pci_bridge.match(line)
                if m is not None:
                    cls.pci_bridge_addr = m.group(1)
                    break
            else:
                raise Exception("Failed to find device {} in PCI tree".format(cls.dut_pci_addr))

            # Disable Samba to remove background multicast traffic which affects SerDes
            Samba(host=cls.lkp_hostname).stop()

            cls.pci_max_width, cls.pci_max_speed = cls.get_pci_width_speed(cls.pci_bridge_addr)
            log.info("PCI bridge capabilities: Width = {}, Speed = {}".format(
                cls.pci_max_width, cls.PCI_SPEED_MAP[cls.pci_max_speed]))

            cls.dut_fw_ver_maj, ver_minor, ver_release = cls.dut_atltool_wrapper.get_fw_version()
            quanta_threshold = 0xfef0  # 2x and old 3x firmwares
            if (cls.dut_fw_ver_maj == 3 and ver_minor == 0 and ver_release >= 152) or \
                    (cls.dut_fw_ver_maj == 3 and ver_minor == 1 and ver_release >= 77):
                # Quanta threshold was changed starting from this version
                quanta_threshold = 0xf
            for k in [
                FWSettings.LINK_PAUSE_FRAME_THRESHOLD_100M_OFS,
                FWSettings.LINK_PAUSE_FRAME_THRESHOLD_1G_OFS,
                FWSettings.LINK_PAUSE_FRAME_THRESHOLD_2P5G_OFS,
                FWSettings.LINK_PAUSE_FRAME_THRESHOLD_5G_OFS,
                FWSettings.LINK_PAUSE_FRAME_THRESHOLD_10G_OFS,
                FWSettings.PFC_THRESHOLD_CLASS_0_OFS,
                FWSettings.PFC_THRESHOLD_CLASS_1_OFS,
                FWSettings.PFC_THRESHOLD_CLASS_2_OFS,
                FWSettings.PFC_THRESHOLD_CLASS_3_OFS,
                FWSettings.PFC_THRESHOLD_CLASS_4_OFS,
                FWSettings.PFC_THRESHOLD_CLASS_5_OFS,
                FWSettings.PFC_THRESHOLD_CLASS_6_OFS,
                FWSettings.PFC_THRESHOLD_CLASS_7_OFS
            ]:
                cls.DEFAULT_SETTING_OFS[k] = quanta_threshold

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestFw2xSanity, cls).teardown_class()

    def setup_method(self, method):
        super(TestFw2xSanity, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)
            self.lkp_atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestFw2xSanity, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        if self.MCP_LOG:
            self.dut_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

            self.lkp_bin_log_file, self.lkp_txt_log_file = self.lkp_atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.lkp_bin_log_file, self.test_log_dir)
            shutil.copy(self.lkp_txt_log_file, self.test_log_dir)

    @staticmethod
    def get_pci_width_speed(lspci_device, link_status=False):
        res = Command(cmd="sudo setpci -s {} CAP_EXP+{}".format(
            lspci_device, "0x12.W" if link_status else "0xC.L")).run_join(10)
        if res["returncode"] != 0:
            raise Exception("Failed to get link capabilities of PCI device {}".format(lspci_device))
        pci_link_caps = int(res["output"][0], 16)
        return (pci_link_caps & 0x3F0) >> 4, pci_link_caps & 0xF

    def run_test_speed_switch(self, speed_from, speed_to):
        if self.dut_fw_card in FELICITY_CARDS or self.lkp_fw_card in FELICITY_CARDS:
            if self.supported_speeds is None:
                raise Exception("Do not know supported speeds on Felicity")
            if speed_from == LINK_SPEED_AUTO or speed_from not in self.supported_speeds:
                pytest.xfail()
            if speed_to == LINK_SPEED_AUTO or speed_to not in self.supported_speeds:
                pytest.xfail()
        else:
            if (speed_from == LINK_SPEED_10G or speed_to == LINK_SPEED_10G) and \
                    get_expected_speed(LINK_SPEED_AUTO, self.dut_port) != LINK_SPEED_10G:
                # If the card is not Felicity and it cannot advertize 10G on autoneg we xfail
                pytest.xfail()

        exp_from_speed = get_expected_speed(speed_from, self.dut_port)
        exp_to_speed = get_expected_speed(speed_to, self.dut_port)

        if self.lkp_fw_card not in FELICITY_CARDS:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

        link_check_attempts = int(os.environ.get('LINK_CHECKS', self.DEFAULT_LINK_CHECKS))
        for i in range(link_check_attempts):
            log.info('Link check #{}...'.format(i + 1))
            if self.lkp_fw_card in FELICITY_CARDS:
                self.lkp_ifconfig.set_link_speed(speed_from)
            self.dut_atltool_wrapper.set_link_params_2x(speed_from)
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            pspeed = self.lkp_ifconfig.wait_link_up()
            assert pspeed is not None
            assert pspeed == exp_from_speed

            if self.lkp_fw_card in FELICITY_CARDS:
                self.lkp_ifconfig.set_link_speed(speed_to)
            self.dut_atltool_wrapper.set_link_params_2x(speed_to)
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            pspeed = self.lkp_ifconfig.wait_link_up()
            assert pspeed is not None
            assert pspeed == exp_to_speed

    def run_test_speed_switch_to_no_link(self, speed_from):
        if self.dut_fw_card in FELICITY_CARDS or self.lkp_fw_card in FELICITY_CARDS:
            if self.supported_speeds is None:
                raise Exception("Do not know supported speeds on Felicity")
            if speed_from == LINK_SPEED_AUTO or speed_from not in self.supported_speeds:
                pytest.xfail()
        else:
            if (speed_from == LINK_SPEED_10G) and \
                    get_expected_speed(LINK_SPEED_AUTO, self.dut_port) != LINK_SPEED_10G:
                # If the card is not Felicity and it cannot advertize 10G on autoneg we xfail
                pytest.xfail()

        if self.lkp_fw_card not in FELICITY_CARDS:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        else:
            self.lkp_ifconfig.set_link_speed(speed_from)
        self.dut_atltool_wrapper.set_link_params_2x(speed_from)
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.wait_link_up()
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_NO_LINK)
        self.dut_atltool_wrapper.wait_link_down()

    def test_check_sfp_settings(self):
        if self.dut_fw_card not in FELICITY_CARDS:
            pytest.skip()
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.wait_link_up()

        REG_4C18 = 0x4c18
        REG_4C34 = 0x4c34
        REG_4C38 = 0x4c38
        VALUE_SETTING_SFP = [0x0, 0x25, 0x6, 0x1]
        VALUE_SETTING_SFP_OPTIC = [0x6, 0x2C, 0x0, 0x0]
        VALUE_SETTING_SFP_DAC_PASSIVE = [0x3, 0x2F, 0x0, 0x0]  # ATLFW-447
        VALUE_SETTING_SFP_DAC_ACTIVE = [0x0, 0x32, 0x0, 0x0]  # ATLFW-447
        VALUE_SETTING_SFP_DAC_ACTIVE_7M = VALUE_SETTING_SFP_OPTIC  # ATLFW-447
        ACTIVE_DAC_CABLES = "DAC-CISCO-H10GB-A"
        ACTIVE_DAC_CABLES_7M = "DAC-CISCO-H10GB-ACU7M"

        set_prev = (self.dut_atltool_wrapper.readreg(REG_4C38) >> 4) & 0x3f
        set_main = (self.dut_atltool_wrapper.readreg(REG_4C34) >> 4) & 0x3f
        set_post = (self.dut_atltool_wrapper.readreg(REG_4C38) >> 10) & 0x3f
        ampl = (self.dut_atltool_wrapper.readreg(REG_4C18) >> 4) & 0x3f
        serdes_set = [set_prev, set_main, set_post, ampl]

        if "DAC" in self.sfp:
            if ACTIVE_DAC_CABLES in self.sfp:
                if self.sfp == ACTIVE_DAC_CABLES_7M:
                    def_serdes_set = VALUE_SETTING_SFP_DAC_ACTIVE_7M
                else:
                    def_serdes_set = VALUE_SETTING_SFP_DAC_ACTIVE
            else:
                def_serdes_set = VALUE_SETTING_SFP_DAC_PASSIVE
        else:
            if 'Felicity-opt' in self.platform:
                def_serdes_set = VALUE_SETTING_SFP_OPTIC
            else:
                def_serdes_set = VALUE_SETTING_SFP
        assert serdes_set == def_serdes_set, "Incorrect SFP setting: expected {}, actual {}".format(
            def_serdes_set, serdes_set)

    def test_stripping_of_padding(self):
        assert self.dut_atltool_wrapper.readmsmreg(0x00000008) & 0x20 == 0

    def test_pci_capabilities(self):
        efuse_dw_63 = self.dut_atltool_wrapper.get_efuse(64 * 4)[-1]
        chip_id = (efuse_dw_63 & 0xFFFF0000) >> 16
        log.info("Chip ID = {:x}".format(chip_id))

        expected_pci_speed = self.pci_max_speed
        expected_pci_width = 4 if chip_id in [0xc100, 0xc107] else 1
        if expected_pci_width > self.pci_max_width:
            expected_pci_width = self.pci_max_width

        dut_pci_width, dut_pci_speed = self.get_pci_width_speed(self.dut_pci_addr, link_status=True)

        log.info("Expected values: Width = {}, Speed = {}".format(expected_pci_width,
                                                                  self.PCI_SPEED_MAP[expected_pci_speed]))
        log.info("DUT values: Width = {}, Speed = {}".format(dut_pci_width, self.PCI_SPEED_MAP[dut_pci_speed]))
        assert expected_pci_width == dut_pci_width
        assert expected_pci_speed == dut_pci_speed

    def test_check_sfp_identifier(self):
        if self.dut_fw_card not in FELICITY_CARDS:
            pytest.skip()
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.wait_link_up()
        for i in range(100):
            log_file = "iteration_{}".format(i)
            bin_log_file, txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)
            self.dut_atltool_wrapper.kickstart(False)
            time.sleep(5)
            self.dut_atltool_wrapper.debug_buffer_enable(False)
            os.rename("{}".format(txt_log_file), "{}.log".format(log_file))
            os.rename("{}".format(bin_log_file), "{}.bin".format(log_file))
            f = open('{}.log'.format(log_file), 'r')
            message = 0
            for line in f:
                if "SFP A0 CC expected:" in line:
                    message += 1
            f.close()
            assert message < 10
            self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
            self.dut_atltool_wrapper.wait_link_up()

    def test_fw_version(self):
        """Test that register 0x18 contains correct FW version"""
        expected_version = self.get_actual_firmware_version(self.dut_fw_version)
        log.info("Expected FW version: {}".format(expected_version))
        re_fw_ver = re.compile("^((\d+)\.(\d+)\.(\d+)).*", re.DOTALL)
        m = re_fw_ver.match(expected_version)
        if m is None:
            raise Exception("Invalid expected version: {}".format(expected_version))
        ver_high = int(m.group(2))
        ver_mid = int(m.group(3))
        ver_low = int(m.group(4))

        ver_major, ver_minor, ver_release = self.dut_atltool_wrapper.get_fw_version()
        log.info("Actual FW version in reg 0x18: {}.{}.{}".format(ver_major, ver_minor, ver_release))

        assert ver_high == ver_major and ver_mid == ver_minor and ver_low == ver_release

    def test_fw_statistics(self):
        old_tr_id = -1
        expected_host_if_ver = 0x4
        log.info("Expected version in reg 0x360: {}".format(hex(expected_host_if_ver)))

        for i in range(3):
            version, transaction_id = self.dut_atltool_wrapper.get_fw_statistics()
            log.info("(iteration {}) Transaction ID: {}, version: {}".format(i, hex(transaction_id), hex(version)))
            assert version == expected_host_if_ver

            # TODO: uncomment when statistics is enabled again
            # assert transaction_id > old_tr_id

            # TODO: check more fields of statistics structure

            old_tr_id = transaction_id
            time.sleep(0.5)

    def test_phy_heart_bit_in_stats(self):
        if self.dut_fw_ver_maj != 3:
            pytest.skip()
        prov_stat = self.dut_atltool_wrapper.readmem(0x1FB10024, 4)
        hb_chek_on = 0x1FB10000 + prov_stat[0] + 4 * 26
        if self.dut_atltool_wrapper.readmem(hb_chek_on, 4)[0] & 0x1 != 0x1:
            pytest.skip()
        addr_mem = self.dut_atltool_wrapper.readreg(0x360)
        stat = self.dut_atltool_wrapper.readmem(addr_mem, 128)
        heart_bit = stat[19] & 0xFFFF
        hb_phy = self.dut_atltool_wrapper.readphyreg(0x1E, 0xC886)
        assert heart_bit > 0
        assert abs(heart_bit - hb_phy) < 3

    def run_test_link_speed_dut_auto_partner_x(self, speed):
        if self.dut_fw_card in FELICITY_CARDS:
            # Autoneg is not supported on Felicity
            pytest.xfail()
        elif self.lkp_fw_card in FELICITY_CARDS:
            if self.supported_speeds is None:
                raise Exception("Do not know supported speeds on Felicity")
            if speed == LINK_SPEED_AUTO or speed not in self.supported_speeds:
                pytest.xfail()
        else:
            if speed == LINK_SPEED_10G and get_expected_speed(LINK_SPEED_AUTO, self.dut_port) != LINK_SPEED_10G:
                # Is the card is not Felicity and it cannot advertize 10G on autoneg we xfail
                pytest.xfail()

        exp_speed = get_expected_speed(speed, self.dut_port)

        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.wait_link_up()
        link_check_attempts = int(os.environ.get('LINK_CHECKS', self.DEFAULT_LINK_CHECKS))
        for i in range(link_check_attempts):
            log.info('Link check #{}...'.format(i + 1))
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            self.lkp_ifconfig.wait_link_up()
            if speed == LINK_SPEED_AUTO:
                dspeed, dstate_is_up = self.dut_atltool_wrapper.get_link_params_2x_auto(exp_speed)
            else:
                dspeed, dstate_is_up = self.dut_atltool_wrapper.get_link_params_2x()
            log.info('dspeed, dstate_is_up = {}, {}'.format(dspeed, dstate_is_up))
            assert dspeed is not None
            assert dspeed == exp_speed

    def run_test_link_speed_dut_x_partner_auto(self, speed):
        if self.lkp_fw_card in FELICITY_CARDS:
            # Autoneg is not supported on Felicity
            pytest.xfail()
        elif self.dut_fw_card in FELICITY_CARDS:
            if self.supported_speeds is None:
                raise Exception("Do not know supported speeds on Felicity")
            if speed == LINK_SPEED_AUTO or speed not in self.supported_speeds:
                pytest.xfail()
        else:
            if speed == LINK_SPEED_10G and get_expected_speed(LINK_SPEED_AUTO, self.dut_port) == LINK_SPEED_5G:
                # Is the card is not Felicity and it cannot advertize 10G on autoneg we xfail
                pytest.xfail()

        exp_speed = get_expected_speed(speed, self.dut_port)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.set_link_params_2x(speed)
        self.dut_atltool_wrapper.wait_link_up()
        link_check_attempts = int(os.environ.get('LINK_CHECKS', self.DEFAULT_LINK_CHECKS))
        for i in range(link_check_attempts):
            log.info('Link check #{}...'.format(i + 1))
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            pspeed = self.lkp_ifconfig.wait_link_up()
            assert pspeed is not None
            assert pspeed == exp_speed

    def test_link_speed_dut_100m_partner_auto(self):
        self.run_test_link_speed_dut_x_partner_auto(LINK_SPEED_100M)

    def test_link_speed_dut_1g_partner_auto(self):
        self.run_test_link_speed_dut_x_partner_auto(LINK_SPEED_1G)

    def test_link_speed_dut_2_5g_partner_auto(self):
        self.run_test_link_speed_dut_x_partner_auto(LINK_SPEED_2_5G)

    def test_link_speed_dut_5g_partner_auto(self):
        self.run_test_link_speed_dut_x_partner_auto(LINK_SPEED_5G)

    def test_link_speed_dut_10g_partner_auto(self):
        self.run_test_link_speed_dut_x_partner_auto(LINK_SPEED_10G)

    def test_link_speed_dut_auto_partner_auto(self):
        self.run_test_link_speed_dut_x_partner_auto(LINK_SPEED_AUTO)

    def test_link_speed_dut_auto_partner_100m(self):
        self.run_test_link_speed_dut_auto_partner_x(LINK_SPEED_100M)

    def test_link_speed_dut_auto_partner_1g(self):
        self.run_test_link_speed_dut_auto_partner_x(LINK_SPEED_1G)

    def test_link_speed_dut_auto_partner_2_5g(self):
        self.run_test_link_speed_dut_auto_partner_x(LINK_SPEED_2_5G)

    def test_link_speed_dut_auto_partner_5g(self):
        self.run_test_link_speed_dut_auto_partner_x(LINK_SPEED_5G)

    def test_link_speed_dut_auto_partner_10g(self):
        self.run_test_link_speed_dut_auto_partner_x(LINK_SPEED_10G)

    def test_speed_switch_from_100m_to_1g(self):
        self.run_test_speed_switch(LINK_SPEED_100M, LINK_SPEED_1G)

    def test_speed_switch_from_100m_to_2_5g(self):
        self.run_test_speed_switch(LINK_SPEED_100M, LINK_SPEED_2_5G)

    def test_speed_switch_from_100m_to_5g(self):
        self.run_test_speed_switch(LINK_SPEED_100M, LINK_SPEED_5G)

    def test_speed_switch_from_100m_to_auto(self):
        self.run_test_speed_switch(LINK_SPEED_100M, LINK_SPEED_AUTO)

    def test_speed_switch_from_1g_to_2_5g(self):
        self.run_test_speed_switch(LINK_SPEED_1G, LINK_SPEED_2_5G)

    def test_speed_switch_from_1g_to_5g(self):
        self.run_test_speed_switch(LINK_SPEED_1G, LINK_SPEED_5G)

    def test_speed_switch_from_1g_to_10g(self):
        self.run_test_speed_switch(LINK_SPEED_1G, LINK_SPEED_10G)

    def test_speed_switch_from_1g_to_auto(self):
        self.run_test_speed_switch(LINK_SPEED_1G, LINK_SPEED_AUTO)

    def test_speed_switch_from_2_5g_to_5g(self):
        self.run_test_speed_switch(LINK_SPEED_2_5G, LINK_SPEED_5G)

    def test_speed_switch_from_2_5g_to_auto(self):
        self.run_test_speed_switch(LINK_SPEED_2_5G, LINK_SPEED_AUTO)

    def test_speed_switch_from_5g_to_auto(self):
        self.run_test_speed_switch(LINK_SPEED_5G, LINK_SPEED_AUTO)

    def test_speed_switch_from_10g_to_1g(self):
        self.run_test_speed_switch(LINK_SPEED_10G, LINK_SPEED_1G)

    def test_speed_switch_from_100m_to_no_link(self):
        self.run_test_speed_switch_to_no_link(LINK_SPEED_100M)

    def test_speed_switch_from_1g_to_no_link(self):
        self.run_test_speed_switch_to_no_link(LINK_SPEED_1G)

    def test_speed_switch_from_2_5g_to_no_link(self):
        self.run_test_speed_switch_to_no_link(LINK_SPEED_2_5G)

    def test_speed_switch_from_5g_to_no_link(self):
        self.run_test_speed_switch_to_no_link(LINK_SPEED_5G)

    def test_speed_switch_from_10g_to_no_link(self):
        self.run_test_speed_switch_to_no_link(LINK_SPEED_10G)

    def test_control_link_linkdrop(self):
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=False)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.wait_link_up()
        cur_speed = self.dut_atltool_wrapper.get_link_speed_2x()
        assert cur_speed != LINK_SPEED_NO_LINK
        log.info('Link up. Current speed (reg 0x370) = {}'.format(cur_speed))
        self.dut_atltool_wrapper.set_link_control_2x(LINK_CONTROL_LINK_DROP)
        log.info('Link dropped (wrote 0x400000 to 0x36c)')
        self.dut_atltool_wrapper.wait_link_down()
        reg_value = self.dut_atltool_wrapper.get_link_control_2x()
        reg_value = (reg_value & LINK_CONTROL_LINK_DROP)
        assert reg_value != 0
        cur_speed_with_drop = self.dut_atltool_wrapper.get_link_speed_2x()
        log.info('Current speed (reg 0x370) = {}'.format(cur_speed_with_drop))
        assert cur_speed_with_drop == LINK_SPEED_NO_LINK
        self.dut_atltool_wrapper.set_link_control_2x(0)
        log.info('Link drop bit was cleared (bit 0x400000 in reg 0x36c)')
        self.dut_atltool_wrapper.wait_link_up()
        cur_speed_new = self.dut_atltool_wrapper.get_link_speed_2x()
        log.info('Current speed (reg 0x370) = {}'.format(cur_speed_new))
        assert cur_speed_new == cur_speed
        reg_value = self.dut_atltool_wrapper.get_link_control_2x()
        reg_value = (reg_value & LINK_CONTROL_LINK_DROP)
        assert reg_value == 0

    def test_control_link_sleep_proxy(self):
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=False)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
        speed = self.dut_atltool_wrapper.wait_link_up()
        assert speed != LINK_SPEED_NO_LINK

        sleep_proxy_cfg = DrvEthConfig()
        sleep_proxy_cfg.version = 0
        sleep_proxy_cfg.len = 0x407  # not used
        sleep_proxy_cfg.mac = "00:15:00:19:00:77"
        ips = OffloadIpInfo()
        ips.v4_addr_count = 1
        ips.v4_addresses = ["200.200.200.200"]
        ips.v4_masks = [24]
        sleep_proxy_cfg.ips = ips
        sleep_proxy_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY
        beton_file = os.path.join(self.test_log_dir, "sleep_proxy.txt")
        # Next line applies sleep proxy bit automatically
        # self.dut_atltool_wrapper.set_link_control_2x(LINK_CONTROL_SLEEP_PROXY)
        sleep_proxy_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info('Sleep proxy bit was set (bit 0x800000 in reg 0x36c)')
        time.sleep(1)
        reg_value = self.dut_atltool_wrapper.get_link_control_2x()
        assert (reg_value & LINK_CONTROL_SLEEP_PROXY) != 0

        # Link should be UP on link partner
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed != LINK_SPEED_NO_LINK

    def test_control_link_wol(self):
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=False)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.set_link_control_2x(0)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
        speed = self.dut_atltool_wrapper.wait_link_up()
        assert speed != LINK_SPEED_NO_LINK

        wol_cfg = DrvWinWoLConfig()
        wol_cfg.mac = "65:64:63:62:61:60"
        wol_cfg.magic_enabled = True
        wol_cfg.caps = DrvMessage.CAPS_HI_WOL
        beton_file = os.path.join(self.test_log_dir, "wol.txt")
        # Next line applies sleep proxy bit automatically
        # self.dut_atltool_wrapper.set_link_control_2x(LINK_CONTROL_WOL)
        wol_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info('Sleep proxy bit was set (bit 0x1000000 in reg 0x36c)')
        time.sleep(self.LINK_CONTROL_DELAY)
        reg_value = self.dut_atltool_wrapper.get_link_control_2x()
        assert (reg_value & LINK_CONTROL_WOL) != 0

        # Link should be UP on link partner
        speed = self.lkp_ifconfig.wait_link_up()
        assert speed != LINK_SPEED_NO_LINK

    def test_control_link_linkdrop_with_tr_id(self):
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=False)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.set_link_control_2x(0)
        time.sleep(2)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
        cur_speed = self.dut_atltool_wrapper.wait_link_up()
        assert cur_speed != LINK_SPEED_NO_LINK
        log.info('Link up. Current speed = {}'.format(cur_speed))
        self.dut_atltool_wrapper.set_link_control_2x(LINK_CONTROL_LINK_DROP | LINK_CONTROL_TRANSACTION_ID)
        log.info('Link dropped (wrote 0x80400000 to 0x36c)')
        self.dut_atltool_wrapper.wait_link_down()  # To make sure that transaction is cleared
        reg_374 = self.dut_atltool_wrapper.get_link_control_2x()
        tr_id = self.dut_atltool_wrapper.transaction_id_is_set()
        assert (tr_id == 0) and ((reg_374 & LINK_CONTROL_LINK_DROP) != 0)
        cur_speed_drop = self.dut_atltool_wrapper.get_link_speed_2x()
        log.info('Current speed = {}'.format(cur_speed_drop))
        assert cur_speed_drop == LINK_SPEED_NO_LINK
        self.dut_atltool_wrapper.set_link_control_2x(LINK_CONTROL_TRANSACTION_ID)
        log.info('Link drop bit was cleared (bit 0x400000 in reg 0x36c)')
        time.sleep(2)
        assert (self.dut_atltool_wrapper.transaction_id_is_set() == 0)
        cur_speed = self.dut_atltool_wrapper.wait_link_up()
        cur_speed_new = self.dut_atltool_wrapper.get_link_speed_2x()
        log.info('Current speed {}'.format(cur_speed_new))
        log.info('Expected speed = {}'.format(cur_speed))
        assert cur_speed_new == cur_speed
        reg_value = self.dut_atltool_wrapper.get_link_control_2x()
        reg_value = (reg_value & LINK_CONTROL_LINK_DROP)
        assert reg_value == 0

    def test_control_link_sleep_proxy_with_tr_id(self):
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=False)

        def wait_tr_id_is_cleared():
            log.info("Waiting util transaction ID is cleared")
            for i in range(7):
                tr_id = self.dut_atltool_wrapper.transaction_id_is_set()
                if tr_id != 0:
                    time.sleep(1)
                else:
                    break
            else:
                raise Exception("Transaction ID was not cleared")

        sleep_proxy_cfg = DrvEthConfig()
        sleep_proxy_cfg.version = 0
        sleep_proxy_cfg.len = 0x407  # not used
        sleep_proxy_cfg.mac = "00:15:00:19:00:77"
        ips = OffloadIpInfo()
        ips.v4_addr_count = 1
        ips.v4_addresses = ["200.200.200.200"]
        ips.v4_masks = [24]
        sleep_proxy_cfg.ips = ips
        sleep_proxy_cfg.caps = DrvMessage.CAPS_HI_SLEEP_PROXY | LINK_CONTROL_TRANSACTION_ID
        beton_file = os.path.join(self.test_log_dir, "sleep_proxy.txt")
        # Next line applies sleep proxy bit automatically
        # self.dut_atltool_wrapper.set_link_control_2x(LINK_CONTROL_SLEEP_PROXY | LINK_CONTROL_TRANSACTION_ID)
        sleep_proxy_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info('Sleep proxy bit was set (bit 0x80800000 in reg 0x36c)')
        wait_tr_id_is_cleared()
        reg_value = self.dut_atltool_wrapper.get_link_control_2x()
        assert (reg_value & LINK_CONTROL_SLEEP_PROXY) != 0
        self.dut_atltool_wrapper.set_link_control_2x(LINK_CONTROL_TRANSACTION_ID)
        log.info('Sleep proxy bit was cleared (bit 0x800000 in reg 0x36c)')
        wait_tr_id_is_cleared()
        reg_value = self.dut_atltool_wrapper.get_link_control_2x()
        assert (reg_value & LINK_CONTROL_SLEEP_PROXY) == 0

    def test_control_link_wol_with_tr_id(self):
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=False)

        wol_cfg = DrvWinWoLConfig()
        wol_cfg.mac = "65:64:63:62:61:60"
        wol_cfg.magic_enabled = True
        wol_cfg.caps = DrvMessage.CAPS_HI_WOL | LINK_CONTROL_TRANSACTION_ID
        beton_file = os.path.join(self.test_log_dir, "wol.txt")
        # Next line applies sleep proxy bit automatically
        # self.dut_atltool_wrapper.set_link_control_2x(LINK_CONTROL_WOL | LINK_CONTROL_TRANSACTION_ID)
        wol_cfg.apply(self.dut_atltool_wrapper, beton_file)

        log.info('Sleep proxy bit was set (bit 0x81000000 in reg 0x36c)')
        time.sleep(self.LINK_CONTROL_DELAY)
        assert self.dut_atltool_wrapper.transaction_id_is_set() == 0
        reg_value = self.dut_atltool_wrapper.get_link_control_2x()
        assert (reg_value & LINK_CONTROL_WOL) != 0

    def control_link_tpo2(self, no_link, ptp_avb_enabled=False):
        if not no_link:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
            self.dut_atltool_wrapper.wait_link_up()
        reg_value = LINK_CONTROL_PTP_AVB | LINK_CONTROL_TPO2 if ptp_avb_enabled else LINK_CONTROL_TPO2
        self.dut_atltool_wrapper.set_link_control_2x(reg_value)
        log.info('TPO2 bit was set (bit 0x1 in reg 0x36c). PTP/AVB enabled: {}'.format(ptp_avb_enabled))
        time.sleep(self.LINK_CONTROL_DELAY)
        reg_374 = self.dut_atltool_wrapper.readreg(0x374)
        tpo2_enabled = bool(reg_374 & 1)
        log.info("TPO2 ready to be enabled: {}".format(tpo2_enabled))
        assert tpo2_enabled, "TPO2 bit 0 was not set in 0x374 if PTP/AVB enabled"
        if not no_link:
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_NO_LINK)
            self.dut_atltool_wrapper.wait_link_down()
        self.dut_atltool_wrapper.set_link_control_2x(0x0)
        time.sleep(self.LINK_CONTROL_DELAY)
        reg_374 = self.dut_atltool_wrapper.readreg(0x374)
        assert reg_374 == 0, "0x374 was not reset"

    def test_tpo2_no_link_avb_disabled(self):
        self.control_link_tpo2(no_link=True, ptp_avb_enabled=False)

    def test_tpo2_no_link_avb_enabled(self):
        self.control_link_tpo2(no_link=True, ptp_avb_enabled=True)

    def test_tpo2_with_link_avb_disabled(self):
        self.control_link_tpo2(no_link=False, ptp_avb_enabled=False)

    def test_tpo2_with_link_avb_enabled(self):
        self.control_link_tpo2(no_link=False, ptp_avb_enabled=True)

    def test_software_mailbox(self):
        """Test for software mailbox

        Do the following actions in a loop:
        1. Write data DWORD to 0x328.
        2. Write 0x8000NNNN to 0x32c
           (where NNNN is offset of the DWORD to be modified in buffer,
           in bytes, must be aligned and not greater than buffer size).
        3. Set bit 1 in register 0x404:
           self.atltool_wrapper.writereg(0x0404, 0x00000002)
        4. Poll 0x32c till success or error:
            First digit of the DWORD will be changed by FW
            from 8 to 4 if suceeded or to 5-7 for error.
        5. Read memory form the buffer and make sure it was modified.
           Address of the buffer is at the register 0x334.
        """
        log.info('Making clean-up: > writereg 0x36c 0x0')
        self.dut_atltool_wrapper.writereg(0x36c, 0x0)
        time.sleep(1.0)  # give FW some time to detect this action
        snapshot_file = os.path.join(os.path.dirname(__file__), 'fw_2x_snapshot_3k.txt')
        log.info('Snapshot file: {}'.format(snapshot_file))
        expected_data = [0] * 768  # 3KB
        data_dword = None
        with open(snapshot_file, 'r') as f:
            for line in f:
                if not line.startswith('#') and 'writereg' in line:
                    [reg_cmd, register, reg_data] = line.strip().split()
                    if reg_cmd != 'writereg':
                        raise RuntimeError('Incorrect command in the snapshot: {}'.format(reg_cmd))
                    register = int(register, 16)
                    reg_data = int(reg_data, 16)

                    log.info('(MBU) > writereg {} {}'.format(hex(register), hex(reg_data)))
                    self.dut_atltool_wrapper.writereg(register, reg_data)

                    if register == 0x328:
                        data_dword = reg_data
                    elif register == 0x32c:
                        offset = reg_data ^ 0x80000000
                        index = offset // 4
                        if data_dword is None:
                            log.info('Warning! Data dword[{}] is None!'.format(data_dword))
                        else:
                            expected_data[index] = data_dword
                    elif register == 0x404:
                        data_dword = None
                        # poll register 0x32c
                        byte_done = None
                        for i in range(100):
                            reg_value = self.dut_atltool_wrapper.readreg(0x32c)
                            status_byte = int(hex(reg_value).lstrip('0x')[0])
                            if status_byte != 8:
                                byte_done = status_byte
                                break
                            time.sleep(0.01)
                        if byte_done is None:
                            raise RuntimeError(
                                'Register 0x32c value did not change last byte from 8 to finished status')
                        if byte_done == 4:
                            log.info('Mailbox write operation succeed! Status code = 4.')
                        else:
                            msg = 'Mailbox write operation failed! Error code = {}.'.format(byte_done)
                            log.error(msg)
                            raise RuntimeError(msg)

        # read MCP memory to check that FW config is written correctly
        buf_addr = self.dut_atltool_wrapper.readreg(0x334)
        log.info('MCP memory address for FW config data (3KB): {}'.format(hex(buf_addr)))
        data = self.dut_atltool_wrapper.readmem(buf_addr, 3072)  # read 3K config

        # verify the buffer
        log.info('Starting data verification...')
        log.info('len(data) = {}'.format(len(data)))
        log.info('len(expected_data) = {}'.format(len(expected_data)))
        assert len(data) == len(expected_data)
        failures = 0
        for i, dword in enumerate(data):
            log.info('Checking dword[{}]: {}'.format(i, hex(dword)))
            if dword != expected_data[i]:
                log.error('Verification failed! expected dword[{}]: {}'.format(i, hex(expected_data[i])))
                failures += 1
        if failures:
            raise RuntimeError('FW config data is incorrect!')
        log.info('FW config data is correct!')

        # commit FW config
        self.dut_atltool_wrapper.writereg(0x036C, 0x00800000)
        time.sleep(1.0)  # give FW some time to detect this action

    def test_settings_mailbox(self):
        """Test that writing setting into settings mailbox changes that setting in settings memory (in DRAM)"""
        stats_addr = self.dut_atltool_wrapper.readreg(0x360)
        settings_address = self.dut_atltool_wrapper.readmem(stats_addr + FWStatistics.SETTINGS_ADDRESS_OFS, 4)[0]
        settings_length = self.dut_atltool_wrapper.readmem(stats_addr + FWStatistics.SETTINGS_LENGTH_OFS, 4)[0]

        assert settings_length >= 0x90, "FW settings length is too small: 0x{:x}".format(settings_length)

        ofs = 0x0
        while ofs < settings_length:
            # Write random value to settings memory using mailbox
            val = random.randint(0x0001, 0xFFFF)
            SettingsMemory.write_dword(self.dut_atltool_wrapper, ofs, val)

            # Check that value in DRAM changed
            val_dram = self.dut_atltool_wrapper.readmem(settings_address + ofs, 4)[0]
            assert val_dram == val, \
                "FW didn't write setting 0x{:x} to DRAM. Expected 0x{:x}, got 0x{:x}".format(ofs, val, val_dram)

            ofs += 4

    def test_downshift_attempts_config(self):
        """Test that downshift settings are applied correctly (fixed in FW 3.0.98)"""
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip("Can't configure downshift on Felicity")

        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)

        downshift_cfg = DrvDownshiftConfig()
        downshift_cfg.retry_count = 5
        downshift_cfg.caps = DrvMessage.CAPS_HI_DOWNSHIFT
        downshift_cfg.apply(self.dut_atltool_wrapper, cleanup_fw=True)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.wait_link_up()

        phy_dnshft_att = self.dut_atltool_wrapper.readphyreg(0x07, 0xC400) & 0x7
        assert phy_dnshft_att == 5, "MAC FW didn't pass correct downshift attempts to PHY FW"

        # Upload another Drv Downshift message to config memory
        downshift_cfg.retry_count = 3
        downshift_cfg.apply(self.dut_atltool_wrapper, cleanup_fw=False)

        # Link down - up
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_NO_LINK)
        time.sleep(2)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.wait_link_up()

        # Make sure that downshift settings are the same
        phy_dnshft_att = self.dut_atltool_wrapper.readphyreg(0x07, 0xC400) & 0x7
        assert phy_dnshft_att == 5, "MAC FW didn't pass correct downshift attempts to PHY FW"

    def test_settings_eee_autodisable(self):
        """Test that EEE autodisable params are passed from config memory to settings memory"""
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)

        stats_addr = self.dut_atltool_wrapper.readreg(0x360)
        settings_address = self.dut_atltool_wrapper.readmem(stats_addr + FWStatistics.SETTINGS_ADDRESS_OFS, 4)[0]
        settings_length = self.dut_atltool_wrapper.readmem(stats_addr + FWStatistics.SETTINGS_LENGTH_OFS, 4)[0]

        eee_cfg = DrvEEEStateMachineConfig()
        eee_cfg.link_down_timeout = 20000
        eee_cfg.link_up_timeout = 120000
        eee_cfg.max_link_drops = 3
        eee_cfg.feature_mask = self.EEE_STATEMACHINE_MASK[LINK_SPEED_2_5G] | self.EEE_STATEMACHINE_MASK[LINK_SPEED_5G]
        eee_cfg.caps = DrvMessage.CAPS_HI_2P5GBASET_FD_EEE | DrvMessage.CAPS_HI_5GBASET_FD_EEE | \
                       DrvMessage.CAPS_HI_EEE_AUTO_DISABLE
        eee_cfg.apply(self.dut_atltool_wrapper, cleanup_fw=True)

        time.sleep(5)

        lnk_dwn_to = self.dut_atltool_wrapper.readmem(settings_address + FWSettings.EEE_LINK_DOWN_TIMEOUT_OFS, 4)[0]
        lnk_up_to = self.dut_atltool_wrapper.readmem(settings_address + FWSettings.EEE_LINK_UP_TIMEOUT_OFS, 4)[0]
        max_lnk_drps = self.dut_atltool_wrapper.readmem(settings_address + FWSettings.EEE_MAX_LINK_DROPS_OFS, 4)[0]
        feature_msk = self.dut_atltool_wrapper.readmem(settings_address + FWSettings.EEE_RATES_MASK_OFS, 4)[0]

        assert lnk_dwn_to == eee_cfg.link_down_timeout, "FW didn't put Link down timeout into settings memory"
        assert lnk_up_to == eee_cfg.link_up_timeout, "FW didn't put Link up timeout into settings memory"
        assert max_lnk_drps == eee_cfg.max_link_drops, "FW didn't put Max link drops into settings memory"
        assert feature_msk == eee_cfg.feature_mask, "FW didn't put Feature mask into settings memory"

    def test_pfc_settings(self):
        """Test that FW applies PFC settings to MSM registers"""
        pytest.skip("Currently PFC is disabled in provisioning")

        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)

        log.info("Writing PFC Quanta configuration to FW's settings memory")
        cls0_quanta = random.randint(1, 0xFFFF)
        cls1_quanta = random.randint(1, 0xFFFF)
        cls2_quanta = random.randint(1, 0xFFFF)
        cls3_quanta = random.randint(1, 0xFFFF)
        cls4_quanta = random.randint(1, 0xFFFF)
        cls5_quanta = random.randint(1, 0xFFFF)
        cls6_quanta = random.randint(1, 0xFFFF)
        cls7_quanta = random.randint(1, 0xFFFF)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_QUANTA_CLASS_0_OFS, cls0_quanta)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_QUANTA_CLASS_1_OFS, cls1_quanta)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_QUANTA_CLASS_2_OFS, cls2_quanta)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_QUANTA_CLASS_3_OFS, cls3_quanta)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_QUANTA_CLASS_4_OFS, cls4_quanta)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_QUANTA_CLASS_5_OFS, cls5_quanta)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_QUANTA_CLASS_6_OFS, cls6_quanta)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_QUANTA_CLASS_7_OFS, cls7_quanta)

        log.info("Writing PFC Threshold configuration to FW's settings memory")
        cls0_threshold = random.randint(1, 0xFFFF)
        cls1_threshold = random.randint(1, 0xFFFF)
        cls2_threshold = random.randint(1, 0xFFFF)
        cls3_threshold = random.randint(1, 0xFFFF)
        cls4_threshold = random.randint(1, 0xFFFF)
        cls5_threshold = random.randint(1, 0xFFFF)
        cls6_threshold = random.randint(1, 0xFFFF)
        cls7_threshold = random.randint(1, 0xFFFF)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_THRESHOLD_CLASS_0_OFS, cls0_threshold)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_THRESHOLD_CLASS_1_OFS, cls1_threshold)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_THRESHOLD_CLASS_2_OFS, cls2_threshold)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_THRESHOLD_CLASS_3_OFS, cls3_threshold)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_THRESHOLD_CLASS_4_OFS, cls4_threshold)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_THRESHOLD_CLASS_5_OFS, cls5_threshold)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_THRESHOLD_CLASS_6_OFS, cls6_threshold)
        SettingsMemory.write_dword(self.dut_atltool_wrapper, FWSettings.PFC_THRESHOLD_CLASS_7_OFS, cls7_threshold)

        log.info("Enabling PFC in FW's control register")
        self.dut_atltool_wrapper.set_link_control_2x(DrvMessage.CAPS_HI_PFC | DrvMessage.CAPS_HI_PAUSE |
                                                     DrvMessage.CAPS_HI_ASYMMETRIC_PAUSE)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.wait_link_up()

        log.info("Verifying that FW applied settings to MSM")
        msm_pause_control_1 = self.dut_atltool_wrapper.readmsmreg(0x54)
        assert cls0_quanta == msm_pause_control_1 & 0xFFFF
        assert cls1_quanta == (msm_pause_control_1 >> 16) & 0xFFFF
        msm_pause_control_2 = self.dut_atltool_wrapper.readmsmreg(0x58)
        assert cls2_quanta == msm_pause_control_2 & 0xFFFF
        assert cls3_quanta == (msm_pause_control_2 >> 16) & 0xFFFF
        msm_pause_control_3 = self.dut_atltool_wrapper.readmsmreg(0x5C)
        assert cls4_quanta == msm_pause_control_3 & 0xFFFF
        assert cls5_quanta == (msm_pause_control_3 >> 16) & 0xFFFF
        msm_pause_control_4 = self.dut_atltool_wrapper.readmsmreg(0x60)
        assert cls6_quanta == msm_pause_control_4 & 0xFFFF
        assert cls7_quanta == (msm_pause_control_4 >> 16) & 0xFFFF

        msm_pause_control_5 = self.dut_atltool_wrapper.readmsmreg(0x64)
        assert cls0_threshold == msm_pause_control_5 & 0xFFFF
        assert cls1_threshold == (msm_pause_control_5 >> 16) & 0xFFFF
        msm_pause_control_6 = self.dut_atltool_wrapper.readmsmreg(0x68)
        assert cls2_threshold == msm_pause_control_6 & 0xFFFF
        assert cls3_threshold == (msm_pause_control_6 >> 16) & 0xFFFF
        msm_pause_control_7 = self.dut_atltool_wrapper.readmsmreg(0x6C)
        assert cls4_threshold == msm_pause_control_7 & 0xFFFF
        assert cls5_threshold == (msm_pause_control_7 >> 16) & 0xFFFF
        msm_pause_control_8 = self.dut_atltool_wrapper.readmsmreg(0x70)
        assert cls6_threshold == msm_pause_control_8 & 0xFFFF
        assert cls7_threshold == (msm_pause_control_8 >> 16) & 0xFFFF

    def test_smbus_read(self):
        """Test that FW can read data from SMBUS correcty (via FW to host interface)"""
        if self.dut_fw_card not in FELICITY_CARDS:
            pytest.skip("SMBUS operations are supported only for Felicity boards")

        if self.dut_fw_ver_maj != 3:
            pytest.skip("SMBUS operations are supported only for FW 3.x")

        # http://www.schelto.com/sfp/sfp%20msa.pdf (Page 32, Table 3.1)
        # Size of Base ID Fields + Extended ID Fields = 96
        class SfpDataFields(object):
            def __init__(self, list_of_ints):
                data = array.array("L", list_of_ints).tostring()

                self.identifier, self.extIdentifier, self.connector, self.transfer, self.encoding, self.br_nominal, \
                self.reserved1, self.linkLengthFiberKm1, self.linkLengthFiberM100, self.linkLengthFiberM10, \
                self.linkLengthFiberM1, self.linkLengthCopperM1, self.reserved2, self.vendorName, self.reserved3, \
                self.vendorOUI, self.vendorPn, self.vendorRev, self.reserved4, self.cc_base, self.options, \
                self.br_max_percent, self.br_min_percent, self.vendorSn, self.dateCode, self.reserved5, \
                self.cc_ext = struct.unpack("BBB8sBBBBBBBBB16sB3s16s4s3sBHBB16s8s3sB", data)

                self.transfer = struct.unpack("Q", self.transfer)[0]

        SMBUS_SFP_A0_ADDR = 0x50
        SMBUS_SFP_A0_DEVICE_INFO_ADDR = 0x0

        for _ in range(10):
            read_request = FWSmbusReadRequest(SMBUS_SFP_A0_ADDR, SMBUS_SFP_A0_DEVICE_INFO_ADDR, 0x60)
            sfp_a0_data = read_request.request_data(self.dut_atltool_wrapper)

            data_fields = SfpDataFields(sfp_a0_data)

            if data_fields.dateCode[0] != "\x00":
                break

            time.sleep(2)
        else:
            raise Exception("Failed to read SFP A0 data")

        log.info("SFP A0 data: {}".format(data_fields.__dict__))

    def test_default_value_threshold_temp(self):
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip()

        self.dut_atltool_wrapper.kickstart(reload_phy_fw=True)

        # Check default settings
        error_value_threshold = []
        for k, (mmd, addr, default_value) in self.TEMP_THRESHOLD:
            value = self.dut_atltool_wrapper.readphyreg(mmd, addr)
            if value != default_value:
                error_value_threshold.append(k)
        assert len(error_value_threshold) == 0, "Incorrect default value threshold temp: '{}'".format(
            ", ".join(error_value_threshold))

        # Check that feature is disabled
        th_sh_enable = (self.dut_atltool_wrapper.readphyreg(0x1e, 0xc478) & 0x400) >> 0xa
        assert th_sh_enable == 0, "Thermal shutdown is enabled by default!"
        log.info("Thermal shutdown is disabled as expected")

    def test_write_value_threshold_temp(self):
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip()

        self.dut_atltool_wrapper.kickstart(reload_phy_fw=True)

        cfg = DrvThermalShutdownConfig()
        cfg.shutdown_temperature = random.randint(65, 80)
        cfg.warning_temperature = random.randint(50, 65)
        cfg.cold_temperature = random.randint(10, 20)

        beton_file = os.path.join(self.test_log_dir, "thermal_shutdown.txt")
        cfg.apply(self.dut_atltool_wrapper, beton_file)

        thermal_enabled = False
        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time < 1.0:
            lnk_ctrl = self.dut_atltool_wrapper.get_link_control_2x()
            if lnk_ctrl & DrvMessage.CAPS_HI_THERMAL_SHUTDOWN:
                thermal_enabled = True
                log.info("Thermal shutdown enabled")
                break
        if not thermal_enabled:
            raise Exception("Failed to enable thermal shutdown")

        def phy_temp_to_normal(temp):
            return (temp >> 8) & 0xFF

        log.info("Checking applied values")
        shutdown_temperature = self.dut_atltool_wrapper.readphyreg(self.HIGH_TEMP_FAILURE_THRESHOLD[0],
                                                                   self.HIGH_TEMP_FAILURE_THRESHOLD[1])
        shutdown_temperature = phy_temp_to_normal(shutdown_temperature)
        log.info("Requested shutdown temperature: {}, actual: {}".format(cfg.shutdown_temperature,
                                                                         shutdown_temperature))
        try:
            assert cfg.shutdown_temperature == shutdown_temperature
            warning_temperature = self.dut_atltool_wrapper.readphyreg(self.HIGH_TEMP_WARNING_THRESHOLD[0],
                                                                      self.HIGH_TEMP_WARNING_THRESHOLD[1])
            warning_temperature = phy_temp_to_normal(warning_temperature)
            log.info("Requested warning temperature: {}, actual: {}".format(cfg.warning_temperature,
                                                                            warning_temperature))
            assert cfg.warning_temperature == warning_temperature
            cold_temperature = self.dut_atltool_wrapper.readphyreg(self.LOW_TEMP_WARNING_THRESHOLD[0],
                                                                   self.LOW_TEMP_WARNING_THRESHOLD[1])
            cold_temperature = phy_temp_to_normal(cold_temperature)
            log.info("Requested low temperature: {}, actual: {}".format(cfg.cold_temperature, cold_temperature))
            assert cfg.cold_temperature == cold_temperature
        finally:
            self.dut_atltool_wrapper.kickstart(reload_phy_fw=True)

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_link_speed_negotiation(self, speed):
        """
        @description: This subtest performs check that firmware set up correct value of 0x370 register
        for various speed.

        @steps:
        1. Set 10G/5G/2,5G/1G/100M link speed on DUT through 0x368 register.
        2. Check value of 0x370 reg.

        @result: The value of register 0x370 is equal to the expected value.
        """

        if speed not in (self.supported_speeds or []):
            pytest.skip()

        if self.dut_fw_card in FELICITY_CARDS and "DAC" in self.sfp:
            pytest.skip("There is no autoneg on Felicity with DAC cable")

        reg_val = LINK_SPEED_TO_REG_VAL_MAP_2X[speed]
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.dut_atltool_wrapper.writereg(0x368, reg_val)
        time.sleep(1)
        for i in range(15):
            val = self.dut_atltool_wrapper.readreg(0x370) & 0xFFFF
            if val == 0:
                time.sleep(1)
            else:
                if val == reg_val:
                    break
                else:
                    raise Exception("Invalid link speed negotiated")
        else:
            raise Exception("No link")

    def test_link_down_on_lkp(self):
        for speed in self.supported_speeds:
            log.info("Testing speed {}".format(speed))
            if self.lkp_fw_card in FELICITY_CARDS:
                self.lkp_ifconfig.set_link_speed(speed)
            else:
                self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            self.dut_atltool_wrapper.set_link_params_2x(speed)
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.wait_link_down()
            self.dut_atltool_wrapper.wait_link_down()

    def test_default_values(self):
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)

        stats_addr = self.dut_atltool_wrapper.readreg(0x360)
        stgs_addr = self.dut_atltool_wrapper.readmem(stats_addr + FWStatistics.SETTINGS_ADDRESS_OFS, 4)[0]

        log.info("Verifying that FW applied default settings")
        for key, value in self.DEFAULT_SETTING_OFS.items():
            if self.dut_fw_card not in FELICITY_CARDS:
                if key == FWSettings.DAC_CABLE_SERDES_MODES_OFS:
                    log.info("Skipping setting {:#x} for non-Felicity card ...".format(key))
                    continue
            else:
                if key in [FWSettings.DOWNSHIFT_RETRY_COUNT_OFS, FWSettings.THERMAL_SHUTDOWN_OFF_TEMP_OFS,
                           FWSettings.THERMAL_SHUTDOWN_WARNING_TEMP_OFS, FWSettings.THERMAL_SHUTDOWN_COLD_TEMP_OFS,
                           FWSettings.EEE_RATES_MASK_OFS, FWSettings.EEE_MAX_LINK_DROPS_OFS,
                           FWSettings.EEE_LINK_UP_TIMEOUT_OFS, FWSettings.EEE_LINK_DOWN_TIMEOUT_OFS]:
                    log.info("Skipping setting {:#x} for Felicity card ...".format(key))
                    continue
            current_setting = self.dut_atltool_wrapper.readmem(stgs_addr + key, 4)[0]
            assert current_setting == value, \
                "Incorrect default setting at offset {:#x}. Current = {:#x}, expected = {:#x}".format(
                    key, current_setting, value)

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_kickstart_drv_prov_link(self, speed):
        """
        @description: Verify that FW keeps link settings in case of special kickstart.

        @steps:
        1. Set link speed to *speed*. Wait for it to go up.
        2. Start kickstart and stop at driver provisioning part.
        3. Write link control register back to the *speed* value.
        4. Finish kickstart.
        5. Check speed in LKP.

        @result: Speed on LKP is not changed.
        @duration: 1 minute.
        """
        if self.dut_fw_ver_maj != 3:
            pytest.skip()

        if speed not in self.supported_speeds:
            pytest.skip()

        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)

        if self.lkp_fw_card not in FELICITY_CARDS:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        else:
            self.lkp_ifconfig.set_link_speed(speed)

        self.dut_atltool_wrapper.set_link_params_2x(speed)
        self.dut_atltool_wrapper.wait_link_up()

        self.dut_atltool_wrapper.kickstart(reload_phy_fw=False, drv_prov=-1)
        self.dut_atltool_wrapper.writereg(0x368, LINK_SPEED_TO_REG_VAL_MAP_2X[speed])
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=False, drv_prov=1)
        if self.dut_fw_card in FELICITY_CARDS:
            link_speed = self.lkp_ifconfig.wait_link_up()
        else:
            link_speed = self.lkp_ifconfig.get_link_speed()
        assert link_speed == speed, "Link speed changed. Current: {}".format(link_speed)

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    def test_flow_control_mode(self, speed):
        """
        @description: Check flow control mode depend on speed.

        @steps:
        1. Enable Flow Control on DUT.
        2. In loop for each speed in KNOWN_LINK_SPEEDS:
            a. Set link speed and wait for link up.
            b. Read MSM reg 0x8 [8,7]

        @result: Check that 'MSM Pause Ignore' (0x8[8]) and 'MSM Pause Forward' (0x8[7])
        enabled for 100M, 1G "Software Flow Control" and disabled
        for others speeds "Hardware Flow Control".

        @duration: 1 minutes.
        @requirements: FW_FLOW_CONTROL_15
        """
        REG_08_GENERAL_CONTROL = 0x8

        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)
        self.dut_atltool_wrapper.writereg(0x36c, 0x18)
        if speed not in self.supported_speeds:
            pytest.skip("Not supported speed")
        if self.lkp_fw_card not in FELICITY_CARDS:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        else:
            self.lkp_ifconfig.set_link_speed(speed)
        self.dut_atltool_wrapper.set_link_params_2x(speed)
        self.dut_atltool_wrapper.wait_link_up()

        dut_msm_reg_val = self.dut_atltool_wrapper.readmsmreg(REG_08_GENERAL_CONTROL)
        if speed in [LINK_SPEED_100M, LINK_SPEED_1G]:
            expected = 1
        else:
            expected = 0
        assert dut_msm_reg_val >> 8 & 0x1 == expected  # MSM Pause Ignore
        assert dut_msm_reg_val >> 7 & 0x1 == expected  # MSM Pause Forward

    @idparametrize("speed", KNOWN_LINK_SPEEDS)
    @idparametrize("dst", ['multicast', 'unicast'])
    def test_rx_pfm_counters(self, speed, dst):
        """
        @description: Check RX PFM counters for multicast/unicast pause frames.

        @steps:
        1. Enable flow control on DUT.
        2. Send multicast/unicast pause frames from LKP to DUT
        3. Check PFM counters.

        @result: Counters should be equal to count of send pause frame packets.

        @duration: 1 minutes.
        @requirements: FW_FLOW_CONTROL_16
        """
        self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)
        self.dut_atltool_wrapper.writereg(0x36c, 0x18)
        if speed not in self.supported_speeds:
            pytest.skip("Not supported speed")
        if self.lkp_fw_card not in FELICITY_CARDS:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        else:
            self.lkp_ifconfig.set_link_speed(speed)
        self.dut_atltool_wrapper.set_link_params_2x(speed)
        self.dut_atltool_wrapper.wait_link_up()

        # Pause packet
        if dst == 'multicast':
            dst_mac = "01:80:c2:00:00:01"
        elif dst == 'unicast':
            dst_mac = self.dut_atltool_wrapper.get_mac_address()
        else:
            raise Exception('Unknown dst: {}'.format(dst))

        l2 = Ether(
            src="00:00:00:00:00:00",
            dst=dst_mac,
            type=0x8808
        )
        raw = Raw(
            load='\x00\x01'  # operation code
                 '\xff\xff'  # quanta
                 + '\x00' * 42  # padding
        )
        pause_frame_pkt = scapy_pkt_to_aqsendp_str(l2 / raw)

        pause_count = 200
        lkp_aqsendp = Aqsendp(count=pause_count, rate=100, host=self.lkp_hostname, packet=pause_frame_pkt)

        REG_A8_RX_PAUSE_FRAMES = 0x000000A8
        dut_rx_pfm_before = self.dut_atltool_wrapper.readmsmreg(REG_A8_RX_PAUSE_FRAMES)
        lkp_aqsendp.run()
        dut_rx_pfm_after = self.dut_atltool_wrapper.readmsmreg(REG_A8_RX_PAUSE_FRAMES)

        log.info('>>> dut_rx_pfm_before: {}'.format(dut_rx_pfm_before))
        log.info('>>> dut_rx_pfm_after: {}'.format(dut_rx_pfm_after))

        assert dut_rx_pfm_after - dut_rx_pfm_before == pause_count


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
