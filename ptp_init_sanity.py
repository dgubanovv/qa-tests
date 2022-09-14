import os
import tempfile
import time
import timeit

import pytest

from tools.mbuper import download_mbu, MbuWrapper
from infra.test_base import TestBase, idparametrize
from tools.ifconfig import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_NO_LINK, LINK_SPEED_AUTO, LINK_SPEED_10G, LINK_STATE_UP, get_expected_speed
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.utils import get_atf_logger
from tools.lom import LightsOutManagement


log = get_atf_logger()


class PtpTime(object):

    def __init__(self, stamp=0):
        if type(stamp) in [int, long]:
            self.secs = stamp / 10**9
            self.nanosecs = stamp % 10**9
            self.fracNs = 0
            self.fracSec = 0
        else:
            self.secs, self.nanosecs, self.fracNs, self.fracSec = stamp

    def __ne__(self, other):
        if type(other) in [int, long]:
            other = PtpTime(other)
        return self.secs != other.secs \
            or self.nanosecs != other.nanosecs \
            or self.fracNs != other.fracNs \
            or self.fracSec != other.fracSec

    def __eq__(self, other):
        if type(other) in [int, long]:
            other = PtpTime(other)
        return self.secs == other.secs \
            and self.nanosecs == other.nanosecs \
            and self.fracNs == other.fracNs \
            and self.fracSec == other.fracSec

    def __gt__(self, other):
        if type(other) in [int, long]:
            other = PtpTime(other)
        if self.secs * 10**9 + self.nanosecs == other.secs * 10**9 + other.nanosecs:
            return self.fracNs > other.fracNs
        return self.secs * 10**9 + self.nanosecs > other.secs * 10**9 + other.nanosecs

    def __lt__(self, other):
        if type(other) in [int, long]:
            other = PtpTime(other)
        if self.secs * 10**9 + self.nanosecs == other.secs * 10**9 + other.nanosecs:
            return self.fracNs < other.fracNs
        return self.secs * 10**9 + self.nanosecs < other.secs * 10**9 + other.nanosecs

    def __add__(self, other):
        if type(other) in [int, long]:
            other = PtpTime(other)
        return PtpTime((
            self.secs + other.secs,
            self.nanosecs + other.nanosecs,
            self.fracNs + other.fracNs,
            self.fracSec + other.fracSec
        ))

    def __sub__(self, other):
        if type(other) in [int, long]:
            other = PtpTime(other)
        return PtpTime((
            self.secs - other.secs,
            self.nanosecs - other.nanosecs,
            self.fracNs - other.fracNs,
            self.fracSec - other.fracSec
        ))

    def __repr__(self):
        return "{} sec, {} nsec, {} fracNsec, {} fracSec".format(self.secs,
                                                                 str.zfill(str(self.nanosecs), 9),
                                                                 str.zfill(str(self.fracNs), 9),
                                                                 self.fracSec)


def setup_module(module):
    os.environ["TEST"] = "ptp_sanity"


class TestPtpSanity(TestBase):
    mbu_wrapper = None
    CAPS_HI_PTP_AVB_EN = 0x100000
    STATUS_CHANGE_TIMEOUT = 10
    ENABLE_DISABLE_CNT = 3
    PHY_COUNTER_INIT_TIMEOUT = 4
    one_sec_time = PtpTime((1, 0, 0, 0))

    @classmethod
    def setup_class(cls):
        super(TestPtpSanity, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.install_firmwares()
            # Install drivers
            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.dut_driver.install()

            cls.supported_speeds = os.environ.get("SUPPORTED_SPEEDS", "AUTO,100M,1G,2.5G,5G,10G").split(',')

            cls.mbu_dir = download_mbu(cls.mbu_version, cls.working_dir)
            cls.log_local_dir = os.path.join(cls.mbu_dir, "logs")

            log.info("Initializing MBU wrapper")
            cls.mbu_wrapper = MbuWrapper(mbu_dir=cls.mbu_dir, port=cls.dut_port)
            cls.mac_ptp_control = cls.mbu_wrapper.mac_control.macPhyControl.ptp
            cls.phy_ptp_control = cls.mbu_wrapper.mac_control.phyControl.ptpControl
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestPtpSanity, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)

    def teardown_method(self, method):
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        self.mbu_wrapper.set_link_params_2x(LINK_SPEED_NO_LINK)

    def read_phy_timestamp(self):
        self.mbu_wrapper.mac_control.aquireSemaphore(0)
        self.mbu_wrapper.mac_control.aquireSemaphore(1)
        self.mbu_wrapper.writereg(0x404, 0xe1, silent=True)
        phy_timestamp = PtpTime(self.phy_ptp_control.readPtpTimeStamp())
        self.mbu_wrapper.writereg(0x404, 0xe0, silent=True)
        self.mbu_wrapper.mac_control.releaseSemaphore(1)
        self.mbu_wrapper.mac_control.releaseSemaphore(0)
        return phy_timestamp

    def read_mac_timestamp(self):
        self.mbu_wrapper.mac_control.aquireSemaphore(1)
        mac_timestamp = PtpTime(self.mac_ptp_control.readPtpTimeStamp())
        self.mbu_wrapper.mac_control.releaseSemaphore(1)
        return mac_timestamp

    def read_time_from_reg(self):
        self.mbu_wrapper.mac_control.aquireSemaphore(1)
        gen_ts0_lsw = self.mbu_wrapper.readreg(0x310)
        gen_ts0_msw = self.mbu_wrapper.readreg(0x314)
        time.sleep(0.001)
        gen_ts1_lsw = self.mbu_wrapper.readreg(0x310)
        gen_ts1_msw = self.mbu_wrapper.readreg(0x314)
        self.mbu_wrapper.mac_control.releaseSemaphore(1)
        gen_ts0_msw = gen_ts1_msw if (gen_ts0_lsw < gen_ts1_lsw) else gen_ts0_msw
        return PtpTime(gen_ts0_lsw + (gen_ts0_msw << 32))

    def check_link_status(self, dut_speed):
        if dut_speed != LINK_SPEED_NO_LINK:
            speed, status = self.mbu_wrapper.get_link_params_2x()
            assert status, "Link is DOWN, but must be UP"
            if dut_speed != LINK_SPEED_AUTO:
                assert dut_speed == speed, "Expected speed {} != actual speed {}".format(dut_speed, speed)

    def wait_change_status(self, expected_enable, timeout=STATUS_CHANGE_TIMEOUT, retry_interval=0.5):
        start = time.clock()
        while time.clock() - start < timeout:
            time.sleep(retry_interval)
            status = self.mbu_wrapper.readreg(0x374)
            if expected_enable:
                if status & self.CAPS_HI_PTP_AVB_EN:
                    return True
            else:
                if not status & self.CAPS_HI_PTP_AVB_EN:
                    return True
        if expected_enable:
            raise Exception('PTP still disabled after timeout = {} sec.'.format(timeout))
        else:
            raise Exception('PTP still enabled after timeout = {} sec.'.format(timeout))

    @idparametrize("dut_speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G,
                                 LINK_SPEED_5G, LINK_SPEED_AUTO, LINK_SPEED_10G])
    @idparametrize("en", ["before_link_up", "after_link_up"])
    def test_init(self, dut_speed, en):
        if dut_speed == LINK_SPEED_10G and get_expected_speed(LINK_SPEED_AUTO, self.dut_port) != LINK_SPEED_10G:
            pytest.skip()
        log.info("Disable ptp...")
        self.mbu_wrapper.mac_control.mcpControl.enablePtp(enable=False)
        when_enable = en

        if when_enable == "before_link_up":
            log.info("Enabling Ptp...")
            self.mbu_wrapper.writereg(0x36C, self.CAPS_HI_PTP_AVB_EN)
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            self.mbu_wrapper.set_link_params_2x(dut_speed)
            if dut_speed == LINK_SPEED_AUTO:
                self.lkp_ifconfig.wait_link_up(10)
            self.wait_change_status(expected_enable=True)
            self.check_link_status(dut_speed)
        else:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            self.mbu_wrapper.set_link_params_2x(dut_speed)
            if dut_speed == LINK_SPEED_AUTO:
                self.lkp_ifconfig.wait_link_up(10)
            log.info("Enabling Ptp...")
            self.mbu_wrapper.writereg(0x36C, self.CAPS_HI_PTP_AVB_EN)
            self.wait_change_status(expected_enable=True)
            self.check_link_status(dut_speed)

        max_clock_time = self.one_sec_time + PtpTime((4, 0, 0, 0))

        # check that ptp clock resets
        phy_timestamp = self.read_phy_timestamp()
        log.info('PHY PTP clock = {}'.format(phy_timestamp))
        assert phy_timestamp != 0, "PHY clock is zero: {}".format(phy_timestamp)
        assert phy_timestamp < max_clock_time, "PHY clock did`t reset: {}".format(phy_timestamp)

        mac_timestamp = self.read_mac_timestamp()
        log.info('MAC PTP clock = {}'.format(mac_timestamp))
        assert mac_timestamp != 0, "MAC clock is zero: {}".format(mac_timestamp)
        assert mac_timestamp < max_clock_time, "MAC clock did`t reset: {}".format(mac_timestamp)
        previous_mac_timestamp = mac_timestamp
        for _ in range(10):
            phy_timestamp = self.read_phy_timestamp()
            log.info('PHY PTP clock = {}'.format(phy_timestamp))
            assert phy_timestamp > previous_mac_timestamp, \
                "PHY PTP clock: {} < previous MAC PTP clock: {}".format(phy_timestamp, previous_mac_timestamp)
            mac_timestamp = self.read_mac_timestamp()
            log.info('MAC PTP clock = {}'.format(mac_timestamp))
            assert phy_timestamp < mac_timestamp, \
                "PHY PTP clock: {} > MAC PTP clock: {}".format(phy_timestamp, mac_timestamp)
            previous_mac_timestamp = mac_timestamp

    def test_ptp_rr_arbitration(self):
        """
        @description: Check Round Robin TX packet scheduler arbitration.

        @steps:
        1. Set link speed and wait link up.
        2. Disable ptp.
        3. Check that ptp disabled.
        4. Check Round Robin TX packet scheduler arbitration is used(in 0x7100.0 register the value is 0).

        @result: Round Robin TX packet scheduler arbitration is used.
        @duration: 30 seconds.
        @requirements: FW_PTP_1
        """
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.mbu_wrapper.set_link_params_2x(LINK_SPEED_100M)
        self.lkp_ifconfig.wait_link_up(10)
        log.info("Disable ptp...")
        self.mbu_wrapper.mac_control.mcpControl.enablePtp(enable=False)
        self.lkp_ifconfig.wait_link_up(10)  # enablePtp writes CAPS_HI_TRANSACTION_ID it causes link reneg
        self.wait_change_status(expected_enable=False)
        ver_major, ver_minor, ver_release = self.mbu_wrapper.get_fw_version()
        if ver_major == 2:
            assert self.mbu_wrapper.readreg(0x7100) & 0x1 == 0x1
        else:
            assert self.mbu_wrapper.readreg(0x7100) & 0x1 == 0x0

    def test_ptp_wsp_arbitration(self):
        """
        @description: Check Weighted-Strict Priority TX packet scheduler arbitration.

        @steps:
        1. Set link speed and wait link up.
        2. Enable ptp.
        3. Check that ptp enabled.
        4. Check Weighted-Strict Priority TX packet scheduler arbitration is used(in 0x7100.0 register the value is 1).

        @result: Weighted-Strict Priority TX packet scheduler arbitration is used.
        @duration: 30 seconds.
        @requirements: FW_PTP_2
        """
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.mbu_wrapper.set_link_params_2x(LINK_SPEED_100M)
        self.lkp_ifconfig.wait_link_up(10)
        log.info("Enable ptp...")
        self.mbu_wrapper.mac_control.mcpControl.enablePtp(enable=True)
        self.wait_change_status(expected_enable=True)
        self.lkp_ifconfig.wait_link_up(10)
        assert self.mbu_wrapper.readreg(0x7100) & 0x1 == 0x1

    @idparametrize("dut_speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G,
                                 LINK_SPEED_5G, LINK_SPEED_AUTO, LINK_SPEED_10G, LINK_SPEED_NO_LINK])
    def test_enable_disable(self, dut_speed):
        if dut_speed == LINK_SPEED_10G and get_expected_speed(LINK_SPEED_AUTO, self.dut_port) != LINK_SPEED_10G:
            pytest.skip()

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.mbu_wrapper.set_link_params_2x(dut_speed)

        if dut_speed != LINK_SPEED_NO_LINK:
            self.lkp_ifconfig.wait_link_up(10)

        for _ in range(self.ENABLE_DISABLE_CNT):
            log.info("Disable ptp...")
            self.mbu_wrapper.mac_control.mcpControl.enablePtp(enable=False)
            if dut_speed != LINK_SPEED_NO_LINK:
                self.lkp_ifconfig.wait_link_up(10)  # enablePtp writes CAPS_HI_TRANSACTION_ID it causes link reneg
            self.wait_change_status(expected_enable=False)
            self.check_link_status(dut_speed)
            log.info("Enable ptp...")
            self.mbu_wrapper.mac_control.mcpControl.enablePtp(enable=True)
            if dut_speed == LINK_SPEED_NO_LINK:
                self.wait_change_status(expected_enable=False)  # Shouldn't be enabled without link detected
            else:
                self.lkp_ifconfig.wait_link_up(10)
                self.wait_change_status(expected_enable=True)
            self.check_link_status(dut_speed)

    @idparametrize("dut_speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G,
                                 LINK_SPEED_5G, LINK_SPEED_AUTO, LINK_SPEED_10G, LINK_SPEED_NO_LINK])
    def test_enable_disable_via_reg(self, dut_speed):
        if dut_speed != LINK_SPEED_NO_LINK and dut_speed not in self.supported_speeds:
            pytest.skip()

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.mbu_wrapper.set_link_params_2x(dut_speed)

        if dut_speed != LINK_SPEED_NO_LINK:
            self.lkp_ifconfig.wait_link_up(10)

        for _ in range(self.ENABLE_DISABLE_CNT):
            log.info("Disable ptp...")
            self.mbu_wrapper.writereg(0x36C, 0x0)
            self.wait_change_status(expected_enable=False)
            self.check_link_status(dut_speed)
            # check that CAPS_HI_PTP_AVB_EN bit disabled in 0x374 reg
            log.info("Enable ptp...")
            self.mbu_wrapper.writereg(0x36C, self.CAPS_HI_PTP_AVB_EN)
            if dut_speed == LINK_SPEED_NO_LINK:
                self.wait_change_status(expected_enable=False)  # Shouldn't be enabled without link detected
            else:
                self.wait_change_status(expected_enable=True)
            self.check_link_status(dut_speed)

    @idparametrize("dut_speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G,
                                 LINK_SPEED_5G, LINK_SPEED_AUTO, LINK_SPEED_10G])
    def test_sync(self, dut_speed):
        if dut_speed == LINK_SPEED_10G and get_expected_speed(LINK_SPEED_AUTO, self.dut_port) != LINK_SPEED_10G:
            pytest.skip()
        ERR_CNT = 0
        print_count = 1
        log.info("Test time sync between MAC & PHY for a long time")
        test_time = 60
        start_time = timeit.default_timer()
        previous_mac_timestamp = PtpTime(0)

        log.info("restart ptp counters")
        self.mbu_wrapper.mac_control.mcpControl.enablePtp(enable=False)
        self.mbu_wrapper.mac_control.mcpControl.enablePtp(enable=True)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.mbu_wrapper.set_link_params_2x(dut_speed)
        if dut_speed != LINK_SPEED_NO_LINK:
            self.lkp_ifconfig.wait_link_up(10)

        # mac/phy counter initialization takes some time
        time.sleep(self.PHY_COUNTER_INIT_TIMEOUT)

        self.wait_change_status(expected_enable=True)

        log.info("start reading...")
        while timeit.default_timer() - start_time < test_time:
            print_count += 1
            phy_timestamp = self.read_phy_timestamp()
            if print_count % 1000 == 0:
                log.info('PHY PTP clock = {}'.format(phy_timestamp))
            assert previous_mac_timestamp < phy_timestamp, \
                "previous MAC PTP clock: {} > PHY PTP clock: {}".format(previous_mac_timestamp, phy_timestamp)
            mac_timestamp = self.read_mac_timestamp()
            # retry only if previous nanosec > 900000000 BUG
            if previous_mac_timestamp > mac_timestamp and previous_mac_timestamp.nanosecs / 10**8 == 9:
                time.sleep(0.5)
                log.info("retry reading mac time because second not increased: ")
                log.info("previous MAC PTP clock: {}".format(previous_mac_timestamp))
                log.info("current MAC PTP clock: {}".format(mac_timestamp))
                mac_timestamp = self.read_mac_timestamp()
                ERR_CNT += 1
            if print_count % 1000 == 0:
                log.info('MAC PTP clock = {}'.format(mac_timestamp))
            assert phy_timestamp < mac_timestamp, \
                "PHY PTP clock: {} > MAC PTP clock: {}".format(phy_timestamp, mac_timestamp)
            previous_mac_timestamp = mac_timestamp
        log.info("Retries count = {}".format(ERR_CNT))

    @idparametrize("dut_speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G,
                                 LINK_SPEED_5G, LINK_SPEED_AUTO, LINK_SPEED_10G])
    def test_sync_reg(self, dut_speed):
        if dut_speed == LINK_SPEED_10G and get_expected_speed(LINK_SPEED_AUTO, self.dut_port) != LINK_SPEED_10G:
            pytest.skip()
        ERR_CNT = 0
        print_count = 1
        log.info("Test time sync between MAC & PHY for a long time")
        test_time = 60
        start_time = timeit.default_timer()
        previous_mac_timestamp = PtpTime(0)

        log.info("restart ptp counters")
        self.mbu_wrapper.mac_control.mcpControl.enablePtp(enable=False)
        self.mbu_wrapper.mac_control.mcpControl.enablePtp(enable=True)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.mbu_wrapper.set_link_params_2x(dut_speed)
        if dut_speed != LINK_SPEED_NO_LINK:
            self.lkp_ifconfig.wait_link_up(10)

        self.wait_change_status(expected_enable=True)

        # mac/phy counter initialization takes some time
        time.sleep(self.PHY_COUNTER_INIT_TIMEOUT)

        log.info("start reading clocks: MAC -> PHY")
        while timeit.default_timer() - start_time < test_time:
            print_count += 1
            phy_timestamp = self.read_phy_timestamp()
            if print_count % 1000 == 0:
                log.info('PHY PTP clock = {}'.format(phy_timestamp))
            assert previous_mac_timestamp < phy_timestamp, \
                "previous MAC PTP clock: {} > PHY PTP clock: {}".format(previous_mac_timestamp, phy_timestamp)
            mac_timestamp = self.read_time_from_reg()
            if mac_timestamp - phy_timestamp > self.one_sec_time:
                time.sleep(0.5)
                log.info("retry reading mac time: ")
                log.info("previous MAC PTP clock: {}".format(phy_timestamp))
                log.info("current MAC PTP clock: {}".format(mac_timestamp))
                mac_timestamp = self.read_time_from_reg()
                ERR_CNT += 1
            if print_count % 1000 == 0:
                log.info('MAC PTP clock = {}'.format(mac_timestamp))
            assert phy_timestamp < mac_timestamp, \
                "PHY PTP clock: {} > MAC PTP clock: {}".format(phy_timestamp, mac_timestamp)
            previous_mac_timestamp = mac_timestamp
        log.info("Retries count = {}".format(ERR_CNT))

    def test_mcp_clock_reg(self):
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.mbu_wrapper.set_link_params_2x(LINK_SPEED_100M)
        test_time = 120
        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time < test_time:
            mac_timestamp = self.read_mac_timestamp()
            log.info('MAC PTP clock = {}'.format(mac_timestamp))
            reg_timestamp = self.read_time_from_reg()
            log.info('Reg MAC PTP clock = {}'.format(reg_timestamp))
            assert reg_timestamp > mac_timestamp


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
