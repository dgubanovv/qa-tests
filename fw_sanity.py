import copy
import os
import timeit

import pytest
import re
from shutil import copyfile, move
import time
import tempfile

import tools.mbuper
from tools.atltoolper import AtlTool
from tools.constants import LINK_STATE_UP, LINK_STATE_DOWN, FELICITY_CARDS, LINK_SPEED_100M, LINK_SPEED_1G, \
    LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_NO_LINK, LINK_SPEED_AUTO
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.ifconfig import get_expected_speed
from infra.test_base import TestBase, idparametrize
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_sanity"


class TestFwSanity(TestBase):
    mbu_wrapper = None
    DEFAULT_LINK_CHECKS = 3
    AFTER_LINK_UP_DELAY = 40

    @classmethod
    def setup_class(cls):
        super(TestFwSanity, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            log.info("Initializing MBU wrapper")
            cls.mbu_dir = tools.mbuper.download_mbu(cls.mbu_version, cls.working_dir)
            cls.mbu_wrapper = tools.mbuper.MbuWrapper(mbu_dir=cls.mbu_dir, port=cls.dut_port)
            cls.log_local_dir = os.path.join(cls.mbu_dir, "logs")

            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestFwSanity, self).setup_method(method)
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.atltool_wrapper.debug_buffer_enable(True)

    def teardown_method(self, method):
        super(TestFwSanity, self).teardown_method(method)
        if self.MCP_LOG:
            self.atltool_wrapper.debug_buffer_enable(False)
            move(self.bin_log_file, self.test_log_dir)
            move(self.txt_log_file, self.test_log_dir)

    def copy_config(self, config):
        test_dir = os.path.join(TestBase.log_local_dir, self.state.current_test_norm)
        copyfile(os.path.join("tools/beton", config), os.path.join(test_dir, os.path.basename(config)))

    def test_fw_version(self):
        """Test that register 0x18 contains correct FW version"""
        expected_version = self.get_actual_firmware_version(self.dut_fw_version)
        log.info("Expected FW version: {}".format(expected_version))
        re_fw_ver = re.compile("^((\d+)\.(\d+)\.(\d+))$")
        m = re_fw_ver.match(expected_version)
        if m is None:
            raise Exception("Invalid expected version: {}".format(expected_version))
        ver_high = int(m.group(2))
        ver_mid = int(m.group(3))
        ver_low = int(m.group(4))

        ver_major, ver_minor, ver_release = self.mbu_wrapper.get_fw_version()
        log.info("Actual FW version in reg 0x18: {}.{}.{}".format(ver_major, ver_minor, ver_release))

        assert ver_high == ver_major and ver_mid == ver_minor and ver_low == ver_release

    def test_time_link_up_less_10sec(self):
        log.info('Link up and wait')

        wait_time = 10
        count_tests = 10

        report_downshift_0 = []
        report_downshift_auto = []

        if self.supported_speeds is not None:
            speeds_to_test = copy.deepcopy(self.supported_speeds)
        else:
            speeds_to_test = [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G]
            if get_expected_speed(LINK_SPEED_AUTO, self.dut_port) == LINK_SPEED_10G:
                speeds_to_test.append(LINK_SPEED_10G)
        if self.dut_fw_card not in FELICITY_CARDS:
            speeds_to_test.append(LINK_SPEED_AUTO)

        for down in [0, 7]:
            for i in range(count_tests):
                times = {}
                log.info('Iteration downshift:{}    {:2d}/{}'.format(down, i + 1, count_tests))
                for speed in self.speeds_to_test:

                    log.info('Link down and sleep 1 secs')
                    self.mbu_wrapper.set_link_params(LINK_SPEED_NO_LINK, tools.mbuper.LINK_STATE_DOWN, 0)
                    time.sleep(1)

                    log.info('Try link up: {}'.format(speed))

                    start = timeit.default_timer()
                    try:
                        self.mbu_wrapper.set_link_params(speed, tools.mbuper.LINK_STATE_UP, down)
                    except Exception:
                        pass
                    time_linkup_in_ms = (timeit.default_timer() - start) * 1000
                    times[speed] = time_linkup_in_ms

                    log.info('Time link up is: {:.1f} ms'.format(time_linkup_in_ms))
                    assert time_linkup_in_ms < (wait_time * 1000), "It's very slow"

                if down == 0:
                    report_downshift_0.append(times)
                else:
                    report_downshift_auto.append(times)

        log.info('Report:')
        log.info('-' * 80)

        msg = ' {:6s} '.format('N')
        for speed in speeds_to_test:
            msg += '| {:^10s} '.format(speed)

        log.info(msg)
        log.info('-' * 80)
        log.info('downshift: 0')
        log.info('-' * 80)

        for i in range(count_tests):
            msg = ' {:6d} '.format(i + 1)
            for speed in speeds_to_test:
                msg += '| {:7.1f} ms '.format(report_downshift_0[i][speed])
            log.info(msg)
        log.info('-' * 80)
        log.info('downshift: AUTO(7)')
        log.info('-' * 80)
        for i in range(count_tests):
            msg = ' {:6d} '.format(i + 1)
            for speed in speeds_to_test:
                msg += '| {:7.1f} ms '.format(report_downshift_auto[i][speed])
            log.info(msg)
        log.info('-' * 80)

    def test_fw_statistics(self):
        old_tr_id = -1
        expected_host_if_ver = 0x4
        log.info("Expected version in reg 0x360: {}".format(hex(expected_host_if_ver)))

        for i in range(3):
            version, transaction_id = self.mbu_wrapper.get_fw_statistics()
            log.info("(iteration {}) Transaction ID: {}, version: {}".format(i, hex(transaction_id), hex(version)))
            assert version == expected_host_if_ver
            assert transaction_id > old_tr_id
            old_tr_id = transaction_id
            time.sleep(0.5)

    @idparametrize("dut_speed", [
        LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G,
        LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_AUTO
    ])
    def test_link_speed_dut_x_partner_auto(self, dut_speed):
        if dut_speed != LINK_SPEED_AUTO and dut_speed not in self.supported_speeds:
            pytest.skip()
        elif dut_speed == LINK_SPEED_AUTO and self.dut_fw_card in FELICITY_CARDS:
            pytest.skip()

        exp_speed = get_expected_speed(dut_speed, self.dut_port)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.mbu_wrapper.set_link_params(dut_speed, tools.mbuper.LINK_STATE_UP)

        link_check_attempts = int(os.environ.get("LINK_CHECKS", self.DEFAULT_LINK_CHECKS))
        for i in range(link_check_attempts):
            log.info("Link check #{}...".format(i + 1))
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            pspeed = self.lkp_ifconfig.wait_link_up()
            assert pspeed is not None
            assert pspeed == exp_speed
            log.info("Iteration {}: OK".format(i))

    @idparametrize("lkp_speed", [
        LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G,
        LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_AUTO
    ])
    def test_link_speed_dut_auto_partner_x(self, lkp_speed):
        if lkp_speed not in self.supported_speeds:
            pytest.skip()

        exp_speed = get_expected_speed(lkp_speed, self.dut_port)

        self.lkp_ifconfig.set_link_speed(lkp_speed)
        self.mbu_wrapper.set_link_params(LINK_SPEED_AUTO,
                                         tools.mbuper.LINK_STATE_UP)

        link_check_attempts = int(os.environ.get('LINK_CHECKS', self.DEFAULT_LINK_CHECKS))
        for i in range(link_check_attempts):
            log.info("Link check #{}...".format(i + 1))
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            self.lkp_ifconfig.wait_link_up()
            _, dspeed, dstate = self.mbu_wrapper.get_link_params()
            log.info("dspeed = {}, dstate = {}".format(dspeed, dstate))
            assert dspeed is not None
            assert dspeed == exp_speed
            log.info("Iteration {}: OK".format(i))

    def generate_pair(l):
        pair = []
        for i, e in enumerate(l):
            for el in l[i + 1:]:
                pair.append((e, el))
        return pair

    @idparametrize(("from_", "to"), generate_pair([LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G,
                                                   LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_AUTO]))
    def test_speed_switch(self, from_, to):
        if from_ not in self.supported_speeds or to not in self.supported_speeds:
            pytest.skip()

        exp_from_speed = get_expected_speed(from_, self.dut_port)
        exp_to_speed = get_expected_speed(to, self.dut_port)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

        link_check_attempts = 1  # int(os.environ.get('LINK_CHECKS', self.DEFAULT_LINK_CHECKS))
        for i in range(link_check_attempts):
            log.info("Link check #{}...".format(i + 1))
            self.mbu_wrapper.set_link_params(from_, tools.mbuper.LINK_STATE_UP)
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            pspeed = self.lkp_ifconfig.wait_link_up()
            assert pspeed is not None
            assert pspeed == exp_from_speed

            self.mbu_wrapper.set_link_params(to, tools.mbuper.LINK_STATE_UP)
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
            pspeed = self.lkp_ifconfig.wait_link_up()
            assert pspeed is not None
            assert pspeed == exp_to_speed

            log.info("Iteration {}: OK".format(i))

    def test_sleep_mode(self):
        speed = LINK_SPEED_AUTO if self.dut_fw_card in FELICITY_CARDS else LINK_SPEED_1G

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.mbu_wrapper.set_link_params(speed, tools.mbuper.LINK_STATE_UP)

        time.sleep(self.LINK_CONFIG_DELAY)

        self.mbu_wrapper.set_link_params(speed, tools.mbuper.LINK_STATE_SLEEP)

        time.sleep(self.LINK_CONFIG_DELAY)
        _, dspeed, dstate = self.mbu_wrapper.get_link_params()

        assert dstate == tools.mbuper.LINK_STATE_SLEEP

    def test_efuse(self):
        efuse = self.mbu_wrapper.get_efuse()
        assert efuse != 0

    def test_ping_lwip(self):
        self.mbu_wrapper.kickstart()  # Clean up FW

        dut_ip = "169.254.1.1"
        lkp_ip = "169.254.0.100"
        netmask = "255.255.0.0"

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_ip_address(lkp_ip, netmask, None)

        beton_file = "testFW/offloads/sanity/ping_offload_lwip_enable.txt"
        self.copy_config(beton_file)
        self.mbu_wrapper.exec_txt(beton_file)

        for speed in self.supported_speeds:
            log.info("Ping LWIP on {} speed".format(speed))
            self.mbu_wrapper.set_link_params(speed, tools.mbuper.LINK_STATE_UP, 0)
            assert self.lkp_ifconfig.wait_link_up() != LINK_SPEED_NO_LINK, "DUT didn't set up link"

            time.sleep(self.AFTER_LINK_UP_DELAY)

            assert self.ping(from_host=self.lkp_hostname, to_host=dut_ip, number=10, ipv6=False, src_addr=lkp_ip), \
                "Failed to ping {} from {}".format(dut_ip, lkp_ip)

    def test_ns_ipv6_offload(self):
        self.mbu_wrapper.kickstart()  # Clean up FW

        DUT_IPV6_1 = "4000::1234:1234:1185"
        DUT_IPV6_2 = "4000::1234:1234:0146"
        LKP_IPV6 = "4000::1234:1234:1000"
        LKP_IPV6_PREFIX = "64"

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_ipv6_address(LKP_IPV6, LKP_IPV6_PREFIX, None)

        beton_file = "testFW/offloads/sanity/ping_ipv6_ns_offload.txt"
        self.copy_config(beton_file)
        self.mbu_wrapper.set_link_params(LINK_SPEED_NO_LINK, tools.mbuper.LINK_STATE_DOWN, 0)
        time.sleep(5)  # Give FW some time to reset
        self.mbu_wrapper.exec_txt(beton_file)

        for speed in self.supported_speeds:
            log.info("Pinging DUT on {} speed".format(speed))
            self.mbu_wrapper.set_link_params(speed, tools.mbuper.LINK_STATE_UP, 0)
            assert self.lkp_ifconfig.wait_link_up() != LINK_SPEED_NO_LINK, "DUT didn't set up link"

            time.sleep(self.AFTER_LINK_UP_DELAY)

            assert self.ping(from_host=self.lkp_hostname, to_host=DUT_IPV6_1, number=10, ipv6=True,
                             src_addr=LKP_IPV6), \
                "Failed to ping DUT address {} from {}".format(DUT_IPV6_1, LKP_IPV6)
            assert self.ping(from_host=self.lkp_hostname, to_host=DUT_IPV6_2, number=10, ipv6=True,
                             src_addr=LKP_IPV6), \
                "Failed to ping DUT address {} from {}".format(DUT_IPV6_2, LKP_IPV6)

    # def test_msm_settings(self):
    #     iface_addr = int(self.mbu_wrapper.readreg(0x334))
    #     self.mbu_wrapper.writereg_mcp(iface_addr, 11)
    #     msm_settings_addr = iface_addr + 4
    #     for i in range(1, 10):
    #         self.mbu_wrapper.writereg_mcp(msm_settings_addr, i)
    #
    #     id1 = self.mbu_wrapper.readreg(0x33c)
    #     id1 += 1
    #     self.mbu_wrapper.writereg(0x338, id1)
    #     time.sleep(3)
    #     id2 = self.mbu_wrapper.readreg(0x33c)
    #     assert id1 == id2, "Transaction id is not incremented by 1"
    #
    #     self.mbu_wrapper.set_link_state("Down")
    #     time.sleep(3)
    #     link_state = self.mbu_wrapper.get_mac_devprop("link")
    #     assert link_state is None
    #
    #     self.mbu_wrapper.set_mac_devprop("link", "1G")
    #     self.mbu_wrapper.set_link_state("Up")
    #     time.sleep(10)
    #     link_state = self.mbu_wrapper.get_mac_devprop("link")
    #     assert link_state is not None
    #
    #     val = 1
    #     msm_settings_addr = 0x54
    #     while msm_settings_addr <= 0x70:
    #         msm_val = self.mbu_wrapper.readreg_msm(msm_settings_addr)
    #         assert val == int(msm_val)
    #         msm_settings_addr += 4
    #         val += 1
    #
    #     val = self.mbu_wrapper.readreg_msm(0x8)
    #     assert (val >> 0x13) & 0x1 == 1


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
