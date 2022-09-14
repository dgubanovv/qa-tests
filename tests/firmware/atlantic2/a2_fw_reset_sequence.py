import os
import re
import sys
import time

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.atltoolper import AtlTool
from tools.constants import KNOWN_LINK_SPEEDS, LINK_SPEED_AUTO, LINK_STATE_UP
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.utils import get_atf_logger
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config, SleepProxyOffload, HOST_MODE_ACTIVE
from infra.test_base import TestBase, idparametrize

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_fw_2x_reset_sequence"


class TestA2FwResetSequence(TestBase):
    DUT_MAC_ADDR = "00:17:B6:01:02:03"
    DUT_IP4_ADDR = "169.254.0.110"
    LKP_IP4_ADDR = "169.254.0.120"

    @classmethod
    def setup_class(cls):
        super(TestA2FwResetSequence, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", host=cls.dut_hostname,
                                    drv_type=DRV_TYPE_DIAG)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, silent=False)
            cls.dut_fw_config = FirmwareA2Config(cls.dut_atltool_wrapper)
        except Exception:
            log.exception("Failed while setting up class")
            raise

    def check_heart_beat(self):
        heart_beat_1 = self.dut_fw_config.read_drv_iface_struct_field(
            "DRIVER_INTERFACE_OUT.macHealthMonitor.macHeartBeat")
        time.sleep(2)
        heart_beat_2 = self.dut_fw_config.read_drv_iface_struct_field(
            "DRIVER_INTERFACE_OUT.macHealthMonitor.macHeartBeat")
        time.sleep(4)
        phy_heart_beat_1 = self.dut_fw_config.read_drv_iface_struct_field(
            "DRIVER_INTERFACE_OUT.phyHealthMonitor.phyHeartBeat")
        time.sleep(2)
        phy_heart_beat_2 = self.dut_fw_config.read_drv_iface_struct_field(
            "DRIVER_INTERFACE_OUT.phyHealthMonitor.phyHeartBeat")

        assert heart_beat_2 > heart_beat_1, "MAC heart beat is not ticking"
        assert phy_heart_beat_2 > phy_heart_beat_1, "PHY heart beat is not ticking"

    @idparametrize("mode", ['soft', 'hard', 'fast', 'skip_phy'])
    def test_reset_with_link_up(self, mode):
        """
        @description: This subtest performs check what after kickstart speed is sets correctly.

        @steps:
        1. Set link speed auto on LKP.
        2. Kickstart DUT.
        4. Check MAC and PHY HeartBeat.
        3. Set link up on DUT.

        @result: DUT negotiate correct speed.
        @duration: 5 minutes.
        """

        def parse_output(find_regex, lines):
            for line in lines:
                m = re.match(find_regex, line)
                if m is not None:
                    return int(m.groups()[0])
            return 0

        for i in range(5):
            expected_speed = self.supported_speeds[i % len(self.supported_speeds)]

            log.info("Kickstart attempt #{} with speed {}".format(i, expected_speed))
            phy_heart_beat_1 = self.dut_fw_config.get_phy_health_monitor().phyHeartBeat
            res = self.dut_atltool_wrapper.kickstart2(
                full_reset=(mode == 'hard'), fast_reset=(mode == 'fast'), skip_phy=(mode == 'skip_phy'))
            phy_heart_beat_2 = self.dut_fw_config.get_phy_health_monitor().phyHeartBeat
            global_reset = self.dut_atltool_wrapper.readreg(0x3040)
            fast_boot = bool(global_reset >> 0x19 & 1)
            full_boot = bool(global_reset >> 0x1A & 1)
            if mode == 'fast':
                assert fast_boot and not full_boot
            else:
                assert full_boot and not fast_boot

            if mode == 'skip_phy':
                assert phy_heart_beat_2 > phy_heart_beat_1

            rbl_time = parse_output("RBL initialization .*: (\d+) ms", res)
            reset_time = parse_output("Reset completed .*Time: (\d+) ms", res)
            mac_finish = parse_output("MAC FW finished boot. Time: (\d+) ms", res)
            phy_finish = parse_output("PHY is ready. Load time: (\d+) ms ms", res)
            assert rbl_time + reset_time + mac_finish + phy_finish < 3000

            time.sleep(1)
            self.check_heart_beat()

            self.dut_fw_config.set_link_state(LINK_STATE_UP)
            self.dut_fw_config.set_link_speed(expected_speed)
            self.dut_fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
            self.dut_fw_config.wait_link_up()
            self.lkp_ifconfig.wait_link_up()

            actual_speed = self.dut_fw_config.get_fw_link_speed()
            assert actual_speed == expected_speed, "Invalid link speed negotiated: {}".format(actual_speed)

    def test_reset_force_flashless(self):
        """
        @description: This subtest performs check what after kickstart speed is sets correctly.

        @steps:
        1. Set link speed auto on LKP.
        2. Kickstart DUT in flashledd mode.
        4. Check MAC and PHY HeartBeat.
        3. Set link up on DUT.

        @result: DUT negotiate correct speed.
        @duration: 5 minutes.
        """

        dut_fw_clx = self.dut_firmware.download()

        for i in range(1):
            expected_speed = self.supported_speeds[-1]

            log.info("Kickstart attempt #{} with speed {}".format(i, expected_speed))
            self.dut_atltool_wrapper.kickstart2(force_flashless=True, clx_path=dut_fw_clx)
            time.sleep(1)
            self.check_heart_beat()

            self.dut_fw_config.set_link_state(LINK_STATE_UP)
            self.dut_fw_config.set_link_speed(expected_speed)
            self.dut_fw_config.set_link_control_mode(HOST_MODE_ACTIVE)
            self.lkp_ifconfig.wait_link_up()

            actual_speed = self.dut_fw_config.get_fw_link_speed()
            assert actual_speed == expected_speed, "Invalid link speed negotiated: {}".format(actual_speed)

    @idparametrize("mode", ['soft', 'hard'])
    def test_reset_from_sleep_proxy(self, mode):
        """
        @description: This subtest performs check what after kickstart speed is negotiated correctly
        and interface is alive.

        @steps:
        1. Kickstart DUT.
        2. Configure IPv4 offloads on DUT.
        3. Set link speed on LKP.
        4. Wait for link up.
        5. Make sure that link is negotiated on LKP with correct speed.
        6. Send pings from LKP to DUT.

        @result: Ping is passed.
        @duration: 5 minutes.
        """

        sp_cfg = SleepProxyOffload()
        sp_cfg.ipv4_offload.arp_responder = True
        sp_cfg.ipv4_offload.echo_responder = True
        sp_cfg.ipv4_offload.ipv4[0] = self.DUT_IP4_ADDR

        for i in range(5):
            expected_speed = self.supported_speeds[i % len(self.supported_speeds)]
            self.lkp_ifconfig.set_link_speed(expected_speed)

            log.info("Kickstart attempt #{} with speed {}".format(i, expected_speed))
            self.dut_atltool_wrapper.kickstart2(full_reset=(mode == 'hard'))
            time.sleep(3)
            self.check_heart_beat()
            self.dut_fw_config.configure_sleep_proxy(sp_cfg, self.DUT_MAC_ADDR)

            actual_speed = self.lkp_ifconfig.wait_link_up()
            assert actual_speed == expected_speed, "Invalid link speed negotiated: {}".format(actual_speed)

            time.sleep(15)
            assert self.ping(self.lkp_hostname, self.DUT_IP4_ADDR, 10, src_addr=self.LKP_IP4_ADDR)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
