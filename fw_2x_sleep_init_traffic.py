import os
import shutil
import time
import tempfile

import pytest

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, LINK_STATE_UP, LINK_STATE_DOWN
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.drv_iface_cfg import DrvEthConfig, OffloadIpInfo
from tools.samba import Samba
from tools.utils import get_atf_logger

from infra.test_base import TestBase
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_2x_sleep_init_traffic"


class TestSleepProxy(TestBase):
    DUT_IP = "192.168.0.3"
    DUT_MAC = "00:17:b6:00:07:82"
    LKP_IP = "192.168.0.2"
    NETMASK = "255.255.255.0"
    GATEWAY = "192.168.0.1"

    DEFAULT_LINK_CHECKS = 30
    DEFAULT_LINK_INTERVAL = 30

    @classmethod
    def setup_class(cls):
        super(TestSleepProxy, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, cls.GATEWAY)

            cls.atltool_wrapper = AtlTool(port=cls.dut_port)

            cls.link_checks = int(os.environ.get('LINK_CHECKS', cls.DEFAULT_LINK_CHECKS))
            cls.link_interval = float(os.environ.get('LINK_INTERVAL', cls.DEFAULT_LINK_INTERVAL))

            # Disable Samba to remove background multicast traffic which affects SerDes
            Samba(host=cls.lkp_hostname).stop()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestSleepProxy, self).setup_method(method)
        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.atltool_wrapper.debug_buffer_enable(True)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)

    def teardown_method(self, method):
        super(TestSleepProxy, self).teardown_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()
        if self.MCP_LOG:
            self.atltool_wrapper.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

    def test_link_down_up_pause_30s(self):
        cfg = DrvEthConfig()

        cfg.version = 0
        cfg.len = 0x407
        cfg.mac = self.DUT_MAC
        cfg.caps = cfg.CAPS_HI_WOL
        cfg.caps = cfg.caps | cfg.CAPS_HI_SLEEP_PROXY

        ips = OffloadIpInfo()
        cfg.ips = ips

        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_sleep_init_traffic.txt")
        cfg.apply(self.atltool_wrapper, beton_file)

        link_speed = self.lkp_ifconfig.wait_link_up()
        log.info("Link {} is up".format(link_speed))

        for i in xrange(self.link_checks):
            log.info("##### Iteration: {} #####".format(i))
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

            # read debug PHY registers
            phy_status = self.atltool_wrapper.readphyreg(0x1E, 0xC850)
            log.info("PHY status = {}".format(hex(phy_status).rstrip('L')))
            for i in range(7):
                self.atltool_wrapper.readphyreg(0x1e, 0xc800 + i)
            self.atltool_wrapper.readphyreg(0x1E, 0xC886)

            # if link is not up it means we catch packet extractor crash in EUR
            self.lkp_ifconfig.wait_link_up()

            time.sleep(self.link_interval)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
