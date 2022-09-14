import glob
import os
import time
import shutil
import random

import pytest

from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_NO_LINK, FELICITY_CARDS, LINK_STATE_UP
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.mbuper import LINK_SPEED_TO_REG_VAL_MAP_2X
from tools import pcontrol
from infra.test_base import TestBase
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "sfp_sanity"


class TestSfpSanity(TestBase):
    @classmethod
    def setup_class(cls):
        super(TestSfpSanity, cls).setup_class()

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
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestSfpSanity, self).setup_class()
        assert pcontrol.PControl().gpio(self.dut_hostname, pcontrol.PIN_GPIO, pcontrol.GPIO_ENABLE)

    def set_link_params(self, speed):
        log.info("Setting speed {}...".format(speed))

        val = LINK_SPEED_TO_REG_VAL_MAP_2X[speed]
        reg = 0x368
        self.dut_atltool_wrapper.writereg(reg, val)

    def test_sfp_enable_disable(self):
        early_file_txt = None
        early_file_bin = None
        fail = 0
        speed = self.supported_speeds[-1]
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.set_link_params(speed)
        pcontrol.PControl().gpio(self.dut_hostname, pcontrol.PIN_GPIO, pcontrol.GPIO_DISABLE)
        time.sleep(3)
        pcontrol.PControl().gpio(self.dut_hostname, pcontrol.PIN_GPIO, pcontrol.GPIO_ENABLE)
        self.dut_atltool_wrapper.wait_link_up()
        for i in range(1000):
            log.info("ITERATION: {}".format(i))
            bin_log_file, txt_log_file = self.dut_atltool_wrapper.debug_buffer_enable(True)
            if pcontrol.PControl().gpio(self.dut_hostname, pcontrol.PIN_GPIO, pcontrol.GPIO_DISABLE) is False:
                self.lkp_ifconfig.wait_link_down()
                t = random.uniform(0.5, 10)
                log.info("SLEEP: {}s".format(round(t, 1)))
                time.sleep(t)
                if pcontrol.PControl().gpio(self.dut_hostname, pcontrol.PIN_GPIO, pcontrol.GPIO_ENABLE):
                    for j in range(25):
                        link_state = self.dut_atltool_wrapper.get_link_speed_2x()
                        if link_state is LINK_SPEED_NO_LINK:
                            time.sleep(1)
                        else:
                            break
                    self.dut_atltool_wrapper.debug_buffer_enable(False)
                    time.sleep(3)
                    log_file = "iteration_{}_time_{}".format(i, round(t, 1))
                    if link_state is not LINK_SPEED_NO_LINK:
                        log_file = log_file + "-PASS"
                        os.rename("{}".format(bin_log_file), "{}.bin".format(log_file))
                        os.rename("{}".format(txt_log_file), "{}.log".format(log_file))
                        if early_file_txt is not None:
                            os.remove(early_file_txt)
                            os.remove(early_file_bin)
                        early_file_txt = log_file + ".log"
                        early_file_bin = log_file + ".bin"
                    else:
                        fail = fail + 1
                        log_file = log_file + "-FAIL"
                        os.rename("{}".format(bin_log_file), "{}.bin".format(log_file))
                        os.rename("{}".format(txt_log_file), "{}.log".format(log_file))
                        if early_file_txt is not None:
                            shutil.copy(early_file_txt, self.test_log_dir)
                            shutil.copy(early_file_bin, self.test_log_dir)
                            os.remove(early_file_txt)
                            os.remove(early_file_bin)
                        log_file_txt = log_file + ".log"
                        log_file_bin = log_file + ".bin"
                        shutil.copy(log_file_txt, self.test_log_dir)
                        shutil.copy(log_file_bin, self.test_log_dir)
                        os.remove(log_file_txt)
                        os.remove(log_file_bin)
                        early_file_txt = None
                        early_file_bin = None
                        time.sleep(7)
                        link_state = self.dut_atltool_wrapper.get_link_speed_2x()
                        if link_state is LINK_SPEED_NO_LINK:
                            log.info("LINK DOWN")
                            raise Exception("Link is not up")
                        else:
                            log.info("LINK UP")
                else:
                    log.info("Not received package from powercontrol")
            else:
                log.info("Not received package from powercontrol")

        assert fail == 0


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
