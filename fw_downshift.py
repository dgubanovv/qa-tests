import os
import pytest
import time
import tempfile
import tools.driver
from tools.mbuper import download_mbu, MbuWrapper, LINK_STATE_UP
from tools.drv_iface_cfg import DrvDownshiftConfig
from tools.ifconfig import LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_AUTO
from tools.utils import get_atf_logger
from infra.test_base import TestBase

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_downshift"


class TestDownshift(TestBase):

    mbu_wrapper = None
    MAX_RETRY_COUNT = 7
    NOF_CHECKS = 20
    LINK_CONFIG_DELAY = 20

    @classmethod
    def setup_class(cls):
        super(TestDownshift, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = tools.driver.Driver(port=cls.dut_port, version="latest",
                                                 drv_type=tools.driver.DRV_TYPE_DIAG)
            cls.lkp_driver = tools.driver.Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.mbu_dir = download_mbu(cls.mbu_version, cls.working_dir)
            cls.mbu_wrapper = MbuWrapper(mbu_dir=cls.mbu_dir, port=cls.dut_port)
            cls.log_local_dir = os.path.join(cls.mbu_dir, "logs")
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def set_downshift_and_link(self, retry_count):
        log.info("Setting downshift retry count = {}".format(retry_count))
        if self.dut_firmware.is_1x():
            self.mbu_wrapper.set_link_params(LINK_SPEED_AUTO, LINK_STATE_UP, downshift_att=retry_count)
        elif self.dut_firmware.is_2x():
            cfg = DrvDownshiftConfig()
            cfg.retry_count = retry_count
            beton_file = os.path.join(self.working_dir, "downshift_{}_retries.txt".format(retry_count))
            cfg.apply(self.mbu_wrapper, beton_file)
            time.sleep(1)
            self.mbu_wrapper.set_link_params_2x(LINK_SPEED_AUTO)
        else:
            raise Exception("Unsupported firmware")

    def get_link_speed(self):
        if self.dut_firmware.is_1x():
            _, speed, __ = self.mbu_wrapper.get_link_params()
            return speed
        elif self.dut_firmware.is_2x():
            return self.mbu_wrapper.get_link_speed_2x()
        else:
            raise Exception("Unsupported firmware")

    def test_downshift(self):
        if "2.8" in self.dut_firmware.actual_version:
            log.info("2.8.x firmware doesn't support downshift")
            pytest.skip()

        speeds_5G_per_retries_num = [0] * (TestDownshift.MAX_RETRY_COUNT + 1)
        speeds_10G_per_retries_num = [0] * (TestDownshift.MAX_RETRY_COUNT + 1)
        speeds_unknown_retries_num = [0] * (TestDownshift.MAX_RETRY_COUNT + 1)

        self.lkp_ifconfig.set_advanced_property("Downshift", 7)
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        time.sleep(self.LINK_CONFIG_DELAY)

        for i in range(TestDownshift.MAX_RETRY_COUNT + 1):
            log.info("Nof downshift retries: {}".format(i))

            for j in range(TestDownshift.NOF_CHECKS):
                log.info("Downshift check attempt: {}".format(j + 1))

                # Set link down by reg 0x368 due set_link_state("Down") not works
                self.mbu_wrapper.writereg(0x368, 0)
                time.sleep(5)

                self.set_downshift_and_link(i)

                time.sleep(self.LINK_CONFIG_DELAY)

                phy_retry_count = self.mbu_wrapper.readphyreg("0x7.0xc400")
                phy_retry_count &= 0x7

                if phy_retry_count != i:
                    raise Exception("Wrong retry count in PHY: {}".format(phy_retry_count))

                dspeed = self.get_link_speed()
                pspeed = self.lkp_ifconfig.get_link_speed()

                if dspeed != pspeed:
                    speeds_unknown_retries_num[i] += 1
                    log.error("Wrong speed negotiated, DUT: {}, LKP: {}".format(dspeed, pspeed))
                    continue

                if pspeed == LINK_SPEED_5G:
                    speeds_5G_per_retries_num[i] += 1
                    log.info("Link 5G is up")
                elif pspeed == LINK_SPEED_10G:
                    speeds_10G_per_retries_num[i] += 1
                    log.info("Link 10G is up")
                else:
                    speeds_unknown_retries_num[i] += 1
                    log.info("Unexpected link speed: {}".format(pspeed))

        log.info("Summary")
        log.info("5G:  {}".format(speeds_5G_per_retries_num))
        log.info("10G: {}".format(speeds_10G_per_retries_num))
        log.info("xG:  {}".format(speeds_unknown_retries_num))

        # log.info("Generating log file...")
        # log_file = os.path.join(self.working_dir, 'downshift_stats.txt')
        # with open(log_file, 'w') as f:
        #     for i in range(TestDownshift.MAX_RETRY_COUNT):
        #         stat_5G = "Link 5G count: {}".format(speeds_5G_per_retries_num[i])
        #         stat_10G = "Link 10G count: {}".format(speeds_10G_per_retries_num[i])
        #         stat_unknown = "Link Unknown count: {}".format(speeds_unknown_retries_num[i])

        #         f.write("###### Summary for attempt: {} ######\n".format(i + 1))
        #         f.write(stat_5G + '\n')
        #         f.write(stat_10G + '\n')
        #         f.write(stat_unknown + '\n')
        #         f.write('\n\n')

        # tools.utils.upload_file(self.log_server, log_file, self.log_server_dir)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
