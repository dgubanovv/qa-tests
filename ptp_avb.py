import os
import pytest
import tempfile
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.mbuper import download_mbu, MbuWrapper
from infra.test_base import TestBase, idparametrize
from tools.constants import LINK_SPEED_100M, LINK_SPEED_2_5G, \
    LINK_SPEED_5G, LINK_SPEED_10G
from tools.utils import get_atf_logger
from tools.lom import LightsOutManagement

log = get_atf_logger()

def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "ptp_avb"


class TestPtpAvb(TestBase):

    mbu_wrapper = None

    @classmethod
    def setup_class(cls):
        super(TestPtpAvb, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version=cls.dut_drv_version)
            cls.dut_driver.install()

            cls.mbu_dir = download_mbu(cls.mbu_version, cls.working_dir)

            log.info("Initializing MBU wrapper")
            cls.mbu_wrapper = MbuWrapper(mbu_dir=cls.mbu_dir, port=cls.dut_port)
            cls.log_local_dir = os.path.join(cls.mbu_dir, "logs")
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestPtpAvb, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)

    def teardown_method(self, method):
        super(TestPtpAvb, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()

    @idparametrize("t", ["ptp_sync", "ptp_delay_req"])
    @idparametrize("c", [2, 4])
    @idparametrize("s", [LINK_SPEED_100M, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    @idparametrize("en", ["before_link_up", "after_link_up"])
    def test_loopb(self, t, c, s, en):
        pkt_type = t
        pkt_count = c
        speed = s
        when_enable = en
        scripts_path = os.path.join(os.environ["ATF_HOME"],
                                    "qa-tests/tools/beton")
        self.mbu_wrapper.set_var("PWD", scripts_path)
        self.mbu_wrapper.set_var("pkt_type", pkt_type)
        self.mbu_wrapper.set_var("pkt_count", pkt_count)
        self.mbu_wrapper.set_var("link_speed", speed)
        self.mbu_wrapper.set_var("when_enable_ptp", when_enable)
        self.mbu_wrapper.exec_txt("PTP/ptp_2side.txt")
        report = self.mbu_wrapper.get_var("finalReport")
        if len(report) != 0:
            raise Exception("MBU script detected error")


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
