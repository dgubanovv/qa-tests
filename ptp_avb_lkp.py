import os
import pytest
import tempfile
from tools.mbuper import download_mbu, MbuWrapper
from infra.test_base import TestBase, idparametrize
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, \
    LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_AUTO
from tools.ifconfig import get_expected_speed
from tools.utils import get_atf_logger
from tools.lom import LightsOutManagement


log = get_atf_logger()

def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "ptp_avb"


class TestPtp(TestBase):
    mbu_wrapper = None

    @classmethod
    def setup_class(cls):
        super(TestPtp, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.lkp_fw_version = cls.dut_fw_version
            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG,
                                    version="latest")
            cls.lkp_driver = Driver(port=cls.lkp_port, drv_type=DRV_TYPE_DIAG,
                                    version="latest", host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.dut_driver.install()

            log.info("Initializing MBU wrapper")
            cls.mbu_dir = download_mbu(cls.mbu_version, cls.working_dir)
            cls.mbu_wrapper = MbuWrapper(mbu_dir=cls.mbu_dir, port=cls.dut_port)
            cls.log_local_dir = os.path.join(cls.mbu_dir, "logs")
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestPtp, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)

    def teardown_method(self, method):
        super(TestPtp, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()

    @idparametrize("t", ["ptp_sync", "ptp_delay_req"])
    @idparametrize("c", [4, 8])
    @idparametrize("s", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G,
                                  LINK_SPEED_5G, LINK_SPEED_10G])
    @idparametrize("en", ["before_link_up", "after_link_up"])
    @idparametrize("d", ["tx", "rx"])
    def test_lkp(self, t, c, s, en, d):
        pkt_type = t
        pkt_count = c
        speed = s
        when_enable = en
        direction = d

        if speed == LINK_SPEED_10G and get_expected_speed(LINK_SPEED_AUTO, self.dut_port) != LINK_SPEED_10G:
            pytest.xfail()

        scripts_path = os.path.join(os.environ["ATF_HOME"],
                                    "qa-tests/tools/beton")
        self.mbu_wrapper.set_var("PWD", scripts_path)
        self.mbu_wrapper.set_var("pkt_type", pkt_type)
        self.mbu_wrapper.set_var("pkt_count", pkt_count)
        self.mbu_wrapper.set_var("link_speed", speed)
        self.mbu_wrapper.set_var("when_enable_ptp", when_enable)
        self.mbu_wrapper.set_var("loopback", "None")
        self.mbu_wrapper.set_var("ptp_direction", "egress" if direction == "tx" else "ingress")
        
        self.lkp_mbu = MbuWrapper(mbu_dir=self.mbu_dir, port=self.lkp_port, version=self.mbu_version, host=self.lkp_hostname)
        
        ptp_2side_lkp_local = os.path.join(scripts_path, "PTP", "ptp_2side_lkp.txt")
        with open(ptp_2side_lkp_local, 'w') as f:
            f.write('PWD = {}\n'.format(scripts_path))
            f.write('pkt_type = {}\n'.format(pkt_type))
            f.write('pkt_count = {}\n'.format(pkt_count))
            f.write('link_speed = {}\n'.format(speed))
            f.write('when_enable_ptp = {}\n'.format(when_enable))
            f.write('loopback = {}\n'.format("None"))
            f.write('ptp_direction = {}\n'.format("ingress" if direction == "tx" else "egress"))
            f.write('exec PTP/ptp_2side.txt\n')

        remote_file = '%ATF_HOME%\\qa-tests\\tools\\beton\\PTP\\ptp_2side_lkp.txt'
        file_to_upload = '~/qa-tests/tools/beton/PTP/ptp_2side_lkp.txt'

        # start MBU script on LKP
        log.info('***** ***** ***** ***** Running MBU on LKP...')
        self.lkp_mbu.exec_txt(ptp_2side_lkp_local, run_async=True,
                              remote_file=file_to_upload,
                              work_dir='$ATF_HOME/qa-tests/tools/beton',
                              output=None,
                              file_to_upload=file_to_upload)

        # run on DUT
        log.info('***** ***** ***** ***** Running MBU on DUT...')
        self.mbu_wrapper.exec_txt("PTP/ptp_2side.txt")
        report = self.mbu_wrapper.get_var("finalReport")
        log.info('finalReport = {}'.format(report))

        # wait for LKP script finished
        log.info('***** ***** ***** ***** Waiting while LKP script finished...')
        lkp_res = self.lkp_mbu.exec_join()

        if len(report) != 0:
            log.error(report)
            raise Exception("DUT MBU script detected error")

        if not any(['[PASSED]' in line for line in lkp_res["output"]]) or \
                any(["Exception" in line for line in lkp_res["output"]]):
            raise Exception("LKP MBU script detected error")


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
