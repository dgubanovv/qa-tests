import copy
import os
import sys
import re
import pytest
import yaml

from tools.diagper import DiagWrapper, download_diag, get_actual_diag_version, uninstall_diag
from tools import driver
from tools.atltoolper import AtlTool
from tools.utils import get_atf_logger
from infra.test_base import TestBase, idparametrize
from tools.ops import get_arch, OpSystem
from tools.constants import FELICITY_CARDS, BERMUDA_CARDS
from tools.command import Command


log = get_atf_logger()


def setup_module(module):
    #import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "diag_selftest_verbose_t"

class TestDiag(TestBase):

    @classmethod
    def add_diag_drv_cert(cls, path):
        arch = get_arch()
        cert_dir = "win32" if arch == "32" else "x64"
        cert = os.path.join(path, "mbu/Os/{}/aquantiaDiagPack.cer".format(cert_dir))

        cls.diag_drv.install_trusted_certificate(cert)

    @classmethod
    def setup_class(cls):
        dut_felicity = os.environ.get('DUT_FELICITY', None)
        if dut_felicity is not None:
            os.environ['DUT_PORT'] = dut_felicity
            os.environ['DUT_FW_CARD'] = 'Felicity'

        super(TestDiag, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.os = OpSystem()

            cls.install_firmwares()

            if cls.os.is_centos() or cls.os.is_ubuntu():
                uninstall_diag()
            cls.diag_dir = download_diag(cls.diag_version)
            cls.diag_ver = get_actual_diag_version(cls.diag_version)

            cls.diag_drv = driver.Driver(port=cls.dut_port, drv_type="diag", version=cls.dut_drv_version)

            if cls.os.is_windows():
                cls.add_diag_drv_cert(cls.diag_dir)

            if cls.os.is_linux():
                if cls.os.is_rhel():
                    cls.diag_drv_path = '{}/mbu/Os/linux/driver/src'.format(cls.diag_dir)
                    Command(cmd='cd {}; make'.format(cls.diag_drv_path)).run_join(15)
                    Command(cmd='insmod {}/aqdiag.ko'.format(cls.diag_drv_path)).run_join(15)
                else:
                    Command(cmd='insmod /opt/aquantia/diag/mbu/Os/linux/driver/src/aqdiag.ko').run_join(15)
            else:
                cls.diag_drv.install()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def run_test_selftest_verbose_test(self, params):
        res = DiagWrapper.exec_single(params, self.diag_dir)

        assert res["reason"] == Command.REASON_OK
        assert res["returncode"] == 0
        log.info('Exit code: {}, reason: {}'.format(res["returncode"], res["reason"]))

        re_pass = re.compile(r"^(\w+\s*\w*\s*)=\s*\d*[a-z ]*\d* passed \(100.00%\)?")
        assert any(re_pass.match(line) for line in res["output"] \
            if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line)
        log.info('tests are 100% passed')

        re_pass_subtest = re.compile(r"^Ending (\w+\s*\w*\s*)\(*\d*\.*\d*\w*\)*(\s*\.*)* RESULT = PASS?")
        itr_re_pass_subtest = 0
        for line in res["output"]:
            if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line:
                ms = re_pass_subtest.match(line)
                if ms is not None:
                    log.info('subtest iteration #{} have been passed'.format(itr_re_pass_subtest))
                    itr_re_pass_subtest += 1
        assert itr_re_pass_subtest == 1

    @idparametrize("test_name", ["Mac", "Phy", "External_Loopback"])
    def test_datapath(self, test_name):
        log.info("Start {} datapath test".format(test_name))
        params = "-v 2 -t fast_datapath:{} -r --raise".format(test_name)
        if self.dut_fw_card in FELICITY_CARDS and test_name is "Phy":
            pytest.skip("Felicity has no PHY")
            
        self.run_test_selftest_verbose_test(params)

    def test_lso(self):
        log.info("Start LSO offload test")
        params = "-v 2 -t offload:LSO -r --raise"

        self.run_test_selftest_verbose_test(params)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
