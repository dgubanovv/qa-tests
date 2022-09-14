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
from tools.constants import CHIP_REV_B0, CHIP_REV_B1, FELICITY_CARDS, BERMUDA_CARDS
from tools.command import Command

log = get_atf_logger()

def setup_module(module):
    #import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "diag_memorytest_verbose"
    del os.environ["AQ_DEVICEREV"]

class TestDiag(TestBase):
    DIAG_TEST_ITERATIONS = int(os.environ.get("DIAG_TEST_ITERATIONS", 1))
    DEFAULT_SELFTEST_CONFIG = {
        "version": 1,
        "tests": {
            "datapath_tests": [],
            "memory_tests": [],
            "offload_tests": [],
            "flash_tests": [],
            "misc_tests": []
        },
        "Ethernet_Speed": []
        }
        
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
            cls.chip_rev = cls.get_chip_revision(cls.dut_port)
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

    def run_test_memory_verbose(self, params, test_iter):
        os.environ["AQ_DEVICEREV"] = "B1"
        diag_fields = "--password !h:ahT8uW6 --flash_fields dev_id=0xd107 -d {}".format(self.dut_port.replace("00","0"))
        DiagWrapper.exec_single(diag_fields, self.diag_dir)
        del os.environ["AQ_DEVICEREV"]
        res = DiagWrapper.exec_single(params, self.diag_dir)

        if self.chip_rev == CHIP_REV_B0:
            assert res["reason"] == Command.REASON_OK
            assert res["returncode"] == 0
            log.info('Exit code: {}, reason: {}'.format(res["returncode"], res["reason"]))

            re_pass = re.compile(r"^(\w+\/*\w*\s*\w*\s*)=\s*\d*[a-z ]*\d* passed \(100.00%\)")
            assert any(re_pass.match(line) for line in res["output"] \
                if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line)
            log.info('tests are 100% passed')

            re_pass_subtest = re.compile(r"^Ending (\w+\/*\w*\s*\w*\s*)(\s*\.*)* RESULT = PASS")
            itr_re_pass_subtest = 0
            for line in res["output"]:
                if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line:
                    ms = re_pass_subtest.match(line)
                    if ms is not None:
                        log.info('subtest iteration #{} have been passed'.format(itr_re_pass_subtest))
                        itr_re_pass_subtest += 1
            assert itr_re_pass_subtest == test_iter
        else:
            re_pass_skipped = re.compile(r"^Memory tests not available on B1. Skipping...")
            assert any(re_pass_skipped.match(line) for line in res["output"] \
                if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line)

    @idparametrize("test_name", ["IRAM_Memory", "DRAM_Memory", "TPB/RPB_Memory"])
    def test_memory_t(self, test_name):
        log.info("Start {} memory test".format(test_name))
        params = "-v 2 -t mem:{} -d {} -r --raise".format(test_name, self.dut_port.replace("00","0"))
        test_iter = 1
        self.run_test_memory_verbose(params, test_iter)
        
        
    @idparametrize("test_name", ["IRAM Memory", "DRAM Memory", "TPB/RPB Memory"])
    def test_memory_cfg(self, test_name):
        config = copy.deepcopy(self.DEFAULT_SELFTEST_CONFIG)
        config["tests"]["memory_tests"] = [test_name]
        config_path = "tmp.cfg"
        tmp_content = ["tmp.cfg file content:"]

        with open(config_path, "w") as f:
            yaml.dump(config, f)
            tmp_content.append(yaml.dump(config))
        log.info('\n'.join(tmp_content))

        params = "-v 2 -c -a {} {} -d {} -r --raise".format(config_path, self.DIAG_TEST_ITERATIONS, 
                                                            self.dut_port.replace("00","0"))
        test_iter = self.DIAG_TEST_ITERATIONS
        self.run_test_memory_verbose(params, test_iter)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
