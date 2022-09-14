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
    os.environ["TEST"] = "diag_selftest_verbose"


class TestDiag(TestBase):

    DIAG_TEST_ITERATIONS = int(os.environ.get("DIAG_TEST_ITERATIONS", 5))

    DEFAULT_SELFTEST_CONFIG = {
        "version": 1,
        "tests": {
            "datapath_tests": [],
            "memory_tests": [],
            "offload_tests": [],
            "flash_tests": [],
            "misc_tests": []
        },
        "Ethernet_Speed": [],
        "Phy_Speed": [] 
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
            cls.atltool = AtlTool(port=cls.dut_port)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def run_test_selftest_verbose(self, config, speed = None):
        config_path = "tmp.cfg"
        tmp_content = ["tmp.cfg file content:"]

        with open(config_path, "w") as f:
            yaml.dump(config, f)
            tmp_content.append(yaml.dump(config))
        log.info('\n'.join(tmp_content))

        params = "-v 2 -c -a {} {} -r --raise".format(config_path, self.DIAG_TEST_ITERATIONS)
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
        assert itr_re_pass_subtest == self.DIAG_TEST_ITERATIONS

        if speed is not None:
            itr = 0
            re_pass_speed = re.compile(r"^Ending (\w+\s*\w*\s*)\(*(\d*\.*\d*\w*)\)*(\s*\.*)* RESULT = PASS?")
            for line in res["output"]:
                if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line:
                    m = re_pass_speed.match(line)
                    if m is not None:
                        assert m.group(2) == speed
                        log.info('subtest iteration #{} have been passed with speed "{}"'.format(itr, speed))
                        itr += 1
            assert itr == self.DIAG_TEST_ITERATIONS

    def test_selftest_mac_verbose(self):
        config = copy.deepcopy(self.DEFAULT_SELFTEST_CONFIG)
        config["tests"]["datapath_tests"] = ["Mac"]
        self.run_test_selftest_verbose(config)

    @idparametrize("speed", ['100M', '1G', '2.5G', '5G', '10G'])
    def test_selftest_phy_loopback_verbose(self, speed):
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip("Felicity has no PHY")
        if self.dut_fw_card in BERMUDA_CARDS and speed == '10G':
            pytest.skip("Bermuda max 5G")
        else:
            config = copy.deepcopy(self.DEFAULT_SELFTEST_CONFIG)
            config["tests"]["datapath_tests"] = ["Phy Loopback"]
            config["Phy_Speed"] = [speed]
            self.run_test_selftest_verbose(config, speed)

    @idparametrize("speed", ['100M', '2.5G', '5G', '10G'])
    def test_selftest_extloopback_verbose(self, speed):
        if self.dut_fw_card in BERMUDA_CARDS and speed == '10G':
            pytest.skip("Bermuda max 5G")
        else:
            config = copy.deepcopy(self.DEFAULT_SELFTEST_CONFIG)
            config["tests"]["datapath_tests"] = ["External Loopback"]
            config["Ethernet_Speed"] = [speed]
            self.run_test_selftest_verbose(config, speed)

    def test_selftest_lso_verbose(self):
        config = copy.deepcopy(self.DEFAULT_SELFTEST_CONFIG)
        config["tests"]["offload_tests"] = ["LSO"]
        self.run_test_selftest_verbose(config)

if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
