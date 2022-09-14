import os
import sys
import re
import pytest

from tools.diagper import DiagWrapper, download_diag, get_actual_diag_version, uninstall_diag
from tools import driver
from tools.utils import remove_directory, get_atf_logger
from infra.test_base import TestBase
from tools.ops import get_arch, OpSystem
from tools.command import Command

log = get_atf_logger()


def setup_module(module):
    #import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "diag_drv_lin"


class TestDiag(TestBase):
    
    @classmethod
    def setup_class(cls):
        # set DUT_PORT before TestBase.setup_class() because it's needed inside
        dut_felicity = os.environ.get('DUT_FELICITY', None)
        if dut_felicity is not None:
            os.environ['DUT_PORT'] = dut_felicity
            os.environ['DUT_FW_CARD'] = 'Felicity'

        # init from base class
        super(TestDiag, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.os = OpSystem()

            cls.install_firmwares()

            # uninstall previously installed diag on linux to be able to install rpm or deb
            if cls.os.is_linux():
                uninstall_diag()
            cls.diag_dir = download_diag(cls.diag_version)
            cls.diag_ver = get_actual_diag_version(cls.diag_version)

            cls.diag_drv_path = '/opt/aquantia/diag/mbu/Os/linux/driver/src'
            if cls.os.is_rhel():
                cls.diag_drv_path = '{}/mbu/Os/linux/driver/src'.format(cls.diag_dir)
                Command(cmd='cd {}; make'.format(cls.diag_drv_path)).run_join(15)
            cls.lin_diag_drv = driver.Driver(port=cls.dut_port,
                drv_type=driver.DRV_TYPE_SRC_DIAG_LIN, version='latest')
            cls.lin_prod_drv = driver.Driver(port=cls.dut_port, version=cls.dut_drv_version)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestDiag, cls).teardown_class()

        # DiagWrapper.exec_single("--password !h:ahT8uW6 --flash_erase")
        if cls.os.is_linux():
            uninstall_diag()
        else:
            remove_directory(cls.diag_dir)

    def setup_method(self, method):
        super(TestDiag, self).setup_method(method)
        if self.lin_diag_drv.is_loaded():
            log.info("Unloading diag drivers")
            self.lin_diag_drv.unload()
        if self.lin_prod_drv.is_loaded():
            log.info("Unloading prod drivers")
            self.lin_prod_drv.unload()


    if sys.platform == "win32" and 'darwin' not in sys.platform:
        params = ["-h", "/?", "-?"]
    else:
        params = ["-h", "-?"]


    def test_temp_witn_no_drv(self):
        log.info("Running Diag with -s option with no loaded prod and diag drivers")
        output = DiagWrapper.exec_single("-s -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert not self.lin_prod_drv.is_loaded(), "Error, prod driver has to be unloaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert not self.lin_diag_drv.is_loaded(), "Error, diag driver has to be unloaded"
        assert not self.lin_diag_drv.is_bound(), "Error, diag driver has to be unbound"

    def test_temp_prod_is_bound(self):
        log.info("Running Diag with -s option with loaded and bound prod driver")
        self.lin_prod_drv.install()
        output = DiagWrapper.exec_single("-s -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert self.lin_prod_drv.is_loaded(), "Error, prod driver has to be loaded"
        assert self.lin_prod_drv.is_bound(), "Error, prod driver has to be bound"
        assert not self.lin_diag_drv.is_loaded(), "Error, diag driver has to be unloaded"
        assert not self.lin_diag_drv.is_bound(), "Error, diag driver has to be unbound"

    def test_temp_prod_is_loaded(self):
        log.info("Running Diag with -s option with with loaded and unbound prod driver")
        self.lin_prod_drv.install()
        self.lin_prod_drv.unbind()
        output = DiagWrapper.exec_single("-s -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert self.lin_prod_drv.is_loaded(), "Error, prod driver has to be loaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert not self.lin_diag_drv.is_loaded(), "Error, diag driver has to be unloaded"
        assert not self.lin_diag_drv.is_bound(), "Error, diag driver has to be unbound"

    def test_temp_prod_is_bound_and_diag_is_loaded(self):
        log.info("Running Diag with -s option with bound prod driver and loaded diag driver")
        self.lin_diag_drv.load(self.diag_drv_path)
        self.lin_diag_drv.unbind()
        self.lin_prod_drv.install()
        output = DiagWrapper.exec_single("-s -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert self.lin_prod_drv.is_loaded(), "Error, prod driver has to be loaded"
        assert self.lin_prod_drv.is_bound(), "Error, prod driver has to be bound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert not self.lin_diag_drv.is_bound(), "Error, diag driver has to be unbound"

    def test_temp_prod_is_loaded_and_diag_is_bound(self):
        log.info("Running Diag with -s option with loaded prod driver and bound diag driver")
        self.lin_prod_drv.install()
        self.lin_prod_drv.unbind()
        self.lin_diag_drv.load(self.diag_drv_path)
        output = DiagWrapper.exec_single("-s -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert self.lin_prod_drv.is_loaded(), "Error,prod driver has to be loaded"
        assert not self.lin_prod_drv.is_bound(), "Error,prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert self.lin_diag_drv.is_bound(), "Error, diag driver has to be bound"

    def test_temp_prod_is_loaded_and_diag_is_loaded(self):
        log.info("Running Diag with -s option with loaded prod driver and loaded diag driver")
        self.lin_prod_drv.install()
        self.lin_prod_drv.unbind()
        self.lin_diag_drv.load(self.diag_drv_path)
        self.lin_diag_drv.unbind()
        output = DiagWrapper.exec_single("-s -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert self.lin_prod_drv.is_loaded(), "Error, prod driver has to be loaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert not self.lin_diag_drv.is_bound(), "Error, diag driver has to be unbound"

    def test_temp_diag_is_loaded(self):
        log.info("Running Diag with -s option with loaded diag driver")
        self.lin_diag_drv.load(self.diag_drv_path)
        self.lin_diag_drv.unbind()
        output = DiagWrapper.exec_single("-s -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert not self.lin_prod_drv.is_loaded(), "Error, prod driver has to be unloaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error,  diag driver has to be loaded"
        assert not self.lin_diag_drv.is_bound(), "Error,  diag driver has to be  unbound"

    def test_temp_diag_is_bound(self):
        log.info("Running Diag with -s option with bound diag driver")
        self.lin_diag_drv.load(self.diag_drv_path)
        output = DiagWrapper.exec_single("-s -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert not self.lin_prod_drv.is_loaded(), "Error, prod driver has to be unloaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert self.lin_diag_drv.is_bound(), "Error, diag driver has to be bound"

    def test_perm_witn_no_drv(self):
        log.info("Running Diag with -k option with no loaded prod and diag drivers")
        output = DiagWrapper.exec_single("-k -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert  not self.lin_prod_drv.is_loaded(), "Error, prod driver has to be unloaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert self.lin_diag_drv.is_bound(), "Error, diag driver has to be bound"

    def test_perm_prod_is_bound(self):
        log.info("Running Diag with -k option with loaded and bound prod driver")
        self.lin_prod_drv.install()
        output = DiagWrapper.exec_single("-k -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert self.lin_prod_drv.is_loaded(), "Error, prod driver has to be loaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert self.lin_diag_drv.is_bound(), "Error, diag driver has to be bound"

    def test_perm_prod_is_loaded(self):
        log.info("Running Diag with -k option with with loaded and unbound prod driver")
        self.lin_prod_drv.install()
        self.lin_prod_drv.unbind()
        output = DiagWrapper.exec_single("-k -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert self.lin_prod_drv.is_loaded(), "Error, prod driver has to be loaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert self.lin_diag_drv.is_bound(), "Error, diag driver has to be bound"

    def test_perm_prod_is_bound_and_diag_is_loaded(self):
        log.info("Running Diag with -k option with bound prod driver and loaded diag driver")
        self.lin_diag_drv.load(self.diag_drv_path)
        self.lin_diag_drv.unbind()
        self.lin_prod_drv.install()
        output = DiagWrapper.exec_single("-k -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert self.lin_prod_drv.is_loaded(), "Error, prod driver has to be loaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert self.lin_diag_drv.is_bound(), "Error, diag driver has to be bound"

    def test_perm_prod_is_loaded_and_diag_is_bound(self):
        log.info("Running Diag with -k option with loaded prod driver and bound diag driver")
        self.lin_prod_drv.install()
        self.lin_prod_drv.unbind()
        self.lin_diag_drv.load(self.diag_drv_path)
        output = DiagWrapper.exec_single("-k -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert self.lin_prod_drv.is_loaded(), "Error, prod driver has to be loaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert self.lin_diag_drv.is_bound(), "Error, diag driver has to be bound"

    def test_perm_prod_is_loaded_and_diag_is_loaded(self):
        log.info("Running Diag with -k option with loaded prod driver and loaded diag driver")
        self.lin_prod_drv.install()
        self.lin_prod_drv.unbind()
        self.lin_diag_drv.load(self.diag_drv_path)
        self.lin_diag_drv.unbind()
        output = DiagWrapper.exec_single("-k -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert self.lin_prod_drv.is_loaded(), "Error, prod driver has to be loaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert self.lin_diag_drv.is_bound(), "Error, diag driver has to be bound"

    def test_perm_diag_is_loaded(self):
        log.info("Running Diag with -k option with loaded diag driver")
        self.lin_diag_drv.load(self.diag_drv_path)
        self.lin_diag_drv.unbind()
        output = DiagWrapper.exec_single("-k -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert not self.lin_prod_drv.is_loaded(), "Error, prod driver has to be unloaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert self.lin_diag_drv.is_bound(), "Error, diag driver has to be bound"

    def test_perm_diag_is_bound(self):
        log.info("Running Diag with -k option with bound diag driver")
        self.lin_diag_drv.load(self.diag_drv_path)
        output = DiagWrapper.exec_single("-k -p -d {} --raise".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert output["returncode"] == 0, "Error, DIAG exits with return code {}".format(output["returncode"])
        assert not self.lin_prod_drv.is_loaded(), "Error, prod driver has to be unloaded"
        assert not self.lin_prod_drv.is_bound(), "Error, prod driver has to be unbound"
        assert self.lin_diag_drv.is_loaded(), "Error, diag driver has to be loaded"
        assert self.lin_diag_drv.is_bound(), "Error, diag driver has to be bound"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
