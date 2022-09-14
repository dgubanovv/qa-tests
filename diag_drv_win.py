import os
import sys
import re
import pytest

from tools.diagper import DiagWrapper, download_diag, get_actual_diag_version, uninstall_diag
from tools import driver
from infra.test_base import TestBase
from tools.ops import get_arch, OpSystem
from tools.utils import remove_directory, get_atf_logger

log = get_atf_logger()


def setup_module(module):
    #import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "diag_drv_win"


class TestDiag(TestBase):
    
    @classmethod
    def add_diag_drv_cert(cls, path):
        arch = get_arch()
        cert_dir = "win32" if arch == "32" else "x64"
        cert = os.path.join(path, "mbu/Os/{}/aquantiaDiagPack.cer".format(cert_dir))
        cls.diag_drv.install_trusted_certificate(cert)


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

            cls.diag_dir = download_diag(cls.diag_version)
            cls.diag_ver = get_actual_diag_version(cls.diag_version)

            cls.diag_drv = driver.Driver(port=cls.dut_port, drv_type=driver.DRV_TYPE_DIAG, version=cls.dut_drv_version)
            cls.prod_drv = driver.Driver(port=cls.dut_port, version=cls.dut_drv_version)
            
            if cls.os.is_windows():
                cls.add_diag_drv_cert(cls.diag_dir)
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
        log.info("Uninstalling all drivers")
        while(self.prod_drv.is_installed() or self.diag_drv.is_installed()):
            self.diag_drv.uninstall()
            self.prod_drv.uninstall()


    if sys.platform == "win32" and 'darwin' not in sys.platform:
        params = ["-h", "/?", "-?"]
    else:
        params = ["-h", "-?"]

      
    @pytest.mark.skipif('win32' not in sys.platform, reason="Does not run on linux")
    def test_temp_without_drv(self):
        log.info("Running Diag with -s option with no installed drivers")
        output = DiagWrapper.exec_single("-s -p -d {}".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert not self.diag_drv.is_installed(), "Error, diag driver has to be uninstalled"
        assert not self.prod_drv.is_installed(), "Error, prod driver has to be uninstalled"
        
    @pytest.mark.skipif('win32' not in sys.platform, reason="Does not run on linux")
    def test_temp_with_diag_drv_and_prod_drv_in_cache(self):
        self.prod_drv.install()
        self.diag_drv.install()       
        log.info("Running Diag with -s option with already installed diag driver")
        output = DiagWrapper.exec_single("-s -p -d {}".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert self.diag_drv.is_installed(), "Error, diag driver has to be installed"
        assert not self.prod_drv.is_installed(), "Error, NDIS driver has to be uninstalled"

    @pytest.mark.skipif('win32' not in sys.platform, reason="Does not run on linux")
    def test_temp_with_diag_drv(self):
        self.diag_drv.install()       
        log.info("Running Diag with -s option with already installed diag driver")
        output = DiagWrapper.exec_single("-s -p -d {}".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert self.diag_drv.is_installed(), "Error, diag driver has to be installed"
        assert not self.prod_drv.is_installed(), "Error, NDIS driver has to be uninstalled"

    @pytest.mark.skipif('win32' not in sys.platform, reason="Does not run on linux")
    def test_temp_with_prod_drv_and_diag_drv_in_cache(self):
        self.diag_drv.install()
        self.prod_drv.install()
        log.info("Running Diag with -s option with already installed NDIS driver")
        output = DiagWrapper.exec_single("-s -p -d {}".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert not self.diag_drv.is_installed(), "Error, diag driver has to be uninstalled"
        assert self.prod_drv.is_installed(), "Error, NDIS driver has to be installed"
   
    @pytest.mark.skipif('win32' not in sys.platform, reason="Does not run on linux")
    def test_temp_with_prod_drv(self):
        self.prod_drv.install()
        log.info("Running Diag with -s option with already installed NDIS driver")
        output = DiagWrapper.exec_single("-s -p -d {}".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert not self.diag_drv.is_installed(), "Error, diag driver has to be uninstalled"
        assert self.prod_drv.is_installed(), "Error, NDIS driver has to be installed"
    
    @pytest.mark.skipif('win32' not in sys.platform, reason="Does not run on linux")
    def test_perm_without_drv(self):
        log.info("Running Diag with -k option with no installed drivers")
        output = DiagWrapper.exec_single("-k -p -d {}".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert self.diag_drv.is_installed(), "Error, diag driver has to be installed"
        assert not self.prod_drv.is_installed(), "Error, NDIS driver has to be uninstalled"

        
    @pytest.mark.skipif('win32' not in sys.platform, reason="Does not run on linux")
    def test_perm_with_diag_drv(self):
        self.diag_drv.install()
        log.info("Running Diag with -k option with already installed diag driver")
        output = DiagWrapper.exec_single("-k -p -d {}".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert self.diag_drv.is_installed(), "Error, diag driver has to be installed"
        assert not self.prod_drv.is_installed(), "Error, NDIS driver has to be uninstalled"
        

    @pytest.mark.skipif('win32' not in sys.platform, reason="Does not run on linux")
    def test_perm_with_prod_drv(self):
        self.prod_drv.install()        
        log.info("Running Diag with -k option with already installed NDIS driver")
        output = DiagWrapper.exec_single("-k -p -d {}".format(self.dut_port.replace("00","0")), self.diag_dir)
        assert self.diag_drv.is_installed(), "Error, diag driver has to be installed"
        assert not self.prod_drv.is_installed(), "Error, NDIS driver has to be uninstalled"
  
    

if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
