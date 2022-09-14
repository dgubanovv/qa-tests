import os
import re
from time import sleep

import pytest

from tools.command import Command
from tools.diagper import DiagWrapper, download_diag, get_actual_diag_version, uninstall_diag
from tools import driver
from infra.test_base import TestBase, idparametrize
from tools.ops import get_arch, OpSystem
from tools.utils import remove_directory, get_atf_logger

log = get_atf_logger()
diag_timeout = 30
pause = 5


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "diag_select_dev"


class TestDiag(TestBase):
    @classmethod
    def add_diag_drv_cert(cls, path):
        arch = get_arch()
        cert_dir = "win32" if arch == "32" else "x64"
        cert = os.path.join(path, "mbu/Os/{}/aquantiaDiagPack.cer".format(cert_dir))
        cls.diag_drv_first_dev.install_trusted_certificate(cert)
        cls.diag_drv_second_dev.install_trusted_certificate(cert)

    @classmethod
    def setup_class(cls):
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
            if len(cls.dut_card_dict) == 0:
                raise Exception("There isn't a dictionary of cards and ports")
            elif len(cls.dut_card_dict) == 1:
                raise Exception("This is multiple device test, more than one card required")
            else:
                cls.first_port = cls.dut_card_dict.keys()[0]
                cls.second_port = cls.dut_card_dict.keys()[1]
                cls.first_dev_id = cls.dut_card_dict[cls.first_port]
                cls.second_dev_id = cls.dut_card_dict[cls.second_port]
                cls.diag_drv_first_dev = driver.Driver(port=cls.first_port, drv_type=driver.DRV_TYPE_DIAG,
                                                       version=cls.dut_drv_version)
                cls.prod_drv_first_dev = driver.Driver(port=cls.first_port, version=cls.dut_drv_version)
                cls.diag_drv_second_dev = driver.Driver(port=cls.second_port, drv_type=driver.DRV_TYPE_DIAG,
                                                        version=cls.dut_drv_version)
                cls.prod_drv_second_dev = driver.Driver(port=cls.second_port, version=cls.dut_drv_version)
                cls.diag_drv_first_dev.install()
                cls.diag_drv_second_dev.install()
                cls.first_port = cls.first_port.replace("00", "0")
                cls.second_port = cls.second_port.replace("00", "0")
                DiagWrapper.exec_single("--flash_fields dev_id={} -p -d {} --password !h:ahT8uW6" 
                                        "".format(cls.first_dev_id, cls.first_port),
                                        cls.diag_dir)
                DiagWrapper.exec_single("--flash_fields dev_id={} -p -d {} --password !h:ahT8uW6"
                                        "".format(cls.second_dev_id, cls.second_port),
                                        cls.diag_dir)
            if cls.os.is_windows():
                cls.add_diag_drv_cert(cls.diag_dir)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestDiag, cls).teardown_class()
        if cls.os.is_linux():
            uninstall_diag()
        else:
            remove_directory(cls.diag_dir)

    def setup_method(self, method):
        super(TestDiag, self).setup_method(method)
        log.info("Uninstalling drivers of first device")
        while self.prod_drv_first_dev.is_installed() or self.diag_drv_first_dev.is_installed():
            self.diag_drv_first_dev.uninstall()
            self.prod_drv_first_dev.uninstall()
        log.info("Uninstalling drivers of second device")
        while self.prod_drv_second_dev.is_installed() or self.diag_drv_second_dev.is_installed():
            self.diag_drv_second_dev.uninstall()
            self.prod_drv_second_dev.uninstall()

    def is_in_output(self, output, exp_res):
        output = ' '.join(output)
        result = re.findall(exp_res, output)
        return len(result) != 0

    def check_two_devices_in_output(self, output):
        exp_res = r"".join([self.first_port, ".{1,30}", self.second_port])
        assert self.is_in_output(output, exp_res), "Two cards must be represented"

    def check_return_code(self, com):
        assert com.result["returncode"] == 0, "Error, Diag exits with return code {}".format(com.result["returncode"])

    def test_no_drv_on_both_dev(self):
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        com.join(timeout=diag_timeout)
        assert self.is_in_output(com.result["output"], 'No devices found! Diag driver is probably not installed '
                            '[(use "-k" or "-s" option to install)]'), "Diag tool cannot run without any driver"

    def test_diag_drv_on_dev1_and_prod_drv_on_dev2(self):
        self.diag_drv_first_dev.install()
        self.prod_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        self.check_return_code(com)
        self.check_two_devices_in_output(com.result["output"])
        # TODO: check that if you select second device, diag tool ask you to run with option -s/-k

    def test_prod_drv_on_dev1_and_diag_drv_on_dev2(self):
        self.prod_drv_first_dev.install()
        self.diag_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        com.join(timeout=diag_timeout)
        
        assert ('Device {} is found, but diag driver is not installed '
            '(use "-k" or "-s" option to install). Diag driver is installed on {} (use "-d").' \
            .format(self.first_port, self.second_port) in " ".join(com.result["output"]))

    def test_diag_drv_on_both_dev(self):
        self.diag_drv_first_dev.install()
        self.diag_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        self.check_return_code(com)
        self.check_two_devices_in_output(com.result["output"])

    def test_prod_drv_on_both_dev(self):
        self.prod_drv_first_dev.install()
        self.prod_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        com.join(timeout=diag_timeout)
        assert self.is_in_output(com.result["output"], 'No devices found! Diag driver is probably not installed '
                             '[(use "-k" or "-s" option to install)]'), "Diag tool cannot run without any diag driver"

    def test_diag_drv_on_dev1(self):
        self.diag_drv_first_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        self.check_return_code(com)
        self.check_two_devices_in_output(com.result["output"])
        # TODO: check that if you select second device, diag tool ask you to run with option -s/-k

    def test_diag_drv_on_dev2(self):
        self.diag_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        com.join(timeout=diag_timeout)
        assert ('Device {} is found, but diag driver is not installed '
            '(use "-k" or "-s" option to install). Diag driver is installed on {} (use "-d").' \
            .format(self.first_port, self.second_port) in " ".join(com.result["output"]))

    def test_prod_drv_on_dev1(self):
        self.prod_drv_first_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        sleep(pause)
        com.join(timeout=diag_timeout)
        assert self.is_in_output(com.result["output"], 'No devices found! Diag driver is probably not installed '
                                '[(use "-k" or "-s" option to install)]'), "Diag tool cannot run without any diag driver"

    def test_prod_drv_on_dev2(self):
        self.prod_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        com.join(timeout=diag_timeout)
        assert self.is_in_output(com.result["output"], 'No devices found! Diag driver is probably not installed '
                                '[(use "-k" or "-s" option to install)]'), "Diag tool cannot run without any diag driver"

    def test_show_dev1(self):
        self.diag_drv_first_dev.install()
        self.diag_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Select 1 device"],
                        DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        before_select_dev = r"".join([self.first_port, ".{1,30}",
                                      self.second_port])
        after_select_dev = r"".join([self.first_port, ".*[(Selected)].*",
                                     self.second_port])
        exp_res = r"".join([before_select_dev, ".*", after_select_dev])
        exp_dev_id = r"".join(["Device ID = ", self.first_dev_id])
        self.check_return_code(com)
        self.check_two_devices_in_output(com.result["output"])
        assert self.is_in_output(com.result["output"], exp_res), "First device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "First device ID must be in Device Info"

    def test_show_dev2(self):
        self.diag_drv_first_dev.install()
        self.diag_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Select 2 device"],
                        DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        before_select_dev = r"".join([self.first_port, ".{1,30}",
                                      self.second_port])
        after_select_dev = r"".join([self.first_port, ".*",
                                     self.second_port, ".*[(Selected)]"])
        exp_res = r"".join([before_select_dev, ".*", after_select_dev])
        exp_dev_id = r"".join(["Device ID = ", self.second_dev_id])
        self.check_return_code(com)
        self.check_two_devices_in_output(com.result["output"])
        assert self.is_in_output(com.result["output"], exp_res), "Second device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"

    def test_show_dev1_after_dev2(self):
        self.diag_drv_first_dev.install()
        self.diag_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Select 2 device"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Select 1 device"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        before_select_dev = r"".join([self.first_port, ".{1,30}",
                                      self.second_port])
        after_select_second_dev = r"".join([self.first_port, ".*",
                                            self.second_port, ".*[(Selected)]"])
        after_select_first_dev = r"".join([self.first_port, ".*[(Selected)].*",
                                           self.second_port])
        exp_res = r"".join([before_select_dev, ".*", after_select_second_dev, ".*", after_select_first_dev])
        exp_dev_ids = r"".join(["Device ID = ", self.second_dev_id, ".*", "Device ID = ", self.first_dev_id])
        self.check_return_code(com)
        self.check_two_devices_in_output(com.result["output"])
        assert self.is_in_output(com.result["output"], exp_res), "Second device must be selected after the firsts" \
                                                                 " one was selected"
        assert self.is_in_output(com.result["output"], exp_dev_ids), "First device ID must be in Device Info " \
                                                                     "after the firsts one was selected"

    def test_show_dev2_after_dev1(self):
        self.diag_drv_first_dev.install()
        self.diag_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Select 1 device"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Select 2 device"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)

        before_select_dev = r"".join([self.first_port, ".{1,30}",
                                      self.second_port])
        after_select_first_dev = r"".join([self.first_port, ".*[(Selected)].*",
                                           self.second_port])
        after_select_second_dev= r"".join([self.first_port, ".*",
                                           self.second_port, ".*[(Selected)]"])
        exp_res = r"".join([before_select_dev, ".*", after_select_first_dev, ".*", after_select_second_dev])
        exp_dev_ids = r"".join(["Device ID = ", self.first_dev_id, ".*", "Device ID = ", self.second_dev_id])
        self.check_return_code(com)
        self.check_two_devices_in_output(com.result["output"])
        assert self.is_in_output(com.result["output"], exp_res), "Second device must be selected after the firsts" \
                                                                 " one was selected"
        assert self.is_in_output(com.result["output"], exp_dev_ids), "First device ID must be in Device Info " \
                                                                     "after the firsts one was selected"

    def test_show_dev1_with_opt_d_pciport(self):
        self.diag_drv_first_dev.install()
        self.diag_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d {} --raise".format(self.first_port))
        com = Command(cmd=d.cmd)
        com.run_async()
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_res = r"".join([self.first_port, ".*[(Selected)].*",
                            self.second_port])
        exp_dev_id = r"".join(["Device ID = ", self.first_dev_id])
        self.check_return_code(com)
        assert self.is_in_output(com.result["output"], exp_res), "First device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "First device ID must be in Device Info"

    def test_show_dev2_with_opt_d_index(self):
        self.diag_drv_first_dev.install()
        self.diag_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d 1 --raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_res = r"".join([self.first_port, ".{1,30}",
                            self.second_port, ".*[(Selected)]"])
        exp_dev_id = r"".join(["Device ID = ", self.second_dev_id])
        self.check_return_code(com)
        assert self.is_in_output(com.result["output"], exp_res), "Second device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"
    
    def test_show_dev1_with_opt_d_port_and_s(self):
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d {} -s --raise".format(self.first_port.replace("pci", "")))
        com = Command(cmd=d.cmd)
        com.run_async()
        sleep(10)
        assert self.diag_drv_first_dev.is_installed(), "Diag driver must be installed on first device during diag"
        assert not self.diag_drv_second_dev.is_installed(), "Diag driver must not be installed on second device " \
                                                            "during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_res = r"".join([self.first_port, "  [(Selected)]"])
        exp_dev_id = r"".join(["Device ID = ", self.first_dev_id])
        self.check_return_code(com)
        sleep(pause)
        assert self.is_in_output(com.result["output"], exp_res), "First device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "First device ID must be in Device Info"
    
    def test_show_dev2_with_opt_d_pciport_and_s(self):
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d {} -s --raise".format(self.second_port))
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_second_dev.is_installed(), "Diag driver must be installed on second device during diag"
        assert not self.diag_drv_first_dev.is_installed(), "Diag driver must not be installed on first device " \
                                                           "during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_res = r"".join([self.second_port, "  [(Selected)]"])
        exp_dev_id = r"".join(["Device ID = ", self.second_dev_id])
        self.check_return_code(com)
        assert self.is_in_output(com.result["output"], exp_res), "Second device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"

    def test_show_dev1_with_opt_d_index_and_s_when_dev2_has_prod_drv(self):
        self.prod_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d 0 -s --raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_first_dev.is_installed(), "Diag driver must be installed on first device during diag"
        assert not self.diag_drv_second_dev.is_installed(), "Diag driver must not be installed on second device " \
                                                            "during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_res = r"".join([self.first_port, "  [(Selected)]"])
        exp_dev_id = r"".join(["Device ID = ", self.first_dev_id])
        self.check_return_code(com)
        assert self.is_in_output(com.result["output"], exp_res), "First device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "First device ID must be in Device Info"

    def test_show_dev2_with_opt_d_port_and_s_when_dev1_has_prod_drv(self):
        self.prod_drv_first_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d {} -s --raise".format(self.second_port.replace("pci", "")))
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_second_dev.is_installed(), "Diag driver must be installed on second device during diag"
        assert not self.diag_drv_first_dev.is_installed(), "Diag driver must not be installed on first device " \
                                                           "during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_res = r"".join([self.second_port, "  [(Selected)]"])
        exp_dev_id = r"".join(["Device ID = ", self.second_dev_id])
        self.check_return_code(com)
        assert self.is_in_output(com.result["output"], exp_res), "Second device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"

    def test_show_dev1_with_opt_d_pciport_and_k(self):
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d {} -k --raise".format(self.first_port))
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_first_dev.is_installed(), "Diag driver must be installed on first device during diag"
        assert not self.diag_drv_second_dev.is_installed(), "Diag driver must not be installed on second device " \
                                                            "during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_res = r"".join([self.first_port, "  [(Selected)]"])
        exp_dev_id = r"".join(["Device ID = ", self.first_dev_id])
        self.check_return_code(com)
        assert self.is_in_output(com.result["output"], exp_res), "First device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "First device ID must be in Device Info"

    def test_show_dev2_with_opt_d_index_and_k(self):
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d 1 -k --raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_second_dev.is_installed(), "Diag driver must be installed on second device during diag"
        assert not self.diag_drv_first_dev.is_installed(), "Diag driver must not be installed on first device" \
                                                           " during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_res = r"".join([self.second_port, "  [(Selected)]"])
        exp_dev_id = r"".join(["Device ID = ", self.second_dev_id])
        self.check_return_code(com)
        assert self.is_in_output(com.result["output"], exp_res), "Second device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"

    def test_show_dev1_with_opt_d_port_and_k_when_dev2_has_prod_drv(self):
        self.prod_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d {} -k --raise".format(self.first_port.replace("pci", "")))
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_first_dev.is_installed(), "Diag driver must be installed on first device during diag"
        assert not self.diag_drv_second_dev.is_installed(), "Diag driver must not be installed on second device " \
                                                            "during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_res = r"".join([self.first_port, "  [(Selected)]"])
        exp_dev_id = r"".join(["Device ID = ", self.first_dev_id])
        self.check_return_code(com)
        assert self.is_in_output(com.result["output"], exp_res), "First device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "First device ID must be in Device Info"

    def test_show_dev2_with_opt_d_pciport_and_k_when_dev1_has_prod_drv(self):
        self.prod_drv_first_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d {} -k --raise".format(self.second_port))
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_second_dev.is_installed(), "Diag driver must be installed on second device during diag"
        assert not self.diag_drv_first_dev.is_installed(), "Diag driver must not be installed on first device" \
                                                           " during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Go back to main menu"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_res = r"".join([self.second_port, "  [(Selected)]"])
        exp_dev_id = r"".join(["Device ID = ", self.second_dev_id])
        self.check_return_code(com)
        assert self.is_in_output(com.result["output"], exp_res), "Second device must be selected"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"

    def test_dev1_prod_s_d_pciport_select_dev2_diag(self):
        self.diag_drv_second_dev.install()
        self.prod_drv_first_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d {} -s --raise".format(self.first_port))
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_first_dev.is_installed(), "Diag driver must be installed on first device" \
                                                           " during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Choose device to test:2"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_dev_id = r"".join(["Device ID = ", self.second_dev_id])
        self.check_return_code(com)
        assert not self.diag_drv_first_dev.is_installed(), "Error, diag driver has to be uninstalled"
        assert self.prod_drv_first_dev.is_installed(), "Error, prod driver has to be installed"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"

    def test_dev2_prod_s_d_pciport_select_dev1_diag(self):
        self.diag_drv_first_dev.install()
        self.prod_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d {} -s --raise".format(self.second_port))
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_second_dev.is_installed(), "Diag driver must be installed on second device" \
                                                           " during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Choose device to test:1"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_dev_id = r"".join(["Device ID = ", self.first_dev_id])
        self.check_return_code(com)
        assert not self.diag_drv_second_dev.is_installed(), "Error, diag driver has to be uninstalled"
        assert self.prod_drv_second_dev.is_installed(), "Error, prod driver has to be installed"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"

    def test_dev2_diag_s_d_index_select_dev1_diag(self):
        self.diag_drv_first_dev.install()
        self.diag_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d 1 -s --raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_second_dev.is_installed(), "Diag driver must be installed on second device" \
                                                           " during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Choose device to test:1"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_dev_id = r"".join(["Device ID = ", self.first_dev_id])
        self.check_return_code(com)
        assert self.diag_drv_first_dev.is_installed(), "Error, diag driver has to be installed"
        assert self.diag_drv_second_dev.is_installed(), "Error, diag driver has to be installed"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"
        
    def test_dev1_diag_s_d_port_select_dev2_diag(self):
        self.diag_drv_second_dev.install()
        self.diag_drv_first_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d {} -s --raise".format(self.first_port.replace("pci", "")))
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_first_dev.is_installed(), "Diag driver must be installed on first device" \
                                                           " during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Choose device to test:2"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_dev_id = r"".join(["Device ID = ", self.second_dev_id])
        self.check_return_code(com)
        assert self.diag_drv_first_dev.is_installed(), "Error, diag driver has to be installed"
        assert self.diag_drv_second_dev.is_installed(), "Error, diag driver has to be installed"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"
        
    def test_dev1_s_d_pciport_select_dev2_diag(self):
        self.diag_drv_second_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d {} -s --raise".format(self.first_port))
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_first_dev.is_installed(), "Diag driver must be installed on first device" \
                                                           " during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Choose device to test:2"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_dev_id = r"".join(["Device ID = ", self.second_dev_id])
        self.check_return_code(com)
        assert self.diag_drv_first_dev.is_installed(), "Error, diag driver has to be installed"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"
        assert self.diag_drv_second_dev.is_installed(), "Error, diag driver has to be installed"

    def test_dev2_s_d_index_select_dev1_diag(self):
        self.diag_drv_first_dev.install()
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "-d 1 -s --raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        assert self.diag_drv_second_dev.is_installed(), "Diag driver must be installed on second device" \
                                                           " during diag"
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        DiagWrapper.CMD_DICT["Choose device to test:1"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_dev_id = r"".join(["Device ID = ", self.first_dev_id])
        self.check_return_code(com)
        assert self.diag_drv_second_dev.is_installed(), "Error, diag driver has to be installed"
        assert self.diag_drv_first_dev.is_installed(), "Error, diag driver has to be installed"
        assert self.is_in_output(com.result["output"], exp_dev_id), "Second device ID must be in Device Info"

    def install_drv(self, drv1, drv2):
        if drv1 in ['prod', 'diag']:
            getattr(self, drv1 + '_drv_first_dev').install()
        if drv2 in ['prod', 'diag']:
            getattr(self, drv2 + '_drv_second_dev').install()

    def check_install_driver_before(self, port):
        if port == self.first_port:
            assert self.diag_drv_first_dev.is_installed(), "Diag driver must be installed on first device during diag"
        else:
            assert self.diag_drv_second_dev.is_installed(), "Diag driver must be installed on second device" \
                                                           " during diag"
    def check_drv_on_device_after_exit(self, dev, drv, other_drv):
        if drv == 'diag':
            assert getattr(self, "diag_drv_" + dev + "_dev").is_installed(), "Error, diag driver has to be installed"
        elif drv == 'prod':
            assert not getattr(self, "diag_drv_" + dev + "_dev").is_installed(), "Error, diag driver has to be uninstalled"
            assert getattr(self, "prod_drv_" + dev + "_dev").is_installed(), "Error, prod driver has to be installed"
        else:
            if other_drv == 'diag':
                # expected behavior on Windows as we can't rollback to NULL driver without touching other devices
                assert getattr(self, "diag_drv_" + dev + "_dev").is_installed(), "Error, diag driver has to be installed"
            else:
                assert not getattr(self, "diag_drv_" + dev + "_dev").is_installed(), "Error, diag driver has to be uninstalled"

    def check_install_driver_after(self, drv1, drv2, port, install_key):
        if install_key == "-s":
            self.check_drv_on_device_after_exit("first", drv1, drv2)
            self.check_drv_on_device_after_exit("second", drv2, drv1)
        else:
            if port == self.first_port:
                assert self.diag_drv_first_dev.is_installed(), "Error, diag driver has to be installed"
                if install_key == "-k" and drv1 != "prod":
                    # Diag removes diag driver from the first device and OS Windows installs prod driver automatically
                    drv1 = "diag"
                self.check_drv_on_device_after_exit("second", drv2, drv1)
            else:
                assert self.diag_drv_second_dev.is_installed(), "Error, diag driver has to be installed"
                if install_key == "-k" and drv2 != "prod":
                    # Diag removes diag driver from the second device and OS Windows installs prod driver automatically
                    drv2 = "diag"
                self.check_drv_on_device_after_exit("first", drv1, drv2)

    def choose_device_to_test(self, port):
        if port == self.first_port:
            return DiagWrapper.CMD_DICT["Choose device to test:2"]
        else:
            return DiagWrapper.CMD_DICT["Choose device to test:1"]

    def other_port(self, port):
        if port == self.first_port:
            return self.second_port
        else: 
            return self.first_port

    def dev_id_by_port(self, port):
        if port == self.first_port:
            return self.first_dev_id
        else:
            return self.second_dev_id

    def select_device(self, drv1, drv2, port, key):
        if port == 'first':
            port = self.first_port
        else:
            port = self.second_port
        self.install_drv(drv1, drv2)
        log.info("Running Diag...")

        d = DiagWrapper(self.diag_dir, "-d {} {} --raise".format(port, key))
        com = Command(cmd=d.cmd)
        com.run_async()
        
        if key in ["-s", "-k"]:
            self.check_install_driver_before(port)
        sleep(pause)
        com.send_stdin([DiagWrapper.CMD_DICT["Select device"],
                        self.choose_device_to_test(port),
                        DiagWrapper.CMD_DICT["y"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        exp_dev_id = r"".join(["Device ID = ", self.dev_id_by_port(self.other_port(port))])
        self.check_return_code(com)
        self.check_install_driver_after(drv1, drv2, port, key)
        assert self.is_in_output(com.result["output"], exp_dev_id), "{} must be in Device Info".format(exp_dev_id)
 
    @idparametrize("key", ["-s", "-k"])
    @idparametrize("port_to_select", ["first", "second"])
    @idparametrize("drv1, drv2", [("no", "no"), ("prod", "prod"), ("no", "prod"), ("prod", "no")])
    def test_select(self, drv1, drv2, port_to_select, key):
        self.select_device(drv1, drv2, port_to_select, key)

    @idparametrize("drv1, drv2, port_to_select", [("diag", "prod", "first"), ("diag", "no", "first"), \
                                        ("no", "diag", "second"), ("prod", "diag", "second")])
    def test_select_without_key(self, drv1, drv2, port_to_select):
        self.select_device(drv1, drv2, port_to_select, "")

if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
