import copy
import os
import sys
import re
import time
import subprocess

import pytest
import yaml

from tools.diagper import DiagWrapper, download_diag, get_actual_diag_version, uninstall_diag
from tools import driver
from tools.utils import get_atf_logger, download_file
from infra.test_base import TestBase
from tools.ops import get_arch, OpSystem
from tools.constants import FELICITY_CARDS, BERMUDA_CARDS, CARD_BERMUDA_A0
from tools.command import Command


log = get_atf_logger()
pause = 10
diag_timeout = 90
DEFAULT_PATH_FW = r"/storage/export/builds/firmware/3x"

def setup_module(module):
    #import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "diag_file_path"


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
            
        re_fw = 'ssh -o \"StrictHostKeyChecking no\" aqtest@qa-nfs01 \"cat /storage/export/builds/firmware' \
            '/3x/stable/version.txt\"'
        cls.fw_version_stable = subprocess.check_output(re_fw, shell=True).replace('\n', '')
        
        if cls.dut_fw_card in FELICITY_CARDS:
            cls.Path_bdpclx = r"{1}/{0}/Customers/AQC_100/AQC100-Felicity-{0}_bdp.clx".format(cls.fw_version_stable,
                                                                                              DEFAULT_PATH_FW)
            cls.old_fw = r"{0}/3.0.33/Felicity/ATL-3.0.33!EUR-v3.4.11-AQC_AqtionDefaultB1_MDINormal" \
                "!PCIROM-3.0.4-ALL!VPD-0.0.1!AqtionB1_eur!5A2A8B4B-005.clx".format(DEFAULT_PATH_FW)
            dev_id_new = 0xd100
        elif cls.dut_fw_card in CARD_BERMUDA_A0:
            cls.Path_bdpclx = r"{1}/{0}/Customers/AQC_111_112/Bermuda-A0-{0}.clx".format(
                cls.fw_version_stable, DEFAULT_PATH_FW)
            cls.old_fw = r"{}/3.1.21/Bermuda/Bermuda-3.1.21.clx".format(DEFAULT_PATH_FW)
            dev_id_new = 0x11B1
        else:
            cls.Path_bdpclx = r"{1}/{0}/Customers/AQC_107_108/AQC107-Nikki-{0}_bdp.clx".format(cls.fw_version_stable,
                                                                                               DEFAULT_PATH_FW)
            cls.old_fw = r"{0}/3.0.33/Nikki/ATL-3.0.33!EUR-v3.4.11-AQC_AqtionDefaultB1_MDINormal!PCIROM-3.0.4-ALL!" \
                "VPD-0.0.1!AqtionB1_eur!5A2A8B4B-005.clx".format(DEFAULT_PATH_FW)
            dev_id_new = 0xd107

        download_file("nn-nfs01", cls.Path_bdpclx, os.path.join(cls.log_local_dir, "{1}-{0}_bdp.clx".format(
            cls.fw_version_stable, cls.dut_fw_card.replace('A0', ''))))
        
        cls.cmd_dict_path = r"{3}/{0}/{2}/{1}-{0}.clx".format(cls.fw_version_stable, cls.dut_fw_card.replace('A0', ''),
                                                              cls.dut_fw_card, DEFAULT_PATH_FW)
        download_file("nn-nfs01", cls.cmd_dict_path, os.path.join(cls.log_local_dir, "{0}-{1}.clx".format(
            cls.dut_fw_card.replace('A0', ''), cls.fw_version_stable)))

        download_file("nn-nfs01", cls.old_fw, os.path.join(cls.log_local_dir, "old_fw_{}.clx".format(cls.dut_fw_card)))

        aqc = {
            "clx": os.path.join(cls.log_local_dir, "{1}-{0}.clx".format(cls.fw_version_stable, 
                                                                        cls.dut_fw_card.replace('A0', ''))),
            "mac": "11:22:33:22:11:22",
            "dev_id": dev_id_new, 
        }
        aqc_file = DiagWrapper.create_aqc_file(aqc)

        
        DiagWrapper.CMD_DICT["File Path clx"] = {
            "command": os.path.join(cls.log_local_dir, "{1}-{0}.clx".format(cls.fw_version_stable, 
                                                                            cls.dut_fw_card.replace('A0', ''))),
            "pause": 15,
        }
        
        DiagWrapper.CMD_DICT["File Path aqc"] = {
            "command": aqc_file,
            "pause": 10,
        }
        
        DiagWrapper.CMD_DICT["File Path for save and compare"] = {
            "command": os.path.join(cls.log_local_dir, "new.clx"),
            "pause": 15,
        }
        
        DiagWrapper.CMD_DICT["File Path bdp.clx"] = {
            "command": os.path.join(cls.log_local_dir, "{1}-{0}_bdp.clx".format(cls.fw_version_stable, 
                                                                                cls.dut_fw_card.replace('A0', ''))),
            "pause": 10,
        }


    def test_flash_options_update(self):
        log.info("Running Diag...")
        old_fw_copy = "scp aqtest@nn-nfs01:{} {}".format(self.old_fw, os.path.join(self.log_local_dir, 
                "old_fw_{}.clx".format(self.dut_fw_card))).replace("\\", "/")
        if self.os.is_windows():
            log.info(old_fw_copy)
        else:
            log.info(old_fw_copy.replace("!", "\!"))
        log.info("scp aqtest@nn-nfs01:{} {}".format(self.cmd_dict_path, os.path.join(self.log_local_dir, 
            "{0}-{1}.clx".format(self.dut_fw_card.replace('A0', ''), self.fw_version_stable))).replace("\\", "/"))
        DiagWrapper.exec_single("-f {} --phy_clx_bdp".format(os.path.join(self.log_local_dir, "old_fw_{}.clx".format(
            self.dut_fw_card))), self.diag_dir)
        time.sleep(10)
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        time.sleep(pause)
        
        com.send_stdin([DiagWrapper.CMD_DICT["Flash"],
                        DiagWrapper.CMD_DICT["Update Flash Image"],
                        DiagWrapper.CMD_DICT["File Path clx"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["PHY flash clx"],
                        DiagWrapper.CMD_DICT["Exit"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        assert com.result["returncode"] == 0
        log.info('Exit code: {}, reason: {}'.format(com.result["returncode"], com.result["reason"]))
        
        re_pass = re.compile("Flash update successful.")
        assert any(re_pass.match(line) for line in com.result["output"])
        log.info('test: Flash update successful')
        
        re_pass_new_fw = re.compile("Firmware Version = {}".format(self.fw_version_stable))
        assert any(re_pass_new_fw.match(line) for line in com.result["output"])
        log.info('test: firmware version established')
   
    def test_flash_options_save_compare(self):
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        time.sleep(pause)
        
        com.send_stdin([DiagWrapper.CMD_DICT["Flash"],
                        DiagWrapper.CMD_DICT["Save Flash Contents To File"],
                        DiagWrapper.CMD_DICT["File Path for save and compare"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Compare Flash Contents To CLX File"],
                        DiagWrapper.CMD_DICT["File Path for save and compare"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        assert com.result["returncode"] == 0
        log.info('Exit code: {}, reason: {}'.format(com.result["returncode"], com.result["reason"]))
        
        if self.os.is_windows():
            re_saved = re.compile(r"Flash image successfully saved to \w\:\/*(\\*\w*)+\.*\w*")
        else:
            re_saved = re.compile(r"Flash image successfully saved to (\/*\w*)+\.*\w*")
        log.info('"Flash image successfully saved" is found in the output. OK.')
        assert(os.path.getsize(os.path.join(self.log_local_dir, "new.clx")) > 4194000)
        log.info('File {} exists, size = {} bytes. OK.'.format(os.path.join(self.log_local_dir, "new.clx"),
            os.path.getsize(os.path.join(self.log_local_dir, "new.clx"))))
        assert any(re_saved.match(line) for line in com.result["output"] \
            if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line)
        re_compare = re.compile("Starting Flash Verification  .(\s*\.*)* Pass")
        assert any(re_compare.search(line) for line in com.result["output"])
        log.info('"Flash Verification" step has been passed in the output. OK.')

    def test_specialconf_select(self):
        log.info("Running Diag...")
        old_fw_copy = "scp aqtest@nn-nfs01:{} {}".format(self.old_fw, os.path.join(self.log_local_dir, 
                "old_fw_{}.clx".format(self.dut_fw_card))).replace("\\", "/")
        if self.os.is_windows():
            log.info(old_fw_copy)
        else:
            log.info(old_fw_copy.replace("!", "\!"))
        log.info("scp aqtest@nn-nfs01:{} {}".format(self.cmd_dict_path, os.path.join(self.log_local_dir, 
            "{0}-{1}.clx".format(self.dut_fw_card.replace('A0', ''), self.fw_version_stable))).replace("\\", "/"))
        DiagWrapper.exec_single("-f {} --phy_clx_bdp".format(os.path.join(self.log_local_dir, "old_fw_{}.clx".format(
            self.dut_fw_card))), self.diag_dir)
        time.sleep(10)
        d = DiagWrapper(self.diag_dir, "--password !h:ahT8uW6 --raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        time.sleep(pause)
        
        com.send_stdin([DiagWrapper.CMD_DICT["Special configuration"],
                        DiagWrapper.CMD_DICT["Select New FW and OpROM Driver"],
                        DiagWrapper.CMD_DICT["File Path clx"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Apply New Settings"],
                        DiagWrapper.CMD_DICT["PHY flash clx"],
                        DiagWrapper.CMD_DICT["Exit"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        assert com.result["returncode"] == 0
        log.info('Exit code: {}, reason: {}'.format(com.result["returncode"], com.result["reason"]))
        
        re_select = re.compile(r"2\) Select New FW and OpROM Driver \[{0}-{1}.clx\]".format(
            self.dut_fw_card.replace('A0', ''), self.fw_version_stable)) 
        assert any(re_select.search(line) for line in com.result["output"])
        log.info('test: Select New FW and OpROM Driver: firmware version got up correct')
        re_config = re.compile("NCB pointers were updated.")
        assert any(re_config.search(line) for line in com.result["output"])
        log.info('test: NCB pointers were updated')
        re_pass_new_fw = re.compile("Firmware Version = {}".format(self.fw_version_stable))
        assert any(re_pass_new_fw.match(line) for line in com.result["output"])
        log.info('test: firmware version established')
   
    def test_specialconf_BDP(self):
        log.info("Running Diag...")
        log.info("scp aqtest@nn-nfs01:{} {}".format(self.Path_bdpclx, os.path.join(self.log_local_dir, 
            "{1}-{0}_bdp.clx".format(self.fw_version_stable, self.dut_fw_card.replace('A0', '')))).replace("\\", "/"))
        d = DiagWrapper(self.diag_dir, "--password !h:ahT8uW6 --raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        time.sleep(pause)
        
        com.send_stdin([DiagWrapper.CMD_DICT["Special configuration"],
                        DiagWrapper.CMD_DICT["Board Dependent Provisioning"],
                        DiagWrapper.CMD_DICT["MAC clx/bin File"],
                        DiagWrapper.CMD_DICT["File Path bdp.clx"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["PHY clx/bin file"],
                        DiagWrapper.CMD_DICT["File Path bdp.clx"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"],
                        DiagWrapper.CMD_DICT["Apply New Settings"],
                        DiagWrapper.CMD_DICT["Exit"],
                        DiagWrapper.CMD_DICT["Exit"]])

        com.join(timeout=diag_timeout)
        assert com.result["returncode"] == 0
        log.info('Exit code: {}, reason: {}'.format(com.result["returncode"], com.result["reason"]))
        re_bdp=re.compile(r"\[mac_bdp: \[*(\w*\,*\s*)*\]*, phy_bdp: \[*(\w*\,*\s*)+\]*]")
        assert any(re_bdp.search(line) for line in com.result["output"] \
            if not line.startswith('=====') and 'Diagnostic Utility Version' not in line and 'Using it...' not in line)
        log.info('test:mac_bdp and phy_bdp are displayed')
       
    def test_flash_options_program_mirror(self):
        log.info("Running Diag...")
        log.info("scp aqtest@nn-nfs01:{} {}".format(self.cmd_dict_path, os.path.join(self.log_local_dir, 
            "{0}-{1}.clx".format(self.dut_fw_card.replace('A0', ''), self.fw_version_stable))).replace("\\", "/"))
        d = DiagWrapper(self.diag_dir, "--password !h:ahT8uW6 --raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        time.sleep(pause)
        
        com.send_stdin([DiagWrapper.CMD_DICT["Flash"],
                        DiagWrapper.CMD_DICT["Program Mirror Image of CLX File To Flash"],
                        DiagWrapper.CMD_DICT["File Path clx"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        assert com.result["returncode"] == 0
        log.info('Exit code: {}, reason: {}'.format(com.result["returncode"], com.result["reason"]))
        re_prog_mirror = re.compile(r"\. Pass" )
        assert any(re_prog_mirror.search(line) for line in com.result["output"])
        log.info('"Program Mirror Image" has been passed')

    def test_specialconf_config(self):
        log.info("Running Diag...")
        d = DiagWrapper(self.diag_dir, "--password !h:ahT8uW6 --raise")
        com = Command(cmd=d.cmd)
        com.run_async()
        time.sleep(pause)
        
        com.send_stdin([DiagWrapper.CMD_DICT["Special configuration"],
                        DiagWrapper.CMD_DICT["Config File"],
                        DiagWrapper.CMD_DICT["File Path aqc"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Apply New Settings"],
                        DiagWrapper.CMD_DICT["Exit"],
                        DiagWrapper.CMD_DICT["Device Info"],
                        DiagWrapper.CMD_DICT["Enter"],
                        DiagWrapper.CMD_DICT["Exit"]])
        com.join(timeout=diag_timeout)
        assert com.result["returncode"] == 0
        log.info('Exit code: {}, reason: {}'.format(com.result["returncode"], com.result["reason"]))
        re_pass_new_fw = re.compile("Firmware Version = {}".format(self.fw_version_stable))
        assert any(re_pass_new_fw.match(line) for line in com.result["output"])
        log.info('test: firmware version established')
        
        
if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
