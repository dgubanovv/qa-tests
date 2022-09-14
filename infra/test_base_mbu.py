import os, sys
import pytest
import yaml
import random
import time

from test_base import TestBase
from tools.mbuper import download_mbu
from tools.utils import get_atf_logger, remove_directory
from tools import driver
from tools.ops import OpSystem

log = get_atf_logger()
felicity_skip_loopback = ['PHY SIF', 'PHY NET', 'RJ45']
mbu_seed = os.environ.get("SEED", -1)

class TestBaseMbu(TestBase):
    @classmethod
    def setup_class(cls):
        super(TestBaseMbu, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.install_firmwares()

            cls.diag_drv = driver.Driver(port=cls.dut_port, drv_type=driver.DRV_TYPE_DIAG, version='latest')
            cls.diag_drv.install()

            cls.mbu_dir = download_mbu(cls.mbu_version, cls.working_dir)

            if OpSystem().is_linux():
                default_linux_driver_path = 'Os/linux/driver/src'
                os.environ['LD_LIBRARY_PATH'] = os.path.join(cls.mbu_dir, default_linux_driver_path)

            cls.log_local_dir = os.path.join(cls.mbu_dir, "logs")
            sys.path.append(cls.mbu_dir)
            import support
            cls.maccontrol = support.get_mac_control(port=cls.dut_port)
            if cls.maccontrol is None:
                raise ValueError("Error! Maccontrol is None!")
            support.set_device_properties(cls.maccontrol)

            sys.path.append(os.path.join(cls.mbu_dir, 'Scripts'))

            import logcontrol
            import maclib

            cls.seed = time.time() * 1000000 if mbu_seed == -1 else int(mbu_seed, 0)
            log.info('Random seed value is %#x' % cls.seed)
            random.seed(cls.seed)

            mbu_instance = maclib.newInstance("mbu")
            mbu_instance_name = "{}_{}".format("mbu", mbu_instance.instance)

            fdir = os.path.dirname(os.path.abspath(__file__))
            root_dir = os.path.split(fdir)[0]
            log_cfg_file = os.path.join(os.path.join(root_dir, "tools"), "logging_with_mbu.conf")
            tmp_log_config = cls._modify_log_config(log_cfg_file)

            logcontrol.parseLogOptions(tmp_log_config,
                                       instance=mbu_instance.instance,
                                       instanceName=mbu_instance_name)
        except Exception as e:
            log.exception("Failed while setting up MBU base class")
            raise e

    def check_parameters(self, loopback, speed):
        if self.dut_fw_card == 'Felicity' and loopback in felicity_skip_loopback:
            pytest.skip("Doesn't run on Felicity.")
        if speed not in self.supported_speeds:
            pytest.skip("Unsupported speed. {} not in {}.".format(speed, self.dut_fw_speed))
        if self.lkp_hostname is not None and loopback == 'RJ45':
            pytest.skip("RJ45 isn't available")
        if speed == '1G' and loopback == 'RJ45':
            pytest.skip("RJ45 doesn't run on 1G.")

    @classmethod
    def _modify_log_config(cls, cfg_file):
        with open(cfg_file, "r") as f:
            log_cfg_data = yaml.safe_load(f)
        print(log_cfg_data["handlers"]["wholelog"])
        for key, handler in log_cfg_data["handlers"].iteritems():
            if log_cfg_data["handlers"][key].get("filename") is not None:
                log_cfg_data["handlers"][key]["filename"] = os.path.join(cls.mbu_dir,
                                                                         log_cfg_data["handlers"][key]["filename"])
        fdir = os.path.dirname(cfg_file)
        tmp_file = os.path.join(fdir, "tmp_log_config_with_mbu.conf")
        with open(tmp_file, "w") as f:
            yaml.dump(log_cfg_data, f)
        return tmp_file

    def setup_method(self, method):
        super(TestBaseMbu, self).setup_method(method)

    @classmethod
    def teardown_class(cls):
        super(TestBaseMbu, cls).teardown_class()
        cls.maccontrol.close()
        remove_directory(cls.mbu_dir)

    def set_seed(self):
        if self.seed != -1:
            log.info('Seed value is %#x' % self.seed)
            random.seed(self.seed)

if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
