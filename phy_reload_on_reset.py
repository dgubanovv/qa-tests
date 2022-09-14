import os
import re

import pytest

from infra.test_base import TestBase
from tools.command import Command
from tools.constants import FELICITY_CARDS
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.firmware import Firmware
from tools.log import get_atf_logger
from tools.ops import OpSystem

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "phy_reload_on_reset"


class TestPhyReloadOnReset(TestBase):

    FIRMWARE_VERSIONS = ["3x/3.1.38", "3x/3.1.48", "3x/3.1.51"]

    @classmethod
    def setup_class(cls):
        super(TestPhyReloadOnReset, cls).setup_class()

        try:
            assert cls.dut_fw_card not in FELICITY_CARDS

            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def burn_firmware(self, version):
        dut_firmware = Firmware(port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
                                version=version, mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
                                pause=self.dut_fw_pause, pcirom=self.dut_fw_pcirom,
                                dirtywake=self.dut_fw_dirtywake, host=self.dut_hostname,
                                bdp=self.dut_bdp, sign=self.dut_sign, se_enable=self.dut_se)
        dut_firmware.install(overrides=self.get_flash_override()[0])

    def get_phy_fw_version(self):
        cmd = "readstat"
        if not OpSystem().is_windows():
            cmd = "sudo " + cmd
        res = Command(cmd=cmd).wait(30)
        if res["returncode"] != 0:
            raise Exception("Failed to run readstat")

        re_phy_ver = re.compile(r".*Firmware Version = .* VerStr: ([a-zA-Z0-9\-\.]+): .*", re.DOTALL)
        for line in res["output"]:
            m = re_phy_ver.match(line)
            if m is not None:
                return m.group(1)

    def test_phy_reload(self):
        dut_driver = Driver(port=self.dut_port, version="latest", type=DRV_TYPE_DIAG)
        dut_driver.install()

        for i in range(100):
            fw_ver = self.FIRMWARE_VERSIONS[i % len(self.FIRMWARE_VERSIONS)]

            if i == 0:
                prev_phy_version = None
            else:
                prev_phy_version = self.get_phy_fw_version()
            self.burn_firmware(fw_ver)
            new_phy_version = self.get_phy_fw_version()
            log.info("PHY versions: prev = {}, new = {}".format(prev_phy_version, new_phy_version))
            assert prev_phy_version != new_phy_version


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
