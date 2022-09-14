import os
import re
import tempfile
from shutil import copyfile

import pytest

from infra.test_base import TestBase
from tools import command
from tools import constants
from tools import ifconfig
from tools import ops
from tools import driver
from tools import mbuper
from tools import firmware
from tools.utils import get_atf_logger, upload_directory, upload_file, download_file


log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "reset_sequence_extended"


class TestResetSequenceExtended(TestBase):
    ITERATIONS = 5
    @classmethod
    def setup_class(cls):
        super(TestResetSequenceExtended, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()
            cls.dut_driver = driver.Driver(
                port=cls.dut_port, drv_type=driver.DRV_TYPE_DIAG, version="stable", host=cls.dut_hostname
            )
            cls.dut_driver.install()
            cls.lkp_driver = driver.Driver(
                port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname
            )
            cls.lkp_driver.install()
            cls.link_speed = os.environ.get("SUPPORTED_SPEEDS", "100M,1G").split(",")[-1]
            cls.lkp_ifconfig.set_link_speed(cls.link_speed)
            cls.lkp_ifconfig.set_link_state(ifconfig.LINK_STATE_UP)

            cls.remote_temp_dir = cls.get_remote_temp_dir(cls.dut_hostname)
            remote_mbu_dir = os.path.join(cls.remote_temp_dir, "mbu")
            command.Command(
                cmd="sudo rm -rf {}".format(remote_mbu_dir), host=cls.lkp_hostname
            ).run()
            cls.mbu_dir = mbuper.download_mbu("mbu_fixed_loadfile", cls.working_dir)
            upload_directory(cls.dut_hostname, os.path.join(cls.working_dir, "mbu"), cls.remote_temp_dir)
            cls.dut_mbu_wrapper = mbuper.MbuWrapper(host=cls.dut_hostname, mbu_dir=remote_mbu_dir, port=cls.dut_port)

            cls.is_felicity = cls.dut_fw_card in [
                constants.CARD_FELICITY,
                constants.CARD_FELICITY_KR,
                constants.CARD_FELICITY_EUROPA,
            ]
            if not cls.is_felicity:
                cls.dut_nof_pci_lines = cls.dut_ifconfig.get_nof_pci_lines()
            lkp_os_name = ops.OpSystem(host=cls.dut_hostname).get_name()
            # if lkp_os_name in constants.WIN_OSES:
            #     command.Command(cmd='setx AQ_DEVICEREV "B1"', host=cls.dut_hostname).run_join(100)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestResetSequenceExtended, cls).teardown_class()

    def setup_method(self, method):
        super(TestResetSequenceExtended, self).setup_method(method)

    def copy_config(self, config):
        test_dir = os.path.join(TestBase.log_local_dir, self.state.current_test_norm)
        copyfile(os.path.join("tools/beton", config), os.path.join(test_dir, os.path.basename(config)))

    def get_fw_ver_from_file_path(self, fileo):
        pattern = re.compile(".*(?P<major>[0-9])\.(?P<minor>[0-9]+)\.(?P<release>[0-9]+).*")
        fw_filename_parts = os.path.basename(fileo).split("!")
        fw_ver = None
        for part in fw_filename_parts:
            fw_ver = pattern.match(part)
            if fw_ver:
                fw_ver = int(fw_ver.group("major")), int(fw_ver.group("minor")), int(fw_ver.group("release"))
                break
        return fw_ver

    def compare_fw_version(self, fw_file, mbu_value):
        fw_ver = self.get_fw_ver_from_file_path(fw_file)
        log.debug("Comparing FW versions from file: {} and read from MBU: {}".format(fw_ver, mbu_value))
        return fw_ver == mbu_value

    def exec_beton(self, beton):
        temp_beton_path = os.path.join(self.working_dir, "temp_beton.txt")
        with open(temp_beton_path, "w") as fileo:
            for line in beton:
                fileo.write("{}\n".format(line))

        with open(temp_beton_path, "r") as fileo:
            log.debug("Temp beton is written:\n{}".format(fileo.read()))
        result = self.dut_mbu_wrapper.exec_txt(temp_beton_path)
        return result

    def exec_reset_seq(self):
        scripts_path = os.path.join(os.environ["ATF_HOME"], "qa-tests/tools/beton")
        upload_file(
            self.dut_hostname, os.path.join(scripts_path, "reset_sequence.txt"), self.remote_temp_dir
        )
        upload_file(
            self.dut_hostname, os.path.join(scripts_path, "ResetSeq/resetSeqTest.txt"), self.remote_temp_dir
        )
        upload_file(
            self.dut_hostname, os.path.join(scripts_path, "helpers/showTestResult.txt"), self.remote_temp_dir
        )
        reg_368 = mbuper.LINK_SPEED_TO_REG_VAL_MAP_2X[self.link_speed]
        beton = [
            "iterations = {}".format(self.ITERATIONS),
            "is_felicity = {}".format(self.is_felicity),
            "reg368value = {}".format(reg_368),
            "forceFlashless = 0",
            "resetScriptPath = {}".format(
                os.path.normpath(os.path.join(self.remote_temp_dir, "reset_sequence.txt")))
        ]
        if not self.is_felicity:
            beton.append("num_lanes = {}".format(self.dut_nof_pci_lines))
            beton.append("reloadPhyFw = {}".format(1))
        else:
            beton.append("reloadPhyFw = {}".format(0))
        beton.append("exec {}".format(os.path.join(self.remote_temp_dir, "resetSeqTest.txt")))

        result = self.exec_beton(beton)
        return result

    def corrupt_fw(self, fw_file):
        fw_file = os.path.normpath(fw_file)
        local_fw_file = os.path.join(self.working_dir, os.path.basename(fw_file.replace("\\", "/")))
        download_file(self.dut_hostname, remote_file=fw_file, local_file=local_fw_file)
        with open(local_fw_file, 'rb') as fileo:
            fw_content = fileo.read()
        corrupted = "00000000".decode("hex") + fw_content[4:0x4000] + "00000000".decode("hex") + fw_content[0x4004:]
        path = os.path.dirname(local_fw_file)
        corr_file = os.path.join(path, "CORR.clx")
        with open(corr_file, 'wb') as fileo:
            fileo.write(corrupted)
        upload_file(self.dut_hostname, local_file=corr_file, remote_dir=self.remote_temp_dir)
        return os.path.join(self.remote_temp_dir, os.path.basename(corr_file))

    @classmethod
    def get_remote_temp_dir(cls, host):
        cmd = command.Command(
            cmd='python -c "import tempfile; temp_dir = tempfile.gettempdir(); print temp_dir;"',
            host=host
        )
        result = cmd.run_join(5)
        result = result["output"][0]
        log.debug("Remote temp dir: {}".format(result))
        return result

    def test_reset_squence_extended(self):
        self.dut_flash_override, self.dut_flash_override = self.get_flash_override()
        self.dut_firmware = firmware.Firmware(port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
                                              version=self.dut_fw_version, mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
                                              pause=self.dut_fw_pause, pcirom=self.dut_fw_pcirom,
                                              dirtywake=self.dut_fw_dirtywake, host=self.dut_hostname)
        fw_file = self.dut_firmware.download()

        fw_ver = self.get_fw_ver_from_file_path(fw_file)
        high, low, build = fw_ver
        another_fw_ver = ".".join((str(high), str(low), str(build - 1)))
        fw_ver = ".".join((str(high), str(low), str(build)))
        self.another_fw_version = self.dut_fw_version.replace("latest", another_fw_ver)
        self.another_fw_version = self.another_fw_version.replace("stable", another_fw_ver)
        another_fw_version = []
        for item in self.another_fw_version.split("/"):
            if fw_ver in item:
                another_fw_version.append(another_fw_ver)
            else:
                another_fw_version.append(item)
        self.another_fw_version = "/".join(another_fw_version)
        log.info("Another fw version to be used: {}".format(self.another_fw_version))

        self.dut_another_firmware = firmware.Firmware(port=self.dut_port, card=self.dut_fw_card,
                                                      speed=self.dut_fw_speed,
                                                      version=self.another_fw_version, mdi=self.dut_fw_mdi,
                                                      mii=self.dut_fw_mii,
                                                      pause=self.dut_fw_pause, pcirom=self.dut_fw_pcirom,
                                                      dirtywake=self.dut_fw_dirtywake, host=self.dut_hostname)
        corrupted_fw = self.corrupt_fw(fw_file)
        another_fw_file = self.dut_another_firmware.download()
        log.debug("corrupted_fw = {}".format(corrupted_fw))

        log.info("#" * 100)
        log.info("Executing step: successful cold boot, then call reset sequence")
        log.info("#" * 100)
        self.exec_beton(["flash.init", "flash.loadFile {}".format(fw_file)])
        self.cold_restart(host=self.dut_hostname)
        mbu_fw_ver = self.dut_mbu_wrapper.get_fw_version()
        assert mbu_fw_ver != (0, 0, 0), "Firmware was not loaded after cold restart"
        assert self.compare_fw_version(fw_file, mbu_fw_ver), \
            "Invalid fw version was loaded after cold restart: {}. Expected: {}".format(mbu_fw_ver, self.dut_fw_version)

        result = self.exec_reset_seq()
        assert "[PASSED]" in result, "Beton script detected error"
        assert mbu_fw_ver != (0, 0, 0), "Firmware was not loaded after reset sequence"
        assert (
            self.compare_fw_version(fw_file, mbu_fw_ver),
            "Invalid fw version was loaded after reset sequence: {}. Expected: {}".format(
                mbu_fw_ver, self.dut_fw_version
            )
        )

        log.info("#" * 100)
        log.info("Executing step: successful cold boot, then burn another image to flash, then call reset sequence")
        log.info("#" * 100)
        self.cold_restart(host=self.dut_hostname)
        mbu_fw_ver = self.dut_mbu_wrapper.get_fw_version()
        assert mbu_fw_ver != (0, 0, 0), "Firmware was not loaded after cold restart"
        assert self.compare_fw_version(fw_file, mbu_fw_ver), \
            "Invalid fw version was loaded after cold restart: {}. Expected: {}".format(mbu_fw_ver, self.dut_fw_version)
        self.exec_beton(["flash.init", "flash.loadFile {}".format(another_fw_file)])

        result = self.exec_reset_seq()
        assert "[PASSED]" in result, "Beton script detected error"
        mbu_fw_ver = self.dut_mbu_wrapper.get_fw_version()
        assert mbu_fw_ver != (0, 0, 0), "Firmware was not loaded after reset sequence"
        assert self.compare_fw_version(another_fw_file, mbu_fw_ver), \
            "Invalid fw version was loaded after reset sequence: {}. Expected: {}".format(
                mbu_fw_ver, self.another_fw_version
            )

        log.info("#" * 100)
        log.info("Executing step: call reset sequence successfully, then burn another image to flash, then call "
                 "reset sequence one more time")
        log.info("#" * 100)
        result = self.exec_reset_seq()
        assert "[PASSED]" in result, "Beton script detected error"
        mbu_fw_ver = self.dut_mbu_wrapper.get_fw_version()
        assert mbu_fw_ver != (0, 0, 0), "Firmware was not loaded after reset sequence"
        assert self.compare_fw_version(another_fw_file, mbu_fw_ver), \
            "Invalid fw version was loaded after reset sequence: {}. Expected: {}".format(
                mbu_fw_ver, self.another_fw_version
            )
        self.exec_beton(["flash.init", "flash.loadFile {}".format(fw_file)])
        result = self.exec_reset_seq()
        assert "[PASSED]" in result, "Beton script detected error"
        mbu_fw_ver = self.dut_mbu_wrapper.get_fw_version()
        assert mbu_fw_ver != (0, 0, 0), "Firmware was not loaded after reset sequence"
        assert self.compare_fw_version(fw_file, mbu_fw_ver), \
            "Invalid fw version was loaded after reset sequence: {}. Expected: {}".format(
                mbu_fw_ver, self.dut_fw_version
            )

        log.info("#" * 100)
        log.info("Executing step: unsuccessful cold boot (no active NCB), then burn another image to flash, then call "
                 "reset sequence")
        log.info("#" * 100)
        self.exec_beton(["flash.init", "flash.loadFile -d {}".format(corrupted_fw)])
        self.cold_restart(host=self.dut_hostname)
        mbu_fw_ver = self.dut_mbu_wrapper.get_fw_version()
        assert mbu_fw_ver == (0, 0, 0), "Firmware was loaded unexpectedly"
        self.exec_beton(["flash.init", "flash.loadFile {}".format(fw_file)])

        result = self.exec_reset_seq()
        assert "[PASSED]" in result, "Beton script detected error"
        mbu_fw_ver = self.dut_mbu_wrapper.get_fw_version()
        assert mbu_fw_ver != (0, 0, 0), "Firmware was not loaded after reset sequence"
        assert self.compare_fw_version(fw_file, mbu_fw_ver), \
            "Invalid fw version was loaded after reset sequence: {}. Expected: {}".format(
                mbu_fw_ver, self.dut_fw_version
            )
        self.exec_beton(["flash.init", "flash.loadFile {}".format(fw_file)])
        result = self.exec_reset_seq()
        assert "[PASSED]" in result, "Beton script detected error"
        mbu_fw_ver = self.dut_mbu_wrapper.get_fw_version()
        assert mbu_fw_ver != (0, 0, 0), "Firmware was not loaded after reset sequence"
        assert self.compare_fw_version(fw_file, mbu_fw_ver), \
            "Invalid fw version was loaded after reset sequence: {}. Expected: {}".format(
                mbu_fw_ver, self.dut_fw_version
            )

        log.info("#" * 100)
        log.info("Executing step: successful cold boot, then burn incorrect image to flash, then call reset sequence "
                 "unsuccessfully, then burn valid image to flash, then call reset sequence")
        log.info("#" * 100)
        self.cold_restart(host=self.dut_hostname)
        mbu_fw_ver = self.dut_mbu_wrapper.get_fw_version()
        assert mbu_fw_ver != (0, 0, 0), "Firmware was not loaded after cold restart"
        assert self.compare_fw_version(fw_file, mbu_fw_ver), \
            "Invalid fw version was loaded after cold restart: {}. Expected: {}".format(mbu_fw_ver, self.dut_fw_version)
        self.exec_beton(["flash.init", "flash.loadFile -d {}".format(corrupted_fw)])
        result = self.exec_reset_seq()
        assert "[FAILED]" in result, "Beton script detected error"
        mbu_fw_ver = self.dut_mbu_wrapper.get_fw_version()
        assert mbu_fw_ver == (0, 0, 0), "Firmware was loaded after reset sequence unexpectedly"
        self.exec_beton(["flash.init", "flash.loadFile {}".format(fw_file)])
        result = self.exec_reset_seq()
        assert "[PASSED]" in result, "Beton script detected error"
        mbu_fw_ver = self.dut_mbu_wrapper.get_fw_version()
        assert mbu_fw_ver != (0, 0, 0), "Firmware was not loaded after reset sequence"
        assert self.compare_fw_version(fw_file, mbu_fw_ver), \
            "Invalid fw version was loaded after reset sequence: {}. Expected: {}".format(
                mbu_fw_ver, self.dut_fw_version
            )


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
