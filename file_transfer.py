import os
import re
import sys
import time
import timeit
from collections import OrderedDict

import pexpect
import pytest

from infra.test_base import TestBase
from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, CARD_FIJI
from tools.driver import Driver, DRV_TYPE_MAC_CDC, DRV_TYPE_LIN_CDC
from tools.ops import OpSystem
from tools.samba import Samba
from tools.utils import get_atf_logger, remove_file

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "file_transfer_test"


class TestFileTransfer(TestBase):
    """
    @description: The TestFileTransfer test is dedicated to perform file transfer via scp and samba mount.

    @setup: Two Aquantia devices connected back to back.
    """
    FILE_NAME = "tmpfile.bin"
    DIRECTION_RX = "RX"
    DIRECTION_TX = "TX"
    AQTEST_PASS = "aq90#$rt"
    PEXPECT_TIMEOUT = 10
    AFTER_LINKUP_TIMEOUT = 10

    @classmethod
    def setup_class(cls):
        super(TestFileTransfer, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            if cls.dut_fw_card not in CARD_FIJI:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            if cls.lkp_fw_card not in CARD_FIJI:
                cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            if cls.dut_drv_cdc:
                if cls.dut_ops.is_mac():
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, drv_type=DRV_TYPE_MAC_CDC)
                elif cls.dut_ops.is_linux():
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, drv_type=DRV_TYPE_LIN_CDC)
                else:
                    raise Exception("CDC driver is not supported")
            else:
                if cls.dut_fw_card not in CARD_FIJI and cls.dut_atltool_wrapper.is_secure_chips() and cls.dut_ops.is_linux():
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version,
                                            flashless_fw=cls.dut_fw_version)
                else:
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.DUT_IP = cls.suggest_test_ip_address(cls.dut_port)
            cls.LKP_IP = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)
            cls.NETMASK = "255.255.0.0"

            cls.dut_ifconfig.set_ip_address(cls.DUT_IP, cls.NETMASK, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, None)

            if cls.dut_ops.is_windows() and cls.lkp_ops.is_mac():
                log.error("There is a problem accessing shared folders from Windows to macOS")
                log.error("macOS always asks for a password")
                raise NotImplementedError()

            if cls.dut_ops.is_windows():
                atf_home = os.environ.get("ATF_HOME")
                cls.LOCAL_FILE_PATH = os.path.join(atf_home, "data\\tmpfile.bin").replace("\\", "/")
            elif cls.dut_ops.is_mac():
                cls.LOCAL_FILE_PATH = "/Users/aqtest/data/tmpfile.bin"
            else:
                cls.LOCAL_FILE_PATH = "/home/aqtest/tmpfile.bin"

            if cls.lkp_ops.is_mac():
                cls.REMOTE_FILE_PATH = "/Users/aqtest/data/tmpfile.bin"
            else:
                cls.REMOTE_FILE_PATH = "/home/aqtest/tmpfile.bin"

            Samba(host=cls.lkp_hostname).start()

            cls.scp_results = OrderedDict()
            cls.smb_results = OrderedDict()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestFileTransfer, cls).teardown_class()

        # Cleanup files just in case
        cls.remove_file()
        cls.remove_file(host=cls.lkp_hostname)

        log.info("SCP transfer results:")
        for speed, data in cls.scp_results.items():
            log.info("Results for {} link speed".format(speed))
            for size, times in cls.scp_results[speed].items():
                log.info("File with size {}M times: {}".format(size, times))

        log.info("SMB transfer results:")
        for speed, data in cls.smb_results.items():
            log.info("Results for {} link speed".format(speed))
            for size, times in cls.smb_results[speed].items():
                log.info("File with size {}M times: {}".format(size, times))
        # Do umount folder
        cls.umount_folder(smb_mount_point="smb_mount_point")

    @classmethod
    def remove_file(cls, host=None):
        assert host in [None, cls.lkp_hostname]

        if host is None:
            if cls.dut_ops.is_windows():
                remove_file(cls.LOCAL_FILE_PATH)
            else:
                # Copy-paste can be executed with sudo so remove the file with sudo rights
                Command(cmd="sudo rm {}".format(cls.LOCAL_FILE_PATH)).run_join(20)
        else:
            Command(cmd="sudo rm {}".format(cls.REMOTE_FILE_PATH), host=host).run_join(20)

    @classmethod
    def umount_folder(cls, smb_mount_point):
        if not cls.dut_ops.is_windows():
            if os.path.exists(smb_mount_point):
                Command(cmd="sudo umount {}".format(smb_mount_point)).run_join(60)
                Command(cmd="sudo rm -rf {}".format(smb_mount_point)).run_join(60)

    def create_file(self, size, host=None):
        assert host in [None, self.lkp_hostname]

        log.info("Creating file {} with size {}M".format(self.LOCAL_FILE_PATH, size))
        self.remove_file(host=host)

        if host is None:
            ops = self.dut_ops
            file_path = self.LOCAL_FILE_PATH
        else:
            ops = self.lkp_ops
            file_path = self.REMOTE_FILE_PATH

        if ops.is_linux():
            cmd = "fallocate -l {}M {}".format(size, file_path)
        elif ops.is_mac():
            cmd = "mkfile -n {}M {}".format(size, file_path)
        elif ops.is_freebsd():
            cmd = "dd if=/dev/random of={} bs=$(( 1024 * 1024 )) count={}".format(file_path, size)
        else:
            cmd = "fsutil file createnew {} {}".format(file_path, size * 1024 * 1024)

        res = Command(cmd=cmd, host=host).run_join(120)
        if res["returncode"] != 0:
            raise Exception("Failed to create file to transfer")

    def get_md5(self, host=None):
        if OpSystem(host=host).is_mac() or OpSystem(host=host).is_freebsd():
            cmd = "md5 {}".format(self.LOCAL_FILE_PATH if host is None else self.REMOTE_FILE_PATH)
            re_md5 = re.compile("MD5 .* = ([0-9a-z]+)", re.DOTALL)
        else:
            cmd = "md5sum {}".format(self.LOCAL_FILE_PATH if host is None else self.REMOTE_FILE_PATH)
            re_md5 = re.compile("([0-9a-z]+) *.*", re.DOTALL)

        res = Command(cmd=cmd, host=host).run_join(120)
        if res["returncode"] != 0:
            raise Exception("Failed to get MD5")

        for line in res["output"]:
            if line.startswith("\\"):
                # On Windows sometimes backslash is added to the begin of the line, I do not know why
                line = line[1:]
            m = re_md5.match(line)
            if m is not None:
                return m.group(1)

        raise Exception("Failed to parse MD5 checksum")

    def scp_file_transfer(self, host=None):
        assert host in [None, self.lkp_hostname]

        start = timeit.default_timer()

        if host is None:
            Command(cmd="sudo rm {}".format(self.REMOTE_FILE_PATH), host=self.lkp_hostname).wait(30)
            cmd = "scp -v {} aqtest@{}:{}".format(self.LOCAL_FILE_PATH, self.LKP_IP, self.REMOTE_FILE_PATH)
            res = Command(cmd=cmd).run_join(1200)
            if res["returncode"] != 0:
                raise Exception("Failed to transfer file")
        else:
            Command(cmd="sudo rm {}".format(self.LOCAL_FILE_PATH)).wait(30)
            cmd = "scp -v {} aqtest@{}:{}".format(self.REMOTE_FILE_PATH, self.DUT_IP, self.LOCAL_FILE_PATH)
            res = Command(cmd=cmd, host=host).run_join(1200)
            if res["returncode"] != 0:
                raise Exception("Failed to transfer file")

        end = timeit.default_timer()
        return end - start

    def wait_pexpect_child(self, child):
        start = timeit.default_timer()
        while timeit.default_timer() - start < self.PEXPECT_TIMEOUT:
            if child.isalive():
                time.sleep(1)
            else:
                return
        raise Exception("Pexpect is timed out")

    def run_scp_file_transfer_test(self, link_speed, file_size, nof_transfers, direction):
        assert direction in [self.DIRECTION_RX, self.DIRECTION_TX]

        if link_speed not in self.supported_speeds:
            pytest.skip()

        if not self.dut_drv_cdc:
            self.dut_ifconfig.set_link_speed(link_speed)

        self.lkp_ifconfig.set_link_speed(link_speed)
        assert self.lkp_ifconfig.wait_link_up() == link_speed
        time.sleep(self.AFTER_LINKUP_TIMEOUT)

        if direction == self.DIRECTION_RX:
            self.create_file(file_size, self.lkp_hostname)
        else:
            self.create_file(file_size)

        if direction == self.DIRECTION_RX:
            original_md5 = self.get_md5(host=self.lkp_hostname)
        else:
            original_md5 = self.get_md5()

        for i in range(nof_transfers):
            if direction == self.DIRECTION_RX:
                ttime = self.scp_file_transfer(host=self.lkp_hostname)
                transfered_md5 = self.get_md5()
            else:
                ttime = self.scp_file_transfer()
                transfered_md5 = self.get_md5(host=self.lkp_hostname)
            assert transfered_md5 == original_md5

            if link_speed not in self.scp_results:
                self.scp_results[link_speed] = {}
            if file_size not in self.scp_results[link_speed]:
                self.scp_results[link_speed][file_size] = []

            self.scp_results[link_speed][file_size].append(ttime)
            log.info("File with size {}M transfered in {} seconds".format(file_size, ttime))

    def run_smb_file_transfer_test(self, link_speed, file_size, nof_transfers, direction):
        if self.dut_ops.is_freebsd():
            pytest.skip("Not support samba mount")
            # TODO: need configure machine for samba
        assert direction in [self.DIRECTION_RX, self.DIRECTION_TX]

        if link_speed not in self.supported_speeds:
            pytest.skip()

        smb_mount_point = "smb_mount_point"

        if not self.dut_drv_cdc:
            self.dut_ifconfig.set_link_speed(link_speed)

        self.lkp_ifconfig.set_link_speed(link_speed)
        assert self.lkp_ifconfig.wait_link_up() == link_speed
        time.sleep(self.AFTER_LINKUP_TIMEOUT)

        if direction == self.DIRECTION_RX:
            self.create_file(file_size, self.lkp_hostname)
        else:
            self.create_file(file_size)

        if not self.dut_ops.is_windows():
            self.umount_folder(smb_mount_point=smb_mount_point)

            Command(cmd="mkdir {}".format(smb_mount_point)).run_join(20)
            if self.dut_ops.is_linux() or self.dut_ops.is_freebsd():
                res = Command(cmd="sudo mount -t cifs -o user='aqtest',password='{}' //{}/data {}".format(
                    self.AQTEST_PASS, self.LKP_IP, smb_mount_point)).wait(30)
                if res["returncode"] != 0:
                    raise Exception("Failed to mount remote directory")
            elif self.dut_ops.is_mac() and self.lkp_ops.is_linux():
                # Use guest account when mount folder from macOS to Linux
                res = Command(cmd="mount_smbfs smb://guest@{}/data {}".format(
                    self.LKP_IP, smb_mount_point)).wait(30)
                if res["returncode"] != 0:
                    raise Exception("Failed to mount remote directory")
            else:
                # Mounting remote shared folder on macOS is tricky
                child = pexpect.spawn("mount_smbfs //aqtest@{}/data {}".format(self.LKP_IP, smb_mount_point))
                child.logfile_read = sys.stdout
                child.expect("assword")
                child.sendline(self.AQTEST_PASS)
                child.expect(pexpect.EOF)
                self.wait_pexpect_child(child)

                Command(cmd="mount").run_join(20)

        if link_speed not in self.smb_results:
            self.smb_results[link_speed] = {}
        if file_size not in self.smb_results[link_speed]:
            self.smb_results[link_speed][file_size] = []

        for i in range(nof_transfers):
            if self.dut_ops.is_windows():
                if direction == self.DIRECTION_RX:
                    Command(cmd="rm {}".format(self.LOCAL_FILE_PATH)).run_join()
                    start = timeit.default_timer()
                    res = Command(cmd="cp //{}/data/{} {}".format(
                        self.LKP_IP, self.FILE_NAME, self.LOCAL_FILE_PATH)).run_join(1800)
                    ttime = timeit.default_timer() - start
                else:
                    Command(cmd="rm {}".format(self.REMOTE_FILE_PATH), host=self.lkp_hostname).run_join(20)
                    start = timeit.default_timer()
                    res = Command(cmd="cp {} //{}/data/{}".format(
                        self.LOCAL_FILE_PATH, self.LKP_IP, self.FILE_NAME)).run_join(1800)
                    ttime = timeit.default_timer() - start
                if res["returncode"] != 0:
                    raise Exception("Failed to copy file")
            else:
                if direction == self.DIRECTION_RX:
                    Command(cmd="sudo rm {}".format(self.LOCAL_FILE_PATH)).run_join(20)
                    # Copying from mounted folder to local
                    start = timeit.default_timer()
                    res = Command(cmd="sudo cp {} {}".format(
                        os.path.join(smb_mount_point, self.FILE_NAME), self.LOCAL_FILE_PATH)).run_join(1800)
                    ttime = timeit.default_timer() - start
                else:
                    # Copying from local folder to mounted
                    Command(cmd="sudo rm {}".format(os.path.join(smb_mount_point, self.FILE_NAME))).run_join(20)
                    start = timeit.default_timer()
                    res = Command(cmd="sudo cp {} {}".format(self.LOCAL_FILE_PATH, smb_mount_point)).run_join(1800)
                    ttime = timeit.default_timer() - start
                if res["returncode"] != 0:
                    raise Exception("Failed to copy file")
            self.smb_results[link_speed][file_size].append(ttime)

    def test_scp_2g_file_1time_100m_tx(self):
        """
        @description: Perform file transfer via scp on 100M link speed.
        Condition: number of transfers - 1, direction - TX.

        @steps:
        1. Create 2048 Mbytes file.
        2. Copy file from DUT to LKP (transfer should be no more than 1200 seconds).
        3. Check that file was copied without errors.

        @result: SCP copy is passed.
        @duration: 5 minutes.
        """
        self.run_scp_file_transfer_test(LINK_SPEED_100M, 2048, 1, self.DIRECTION_TX)

    def test_scp_2g_file_1time_100m_rx(self):
        """
        @description: Perform file transfer via scp on 100M link speed.
        Condition: number of transfers - 1, direction - RX.

        @steps:
        1. Create 2048 Mbytes file.
        2. Copy file from LKP to DUT (transfer should be no more than 1200 seconds).
        3. Check that file was copied without errors.

        @result: SCP copy is passed.
        @duration: 5 minutes.
        """
        self.run_scp_file_transfer_test(LINK_SPEED_100M, 2048, 1, self.DIRECTION_RX)

    def test_scp_2g_file_2times_1g_tx(self):
        """
        @description: Perform file transfer via scp on 1G link speed.
        Condition: number of transfers - 2, direction - TX.

        @steps:
        1. Create 2048 Mbytes file.
        2. Copy 2 files from DUT to LKP (transfer should be no more than 1200 seconds).
        3. Check that files were copied without errors.

        @result: SCP copy is passed.
        @duration: 5 minutes.
        """
        self.run_scp_file_transfer_test(LINK_SPEED_1G, 2048, 2, self.DIRECTION_TX)

    def test_scp_2g_file_2times_1g_rx(self):
        """
        @description: Perform file transfer via scp on 1G link speed.
        Condition: number of transfers - 2, direction - RX.

        @steps:
        1. Create 2048 Mbytes file.
        2. Copy 2 files from LKP to DUT (transfer should be no more than 1200 seconds).
        3. Check that files were copied without errors.

        @result: SCP copy is passed.
        @duration: 5 minutes.
        """
        self.run_scp_file_transfer_test(LINK_SPEED_1G, 2048, 2, self.DIRECTION_RX)

    def test_scp_2g_file_2times_2_5g_tx(self):
        """
        @description: Perform file transfer via scp on 2.5G link speed.
        Condition: number of transfers - 2, direction - TX.

        @steps:
        1. Create 2048 Mbytes file.
        2. Copy 2 files from DUT to LKP (transfer should be no more than 1200 seconds).
        3. Check that files were copied without errors.

        @result: SCP copy is passed.
        @duration: 5 minutes.
        """
        self.run_scp_file_transfer_test(LINK_SPEED_2_5G, 2048, 2, self.DIRECTION_TX)

    def test_scp_2g_file_2times_2_5g_rx(self):
        """
        @description: Perform file transfer via scp on 2.5G link speed.
        Condition: number of transfers - 2, direction - RX.

        @steps:
        1. Create 2048 Mbytes file.
        2. Copy 2 files from LKP to DUT (transfer should be no more than 1200 seconds).
        3. Check that files were copied without errors.

        @result: SCP copy is passed.
        @duration: 5 minutes.
        """
        self.run_scp_file_transfer_test(LINK_SPEED_2_5G, 2048, 2, self.DIRECTION_RX)

    def test_scp_2g_file_2times_5g_tx(self):
        """
        @description: Perform file transfer via scp on 5G link speed.
        Condition: number of transfers - 2, direction - TX.

        @steps:
        1. Create 2048 Mbytes file.
        2. Copy 2 files from DUT to LKP (transfer should be no more than 1200 seconds).
        3. Check that files were copied without errors.

        @result: SCP copy is passed.
        @duration: 5 minutes.
        """
        self.run_scp_file_transfer_test(LINK_SPEED_5G, 2048, 2, self.DIRECTION_TX)

    def test_scp_2g_file_2times_5g_rx(self):
        """
        @description: Perform file transfer via scp on 5G link speed.
        Condition: number of transfers - 2, direction - RX.

        @steps:
        1. Create 2048 Mbytes file.
        2. Copy 2 files from LKP to DUT (transfer should be no more than 1200 seconds).
        3. Check that files were copied without errors.

        @result: SCP copy is passed.
        @duration: 5 minutes.
        """
        self.run_scp_file_transfer_test(LINK_SPEED_5G, 2048, 2, self.DIRECTION_RX)

    def test_scp_2g_file_5times_10g_tx(self):
        """
        @description: Perform file transfer via scp on 10G link speed.
        Condition: number of transfers - 5, direction - TX.

        @steps:
        1. Create 2048 Mbytes file.
        2. Copy 5 file from DUT to LKP (transfer should be no more than 1200 seconds).
        3. Check that files were copied without errors.

        @result: SCP copy is passed.
        @duration: 5 minutes.
        """
        self.run_scp_file_transfer_test(LINK_SPEED_10G, 2048, 5, self.DIRECTION_TX)

    def test_scp_2g_file_5times_10g_rx(self):
        """
        @description: Perform file transfer via scp on 5G link speed.
        Condition: number of transfers - 5, direction - RX.

        @steps:
        1. Create 2048 Mbytes file.
        2. Copy 5 files from LKP to DUT (transfer should be no more than 1200 seconds).
        3. Check that files were copied without errors.

        @result: SCP copy is passed.
        @duration: 5 minutes.
        """
        self.run_scp_file_transfer_test(LINK_SPEED_10G, 2048, 5, self.DIRECTION_RX)

    def test_smb_5g_file_1time_100m_tx(self):
        """
        @description: Perform file transfer via samba mount on 100M link speed.
        Condition: number of transfers - 1, direction - TX.

        @steps:
        1. Create 5120 Mbytes file.
        2. Mount folder using samba file shares.
        3. Copy file from DUT to LKP (transfer should be no more than 1200 seconds).
        4. Check that file was copied without errors.

        @result: Copy is passed.
        @duration: 5 minutes.
        """
        self.run_smb_file_transfer_test(LINK_SPEED_100M, 5120, 1, self.DIRECTION_TX)

    def test_smb_5g_file_1time_100m_rx(self):
        """
        @description: Perform file transfer via samba mount on 100M link speed.
        Condition: number of transfers - 1, direction - RX.

        @steps:
        1. Create 5120 Mbytes file.
        2. Mount folder using samba file shares.
        3. Copy file from LKP to DUT (transfer should be no more than 1200 seconds).
        4. Check that file was copied without errors.

        @result: Copy is passed.
        @duration: 5 minutes.
        """
        self.run_smb_file_transfer_test(LINK_SPEED_100M, 5120, 1, self.DIRECTION_RX)

    def test_smb_5g_file_2times_1g_tx(self):
        """
        @description: Perform file transfer via samba mount on 1G link speed.
        Condition: number of transfers - 1, direction - TX.

        @steps:
        1. Create 5120 Mbytes file.
        2. Mount folder using samba file shares.
        3. Copy 2 files from DUT to LKP (transfer should be no more than 1200 seconds).
        4. Check that files were copied without errors.

        @result: Copy is passed.
        @duration: 5 minutes.
        """
        self.run_smb_file_transfer_test(LINK_SPEED_1G, 5120, 2, self.DIRECTION_TX)

    def test_smb_5g_file_2times_1g_rx(self):
        """
        @description: Perform file transfer via samba mount on 1G link speed.
        Condition: number of transfers - 1, direction - RX.

        @steps:
        1. Create 5120 Mbytes file.
        2. Mount folder using samba file shares.
        3. Copy 2 files from LKP to DUT (transfer should be no more than 1200 seconds).
        4. Check that files were copied without errors.

        @result: Copy is passed.
        @duration: 5 minutes.
        """
        self.run_smb_file_transfer_test(LINK_SPEED_1G, 5120, 2, self.DIRECTION_RX)

    def test_smb_5g_file_3times_2_5g_tx(self):
        """
        @description: Perform file transfer via samba mount on 2.5G link speed.
        Condition: number of transfers - 1, direction - TX.

        @steps:
        1. Create 5120 Mbytes file.
        2. Mount folder using samba file shares.
        3. Copy 2 files from DUT to LKP (transfer should be no more than 1200 seconds).
        4. Check that files were copied without errors.

        @result: Copy is passed.
        @duration: 5 minutes.
        """
        self.run_smb_file_transfer_test(LINK_SPEED_2_5G, 5120, 3, self.DIRECTION_TX)

    def test_smb_5g_file_3times_2_5g_rx(self):
        """
        @description: Perform file transfer via samba mount on 2.5G link speed.
        Condition: number of transfers - 1, direction - RX.

        @steps:
        1. Create 5120 Mbytes file.
        2. Mount folder using samba file shares.
        3. Copy 2 files from LKP to DUT (transfer should be no more than 1200 seconds).
        4. Check that files were copied without errors.

        @result: Copy is passed.
        @duration: 5 minutes.
        """
        self.run_smb_file_transfer_test(LINK_SPEED_2_5G, 5120, 3, self.DIRECTION_RX)

    def test_smb_5g_file_4times_5g_tx(self):
        """
        @description: Perform file transfer via samba mount on 5G link speed.
        Condition: number of transfers - 1, direction - TX.

        @steps:
        1. Create 5120 Mbytes file.
        2. Mount folder using samba file shares.
        3. Copy 2 files from DUT to LKP (transfer should be no more than 1200 seconds).
        4. Check that files were copied without errors.

        @result: Copy is passed.
        @duration: 5 minutes.
        """
        self.run_smb_file_transfer_test(LINK_SPEED_5G, 5120, 4, self.DIRECTION_TX)

    def test_smb_5g_file_4times_5g_rx(self):
        """
        @description: Perform file transfer via samba mount on 5G link speed.
        Condition: number of transfers - 1, direction - RX.

        @steps:
        1. Create 5120 Mbytes file.
        2. Mount folder using samba file shares.
        3. Copy 2 files from LKP to DUT (transfer should be no more than 1200 seconds).
        4. Check that files were copied without errors.

        @result: Copy is passed.
        @duration: 5 minutes.
        """
        self.run_smb_file_transfer_test(LINK_SPEED_5G, 5120, 4, self.DIRECTION_RX)

    def test_smb_5g_file_10times_10g_tx(self):
        """
        @description: Perform file transfer via samba mount on 10G link speed.
        Condition: number of transfers - 1, direction - TX.

        @steps:
        1. Create 5120 Mbytes file.
        2. Mount folder using samba file shares.
        3. Copy 5 files from DUT to LKP (transfer should be no more than 1200 seconds).
        4. Check that files were copied without errors.

        @result: Copy is passed.
        @duration: 5 minutes.
        """
        self.run_smb_file_transfer_test(LINK_SPEED_10G, 5120, 10, self.DIRECTION_TX)

    def test_smb_5g_file_10times_10g_rx(self):
        """
        @description: Perform file transfer via samba mount on 10G link speed.
        Condition: number of transfers - 1, direction - RX.

        @steps:
        1. Create 5120 Mbytes file.
        2. Mount folder using samba file shares.
        3. Copy 5 files from LKP to DUT (transfer should be no more than 1200 seconds).
        4. Check that files were copied without errors.

        @result: Copy is passed.
        @duration: 5 minutes.
        """
        self.run_smb_file_transfer_test(LINK_SPEED_10G, 5120, 10, self.DIRECTION_RX)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
