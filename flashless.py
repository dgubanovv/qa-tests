import os
import ctypes
import time
import re

import pytest

from tools.firmware import Firmware
from tools.atltoolper import AtlTool
from tools.driver import Driver
from tools.constants import LINK_STATE_UP, FELICITY_CARDS
from tools.command import Command
from infra.test_base import TestBase
from tools.utils import get_atf_logger, download_file

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "flashless"


class PHY_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("header", ctypes.c_uint16),
        ("header_1", ctypes.c_uint16),
    ]


class PHY_BDP(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("reg", ctypes.c_uint16),
        ("val", ctypes.c_uint16),
        ("mask", ctypes.c_uint16),
    ]


class MAC_BDP(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("header", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("header_1", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("reg", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("val", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("mask", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
    ]


class CONFIGURATION_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("svid_ssid", ctypes.c_uint32),
        ("_macBDPPointer", ctypes.c_uint32),
        ("_macBDPLength", ctypes.c_uint32),
        ("_phyBDPPointer", ctypes.c_uint32),
        ("_phyBDPLength", ctypes.c_uint32),
    ]


class HEADER_HOST_LOAD(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("_macIramPointer", ctypes.c_uint32),
        ("_macIramLength",  ctypes.c_uint32),
        ("_macDramPointer", ctypes.c_uint32),
        ("_macDramLength",  ctypes.c_uint32),
        ("_phyIramPointer", ctypes.c_uint32),
        ("_phyIramLength",  ctypes.c_uint32),
        ("_phyDramPointer", ctypes.c_uint32),
        ("_phyDramLength",  ctypes.c_uint32),
        ("_configurationPointer",  ctypes.c_uint32),
        ("_configurationLength",  ctypes.c_uint32),
        ("_configurationCount",  ctypes.c_uint32),
        ("macCRC", ctypes.c_uint32),
        ("phyCRC", ctypes.c_uint32),
        ("confCRC", ctypes.c_uint32),
    ]


class TestFlashless(TestBase):

    @classmethod
    def setup_class(cls):
        super(TestFlashless, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            if "forwarding" in cls.dut_drv_version:
                cls.driver_name = "atlantic-fwd"
            else:
                cls.driver_name = "atlantic"
            driver_dir = "/storage/export/builds/driver/linux/aquantia/{}/*.gz".format(cls.dut_drv_version)
            download_file("nn-nfs01", "{}".format(driver_dir), "./")
            cls.dut_atltool = AtlTool(port=cls.dut_port)
            cls.download_fw()
            res = Command(cmd="sudo flashErase -d {}".format(cls.dut_atltool.pciutil_port[5:])).run()
            if res["returncode"] != 0:
                raise Exception("FlashErase is fail")
            res = Command(cmd="sudo kickstart").run()
            if res["returncode"] == 0:
                raise Exception("Kickstart should be failed")
            Command(cmd="sudo rmmod atlantic").run_join()
            Command(cmd="sudo rmmod atlantic_fwd").run_join()
            Command(cmd="sudo modprobe crc_itu_t").run_join()
            Command(cmd="sudo modprobe ptp").run_join()
            Command(cmd="sudo tar xzf atlantic.tar.gz").run_join()
            Command(cmd="cd Linux; sudo make; sudo make install").run_join()
            Command(cmd="sudo dmesg -C").run_join()
            Command(cmd="cd Linux; sudo rmmod {}".format(cls.driver_name)).run()
            res = Command(cmd="cd Linux; sudo insmod {}.ko".format(cls.driver_name)).run()
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to load driver")

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestFlashless, self).setup_method(method)
        res = Command(cmd="sudo flashErase -d {}".format(self.dut_atltool.pciutil_port[5:])).run()
        if res["returncode"] != 0:
            raise Exception("FlashErase is fail")
        res = Command(cmd="sudo kickstart").run()
        if res["returncode"] == 0:
            raise Exception("Kickstart should be failed")
        self.download_fw()
        self.uninstall_driver()
        self.install_driver()
        self.check_ko_loaded("atlantic" if "forwarding" not in self.dut_drv_version else "atlantic_fwd")
        Command(cmd="ip a").run_join()

    @classmethod
    def download_fw(self):
        self.skip = False
        hostload_dir = "/storage/export/builds/firmware/{}/Customers_AqSign/hostload/*.fw".format(self.dut_fw_version)
        firmware_dir = "/lib/firmware/mrvl"
        Command(cmd="sudo rm /lib/firmware/mrvl/*.fw").run_join()
        Command(cmd="sudo mkdir {}/".format(firmware_dir)).run_join()
        res = download_file("qa-nfs01", "{}".format(hostload_dir), "{}".format(firmware_dir))
        for line in res["output"]:
            if "No such file or directory" in line:
                self.skip = True
                break

    @classmethod
    def uninstall_driver(self):
        res = Command(cmd="sudo rmmod {}".format(self.driver_name)).run()
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            uninst = False
            for line in res["output"]:
                if "Module atlantic is not currently loaded" in line:
                    uninst = True
            if not uninst:
                raise Exception("Failed to uninstall driver")

    @classmethod
    def install_driver(self, aq_fw_did=None, aq_fw_sid=None):
        cmd = "cd Linux; sudo insmod {}.ko ".format(self.driver_name)
        if aq_fw_did is not None:
            dids = ",".join(map(str, aq_fw_did))
            cmd = cmd + "aq_fw_did={}".format(dids)
        if aq_fw_sid is not None:
            dids = ",".join(map(str, aq_fw_sid))
            cmd = cmd + "aq_fw_sid={}".format(dids)
        res = Command(cmd=cmd).run()
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to install driver")

    @classmethod
    def check_ko_loaded(self, name):
        if name not in ["atlantic", "atlantic_fwd"]:
            raise Exception("Unknown KO name")
        re_c = re.compile("([a-z0-9_]+) *[0-9]+ *[0-9]")
        for ko_name in ["atlantic", "atlantic_fwd"]:
            res = Command(cmd="lsmod | grep ^{}".format(ko_name)).run()
            if ko_name == name:
                assert res["returncode"] == 0
                for str in res["output"]:
                    if name != re_c.match(str).group(1):
                        raise Exception("Invalid KO found: {}".format(re_c.match(str).group(1)))
            else:
                for str in res["output"]:
                    if ko_name == re_c.match(str).group(1):
                        raise Exception("Invalid KO found: {}".format(ko_name))

    def install_drv_and_check_fw(self):
        Command(cmd="sudo dmesg -C").run_join()
        self.uninstall_driver()
        self.install_driver()
        res = Command(cmd="sudo dmesg").run_join()
        successfully = False
        for line in res["output"]:
            if "Host load completed successfully" in line:
                successfully = True
        return successfully

    def get_fw_file(self, atl):
        dev_ids = {0x7b1: "87B1.fw", 0x0b1: "80B1.fw", 0x11b1: "91B1.fw"}
        _, dev_id, __, ___ = atl.get_device_ids()
        return dev_ids[dev_id]

    def is_not_secure_chips(self):
        efuse = self.dut_atltool.get_efuse(504)
        rbl = efuse[62]
        if rbl & 0x00027000 != 0x27000:
            return True
        else:
            return False
        
    def get_rbl_hash(self):
        efuse = self.dut_atltool.get_efuse(504)
        rbl_hash = [efuse[103], efuse[104], efuse[105], efuse[121], efuse[122], efuse[123], efuse[124], efuse[125]]
        print(rbl_hash)
        return rbl_hash

    def test_is_installed_fw(self):
        """
        @description: Check installation flashless firmware.

        @steps:
        1. Install driver.
        2. Make sure dmesg contains message "Host load completed successfully", to make sure that the flashless
        firmware is loaded.
        3. Check 0x18 register that it is not zero, to make sure that the firmware is loaded.

        @result: Flashless firmware successfully loaded.
        @duration: 5 s.

        @requirements: DRV_FLASHLESS_02, DRV_FLASHLESS_03, DRV_FLASHLESS_04
        """
        if self.skip:
            pytest.skip()
        if self.is_not_secure_chips():
            pytest.skip("Not secure chip")
        assert self.install_drv_and_check_fw(), "Host load is fail"
        assert self.dut_atltool.readreg(0x18) != 0, "Host load is fail"

    def test_ping(self):
        """
        @description: Check traffic with flashless firmware.

        @steps:
        1. Install driver.
        2. Make sure dmesg contains message "Host load completed successfully", to make sure that the flashless
        firmware is loaded.
        3. Link up.
        4. Check ping from DUT to LKP.

        @result: Ping successfully.
        @duration: 30 s.

        """
        if self.skip:
            pytest.skip()
        if self.is_not_secure_chips():
            pytest.skip("Not secure chip")
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, None)
        self.lkp_ifconfig.set_ip_address(self.LKP_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, None)
        self.dut_ifconfig.wait_link_up()
        assert self.ping(to_host=self.LKP_IPV4_ADDR, from_host=self.DUT_IPV4_ADDR)

    def test_not_secure_chips(self):
        """
        @description: Check installation flashless firmware on not secure chip.

        @steps:
        1. Install driver.
        2. Make sure dmesg does not contains message "Host load completed successfully", to make sure that the flashless
        firmware is not loaded.

        @result: Flashless firmware is not loaded.
        @duration: 5 s.

        @requirements: DRV_FLASHLESS_01, DRV_FLASHLESS_06
        """
        if self.skip:
            pytest.skip()
        if not self.is_not_secure_chips():
            pytest.skip("Secure chip")
        assert self.install_drv_and_check_fw() is False

    def test_zero_rbl_hash(self):
        """
        @description: Check installation flashless firmware when rbl hash is zero.

        @steps:
        1. Install driver.
        2. Make sure dmesg contains message "Host load completed successfully", to make sure that the flashless
        firmware is loaded.

        @result: Flashless firmware successfully loaded.
        @duration: 7 s.

        @requirements: DRV_FLASHLESS_05
        """
        if self.skip:
            pytest.skip()
        if self.is_not_secure_chips():
            pytest.skip("Not secure chip")
        rbl_hash = self.get_rbl_hash()
        if any(rbl_hash) == 0:
            pytest.skip("RBL Hash is not zero")
        assert self.install_drv_and_check_fw()

    def test_without_flashless_fw(self):
        """
        @description: Check installation flashless firmware without fw file.

        @steps:
        1. Install driver.
        2. Make sure dmesg does not contains message "Host load completed successfully", to make sure that the flashless
        firmware is not loaded.
        3. Check that the 18 register is zero, to make sure that the firmware is not loaded.

        @result: Flashless firmware is not loaded.
        @duration: 5 s.

        @requirements: DRV_FLASHLESS_10
        """
        if self.skip:
            pytest.skip()
        if self.is_not_secure_chips():
            pytest.skip("Not secure chip")
        Command(cmd="sudo rm /lib/firmware/mrvl/*.fw").run_join()
        assert self.install_drv_and_check_fw() is False
        assert self.dut_atltool.readreg(0x18) == 0

    def test_fw_from_flash(self):
        """
        @description: Check installation flashless from flash.

        @steps:
        1. Install firmware from flash.
        2. Check the firmware version to make sure that flashless boot should not start.

        @result: Flashless firmware is not loaded.
        @duration: 1 m.

        @requirements: DRV_FLASHLESS_07
        """
        if self.skip:
            pytest.skip()
        if self.is_not_secure_chips():
            pytest.skip("Not secure chip")
        ver_major_exp = 3
        ver_minor_exp = 1
        ver_release_exp = 44
        self.dut_flash_override, _ = self.get_flash_override()
        self.dut_firmware = Firmware(port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
                                     version="{}x/{}.{}.{}".format(ver_major_exp, ver_major_exp, ver_minor_exp, ver_release_exp), mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
                                     pause=self.dut_fw_pause, pcirom=self.dut_fw_pcirom,
                                     dirtywake=self.dut_fw_dirtywake, host=self.dut_hostname, bdp=self.dut_bdp,
                                     sign=self.dut_sign,
                                     se_enable=self.dut_se, hsd=self.dut_hsd)
        self.dut_firmware.install(overrides=self.dut_flash_override)
        self.dut_atltool.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)
        ver_major, ver_minor, ver_release = self.dut_atltool.get_fw_version()
        assert ver_major == ver_major_exp and ver_minor == ver_minor_exp and ver_release_exp == ver_release
        self.install_driver()
        ver_major, ver_minor, ver_release = self.dut_atltool.get_fw_version()
        assert ver_major == ver_major_exp and ver_minor == ver_minor_exp and ver_release_exp == ver_release

    def test_phy_fw(self):
        """
        @description: Check installation PHY firmware.

        @steps:
        1. Check PHY HB.
        2. Uninstall driver.
        3. Install driver.
        4. Check PHY HB to make sure phy is not restarted.

        @result: When unloading and loading driver, PHY firmware does not restart.
        @duration: 5 s.

        @requirements: DRV_FLASHLESS_15
        """
        if self.skip:
            pytest.skip()
        if self.is_not_secure_chips():
            pytest.skip("Not secure chip")
        time.sleep(1.1)
        hb_phy_before = self.dut_atltool.readphyreg(0x1E, 0xC886)
        self.uninstall_driver()
        self.install_driver()
        time.sleep(1)
        hb_phy_after = self.dut_atltool.readphyreg(0x1E, 0xC886)
        assert hb_phy_before < hb_phy_after

    def test_device_id(self):
        """
        @description: Check installation flashless firmware with 'aq_fw_did'.

        @steps:
        1. Install driver without aq_fw_did.
        2. Check the firmware version to verify that the correct aq_fw_did is being used.
        3. Install with aq_fw_did = 0.
        4. Check the firmware version to verify that the correct aq_fw_did is being used.
        5. Install with aq_fw_did = did.
        6. Check the firmware version to verify that the correct aq_fw_did is being used.

        @result: correct aq_fw_did is applied.
        @duration: 30 s.

        @requirements: DRV_LINUX_FLASHLESS_01, DRV_LINUX_FLASHLESS_02
        """
        if self.skip:
            pytest.skip()
        if self.is_not_secure_chips():
            pytest.skip("Not secure chip")
        ver_major_exp = 3
        ver_minor_exp = 1
        ver_release_exp = 79

        fw = self.get_fw_file(self.dut_atltool)
        hostload_dir = "/storage/export/builds/firmware/{}x/{}.{}.{}/Customers_AqSign/hostload/{}".format(
                ver_major_exp, ver_major_exp, ver_minor_exp, ver_release_exp, fw)
        firmware_dir = "/lib/firmware/mrvl"
        Command(cmd="sudo rm /lib/firmware/mrvl/{}".format(fw)).run_join()
        download_file("qa-nfs01", hostload_dir, firmware_dir)
        self.uninstall_driver()
        self.install_driver()
        ver_major, ver_minor, ver_release = self.dut_atltool.get_fw_version()
        assert ver_major == ver_major_exp and ver_minor == ver_minor_exp and ver_release_exp == ver_release
        self.uninstall_driver()
        self.install_driver(aq_fw_did=["0"])
        assert self.install_drv_and_check_fw()
        ver_major, ver_minor, ver_release = self.dut_atltool.get_fw_version()
        assert ver_major == ver_major_exp and ver_minor == ver_minor_exp and ver_release_exp == ver_release
        self.uninstall_driver()
        self.install_driver(aq_fw_did=["0x{}".format(fw[:-3])])
        assert self.install_drv_and_check_fw()
        ver_major, ver_minor, ver_release = self.dut_atltool.get_fw_version()
        assert ver_major == ver_major_exp and ver_minor == ver_minor_exp and ver_release_exp == ver_release

    def test_device_id_two_cards(self):
        """
        @description: Check installation flashless firmware with 'aq_fw_did' on two-card setup.

        @steps:
        1. Install without aq_fw_did.
        2. Check the firmware version to make sure that the firmware for the two cards is loaded correctly.
        3. Install with aq_fw_did = [did].
        4. Check the firmware version to make sure that the firmware for the two cards is loaded correctly.
        5. Install with aq_fw_did = [did, did1].
        6. Check the firmware version to make sure that the firmware for the two cards is loaded correctly.
        7. Install with aq_fw_did = [did, did1, did2].
        8. Check the firmware version to make sure that the firmware for the two cards is loaded correctly.

        @result: Firmware for two cards loaded correctly.
        @duration: 30 s.

        @requirements: DRV_LINUX_FLASHLESS_01, DRV_LINUX_FLASHLESS_02, DRV_LINUX_FLASHLESS_03, DRV_LINUX_FLASHLESS_04,
        DRV_LINUX_FLASHLESS_05, DRV_LINUX_FLASHLESS_06, DRV_LINUX_FLASHLESS_07, DRV_LINUX_FLASHLESS_08
        """
        if self.skip:
            pytest.skip()
        if self.is_not_secure_chips():
            pytest.skip("Not secure chip")
        if self.dut_ports is not None and len(self.dut_ports) > 1:
            ver_major_exp = 3
            ver_minor_exp = 1
            ver_release_exp = 78
            dut_atltool_1 = AtlTool(port=self.dut_ports[1])

            def check():
                assert self.install_drv_and_check_fw()
                ver_major, ver_minor, ver_release = self.dut_atltool.get_fw_version()
                assert ver_major == ver_major_exp and ver_minor == ver_minor_exp and ver_release_exp == ver_release_exp
                ver_major, ver_minor, ver_release = dut_atltool_1.get_fw_version()
                assert ver_major == ver_major_exp and ver_minor == ver_minor_exp and ver_release_exp == ver_release_exp

            fw = self.get_fw_file(self.dut_atltool)
            fw_1 = self.get_fw_file(dut_atltool_1)
            hostload_dir = "/storage/export/builds/firmware/{}x/{}.{}.{}/Customers_AqSign/hostload/{}".format(
                    ver_major_exp, ver_major_exp, ver_minor_exp, ver_release_exp, fw)
            hostload_dir_1 = "/storage/export/builds/firmware/{}x/{}.{}.{}/Customers_AqSign/hostload/{}".format(
                    ver_major_exp, ver_major_exp, ver_minor_exp, ver_release_exp, fw_1)

            firmware_dir = "/lib/firmware/mrvl"
            download_file("qa-nfs01", "{}".format(hostload_dir), "{}".format(firmware_dir))
            download_file("qa-nfs01", "{}".format(hostload_dir_1), "{}".format(firmware_dir))
            self.uninstall_driver()
            self.install_driver()
            check()
            self.uninstall_driver()
            self.install_driver(aq_fw_did=["0x{}".format(fw[:-3])])
            check()
            self.uninstall_driver()
            self.install_driver(aq_fw_did=["0x{}".format(fw[:-3]), "0x{}".format(fw_1[:-3])])
            check()
            self.uninstall_driver()
            self.install_driver(aq_fw_did=["0", "0x{}".format(fw_1[:-3])])
            check()
            self.uninstall_driver()
            self.install_driver(aq_fw_did=["0x{}".format(fw[:-3]), "0x{}".format(fw_1[:-3]), "0x{}".format(fw_1[:-3])])
            check()
        else:
            pytest.skip()

    def test_phy_bdp(self):
        """
        @description: Check that the correct phy bdp is applied.

        @steps:
        1. Install with different aq_fw_sid.
        2. Check that phy bdp is applied depending on aq_fw_sid.

        @result: PHY BDP is applied depending on aq_fw_sid.
        @duration: 30 s.

        @requirements: DRV_FLASHLESS_11, DRV_FLASHLESS_13, DRV_LINUX_FLASHLESS_11
        """
        if self.skip:
            pytest.skip()
        if self.is_not_secure_chips():
            pytest.skip("Not secure chip")
        _, _, subven_id, subsys_id = self.dut_atltool.get_device_ids()

        fw = self.get_fw_file(self.dut_atltool)
        with open('/lib/firmware/mrvl/{}'.format(fw), 'rb') as fw_file:
            clx_header = fw_file.read(ctypes.sizeof(HEADER_HOST_LOAD))
            n = HEADER_HOST_LOAD.from_buffer_copy(clx_header)
            count_conf = n._configurationCount
            fw_file.seek(n._configurationPointer)
            list_conf = []
            while count_conf:
                clx_header = fw_file.read(ctypes.sizeof(CONFIGURATION_HEADER))
                n = CONFIGURATION_HEADER.from_buffer_copy(clx_header)
                count_conf -= 1
                list_conf.append(n)
            for n in list_conf:
                phyControl = self.dut_atltool.readphyreg(0x1e, 0x1000)
                phyControl = phyControl & 0xFFFFFFF7
                self.dut_atltool.writephyreg(0x1e, 0x1000, phyControl)
                if n._phyBDPLength != 0:
                    hb_phy_before = self.dut_atltool.readphyreg(0x1E, 0xC886)
                    self.uninstall_driver()
                    self.install_driver(aq_fw_sid=["{}".format(str(hex(n.svid_ssid))[:-1])])
                    hb_phy_after = self.dut_atltool.readphyreg(0x1E, 0xC886)
                    assert hb_phy_before >= hb_phy_after
                    fw_file.seek(n._phyBDPPointer)
                    clx_header = fw_file.read(ctypes.sizeof(PHY_HEADER))
                    m = PHY_HEADER.from_buffer_copy(clx_header)
                    len = n._phyBDPLength - ctypes.sizeof(PHY_HEADER)
                    list_reg = []
                    while True:
                        clx = fw_file.read(ctypes.sizeof(PHY_BDP))
                        r = PHY_BDP.from_buffer_copy(clx)
                        if r.reg == 0:
                            break
                        list_reg.append(r)
                        len -= ctypes.sizeof(PHY_BDP)

                    for r in list_reg:
                        assert r.val == (self.dut_atltool.readphyreg(0x01, r.reg) & r.mask)

    def test_sid_two_cards(self):
        """
        @description: Check installation flashless firmware with 'aq_fw_sid' on two-card setup.

        @steps:
        1. Install without aq_fw_sid.
        2. Make sure that the firmware is properly loaded on the two cards and check the bdp to make sure that the
        correct aq_fw_sid is used.
        3. Install with aq_fw_sid = 0.
        4. Make sure that the firmware is properly loaded on the two cards and check the bdp to make sure that the
        correct aq_fw_sid is used.
        5. Install with aq_fw_did = [did, did1].
        6. Make sure that the firmware is properly loaded on the two cards and check the bdp to make sure that the
        correct aq_fw_sid is used.
        7. Install with aq_fw_did = [did, did1, did2].
        8. Make sure that the firmware is properly loaded on the two cards and check the bdp to make sure that the
        correct aq_fw_sid is used.

        @result: Correct aq_fw_sid applied.
        @duration: 30 s.

        @requirements: DRV_LINUX_FLASHLESS_09, DRV_LINUX_FLASHLESS_12, DRV_LINUX_FLASHLESS_14,
        DRV_LINUX_FLASHLESS_15, DRV_LINUX_FLASHLESS_16, DRV_LINUX_FLASHLESS_17
        """
        if self.skip:
            pytest.skip()
        if self.is_not_secure_chips():
            pytest.skip("Not secure chip")
        if self.dut_ports is not None and len(self.dut_ports) > 1:
            fwsettings_offset = 0x1FB10024
            dut_atltool_1 = AtlTool(port=self.dut_ports[1])
            fw = self.get_fw_file(self.dut_atltool)
            fw_1 = self.get_fw_file(dut_atltool_1)
            sid = self.dut_atltool.get_device_ids()[3] << 16 | self.dut_atltool.get_device_ids()[2]
            sid_1 = dut_atltool_1.get_device_ids()[3] << 16 | dut_atltool_1.get_device_ids()[2]

            def check_correct_bdp(fw, sid, atl):
                with open('/lib/firmware/mrvl/{}'.format(fw), 'rb') as fw_file:
                    clx_header = fw_file.read(ctypes.sizeof(HEADER_HOST_LOAD))
                    n = HEADER_HOST_LOAD.from_buffer_copy(clx_header)
                    count_conf = n._configurationCount
                    fw_file.seek(n._configurationPointer)
                    list_conf = []
                    while count_conf:
                        clx_header = fw_file.read(ctypes.sizeof(CONFIGURATION_HEADER))
                        n = CONFIGURATION_HEADER.from_buffer_copy(clx_header)
                        count_conf -= 1
                        list_conf.append(n)
                    for n in list_conf:
                        if n._macBDPLength != 0:
                            if n.svid_ssid == sid:
                                fw_file.seek(n._macBDPPointer)
                                clx_header = fw_file.read(ctypes.sizeof(MAC_BDP))
                                m = MAC_BDP.from_buffer_copy(clx_header)
                                val = atl.readmem(0x1fb10000 | self.dut_atltool.readmem(fwsettings_offset, 4)[0],
                                                  (m.reg + 1) * 4)[-1]
                                assert val == m.val & m.mask

            self.uninstall_driver()
            self.install_driver()
            check_correct_bdp(fw, sid, self.dut_atltool)
            check_correct_bdp(fw_1, sid_1, dut_atltool_1)

            Command(cmd="sudo dmesg -C").run_join()
            self.uninstall_driver()
            try:
                self.install_driver(aq_fw_sid=[0xffffffff1])
            except:
                pass
            res = Command(cmd="sudo dmesg").run()
            successfully = False
            for line in res["output"]:
                if "Host load completed successfully" in line:
                    successfully = True
            assert successfully is False

            self.uninstall_driver()
            self.install_driver(aq_fw_sid=[0])
            check_correct_bdp(fw, sid, self.dut_atltool)
            check_correct_bdp(fw_1, sid_1, dut_atltool_1)

            self.uninstall_driver()
            self.install_driver(aq_fw_sid=[sid])
            check_correct_bdp(fw, sid, self.dut_atltool)
            check_correct_bdp(fw_1, sid_1, dut_atltool_1)

            self.uninstall_driver()
            self.install_driver(aq_fw_sid=[sid, sid_1])
            check_correct_bdp(fw, sid, self.dut_atltool)
            check_correct_bdp(fw_1, sid_1, dut_atltool_1)

            self.uninstall_driver()
            self.install_driver(aq_fw_sid=[sid, sid_1, 0x11111111])
            check_correct_bdp(fw, sid, self.dut_atltool)
            check_correct_bdp(fw_1, sid_1, dut_atltool_1)
        else:
            pytest.skip()

    def test_mac_bdp(self):
        """
        @description: Check that the correct mac bdp is applied.

        @steps:
        1. Install with different aq_fw_sid.
        2. Check that mac bdp is applied depending on aq_fw_sid.

        @result: MAC BDP is applied depending on aq_fw_sid.
        @duration: 30 s.

        @requirements: DRV_FLASHLESS_11, DRV_LINUX_FLASHLESS_11
        """
        if self.skip:
            pytest.skip()
        if self.is_not_secure_chips():
            pytest.skip("Not secure chip")
        fwsettings_offset = 0x1FB10024
        fw = self.get_fw_file(self.dut_atltool)
        with open('/lib/firmware/mrvl/{}'.format(fw), 'rb') as fw_file:
            clx_header = fw_file.read(ctypes.sizeof(HEADER_HOST_LOAD))
            n = HEADER_HOST_LOAD.from_buffer_copy(clx_header)
            count_conf = n._configurationCount
            fw_file.seek(n._configurationPointer)
            list_conf = []
            while count_conf:
                clx_header = fw_file.read(ctypes.sizeof(CONFIGURATION_HEADER))
                n = CONFIGURATION_HEADER.from_buffer_copy(clx_header)
                count_conf -= 1
                list_conf.append(n)
            for n in list_conf:
                if n._macBDPLength != 0:
                    self.uninstall_driver()
                    self.install_driver(aq_fw_sid=["{}".format(str(hex(n.svid_ssid))[:-1])])
                    fw_file.seek(n._macBDPPointer)
                    clx_header = fw_file.read(ctypes.sizeof(MAC_BDP))
                    m = MAC_BDP.from_buffer_copy(clx_header)
                    val = self.dut_atltool.readmem(0x1fb10000 | self.dut_atltool.readmem(fwsettings_offset, 4)[0],
                                                   (m.reg + 1) * 4)[-1]
                    assert val == m.val & m.mask


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
