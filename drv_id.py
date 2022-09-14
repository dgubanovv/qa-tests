import os
import re
import sys
import tempfile
import time

import pytest

from tools.command import Command
from tools.constants import CARD_NIKKI, CARD_JAMAICA, CARD_FELICITY_KR, CARD_FELICITY_EUROPA, \
    LINK_SPEED_5G, LINK_SPEED_10G, CARD_FELICITY
from tools.driver import Driver, DRV_TYPE_DIAG, DRV_TYPE_MSI, DRV_TYPE_NDIS
from tools.mbuper import MbuWrapper, download_mbu
from tools.ops import OpSystem
from infra.test_base import TestBase, idparametrize
from tools.utils import get_atf_logger, remove_directory

if sys.platform == "win32":
    import wmi
    from tools.utils import get_wmi_pnp_devices

log = get_atf_logger()


def setup_module(module):
    pass
    # import tools._test_setup  # uncomment for manual test setup
    # os.environ["TEST"] = "NDIS"
    # os.environ["TEST"] = "MSI"


class WoLState(object):
    ENABLED = "enabled"
    DISABLED = "disabled"
    ABSENT = "absent"
    S5DISABLED = "S5 disabled"
    S5NOTSUPPORTED = "S5 not supported"


# dev_id, subsystem_id, subsystem_vendor_id, driver_name, wol_enabled
TEST_PARAMS = [
    ("d107", "872e", "1043", "ROG AREION 10G", WoLState.ENABLED),
    ("d107", "8741", "1043", "ASUS XG-C100C 10G PCI-E Network Adapter", WoLState.ABSENT),
    ("d100", "874a", "1043", "ASUS XG-C100F 10G SFP+ Network Adapter", WoLState.ENABLED),
    ("d107", "8757", "1043", "Aquantia 10G Ethernet connection", WoLState.ENABLED),
    ("d108", "875b", "1043", "Aquantia 5G Ethernet connection", WoLState.ENABLED),
    ("d107", "200f", "1043", "Aquantia AQtion 10Gbit Network Adapter (NDIS 6.{}0 Miniport)", WoLState.S5DISABLED),
    ("d107", "205f", "1043", "Aquantia AQtion 10Gbit Network Adapter (NDIS 6.{}0 Miniport)", WoLState.ENABLED),
    ("d107", "208f", "1043", "Aquantia AQtion 10Gbit Network Adapter (NDIS 6.{}0 Miniport)", WoLState.S5NOTSUPPORTED),
    ("d107", "1202", "1462", "Aquantia AQtion 10Gbit Network Adapter (NDIS 6.{}0 Miniport)", WoLState.ENABLED),
    ("d107", "b912", "1462", "Aquantia AQtion 10Gbit Network Adapter (NDIS 6.{}0 Miniport)", WoLState.ENABLED),
    ("d107", "7a92", "1462", "Aquantia AQtion 10Gbit Network Adapter (NDIS 6.{}0 Miniport)", WoLState.ENABLED),
    ("d107", "d107", "1849", "Aquantia AQtion 10Gbit Network Adapter (NDIS 6.{}0 Miniport)", WoLState.DISABLED),

    ("d107", "72e1", "16B8", "Aquantia AQtion 10Gbit Network Adapter (NDIS 6.{}0 Miniport)", WoLState.ENABLED),
    ("d107", "72e3", "16B8", "Aquantia AQtion 10Gbit Network Adapter (NDIS 6.{}0 Miniport)", WoLState.ENABLED),
    ("d100", "72e5", "16B8", "Aquantia Felicity Network Adapter (NDIS 6.{}0 Miniport)", WoLState.ENABLED),
    ("d100", "72e7", "16B8", "Aquantia Felicity Network Adapter (NDIS 6.{}0 Miniport)", WoLState.ENABLED),
]


class TestDrvID(TestBase):
    DIAG_FIELDS_CMD = "diag.exe --password !h:ahT8uW6 --flash_fields dev_id={} lane_width={} subsys={}"
    RE_WMI_DEV_ID = re.compile(r"PCI\\+VEN_([0-9a-fA-F]{4})&DEV_([0-9a-fA-F]{4})&"
                               r"SUBSYS_([0-9a-fA-F]{8})&REV_([0-9]{2})", re.DOTALL)

    @classmethod
    def setup_class(cls):
        super(TestDrvID, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            assert os.environ["TEST"].lower() in [DRV_TYPE_MSI, DRV_TYPE_NDIS]

            cls.install_firmwares()

            cls.dut_win_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version,
                                        drv_type=os.environ["TEST"].lower())
            cls.dut_diag_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, drv_type=DRV_TYPE_DIAG)

            cls.mbu_dir = download_mbu("universal", cls.working_dir)

            op_name = OpSystem().get_name().lower()
            if "win10" in op_name:
                cls.dut_drv_os_id = 5
            elif "win8.1" in op_name:
                cls.dut_drv_os_id = 4
            elif "win8" in op_name:
                cls.dut_drv_os_id = 3
            elif "win7" in op_name:
                cls.dut_drv_os_id = 2
            log.info("OS id for driver = {}".format(cls.dut_drv_os_id))
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestDrvID, cls).teardown_class()

        if cls.dut_fw_card in [CARD_FELICITY_KR, CARD_FELICITY_EUROPA, CARD_FELICITY]:
            dev_id = "0xd100"
        else:
            if cls.dut_fw_speed == LINK_SPEED_10G:
                dev_id = "0xd107"
            else:
                dev_id = "0xd108"
        lanes = 4 if dev_id in ["0xd107", "0xd100"] else 1
        subsys = "0x00011d6a"
        log.info("Restoring default settings")
        log.info("Device ID: {}, lane width: {}, subsystem: {}".format(dev_id, lanes, subsys))

        # Update WMI cache
        cls.update_wmi_cache()
        cls.dut_diag_driver.install()
        cmd = cls.DIAG_FIELDS_CMD.format(dev_id, lanes, subsys)
        res = Command(cmd=cmd).run()
        # Update WMI cache
        cls.update_wmi_cache()
        cls.dut_diag_driver.uninstall(ignore_remove_errors=True)

        cls.dut_diag_driver.remove_all_hidden_devices()
        remove_directory(cls.mbu_dir)

        # Restart services that depend on WMI
        Command(cmd="net start wscsvc").run()  # Security Center
        time.sleep(3)
        Command(cmd="net start iphlpsvc").run()  # IP Helper
        time.sleep(3)

        cls.state.test_cleanup_cold_restart = True

    def teardown_method(self, method):
        super(TestDrvID, self).teardown_method(method)

        self.dut_win_driver.uninstall()

    @staticmethod
    def update_wmi_cache():
        log.info("Trying to update WMI cache by restarting its service")
        Command(cmd="net stop winmgmt /Y").run()
        time.sleep(3)
        Command(cmd="net start winmgmt").run()
        time.sleep(3)

    @idparametrize("dev_id,ss_id,ss_vendor_id,name,wol", TEST_PARAMS)
    def test_driver_install(self, dev_id, ss_id, ss_vendor_id, name, wol):
        if dev_id.lower() in ["d108", "d109"]:
            lanes = 1
        elif dev_id.lower() in ["d107", "d100"]:
            lanes = 4
        else:
            raise Exception("Unrecognised device ID: {}".format(dev_id))
        dev_id_str = "0x{}".format(dev_id)
        subsys_str = "0x{}{}".format(ss_id, ss_vendor_id)

        # Update WMI cache
        self.update_wmi_cache()
        self.dut_diag_driver.install()
        cmd = self.DIAG_FIELDS_CMD.format(dev_id_str, lanes, subsys_str)
        res = Command(cmd=cmd).run()

        # Kickstart
        mbu_wrapper = MbuWrapper(mbu_dir=self.mbu_dir, port=self.dut_port)
        mbu_wrapper.kickstart()
        mbu_wrapper.destroy()
        time.sleep(5)

        # Update WMI cache
        self.update_wmi_cache()
        self.dut_diag_driver.uninstall(ignore_remove_errors=True)

        self.dut_win_driver.install()

        # Check driver properties
        if self.dut_win_driver.drv_type == DRV_TYPE_MSI:
            log.info("Checking driver status")
            self.dut_win_driver.check_driver_status()
            log.info("Driver has been installed without errors")

            assert self.dut_win_driver.is_present(), "Driver is not present Control Panel/Programs list"
            log.info("Driver is present in Control Panel/Programs list")

        wmi_drv = get_wmi_pnp_devices(self.dut_port)[0]
        match = self.RE_WMI_DEV_ID.match(wmi_drv.DeviceID)
        assert match is not None, "Matching failed for Device ID: {}".format(wmi_drv.DeviceID)

        _, drv_dev_id, drv_subsys, __ = match.groups()

        assert dev_id.lower() == drv_dev_id.lower(), "Device IDs are different"
        log.info("Device ID is correct: expected = {}, actual = {}".format(dev_id, drv_dev_id))

        assert (ss_id + ss_vendor_id).lower() == drv_subsys.lower(), "Subsystems are different"
        log.info("Subsystem ID is correct: expected = {}, actual = {}".format(ss_id + ss_vendor_id, drv_subsys))

        assert name.format(self.dut_drv_os_id) in wmi_drv.Name, "Driver names are different"
        log.info("Driver name is correct: expected = {}, actual = {}".format(name, wmi_drv.Name))

        # Check PM setting
        power_wake_enables = wmi.WMI(namespace='wmi').MSPower_DeviceWakeEnable()
        for pwr_wake_enable in power_wake_enables:
            if wmi_drv.PNPDeviceID.lower() in pwr_wake_enable.InstanceName.lower():
                if wol in [WoLState.ENABLED, WoLState.S5DISABLED, WoLState.S5NOTSUPPORTED]:
                    assert bool(pwr_wake_enable.Enable) is True, "PM setting is not correct"
                elif wol in [WoLState.DISABLED, WoLState.ABSENT]:
                    assert bool(pwr_wake_enable.Enable) is False, "PM setting is not correct"
                else:
                    raise Exception("Got unexpected WoL state: {}".format(wol))
                break
        log.info("PM setting is correct for preset \"{}\"".format(wol))

        # Check WoL setting
        if wol == WoLState.ABSENT:
            pytest.raises(WindowsError, self.dut_ifconfig.get_advanced_prop, "*WakeOnMagicPacket")
            pytest.raises(WindowsError, self.dut_ifconfig.get_advanced_prop, "*WakeOnPattern")
            pytest.raises(WindowsError, self.dut_ifconfig.get_advanced_prop, "WakeFromPowerOff")
            pytest.raises(WindowsError, self.dut_ifconfig.get_advanced_prop, "WakeOnPing")
            pytest.raises(WindowsError, self.dut_ifconfig.get_advanced_prop, "WakeOnLink")

            log.info("WoL settings are missing as expected")
        else:
            if wol == WoLState.ENABLED:
                on_magic = True
                on_pattern = True
                from_poff = True
            elif wol == WoLState.DISABLED:
                on_magic = False
                on_pattern = False
                from_poff = False
            elif wol == WoLState.S5DISABLED:
                on_magic = True
                on_pattern = True
                from_poff = False
            elif wol == WoLState.S5NOTSUPPORTED:
                on_magic = True
                on_pattern = True
            else:
                raise Exception("Got unexpected WoL state: {}".format(wol))

            drv_on_magic = self.dut_ifconfig.get_advanced_prop("*WakeOnMagicPacket") == "1"
            drv_on_pattern = self.dut_ifconfig.get_advanced_prop("*WakeOnPattern") == "1"
            drv_on_ping = self.dut_ifconfig.get_advanced_prop("WakeOnPing") == "1"
            drv_on_link = self.dut_ifconfig.get_advanced_prop("WakeOnLink") == "1"

            if wol == WoLState.S5NOTSUPPORTED:
                pytest.raises(WindowsError, self.dut_ifconfig.get_advanced_prop, "WakeFromPowerOff")
            else:
                drv_from_poff = self.dut_ifconfig.get_advanced_prop("WakeFromPowerOff") == "1"
                assert drv_from_poff == from_poff, "WakeFromPowerOff should be: {}".format(from_poff)

            assert drv_on_magic == on_magic, "WakeOnMagicPacket should be: {}".format(on_magic)
            assert drv_on_pattern == on_pattern, "WakeOnPattern should be: {}".format(on_pattern)
            assert drv_on_ping is False, "WakeOnPing should be: {}".format(False)
            assert drv_on_link is False, "WakeOnLink should be: {}".format(False)

            log.info("WoL settings are correct for preset \"{}\"".format(wol))


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
