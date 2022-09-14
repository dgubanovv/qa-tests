import os
import tempfile
import time
import traceback

import pytest

import tools.usb_control

import tools.driver

from infra.test_base import TestBase, idparametrize
from tools.utils import get_atf_logger

from tools.utils import get_wmi_device_pnp_driver as device_on_bus

SCRIPT_STATUS_SUCCESS = "[POWER-SUCCESS]"
SCRIPT_STATUS_FAILED = "[POWER-FAILED]"

log = get_atf_logger()

SHORT_TIMEOUT = 0
LONG_TIMEOUT = 5
ITER_COUNT = 10


def setup_module(module):
    # os.environ["DUT_HOSTNAME"] = "at085-b150m"
    # os.environ["LKP_HOSTNAME"] = "at053-970m"
    #
    os.environ["DUT_PORT"] = "usb0.0019.0001"
    os.environ["DUT_DRV_VERSION"] = "latest"
    # os.environ["DUT_FW_VERSION"] = "x1/latest"
    # os.environ["DUT_FW_CARD"] = "Nikki"
    # os.environ["DUT_FW_SPEED"] = "5G"
    # os.environ["DUT_FW_MDI"] = "MDINormal"
    # os.environ["DUT_FW_MII"] = "USX_SGMII"
    # os.environ["DUT_FW_PAUSE"] = "no"
    # os.environ["DUT_FW_PCIROM"] = "0.0.1"
    # os.environ["DUT_FW_DIRTYWAKE"] = "no"
    # os.environ["DUT_DEV_ID"] = "0xD108"
    # os.environ["DUT_SUBSYS_ID"] = "0x0001"
    # os.environ["DUT_SUBVEN_ID"] = "0x1D6A"

    os.environ["USB_SWITCH_TYPE"] = "USBCSwitch"
    log.info(os.environ["USB_SWITCH_TYPE"])
    # os.environ["USB_SWITCH_SERIAL"] = "None"
    # os.environ["USB_SWITCH_PORT"] = "1"
    #
    # os.environ["LKP_PORT"] = "pci1.00.0"
    # os.environ["LKP_DRV_VERSION"] = "stable"
    # os.environ["LKP_FW_VERSION"] = "x1/stable"
    # os.environ["LKP_FW_CARD"] = "Nikki"
    # os.environ["LKP_FW_SPEED"] = "5G"
    # os.environ["LKP_FW_MDI"] = "MDINormal"
    # os.environ["LKP_FW_MII"] = "USX_SGMII"
    # os.environ["LKP_FW_PAUSE"] = "no"
    # os.environ["LKP_FW_PCIROM"] = "0.0.1"
    # os.environ["LKP_FW_DIRTYWAKE"] = "no"
    # os.environ["LKP_DEV_ID"] = "0xD108"
    # os.environ["LKP_SUBSYS_ID"] = "0x0001"
    # os.environ["LKP_SUBVEN_ID"] = "0x1D6A"

    os.environ["MBU_VERSION"] = "latest"
    os.environ["ATB_VERSION"] = "latest"
    os.environ[
        "SUBTEST_STATUS_API_URL"] = "http://nn-ap01.rdc-lab.marvell.com/flask/addsubtest-fake/0"
    os.environ["TEST_TOOL_VERSION"] = "LATEST"
    os.environ["LOG_SERVER"] = "nn-ap01.rdc-lab.marvell.com"
    os.environ["LOG_PATH"] = "/storage/logs"
    os.environ["JOB_ID"] = "0"
    os.environ["PLATFORM"] = "usb_platform"
    os.environ["WORKING_DIR"] = tempfile.gettempdir()

    # Hardcoded test name for log path
    os.environ["TEST"] = "USB_manipulating"


class TestUSBManBase(TestBase):
    _skip_setup_class_ = False

    @classmethod
    def setup_class(cls):
        try:
            super(TestUSBManBase, cls).setup_class()

            cls.dev = os.getenv("USB_SWITCH_TYPE", None)
            cls.ser = os.getenv("USB_SWITCH_SERIAL", None)
            cls.p = int(os.getenv("USB_SWITCH_PORT", 0))

            if cls._skip_setup_class_ is False:
                cls.dut_driver = tools.driver.Driver(port=cls.dut_port,
                                                     drv_type="ndis",
                                                     version=cls.dut_drv_version)
                cls.dut_driver.install()

            # Log dirs
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            time.sleep(cls.LINK_CONFIG_DELAY)
        except Exception as e:
            log.error(traceback.format_exc(e))
            raise e

    def setup_method(self, method):
        super(TestUSBManBase, self).setup_method(method)

    @classmethod
    def sample_method(cls):
        pass

    @idparametrize("iterations,timeout", [
        (ITER_COUNT, SHORT_TIMEOUT),
        (ITER_COUNT, LONG_TIMEOUT), ])
    def test_plug_unplug(cls, iterations, timeout):
        if not device_on_bus(cls.dut_port):
            tools.usb_control.enable(cls.dev, cls.ser, cls.p)

        if not device_on_bus(cls.dut_port):
            raise Exception(
                "Device is not on a bus even after enabling port on USB switch")

        tools.usb_control.enable(cls.dev, cls.ser, cls.p, iterations, timeout)

        if not device_on_bus(cls.dut_port):
            raise Exception("Device is not on a bus after plug/unplug.")

    def test_flip_cable(cls):
        if not device_on_bus(cls.dut_port):
            tools.usb_control.enable(cls.dev, cls.ser, cls.p)

        if not device_on_bus(cls.dut_port):
            raise Exception(
                "Device is not on a bus even after enabling port on USB switch")

        for i in range(2):
            tools.usb_control.flip_cable(cls.dev, cls.ser, cls.p)
            tools.usb_control.disable(cls.dev, cls.ser, cls.p)
            if not device_on_bus(cls.dut_port):
                raise Exception("Device is not on a bus after cable flip")

    def test_highspeed_only(cls):
        if not device_on_bus(cls.dut_port):
            tools.usb_control.enable(cls.dev, cls.ser, cls.p)

        tools.usb_control.disable_superspeed(cls.dev, cls.ser, cls.p)
        if not device_on_bus(cls.dut_port):
            raise Exception(
                "Device is not on a bus after disabling SuperSpeed")
        tools.usb_control.enable_superspeed(cls.dev, cls.ser, cls.p)

        # print device_on_bus(cls.dut_port)

    def test_superspeed(cls):
        if not device_on_bus(cls.dut_port):
            tools.usb_control.enable(cls.dev, cls.ser, cls.p)

        tools.usb_control.disable_hispeed(cls.dev, cls.ser, cls.p)
        if not device_on_bus(cls.dut_port):
            raise Exception("Device is not on a bus after disabling HighSpeed")
        tools.usb_control.enable_hispeed(cls.dev, cls.ser, cls.p)

        print device_on_bus(cls.dut_port)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])