import io
import shutil
import ntpath
import os
import re
import sys
import tempfile
import time
import urlparse
import zipfile
import random

import pytest

from infra.test_base import idparametrize
from infra.test_base import TestBase
from tools import firmware
from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import (
    NFS_SERVER, BUILDS_SERVER, FELICITY_CARDS, BERMUDA_CARDS, LINK_STATE_UP, LINK_STATE_DOWN, CARD_FIJI, CARD_NIKKI,
    CARD_ANTIGUA, LINK_SPEED_AUTO, LINK_SPEED_10G, MDI_NORMAL, MDI_SWAP, LINK_STATE_UP, LINK_STATE_DOWN)
from tools.diagper import DiagWrapper, download_diag
from tools.driver import Driver, DRV_TYPE_DIAG, DRV_TYPE_DIAG_WIN_USB, DRV_TYPE_T6, DRV_TYPE_SRC_DIAG_LIN
from tools.firmware import Firmware, get_actual_fw_version, get_mac
from tools.killer import Killer
from tools.ops import OpSystem
from tools.utils import get_atf_logger, get_domain_bus_dev_func, get_url_response, remove_directory, str_to_bool

log = get_atf_logger()
datapath_seeds = os.environ.get("SEED").split(";") if os.environ.get("SEED", None) is not None else [123]
datapath_time = os.environ.get("TRAFFIC_TIME", 5)


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "flash_tools_test"


def download_from_url(suburl, directory, unzip=False):
    url = urlparse.urljoin(BUILDS_SERVER, suburl)
    fname = ntpath.basename(suburl)
    log.debug("Downloading {} from {}".format(fname, url))
    _file = os.path.join(directory, fname)
    content = get_url_response(url)
    if unzip:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            archive.extractall(directory)
    else:
        with open(_file, "wb") as f:
            f.write(content)


def download_fwtools(host, fwtools_local, a2_tools_version=False, fwtools_ver=None):
    target_ops = OpSystem(host=host)
    if target_ops.is_linux():
        res = Command(cmd="uname -i", host=host).run()
        if res["output"][0] == "aarch64":
            platform = "linuxarm64"
        else:
            platform = "linux64"
    elif target_ops.is_windows():
        if target_ops.is_32_bit():
            platform = "win32"
        else:
            platform = "win64"
    elif target_ops.is_freebsd():
        platform = "freebsd"
    else:
        raise Exception("Unsupported platform")

    if fwtools_ver is None:
        fwtools_ver = os.environ.get("FW_TOOLS", "latest")
    tools_version = "atlantic2" if a2_tools_version else "atlantic"
    fwtools_storage = "/storage/export/builds/tools/{}/{}/{}".format(tools_version, fwtools_ver, platform)
    update_fwtools_cmd = "scp -r aqtest@{}:{}/* {}".format(NFS_SERVER, fwtools_storage, fwtools_local)
    Command(cmd=update_fwtools_cmd, host=host).run()

    if target_ops.is_linux():
        Command(cmd='sync', host=host).run()
        res = Command(cmd='{}/listDevices --help'.format(fwtools_local), host=host).run()
        assert res['returncode'] == 0


def get_lspci_port(port):
    domain, bus, dev, func = get_domain_bus_dev_func(port)
    return "{:04x}-{:02x}:{:02x}.{:x}".format(domain, bus, dev, func)


def readstat(port, host=None, attempts=1):
    lspci_port = get_lspci_port(port)

    stats = {
        "fw_version": {"value": None, "regexp": re.compile("Firmware Version = ([0-9.]+)")},
        "mac": {"value": None, "regexp": re.compile("MAC address = ([0-9a-z:]+)")},
        "vendor_id": {"value": None, "regexp": re.compile("Vendor ID = ([xA-Z0-9]+)")},
        "device_id": {"value": None, "regexp": re.compile("Device ID = ([xA-Z0-9]+)")},
        "subvid": {"value": None, "regexp": re.compile("Subsystem Vendor ID = ([a-zA-Z0-9]+)")},
        "subdid": {"value": None, "regexp": re.compile("Subsystem Device ID = ([a-zA-Z0-9]+)")},
        "lanes": {"value": None, "regexp": re.compile("PCIe Link Width = x(\d)")},
        "pcirom": {"value": None, "regexp": re.compile("Oprom\sVersion\s=\s(\d+.\d+.\d+)")},
    }

    cmd = "sudo readstat -d {}".format(lspci_port)
    for at in range(1, attempts + 1):
        log.info("readstat #{}".format(at))
        res = Command(cmd=cmd, host=host).wait(180)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            if at == attempts:
                raise Exception("Failed to run readstat")
            else:
                log.info('Wait 10 sec...')
                time.sleep(10)
        else:
            break

    for line in res["output"]:
        for key in stats:
            s = stats[key]
            if s["value"] is None:
                m = s["regexp"].match(line)
                if m is not None:
                    s["value"] = m.group(1)
                    continue

    log.info('Readstat result:')
    for key in stats:
        log.info("{}: {}".format(key, stats[key]["value"]))

    return stats


if os.environ.get("XAVIER_DUT_HOSTNAME", None) is not None:
    from xavier_test import XavierTestBase

    base_class = XavierTestBase
else:
    base_class = TestBase


class TestFlashTools(base_class):
    @classmethod
    def setup_class(cls):
        super(TestFlashTools, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            # Self protection, the test can't be run on FIJI
            assert cls.dut_fw_card != CARD_FIJI

            if base_class == TestBase:
                if cls.state.skip_class_setup:
                    cls.skip_fw_install = True
                cls.install_firmwares()

                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
                cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)

                if not cls.state.skip_class_setup:
                    cls.dut_driver.install()
                    cls.lkp_driver.install()

            if cls.dut_ops.is_windows():
                cls.dut_diag_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version=cls.dut_drv_version)

            assert os.environ.get("OLD_DUT_FW_VERSION", None) is not None
            cls.old_dut_fw_version = os.environ.get("OLD_DUT_FW_VERSION", None)

            cls.old_dut_firmware = Firmware(
                host=cls.dut_hostname, port=cls.dut_port, card=cls.dut_fw_card, speed=cls.dut_fw_speed,
                version=cls.old_dut_fw_version, mdi=cls.dut_fw_mdi, mii=cls.dut_fw_mii,
                pause=cls.dut_fw_pause, pcirom=cls.dut_fw_pcirom, dirtywake=cls.dut_fw_dirtywake,
                bdp=cls.dut_bdp, sign=cls.dut_sign, se_enable=cls.dut_se, hsd=cls.dut_hsd)

            cls.old_dut_fw_actual_version = get_actual_fw_version(cls.old_dut_fw_version)
            cls.new_dut_fw_actual_version = get_actual_fw_version(cls.dut_fw_version)

            cls.old_dut_clx_file = cls.old_dut_firmware.download()
            cls.new_dut_clx_file = cls.dut_firmware.download()

            cls.bb_name = os.environ.get("BB_NAME", None)
            cls.t6_name = os.environ.get("T6_NAME", None)
            cls.t6_port = os.environ.get("T6_PORT", None)

            if cls.bb_name is not None:
                cls.dut_iface_name = cls.bb_name
            elif cls.t6_name is not None:
                if cls.dut_ops.is_windows():
                    cls.t6_driver = Driver(port=cls.t6_port, drv_type=DRV_TYPE_T6, version="latest")
                    cls.t6_driver.install()
                elif cls.dut_ops.is_linux():
                    Command(cmd="sudo rmmod ftdi_sio", host=cls.dut_hostname).run()
                    Command(cmd="sudo rmmod usbserial", host=cls.dut_hostname).run()
                cls.dut_iface_name = cls.t6_name
            else:
                cls.dut_iface_name = get_lspci_port(cls.dut_port)

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)

            cls.fwtools_local = "/home/aqtest/fwtools"
            for target in [cls.dut_hostname, cls.lkp_hostname]:
                download_fwtools(host=target, fwtools_local=cls.fwtools_local)

            if not cls.state.skip_class_setup:
                cls.state.skip_class_setup = True
                cls.state.update()

        except Exception:
            log.exception("Failed while setting up class")
            raise

    @classmethod
    def teardown_class(cls):
        super(TestFlashTools, cls).teardown_class()
        Command(cmd="sudo rm -f *.clx", host=cls.dut_hostname).run()

    def check_and_install_diag_drv(self):
        if self.dut_ops.is_windows():
            if self.dut_driver.is_installed():
                log.info("<----- Remove NDIS driver  ----->")
                self.dut_driver.uninstall()

            if not self.dut_diag_driver.is_installed():
                log.info("<----- Install DIAG driver ----->")
                self.dut_diag_driver.install()

    def run_readstat(self):
        stats = {
            "fw_version": {"value": None, "regexp": re.compile("Firmware Version = ([0-9.]+)")},
            "phy_fw_version": {"value": None,
                               "regexp": re.compile("PHY Firmware Version = ([0-9A-F.]+ VerStr: [0-9A-Za-z-.]+).*")},
            "mac": {"value": None, "regexp": re.compile("MAC address = ([0-9a-z:]+)")},
            "vendor_id": {"value": None, "regexp": re.compile("Vendor ID = ([xA-Z0-9]+)")},
            "device_id": {"value": None, "regexp": re.compile("Device ID = ([xA-Z0-9]+)")},
            "subvid": {"value": None, "regexp": re.compile("Subsystem Vendor ID = ([a-zA-Z0-9]+)")},
            "subdid": {"value": None, "regexp": re.compile("Subsystem Device ID = ([a-zA-Z0-9]+)")},
            "lanes": {"value": None, "regexp": re.compile("PCIe Link Width = x(\d)")},
        }

        cmd = "sudo {}/readstat -d {}".format(self.fwtools_local, self.dut_iface_name)

        res = Command(cmd=cmd, host=self.dut_hostname).wait(180)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to run readstat")

        for line in res["output"]:
            for key in stats:
                s = stats[key]
                if s["value"] is None:
                    m = s["regexp"].match(line)
                    if m is not None:
                        s["value"] = m.group(1)
                        continue

        log.info('Readstat result:')
        for key in stats:
            log.info("{}: {}".format(key, stats[key]["value"]))

        return stats

    def run_flash_erase(self):
        cmd = "sudo {}/flashErase -d {}".format(self.fwtools_local, get_lspci_port(self.dut_port))
        res = Command(cmd=cmd, host=self.dut_hostname).wait(180)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to run flashErase")

    def run_flash_dump(self, out_file=None):
        cmd = "sudo {}/flashDump -d {}".format(self.fwtools_local, self.dut_iface_name)
        if out_file is not None:
            cmd += " -o {}".format(out_file)
        res = Command(cmd=cmd, host=self.dut_hostname).wait(180)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to run flashDump")

    def run_flash_burn(self, clx_file, nocrc=False, exp_success=True):
        cmd = "AQ_API_STOP_ON_FIRST_IMAGE_MISMATCH=1 {}/flashBurn -d {} {}".format(
            self.fwtools_local, get_lspci_port(self.dut_port), clx_file)
        if nocrc:
            cmd += " -n"
        cmd = "sudo bash -c \"{}\"".format(cmd)
        res = Command(cmd=cmd, host=self.dut_hostname).wait(180)
        if exp_success:
            assert res["returncode"] == 0
            assert any("Device burned and verified" in line for line in res["output"])
        else:
            assert res["returncode"] != 0
            assert any("Error:" in line for line in res["output"])

    def run_flash_override(self, ids=None, mac=None, check=True):
        cmd = "sudo {}/flashOverride -d {}".format(self.fwtools_local, self.dut_iface_name)
        if ids:
            cmd += " -i {}".format(ids)
        if mac:
            cmd += " -m {}".format(mac)
        res = Command(cmd=cmd, host=self.dut_hostname).wait(180)
        if check:
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to run flashOverride")
            if "Override finished" not in res["output"][-1]:
                raise Exception("Failed to run flashOverride")
        return res

    def run_flash_update(self, clx_file, bdp=False):
        cmd = "sudo {}/flashUpdate -d {} {}".format(self.fwtools_local, self.dut_iface_name, clx_file)
        if bdp:
            cmd += " --bdp"
        return Command(cmd=cmd, host=self.dut_hostname).wait(180)

    def run_kickstart(self, phy=False):
        cmd = "sudo {}/kickstart -d {}".format(self.fwtools_local, self.dut_iface_name)
        if phy:
            cmd += " --phy"
        return Command(cmd=cmd, host=self.dut_hostname).wait(180)

    # listDevices

    def test_list_devices(self):

        if self.bb_name is not None:
            res = Command(cmd="sudo {}/listDevices -d BB".format(self.fwtools_local), host=self.dut_hostname).run()
            assert res["returncode"] == 0, "Couldn't run listDevices"

            assert any(self.bb_name in line for line in res['output'])

        elif self.t6_name is not None:
            res = Command(cmd="sudo {}/listDevices -d T6".format(self.fwtools_local), host=self.dut_hostname).run()
            assert res["returncode"] == 0, "Couldn't run listDevices"

            assert any(self.t6_name in line for line in res['output'])

        else:
            res = Command(cmd="lspci -D -d 1d6a:", host=self.dut_hostname).run()
            assert res["returncode"] == 0, "Couldn't run lspci"

            common_format = [line.split(' ')[0] for line in res["output"]]
            new_format = [re.sub("^(\d+)(:)", "\g<1>-", d) for d in common_format]

            res = Command(cmd="sudo {}/listDevices".format(self.fwtools_local), host=self.dut_hostname).run()
            assert res["returncode"] == 0, "Couldn't run listDevices"

            for d in new_format:
                assert any(d in line for line in res["output"])

    # readlog

    def run_readlog(self, mode, log_file=None, phy=False):
        if mode == "normal":
            exec_bin = "readlog"
        elif mode == "crypt":
            exec_bin = "readlog_crypt"
        elif mode == "phy":
            exec_bin = "readphylog"
        else:
            raise Exception("Incorrect mode: {}. Possible values: normal, crypt, phy".format(mode))

        cmd = "sudo {}/{} -d {}".format(self.fwtools_local, exec_bin, self.dut_iface_name)
        if log_file is None:
            log_file = "phy_dbg_buffer.bin" if mode == "phy" else "mac_dbg_buf.bin"
        else:
            cmd += " -f {}".format(log_file)
        if phy:
            cmd += " --phy"

        readlog_cmd = Command(cmd=cmd, host=self.dut_hostname)
        readlog_cmd.run_async()

        self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
        if self.dut_ops.is_linux():
            self.dut_atltool_wrapper.kickstart(reload_phy_fw=self.dut_fw_card not in FELICITY_CARDS)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up(retry_interval=2)

        readlog_cmd.join(timeout=10)
        Killer(host=self.dut_hostname).kill(exec_bin, excludes=['python'])

        if mode == "normal":
            cmd = "python qa-tests/tools/mcplog/mdbgtrace.py -f ./{}".format(log_file)
        elif mode == "crypt":
            cmd = "python qa-tests/tools/mcplog/mdbgtrace.py -e -f ./{}".format(log_file)
        elif mode == "phy":
            dbg_trace = "dbgtrace.py"
            remote_file = "/storage/export/builds/firmware/{}/input/Nikki/default/{}".format(
                self.dut_fw_version, dbg_trace)
            Command(cmd='rm -f {}'.format(dbg_trace), host=self.dut_hostname).run()
            res = Command(cmd="scp aqtest@{}:{} {}".format(NFS_SERVER, remote_file, dbg_trace),
                          host=self.dut_hostname).run()
            assert res['returncode'] == 0, "Can't download dbgtrace file"
            cmd = "python {} -m ble -f ./{}".format(dbg_trace, log_file)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        if not mode == 'phy':
            # Can't read phy logs from the beginning
            assert any(re.match(".*?Aquantia\s[A-Za-z]+\sF/W\sversion:\s[0-9.]+", line) for line in res["output"])

    def test_readlog_no_options(self):
        self.run_readlog(mode="normal")

    def test_readlog_log_file(self):
        self.run_readlog(mode="normal", log_file="mac_dbg_buf_log.bin")

    def test_readlog_with_phy(self):
        self.run_readlog(mode="normal", phy=True)

    # readlog_crypt

    def test_readlog_crypt_no_options(self):
        self.run_readlog(mode="crypt")

    def test_readlog_crypt_log_file(self):
        self.run_readlog(mode="crypt", log_file='mac_dbg_buf_crypt.bin')

    def test_readlog_crypt_with_phy(self):
        self.run_readlog(mode="crypt", phy=True)

    # readphylog

    def test_readphylog_no_options(self):
        self.run_readlog(mode="phy")

    def test_readphylog_log_file(self):
        self.run_readlog(mode="phy", log_file='phy_dbg_buf_log.bin')

    # readefuse

    def run_readefuse(self, options):
        cmd = "sudo {}/readefuse -d {} {}".format(self.fwtools_local, self.dut_iface_name, options)
        res = Command(cmd=cmd, host=self.dut_hostname, silent=True).run()
        tool_res = []
        for line in res["output"]:
            m = re.match("eFuse\sdata\s+\d+\s=\s([xa-f0-9]+)", line)
            if m is not None:
                tool_res.append(int(m.group(1), 16))

        return tool_res

    def test_readefuse_no_options(self):
        tool_res = self.run_readefuse(options="")
        lib_res = self.dut_atltool_wrapper.load_efuse(0, 128)

        assert tool_res == lib_res

    def test_readefuse_start(self):
        tool_res = self.run_readefuse(options="-s 60")
        lib_res = self.dut_atltool_wrapper.load_efuse(60, 68)

        assert tool_res == lib_res

    def test_readefuse_number(self):
        tool_res = self.run_readefuse(options="-n 100")
        lib_res = self.dut_atltool_wrapper.load_efuse(0, 100)

        assert tool_res == lib_res

    def test_readefuse_start_number(self):
        tool_res = self.run_readefuse(options="-s 60 -n 5")
        lib_res = self.dut_atltool_wrapper.load_efuse(60, 5)

        assert tool_res == lib_res

    # tcpServer

    def run_tcp_server(self):
        if self.dut_ops.is_linux():
            Command(cmd="sudo iptables -F && sudo iptables -X", host=self.dut_hostname).run()
        if self.lkp_ops.is_linux():
            Command(cmd="sudo iptables -F && sudo iptables -X", host=self.lkp_hostname).run()

        Killer(host=self.dut_hostname).kill("tcpServer")
        tcp_server_thread = Command(cmd="sudo {}/tcpServer -v".format(self.fwtools_local), host=self.dut_hostname)
        tcp_server_thread.run_async()
        time.sleep(5)

        try:
            # workaround for Xavier
            res = Command(cmd="hostname", host=self.dut_hostname).run()
            hostname = res["output"][0].strip()

            res = Command(cmd="listDevices -d TCP", host=self.lkp_hostname).run()
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to run listDevices")

            server_found = False
            for line in res["output"]:
                if hostname in line:
                    server_found = True
                if server_found and self.dut_iface_name in line:
                    tcp_port = line.strip()
                    break
            else:
                raise Exception("Can't find tcp server")
        except Exception:
            tcp_server_thread.join(1)
            raise

        return tcp_server_thread, tcp_port

    def test_tcp_server_rr(self):
        tcp_server_thread, tcp_port = self.run_tcp_server()

        reg = 0x18
        cmd = "sudo {}/atltool -d {} -rr {}".format(self.fwtools_local, tcp_port, reg)
        tool_res = Command(cmd=cmd, host=self.lkp_hostname).run()
        tcp_server_thread.join(1)
        Killer(host=self.dut_hostname).kill("tcpServer")
        assert tool_res["returncode"] == 0, "Couldn't run atltool"

        re_mac_readreg = re.compile(r".*Register 0x[a-z0-9]+: (0x[a-z0-9]+) : [01\s]+")
        for line in tool_res["output"]:
            m = re_mac_readreg.match(line)
            if m is not None:
                tool_reg = int(m.group(1), 16)
                break
        else:
            raise Exception("Can not parse the value of the register.")

        lib_reg = self.dut_atltool_wrapper.readreg(reg)

        assert tool_reg == lib_reg

    def test_tcp_server_wr(self):
        tcp_server_thread, tcp_port = self.run_tcp_server()
        reg = 0x10C
        reg_val = 0x10
        cmd = "sudo {}/atltool -d {} -wr {} {}".format(self.fwtools_local, tcp_port, reg, reg_val)
        tool_res = Command(cmd=cmd, host=self.lkp_hostname).run()
        tcp_server_thread.join(1)
        Killer(host=self.dut_hostname).kill("tcpServer")
        assert tool_res["returncode"] == 0, "Couldn't run atltool"

        lib_res = self.dut_atltool_wrapper.readreg(reg)

        assert lib_res == reg_val

    def test_tcp_server_rpr(self):
        tcp_server_thread, tcp_port = self.run_tcp_server()

        mmd, reg = 0x1e, 0x300
        cmd = "sudo {}/atltool -d {} -rpr {}".format(self.fwtools_local, tcp_port, "0x{:X}.0x{:X}".format(mmd, reg))
        tool_res = Command(cmd=cmd, host=self.lkp_hostname).run()
        tcp_server_thread.join(1)
        Killer(host=self.dut_hostname).kill("tcpServer")
        assert tool_res["returncode"] == 0, "Couldn't run atltool"

        re_phy_readreg = re.compile(r".*Register PHY \d 0x[0-9a-z.]+: (0x[0-9a-z.]+) : [01]+ [01]+")
        for line in tool_res["output"]:
            m = re_phy_readreg.match(line)
            if m is not None:
                tool_reg = int(m.group(1), 16)
                break
        else:
            raise Exception("Can not parse the value of the register.")

        lib_reg = self.dut_atltool_wrapper.readphyreg(mmd, reg)

        assert tool_reg == lib_reg

    def test_tcp_server_wpr(self):
        tcp_server_thread, tcp_port = self.run_tcp_server()

        mmd, reg = 0x1e, 0x300
        val = 0x42
        cmd = "sudo {}/atltool -d {} -wpr {} 0x{:X}".format(self.fwtools_local, tcp_port,
                                                            "0x{:X}.0x{:X}".format(mmd, reg), val)
        tool_res = Command(cmd=cmd, host=self.lkp_hostname).run()
        tcp_server_thread.join(1)
        Killer(host=self.dut_hostname).kill("tcpServer")
        assert tool_res["returncode"] == 0, "Couldn't run atltool"

        lib_reg = self.dut_atltool_wrapper.readphyreg(mmd, reg)

        assert lib_reg == val

    # flashOverride

    # # Flash erased
    def test_flash_override_erased_mac_did_subvid_subdid(self):
        """
        Tests FlashOverride
        Initial state: Flash erased
        Run with options: -m -i (Device id, SubVendor id, SubDevice id)
        Expected result: "Error: No valid NCB detected in FLASH!"
        """
        self.run_flash_erase()
        new_mac = self.suggest_test_mac_address(self.dut_port, host=self.dut_hostname)
        new_ids = "0x87B1:0xAAEE:0x0042"
        res = self.run_flash_override(mac=new_mac, ids=new_ids, check=False)
        assert any("Error: No valid NCB detected in FLASH!" in line for line in res["output"])

    def test_flash_override_erased_mac_subvid_subdid(self):
        """
        Tests FlashOverride
        Initial state: Flash erased
        Run with options: -m -i (SubVendor id, SubDevice id)
        Expected result: "Error: No valid NCB detected in FLASH!"
        """
        self.run_flash_erase()
        new_mac = self.suggest_test_mac_address(self.dut_port, host=self.dut_hostname)
        new_ids = "0xAAEE:0x0042"
        res = self.run_flash_override(mac=new_mac, ids=new_ids, check=False)
        assert any("Error: No valid NCB detected in FLASH!" in line for line in res["output"])

    def test_flash_override_erased_mac(self):
        """
        Tests FlashOverride
        Initial state: Flash erased
        Run with options: -m
        Expected result: "Error: No valid NCB detected in FLASH!"
        """
        self.run_flash_erase()
        new_mac = self.suggest_test_mac_address(self.dut_port, host=self.dut_hostname)
        res = self.run_flash_override(mac=new_mac, check=False)
        assert any("Error: No valid NCB detected in FLASH!" in line for line in res["output"])

    def test_flash_override_erased_did_subvid_subdid(self):
        """
        Tests FlashOverride
        Initial state: Flash erased
        Run with options: -i (Device id, SubVendor id, SubDevice id)
        Expected result: "Error: No valid NCB detected in FLASH!"
        """
        self.run_flash_erase()
        new_ids = "0x87B1:0xAAEE:0x0042"
        res = self.run_flash_override(ids=new_ids, check=False)
        assert any("Error: No valid NCB detected in FLASH!" in line for line in res["output"])

    def test_flash_override_erased_subvid_subdid(self):
        """
        Tests FlashOverride
        Initial state: Flash erased
        Run with options: -i (SubVendor id, SubDevice id)
        Expected result: "Error: No valid NCB detected in FLASH!"
        """
        self.run_flash_erase()
        new_ids = "0xAAEE:0x0042"
        res = self.run_flash_override(ids=new_ids, check=False)
        assert any("Error: No valid NCB detected in FLASH!" in line for line in res["output"])

    def test_flash_override_erased_no_options(self):
        """
        Tests FlashOverride
        Initial state: Flash erased
        Run without options
        Expected result: "Error: No valid NCB detected in FLASH!"
        """
        self.run_flash_erase()
        res = self.run_flash_override(check=False)
        assert any("Error: No valid NCB detected in FLASH!" in line for line in res["output"])

    # # Flash contains FW
    def run_flash_override_with_fw(self, args):
        if not self.state.skip_reboot:
            self.state.skip_reboot = True
            self.state.update()

            try:
                self.run_flash_burn(clx_file=self.old_dut_clx_file)
                self.run_flash_override(**args)
            except Exception:
                self.state.skip_reboot = False
                self.state.update()
                raise

            self.cold_restart(host=self.dut_hostname)
        else:
            self.state.skip_reboot = False
            self.state.update()

        return self.run_readstat()

    def test_flash_override_with_fw_mac_subvid_subdid(self):
        """
        Tests FlashOverride
        Initial state: Flash contains FW
        Run with options: -m -i (SubVendor id, SubDevice id)
        Expected result: : Device id, SubVendor id, SubDevice id and mac address will be updated
        """

        new_mac = self.suggest_test_mac_address(self.dut_port, host=self.dut_hostname)
        new_ids = "0xAAEE:0x0042"
        stats = self.run_flash_override_with_fw({"mac": new_mac, "ids": new_ids})

        assert stats['subvid']['value'] == new_ids.split(':')[0]
        assert stats['subdid']['value'] == new_ids.split(':')[1]
        assert stats['mac']['value'] == new_mac

    def test_flash_override_with_fw_mac_did_subvid_subdid(self):
        """
        Tests FlashOverride
        Initial state: Flash contains FW
        Run with options: -m -i (Device id, SubVendor id, SubDevice id)
        Expected result: : Device id, SubVendor id, SubDevice id and mac address will be updated
        """

        new_mac = self.suggest_test_mac_address(self.dut_port, host=self.dut_hostname)
        new_ids = "0x87B1:0xAAEE:0x0042"
        stats = self.run_flash_override_with_fw({"mac": new_mac, "ids": new_ids})

        assert stats['device_id']['value'] == new_ids.split(':')[0]
        assert stats['subvid']['value'] == new_ids.split(':')[1]
        assert stats['subdid']['value'] == new_ids.split(':')[2]
        assert stats['mac']['value'] == new_mac

    def test_flash_override_with_fw_mac(self):
        """
        Tests FlashOverride
        Initial state: Flash contains FW
        Run with options: -m
        Expected result: : mac address will be updated
        """

        new_mac = self.suggest_test_mac_address(self.dut_port, host=self.dut_hostname)
        stats = self.run_flash_override_with_fw({"mac": new_mac})

        assert stats['mac']['value'] == new_mac

    def test_flash_override_with_fw_did_subvid_subdid(self):
        """
        Tests FlashOverride
        Initial state: Flash contains FW
        Run with options: -i (Device id, SubVendor id, SubDevice id)
        Expected result: : Device id, SubVendor id, SubDevice id will be updated
        """

        new_ids = "0x87B1:0xAAEE:0x0042"
        stats = self.run_flash_override_with_fw({"ids": new_ids})

        assert stats['device_id']['value'] == new_ids.split(':')[0]
        assert stats['subvid']['value'] == new_ids.split(':')[1]
        assert stats['subdid']['value'] == new_ids.split(':')[2]

    def test_flash_override_with_fw_subvid_subdid(self):
        """
        Tests FlashOverride
        Initial state: Flash contains FW
        Run with options: -i (SubVendor id, SubDevice id)
        Expected result: : Device id, SubVendor id, SubDevice id and mac address will be updated
        """

        new_ids = "0xAAEE:0x0042"
        stats = self.run_flash_override_with_fw({"ids": new_ids})

        assert stats['subvid']['value'] == new_ids.split(':')[0]
        assert stats['subdid']['value'] == new_ids.split(':')[1]

    def test_flash_override_with_fw_no_options(self):
        """
        Tests FlashOverride
        Initial state: Flash contains FW
        Run with no options
        Expected result: : nothing changes
        """
        vendor_id_default = 0x1D6A
        device_id_default = 0x07B1
        mac_default = "00:17:b6:00:00:00"

        stats = self.run_flash_override_with_fw({})

        assert int(stats['vendor_id']['value'], 16) == vendor_id_default
        assert int(stats['device_id']['value'], 16) == device_id_default
        assert stats['mac']['value'] == mac_default

    # flashBurn

    def run_flash_burn_test(self, erased, corrupted, clx_size, exp_success, no_crc=False):
        clx_size = int(clx_size)
        if erased:
            self.run_flash_erase()
        else:
            self.run_flash_burn(clx_file=self.old_dut_clx_file)

        crptd_clx = 'ncb0_corrupted.clx'
        cmd = "cp {} {}".format(self.new_dut_clx_file, crptd_clx)
        Command(cmd=cmd, host=self.dut_hostname).run()

        if corrupted:
            cmd = "dd if=/dev/zero of={} bs=1 count=20 seek=10 conv=notrunc".format(crptd_clx)
            Command(cmd=cmd, host=self.dut_hostname).run()

        crptd_resize_clx = 'trnc_{}_{}'.format(clx_size, crptd_clx)
        cmd = "dd if={} of={} bs=1K count={}".format(crptd_clx, crptd_resize_clx, clx_size)
        Command(cmd=cmd, host=self.dut_hostname).run()

        cmd = "dd if=/dev/zero of={} bs=1K count=0 seek={}".format(crptd_resize_clx, clx_size)
        Command(cmd=cmd, host=self.dut_hostname).run()

        self.run_flash_burn(clx_file=crptd_resize_clx, nocrc=no_crc, exp_success=exp_success)

    # # Flash erased

    # NCB0 corrupted
    def test_flash_burn_erased_corrupted_low_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=True, clx_size=1500, exp_success=False)

    def test_flash_burn_erased_corrupted_eq_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=True, clx_size=1024 * 2, exp_success=False)

    def test_flash_burn_erased_corrupted_more_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=True, clx_size=1024 * 2.5, exp_success=False)

    # NCB0 not corrupted
    def test_flash_burn_erased_not_corrupted_low_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=False, clx_size=1500, exp_success=True)

    def test_flash_burn_erased_not_corrupted_eq_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=False, clx_size=1024 * 2, exp_success=True)

    def test_flash_burn_erased_not_corrupted_more_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=False, clx_size=1024 * 2.5, exp_success=True)

    # # Flash contains FW

    # NCB0 corrupted
    def test_flash_burn_not_erased_corrupted_low_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=True, clx_size=1500, exp_success=False)

    def test_flash_burn_not_erased_corrupted_eq_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=True, clx_size=1024 * 2, exp_success=False)

    def test_flash_burn_not_erased_corrupted_more_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=True, clx_size=1024 * 2.5, exp_success=False)

    # NCB0 not corrupted
    def test_flash_burn_not_erased_not_corrupted_low_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=False, clx_size=1500, exp_success=True)

    def test_flash_burn_not_erased_not_corrupted_eq_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=False, clx_size=1024 * 2, exp_success=True)

    def test_flash_burn_not_erased_not_corrupted_more_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=False, clx_size=1024 * 2.5, exp_success=True)

    # # # No CRC

    # # Flash erased

    # NCB0 corrupted
    def test_flash_burn_erased_corrupted_nocrc_low_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=True, clx_size=1500, exp_success=True, no_crc=True)

    def test_flash_burn_erased_corrupted_nocrc_eq_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=True, clx_size=1024 * 2, exp_success=True, no_crc=True)

    def test_flash_burn_erased_corrupted_nocrc_more_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=True, clx_size=1024 * 2.5, exp_success=True, no_crc=True)

    # NCB0 not corrupted
    def test_flash_burn_erased_not_corrupted_nocrc_low_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=False, clx_size=1500, exp_success=True, no_crc=True)

    def test_flash_burn_erased_not_corrupted_nocrc_eq_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=False, clx_size=1024 * 2, exp_success=True, no_crc=True)

    def test_flash_burn_erased_not_corrupted_nocrc_more_2mb(self):
        self.run_flash_burn_test(erased=True, corrupted=False, clx_size=1024 * 2.5, exp_success=True, no_crc=True)

    # # Flash contains FW

    # NCB0 corrupted
    def test_flash_burn_not_erased_corrupted_nocrc_low_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=True, clx_size=1500, exp_success=True, no_crc=True)

    def test_flash_burn_not_erased_corrupted_nocrc_eq_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=True, clx_size=1024 * 2, exp_success=True, no_crc=True)

    def test_flash_burn_not_erased_corrupted_nocrc_more_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=True, clx_size=1024 * 2.5, exp_success=True, no_crc=True)

    # NCB0 not corrupted
    def test_flash_burn_not_erased_not_corrupted_nocrc_low_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=False, clx_size=1500, exp_success=True, no_crc=True)

    def test_flash_burn_not_erased_not_corrupted_nocrc_eq_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=False, clx_size=1024 * 2, exp_success=True, no_crc=True)

    def test_flash_burn_not_erased_not_corrupted_nocrc_more_2mb(self):
        self.run_flash_burn_test(erased=False, corrupted=False, clx_size=1024 * 2.5, exp_success=True, no_crc=True)

    # flashUpdadte

    MAC_IRAM_POINTER = 0x2c, 3
    PHY_IRAM_POINTER = 0x40, 3
    PCI_ROM_POINTER = 0x54, 3
    PCI_CFG_POINTER = 0x24, 2

    def corrupt_clx(self, clx_file, ncb_num, ptr, shift_offset=0):
        ptr_addr = ptr[0]
        ptr_size = ptr[1]

        if ncb_num == 1:
            ptr_addr += 0x4000

        # Read Pointer
        cmd = "xxd -s {} -l {} -e {} | awk '{{print $2}}'".format(ptr_addr, ptr_size, clx_file)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        offset = int(res["output"][0], 16)
        offset += shift_offset

        # Corrupt block
        crptd_clx = 'ncb{}_block_0x{:02x}_corrupted.clx'.format(ncb_num, ptr_addr)
        cmd = "cp {} {}".format(clx_file, crptd_clx)
        Command(cmd=cmd, host=self.dut_hostname).run()
        # cmd = "dd if=/dev/urandom of={} bs=1 count=20 seek={} conv=notrunc".format(crptd_clx, offset)
        cmd = "tr '\\0' '\\377' < /dev/zero | dd of={} bs=1 count=20 seek={} conv=notrunc".format(crptd_clx, offset)
        Command(cmd=cmd, host=self.dut_hostname).run()

        return crptd_clx

    # Corrupted NCB0
    def test_flash_update_corrupted_mac_fw_ncb0_bdp_on(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.MAC_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=True)

        assert all([
            any("Error: MAC FW 0 is corrupted" in line for line in res["output"]),
            any("Using NCB1 from CLX image" in line for line in res["output"]),
            any("Updating BDP in FLASH from CLX image" in line for line in res["output"]),
        ])

    def test_flash_update_corrupted_mac_fw_ncb0_bdp_off(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.MAC_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=False)

        assert all([
            any("Error: MAC FW 0 is corrupted" in line for line in res["output"]),
            any("Using NCB1 from CLX image" in line for line in res["output"]),
            all("Updating BDP in FLASH from CLX image" not in line for line in res["output"]),
        ])

    def test_flash_update_corrupted_phy_fw_ncb0_bdp_on(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PHY_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=True)

        assert all([
            any("Error: PHY FW 0 is corrupted" in line for line in res["output"]),
            any("Using NCB1 from CLX image" in line for line in res["output"]),
            any("Updating BDP in FLASH from CLX image" in line for line in res["output"]),
        ])

    def test_flash_update_corrupted_phy_fw_ncb0_bdp_off(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PHY_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=False)

        assert all([
            any("Error: PHY FW 0 is corrupted" in line for line in res["output"]),
            any("Using NCB1 from CLX image" in line for line in res["output"]),
            all("Updating BDP in FLASH from CLX image" not in line for line in res["output"]),
        ])

    def test_flash_update_corrupted_pci_rom_ncb0_bdp_on(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PCI_ROM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=True)

        assert all([
            any("Error: PCI Option ROM 0 is corrupted" in line for line in res["output"]),
            any("Using NCB1 from CLX image" in line for line in res["output"]),
            any("Updating BDP in FLASH from CLX image" in line for line in res["output"]),
        ])

    def test_flash_update_corrupted_pci_rom_ncb0_bdp_off(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PCI_ROM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=False)

        assert all([
            any("Error: PCI Option ROM 0 is corrupted" in line for line in res["output"]),
            any("Using NCB1 from CLX image" in line for line in res["output"]),
            all("Updating BDP in FLASH from CLX image" not in line for line in res["output"]),
        ])

    # Corrupted NCB1
    @pytest.mark.xfail(reason="There are no messages about NCB1")
    def test_flash_update_corrupted_mac_fw_ncb1_bdp_on(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.MAC_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=True)

        assert all([
            any("Error: MAC FW 1 is corrupted" in line for line in res["output"]),
            any("Using NCB0 from CLX image" in line for line in res["output"]),
            any("Updating BDP in FLASH from CLX image" in line for line in res["output"]),
        ])

    @pytest.mark.xfail(reason="There are no messages about NCB1")
    def test_flash_update_corrupted_mac_fw_ncb1_bdp_off(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.MAC_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=False)

        assert all([
            any("Error: MAC FW 1 is corrupted" in line for line in res["output"]),
            any("Using NCB0 from CLX image" in line for line in res["output"]),
            all("Updating BDP in FLASH from CLX image" not in line for line in res["output"]),
        ])

    @pytest.mark.xfail(reason="There are no messages about NCB1")
    def test_flash_update_corrupted_phy_fw_ncb1_bdp_on(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.PHY_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=True)

        assert all([
            any("Error: PHY FW 1 is corrupted" in line for line in res["output"]),
            any("Using NCB0 from CLX image" in line for line in res["output"]),
            any("Updating BDP in FLASH from CLX image" in line for line in res["output"]),
        ])

    @pytest.mark.xfail(reason="There are no messages about NCB1")
    def test_flash_update_corrupted_phy_fw_ncb1_bdp_off(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.PHY_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=False)

        assert all([
            any("Error: PHY FW 1 is corrupted" in line for line in res["output"]),
            any("Using NCB0 from CLX image" in line for line in res["output"]),
            all("Updating BDP in FLASH from CLX image" not in line for line in res["output"]),
        ])

    @pytest.mark.xfail(reason="There are no messages about NCB1")
    def test_flash_update_corrupted_pci_rom_ncb1_bdp_on(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.PCI_ROM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=True)

        assert all([
            any("Error: PCI Option ROM 1 is corrupted" in line for line in res["output"]),
            any("Using NCB0 from CLX image" in line for line in res["output"]),
            any("Updating BDP in FLASH from CLX image" in line for line in res["output"]),
        ])

    @pytest.mark.xfail(reason="There are no messages about NCB1")
    def test_flash_update_corrupted_pci_rom_ncb1_bdp_off(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.PCI_ROM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=False)

        assert all([
            any("Error: PCI Option ROM 1 is corrupted" in line for line in res["output"]),
            any("Using NCB0 from CLX image" in line for line in res["output"]),
            all("Updating BDP in FLASH from CLX image" not in line for line in res["output"]),
        ])

    # Corrupted NCB0 and NCB1
    def test_flash_update_corrupted_mac_fw_ncb0_ncb1_bdp_on(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.MAC_IRAM_POINTER)
        crptd_clx = self.corrupt_clx(crptd_clx, ncb_num=1, ptr=self.MAC_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=True)

        assert all([
            any("Error: MAC FW 0 is corrupted" in line for line in res["output"]),
            any("Error: MAC FW 1 is corrupted" in line for line in res["output"]),
            any("Error: Can't update FW, CLX image is corrupted" in line for line in res["output"]),
        ])

    def test_flash_update_corrupted_mac_fw_ncb0_ncb1_bdp_off(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.MAC_IRAM_POINTER)
        crptd_clx = self.corrupt_clx(crptd_clx, ncb_num=1, ptr=self.MAC_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=False)

        assert all([
            any("Error: MAC FW 0 is corrupted" in line for line in res["output"]),
            any("Error: MAC FW 1 is corrupted" in line for line in res["output"]),
            any("Error: Can't update FW, CLX image is corrupted" in line for line in res["output"]),
        ])

    def test_flash_update_corrupted_phy_fw_ncb0_ncb1_bdp_on(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PHY_IRAM_POINTER)
        crptd_clx = self.corrupt_clx(crptd_clx, ncb_num=1, ptr=self.PHY_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=True)

        assert all([
            any("Error: PHY FW 0 is corrupted" in line for line in res["output"]),
            any("Error: PHY FW 1 is corrupted" in line for line in res["output"]),
            any("Error: Can't update FW, CLX image is corrupted" in line for line in res["output"]),
        ])

    def test_flash_update_corrupted_phy_fw_ncb0_ncb1_bdp_off(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PHY_IRAM_POINTER)
        crptd_clx = self.corrupt_clx(crptd_clx, ncb_num=1, ptr=self.PHY_IRAM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=False)

        assert all([
            any("Error: PHY FW 0 is corrupted" in line for line in res["output"]),
            any("Error: PHY FW 1 is corrupted" in line for line in res["output"]),
            any("Error: Can't update FW, CLX image is corrupted" in line for line in res["output"]),
        ])

    def test_flash_update_corrupted_pci_rom_ncb0_ncb1_bdp_on(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PCI_ROM_POINTER)
        crptd_clx = self.corrupt_clx(crptd_clx, ncb_num=1, ptr=self.PCI_ROM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=True)

        assert all([
            any("Error: PCI Option ROM 0 is corrupted" in line for line in res["output"]),
            any("Error: PCI Option ROM 1 is corrupted" in line for line in res["output"]),
            any("Error: Can't update FW, CLX image is corrupted" in line for line in res["output"]),
        ])

    def test_flash_update_corrupted_pci_rom_ncb0_ncb1_bdp_off(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PCI_ROM_POINTER)
        crptd_clx = self.corrupt_clx(crptd_clx, ncb_num=1, ptr=self.PCI_ROM_POINTER)
        res = self.run_flash_update(clx_file=crptd_clx, bdp=False)

        assert all([
            any("Error: PCI Option ROM 0 is corrupted" in line for line in res["output"]),
            any("Error: PCI Option ROM 1 is corrupted" in line for line in res["output"]),
            any("Error: Can't update FW, CLX image is corrupted" in line for line in res["output"]),
        ])

    # NCB0 and NCB1 is not corrupted
    def test_flash_update_not_corrupted_bdp_on(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        res = self.run_flash_update(clx_file=self.new_dut_clx_file, bdp=True)

        assert all([
            any("Updating BDP in FLASH from CLX image" in line for line in res["output"]),
            any("Flash update finished" in line for line in res["output"]),
        ])

    def test_flash_update_not_corrupted_bdp_off(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        res = self.run_flash_update(clx_file=self.new_dut_clx_file, bdp=False)

        assert any("Flash update finished" in line for line in res["output"])

    # Kickstart

    def test_kickstart_normal_fw_with_phy(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        res = self.run_kickstart(phy=True)

        assert all([
            any("Kickstarting MAC" in line for line in res["output"]),
            any("Kickstarting PHY" in line for line in res["output"]),
            any("Kickstart is done" in line for line in res["output"]),
        ])

    def test_kickstart_normal_fw_without_phy(self):
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        res = self.run_kickstart(phy=False)

        assert all([
            any("Kickstarting MAC" in line for line in res["output"]),
            any("Kickstart is done" in line for line in res["output"]),
        ])

    def test_kickstart_erased_fw_with_phy(self):
        self.run_flash_erase()
        res = self.run_kickstart(phy=True)

        assert any("Error: MAC kickstart failed" in line for line in res["output"])

    def test_kickstart_erased_fw_without_phy(self):
        self.run_flash_erase()
        res = self.run_kickstart(phy=False)

        assert any("Error: MAC kickstart failed" in line for line in res["output"])

    def flash_corrupted_clx(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PHY_IRAM_POINTER)
        crptd_clx = self.corrupt_clx(crptd_clx, ncb_num=1, ptr=self.PHY_IRAM_POINTER)
        self.run_flash_burn(clx_file=crptd_clx, nocrc=True)

    def test_kickstart_corrupted_fw_with_phy(self):
        self.flash_corrupted_clx()
        res = self.run_kickstart(phy=True)

        assert any("Error: PHY kickstart failed" in line or
                   "Error: FW restart failed" in line
                   for line in res["output"])

    def test_kickstart_corrupted_fw_without_phy(self):
        self.flash_corrupted_clx()
        res = self.run_kickstart(phy=False)

        assert any("Error: FW restart failed" in line for line in res["output"])

    # flashErase

    def test_flash_erase(self):
        dump_file = "flash_dump.bin"
        self.run_flash_erase()
        self.run_flash_dump(out_file=dump_file)
        res = Command(cmd="xxd {}".format(dump_file), host=self.dut_hostname, silent=True).run()
        assert all(re.match("[0-9a-f]+:(\sf{4}){8}\s+\.+", line) for line in res["output"])

    # flashDump

    def test_flash_dump(self):
        dump_file = "flash_dump.bin"
        self.run_flash_burn(clx_file=self.old_dut_clx_file)
        self.run_flash_dump(out_file=dump_file)

        cmd = "sudo dd if=/dev/zero of={} bs=1K count=0 seek={}".format(dump_file, 2048)
        Command(cmd=cmd, host=self.dut_hostname).run()

        cmd = "md5sum {}".format(self.old_dut_clx_file)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        clx_md5 = res["output"][0].split(" ")[0]

        cmd = "md5sum {}".format(dump_file)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        dump_md5 = res["output"][0].split(" ")[0]

        assert clx_md5 == dump_md5

    # readstat

    def run_readstat_test(self, fw_loaded=False, driver_loaded=False):
        if self.dut_ops.is_windows() and not driver_loaded:
            log.info("Can't run readstat with unloaded driver on Windows.")
            pytest.skip()

        if not self.state.skip_reboot:
            self.state.skip_reboot = True
            self.state.update()

            try:
                if fw_loaded:
                    self.run_flash_burn(clx_file=self.old_dut_clx_file)
                else:
                    self.run_flash_erase()
            except Exception:
                self.state.skip_reboot = False
                self.state.update()
                raise
            self.cold_restart(host=self.dut_hostname)
        else:
            if driver_loaded:
                if self.dut_ops.is_windows():
                    self.dut_diag_driver.install()
                else:
                    self.dut_driver.install()
            else:
                self.dut_driver.uninstall()

            self.state.skip_reboot = False
            self.state.update()

        return self.run_readstat()

    def test_readstat_fw_loaded_driver_loaded(self):
        stats = self.run_readstat_test(fw_loaded=True, driver_loaded=True)
        assert stats["fw_version"]['value'] == self.old_dut_fw_actual_version

    def test_readstat_fw_unloaded_driver_loaded(self):
        stats = self.run_readstat_test(fw_loaded=False, driver_loaded=True)
        assert stats["fw_version"]['value'] != self.old_dut_fw_actual_version

    def test_readstat_fw_loaded_driver_unloaded(self):
        stats = self.run_readstat_test(fw_loaded=True, driver_loaded=False)
        assert stats["fw_version"]['value'] == self.old_dut_fw_actual_version

    def test_readstat_fw_unloaded_driver_unloaded(self):
        try:
            if self.dut_ops.is_linux():
                self.dut_driver.add_blacklist('atlantic')

            stats = self.run_readstat_test(fw_loaded=False, driver_loaded=False)
            assert stats["fw_version"]['value'] != self.old_dut_fw_actual_version

        except Exception:
            if self.dut_ops.is_linux():
                self.dut_driver.remove_blacklist('atlantic')
            raise

    # clxoverride

    def run_clxoverride(self, clx_file, silent=False, info=False, update=False, ncb=0, mac=None, ids=None, status=None,
                        lanes=None, pcirom=None):
        cmd = "sudo {}/clxoverride {}".format(self.fwtools_local, clx_file)
        if info:
            cmd += " -i"
        elif update:
            cmd += " -u"
        elif mac is not None:
            cmd += " --mac{} {}".format(ncb, mac)
        elif ids is not None:
            cmd += " --id{} {}".format(ncb, ids)
        elif status is not None:
            cmd += " --ncb{} {}".format(ncb, int(status))
        elif lanes is not None:
            cmd += " --lanes{} {}".format(ncb, lanes)
        elif pcirom is not None:
            cmd += " --pcirom{} {}".format(ncb, int(pcirom))
        res = Command(cmd=cmd, host=self.dut_hostname, silent=silent).run()

        return res

    def get_clx_crc_status(self, clx_file):
        status = [
            {
                "NCB": None,
                "PCI_CFG": None,
                "MAC_FW": None,
                "PHY_FW": None,
                "ROM": None,
            },
            {
                "NCB": None,
                "PCI_CFG": None,
                "MAC_FW": None,
                "PHY_FW": None,
                "ROM": None,
            }
        ]

        ncb_checks = {
            "NCB": ".*NCB CRC = 0x[0-9A-Z]+, Calculated NCB CRC = 0x[0-9A-Z]+ - (ERROR|OK)",
            "PCI_CFG": ".*PCI CFG CRC = 0x[0-9A-Z]+, Calculated PCI CFG CRC = 0x[0-9A-Z]+ - (ERROR|OK)",
            "MAC_FW": ".*MAC FW CRC = 0x[0-9A-Z]+, Calculated MAC FW CRC = 0x[0-9A-Z]+ - (ERROR|OK)",
            "PHY_FW": ".*PHY FW CRC = 0x[0-9A-Z]+, Calculated PHY FW CRC = 0x[0-9A-Z]+ - (ERROR|OK)",
            "ROM": ".*Option ROM CRC = 0x[0-9A-Z]+, Calculated Option ROM CRC = 0x[0-9A-Z]+ - (ERROR|OK)",
        }

        ncb_no = None
        res = self.run_clxoverride(clx_file, info=True, silent=False)
        for line in res["output"]:
            if "NCB0 (offset 0x0)" in line:
                ncb_no = 0
            if "NCB1 (offset 0x4000)" in line:
                ncb_no = 1

            for check, re_str in ncb_checks.items():
                m = re.match(re_str, line)
                if m is not None:
                    status[ncb_no][check] = m.group(1)

        # DEBUG
        log.info("Status:")
        for ncb_no in range(2):
            log.info("NCB{} ==================================================".format(ncb_no))
            for check, re_str in status[ncb_no].items():
                log.info("{}: {}".format(check, re_str))

        return status

    def run_clxoverride_mac(self, ncb):
        new_mac = "00:17:b6:1a:2b:3c"
        new_clx = "overrride_mac_ncb{}.clx".format(ncb)
        self.check_and_install_diag_drv()
        if not self.state.skip_reboot:
            self.state.skip_reboot = True
            self.state.update()

            try:
                Command(cmd="cp {} {}".format(self.new_dut_clx_file, new_clx), host=self.dut_hostname).run()
                self.run_clxoverride(new_clx, ncb=ncb, mac=new_mac)
                self.run_clxoverride(new_clx, status=False, ncb=1 if ncb == 0 else 0)
                self.run_flash_burn(clx_file=new_clx)
            except Exception:
                self.state.skip_reboot = False
                self.state.update()
                raise

            self.cold_restart(host=self.dut_hostname)
        else:
            self.state.skip_reboot = False
            self.state.update()

        res_mac = self.dut_atltool_wrapper.get_mac_address()
        assert new_mac == res_mac

    def test_clxoverride_mac_ncb0(self):
        self.run_clxoverride_mac(ncb=0)

    def test_clxoverride_mac_ncb1(self):
        self.run_clxoverride_mac(ncb=1)

    def run_clxoverride_ids(self, ncb):
        stats = self.run_readstat()

        vendor_id = "{:x}".format(int(stats["vendor_id"]["value"], 16))
        device_id = "{:x}".format(int(stats["device_id"]["value"], 16))
        sub_vendor_id = "1daa"
        sub_device_id = "0042"

        new_ids = "{}:{}:{}:{}".format(vendor_id, device_id, sub_vendor_id, sub_device_id)
        new_clx = "overrride_mac_ncb{}.clx".format(ncb)
        self.check_and_install_diag_drv()
        if not self.state.skip_reboot:
            self.state.skip_reboot = True
            self.state.update()

            try:
                Command(cmd="cp {} {}".format(self.new_dut_clx_file, new_clx), host=self.dut_hostname).run()
                self.run_clxoverride(new_clx, ncb=ncb, ids=new_ids)
                self.run_clxoverride(new_clx, status=False, ncb=1 if ncb == 0 else 0)
                self.run_flash_burn(clx_file=new_clx)
            except Exception:
                self.state.skip_reboot = False
                self.state.update()
                raise

            self.cold_restart(host=self.dut_hostname)
        else:
            self.state.skip_reboot = False
            self.state.update()

        stats = self.run_readstat()
        assert all([
            int(sub_vendor_id, 16) == int(stats["subvid"]['value'], 16),
            int(sub_device_id, 16) == int(stats["subdid"]['value'], 16)
        ])

    def test_clxoverride_ids_ncb0(self):
        self.run_clxoverride_ids(ncb=0)

    def test_clxoverride_ids_ncb1(self):
        self.run_clxoverride_ids(ncb=1)

    def restore_state(self):
        self.state.test_cleanup_cold_restart = False
        self.state.skip_reboot = False
        self.state.update()

    def run_clxoverride_lanes(self, ncb, new_lanes):
        if not self.state.test_cleanup_cold_restart:
            self.state.test_cleanup_cold_restart = True
            self.state.update()
            self.run_flash_burn(clx_file=self.old_dut_clx_file)
            self.cold_restart(host=self.dut_hostname)

        stats = self.run_readstat()
        stat_lanes = int(stats["lanes"]["value"])
        self.check_and_install_diag_drv()
        if not self.state.skip_reboot:
            self.state.skip_reboot = True
            self.state.update()

            try:
                if new_lanes > stat_lanes:
                    self.restore_state()
                    pytest.skip()

                new_clx = "override_lanes{}_ncb{}.clx".format(new_lanes, ncb)
                Command(cmd="cp {} {}".format(self.new_dut_clx_file, new_clx), host=self.dut_hostname).run()
                self.run_clxoverride(new_clx, ncb=ncb, lanes=new_lanes)
                self.run_clxoverride(new_clx, status=False, ncb=1 if ncb == 0 else 0)
                self.run_flash_burn(clx_file=new_clx)
            except Exception:
                self.restore_state()
                raise

            self.cold_restart(host=self.dut_hostname)
        else:
            self.restore_state()

        assert stat_lanes == new_lanes

    @pytest.mark.xfail()
    def test_clxoverride_lanes_1_ncb0(self):
        self.run_clxoverride_lanes(ncb=0, new_lanes=1)

    def test_clxoverride_lanes_2_ncb0(self):
        self.run_clxoverride_lanes(ncb=0, new_lanes=2)

    def test_clxoverride_lanes_4_ncb0(self):
        self.run_clxoverride_lanes(ncb=0, new_lanes=4)

    @pytest.mark.xfail()
    def test_clxoverride_lanes_1_ncb1(self):
        self.run_clxoverride_lanes(ncb=1, new_lanes=1)

    def test_clxoverride_lanes_2_ncb1(self):
        self.run_clxoverride_lanes(ncb=1, new_lanes=2)

    def test_clxoverride_lanes_4_ncb1(self):
        self.run_clxoverride_lanes(ncb=1, new_lanes=4)

    def run_clxoverride_pcirom(self, ncb):
        if not self.dut_ops.is_linux():
            pytest.skip()

        new_clx = "overrride_pcirom_ncb{}.clx".format(ncb)
        domain, bus, dev, func = get_domain_bus_dev_func(self.dut_port)
        bus_address = '{:04x}:{:02x}:{:02x}.{:01x}'.format(domain, bus, dev, func)

        if not self.state.test_cleanup_cold_restart:
            self.state.test_cleanup_cold_restart = True
            self.state.update()

            Command(cmd="cp {} {}".format(self.new_dut_clx_file, new_clx), host=self.dut_hostname).run()
            self.run_clxoverride(new_clx, ncb=ncb, pcirom=False)
            self.run_clxoverride(new_clx, status=False, ncb=1 if ncb == 0 else 0)
            self.run_flash_burn(clx_file=new_clx)

            self.cold_restart(host=self.dut_hostname)

        res = Command(cmd="sudo lshw -c network", host=self.dut_hostname).run()
        pci_bus = ""
        capabilities = ""
        for line in res["output"]:
            if "bus info" in line:
                pci_bus = line
                continue
            if bus_address in pci_bus and "capabilities" in line:
                capabilities = line

        if not self.state.skip_reboot:
            self.state.skip_reboot = True
            self.state.update()

            try:

                assert "rom" not in capabilities.split()

                Command(cmd="cp {} {}".format(self.new_dut_clx_file, new_clx), host=self.dut_hostname).run()
                self.run_clxoverride(new_clx, ncb=ncb, pcirom=True)
                self.run_clxoverride(new_clx, status=False, ncb=1 if ncb == 0 else 0)
                self.run_flash_burn(clx_file=new_clx)

            except Exception:
                self.restore_state()
                raise

            self.cold_restart(host=self.dut_hostname)
        else:
            self.restore_state()

        assert "rom" in capabilities.split()

    def test_clxoverride_pcirom_disable_ncb0(self):
        self.run_clxoverride_pcirom(0)

    def test_clxoverride_pcirom_disable_ncb1(self):
        self.run_clxoverride_pcirom(1)

    # NCB0

    def test_clxoverride_crc_check_mac_fw_ncb0_wo_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.MAC_IRAM_POINTER)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[0]["MAC_FW"] == "ERROR"

    def test_clxoverride_crc_check_mac_fw_ncb0_with_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.MAC_IRAM_POINTER)
        self.run_clxoverride(crptd_clx, update=True)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[0]["MAC_FW"] == "OK"

    def test_clxoverride_crc_check_phy_fw_ncb0_wo_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PHY_IRAM_POINTER)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[0]["PHY_FW"] == "ERROR"

    def test_clxoverride_crc_check_phy_fw_ncb0_with_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PHY_IRAM_POINTER)
        self.run_clxoverride(crptd_clx, update=True)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[0]["PHY_FW"] == "OK"

    def test_clxoverride_crc_check_pci_rom_ncb0_wo_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PCI_ROM_POINTER)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[0]["ROM"] == "ERROR"

    def test_clxoverride_crc_check_pci_rom_ncb0_with_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PCI_ROM_POINTER)
        self.run_clxoverride(crptd_clx, update=True)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[0]["ROM"] == "OK"

    def test_clxoverride_crc_check_pci_cfg_ncb0_wo_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PCI_CFG_POINTER, shift_offset=16)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[0]["NCB"] == "ERROR"
        assert status[0]["PCI_CFG"] == "ERROR"

    def test_clxoverride_crc_check_pci_cfg_ncb0_with_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PCI_CFG_POINTER, shift_offset=16)
        self.run_clxoverride(crptd_clx, update=True)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[0]["PCI_CFG"] == "OK"

    # NCB1

    def test_clxoverride_crc_check_mac_fw_ncb1_wo_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.MAC_IRAM_POINTER)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[1]["MAC_FW"] == "ERROR"

    def test_clxoverride_crc_check_mac_fw_ncb1_with_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.MAC_IRAM_POINTER)
        self.run_clxoverride(crptd_clx, update=True)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[1]["MAC_FW"] == "OK"

    def test_clxoverride_crc_check_phy_fw_ncb1_wo_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.PHY_IRAM_POINTER)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[1]["PHY_FW"] == "ERROR"

    def test_clxoverride_crc_check_phy_fw_ncb1_with_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.PHY_IRAM_POINTER)
        self.run_clxoverride(crptd_clx, update=True)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[1]["PHY_FW"] == "OK"

    def test_clxoverride_crc_check_pci_rom_ncb1_wo_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.PCI_ROM_POINTER)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[1]["ROM"] == "ERROR"

    def test_clxoverride_crc_check_pci_rom_ncb1_with_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.PCI_ROM_POINTER)
        self.run_clxoverride(crptd_clx, update=True)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[1]["ROM"] == "OK"

    def test_clxoverride_crc_check_pci_cfg_ncb1_wo_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.PCI_CFG_POINTER, shift_offset=16)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[1]["NCB"] == "ERROR"
        assert status[1]["PCI_CFG"] == "ERROR"

    def test_clxoverride_crc_check_pci_cfg_ncb1_with_update(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=1, ptr=self.PCI_CFG_POINTER, shift_offset=16)
        self.run_clxoverride(crptd_clx, update=True)
        status = self.get_clx_crc_status(crptd_clx)

        assert status[1]["PCI_CFG"] == "OK"

    # PCI config checks

    def test_clxoverride_pci_cfg_wrong_size(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PCI_CFG_POINTER, shift_offset=0)
        res = self.run_clxoverride(crptd_clx, update=True, silent=False)

        for line in res["output"]:
            m = re.match("Error: numDwords \(\d+\) doesn't match PCI Config \d+ size \(\d+\)", line)
            if m is not None:
                break
        else:
            raise Exception("PCI config size check is failed")

    def test_clxoverride_pci_cfg_valid_marker(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PCI_CFG_POINTER, shift_offset=4)
        res = self.run_clxoverride(crptd_clx, update=True, silent=False)

        for line in res["output"]:
            if "Error: Wrong Valid Marker in PCI config in NCB0" in line:
                break
        else:
            raise Exception("PCI config valid marker check is failed")

    def test_clxoverride_pci_cfg_class_code(self):
        crptd_clx = self.corrupt_clx(self.new_dut_clx_file, ncb_num=0, ptr=self.PCI_CFG_POINTER, shift_offset=12)
        res = self.run_clxoverride(crptd_clx, update=True, silent=False)

        for line in res["output"]:
            if "Error: Wrong Class Code or Rev ID in PCI config in NCB0" in line:
                break
        else:
            raise Exception("PCI config Class Code check is failed")

    # Disable NCB

    def run_clxoverride_activ_ncb(self, ncb):
        new_clx = "overrride_ncb{}.clx".format(ncb)
        Command(cmd="cp {} {}".format(self.new_dut_clx_file, new_clx), host=self.dut_hostname).run()

        re_val = re.compile("\s*\d+:\s*([a-z0-9]+)", flags=re.IGNORECASE)

        def read_state():
            fl_offset = '0x3' if ncb == 0 else '0x4003'
            cmd = "xxd -s {} -l 1 -e {}".format(fl_offset, new_clx)
            res = Command(cmd=cmd, host=self.dut_hostname).run()
            return int(re_val.match(res["output"][0]).group(1), 16) >> 6

        try:
            self.run_clxoverride(new_clx, ncb=ncb, status=False)
            assert read_state() == 0

            self.run_clxoverride(new_clx, ncb=ncb, status=True)
            assert read_state() == 2
        finally:
            Command(cmd='rm {}'.format(new_clx), host=self.dut_hostname).run()

    def test_clxoverride_disable_enable_ncb0(self):
        self.run_clxoverride_activ_ncb(ncb=0)

    def test_clxoverride_disable_enable_ncb1(self):
        self.run_clxoverride_activ_ncb(ncb=1)


class TestAtltool(TestBase):
    @classmethod
    def setup_class(cls):
        # TODO: dirty hack for beaglebone, remove it
        if "LKP_HOSTNAME" in os.environ:
            os.environ.pop("LKP_HOSTNAME")

        super(TestAtltool, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.bb_name = os.environ.get("BB_NAME", None)
            cls.t6_name = os.environ.get("T6_NAME", None)
            cls.t6_port = os.environ.get("T6_PORT", None)

            if cls.bb_name is not None:
                cls.dut_iface_name = cls.bb_name
            elif cls.t6_name is not None:
                if cls.dut_ops.is_windows():
                    cls.t6_driver = Driver(port=cls.t6_port, drv_type=DRV_TYPE_T6, version="latest")
                    cls.t6_driver.install()
                elif cls.dut_ops.is_linux():
                    Command(cmd="sudo rmmod ftdi_sio", host=cls.dut_hostname).run()
                    Command(cmd="sudo rmmod usbserial", host=cls.dut_hostname).run()
                cls.dut_iface_name = cls.t6_name
            else:
                cls.dut_iface_name = get_lspci_port(cls.dut_port)

            cls.phy_only = False  # Skip MAC tests
            cls.mac_only = False  # Skip PHY tests
            if cls.dut_fw_card in FELICITY_CARDS:
                if 'MDIO' in cls.dut_iface_name:
                    cls.phy_only = True
                else:
                    cls.mac_only = True
            # T6 -> PHY: MDIO
            # T6 -> MAC: I2C

            cls.skip_lkp_fw_install = True
            cls.install_firmwares()
            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.dut_driver.install()

            if not cls.phy_only:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)

            cls.fwtools_local = tempfile.mkdtemp()
            download_fwtools(host=cls.dut_hostname, fwtools_local=cls.fwtools_local)

        except Exception:
            log.exception("Failed while setting up class")
            raise

    def run_atltool(self, option, addr=None, val=None):
        """
        -rr (REG | REG1:REG2)                    Read MAC registers.
        -wr (REG | REG1:REG2) VALUE              Write MAC registers.
        -rpr (MMD.REG | MMD.REG1:MMD.REG2)       Read PHY registers.
        -wpr (MMD.REG | MMD.REG1:MMD.REG2) VALUE Write PHY register.
        -rm ADDR [SIZE]                          Read MCP memory from address ADDR. Default SIZE=4.
        -rpm ADDR [SIZE]                         Read PHY memory from address ADDR. Default SIZE=4.
        -rmsm (REG | REG1:REG2)                  Read MSM registers.
        -wmsm (REG | REG1:REG2) VALUE            Write MSM registers.
        -msm                                     Dump MSM counters.
        -rnwl (REG | REG1:REG2)                  Read NWL register.
        -wnwl (REG | REG1:REG2) VALUE            Write NWL register.
        """

        option_dict = {
            "rr": " -rr {addr}",
            "wr": " -wr {addr} {val}",
            "rpr": " -rpr {addr}",
            "wpr": " -wpr {addr} {val}",
            "rm": " -rm {addr} {val}",
            "rpm": " -rpm {addr} {val}",
            "rmsm": " -rmsm {addr}",
            "wmsm": " -wmsm {addr} {val}",
            "msm": " -msm",
            "rnwl": " -rnwl {addr}",
            "wnwl": " -rnwl {addr} {val}",
        }

        assert option in option_dict.keys()

        cmd = "sudo {}/atltool -d {}".format(self.fwtools_local, self.dut_iface_name)
        cmd += option_dict[option].format(addr=addr, val=val)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        assert res["returncode"] == 0, "Couldn't run atltool"

        re_mac_readreg = re.compile(r".*Register 0x[a-z0-9]+: (0x[a-z0-9]+) : [01\s]+")
        re_phy_readreg = re.compile(r".*Register PHY \d 0x[0-9a-z.]+: (0x[0-9a-z.]+) : [01]+ [01]+")
        re_mem = re.compile(".*Memory at 0x[a-z0-9]+: \[((0x[a-z0-9]+,?\s?)+)\]")
        re_phymem = re.compile(".*0x[A-Z0-9]+: 0x([A-Z0-9]+)")
        re_rmsm = re.compile(r".*Register MSM 0x[a-z0-9]+: (0x[a-z0-9]+) : [01\s]+")
        re_rnwl = re.compile(r"Register NWL 0x[0-9a-f]+: (0x[0-9a-f]+)")

        mac_opts = ["rr", "wr"]
        phy_opts = ["rpr", "wpr"]

        if option in mac_opts + phy_opts and val is None:
            re_readreg = re_mac_readreg if option in mac_opts else re_phy_readreg

            read_vals = []
            for line in res["output"]:
                m = re_readreg.match(line)
                if m is not None:
                    read_vals.append(int(m.group(1), 16))

            return read_vals

        elif option == "rm":
            read_vals = []
            for line in res["output"]:
                m = re_mem.match(line)
                if m is not None:
                    read_vals = map(lambda v: int(v, 16), m.group(1).split(","))

            return read_vals

        elif option == "rpm":
            read_vals = []
            for line in res["output"]:
                m = re_phymem.match(line)
                if m is not None:
                    s1 = m.group(1)
                    l = len(s1)
                    s2 = ''.join(s1[l - (i + 2):l - i] for i in range(0, l, 2))
                    read_vals.append(int(s2, 16))

            return read_vals

        elif option == "rmsm":
            read_vals = []
            for line in res["output"]:
                m = re_rmsm.match(line)
                if m is not None:
                    read_vals.append(int(m.group(1), 16))

            return read_vals

        elif option == "rnwl":
            read_vals = []
            for line in res["output"]:
                m = re_rnwl.match(line)
                if m is not None:
                    read_vals.append(int(m.group(1), 16))

            return read_vals

        elif option == "msm":
            counters = {}
            rows = {
                'tx_gfm': '\s*Tx\sGood\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'rx_gfm': '\s*Rx\sGood\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'fcserr': '\s*FCS\sError:\s+[xa-f\d]+\s+(\d+)',
                'alerr': '\s*Alignment\sError:\s+[xa-f\d]+\s+(\d+)',
                'tx_pfm': '\s*Tx\sPause\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'rx_pfm': '\s*Rx\sPause\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'tlerr': '\s*Rx\sToo\sLong\sErrors:\s+[xa-f\d]+\s+(\d+)',
                'irng_err': '\s*Rx\sIn\sRange\sLength\sErrors:\s+[xa-f\d]+\s+(\d+)',
                'txvlan': '\s*Tx\sVLAN\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'rxvlan': '\s*Rx\sVLAN\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'txoct': '\s*Tx\sOctets:\s+[xa-f\d]+\s+(\d+)',
                'rxoct': '\s*Rx\sOctets:\s+[xa-f\d]+\s+(\d+)',
                'tx_ucastf': '\s*Tx\sUnicast\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'tx_mcastf': '\s*Tx\sMulticast\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'tx_bcastf': '\s*Tx\sBroadcast\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'txerr': '\s*Tx\sErrors:\s+[xa-f\d]+\s+(\d+)',
                'rx_ucastf': '\s*Rx\sUnicast\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'rx_mcastf': '\s*Rx\sMulticast\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'rx_bcastf': '\s*Rx\sBroadcast\sFrames:\s+[xa-f\d]+\s+(\d+)',
                'rxerr': '\s*Rx\sErrors:\s+[xa-f\d]+\s+(\d+)',
                'tx_ucasto': '\s*Tx\sUnicast\sOctets:\s+[xa-f\d]+\s+(\d+)',
                'tx_mcasto': '\s*Tx\sMulticast\sOctets:\s+[xa-f\d]+\s+(\d+)',
                'tx_bcasto': '\s*Tx\sBroadcast\sOctets:\s+[xa-f\d]+\s+(\d+)',
                'rx_ucasto': '\s*Rx\sUnicast\sOctets:\s+[xa-f\d]+\s+(\d+)',
                'rx_mcasto': '\s*Rx\sMulticast\sOctets:\s+[xa-f\d]+\s+(\d+)',
                'rx_bcasto': '\s*Rx\sBroadcast\sOctets:\s+[xa-f\d]+\s+(\d+)',
            }

            for line in res["output"]:
                for key, pattern in rows.iteritems():
                    m = re.match(pattern, line)
                    if m is not None:
                        counters[key] = int(m.group(1))
                        break

            return counters

    def test_atltool_rr(self):
        if self.phy_only:
            pytest.skip()

        reg = 0x18
        read_vals = self.run_atltool(option="rr", addr=hex(reg))
        lib_val = self.dut_atltool_wrapper.readreg(reg)

        assert read_vals[0] == lib_val

    def test_atltool_rr_range(self):
        if self.phy_only:
            pytest.skip()

        # TODO: choose another registers range
        reg_start, reg_end = 0x18, 0x24
        addr_str = "0x{:X}:0x{:X}".format(reg_start, reg_end)

        read_vals = self.run_atltool(option="rr", addr=addr_str)

        lib_vals = []
        for offset in range(0, reg_end - reg_start + 1, 4):
            lib_reg = self.dut_atltool_wrapper.readreg(reg_start + offset)
            lib_vals.append(lib_reg)

        assert read_vals == lib_vals

    def test_atltool_wr(self):
        if self.phy_only:
            pytest.skip()

        reg_addr = 0x10C
        reg_val = 0x42

        addr_str = "0x{:X}".format(reg_addr)
        val_str = "0x{:X}".format(reg_val)
        self.run_atltool(option="wr", addr=addr_str, val=val_str)
        lib_val = self.dut_atltool_wrapper.readreg(reg_addr)

        assert reg_val == lib_val

    def test_atltool_wr_range(self):
        if self.phy_only:
            pytest.skip()

        reg_start, reg_end = 0x300, 0x30c
        reg_val = 0x800

        addr_str = "0x{:X}:0x{:X}".format(reg_start, reg_end)
        val_str = "0x{:X}".format(reg_val)
        self.run_atltool(option="wr", addr=addr_str, val=val_str)

        for offset in range(0, reg_end - reg_start + 1, 4):
            lib_res = self.dut_atltool_wrapper.readreg(reg_start + offset)
            assert lib_res == reg_val

    def test_atltool_rpr(self):
        if self.mac_only:
            pytest.skip()

        mmd, reg = 0x1e, 0xC8AF
        addr_str = "0x{:X}.0x{:X}".format(mmd, reg)

        read_vals = self.run_atltool(option="rpr", addr=addr_str)

        if not self.phy_only:
            lib_val = self.dut_atltool_wrapper.readphyreg(mmd, reg)
            assert read_vals[0] == lib_val
        else:
            assert read_vals[0] in [0xA0, 0xA1, 0xB0, 0xB1]

    def test_atltool_rpr_range(self):
        if self.mac_only:
            pytest.skip()

        mmd, reg_start, reg_end = 0x1e, 0xC8AE, 0xC8AF
        addr_str = "0x{:X}.0x{:X}:0x{:X}.0x{:X}".format(mmd, reg_start, mmd, reg_end)

        read_vals = self.run_atltool(option="rpr", addr=addr_str)

        if not self.phy_only:
            lib_regs = []
            for offset in range(0, reg_end - reg_start + 1):
                val = self.dut_atltool_wrapper.readphyreg(mmd, reg_start + offset)
                lib_regs.append(val)

            assert read_vals == lib_regs
        else:
            log.info("[DEBUG] tool_regs: {}".format(read_vals))

    def test_atltool_wpr(self):
        if self.mac_only:
            pytest.skip()

        mmd, reg = 0x1e, 0x300
        reg_val = 0x42

        addr_str = "0x{:X}.0x{:X}".format(mmd, reg)
        val_str = "0x{:X}".format(reg_val)
        self.run_atltool(option="wpr", addr=addr_str, val=val_str)

        if not self.phy_only:
            lib_reg = self.dut_atltool_wrapper.readphyreg(mmd, reg)
            assert lib_reg == reg_val
        else:
            read_vals = self.run_atltool(option="rpr", addr=addr_str)
            assert read_vals[0] == reg_val

    def test_atltool_wpr_range(self):
        if self.mac_only:
            pytest.skip()

        mmd, reg_start, reg_end = 0x1e, 0x300, 0x310
        reg_val = 0x64
        addr_str = "0x{:X}.0x{:X}:0x{:X}.0x{:X}".format(mmd, reg_start, mmd, reg_end)
        val_str = "0x{:X}".format(reg_val)

        self.run_atltool(option="wpr", addr=addr_str, val=val_str)

        if not self.phy_only:
            for offset in range(0, reg_end - reg_start + 1):
                lib_val = self.dut_atltool_wrapper.readphyreg(mmd, reg_start + offset)
                assert lib_val == reg_val
        else:
            read_vals = self.run_atltool(option="rpr", addr=addr_str)
            for v in read_vals:
                assert v == reg_val

    def test_atltool_rm(self):
        if self.phy_only:
            pytest.skip()

        ef_addr = self.dut_atltool_wrapper.readreg(0x364)
        size = 4  # default value

        addr_str = "0x{:X}".format(ef_addr)
        read_vals = self.run_atltool(option="rm", addr=addr_str, val='')
        lib_vals = self.dut_atltool_wrapper.readmem(ef_addr, size)

        assert read_vals == lib_vals

    def test_atltool_rm_range(self):
        if self.phy_only:
            pytest.skip()

        ef_addr = self.dut_atltool_wrapper.readreg(0x364)
        size = 24

        addr_str = "0x{:X}".format(ef_addr)
        val_str = "0x{:X}".format(size)
        read_vals = self.run_atltool(option="rm", addr=addr_str, val=val_str)
        lib_vals = self.dut_atltool_wrapper.readmem(ef_addr, size)

        assert read_vals == lib_vals

    def test_atltool_rpm(self):
        if self.phy_only:
            pytest.skip()

        addr = 0x3FFE0240
        size = 4
        addr_str = "0x{:X}".format(addr)
        val_str = ""

        lib_vals = self.dut_atltool_wrapper.readphymem(addr, size)
        read_vals = self.run_atltool(option="rpm", addr=addr_str, val=val_str)

        assert read_vals == lib_vals

    def test_atltool_rpm_range(self):
        if self.phy_only:
            pytest.skip()

        addr = 0x3FFE0240
        size = 12
        addr_str = "0x{:X}".format(addr)
        val_str = "0x{:X}".format(size)

        read_vals = self.run_atltool(option="rpm", addr=addr_str, val=val_str)
        lib_vals = self.dut_atltool_wrapper.readphymem(addr, size)

        assert read_vals == lib_vals

    def test_atltool_rmsm(self):
        if self.phy_only:
            pytest.skip()

        addr = 0x0
        addr_str = "0x{:X}".format(addr)
        read_vals = self.run_atltool(option="rmsm", addr=addr_str)
        lib_lav = self.dut_atltool_wrapper.readmsmreg(addr)

        assert read_vals[0] == lib_lav

    def test_atltool_rmsm_range(self):
        if self.phy_only:
            pytest.skip()

        reg_start, reg_end = 0x0, 0xC
        addr_str = "0x{:X}:0x{:X}".format(reg_start, reg_end)
        read_vals = self.run_atltool(option="rmsm", addr=addr_str)

        lib_vals = []
        for offset in range(0, reg_end - reg_start + 4, 4):
            lib_vals.append(self.dut_atltool_wrapper.readmsmreg(reg_start + offset))

        assert read_vals == lib_vals

    def test_atltool_wmsm(self):
        if self.phy_only:
            pytest.skip()

        addr = 0x4
        val = 0x42
        addr_str = "0x{:X}".format(addr)
        val_str = "0x{:X}".format(val)

        self.run_atltool(option="wmsm", addr=addr_str, val=val_str)
        lib_reg = self.dut_atltool_wrapper.readmsmreg(addr)

        assert lib_reg == val

    def test_atltool_wmsm_range(self):
        if self.phy_only:
            pytest.skip()

        reg_start = 0x4
        reg_end = 0xc
        val = 0x42
        addr_str = "0x{:X}:0x{:X}".format(reg_start, reg_end)
        val_str = "0x{:X}".format(val)

        self.run_atltool(option="wmsm", addr=addr_str, val=val_str)

        for offset in range(0, reg_end - reg_start + 4, 4):
            lib_reg = self.dut_atltool_wrapper.readmsmreg(reg_start + offset)

            assert lib_reg == val

    def test_atltool_rnwl(self):
        if self.phy_only:
            pytest.skip()

        reg = 0x0
        addr_str = "0x{:X}".format(reg)
        read_vals = self.run_atltool(option="rnwl", addr=addr_str)

        domain, bus, dev, func = get_domain_bus_dev_func(self.dut_port)
        lspci_device = "{:04x}:{:02x}:{:02x}.{:x}".format(domain, bus, dev, func)

        res = Command(cmd="sudo setpci -s {} VENDOR_ID".format(lspci_device), host=self.dut_hostname).run()
        vendor_id = res["output"][0]

        res = Command(cmd="sudo setpci -s {} DEVICE_ID".format(lspci_device), host=self.dut_hostname).run()
        device_id = res["output"][0]

        assert read_vals[0] & 0xFFFF == int(vendor_id, 16)
        assert read_vals[0] >> 16 == int(device_id, 16)

    def test_atltool_rnwl_range(self):
        if self.phy_only:
            pytest.skip()

        addr = '0x0:0x2'
        read_vals = self.run_atltool(option="rnwl", addr=addr)

        domain, bus, dev, func = get_domain_bus_dev_func(self.dut_port)
        lspci_device = "{:04x}:{:02x}:{:02x}.{:x}".format(domain, bus, dev, func)

        res = Command(cmd="sudo setpci -s {} 0x0.L".format(lspci_device), host=self.dut_hostname).run()
        reg_0 = res["output"][0]

        res = Command(cmd="sudo setpci -s {} 0x8.L".format(lspci_device), host=self.dut_hostname).run()
        reg_1 = res["output"][0]

        res = Command(cmd="sudo setpci -s {} 0x2C.L".format(lspci_device), host=self.dut_hostname).run()
        reg_2 = res["output"][0]

        assert read_vals[0] == int(reg_0, 16)
        assert read_vals[1] == int(reg_1, 16)
        assert read_vals[2] == int(reg_2, 16)

    def test_atltool_msm(self):
        if self.phy_only:
            pytest.skip()

        lib_vals = self.dut_atltool_wrapper.get_msm_counters()
        read_vals = self.run_atltool(option="msm")

        equal = True
        for key in read_vals:
            if lib_vals[key] != read_vals[key]:
                equal = False

        assert equal


class TestPactool(TestBase):
    RE_MAC_READREG = re.compile(r"Register MAC 0x[a-z0-9]+: 0x([a-z0-9]+)")
    RE_PHY_READREG = re.compile(r".*Register PHY \d 0x[0-9a-z.]+: (0x[0-9a-z.]+) : [01]+ [01]+")

    @classmethod
    def setup_class(cls):
        super(TestPactool, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            # Self protection, the test is implemented only for FIJI on Windows
            assert cls.dut_ops.is_windows()
            assert cls.dut_fw_card == CARD_FIJI

            cls.dut_diag_driver = Driver(host=cls.dut_hostname, port=cls.dut_port, version=cls.dut_drv_version,
                                         drv_type=DRV_TYPE_DIAG_WIN_USB)
            cls.dut_diag_driver.install()

            # TODO: download latest pactool
            from tools.pactoolper import PacTool
            cls.dut_pactool = PacTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.usb_port = cls.dut_pactool.usbutil_port
            res = Command(cmd="where pactool", host=cls.dut_hostname).run()
            cls.pactool_path = res["output"][0].replace("\\", "/")
            cls.pactool_cmd = "{} -d {}".format(cls.pactool_path, cls.usb_port)

        except Exception:
            log.exception("Failed while setting up class")
            raise

    # TODO: pactool -s  Display basic information about Aquantia USB device.
    def test_pactool_info(self):
        pass

    def test_pactool_list(self):
        res = Command(cmd="{} -l ".format(self.pactool_path), host=self.dut_hostname).run()
        re_dev = re.compile("\s+{}".format(self.usb_port))
        for line in res["output"]:
            m = re_dev.match(line)
            if m is not None:
                break
        else:
            raise Exception("Can't list usb devices")

    def test_pactool_rr(self):
        res = Command(cmd="{} -rr 0xda".format(self.pactool_cmd), host=self.dut_hostname).run()

        reg_val = None
        for line in res["output"]:
            m = self.RE_MAC_READREG.match(line)
            if m is not None:
                reg_val = m.group(1)

        reg_val = int(reg_val, 16)
        ver_major = int(self.dut_pactool.readreg(0xda))

        assert reg_val == ver_major

    def test_pactool_rr_range(self):
        reg_vals = []
        res = Command(cmd="{} -rr 0xda:0xdc".format(self.pactool_cmd), host=self.dut_hostname).run()
        for line in res["output"]:
            m = self.RE_MAC_READREG.match(line)
            if m is not None:
                reg_vals.append(int(m.group(1), 16))

        lib_vals = []
        for reg_addr in [0xda, 0xdb, 0xdc]:
            lib_vals.append(int(self.dut_pactool.readreg(reg_addr)))

        assert reg_vals == lib_vals

    def test_pactool_wr(self):
        reg_addr = 0x81
        wr_reg_val = 0x42
        Command(cmd="{} -wr 0x{:x} 0x{:x}".format(self.pactool_cmd, reg_addr, wr_reg_val), host=self.dut_hostname).run()

        lib_reg_val = int(self.dut_pactool.readreg(reg_addr))

        assert wr_reg_val == lib_reg_val

    # TODO: pactool -wr REG1:REG2 VALUE
    def test_pactool_wr_range(self):
        pass

    def test_pactool_rpr(self):
        mmd, reg = 7, 0
        res = Command(cmd="{} -rpr {}.{}".format(self.pactool_cmd, mmd, reg), host=self.dut_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Failed to run pactool")

        reg_val = None
        for line in res["output"]:
            m = self.RE_PHY_READREG.match(line)
            if m is not None:
                reg_val = m.group(1).replace(" ", "")
                reg_val = int(reg_val, 16)
                break

        lib_reg_val = int(self.dut_pactool.readphyreg(mmd, reg))

        assert reg_val == lib_reg_val

    # TODO: pactool -rpr MMD.REG1:MMD.REG2
    def test_pactool_rpr_range(self):
        pass

    def test_pactool_wpr(self):
        mmd, reg = 7, 0
        lib_reg_val = int(self.dut_pactool.readphyreg(mmd, reg))
        new_val = lib_reg_val ^ 1
        res = Command(cmd="{} -wpr {}.{} {}".format(self.pactool_cmd, mmd, reg, new_val), host=self.dut_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Failed to run pactool")
        res_val = int(self.dut_pactool.readphyreg(mmd, reg))

        assert new_val == res_val

    # TODO: pactool -wpr MMD.REG1:MMD.REG2 VALUE
    def test_pactool_wpr_range(self):
        pass


class TestDatapathTest(TestBase):
    @classmethod
    def setup_class(cls):
        super(TestDatapathTest, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.install_firmwares()
            cls.os = OpSystem()
            cls.fwtools_local_dut = tempfile.mkdtemp()
            if cls.os.is_linux():
                Driver(port=cls.dut_port, drv_type=DRV_TYPE_SRC_DIAG_LIN, version="latest").install()
            else:
                Driver(host=cls.dut_hostname, port=cls.dut_port, drv_type=DRV_TYPE_DIAG,
                       version=cls.dut_drv_version).install()
            download_fwtools(host=cls.dut_hostname, fwtools_local=cls.fwtools_local_dut, a2_tools_version=False)
        except Exception:
            log.exception("Failed while setting up class")
            raise

    @classmethod
    def teardown_class(cls):
        super(TestDatapathTest, cls).teardown_class()
        Command(cmd="sudo rm -r {}".format(cls.fwtools_local_dut), host=cls.dut_hostname).run()

    @idparametrize('p', [64, 91, 128, 256, 512, 1024, 1333, 2048, 4096, 8192, 16000])
    @idparametrize('l', ["PHY", "EXT"])
    @idparametrize('s', ['100M', '1G', '2.5G', '5G', '10G'])
    @idparametrize('fc', ["OFF", "ON"])
    def test_datapath(self, p, l, s, fc):
        if self.dut_fw_card == 'Felicity' and l == "PHY":
            pytest.skip("PHY loopback is not available for Felicity.")
        if self.lkp_hostname is not None and l == "EXT":
            pytest.skip("EXT loopback is not available in this setup.")
        if s not in self.supported_speeds:
            pytest.skip("Unsupported speed.")

        cmd = "sudo {}/datapathTest -t {} --flow_control {} -s {} -l {} -p {}".format(self.fwtools_local_dut,
                                                                                      datapath_time, fc, s, l, p)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        errror_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        if l == "EXT" and s == "1G" and self.dut_fw_card != 'Felicity':
            for line in res['output']:
                if "Error: RJ45 loopback doesn't support 1G rate" in line:
                    passed_test = True
        #elif self.dut_fw_card == CARD_NIKKI and (
        #        s == "2.5G" or s == "5G"):  # TODO remove this when tool will support 2.5G for Nikki
        #    for line in res['output']:
        #        if "Error! datapathTest can't run 2.5G and 5G on this chip (temporarily disabled)." in line:
        #            passed_test = True
        elif (self.dut_fw_card in BERMUDA_CARDS or "10G" not in self.supported_speeds) and s == "10G":
            for line in res['output']:
                if "Error! datapathTest can't run 10G on this chip" in line:
                    passed_test = True
        else:
            for line in res['output']:
                assert errror_msg not in line, "Errors during running datapathTest"
                assert fail_msg not in line, "datapathTest failed"
                if pass_msg in line:
                    passed_test = True
        assert passed_test, "Test is not passed"

    @idparametrize('p', ["64:3071", "97:4096", "64:16352"])
    @idparametrize('l', ["PHY", "EXT"])
    @idparametrize('s', ['100M', '1G', '2.5G', '5G', '10G'])
    @idparametrize('fc', ["OFF", "ON"])
    def test_datapath_range_pkts(self, p, l, s, fc):
        if self.dut_fw_card == 'Felicity' and l == "PHY":
            pytest.skip("PHY loopback is not available for Felicity.")
        if self.lkp_hostname is not None and l == "EXT":
            pytest.skip("EXT loopback is not available in this setup.")
        if s not in self.supported_speeds:
            pytest.skip("Unsupported speed.")

        cmd = "sudo {}/datapathTest -t {} --flow_control {} -s {} -l {} -p {}".format(self.fwtools_local_dut,
                                                                                      datapath_time, fc, s, l, p)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        if l == "EXT" and s == "1G" and self.dut_fw_card != 'Felicity':
            for line in res['output']:
                if "Error: RJ45 loopback doesn't support 1G rate" in line:
                    passed_test = True
        #elif self.dut_fw_card == CARD_NIKKI and (
        #        s == "2.5G" or s == "5G"):  # TODO remove this when tool will support 2.5G for Nikki
        #    for line in res['output']:
        #        if "Error! datapathTest can't run 2.5G and 5G on this chip (temporarily disabled)." in line:
        #            passed_test = True
        elif (self.dut_fw_card in BERMUDA_CARDS or "10G" not in self.supported_speeds) and s == "10G":
            for line in res['output']:
                if "Error! datapathTest can't run 10G on this chip" in line:
                    passed_test = True
        else:
            for line in res['output']:
                assert error_msg not in line, "Errors during running datapathTest"
                assert fail_msg not in line, "datapathTest failed"
                if pass_msg in line:
                    passed_test = True
        assert passed_test, "Test is not passed"

    @idparametrize('p', [64, 91, 128, 256, 512, 1024, 1333, 2048, 4096, 8192, 16000])
    @idparametrize('l', ["DMA", "DEEP"])
    def test_datapath_mac_lpbs(self, p, l):
        cmd = "sudo {}/datapathTest -t {} --flow_control OFF -l {} -p {}".format(self.fwtools_local_dut,
                                                                                 datapath_time, l, p)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        errror_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False

        for line in res['output']:
            assert errror_msg not in line, "Errors during running datapathTest"
            assert fail_msg not in line, "datapathTest failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"


class TestNightlyDatapathTest(TestDatapathTest):
    @classmethod
    def setup_class(cls):
        super(TestNightlyDatapathTest, cls).setup_class()
        if cls.lkp_hostname is not None:
            cls.os_lkp = OpSystem(host=cls.lkp_hostname)
            cls.fwtools_local_lkp = "/home/aqtest/fwtools"
            cmd = "mkdir /home/aqtest/fwtools"
            Command(cmd=cmd, host=cls.lkp_hostname).run()
            if cls.os_lkp.is_linux():
                cls.lkp_diag_driver = Driver(host=cls.lkp_hostname, port=cls.lkp_port,
                                             drv_type=DRV_TYPE_SRC_DIAG_LIN, version="latest").install()
                cls.lkp_diag_driver_is_installed = True
            else:
                cls.lkp_diag_driver = Driver(host=cls.lkp_hostname, port=cls.lkp_port, drv_type=DRV_TYPE_DIAG,
                                             version=cls.lkp_drv_version).install()
                cls.lkp_diag_driver_is_installed = True
            download_fwtools(host=cls.lkp_hostname, fwtools_local=cls.fwtools_local_lkp, a2_tools_version=False,
                             fwtools_ver="latest")
            cls.supported_speeds = os.environ.get("SUPPORTED_SPEEDS", "100M,1G").split(',')
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

    @classmethod
    def teardown_class(cls):
        super(TestNightlyDatapathTest, cls).teardown_class()
        if cls.lkp_hostname is None:
            Command(cmd="sudo rm -r {}".format(cls.fwtools_local_lkp), host=cls.lkp_hostname).run()

    def enable_lkp_dma_loopback(self):
        if self.lkp_diag_driver_is_installed:
            Driver(host=self.lkp_hostname, port=self.lkp_port, version=self.lkp_drv_version).install()
            self.lkp_iface = str(self.lkp_ifconfig.get_conn_name())
            self.lkp_diag_driver_is_installed = False
        cmd = "sudo ethtool --set-priv-flags {} DMANetworkLoopback on".format(self.lkp_iface)
        Command(cmd=cmd, host=self.lkp_hostname).run()
        cmd = "sudo ifconfig {} up".format(self.lkp_iface)
        Command(cmd=cmd, host=self.lkp_hostname).run()

    def disable_lkp_dma_loopback(self):
        cmd = "sudo ethtool --set-priv-flags {} DMANetworkLoopback off".format(self.lkp_iface)
        Command(cmd=cmd, host=self.lkp_hostname).run()
        cmd = "sudo ifconfig {} down".format(self.lkp_iface)
        Command(cmd=cmd, host=self.lkp_hostname).run()

    def run_datapath(self, ring_size=8148, packet_size=1024, loopback="EXT", speed="10G", flow_control="ON",
                     integrity_check="ON"):
        if self.dut_fw_card == 'Felicity' and loopback == "PHY":
            pytest.skip("PHY loopback is not available for Felicity.")
        if self.lkp_hostname is not None and loopback == "EXT":
            pytest.skip("EXT loopback is not available in this setup.")
        if speed not in self.supported_speeds:
            pytest.skip("Unsupported speed.")

        cmd = "sudo {}/datapathTest -t {} --flow_control {} -s {} -l {} -p {} -r {} -c {}".format(
            self.fwtools_local_dut,
            datapath_time, flow_control, speed, loopback, packet_size, ring_size, integrity_check)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        if loopback == "EXT" and speed == "1G" and self.dut_fw_card != 'Felicity':
            for line in res['output']:
                if "Error: RJ45 loopback doesn't support 1G rate" in line:
                    passed_test = True
        elif (self.dut_fw_card in BERMUDA_CARDS or "10G" not in self.supported_speeds) and speed == "10G":
            for line in res['output']:
                if "Error! datapathTest can't run 10G on this chip" in line:
                    passed_test = True
        else:
            for line in res['output']:
                assert error_msg not in line, "Errors during running datapathTest"
                assert fail_msg not in line, "datapathTest failed"
                if pass_msg in line:
                    passed_test = True
        assert passed_test, "Test is not passed"

    @idparametrize('seed', datapath_seeds)
    @idparametrize('p', [64, 128, 256, 512, 1024, 1333, 4096, 8192, 16000])
    @idparametrize('s', ['100M', '1G', '2.5G', '5G', '10G'])
    @idparametrize('l', ["PHY", "EXT"])
    def test_bad_seeds(self, seed, p, s, l):
        if self.dut_fw_card == 'Felicity' and l == "PHY":
            pytest.skip("PHY loopback is not available for Felicity.")
        if self.lkp_hostname is not None and l == "EXT":
            pytest.skip("EXT loopback is not available in this setup.")
        if s not in self.supported_speeds:
            pytest.skip("Unsupported speed.")

        cmd = "sudo {}/datapathTest -t {} -s {} -l {} -p {} --seed {}".format(self.fwtools_local_dut, datapath_time, s,
                                                                              l, p, seed)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        if l == "EXT" and s == "1G" and self.dut_fw_card != 'Felicity':
            for line in res['output']:
                if "Error: RJ45 loopback doesn't support 1G rate" in line:
                    passed_test = True
        elif (self.dut_fw_card in BERMUDA_CARDS or "10G" not in self.supported_speeds) and s == "10G":
            for line in res['output']:
                if "Error! datapathTest can't run 10G on this chip" in line:
                    passed_test = True
        else:
            for line in res['output']:
                assert error_msg not in line, "Errors during running datapathTest"
                assert fail_msg not in line, "datapathTest failed"
                if pass_msg in line:
                    passed_test = True
        assert passed_test, "Test is not passed"

    @idparametrize('p', [64, 91, 128, 256, 512, 1024, 1333, 2048, 8192, 16000])
    @idparametrize('s', ['100M', '1G', '2.5G', '5G', '10G'])
    @idparametrize('fc', ["OFF", "ON"])
    def test_dma_network_lpb(self, p, s, fc):
        self.enable_lkp_dma_loopback()
        cmd = "sudo {}/datapathTest -l NONE -t {} -p {} -s {} --flow_control {}".format(self.fwtools_local_dut,
                                                                                        datapath_time, p, s, fc)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        for line in res['output']:
            assert error_msg not in line, "Errors during running datapathTest"
            assert fail_msg not in line, "datapathTest failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"
        self.disable_lkp_dma_loopback()

    @idparametrize('p', [64, 91, 128, 256, 512, 1024, 1333, 2048, 8192, 16000])
    @idparametrize('s', ['100M', '1G', '2.5G', '5G', '10G'])
    @idparametrize('fc', ["OFF", "ON"])
    def test_phy_network_lpb(self, p, s, fc):
        # lkp
        cmd = "sudo {}/phyNetworkLoopback ON -s {}".format(self.fwtools_local_lkp, s)
        run_phy_network_loopback_lkp = Command(cmd=cmd, host=self.lkp_hostname)
        run_phy_network_loopback_lkp.run_async()
        # dut
        cmd = "sudo {}/datapathTest -l NONE -t {} -p {} -s {} --flow_control {}".format(self.fwtools_local_dut,
                                                                                        datapath_time, p, s, fc)
        run_datapath_dut = Command(cmd=cmd, host=self.dut_hostname)
        run_datapath_dut.run_async()

        timeout = int(datapath_time) + 20
        run_phy_network_loopback_lkp.join(timeout=timeout)
        res = run_datapath_dut.join(timeout=timeout)

        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        for line in res['output']:
            assert error_msg not in line, "Errors during running datapathTest"
            assert fail_msg not in line, "datapathTest failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"
        cmd = "sudo {}/phyNetworkLoopback OFF".format(self.fwtools_local_lkp)
        Command(cmd=cmd, host=self.lkp_hostname).run()

    @idparametrize('p', [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16000])
    @idparametrize('b2b', ["tx_only", "rx_only"])
    @idparametrize('s', ['100M', '1G', '2.5G', '5G', '10G'])
    def test_b2b(self, p, b2b, s):
        if self.lkp_hostname is None:
            pytest.skip("Cannot run datapathTest tool back to back without lkp.")

        if s not in self.supported_speeds:
            pytest.skip("Unsupported speed.")
        # dut
        cmd = "sudo {}/datapathTest --{} -t {} -s {} -p {}".format(self.fwtools_local_dut, b2b, datapath_time, s, p)
        run_datapath_dut = Command(cmd=cmd, host=self.dut_hostname)
        run_datapath_dut.run_async()

        # lkp
        b2b_lkp_direction = "tx_only" if b2b == "rx_only" else "rx_only"
        cmd = "sudo {}/datapathTest --{} -t {} -s {} -p {}".format(self.fwtools_local_lkp, b2b_lkp_direction,
                                                                   datapath_time, s, p)
        run_datapath_lkp = Command(cmd=cmd, host=self.lkp_hostname)
        run_datapath_lkp.run_async()
        timeout = int(datapath_time) + 25
        res_dut = run_datapath_dut.join(timeout=timeout)
        res_lkp = run_datapath_lkp.join(timeout=timeout)
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        for line in res_dut['output']:
            assert error_msg not in line, "Errors during running datapathTest"
            assert fail_msg not in line, "datapathTest failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"

        for line in res_lkp['output']:
            assert error_msg not in line, "Errors during running datapathTest"
            assert fail_msg not in line, "datapathTest failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"

    @idparametrize('p', ["64:128", "16000:16352", "64:16352", "200:1999"])
    @idparametrize('l', ["PHY", "EXT"])
    @idparametrize('s', ['100M', '1G', '2.5G', '5G', '10G'])
    def test_nightly_range_pkts(self, p, l, s):
        if self.dut_fw_card == 'Felicity' and l == "PHY":
            pytest.skip("PHY loopback is not available for Felicity.")
        if self.lkp_hostname is not None and l == "EXT":
            pytest.skip("EXT loopback is not available in this setup.")
        if s not in self.supported_speeds:
            pytest.skip("Unsupported speed.")

        cmd = "sudo {}/datapathTest -t {} -s {} -l {} -p {}".format(self.fwtools_local_dut,
                                                                    datapath_time, s, l, p)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        if l == "EXT" and s == "1G" and self.dut_fw_card != 'Felicity':
            for line in res['output']:
                if "Error: RJ45 loopback doesn't support 1G rate" in line:
                    passed_test = True
        elif (self.dut_fw_card in BERMUDA_CARDS or "10G" not in self.supported_speeds) and s == "10G":
            for line in res['output']:
                if "Error! datapathTest can't run 10G on this chip" in line:
                    passed_test = True
        else:
            for line in res['output']:
                assert error_msg not in line, "Errors during running datapathTest"
                assert fail_msg not in line, "datapathTest failed"
                if pass_msg in line:
                    passed_test = True
        assert passed_test, "Test is not passed"

    @idparametrize('p', [64, 91, 128, 512, 1024, 2048, 8192, 10723, 1234, 16000, 16352])
    @idparametrize('l', ["DMA", "DEEP"])
    def test_nightly_mac_lpbs(self, p, l):
        cmd = "sudo {}/datapathTest -t {} --flow_control OFF -l {} -p {}".format(self.fwtools_local_dut,
                                                                                 datapath_time, l, p)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False

        for line in res['output']:
            assert error_msg not in line, "Errors during running datapathTest"
            assert fail_msg not in line, "datapathTest failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"

    @idparametrize('p', ["64:3071", "97:4096", "64:16352"])
    @idparametrize('l', ["DMA", "DEEP"])
    def test_nightly_mac_lpbs_range(self, p, l):
        cmd = "sudo {}/datapathTest -t {} --flow_control OFF -l {} -p {}".format(self.fwtools_local_dut, datapath_time,
                                                                                 l, p)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False

        for line in res['output']:
            assert error_msg not in line, "Errors during running datapathTest"
            assert fail_msg not in line, "datapathTest failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"

    @idparametrize('r', [8])
    @idparametrize('p', [64])
    @idparametrize('l', ["PHY"])
    @idparametrize('s', ["10G"])
    @idparametrize('fc', ["OFF"])
    @idparametrize('c', ["OFF"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [8])
    @idparametrize('p', [13352])
    @idparametrize('l', ["PHY"])
    @idparametrize('s', ["10G"])
    @idparametrize('fc', ["OFF"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [8148])
    @idparametrize('p', [13552])
    @idparametrize('l', ["10G"])
    @idparametrize('s', ["EXT"])
    @idparametrize('fc', ["ON"])
    @idparametrize('c', ["OFF"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [512])
    @idparametrize('p', [4777])
    @idparametrize('l', ["EXT"])
    @idparametrize('s', ["10G"])
    @idparametrize('fc', ["ON"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [4096])
    @idparametrize('p', [127])
    @idparametrize('l', ["PHY"])
    @idparametrize('s', ["5G"])
    @idparametrize('fc', ["OFF"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [8184])
    @idparametrize('p', [7890])
    @idparametrize('l', ["EXT"])
    @idparametrize('s', ["5G"])
    @idparametrize('fc', ["OFF"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [8184])
    @idparametrize('p', [10000])
    @idparametrize('l', ["EXT"])
    @idparametrize('s', ["2.5G"])
    @idparametrize('fc', ["ON"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [64])
    @idparametrize('p', [512])
    @idparametrize('l', ["PHY"])
    @idparametrize('s', ["1G"])
    @idparametrize('fc', ["ON"])
    @idparametrize('c', ["OFF"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [8])
    @idparametrize('p', [100])
    @idparametrize('l', ["EXT"])
    @idparametrize('s', ["1G"])
    @idparametrize('fc', ["ON"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [4096])
    @idparametrize('p', [13064])
    @idparametrize('l', ["EXT"])
    @idparametrize('s', ["10G"])
    @idparametrize('fc', ["ON"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [8184])
    @idparametrize('p', [64])
    @idparametrize('l', ["EXT"])
    @idparametrize('s', ["10G"])
    @idparametrize('fc', ["ON"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [512])
    @idparametrize('p', [1488])
    @idparametrize('l', ["PHY"])
    @idparametrize('s', ["1G"])
    @idparametrize('fc', ["OFF"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [888])
    @idparametrize('p', [124])
    @idparametrize('l', ["EXT"])
    @idparametrize('s', ["10G"])
    @idparametrize('fc', ["OFF"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [8184])
    @idparametrize('p', [9000])
    @idparametrize('l', ["EXT"])
    @idparametrize('s', ["2.5G"])
    @idparametrize('fc', ["ON"])
    @idparametrize('c', ["OFF"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [4096])
    @idparametrize('p', [234])
    @idparametrize('l', ["EXT"])
    @idparametrize('s', ["10G"])
    @idparametrize('fc', ["ON"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)

    @idparametrize('r', [1024])
    @idparametrize('p', [13000])
    @idparametrize('l', ["EXT"])
    @idparametrize('s', ["5G"])
    @idparametrize('fc', ["ON"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, fc, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, flow_control=fc, integrity_check=c)


class TestDatapathTest2(TestBase):
    @classmethod
    def setup_class(cls):
        super(TestDatapathTest2, cls).setup_class()
        try:
            if cls.dut_fw_card != "Antigua":
                raise Exception("datapathTest2 is suitable only for Antigua.")
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.install_firmwares()
            cls.os_dut = OpSystem()
            cls.fwtools_local_dut = tempfile.mkdtemp()
            if cls.os_dut.is_linux():
                Driver(port=cls.dut_port, drv_type=DRV_TYPE_SRC_DIAG_LIN, version="latest").install()
            else:
                Driver(host=cls.dut_hostname, port=cls.dut_port, drv_type=DRV_TYPE_DIAG,
                       version=cls.dut_drv_version).install()
            download_fwtools(host=cls.dut_hostname, fwtools_local=cls.fwtools_local_dut, a2_tools_version=True)
        except Exception:
            log.exception("Failed while setting up class")
            raise

    @classmethod
    def teardown_class(cls):
        super(TestDatapathTest2, cls).teardown_class()
        Command(cmd="sudo rm -r {}".format(cls.fwtools_local_dut), host=cls.dut_hostname).run()

    @idparametrize('p', [64, 91, 128, 256, 512, 1024, 1333, 2048, 4096, 8192, 16000])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ['10M', '100M', '1G', '2.5G', '5G', '10G'])
    def test_a2_datapath_rj45(self, p, l, s):
        cmd = "sudo {}/datapathTest2 -t {} -l {} -p {} -s {}".format(self.fwtools_local_dut, datapath_time, l, p, s)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        errror_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        if l == "RJ45" and s == "1G":
            for line in res['output']:
                if "Error: RJ45 loopback doesn't support 1G rate" in line:
                    passed_test = True
        else:
            for line in res['output']:
                assert errror_msg not in line, "Errors during running datapathTest2"
                assert fail_msg not in line, "datapathTest2 failed"
                if pass_msg in line:
                    passed_test = True
        assert passed_test, "Test is not passed"

    @idparametrize('p', [64, 91, 128, 256, 512, 1024, 1333, 2048, 4096, 8192, 16000])
    @idparametrize('l', ["DMA", "DEEP"])
    def test_a2_datapath(self, p, l):
        cmd = "sudo {}/datapathTest2 -t {} -l {} -p {}".format(self.fwtools_local_dut, datapath_time, l, p)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        errror_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        for line in res['output']:
            assert errror_msg not in line, "Errors during running datapathTest"
            assert fail_msg not in line, "datapathTest2 failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"

    '''@idparametrize('pkts', [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16000])
    @idparametrize('b2b', ["tx_only", "rx_only"])
    @idparametrize('rate', ['10M', '100M', '1G', '2.5G', '5G', '10G'])
    @idparametrize('time', [5])
    def test_a2_b2b_datapath(self, pkts, b2b, rate, time):
        if rate not in self.supported_speeds:
            pytest.skip("Unsupported speed.")
        if self.lkp_hostname is None:
            pytest.skip("Cannot run datapathTest tool back to back without lkp")

        # dut
        cmd = "sudo {}/datapathTest --{} -t {} -s {} -p {}".format(self.fwtools_local_dut, b2b, time, rate,
                                                                   pkts)  # TODO
        run_datapath_dut = Command(cmd=cmd, host=self.dut_hostname)
        run_datapath_dut.run_async()
        # lkp
        if self.lkp_fw_card != CARD_ANTIGUA:
            tool_version = "datapathTest"
        else:
            tool_version = "datapathTest2"

        b2b_lkp = "tx_only" if b2b == "rx_only" else "rx_only"
        cmd = "sudo {}/{} --{} -t {} -s {} -p {}".format(self.fwtools_local_lkp, tool_version, b2b_lkp,
                                                                                    time, rate, pkts)
        run_datapath_lkp = Command(cmd=cmd, host=self.lkp_hostname)
        run_datapath_lkp.run_async()
        timeout = time + 15
        res_dut = run_datapath_dut.join(timeout=timeout)
        res_lkp = run_datapath_lkp.join(timeout=timeout)
        pass_msg = "Test Result: PASS"
        errror_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        for line in res_dut['output']:
            assert errror_msg not in line, "Errors during running datapathTest"
            assert fail_msg not in line, "datapathTest failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"

        for line in res_lkp['output']:
            assert errror_msg not in line, "Errors during running datapathTest"
            assert fail_msg not in line, "datapathTest failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"'''


class TestA2NightlyDatapathTest2(TestDatapathTest2):
    @classmethod
    def setup_class(cls):
        super(TestA2NightlyDatapathTest2, cls).setup_class()
        if cls.lkp_hostname is not None:
            cls.os_lkp = OpSystem(host=cls.lkp_hostname)
            cls.fwtools_local_lkp = "/home/aqtest/fwtools"
            cmd = "mkdir /home/aqtest/fwtools"
            Command(cmd=cmd, host=cls.lkp_hostname).run()
            if cls.os_lkp.is_linux():
                Driver(host=cls.lkp_hostname, port=cls.lkp_port, drv_type=DRV_TYPE_SRC_DIAG_LIN,
                       version="latest").install()
                cls.lkp_diag_driver_is_installed = True
            else:
                Driver(host=cls.lkp_hostname, port=cls.lkp_port, drv_type=DRV_TYPE_DIAG,
                       version=cls.lkp_drv_version).install()
                cls.lkp_diag_driver_is_installed = True
            cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)
            if cls.lkp_fw_card != CARD_ANTIGUA:
                download_fwtools(host=cls.lkp_hostname, fwtools_local=cls.fwtools_local_lkp, a2_tools_version=False,
                                 fwtools_ver="latest")
            else:
                download_fwtools(host=cls.lkp_hostname, fwtools_local=cls.fwtools_local_lkp, a2_tools_version=True,
                                 fwtools_ver="latest")

    @classmethod
    def teardown_class(cls):
        super(TestA2NightlyDatapathTest2, cls).teardown_class()
        if cls.lkp_hostname is None:
            Command(cmd="sudo rm -r {}".format(cls.fwtools_local_lkp), host=cls.lkp_hostname).run()

    def enable_lkp_dma_loopback(self):
        if self.lkp_diag_driver_is_installed:
            Driver(host=self.lkp_hostname, port=self.lkp_port, version=self.lkp_drv_version).install()
            self.lkp_iface = str(self.lkp_ifconfig.get_conn_name())
            self.lkp_diag_driver_is_installed = False
        cmd = "sudo ethtool --set-priv-flags {} DMANetworkLoopback on".format(self.lkp_iface)
        Command(cmd=cmd, host=self.lkp_hostname).run()
        cmd = "sudo ifconfig {} up".format(self.lkp_iface)
        Command(cmd=cmd, host=self.lkp_hostname).run()

    def disable_lkp_dma_loopback(self):
        cmd = "sudo ethtool --set-priv-flags {} DMANetworkLoopback off".format(self.lkp_iface)
        Command(cmd=cmd, host=self.lkp_hostname).run()
        cmd = "sudo ifconfig {} down".format(self.lkp_iface)
        Command(cmd=cmd, host=self.lkp_hostname).run()

    def run_datapath(self, ring_size=8148, packet_size=1024, loopback="RJ45", speed="10G", integrity_check="ON"):
        if self.lkp_hostname is not None and loopback == "RJ45":
            pytest.skip("RJ45 loopback is not available in this setup.")

        cmd = "sudo {}/datapathTest2 -t {} -s {} -l {} -p {} -r {} -c {}".format(self.fwtools_local_dut,
                                                                                 datapath_time, speed, loopback,
                                                                                 packet_size, ring_size,
                                                                                 integrity_check)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        if loopback == "RJ45" and speed == "1G" and self.dut_fw_card != 'Felicity':
            for line in res['output']:
                if "Error: RJ45 loopback doesn't support 1G rate" in line:
                    passed_test = True
        else:
            for line in res['output']:
                assert error_msg not in line, "Errors during running datapathTest2"
                assert fail_msg not in line, "datapathTest2 failed"
                if pass_msg in line:
                    passed_test = True
        assert passed_test, "Test is not passed"

    @idparametrize('seed', datapath_seeds)
    @idparametrize('p', [64, 128, 256, 512, 1024, 1333, 4096, 8192, 16000])
    @idparametrize('s', ['1G', '2.5G', '5G', '10G'])
    @idparametrize('l', ["RJ45"])
    def test_bad_seeds(self, seed, p, s, l):
        if self.lkp_hostname is not None and l == "RJ45":
            pytest.skip("RJ45 loopback is not available in this setup.")
        cmd = "sudo {}/datapathTest2 -t {} -s {} -l {} -p {} --seed {}".format(self.fwtools_local_dut, datapath_time, s,
                                                                               l, p, seed)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        for line in res['output']:
            if "Error: RJ45 loopback doesn't support 1G rate" in line:
                passed_test = True
        for line in res['output']:
            assert error_msg not in line, "Errors during running datapathTest2"
            assert fail_msg not in line, "datapathTest2 failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"

    @idparametrize('p', [64, 91, 128, 256, 512, 1024, 1333, 2048, 8192, 16000])
    @idparametrize('s', ['1G', '10G'])
    def test_dma_network_lpb(self, p, s):
        self.enable_lkp_dma_loopback()
        cmd = "sudo {}/datapathTest2 -l NONE -t {} -p {} -s {}".format(self.fwtools_local_dut, datapath_time, p, s)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        for line in res['output']:
            assert error_msg not in line, "Errors during running datapathTest2"
            assert fail_msg not in line, "datapathTest2 failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"
        self.disable_lkp_dma_loopback()

    @idparametrize('p', [64, 91, 128, 256, 512, 1024, 1333, 2048, 8192, 16000])
    @idparametrize('s', ['1G', '10G'])
    def test_phy_network_lpb(self, p, s):
        # lkp
        cmd = "sudo {}/phyNetworkLoopback ON -s {}".format(self.fwtools_local_lkp, s)
        run_phy_network_loopback_lkp = Command(cmd=cmd, host=self.lkp_hostname)
        run_phy_network_loopback_lkp.run_async()
        # dut
        cmd = "sudo {}/datapathTest2 -l NONE -t {} -p {} -s {}".format(self.fwtools_local_dut, datapath_time, p, s)
        run_datapath_dut = Command(cmd=cmd, host=self.dut_hostname)
        run_datapath_dut.run_async()

        timeout = int(datapath_time) + 20
        run_phy_network_loopback_lkp.join(timeout=timeout)
        res = run_datapath_dut.join(timeout=timeout)

        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        for line in res['output']:
            assert error_msg not in line, "Errors during running datapathTest2"
            assert fail_msg not in line, "datapathTest2 failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"
        cmd = "sudo {}/phyNetworkLoopback OFF".format(self.fwtools_local_lkp)
        Command(cmd=cmd, host=self.lkp_hostname).run()

    @idparametrize('p', [64, 89, 128, 256, 512, 1024, 2048, 4096, 1123, 5039, 8192, 16000])
    @idparametrize('b2b', ["tx_only", "rx_only"])
    @idparametrize('s', ['1G', '10G'])
    def test_a2_b2b_datapath(self, p, b2b, s):
        if self.lkp_hostname is None:
            pytest.skip("Cannot run datapathTest2 tool back to back without lkp")

        # dut
        cmd = "sudo {}/datapathTest2 --{} -t {} -s {} -p {}".format(self.fwtools_local_dut, b2b, datapath_time, s, p)
        run_datapath_dut = Command(cmd=cmd, host=self.dut_hostname)
        run_datapath_dut.run_async()
        # lkp
        if self.lkp_fw_card != CARD_ANTIGUA:
            tool_version = "datapathTest"
        else:
            tool_version = "datapathTest2"

        b2b_lkp = "tx_only" if b2b == "rx_only" else "rx_only"
        cmd = "sudo {}/{} --{} -t {} -s {} -p {}".format(self.fwtools_local_lkp, tool_version, b2b_lkp,
                                                         datapath_time, s, p)
        run_datapath_lkp = Command(cmd=cmd, host=self.lkp_hostname)
        run_datapath_lkp.run_async()
        timeout = int(datapath_time) + 20
        res_dut = run_datapath_dut.join(timeout=timeout)
        res_lkp = run_datapath_lkp.join(timeout=timeout)
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        for line in res_dut['output']:
            assert error_msg not in line, "Errors during running datapathTest2"
            assert fail_msg not in line, "datapathTest2 failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"

        for line in res_lkp['output']:
            assert error_msg not in line, "Errors during running datapathTest2"
            assert fail_msg not in line, "datapathTest2 failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passeed"

    '''
    @idparametrize('p', ["64:128", "16000:16352", "64:16352",  "200:1999"])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ['10M', '100M', '1G', '2.5G', '5G', '10G'])
    def test_nightly_range_pkts(self, p, l, s):
        if self.lkp_hostname is not None and l == "RJ45":
            pytest.skip("RJ45 loopback is not available in this setup.")

        cmd = "sudo {}/datapathTest2 -t {} -s {} -l {} -p {}".format(self.fwtools_local_dut,
                                                                                         datapath_time, s, l, p)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False
        if l == "RJ45" and s == "1G" and self.dut_fw_card != 'Felicity':
            for line in res['output']:
                if "Error: RJ45 loopback doesn't support 1G rate" in line:
                    passed_test = True
        else:
            for line in res['output']:
                assert error_msg not in line, "Errors during running datapathTest2"
                assert fail_msg not in line, "datapathTest2 failed"
                if pass_msg in line:
                    passed_test = True
        assert passed_test, "Test is not passed"
    '''

    @idparametrize('p', [64, 91, 128, 512, 1024, 2048, 8192, 10723, 1234, 16000])
    @idparametrize('l', ["DMA", "DEEP"])
    def test_nightly_mac_lpbs(self, p, l):
        cmd = "sudo {}/datapathTest2 -t {} -l {} -p {}".format(self.fwtools_local_dut,
                                                               datapath_time, l, p)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False

        for line in res['output']:
            assert error_msg not in line, "Errors during running datapathTest2"
            assert fail_msg not in line, "datapathTest2 failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"

    '''
    @idparametrize('p', ["64:3071", "97:4096", "64:16352"])
    @idparametrize('l', ["DMA", "DEEP"])
    def test_nightly_mac_lpbs_range(self, p, l):
        cmd = "sudo {}/datapathTest2 -t {}  -l {} -p {}".format(self.fwtools_local_dut, datapath_time, l, p)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        pass_msg = "Test Result: PASS"
        error_msg = "Test Result: ERROR"
        fail_msg = "Test Result: FAIL"
        passed_test = False

        for line in res['output']:
            assert error_msg not in line, "Errors during running datapathTest2"
            assert fail_msg not in line, "datapathTest2 failed"
            if pass_msg in line:
                passed_test = True
        assert passed_test, "Test is not passed"
    '''

    @idparametrize('r', [8])
    @idparametrize('p', [64])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["10G"])
    @idparametrize('c', ["OFF"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [8])
    @idparametrize('p', [13352])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["100M"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [8148])
    @idparametrize('p', [13552])
    @idparametrize('l', ["10G"])
    @idparametrize('s', ["RJ45"])
    @idparametrize('c', ["OFF"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [512])
    @idparametrize('p', [4777])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["10G"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [4096])
    @idparametrize('p', [127])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["5G"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [8184])
    @idparametrize('p', [7890])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["5G"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [8184])
    @idparametrize('p', [10000])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["2.5G"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [64])
    @idparametrize('p', [512])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["1G"])
    @idparametrize('c', ["OFF"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [8])
    @idparametrize('p', [100])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["1G"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [4096])
    @idparametrize('p', [13064])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["10G"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [8184])
    @idparametrize('p', [64])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["10G"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [512])
    @idparametrize('p', [1488])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["1G"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [888])
    @idparametrize('p', [124])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["100M"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [8184])
    @idparametrize('p', [9000])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["2.5G"])
    @idparametrize('c', ["OFF"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [4096])
    @idparametrize('p', [234])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["10G"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)

    @idparametrize('r', [1024])
    @idparametrize('p', [13000])
    @idparametrize('l', ["RJ45"])
    @idparametrize('s', ["10M"])
    @idparametrize('c', ["ON"])
    def test_nightly(self, r, p, l, s, c):
        self.run_datapath(ring_size=r, packet_size=p, loopback=l, speed=s, integrity_check=c)


class TestAtlFlashUpdate(TestBase):
    @staticmethod
    def get_actual_pcirom_version(version):
        try:
            suburl = "firmware/{}/content.txt".format(version)
            url = urlparse.urljoin(BUILDS_SERVER, suburl)
            response = get_url_response(url)
            for line in response.splitlines():
                m = re.match("PCIROM:\s+(\d+.\d+.\d+)", line)
                if m is not None:
                    return m.group(1)
        except Exception:
            return version

    @classmethod
    def add_diag_drv_cert(cls, path):
        cert_dir = "win32" if cls.dut_ops.get_arch() == "32" else "x64"
        cert = os.path.join(path, "mbu/Os/{}/aquantiaDiagPack.cer".format(cert_dir))

        cls.diag_drv.install_trusted_certificate(cert)

    @classmethod
    def download_atlflashupdate_bundle(cls, bundle_ver, base_dir=None):
        log.info("Downloading AtlFlashUpdate Bundle...")

        pattern = '([0-9.]+)_([0-9.]+)_([0-9.]+)'
        tool_ver, fw_ver, build = re.match(pattern, bundle_ver).groups()

        if base_dir is None:
            directory = tempfile.mkdtemp()
        else:
            directory = os.path.join(base_dir, "atl_flash_update_bundle")
            remove_directory(directory)
            os.mkdir(directory)

        suburl = "tools/atl-flash-update-bundle/{bundle}/atlflashupdate_{tool}_{fw}.zip".format(
            bundle=bundle_ver, tool=tool_ver, fw=fw_ver
        )
        download_from_url(suburl, directory, unzip=True)

        log.debug("AtlFlashUpdate Bundle has been downloaded and extracted to {}".format(directory))

        return directory.replace("\\", "/")

    # ====

    @classmethod
    def setup_class(cls):
        super(TestAtlFlashUpdate, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            # Self protection, the test is implemented only for Windows
            assert cls.dut_ops.is_windows()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.diag_drv = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest", host=cls.dut_hostname)

            if not cls.state.skip_class_setup:
                cls.install_firmwares()
                cls.dut_driver.install()
                cls.lkp_driver.install()

            # Download DIAG tool
            diag_1x_base_dir = os.path.join(cls.working_dir, "diag_1x")
            diag_2x_base_dir = os.path.join(cls.working_dir, "diag_2x")
            cls.diag_1x_dir = os.path.join(diag_1x_base_dir, "diag")
            cls.diag_2x_dir = os.path.join(diag_2x_base_dir, "diag")

            # if not cls.state.skip_class_setup:
            if not os.path.exists(diag_1x_base_dir):
                os.mkdir(diag_1x_base_dir)
            if not os.path.exists(diag_2x_base_dir):
                os.mkdir(diag_2x_base_dir)
            download_diag(version="1.3.20", base_dir=diag_1x_base_dir)
            download_diag(version=cls.diag_version, base_dir=diag_2x_base_dir)
            cls.add_diag_drv_cert(cls.diag_2x_dir)

            # Download Atl Flash Update Bundle
            cls.bundle_version = os.environ.get("ATL_FLASH_UPDATE_BUNDLE_VERSION", None)
            assert cls.bundle_version is not None
            cls.flash_tool_dir = cls.download_atlflashupdate_bundle(cls.bundle_version, cls.working_dir)

            if cls.dut_fw_card in FELICITY_CARDS:
                cls.default_did = 0x00b1
                # cls.clx_overrides["dev_id"] = 0x00b1
                # cls.clx_overrides["dev_id"] = 0xd100
                # cls.clx_overrides["dev_id"] = 0x80b1
            elif cls.dut_fw_card in BERMUDA_CARDS:
                # cls.clx_overrides["dev_id"] = 0x12b1
                cls.default_did = 0x12b1
            else:
                # cls.clx_overrides["dev_id"] = 0xd107  # 10G
                cls.default_did = 0xd107
                # cls.clx_overrides["dev_id"] = 0x09b1  # 2.5G

            cls.default_sdid = 0x1
            cls.default_svid = 0x1d6a

            cls.clx_overrides = {
                "dev_id": cls.default_did,
                "subsys_id": cls.default_sdid,
                "subven_id": cls.default_svid,
                "mac": get_mac(cls.dut_port),
                "lanes": 1,
            }

            cls.test_tmp_dir = None

            # CLX v.1
            cls.fw_ver_1_5_44 = "x1/1.5.44/bin_forCustomers"
            cls.fw_ver_1_5_56 = "x1/1.5.56/bin_forCustomers"
            cls.fw_ver_1_5_58 = "x1/1.5.58/bin_forCustomers"

            # CLX v.2
            cls.fw_ver_1_5_83 = "x1/1.5.83"
            cls.fw_ver_1_5_87 = "x1/1.5.87_FW_RELEASE_1_5_87__288/bin_forCustomers"
            cls.fw_ver_1_5_89 = "x1/1.5.89_master__293/bin_forCustomers"
            cls.fw_ver_1_5_90 = "x1/1.5.90/bin_forCustomers"

            cls.fw_ver_3_0_33 = "3x/3.0.33"
            cls.fw_ver_3_1_21 = "3x/3.1.21"  # No FW for Bermuda B0 and Felicity
            cls.fw_ver_3_1_28 = "3x/3.1.28"
            cls.fw_ver_3_1_30 = "3x/3.1.30"
            cls.fw_ver_3_1_32 = "3x/3.1.32"  # No FW for Bermuda B0
            cls.fw_ver_3_1_33 = "3x/3.1.33"  # Thermal shutdown issue
            cls.fw_ver_3_1_41 = "3x/3.1.41"  # Thermal shutdown issue
            cls.fw_ver_3_1_43 = "3x/3.1.43"
            cls.fw_ver_3_1_44 = "3x/3.1.44"
            cls.fw_ver_3_1_50 = "3x/3.1.50"
            cls.fw_ver_3_1_56 = "3x/3.1.56"
            cls.fw_ver_3_1_57 = "3x/3.1.57"
            cls.fw_ver_3_1_58 = "3x/3.1.58"
            cls.fw_ver_3_1_62 = "3x/3.1.62"
            cls.fw_ver_3_1_64 = "3x/3.1.64"
            cls.fw_ver_3_1_66 = "3x/3.1.66"
            cls.fw_ver_3_1_69 = "3x/3.1.69"
            cls.fw_ver_3_1_71 = "3x/3.1.71"
            cls.fw_ver_3_1_73 = "3x/3.1.73"
            cls.fw_ver_3_1_75 = "3x/3.1.75"

            if not cls.state.skip_class_setup:
                cls.state.skip_class_setup = True
                cls.state.update()

        except Exception:
            log.exception("Failed while setting up class")
            raise

    @classmethod
    def teardown_class(cls):
        super(TestAtlFlashUpdate, cls).teardown_class()
        Command(cmd="rm -rf {}".format(cls.flash_tool_dir), host=cls.dut_hostname).run()

    def setup_method(self, method):
        super(TestAtlFlashUpdate, self).setup_method(method)
        self.test_tmp_dir = tempfile.mkdtemp().replace("\\", "/")
        assert Command(cmd='ls {}'.format(self.test_tmp_dir), host=self.dut_hostname).run()['returncode'] == 0
        log.info('Created test temp directory {}'.format(self.test_tmp_dir))

    def teardown_method(self, method):
        super(TestAtlFlashUpdate, self).teardown_method(method)

    # ====

    def remove_drivers(self):
        log.info("<----- Remove drivers ----->")
        while self.dut_driver.is_installed() or self.diag_drv.is_installed():
            self.dut_driver.uninstall()
            self.diag_drv.uninstall()

    def download_fw(self, fw_version):
        upd_dut_firmware = Firmware(
            host=self.dut_hostname, port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
            version=fw_version, mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
            pause=self.dut_fw_pause, pcirom=self.dut_fw_pcirom, dirtywake=self.dut_fw_dirtywake,
            bdp=self.dut_bdp, sign=self.dut_sign, se_enable=self.dut_se, hsd=self.dut_hsd)
        firmware_clx = upd_dut_firmware.download()

        return firmware_clx

    def install_fw(self, fw_version):
        if fw_version == self.fw_ver_1_5_44:
            pciroom = "2.5.13"
        elif fw_version == self.fw_ver_1_5_58:
            pciroom = "2.5.17"
        elif fw_version == self.fw_ver_1_5_90:
            pciroom = "3.0.16"
        else:
            pciroom = self.dut_fw_pcirom

        self.dut_flash_override, _ = self.get_flash_override()
        if all([self.dut_fw_version, self.dut_fw_card]):
            self.dut_firmware = firmware.Firmware(port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
                                                  version=fw_version, mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
                                                  pause=self.dut_fw_pause, pcirom=pciroom,
                                                  dirtywake=self.dut_fw_dirtywake, host=self.dut_hostname,
                                                  bdp=self.dut_bdp,
                                                  sign=self.dut_sign, se_enable=self.dut_se, hsd=self.dut_hsd)

            if self.state.fw_install_cold_restart is True and self.is_local_host(self.dut_hostname):
                log.info("FW installation has been done before reboot")
                self.state.fw_install_cold_restart = False
                self.state.update()
            else:

                # Remove installed drivers
                self.remove_drivers()

                postinstall_action = self.dut_firmware.install(overrides=self.dut_flash_override)
                if postinstall_action == firmware.Firmware.POSTINSTALL_RESTART:
                    self.restart(self.dut_hostname)
                if postinstall_action == firmware.Firmware.POSTINSTALL_COLD_RESTART:
                    if self.is_local_host(self.dut_hostname):
                        self.state.fw_install_cold_restart = True
                        self.state.update()
                    self.cold_restart(self.dut_hostname)

    def install_fw_diag(self, fw_version):
        if not self.state.fw_install_cold_restart:
            try:
                log.info("<----- Burn phase ----->")

                self.state.fw_install_cold_restart = True
                self.state.update()

                # Install Diag driver
                self.remove_drivers()
                log.info("<----- Install Diag driver ----->")
                self.diag_drv.install()

                if fw_version in [self.fw_ver_1_5_44, self.fw_ver_1_5_56, self.fw_ver_1_5_58]:
                    diag_dir = self.diag_1x_dir
                else:
                    diag_dir = self.diag_2x_dir

                if fw_version == self.fw_ver_1_5_44:
                    pciroom = "2.5.13"
                elif fw_version == self.fw_ver_1_5_58:
                    pciroom = "2.5.17"
                elif fw_version == self.fw_ver_1_5_90:
                    pciroom = "3.0.16"
                else:
                    pciroom = self.dut_fw_pcirom

                fw = firmware.Firmware(port=self.dut_port, card=self.dut_fw_card, speed=self.dut_fw_speed,
                                       version=fw_version, mdi=self.dut_fw_mdi, mii=self.dut_fw_mii,
                                       pause=self.dut_fw_pause, pcirom=pciroom,
                                       dirtywake=self.dut_fw_dirtywake, host=self.dut_hostname,
                                       bdp=self.dut_bdp, sign=self.dut_sign,
                                       se_enable=self.dut_se, hsd=self.dut_hsd)

                clx_path = fw.download()

                aqc_data = {
                    "clx": clx_path,
                    "mac": self.clx_overrides["mac"],
                    "dev_id": self.clx_overrides["dev_id"],
                    "subsys_id": self.clx_overrides["subsys_id"],
                    "subven_id": self.clx_overrides["subven_id"],
                    # "lanes": self.clx_overrides["lanes"],
                }

                aqc_path = DiagWrapper.create_aqc_file(aqc_data)

                params = "--password !h:ahT8uW6 --aqc {} --raise -s -v 2  --no_kickstart".format(aqc_path)
                res = DiagWrapper.exec_single(params, diag_dir)

                # Remove Diag driver
                log.info("<----- Remove Diag driver ----->")
                self.diag_drv.uninstall()

            except Exception:
                self.state.fw_install_cold_restart = False
                self.state.update()
                raise

            time.sleep(10)
            self.cold_restart(self.dut_hostname)
        else:
            self.state.fw_install_cold_restart = False
            self.state.update()

    def dump_fw(self, dump_name):
        dump_cmd = "cd {} && flashDump -d {} -o {}".format(
            self.test_tmp_dir, get_lspci_port(self.dut_port), dump_name)
        Command(cmd=dump_cmd, host=self.dut_hostname).run()

    def dump_vpd(self, clx_file, dump_name):
        clx_info_cmd = "cd {} && clxoverride -i {}".format(self.test_tmp_dir, clx_file)
        res = Command(cmd=clx_info_cmd, host=self.dut_hostname, silent=True).run()

        vpd_offset = None
        vpd_size = None
        for line in res["output"]:
            m = re.match(".*vpdOffset\s*=\s0x([0-9a-f]+).*", line, flags=re.IGNORECASE)
            if m is not None:
                vpd_offset = int(m.group(1), 16)
                continue
            m = re.match(".*vpdSize\s*=\s0x([0-9a-f]+).*", line, flags=re.IGNORECASE)
            if m is not None:
                vpd_size = int(m.group(1), 16)
                continue

        assert vpd_offset is not None
        assert vpd_size is not None
        log.info("VPD Offset: {}, VPD size: {}".format(vpd_offset, vpd_size))
        dump_cmd = "cd {} && dd if={} of={} bs=1 count={} skip={} conv=notrunc".format(
            self.test_tmp_dir, clx_file, dump_name, vpd_size, vpd_offset)
        Command(cmd=dump_cmd, host=self.dut_hostname).run()

    def mark_ncb(self, clx_file, ncb):
        mark = "ncb{}".format(ncb)
        dram_pointer = "0x32" if ncb == 0 else "0x4032"
        get_offset_cmd = "xxd -s {} -l 3 -e {}".format(dram_pointer, clx_file)
        res = Command(cmd=get_offset_cmd, host=self.dut_hostname).run()
        re_xxd = re.compile("\s*\d+:\s*([a-z0-9]+)", flags=re.IGNORECASE)
        dram_offset = int(re_xxd.match(res["output"][0]).group(1), 16) + 0x10008
        mark_cmd = "echo {} | dd of={} bs=1 count=4 seek={} conv=notrunc".format(mark, clx_file, dram_offset)
        Command(cmd=mark_cmd, host=self.dut_hostname).run()
        Command(cmd="clxoverride -u {}".format(clx_file), host=self.dut_hostname).run()

    def check_ncb(self, ncb):
        mark = "ncb{}".format(ncb)

        res = Command(cmd="atltool -d {} -rm 0x1fb10008".format(get_lspci_port(self.dut_port)),
                      host=self.dut_hostname).run()
        re_mem = re.compile(".*Memory\sat\s0x[0-9a-f]+: \[(0x[0-9a-f]+)\]", flags=re.IGNORECASE)
        for line in res["output"]:
            if "Memory at" in line:
                m = re_mem.match(line)
                if m is not None:
                    # assert m.group(1) == mark_check
                    assert m.group(1)[2:].decode('hex', )[::-1] == mark
                    break
        else:
            raise Exception("NCB mark is not found")

    def copy_bundle_to_test_dir(self):
        log.info(">> Copy bundle... <<")
        res = Command(cmd="cp {}/* {}".format(self.flash_tool_dir, self.test_tmp_dir), host=self.dut_hostname).run()
        assert res["reason"] == Command.REASON_OK
        assert res["returncode"] == 0

    def run_atl_flash_update(self, failed=False, skip_driver_install=False, check_connection=True):
        # Install Prod driver
        self.remove_drivers()
        if not skip_driver_install:
            log.info("<----- Install NDIS driver ----->")
            self.dut_driver.install()
            if check_connection:
                self.check_connection()

        cmd = "{}/atlflashupdate.exe -s".format(self.test_tmp_dir)
        res = Command(cmd=cmd, live_output=True).run_join(timeout=120)
        assert (res["returncode"] == 0) ^ failed

        self.check_logs_created()

        return res

    def perform_update(self):
        """
        Checks:
            1. Logs created
            2. Dump created and equal to original clx
            3. FW version is updated
            4. PCIROM version is updated
            5. PCI config does not changed after update
            6. VPD does not changed after update
            7. BDP Updated
            8. Connection is working
            #  Save etl logs
        """

        if not self.state.skip_reboot:
            try:
                log.info("<----- Update phase ----->")

                if self.dut_fw_card in FELICITY_CARDS:
                    log.info("Wait 15 sec...")
                    time.sleep(15)

                self.state.fw_install_cold_restart = True
                self.state.skip_reboot = True
                self.state.update()

                # Dump VPD origin
                origin_dump = "origin_clx_dump.bin"
                origin_vpd = "origin_vpd.bin"
                self.dump_fw(dump_name=origin_dump)
                self.dump_vpd(clx_file=origin_dump, dump_name=origin_vpd)

                # Update
                self.copy_bundle_to_test_dir()
                self.run_atl_flash_update()

                # Dump VPD update
                update_dump = "update_clx_dump.bin"
                update_vpd = "update_vpd.bin"
                self.dump_fw(dump_name=update_dump)
                self.dump_vpd(clx_file=update_dump, dump_name=update_vpd)

                # Check VPD
                self.compare_dumps(origin_vpd, update_vpd)

                # Check BDP
                self.check_bdp(update_dump)

                flash_dump = self.check_dump_saved()
                self.compare_dumps(origin_dump, flash_dump)
                self.check_driver_aqnicnvn_removed()

            except Exception:
                self.state.skip_reboot = False
                self.state.fw_install_cold_restart = False
                self.state.update()
                raise

            # "To complete update process please power cycle your PC
            # if any("power cycle your PC" in line for line in res["output"]):
            self.cold_restart(self.dut_hostname)

        self.state.skip_reboot = False
        self.state.fw_install_cold_restart = False
        self.state.update()

        log.info("<----- Final phase ----->")

        pattern = '([0-9.]+)_([0-9.]+)_([0-9.]+)'
        tool_ver, fw_ver, build = re.match(pattern, self.bundle_version).groups()
        fw_version = '3x/' + fw_ver

        stat = readstat(port=self.dut_port, host=self.dut_hostname, attempts=3)

        assert stat["fw_version"]["value"] == self.get_actual_firmware_version(fw_version)
        assert stat["pcirom"]["value"] == self.get_actual_pcirom_version(fw_version)
        # assert stat["lanes"]["value"] == self.clx_overrides["lanes"] # TODO: Check FAILED
        assert stat["mac"]["value"] == self.clx_overrides["mac"]
        assert int(stat["device_id"]["value"], 16) == self.clx_overrides["dev_id"]
        assert int(stat["subvid"]["value"], 16) == self.clx_overrides["subven_id"]
        assert int(stat["subdid"]["value"], 16) == self.clx_overrides["subsys_id"]

        self.check_connection()

    # Checks

    def check_logs_created(self):
        res = Command(cmd="cd {} && ls logs/*/*.etl".format(self.test_tmp_dir), host=self.dut_hostname).run()
        assert res["returncode"] == 0, "Logs is not created"

        logs_path = os.path.join(self.test_tmp_dir, res['output'][0])
        shutil.copy(logs_path, self.test_log_dir)

    def check_dump_saved(self):
        res = Command(cmd="cd {} && ls logs/*/*.bin".format(self.test_tmp_dir), host=self.dut_hostname).run()
        assert res["returncode"] == 0, "Dump is not created"
        return res["output"][0]

    def compare_dumps(self, origin_dump, update_dump):
        compare_cmd = "cd {} && fc.exe {} {}".format(self.test_tmp_dir, origin_dump, update_dump)
        res = Command(cmd=compare_cmd, host=self.dut_hostname).run()
        assert res["returncode"] == 0, "Dumps is not equal"

    def check_driver_aqnicnvn_removed(self):
        res = Command(cmd="sc query aqnicnvm", host=self.dut_hostname).run()
        assert res["returncode"] != 0, "Aqnicnvm driver is not removed after update"

    def read_bdp_list(self):
        import xml.etree.ElementTree as ET
        xml_path = os.path.join(self.test_tmp_dir, 'updatedata.xml')
        xml_path = os.path.normcase(xml_path)

        tree = ET.parse(xml_path)
        root = tree.getroot()

        xml_bdp_list = []
        for xml_bdp in root:
            xml_bdp_list.append({'hwids': [], 'mac': None, 'phy': None, 'image': None})
            for child in xml_bdp:
                if 'hwids' in child.tag:
                    for hwid in child:
                        xml_bdp_list[-1]['hwids'].append(hwid.attrib)
                if 'mac' in child.tag:
                    xml_bdp_list[-1]['mac'] = child.text
                if 'phy' in child.tag:
                    xml_bdp_list[-1]['phy'] = child.text
                if 'image' in child.tag:
                    xml_bdp_list[-1]['image'] = child.text
        return xml_bdp_list

    def check_bdp(self, dump_name):
        xml_bdp_list = self.read_bdp_list()

        target_ids = {
            'vid': '1d6a',
            'did': '{:04x}'.format(self.clx_overrides["dev_id"]),
            'sdid': '{:04x}'.format(self.clx_overrides["subsys_id"]),
            'svid': '{:04x}'.format(self.clx_overrides["subven_id"])
        }

        xml_found_bdp = None
        for xml_bdp_row in xml_bdp_list:
            if target_ids in xml_bdp_row['hwids']:
                xml_found_bdp = xml_bdp_row

        assert xml_found_bdp is not None, 'BDP for ids: {} is not found.'.format(target_ids)

        # MAC
        dirty_wake = "02010000c000000000000000010000000100000000000000"
        no_dirty_wake = "02010000c000000000000000000000000100000000000000"
        dw_prov = dirty_wake if self.dut_fw_dirtywake else no_dirty_wake

        # PHY
        mdi_swap = "0301840000e4030003000000"
        mdi_normal = "0301840000e4020003000000"
        mdi_prov = mdi_normal if self.dut_fw_mdi == 'MDINormal' else mdi_swap

        clx_info_cmd = "cd {} && clxoverride -i {}".format(self.test_tmp_dir, dump_name)
        res = Command(cmd=clx_info_cmd, host=self.dut_hostname, silent=True).run()

        fl_mac = False
        fl_phy = False
        mac_str = ""
        phy_str = ""
        for line in res['output']:
            if ":" in line:
                fl_mac = fl_phy = False
            if "MAC Board Dependent Provision" in line:
                fl_mac = True
                continue
            if "PHY Board Dependent Provision" in line:
                fl_phy = True
                continue

            if fl_mac:
                mac_str += line.replace(" ", "")

            if fl_phy:
                phy_str += line.replace(" ", "")

        def reverse_bytes(bs, fr_size):
            lines = ""
            for fr_offset in range(len(bs) / fr_size):
                for bt_offset in range(fr_size / 2):
                    lines += bs[fr_size * fr_offset:fr_size * (fr_offset + 1)][
                             fr_size - (2 * (bt_offset + 1)):fr_size - (2 * bt_offset)]
            return lines

        mac_bdp = reverse_bytes(mac_str, fr_size=8).lower()
        phy_bdp = reverse_bytes(phy_str, fr_size=4).lower()

        log.info('DirtyWake: {}'.format(self.dut_fw_dirtywake))
        log.info('DirtyWake PROV: {}'.format(dw_prov))

        log.info("MDI: {}".format(self.dut_fw_mdi))
        log.info("MDI PROV: {}".format(mdi_prov))

        log.info('IDS: {}'.format(target_ids))

        log.info("XML MAC BDP: {}".format(xml_found_bdp['mac']))
        log.info("XML PHY BDP: {}".format(xml_found_bdp['phy']))

        log.info("FW MAC BDP: {}".format(mac_bdp))
        log.info("FW PHY BDP: {}".format(phy_bdp))

        if xml_found_bdp['mac'] is not None:
            assert mac_bdp.startswith(xml_found_bdp['mac'][:-8].lower())
        if xml_found_bdp['phy'] is not None:
            assert phy_bdp.startswith(xml_found_bdp['phy'][:-4].lower())

        if (self.clx_overrides["subsys_id"] == 0x0001
                and self.clx_overrides["subven_id"] == 0x1d6a):
            assert mac_bdp.endswith(dw_prov)
            assert phy_bdp.endswith(mdi_prov)
        else:
            log.info("CHECK SKIPPED IDS: sdid: 0x{:x}, svid: 0x{:x} ".format(
                self.clx_overrides["subsys_id"], self.clx_overrides["subven_id"]))

    def check_connection(self):
        # NIC is active again
        self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, gateway=None)
        self.lkp_ifconfig.set_ip_address(self.LKP_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, gateway=None)
        if self.lkp_fw_card in FELICITY_CARDS or self.dut_fw_card in FELICITY_CARDS:
            speed = self.supported_speeds[-1]
            self.dut_ifconfig.set_link_speed(speed)
            self.lkp_ifconfig.set_link_speed(speed)
        else:
            self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            self.dut_ifconfig.set_link_speed(self.supported_speeds[-1])
        self.dut_ifconfig.wait_link_up(retry_interval=2)
        time.sleep(3)
        assert self.ping(self.dut_hostname, self.LKP_IPV4_ADDR, number=10)

    # Runs

    def run_update_ncb_activ_nic(self, activ_ncb):
        firmware_clx = self.download_fw(self.fw_ver_3_1_62)

        # Disable NCB
        Command(cmd="clxoverride --ncb{} 0 {}".format(int(not activ_ncb), firmware_clx), host=self.dut_hostname).run()
        Command(cmd="flashBurn -d {} {}".format(get_lspci_port(self.dut_port), firmware_clx),
                host=self.dut_hostname).run()
        Command(cmd="kickstart", host=self.dut_hostname).run()

        self.copy_bundle_to_test_dir()
        self.run_atl_flash_update()

        # TODO: Check active NCB via readstat
        dump_name = "dump.bin"
        self.dump_fw(dump_name=dump_name)
        re_val = re.compile("\s*\d+:\s*([a-z0-9]+)", flags=re.IGNORECASE)

        ncb0_cmd = " cd {} && xxd -s 0x3 -l 1 -e {}".format(self.test_tmp_dir, dump_name)
        res = Command(cmd=ncb0_cmd, host=self.dut_hostname).run()
        val = int(re_val.match(res["output"][0]).group(1), 16) >> 6
        assert val == (0 if activ_ncb == 0 else 2)

        ncb1_cmd = " cd {} && xxd -s 0x4003 -l 1 -e {}".format(self.test_tmp_dir, dump_name)
        res = Command(cmd=ncb1_cmd, host=self.dut_hostname).run()
        val = int(re_val.match(res["output"][0]).group(1), 16) >> 6
        assert val == (2 if activ_ncb == 0 else 0)

    def run_update_ncb_activ_clx(self, activ_ncb):
        if not self.state.skip_reboot:
            self.state.skip_reboot = True
            self.state.update()

            try:
                self.install_fw(self.fw_ver_3_1_62)
                self.copy_bundle_to_test_dir()

                cmd = 'cd {} && readlink -e *{}*.clx'.format(self.test_tmp_dir, self.dut_fw_card)
                res = Command(cmd=cmd, host=self.dut_hostname).run()
                new_firmware_clx = res['output'][0].strip()

                # Disable NCB
                cmd = "clxoverride --ncb{} 0 {}".format(activ_ncb ^ 1, new_firmware_clx)
                Command(cmd=cmd, host=self.dut_hostname).run()

                if not self.dut_sign:
                    self.mark_ncb(new_firmware_clx, activ_ncb)
                self.run_atl_flash_update()

            except Exception:
                self.state.skip_reboot = False
                self.state.update()
                raise
            time.sleep(10)
            self.cold_restart(self.dut_hostname)
        else:
            self.state.skip_reboot = False
            self.state.update()

        if not self.dut_sign:
            self.check_ncb(activ_ncb)

    def run_update_ncb_wrong_crc(self, ncb):
        self.install_fw(self.fw_ver_3_1_62)
        self.copy_bundle_to_test_dir()

        cmd = 'cd {} && readlink -e *{}*.clx'.format(self.test_tmp_dir, self.dut_fw_card)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        new_firmware_clx = res['output'][0].strip()

        if not self.dut_sign:
            marked_ncb = 1 if ncb == 0 else 0
            self.mark_ncb(new_firmware_clx, marked_ncb)

        seek = 0 if ncb == 0 else 16384
        corrupt_crc_cmd = "dd if=/dev/zero of={} bs=1 count=2 seek={} conv=notrunc".format(new_firmware_clx, seek)
        Command(cmd=corrupt_crc_cmd, host=self.dut_hostname).run()

        self.run_atl_flash_update()

        if not self.dut_sign:
            self.check_ncb(marked_ncb)

    # Tests

    def test_update_no_driver(self):
        self.copy_bundle_to_test_dir()
        res = self.run_atl_flash_update(failed=True, skip_driver_install=True)

        assert any("No Aquantia network adapter found" in line for line in res["output"])
        self.check_logs_created()

    def test_update_no_clx(self):
        self.copy_bundle_to_test_dir()
        Command(cmd="cd {} && rm *.clx".format(self.test_tmp_dir), host=self.dut_hostname).run()
        res = self.run_atl_flash_update(failed=True)

        assert any("No adapters can be updated" in line for line in res["output"])
        self.check_logs_created()

    def test_update_no_xml(self):
        self.copy_bundle_to_test_dir()
        Command(cmd="cd {} && rm *.xml".format(self.test_tmp_dir), host=self.dut_hostname).run()
        res = self.run_atl_flash_update(failed=True)

        assert any("Couldn't load data from XML file" in line for line in res["output"])
        self.check_logs_created()

    def test_update_rename_xml(self):
        self.copy_bundle_to_test_dir()
        Command(cmd="cd {} && mv *.xml test.xml".format(self.test_tmp_dir), host=self.dut_hostname).run()
        res = self.run_atl_flash_update(failed=True)

        assert any("Couldn't load data from XML file" in line for line in res["output"])
        self.check_logs_created()

    def test_update_corrupted_xml(self):
        self.copy_bundle_to_test_dir()
        cmd = "cd {} && dd if=/dev/random of={} bs=1 count=20 seek=10 conv=notrunc".format(self.test_tmp_dir,
                                                                                           "updatedata.xml")
        Command(cmd=cmd.format(self.test_tmp_dir), host=self.dut_hostname).run()
        res = self.run_atl_flash_update(failed=True)

        assert any("Couldn't load data from XML file" in line for line in res["output"])
        self.check_logs_created()

    def test_update_same_fw_version(self):
        pattern = '([0-9.]+)_([0-9.]+)_([0-9.]+)'
        tool_ver, fw_ver, build = re.match(pattern, self.bundle_version).groups()
        fw_version = '3x/' + fw_ver

        self.install_fw(fw_version)
        self.copy_bundle_to_test_dir()
        res = self.run_atl_flash_update(failed=True)

        assert any("No adapters can be updated" in line for line in res["output"])
        self.check_logs_created()

    def test_update_ncb0_activ_nic(self):
        self.run_update_ncb_activ_nic(activ_ncb=0)

    def test_update_ncb1_activ_nic(self):
        self.run_update_ncb_activ_nic(activ_ncb=1)

    def test_update_ncb0_activ_clx(self):
        self.run_update_ncb_activ_clx(activ_ncb=0)

    def test_update_ncb1_activ_clx(self):
        self.run_update_ncb_activ_clx(activ_ncb=1)

    def test_update_both_ncb_disabled_clx(self):
        self.copy_bundle_to_test_dir()

        cmd = 'cd {} && readlink -e *{}*.clx'.format(self.test_tmp_dir, self.dut_fw_card)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        new_firmware_clx = res['output'][0].strip()

        # Disable NCB0
        Command(cmd="clxoverride --ncb0 0 {}".format(new_firmware_clx), host=self.dut_hostname).run()

        # Disable NCB1
        Command(cmd="clxoverride --ncb1 0 {}".format(new_firmware_clx), host=self.dut_hostname).run()

        self.run_atl_flash_update(failed=True)

    def test_update_ncb0_wrong_crc(self):
        self.run_update_ncb_wrong_crc(ncb=0)

    def test_update_ncb1_wrong_crc(self):
        self.run_update_ncb_wrong_crc(ncb=1)

    def test_update_both_ncb_wrong_crc(self):
        self.install_fw(self.fw_ver_3_1_62)
        self.copy_bundle_to_test_dir()

        cmd = 'cd {} && readlink -e *{}*.clx'.format(self.test_tmp_dir, self.dut_fw_card)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        new_firmware_clx = res['output'][0].strip()

        # Corrupt CRC NCB0
        corrupt_crc_cmd = "dd if=/dev/zero of={} bs=1 count=2 seek=0 conv=notrunc".format(new_firmware_clx)
        Command(cmd=corrupt_crc_cmd, host=self.dut_hostname).run()

        # Corrupt CRC NCB1
        corrupt_crc_cmd = "dd if=/dev/zero of={} bs=1 count=2 seek=16384 conv=notrunc".format(new_firmware_clx)
        Command(cmd=corrupt_crc_cmd, host=self.dut_hostname).run()

        self.run_atl_flash_update(failed=True)

    def test_ncb0_activ_wrong_crc_ncb1_disabled(self):
        self.install_fw(self.fw_ver_3_1_62)
        self.copy_bundle_to_test_dir()

        cmd = 'cd {} && readlink -e *{}*.clx'.format(self.test_tmp_dir, self.dut_fw_card)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        new_firmware_clx = res['output'][0].strip()

        # Corrupt CRC NCB0
        corrupt_crc_cmd = "dd if=/dev/zero of={} bs=1 count=2 seek=0 conv=notrunc".format(new_firmware_clx)
        Command(cmd=corrupt_crc_cmd, host=self.dut_hostname).run()

        # Disable NCB1
        Command(cmd="clxoverride --ncb1 0 {}".format(new_firmware_clx), host=self.dut_hostname).run()

        self.run_atl_flash_update(failed=True)

    def test_ncb1_activ_wrong_crc_ncb0_disabled(self):
        self.install_fw(self.fw_ver_3_1_62)
        self.copy_bundle_to_test_dir()

        cmd = 'cd {} && readlink -e *{}*.clx'.format(self.test_tmp_dir, self.dut_fw_card)
        res = Command(cmd=cmd, host=self.dut_hostname).run()
        new_firmware_clx = res['output'][0].strip()

        # Corrupt CRC NCB1
        corrupt_crc_cmd = "dd if=/dev/zero of={} bs=1 count=2 seek=16384 conv=notrunc".format(new_firmware_clx)
        Command(cmd=corrupt_crc_cmd, host=self.dut_hostname).run()

        # Disable NCB0
        Command(cmd="clxoverride --ncb0 0 {}".format(new_firmware_clx), host=self.dut_hostname).run()

        self.run_atl_flash_update(failed=True)

    def test_apply_bdp_dirty_wake_on(self):
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip()
        try:
            self.dut_fw_dirtywake = True

            self.install_fw_diag(self.fw_ver_3_1_62)
            self.copy_bundle_to_test_dir()
            self.run_atl_flash_update(check_connection=False)

            update_dump = "update_clx_dump.bin"
            self.dump_fw(dump_name=update_dump)
            self.check_bdp(update_dump)

        finally:
            self.dut_fw_dirtywake = str_to_bool(os.environ.get("DUT_FW_DIRTYWAKE", "NO"))

    def test_apply_bdp_dirty_wake_off(self):
        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip()
        try:
            self.dut_fw_dirtywake = False

            self.install_fw_diag(self.fw_ver_3_1_62)
            self.copy_bundle_to_test_dir()
            self.run_atl_flash_update(check_connection=False)

            update_dump = "update_clx_dump.bin"
            self.dump_fw(dump_name=update_dump)
            self.check_bdp(update_dump)

        finally:
            self.dut_fw_dirtywake = str_to_bool(os.environ.get("DUT_FW_DIRTYWAKE", "NO"))

    def test_apply_bdp_mdi_swap(self):
        if (self.dut_fw_card in FELICITY_CARDS or
                self.dut_fw_card in BERMUDA_CARDS):
            pytest.skip()

        try:
            self.dut_fw_mdi = MDI_SWAP
            self.dut_bdp = 'Jasmine'

            self.install_fw_diag(self.fw_ver_3_1_62)
            self.copy_bundle_to_test_dir()
            self.run_atl_flash_update(check_connection=False)

            update_dump = "update_clx_dump.bin"
            self.dump_fw(dump_name=update_dump)
            self.check_bdp(update_dump)

        finally:
            self.dut_fw_mdi = os.environ.get("DUT_FW_MDI", None)

    def test_apply_bdp_non_aq_ids(self):
        if self.dut_fw_card in BERMUDA_CARDS:
            did = 0x11b1
            sdid = 0x8772
            svid = 0x1043
        elif self.dut_fw_card in FELICITY_CARDS:
            did = 0xd100
            sdid = 0x101b
            svid = 0x20f4
        else:
            did = 0x07b1
            sdid = 0x0873
            svid = 0x1028

        self.clx_overrides["dev_id"] = did
        self.clx_overrides["subsys_id"] = sdid
        self.clx_overrides["subven_id"] = svid

        try:
            self.install_fw_diag(self.fw_ver_3_1_62)
            self.copy_bundle_to_test_dir()
            self.run_atl_flash_update(check_connection=False)

            update_dump = "update_clx_dump.bin"
            self.dump_fw(dump_name=update_dump)
            self.check_bdp(update_dump)
        finally:
            self.clx_overrides["dev_id"] = self.default_did
            self.clx_overrides["subsys_id"] = self.default_sdid
            self.clx_overrides["subven_id"] = self.default_svid

    def test_update_from_fw_1x(self):
        if self.dut_fw_card in FELICITY_CARDS or self.dut_fw_card in BERMUDA_CARDS:
            pytest.skip()

        self.install_fw_diag(self.fw_ver_1_5_58)
        self.perform_update()

    def test_update_from_fw_3x(self):
        self.install_fw_diag(self.fw_ver_3_1_75)
        self.perform_update()


if __name__ == "__main__":
    exec_list = [__file__, "-s", "-v"]
    if len(sys.argv) > 1:
        exec_list.append("-k {}".format(' '.join(sys.argv[1:])))
        exec_list[-1] += os.environ.get('TEST_FILTER', '')
    log.info('exec_list: {}'.format(exec_list))
    pytest.main(exec_list)
