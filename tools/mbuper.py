import argparse
import io
import os
import re
import sys
import tempfile
import time
import timeit
import urlparse
import zipfile
from abc import abstractmethod, ABCMeta
import logging

import yaml

from command import Command
import constants
from constants import BUILDS_SERVER, ATF_TOOLS_DIR
from constants import LINUX_OSES, OS_MAC_10_12
from utils import get_atf_logger, remove_directory, upload_file, SpacedArgAction, get_url_response

# Set AQ_DEVICEREV environment variable to B1 to be able to override B1 device ID's on B0 chip
os.environ["AQ_DEVICEREV"] = "B1"

log = get_atf_logger()

LINK_SPEED_TO_REG_VAL_MAP = {
    constants.LINK_SPEED_NO_LINK: 0,
    constants.LINK_SPEED_100M: 0x20,
    constants.LINK_SPEED_1G: 0x10,
    constants.LINK_SPEED_2_5G: 0x8,
    constants.LINK_SPEED_5G: 0x2,
    constants.LINK_SPEED_10G: 0x1,
    constants.LINK_SPEED_AUTO: 0xFF,
}

REG_VAL_TO_LINK_SPEED_MAP = {
    0: constants.LINK_SPEED_NO_LINK,
    0x20: constants.LINK_SPEED_100M,
    0x10: constants.LINK_SPEED_1G,
    0x8: constants.LINK_SPEED_2_5G,
    0x2: constants.LINK_SPEED_5G,
    0x1: constants.LINK_SPEED_10G,
    0xFFFF: constants.LINK_SPEED_AUTO,
}

LINK_SPEED_TO_REG_VAL_MAP_2X = {
    constants.LINK_SPEED_NO_LINK: 0,
    constants.LINK_SPEED_100M: 0x20,
    constants.LINK_SPEED_1G: 0x100,
    constants.LINK_SPEED_2_5G: 0x200,
    constants.LINK_SPEED_5G: 0x400,
    constants.LINK_SPEED_10G: 0x800,
    constants.LINK_SPEED_AUTO: 0xF20,
}

REG_VAL_TO_LINK_SPEED_MAP_2X = {
    0: constants.LINK_SPEED_NO_LINK,
    0x20: constants.LINK_SPEED_100M,
    0x100: constants.LINK_SPEED_1G,
    0x200: constants.LINK_SPEED_2_5G,
    0x400: constants.LINK_SPEED_5G,
    0x800: constants.LINK_SPEED_10G,
    0xF20: constants.LINK_SPEED_AUTO
}

LINK_SPEED_TO_REG_VAL_MAP_2X_ALL_AUTO = {
    constants.LINK_SPEED_100M: 0x20,
    constants.LINK_SPEED_1G: 0x20 | 0x100,
    constants.LINK_SPEED_2_5G: 0x20 | 0x100 | 0x200,
    constants.LINK_SPEED_5G: 0x20 | 0x100 | 0x200 | 0x400,
    constants.LINK_SPEED_10G: 0x20 | 0x100 | 0x200 | 0x400 | 0x800
}

REG_VAL_TO_LINK_SPEED_MAP_2X_ALL_AUTO = {
    0: constants.LINK_SPEED_NO_LINK,
    0x20: constants.LINK_SPEED_100M,
    0x20 | 0x100: constants.LINK_SPEED_1G,

    0x20 | 0x100 | 0x200: constants.LINK_SPEED_2_5G,
    0x20 | 0x200: constants.LINK_SPEED_2_5G,
    0x100 | 0x200: constants.LINK_SPEED_2_5G,

    0x20 | 0x100 | 0x200 | 0x400: constants.LINK_SPEED_5G,
    0x20 | 0x100 | 0x400: constants.LINK_SPEED_5G,
    0x100 | 0x200 | 0x400: constants.LINK_SPEED_5G,
    0x20 | 0x200 | 0x400: constants.LINK_SPEED_5G,
    0x200 | 0x400: constants.LINK_SPEED_5G,
    0x100 | 0x400: constants.LINK_SPEED_5G,
    0x20 | 0x400: constants.LINK_SPEED_5G,

    0x20 | 0x100 | 0x200 | 0x400 | 0x800: constants.LINK_SPEED_10G,
    0x20 | 0x100 | 0x200 | 0x800: constants.LINK_SPEED_10G,
    0x20 | 0x100 | 0x400 | 0x800: constants.LINK_SPEED_10G,
    0x20 | 0x200 | 0x400 | 0x800: constants.LINK_SPEED_10G,
    0x100 | 0x200 | 0x400 | 0x800: constants.LINK_SPEED_10G,
    0x200 | 0x400 | 0x800: constants.LINK_SPEED_10G,
    0x100 | 0x400 | 0x800: constants.LINK_SPEED_10G,
    0x20 | 0x400 | 0x800: constants.LINK_SPEED_10G,
    0x20 | 0x200 | 0x800: constants.LINK_SPEED_10G,
    0x100 | 0x200 | 0x800: constants.LINK_SPEED_10G,
    0x20 | 0x100 | 0x800: constants.LINK_SPEED_10G,
    0x20 | 0x800: constants.LINK_SPEED_10G,
    0x100 | 0x800: constants.LINK_SPEED_10G,
    0x200 | 0x800: constants.LINK_SPEED_10G,
    0x400 | 0x800: constants.LINK_SPEED_10G,
}

LINK_STATE_DOWN = 0x0
LINK_STATE_UP = 0x2
LINK_STATE_SLEEP = 0x4

LINK_CONTROL_TRANSACTION_ID = 0x80000000
LINK_CONTROL_LINK_DROP = 0x400000
LINK_CONTROL_SLEEP_PROXY = 0x800000
LINK_CONTROL_WOL = 0x1000000
LINK_CONTROL_TPO2 = 0x1
LINK_CONTROL_PTP_AVB = 0x100000

SCRIPT_STATUS_SUCCESS = "[MBU-WRAPPER-SUCCESS]"
SCRIPT_STATUS_FAILED = "[MBU-WRAPPER-FAILED]"


def download_mbu(version, base_dir=None):
    if base_dir is None:
        directory = tempfile.mkdtemp()
    else:
        directory = os.path.join(base_dir, "mbu")
        remove_directory(directory)
        if not os.path.exists(directory):
            # if it could be deleted on previous step
            os.mkdir(directory)

    # TODO: this is temporary workaround while we don't have MBU build
    # jobs for all supported platforms
    if version == "universal":
        op_sys = os.environ["ATF_OS"]
        if op_sys in LINUX_OSES + [OS_MAC_10_12]:
            suburl = "mbu/{}/{}.zip".format(version, op_sys)
        else:
            suburl = "mbu/{}/Windows.zip".format(version, op_sys)
    else:
        suburl = "mbu/{}/mbu.zip".format(version)

    url = urlparse.urljoin(BUILDS_SERVER, suburl)
    log.info("Downloading MBU from {}".format(url))
    content = get_url_response(url)
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            archive.extractall(directory)
    except zipfile.BadZipfile:
        log.warning("Failed extract zip file using python, trying 7z")
        with open("mbu.zip", "wb") as f:
            f.write(content)
        res = Command(cmd="7z x mbu.zip -o{}".format(directory)).wait(30)
        if res["returncode"] != 0:
            raise Exception("Failed to extract zip file using 7z")
    log.info("MBU has been downloaded and extracted to {}".format(directory))
    return directory


class KickstartError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class MbuWrapper(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost":
            return object.__new__(MbuWrapperLocal)
        else:
            return object.__new__(MbuWrapperRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]
        self.version = kwargs.get("version", "latest")

    @abstractmethod
    def exec_txt(self, file):
        pass

    @abstractmethod
    def exec_beton(self, data):
        pass

    @abstractmethod
    def readreg(self, addr):
        pass

    @abstractmethod
    def readphyreg(self, addr, phyId=-1):
        pass

    @abstractmethod
    def writereg(self, addr, value, silent=False):
        pass

    @abstractmethod
    def writephyreg(self, addr, value):
        pass

    @abstractmethod
    def kickstart(self, reload_phy_fw=True, clx_for_flashless=None, force_flashless=False):
        pass

    @abstractmethod
    def destroy(self):
        pass

    @abstractmethod
    def get_adapter_speed(self):
        pass

    def get_fw_version(self):
        version = self.readreg(0x18)
        ver_major = version >> 24
        ver_minor = (version >> 16) & 0xff
        ver_release = version & 0xffff
        return ver_major, ver_minor, ver_release

    @abstractmethod
    def flash_load_clx(self, filename):
        pass

    @abstractmethod
    def dump_to_config_memory(self, data):
        pass


class MbuWrapperLocal(MbuWrapper):
    INSTANCE_TITLE = "mbu_wrapper"

    def __init__(self, **kwargs):
        super(MbuWrapperLocal, self).__init__(**kwargs)
        self.mbu_dir = kwargs["mbu_dir"]
        self.scripts_dir = os.path.join(self.mbu_dir, "scripts")

        sys.path.append(os.path.join(self.mbu_dir, "CLI"))
        sys.path.append(os.path.join(self.mbu_dir, "MAC"))
        sys.path.append(os.path.join(self.mbu_dir, "Common"))
        sys.path.append(os.path.join(self.mbu_dir, "PlatformDrivers"))
        sys.path.append(os.path.join(self.mbu_dir, "NoPhyCon"))
        sys.path.append(os.path.join(self.mbu_dir, "Tests"))

        import cliglobal
        import deviceProperty
        import logcontrol
        import maccontrol
        import maclib

        # TODO: hardcoded!!!
        devId = 0x79
        mem64 = True
        interrupt = ""

        mbu_logger = logging.getLogger('Mac BringUP')
        if mbu_logger.handlers[:]:
            raise Exception('MBU log handlers list is not empty! Please create only one MBU instance simultaneously!')

        self.mbu_instance = maclib.newInstance(self.INSTANCE_TITLE)
        mbu_instance_name = "{}_{}".format(self.INSTANCE_TITLE,
                                           self.mbu_instance.instance)

        fdir = os.path.dirname(os.path.abspath(__file__))
        log_cfg_file = os.path.join(fdir, "logging_with_mbu.conf")
        tmp_log_config = self._modify_log_config(log_cfg_file)
        logcontrol.parseLogOptions(tmp_log_config,
                                   instance=self.mbu_instance.instance,
                                   instanceName=mbu_instance_name)

        r = re.compile("^pci(.*)$")
        if r.match(self.port):
            fake_port = "pci0"
        else:
            fake_port = self.port

        self.mac_control = maccontrol.MacControl.create(fake_port,  # WTF it must
                                                        # be 0?
                                                        devId=devId,
                                                        memAccess64bit=mem64,
                                                        interrupt=interrupt.upper())
        self.mac_control.macAccess.info = {}
        self.mac_control.macAccess.info["port"] = self.port

        dev_config_path = os.path.join(self.mbu_dir, "device.cfg")
        deviceProperty.read_device_cfg_file(self.mac_control, dev_config_path)

        self.cli = cliglobal.cliGlobal(self.mac_control)
        self.set_var("PWD",
                     os.path.normpath(self.scripts_dir).replace("\\", "/"))

    def _modify_log_config(self, file):
        with open(file, "r") as f:
            log_cfg_data = yaml.load(f)
            print(log_cfg_data["handlers"]["wholelog"])
            for key, handler in log_cfg_data["handlers"].iteritems():
                if log_cfg_data["handlers"][key].get("filename") is not None:
                    log_cfg_data["handlers"][key]["filename"] = os.path.join(self.mbu_dir,
                                                                             log_cfg_data["handlers"][key]["filename"])

        fdir = os.path.dirname(file)
        tmp_file = os.path.join(fdir, "tmp_log_config_with_mbu.conf")
        with open(tmp_file, "w") as f:
            yaml.dump(log_cfg_data, f)
        return tmp_file

    def set_var(self, name, value):
        import commonCli
        commonCli.commonCli.vars[name] = value

    def get_var(self, name):
        import commonCli
        return commonCli.commonCli.vars.get(name, None)

    def exec_txt(self, file):
        origin_wd = os.getcwd()
        os.chdir(self.scripts_dir)

        if not os.path.isfile(file):
            file_dir = os.path.dirname(os.path.realpath(__file__))
            beton_dir = os.path.join(file_dir, "beton")
            os.chdir(beton_dir)
        try:
            self.cli.onecmd("exec {}".format(file))
        finally:
            os.chdir(origin_wd)

    def exec_beton(self, data):
        for cmd in data:
            self.cli.onecmd(cmd)

    def readreg(self, addr):
        read, = self.mac_control.getAccfunc("main", funcNameList=["read"])
        val = read(addr)
        log.info("Register 0x{:08x}: 0x{:08x}".format(addr, val))
        return val

    def readregs(self, addr):
        result = []
        for a in addr:
            result.append(self.readreg(a))
        return result

    def readreg_msm(self, addr):
        return self.mac_control.msmReadData(addr)

    def readregs_msm(self, addr):
        result = []
        for a in addr:
            result.append(self.readreg_msm(a))
        return result

    def readphyreg(self, addr, phy_id=-1):
        assert type(addr) is str
        addrs = addr.split(".")
        assert len(addrs) == 2
        phy_addr = (phy_id, int(addrs[0], 16), int(addrs[1], 16))
        read, = self.mac_control.getAccfunc("phy", funcNameList=["read"])
        val = read(phy_addr)
        log.info("Register PHY {}: 0x{:08x}".format(addr, val))
        return val

    def readregs_phy(self, addr, phyId=-1):
        result = []
        for a in addr:
            result.append(self.readphyreg(a))
        return result

    def writereg(self, addr, value, silent=False):
        write, = self.mac_control.getAccfunc("main", funcNameList=["write"])
        write(addr, value)
        if not silent:
            log.info("Register 0x{:08x}: 0x{:08x} written".format(addr, value))

    def writephyreg(self, addr, value, phy_id=-1):
        assert type(addr) is str
        addrs = addr.split(".")
        assert len(addrs) == 2
        phy_addr = (phy_id, int(addrs[0], 16), int(addrs[1], 16))
        write, = self.mac_control.getAccfunc("phy", funcNameList=["write"])
        write(phy_addr, value)
        log.info("Register PHY {} {}: 0x{:08x} written".format(phy_id, addr, value))

    def kickstart(self, reload_phy_fw=True, clx_for_flashless=None, force_flashless=False, use_phy_reset=False):
        # MAC FW is always reloaded
        # boot code is always reloaded
        assert use_phy_reset is False  # it must be always False, the code leaved for history
        log.info("Kickstarting MAC")
        for k in range(1000):
            flb_status = self.readreg(0x704)
            boot_exit_code = self.readreg(0x388)
            if flb_status != 0x06000000 or boot_exit_code != 0:
                break
            if k == 999:
                raise KickstartError('Neither RBL nor FLB started')

        if boot_exit_code != 0:
            rbl_enabled = True
        else:
            rbl_enabled = False

        if not rbl_enabled:
            log.info('RBL is not enabled')
            self.writereg(0x404, 0x40e1)
            # Let Felicity hardware to complete SMBUS transaction before Global software reset
            time.sleep(0.050)  # pause 50 ms

            # If SPI burst transaction was interrupted (before running the script), global software reset may not
            # clear SPI interface
            # Clean it up manualy before global reset
            nvrProv4 = self.readreg(0x53c)
            nvrProv4 |= 0x10
            self.writereg(0x53c, nvrProv4)

            reg_temp = self.readreg(0x0)
            reg_temp = (reg_temp & 0xBFFF) | 0x8000
            self.writereg(0x0, reg_temp)
            # time.sleep(0.010)  # pause 10 ms

            # Kickstart
            self.writereg(0x404, 0x80e0)
            self.writereg(0x32a8, 0x0)
            self.writereg(0x520, 1)
            # For the case SPI burst transaction was interrupted (by MCP reset above), reset SPI interface
            nvrProv4 = self.readreg(0x53c)
            nvrProv4reset = nvrProv4 | 0x10
            self.writereg(0x53c, nvrProv4reset)
            time.sleep(0.010)
            self.writereg(0x53c, nvrProv4)

            self.writereg(0x404, 0x180e0)
            for k in range(1000):
                flb_status = self.readreg(0x704)
                flb_status = flb_status & 0x10
                if flb_status != 0:
                    break
                time.sleep(0.010)  # pause 10 ms
            if flb_status == 0:
                raise KickstartError('MAC kickstart failed')
            k = k * 10
            log.info('MAC kickstart duration: {} ms'.format(k))

            self.writereg(0x404, 0x80e0)
            # Let Felicity hardware to complete SMBUS transaction before Global software reset
            time.sleep(0.050)  # pause 50 ms
            self.writereg(0x3a0, 1)

            # PHY Kickstart
            if reload_phy_fw:
                log.info("Kickstarting PHY")
                if use_phy_reset:
                    self.writephyreg("0x1e.0x2681", 1)
                else:
                    self.writephyreg("0x1e.0xc001", 0x41)
                    # This is to make sure reset will be triggered later with setting 1e.0.F, as rising edge is needed
                    self.writephyreg("0x1e.0x0", 0x0)
                    self.writephyreg("0x1e.0xc442", 0x1)
                    # Reset PHY
                    self.writephyreg("0x1e.0xC3FE", 0x0)
                    self.writephyreg("0x1e.0x0", 0x8000)
                    self.writephyreg("0x1e.0xc001", 0x0)
                # Without this pause, we sometimes get 0xFFFF from MDIO
                # Anyway, I put another protection against this below
                time.sleep(0.030)  # pause 30 ms
                for k in range(1000):
                    daisy_chain_status = self.readphyreg("0x1e.0xC841")
                    if daisy_chain_status != 0xFFFF:
                        daisy_chain_status = daisy_chain_status & 0x40
                        if daisy_chain_status != 0:
                            break
                    time.sleep(0.010)  # pause 10 ms

                if daisy_chain_status == 0:
                    raise KickstartError('PHY kickstart failed')
                k = k * 10
                log.info('PHY kickstart duration: {} ms'.format(k))

            log.info("Performing global software reset")
            reg_temp = self.readreg(0x5000)
            reg_temp = reg_temp & 0xDFFFFFFF
            self.writereg(0x5000, reg_temp)
            reg_temp = self.readreg(0x7000)
            reg_temp = reg_temp & 0xDFFFFFFF
            self.writereg(0x7000, reg_temp)
            reg_temp = self.readreg(0x4000)
            reg_temp = reg_temp & 0xDFFFFFFF
            self.writereg(0x4000, reg_temp)
            reg_temp = self.readreg(0x0)
            reg_temp = (reg_temp & 0xBFFF) | 0x8000
            self.writereg(0x0, reg_temp)

            for k in range(1000):
                restart_completed = self.readreg(0x18)
                if restart_completed != 0:
                    break
                time.sleep(0.010)  # pause 10 ms
            if restart_completed == 0:
                raise KickstartError('FW restart failed')
            k = k * 10
            log.info('Firmware restart duration: {} ms'.format(k))
        else:
            log.info('RBL is enabled')
            self.writereg(0x404, 0x40e1)
            self.writereg(0x3a0, 1)
            self.writereg(0x32a8, 0x0)
            # MAC FW will reload PHY FW if 1E.1000.3 was cleaned
            if reload_phy_fw:
                if use_phy_reset:
                    self.writephyreg("0x1e.0x2681", 1)
                else:
                    phy_control = self.readphyreg("0x1e.0x1000")
                    phy_control &= 0xfffffff7
                    self.writephyreg("0x1e.0x1000", phy_control)

            # Change RBL status so we can poll and know when boot completed (or entered flashless mode)
            # But don't reset it to 0, so script will never execute non-RBL branch
            self.writereg(0x388, 0xDEAD)

            # If SPI burst operation is in progress at the time when MCP is being stalled, next SPI interface
            # read request fails
            # Reset does not clear this state of SPI interface, so need  to reset it explicitly
            nvrProv4 = self.readreg(0x53c)
            nvrProv4 |= 0x10
            self.writereg(0x53c, nvrProv4)

            # Global software reset with cleaning all registers (this will restart RBL and reload MAC FW)
            log.info("Performing global software reset (restart RBL and reload MAC FW)")
            reg_temp = self.readreg(0x5000)
            reg_temp = reg_temp & 0xDFFFFFFF
            self.writereg(0x5000, reg_temp)
            reg_temp = self.readreg(0x7000)
            reg_temp = reg_temp & 0xDFFFFFFF
            self.writereg(0x7000, reg_temp)
            reg_temp = self.readreg(0x4000)
            reg_temp = reg_temp & 0xDFFFFFFF
            self.writereg(0x4000, reg_temp)
            reg_temp = self.readreg(0x0)
            reg_temp = (reg_temp & 0xFFFFBFFF) | 0x8000
            self.writereg(0x0, reg_temp)
            if force_flashless:
                self.writereg(0x534, 0)
            self.writereg(0x404, 0x40e0)

            log.info('Wait until RBL boot code completed')
            for k in range(1000):
                restart_completed = self.readreg(0x388)
                restart_completed = restart_completed & 0xFFFF
                if restart_completed != 0 and restart_completed != 0xDEAD:
                    break
                time.sleep(0.010)  # pause 10 ms
            if restart_completed == 0 or restart_completed == 0xDEAD:
                raise KickstartError('RBL restart failed')
            k = k * 10
            log.info('RBL restart duration: {} ms'.format(k))
            # Restore NVR interface
            if force_flashless:
                self.writereg(0x534, 0xA0)

            # We can perform flashless boot load here
            if restart_completed == 0xF1A7 and clx_for_flashless is not None:
                log.info('Loading FW from host: {}'.format(clx_for_flashless))
                self.exec_beton('mac.loadfw -f {} -C 0xe2'.format(clx_for_flashless))

            for k in range(1000):
                restart_completed = self.readreg(0x18)
                if restart_completed != 0:
                    break
                time.sleep(0.010)  # pause 10 ms
            if restart_completed == 0:
                raise KickstartError('FW restart failed')
            k = k * 10
            log.info('FW restart duration: {} ms'.format(k))

        time.sleep(3)  # to make sure Flash iface is not locked by reading from FW
        log.info("Kickstart is done")

    def get_adapter_speed(self):
        return self.mac_control.phyControl.getMaxSpeed()

    def destroy(self):
        self.mac_control.close()

        def remove_handlers(handlers):
            for handler in handlers:
                # remove all MBU log handlers (for all instances)
                log.info('Removing log handler: {}'.format(handler))
                handler.close()
                log.removeHandler(handler)

        mbu_logger = logging.getLogger('Mac BringUP')
        handlers = mbu_logger.handlers[:]
        remove_handlers(handlers)
        mbu_logger.handlers = []

        mcp_logger = logging.getLogger('Mac BringUP.mcp')
        handlers = mcp_logger.handlers[:]
        remove_handlers(handlers)
        mcp_logger.handlers = []

        # remove MBU instance
        del self.mbu_instance
        time.sleep(3)  # to make sure that diag driver handle is cleared

    def __del__(self):
        if hasattr(self, 'mbu_instance'):
            self.destroy()

    def exit(self):
        self.cli.onecmd("exit")
        # self.cli.destroy()

    def rollover_logs(self):
        import logcontrol
        logcontrol.rollover("wholelog")
        logcontrol.rollover("dvfile")
        logcontrol.rollover("scmpfile")

    def readlog(self, name):
        logdir = os.path.join(self.mbu_dir, "logs")
        log = os.path.join(logdir, next(obj for obj in os.listdir(logdir) if name in obj))
        with open(log, "r") as f:
            return f.read()

    def cleanup_logs(self):
        self.rollover_logs()
        remove_directory(os.path.join(self.mbu_dir, "logs"))

    def get_link_params(self):
        val = self.readreg(0x36c)
        downshift = val >> 24
        speed = REG_VAL_TO_LINK_SPEED_MAP.get((val >> 16) & 0xff, None)
        state = val & 0xffff
        return downshift, speed, state

    def set_link_params(self, speed, state, downshift_att=7):
        if downshift_att != -1:
            downshift_val = 1 << 3 | downshift_att
            val = downshift_val << 28 | LINK_SPEED_TO_REG_VAL_MAP[speed] << 16 | state
        else:
            val = LINK_SPEED_TO_REG_VAL_MAP[speed] << 16 | state

        self.writereg(0x368, val)
        if speed != constants.LINK_SPEED_AUTO and state == LINK_STATE_UP:
            for i in range(100):
                cur_val = self.readreg(0x36c)
                if cur_val == val:
                    return
                time.sleep(0.1)
            raise Exception("Failed to set link speed {}, state 0x{:x}".format(speed, state))

    def get_link_params_2x(self):
        val = self.readreg(0x370)
        # downshift = val >> 24
        speed = REG_VAL_TO_LINK_SPEED_MAP_2X.get((val & 0xfff), None)  # check mask in caps.h, eCapsLo enum
        state_is_up = ((val & 0xfff) != 0x0)  # & 0xffff
        # return downshift, speed, state
        return speed, state_is_up

    def get_link_params_2x_auto(self, expected_speed):
        log.info('Waiting speed = {}'.format(expected_speed))
        log.info('Polling (MBU) > readreg 0x370')
        for i in range(200):
            val = self.readreg(0x370)
            speed = REG_VAL_TO_LINK_SPEED_MAP_2X_ALL_AUTO.get((val & 0xfff), None)
            state_is_up = ((val & 0xfff) != 0x0)
            if speed == expected_speed:
                return speed, state_is_up
            time.sleep(0.1)
        return speed, state_is_up

    def set_link_control_2x(self, val):
        self.writereg(0x36C, val)

    def get_link_control_2x(self):
        return self.readreg(0x374)

    def set_link_params_2x(self, speed, eee=False):
        log.info('Setting speed {}...'.format(speed))

        val = LINK_SPEED_TO_REG_VAL_MAP_2X[speed]

        reg = 0x36C if eee else 0x368
        self.writereg(reg, val)
        if speed != constants.LINK_SPEED_AUTO:
            log.info('Polling register {}'.format(hex(reg + 8)))
            for i in range(200):
                cur_val = self.readreg(reg + 8)
                if (cur_val & 0xfff) == val:  # check mask in caps.h, eCapsLo enum
                    log.info('Matched return value: {}'.format(hex(cur_val)))
                    return
                time.sleep(0.1)
            log.info('Non-matched return value: {}'.format(hex(cur_val)))
            raise Exception("Failed to set link speed {}".format(speed))

    def get_link_speed_2x(self):
        val = self.readreg(0x370)
        val &= 0xfff
        if val in REG_VAL_TO_LINK_SPEED_MAP_2X:
            return REG_VAL_TO_LINK_SPEED_MAP_2X[val]
        elif val in REG_VAL_TO_LINK_SPEED_MAP_2X_ALL_AUTO:
            return REG_VAL_TO_LINK_SPEED_MAP_2X_ALL_AUTO[val]
        else:
            raise Exception("Unknown link speed: 0x{:08x}".format(val))

    def transaction_id_is_set(self):
        val = self.readreg(0x36c)
        val = val & LINK_CONTROL_TRANSACTION_ID
        if val != 0:
            log.info('TRANSACTION_ID bit (0x80000000) is set')
        else:
            log.info('TRANSACTION_ID bit (0x80000000) is clear')
        return val

    def debug_buffer_enable(self, enable_flag):
        # run mbu loop which can write mcp log
        # note you must call exit in teardownclass method to stop cron loop
        if enable_flag:
            self.cli.cronRun()
        self.mac_control.mcpControl.dbgBuffer.enable(enable_flag)

    def debug_buffer_reset(self):
        self.mac_control.mcpControl.dbgBuffer.reset()

    def get_fw_statistics(self):
        addr = self.readreg(0x360)
        self.mac_control.mcpControl.mailbox.lock()
        self.mac_control.mcpControl.mailbox.setAddress(addr)
        ver = self.mac_control.mcpControl.mailbox.readData()
        self.mac_control.mcpControl.mailbox.setAddress(addr + 4)
        transaction_id = self.mac_control.mcpControl.mailbox.readData()
        self.mac_control.mcpControl.mailbox.unlock()
        return ver, transaction_id

    def get_efuse(self):
        addr = self.readreg(0x374)
        self.mac_control.mcpControl.mailbox.lock()
        self.mac_control.mcpControl.mailbox.enableReadMode()
        self.mac_control.mcpControl.mailbox.setAddress(addr)
        efuse = self.mac_control.mcpControl.mailbox.readData()
        self.mac_control.mcpControl.mailbox.unlock()
        return efuse

    def flash_load_clx(self, filename):
        with open(os.path.join(self.mbu_dir, 'load_file.txt'), 'w') as f:
            f.write('flash.init\n')
            f.write('flash.loadFile {}\n'.format(filename))
            f.write('pause 2 s\n')
            f.write('mac.mcp.kickstart -p\n')

        self.exec_txt(os.path.join(self.mbu_dir, 'load_file.txt'))

    def get_efuse_shadow_memory_address(self):
        EFUSE_SHADOW_SCRATCHPAD_REG_FW1X = 0x1d
        EFUSE_SHADOW_SCRATCHPAD_REG_FW2X = 0x19

        mj, mi, rev = self.get_fw_version()

        if mj == 1:
            scratch_reg = EFUSE_SHADOW_SCRATCHPAD_REG_FW1X
        elif mj in [2, 3, 4]:
            scratch_reg = EFUSE_SHADOW_SCRATCHPAD_REG_FW2X
        else:
            raise NotImplementedError()

        return self.mac_control.dllh.regGlobalMicroprocessorScratchPadGet(scratch_reg) & 0x7fffffff \
            if scratch_reg is not None else 0x0

    def mcp_readmem_buf(self, addr, size_in_bytes):
        # TODO: deprecated
        """Analogue of (MBU) > mac.mcp.readmem <addr>"""
        self.mac_control.mcpControl.mailbox.lock()
        num_of_32bit_dwords = size_in_bytes // 4
        if size_in_bytes % 4:
            num_of_32bit_dwords += 1
        data = self.mac_control.mcpControl.mailbox.readProcessorMemory(
            num_of_32bit_dwords, addr)
        self.mac_control.mcpControl.mailbox.unlock()
        return data

    def readmem_mcp(self, addr, size_in_bytes):
        data = []
        num_of_32bit_dwords = size_in_bytes // 4
        if size_in_bytes % 4:
            num_of_32bit_dwords += 1

        self.mac_control.mcpControl.mailbox.lock()
        self.mac_control.mcpControl.mailbox.enableReadMode()

        try:
            for i in range(num_of_32bit_dwords):
                addr += 4 * i
                self.mac_control.mcpControl.mailbox.setAddress(addr)
                val = self.mac_control.mcpControl.mailbox.readData()
                data.append(val)
        finally:
            self.mac_control.mcpControl.mailbox.unlock()

        log.info("MCP memory at 0x{:08x}: {}".format(addr, ["0x{:08x}".format(d) for d in data]))

        return data

    def get_mac_address(self):
        MAC_ADDR_EFUSE_BASE_OFFSET = 0x28 * 0x4

        efuse_base_addr = self.get_efuse_shadow_memory_address()
        if efuse_base_addr != 0x0:
            dword0, dword1 = self.readmem_mcp(efuse_base_addr + MAC_ADDR_EFUSE_BASE_OFFSET, 8)
        else:
            dword0, dword1 = self.mac_control.com.loadEfuse(MAC_ADDR_EFUSE_BASE_OFFSET * 8, 64)

        mac = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
            (dword0 >> 24) & 0xFF,
            (dword0 >> 16) & 0xFF,
            (dword0 >> 8) & 0xFF,
            (dword0) & 0xFF,
            (dword1 >> 24) & 0xFF,
            (dword1 >> 16) & 0xFF
        )
        return mac

    def get_device_ids(self):
        VEND_DEV_ID_NWL_REG = 0x0  # used for vid and did
        SUB_VEND_DEV_ID_NWL_REG = 0x2  # used for svid and ssid

        vend_dev_id = self.mac_control.readRegNWL(VEND_DEV_ID_NWL_REG)
        sub_vend_dev_id = self.mac_control.readRegNWL(SUB_VEND_DEV_ID_NWL_REG)

        vend_id = (vend_dev_id & 0x0000FFFF)
        dev_id = (vend_dev_id & 0xFFFF0000) >> 16
        subven_id = (sub_vend_dev_id & 0x0000FFFF)
        subsys_id = (sub_vend_dev_id & 0xFFFF0000) >> 16

        return vend_id, dev_id, subven_id, subsys_id

    def set_lwip_address(self, addr):
        if addr == 0 or addr > 0xffffffff:
            raise Exception("Invalid value specified")
        addr &= 0x0000ffff
        self.writereg(0x370, addr)
        return addr

    def get_mac_devprop(self, prop):
        return self.mac_control.devprop[prop].value

    def set_mac_devprop(self, prop, value):
        self.mac_control.devprop[prop].value = value
        self.mac_control.devprop[prop].apply()

    def wait_link_up(self, timeout=25, retry_interval=1):
        log.info("Waiting for link UP")
        mj, _, __ = self.get_fw_version()
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            time.sleep(retry_interval)
            if mj == 1:
                _, speed, __ = self.get_link_params()
            else:
                speed = self.get_link_speed_2x()
            if speed != constants.LINK_SPEED_NO_LINK:
                log.info("Link is up at {}".format(speed))
                return speed
        raise Exception('Link is not up after timeout = {} sec.'.format(timeout))

    def wait_link_down(self, timeout=25, retry_interval=1):
        mj, _, __ = self.get_fw_version()
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            time.sleep(retry_interval)
            if mj == 1:
                _, speed, __ = self.get_link_params()
            else:
                speed = self.get_link_speed_2x()
            if speed == constants.LINK_SPEED_NO_LINK:
                return speed
        raise Exception('Link is not down after timeout = {} sec.'.format(timeout))

    def dump_to_config_memory(self, data):
        def write_to_config_memory(data, ofs):
            self.writereg(0x328, data)
            self.writereg(0x32C, ofs)

            interrupt_reg = self.readreg(0x404)
            interrupt_reg |= 0x2
            self.writereg(0x404, interrupt_reg)

            start = timeit.default_timer()
            while timeit.default_timer() - start < 1.0:
                op_reg = self.readreg(0x32C)
                if (op_reg >> 0x1E) & 0x1:
                    return True
                time.sleep(0.0001)
            raise Exception("Failed to write DWORD to config memory")

        offset = 0x80000000
        for d in data:
            write_to_config_memory(d, offset)
            offset += 4


class MbuWrapperRemote(MbuWrapper):
    def __init__(self, **kwargs):
        super(MbuWrapperRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.mbu_dir = kwargs.get("mbu_dir", None)
        self.cmd_start = "cd {} && python mbuper.py -p {} -v {}".format(ATF_TOOLS_DIR, self.port, self.version)

    def exec_async(self, cmd, timeout=None):
        self.command = Command(cmd=cmd, host=self.host, timeout=timeout)
        self.command.run_async()
        return self

    def exec_join(self, timeout=None):
        return self.command.join(timeout)

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).run()
        if res["returncode"] != 0 or not any(SCRIPT_STATUS_SUCCESS in s for s in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".
                      format(cmd, self.host))
            raise Exception("Failed to perform remote mbuper operation")
        return res["output"]

    def exec_txt(self, file, run_async=False, remote_file=None, work_dir=None, output=None, timeout=None,
                 file_to_upload=None):
        assert type(file) is str

        pwd = ''
        if work_dir is not None:
            pwd = ' --dir "{}"'.format(work_dir)

        if remote_file is None:
            remote_file = "/tmp/remote_beton.txt"
        if file_to_upload is None:
            file_to_upload = "/tmp/remote_beton.txt"
        upload_file(self.host, file, file_to_upload)
        stdout_redir = ''
        if output is not None:
            stdout_redir = ' >{}'.format(output)
        if timeout is None:
            timeout = 180
        cmd = "cd $ATF_HOME/qa-tests/tools && python mbuper.py -c exec_txt -p {} -v {} -f {}{}{} -t {}". \
            format(self.port, self.version, remote_file, pwd, stdout_redir, timeout)
        if run_async:
            return self.exec_async(cmd, timeout=timeout)
        else:
            return self.remote_exec(cmd)

    def exec_beton(self, data, run_async=False):
        assert type(data) is list
        for d in data:
            assert type(d) is str

        cmd = self.cmd_start + "-c exec_beton -b \"{}\"".format(str(data))
        if self.mbu_dir is not None:
            cmd += " -m \"{}\"".format(self.mbu_dir)
        if run_async:
            return self.exec_async(cmd)
        else:
            return self.remote_exec(cmd)

    def exec_cmd(self, cmd):
        local_file = tempfile.NamedTemporaryFile(delete=False)
        local_file.write(cmd)
        local_file.close()

        return self.exec_txt(local_file.name)

    def readreg(self, addr):
        assert isinstance(addr, int)
        addr = hex(addr)
        readreg_cmd = "readreg {}".format(addr)
        log.info("Executing command: {}".format(readreg_cmd))
        res_tuple = self.exec_cmd(readreg_cmd)
        r = re.compile("Register 0x[0-9A-F]+: (0x[0-9A-F]+) : [0-1 ]+")
        reg = False
        for ss in res_tuple:
            m = r.match(ss)
            if m:
                reg = int(m.group(1), 16)
                break
        if reg is False:
            raise Exception("Failed to read register {}".format(addr))
        log.info("Value stored in register {} : {}".format(addr, hex(reg)))
        return reg

    def readphyreg(self, addr, phyId=-1):
        raise NotImplementedError()

    def writereg(self, addr, value, silent=False):
        assert isinstance(addr, int)
        assert isinstance(value, (int, long))
        addr, value = map(hex, [addr, value])
        writereg_cmd = "writereg {} {}".format(addr, value)
        log.info("Executing command: {}".format(writereg_cmd))
        return self.exec_cmd(writereg_cmd)

    def writephyreg(self, addr, value):
        raise NotImplementedError()

    def writemem(self, addr, value):
        assert isinstance(addr, int)
        assert isinstance(value, (int, long))
        addr, value = map(hex, [addr, value])
        writemem_cmd = "mac.mcp.writemem {} {}".format(addr, value)
        log.info("Executing command: {}".format(writemem_cmd))
        return self.exec_cmd(writemem_cmd)

    def kickstart(self, reload_phy_fw=True, clx_for_flashless=None, force_flashless=False):
        arguments = {
            "reloadPhyFw": 1 if reload_phy_fw else 0,
            "forceFlashless": 1 if force_flashless else 0
        }
        if clx_for_flashless is not None:
            arguments["clxForFlashless"] = clx_for_flashless

        cmd = self.cmd_start + "-c kickstart --arguments \"{}\"".format(arguments)
        self.remote_exec(cmd)

    def destroy(self):
        raise NotImplementedError()

    def get_adapter_speed(self):
        raise NotImplementedError()

    def flash_load_clx(self, filename):
        raise NotImplementedError()

    def dump_to_config_memory(self, data):
        cmd = self.cmd_start + "-c dumpconfig --data \"[{}]\"".format(", ".join("{}".format(d) for d in data))
        self.remote_exec(cmd)


class MbuperArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.info("{}".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "%s: error: %s\n" % (self.prog, message))


if __name__ == "__main__":
    parser = MbuperArgumentParser()
    parser.add_argument("-p", "--port", type=str, required=True,
                        help="Connection port, ex: pci1.00.0 or JS12V0B015:11")
    parser.add_argument("-c", "--command", type=str, required=True, help="Command to be performed",
                        choices=["exec_txt", "exec_beton", "kickstart", "dumpconfig"])
    parser.add_argument("-f", "--file", type=str, help="Beton file full path")
    parser.add_argument("-b", "--beton", type=str, help="Array of beton code lines (should be evaluated)")
    parser.add_argument("-v", "--version", type=str, help="MBU version")
    parser.add_argument("-d", "--dir", help="Working directory", default=None)
    parser.add_argument("-m", "--mbudir", help="Predownloaded MBU dir path")
    parser.add_argument("-a", "--arguments", help="Additional arguments for command")
    parser.add_argument("-t", "--timeout", type=int,
                        help="Timeout to kill the process if not finished", default=180)
    parser.add_argument("--data", help="Array of binary data (list of integers)",
                        type=str, action=SpacedArgAction, nargs="+")
    args = parser.parse_args()

    mbu_dir = args.mbudir
    try:
        if mbu_dir is None:
            mbu_dir = download_mbu(args.version)
        mbu_main_py = os.path.join(mbu_dir, "main.py")

        work_dir = ''
        if args.dir is not None:
            work_dir = ' --pwd "{}"'.format(args.dir)

        if args.command == "exec_txt":
            if args.file is None:
                raise Exception("File must be specified to execute MBU")
            cmd = Command(cmd="python {} -p {} -i -f {}{}".format(mbu_main_py, args.port, args.file, work_dir))
            res = cmd.run_join(args.timeout)
        elif args.command == "exec_beton":
            if args.beton is None:
                raise Exception("Beton code must be specified to execute MBU")
            beton = eval(args.beton)
            fd, fpath = tempfile.mkstemp(suffix=".txt")
            log.info("Writing beton code to file {}".format(fpath))
            for line in beton:
                os.write(fd, "{}\n".format(line))
            os.close(fd)
            cmd = Command(cmd="python {} -p {} -i -f {}{}".format(mbu_main_py, args.port, fpath, work_dir))
            res = cmd.run_join(args.timeout)
        elif args.command == "kickstart":
            this_folder = os.path.dirname(os.path.abspath(__file__))
            kickstart_file = os.path.join(this_folder, "beton/reset_sequence.txt")
            if args.arguments is not None:
                arguments = eval(args.arguments)
                tmp_file = "tmp.txt"
                with open(tmp_file, "w") as f:
                    for k, v in arguments.items():
                        f.write("{} = {}\n".format(k, v))
                    f.write("exec {}\n".format(kickstart_file))
                kickstart_file = os.path.abspath(tmp_file)
            cmd = Command(cmd="python {} -p {} -i -f {}{}".format(mbu_main_py, args.port, kickstart_file, work_dir))
            res = cmd.run_join(args.timeout)
        elif args.command == "dumpconfig":
            mbu_wrapper = MbuWrapper(port=args.port)
            data = eval(args.data)
            mbu_wrapper.dump_to_config_memory(data)
    except Exception:
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)
    finally:
        if args.mbudir is None:
            remove_directory(mbu_dir)

    log.info(SCRIPT_STATUS_SUCCESS)
