import argparse
import copy
import hashlib
import ntpath
import os
import re
import socket
import sys
import time
import urlparse

from abc import abstractmethod, ABCMeta

import aeaaper
import atltoolper
import diagper
import driver
from command import Command

from constants import LINK_SPEED_5G, LINK_SPEED_10G, BUILDS_SERVER, NFS_SERVER, MDI_NORMAL, MDI_SWAP, \
    MII_MODE_USX, MII_MODE_XFI, MII_MODE_USX_SGMII, MII_MODE_XFI_SGMII, MII_MODE_OCSGMII, MII_MODES, \
    KNOWN_CARDS, CARD_NIKKI, FELICITY_CARDS, CARD_BERMUDA_A0, CARD_BERMUDA_B0, BERMUDA_CARDS, \
    VENDOR_AQUANTIA, ATF_TOOLS_DIR, PHY_RHEA, PHY_CALYPSO, PHY_EUROPA, VENDOR_QNAP, CARD_ANTIGUA_LOM

from ops import OpSystem
from utils import (
    get_atf_logger, get_url_response, remove_file, get_bus_dev_func, get_domain_bus_dev_func, SpacedArgAction)

SCRIPT_STATUS_SUCCESS = "[FIRMWARE-SUCCESS]"
SCRIPT_STATUS_FAILED = "[FIRMWARE-FAILED]"

log = get_atf_logger()


def get_mac(port):
    host = socket.gethostname()
    hash_host = hashlib.sha256(host + port)
    hex_host = hash_host.hexdigest()
    return "00:17:b6:{}:{}:{}".format(hex_host[:2], hex_host[2:4], hex_host[4:6])


def get_actual_fw_version(version):
    suburl = "firmware/{}/version.txt".format(version)
    url = urlparse.urljoin(BUILDS_SERVER, suburl)
    response = get_url_response(url).rstrip("\r\n")
    if re.compile("[0-9]+.[0-9]+.[0-9]+").match(response) is None:
        return None
    return response


def list_files(path):
    path = path.replace("\\", "/")
    res = Command(cmd="ls {}".format(path), host=NFS_SERVER, silent=True).wait(10)
    if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
        raise Exception("Failed to list file(s) on build server")
    log.info("There are {} files in {} directory".format(len(res["output"]), path))
    return [os.path.basename(line.rstrip("\r\n")) for line in res["output"]]


def download_file(file):
    log.info('downloading {} ...'.format(file))
    file = file.replace("\\", "/")
    suburl = "firmware/{}".format(file)
    url = urlparse.urljoin(BUILDS_SERVER, suburl)
    content = get_url_response(url)
    fname = ntpath.basename(file)
    with open(fname, "wb") as f:
        f.write(content)
    return os.path.abspath(fname).replace("\\", "/")


class Firmware(object):
    __metaclass__ = ABCMeta

    POSTINSTALL_NO_RESTART = 0
    POSTINSTALL_RESTART = 1
    POSTINSTALL_COLD_RESTART = 2

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            version = kwargs["version"]
            if "pacific/" in version:
                return object.__new__(FirmwareLocalPacific)
            elif "atlantic2/" in version:
                return object.__new__(FirmwareLocalAtlantic2)
            actual_version = get_actual_fw_version(version)
            if actual_version:
                ver_major, ver_minor = actual_version.split(".")[:2]
                if int(ver_major) == 1:
                    return object.__new__(FirmwareLocal1x)
                elif int(ver_major) == 2:
                    if int(ver_minor) in [10, 11, 12]:
                        return object.__new__(FirmwareLocal210x)
                    else:
                        return object.__new__(FirmwareLocal2x)
                elif int(ver_major) == 3:
                    return object.__new__(FirmwareLocal3x)
                elif int(ver_major) == 4:
                    return object.__new__(FirmwareLocal4x)
                else:
                    raise Exception("Unknown firmware type")
            else:
                raise Exception("Unknown firmware type: {}".format(version))
        else:
            return object.__new__(FirmwareRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]
        self.version = kwargs["version"]
        self.card = kwargs["card"]
        self.speed = kwargs.get("speed", LINK_SPEED_10G)
        self.mdi = kwargs.get("mdi", MDI_NORMAL)
        self.mii = kwargs.get("mii", MII_MODE_USX_SGMII)
        self.pause = kwargs.get("pause", False)
        self.pcirom = kwargs.get("pcirom", False)
        self.dirtywake = kwargs.get("dirtywake", False)
        self.cached_actual_version = None
        self.bdp = kwargs.get("bdp", None)
        self.sign = kwargs.get("sign", False)
        self.se_enable = kwargs.get("se_enable", False)
        self.hsd = kwargs.get("hsd", False)
        self.cdrom = kwargs.get("cdrom", False)

        assert type(self.version) is str and self.version != ""
        assert self.speed in [LINK_SPEED_5G, LINK_SPEED_10G]
        assert self.mdi in [MDI_NORMAL, MDI_SWAP]
        assert self.mii in [MII_MODE_USX, MII_MODE_XFI, MII_MODE_USX_SGMII, MII_MODE_XFI_SGMII]
        assert type(self.pause) is bool
        assert (type(self.pcirom) is str and self.pcirom != "") or self.pcirom is None or self.pcirom is False
        assert type(self.dirtywake) is bool

        self.default_overrides = {
            "subsys_id": 0x1,
            "subven_id": 0x1d6a,
            "mac": get_mac(self.port)
        }
        if self.card in FELICITY_CARDS:
            self.default_overrides["dev_id"] = 0x00b1
        elif self.card in BERMUDA_CARDS:
            self.default_overrides["dev_id"] = 0x11b1
        else:
            self.default_overrides["dev_id"] = 0x07b1 if self.speed == LINK_SPEED_10G else 0x08b1

    @abstractmethod
    def download(self):
        pass

    @abstractmethod
    def install(self, overrides={}, flashless=False):
        pass

    @property
    def actual_version(self):
        if self.cached_actual_version is None:
            self.cached_actual_version = get_actual_fw_version(self.version)
        return self.cached_actual_version

    def is_1x(self):
        return False

    def is_2x(self):
        return False

    def is_3x(self):
        return False

    def is_4x(self):
        return False

    def is_2_10x(self):
        return False

    def is_2_11x(self):
        return False

    def is_2_12x(self):
        return False

    def is_atlantic2(self):
        return False


class FirmwareLocal(Firmware):
    FW_BUILD_BASE_PATH = "/storage/export/builds/firmware/"

    def _legacy_get_mdi_from_param_str(self, param_str):
        # Check from longest MDI str to shortest
        if MDI_NORMAL in param_str:
            return MDI_NORMAL
        elif MDI_SWAP in param_str:
            return MDI_SWAP
        else:
            return ""

    def _legacy_get_mii_from_param_str(self, param_str):
        # Check from longest MII str to shortest
        if MII_MODE_USX_SGMII in param_str:
            return MII_MODE_USX_SGMII
        elif MII_MODE_XFI_SGMII in param_str:
            return MII_MODE_XFI_SGMII
        elif MII_MODE_USX in param_str:
            return MII_MODE_USX
        elif MII_MODE_XFI in param_str:
            return MII_MODE_XFI
        else:
            return ""

    def get_current_overrides(self, wrapper):
        ver_major, ver_minor, ver_release = wrapper.get_fw_version()

        vend_id, dev_id, subven_id, subsys_id = wrapper.get_device_ids()
        log.info("Current Vendor ID = 0x{:02x}, Device ID = 0x{:02x}, Subsystem Vendor ID = 0x{:02x}, "
                 "Subsystem Device ID = 0x{:02x}".format(vend_id, dev_id, subven_id, subsys_id))

        return ["{}.{}.{}".format(ver_major, ver_minor, ver_release), (vend_id, dev_id, subven_id, subsys_id)]

    def _legacy_choose_clx_file(self, clx_files):
        _file = None
        last_EUR_ver = ""
        is_felicity = self.card in FELICITY_CARDS

        if self.is_3x():
            regexp = re.compile(r"^(\w+)-([\d.]+)!(EUR|CAL)-v([\d.]+)-([\w-]+)!PCIROM-([\w.]+)!VPD-([\d.]+)!Aqtion(\w{2})\w*!.*")
            log.info("Choosing regex for FW 3.x")
        elif is_felicity:
            regexp = re.compile(r"^(\w+)-([\d.]+)\!PCIROM-([\w.]+)-?(.*)\!VPD-([0-9\.]+)\!(Felicity)(\w{2})!.*")
            log.info("Choosing regex for FW Felicity 1.x")
        elif self.is_2_10x() or self.is_2_11x() or self.is_2_12x():
            regexp = re.compile(r"^.*!(EUR)-(.*)_(\w+)!PCIROM-([\w.]+).*")
            log.info("Choosing regex 2.10.x or 2.11.x or 2.12.x")
        else:
            regexp = re.compile(r"^(\w+)-?(\w*)-?(\w*)-([\d.]+)(-dirtywake|-INTERNAL)?!(EUR|CAL)-v([\w.]+)-[a-zA-Z]+[_-]([a-zA-Z0-9]+)_(.*)!PCIROM-([\w.]+).*!VPD-([\d.]+).*")
            log.info("Choosing regex for FW 1.x (Nikki, Bambi, Jamaica) / 2.x")

        log.info("Searching CLX files with next parameters:")
        log.info("\n".join(["", "Version: {}".format(self.version), "Card: {}".format(self.card),
                            "Speed: {}".format(self.speed), "MDI: {}".format(self.mdi),
                            "MII: {}".format(self.mii), "PCIROM: {}".format(self.pcirom),
                            "Pause: {}".format(self.pause), "Dirtywake: {}".format(self.dirtywake)]))

        matched_clxes = 0
        for line in clx_files:
            if "sifpolling" in line:  # TODO: what is that?
                continue
            m = regexp.match(line)
            if m:
                matched_clxes += 1

                if self.is_3x():
                    (_, file_FW_ver, file_phy, file_phy_ver, file_MDI, file_PCIROM_ver, file_VPD_ver,
                     file_chip_rev) = m.groups()
                    file_speed = ''
                    file_MDI = self._legacy_get_mdi_from_param_str(file_MDI)
                elif self.is_2_10x() or self.is_2_11x() or self.is_2_12x():
                    (file_phy, file_phy_ver, file_MDI, file_PCIROM_ver) = m.groups()
                    file_speed = ''
                    file_MII = None
                elif is_felicity:
                    (_, file_FW_ver, file_PCIROM_ver, file_dev_id, file_VPD_ver, file_card, file_chip_rev) = m.groups()
                    file_speed = ''
                    file_phy = ''  # TODO: temp workaround for Bermuda
                    file_MDI = MDI_NORMAL
                else:
                    (_, file_speed, file_chip_rev, file_FW_ver, file_dirtywake, file_phy, file_phy_ver, file_card,
                     file_MDI_MII, file_PCIROM_ver, file_VPD_ver) = m.groups()
                    file_MDI = self._legacy_get_mdi_from_param_str(file_MDI_MII)
                    file_MII = self._legacy_get_mii_from_param_str(file_MDI_MII)
                    if "108" in file_card or "107" in file_card:
                        file_card = "Nikki"
                    elif "100" in file_card:
                        file_card = "Felicity"

                    if file_chip_rev == '':
                        file_speed = ''

                matched = file_speed in [self.speed, ""]
                if not self.is_3x() and not self.is_2_10x() and not self.is_2_11x() and not self.is_2_12x():
                    matched &= self.card == file_card

                if self.pcirom in [None, False, "none", "0.0.1", "no"]:
                    matched &= file_PCIROM_ver in ["0.0.1", "none"]
                elif self.pcirom == "any":
                    # Do not match anything
                    pass
                elif type(self.pcirom) is str:
                    matched &= self.pcirom == file_PCIROM_ver
                else:
                    raise Exception("PCIROM should be string with version, no, None or False; current = {}".format(
                        self.pcirom))

                matched &= file_MDI == self.mdi

                if not is_felicity:
                    matched = matched and (file_phy_ver > last_EUR_ver)

                    if not self.is_3x() and file_MII:
                        matched &= self.mii == file_MII

                if self.pause:
                    matched &= "pause" in line.lower()
                else:
                    matched &= "pause" not in line.lower()
                if self.dirtywake:
                    matched &= "dirtywake" in line.lower()
                else:
                    matched &= "dirtywake" not in line.lower()

                if self.card in BERMUDA_CARDS:
                    matched &= "nonefuse" in line.lower()
                    matched &= file_phy == "CAL"  # TODO: temp workaround for Bermuda
                else:
                    matched &= file_phy != "CAL"  # TODO: temp workaround for Bermuda

                if matched:
                    log.info("Found FW that satisfies all parameters: {}".format(line))
                    _file = line
                    if not is_felicity:
                        last_EUR_ver = file_phy_ver
        log.info("Matched clx files with regex: {}".format(matched_clxes))
        return _file

    def _legacy_install(self, overrides={}):
        op_sys = OpSystem()

        drv = driver.Driver(drv_type=driver.DRV_TYPE_DIAG, port=self.port, version="latest")
        if drv.vendor != VENDOR_AQUANTIA:
            raise Exception("Cannot burn FW on non-Aquantia device (founded: {})".format(drv.vendor))

        drv.install()

        reload_phy_fw = self.card not in FELICITY_CARDS

        pre_install_kickstart_passed = True
        atltool = atltoolper.AtlTool(port=self.port)
        try:
            atltool.kickstart(reload_phy_fw=reload_phy_fw)
        except atltoolper.KickstartError:
            pre_install_kickstart_passed = False

        if pre_install_kickstart_passed:
            current_fw_info = self.get_current_overrides(atltool)

            current_override = {
                "mac": atltool.get_mac_address(),
                "dev_id": current_fw_info[1][1],
                "subven_id": current_fw_info[1][2],
                "subsys_id": current_fw_info[1][3]
            }

        version_to_install = self.actual_version
        if version_to_install is None:
            raise Exception("Cannot parse version to install")

        if pre_install_kickstart_passed:
            log.info("Current FW version = {}, requested FW version = {}".format(
                current_fw_info[0], version_to_install))
            log.info("Current MAC address = {}, requested MAC address = {}".format(
                current_override["mac"], overrides.get("mac", None)))

            is_version_update = version_to_install != current_fw_info[0]
            if "mac" in overrides:
                is_mac_address_update = current_override["mac"] != overrides["mac"]
            else:
                is_mac_address_update = False
            is_ids_update = False
            for key in ["dev_id", "subven_id", "subsys_id"]:
                if key in overrides:
                    is_ids_update |= current_override[key] != overrides[key]
                else:
                    is_ids_update |= current_override[key] != self.default_overrides[key]

            log.info("Is version update = {}, is mac address update = {}, is ids update = {}".format(
                is_version_update, is_mac_address_update, is_ids_update))

            # if (is_version_update | is_mac_address_update | is_ids_update) is False and not force:
            #     log.info("Actual firmware meets all requirements, stopping FW installation")
            #     log.info("Installed firmware version is {}".format(version_to_install))
            #     log.info("Cold restart is not needed")
            #     return self.POSTINSTALL_NO_RESTART
            log.info("We do not skip firmware installation at the moment")
        else:
            # This else clause is needed because FirmwareRemote class parses this string to get installed version
            log.info("Current FW version = UNKNOWN, requested FW version = {}".format(version_to_install))

        local_file = self.download()

        aqc_data = {
            "clx": local_file,
            "mac": overrides.get("mac", current_override["mac"] if pre_install_kickstart_passed else get_mac(self.port)),
            "dev_id": overrides.get("dev_id", self.default_overrides["dev_id"]),
            "subsys_id": overrides.get("subsys_id", self.default_overrides["subsys_id"]),
            "subven_id": overrides.get("subven_id", self.default_overrides["subven_id"])
        }

        # Override PCI Lane Width = 4 for Bermuda card to work
        if self.card in BERMUDA_CARDS:
            aqc_data["lanes"] = 0x4

        diagper.DiagWrapper.exec_aqc(aqc_data)
        time.sleep(2)  # for kickstart

        remove_file(local_file)

        log.info("Installed firmware version is {}".format(version_to_install))

        if not pre_install_kickstart_passed or is_ids_update:
            # If vendor/subvendor IDs were updated we need cold restart
            # Kickstart could be skipped in that case
            log.info("Skipping kickstart and requesting cold restart")
            return self.POSTINSTALL_COLD_RESTART

        atltool.kickstart(reload_phy_fw=reload_phy_fw)
        time.sleep(5)

        if op_sys.is_windows():
            # TODO: investigate driver installation problem (Access denied)
            # drv.remove_all_hidden_devices()

            # This code is commented because we use cold restart at the moment
            # log.info("Trying to update WMI cache by restarting its service")
            # Command(cmd="net stop winmgmt /Y").run()
            # time.sleep(3)
            # Command(cmd="net start winmgmt").run()
            # time.sleep(3)

            # # Restart services that depend on WMI
            # Command(cmd="net start wscsvc").run()  # Security Center
            # time.sleep(3)
            # Command(cmd="net start iphlpsvc").run()  # IP Helper
            # time.sleep(3)
            pass

        log.info("Cold restart is not needed")
        return self.POSTINSTALL_NO_RESTART

    def _atltool_apply_clx_overrides(self, file, overrides):
        cmd = "clxoverride "
        cmd += "--mac0 {} --mac1 {} ".format(overrides["mac"], overrides["mac"])
        cmd += "--id0 1d6a:{:04x}:{:04x}:{:04x} --id1 1d6a:{:04x}:{:04x}:{:04x} ".format(
            overrides["dev_id"], overrides["subven_id"], overrides["subsys_id"],
            overrides["dev_id"], overrides["subven_id"], overrides["subsys_id"])
        cmd += " {}".format(file)
        res = Command(cmd=cmd).run_join(30)
        if res["returncode"] != 0:
            raise Exception("Failed to update CLX")
        return file

    def _atltool_burn_clx(self, file, retries=2):
        if OpSystem().is_linux():
            domain, bus, dev, func = get_domain_bus_dev_func(self.port)
            lspci_port = "{:04x}-{:02x}:{:02x}.{:x}".format(domain, bus, dev, func)
        else:
            bus, dev, func = map(lambda x: int(x), get_bus_dev_func(self.port))
            lspci_port = "{:02x}:{:02x}.{:x}".format(bus, dev, func)
        cmd = "" if OpSystem().is_windows() else "sudo "
        cmd += "flashBurn{} -d {} {}".format("2" if "atlantic2" in self.version else "", lspci_port, file)
        res = None
        for num in xrange(retries):
            res = Command(cmd=cmd, silent=True).run_join(180)
            log.info("Command output:")
            log.info("\n".join(res["output"]))
            if res["returncode"] == 0:
                break
            else:
                log.warning("Burning fw failed retries remaining: {}".format(retries - num - 1))
                atltool = atltoolper.AtlTool(port=self.port)
                if self.is_atlantic2():
                    atltool.kickstart2()
                else:
                    atltool.kickstart(reload_phy_fw=self.card not in FELICITY_CARDS + BERMUDA_CARDS)
        remove_file(file)
        log.info("Command output:")
        log.info("\n".join(res["output"]))
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to burn firmware")
        if "Device burned and verified" not in res["output"][-1]:
            raise Exception("Failed to burn firmware")

    def _pactool_burn_clx(self, file, retries=5):
        bus, dev, func = map(lambda x: int(x), get_bus_dev_func(self.port))
        usb_port = "{:X}:{:X}".format(int(dev), int(func))
        cmd = "" if OpSystem().is_windows() else "sudo "
        cmd += "pacFlashBurn -d {} {}".format(usb_port, file)
        res = None
        for num in xrange(retries):
            res = Command(cmd=cmd).run_join(1200)
            if res["returncode"] == 0:
                break
            else:
                log.warning("Burning fw failed retries remaining: {}".format(retries - num - 1))
        remove_file(file)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to burn firmware")
        if "Device burned and verified" not in res["output"][-1]:
            raise Exception("Failed to burn firmware")

    def _atltool_install(self, overrides={}, flashless=False):
        # TODO: actually driver is not needed here, this is workaround for 0xffffffff problem on Windows and macOS
        if OpSystem().is_freebsd():
            drv = driver.Driver(port=self.port, version="freebsd/latest")
        else:
            if sys.platform == "darwin":
                drv = driver.Driver(port=self.port, version="frank/for_install")
            else:
                drv = driver.Driver(drv_type=driver.DRV_TYPE_DIAG, port=self.port, version="latest")
        if drv.vendor != VENDOR_AQUANTIA:
            raise Exception("Cannot burn FW on non-Aquantia device (founded: {})".format(drv.vendor))

        if OpSystem().is_linux() or OpSystem().is_freebsd():
            drv.uninstall()
        elif OpSystem().is_mac():
            # Unload macOS driver before burning FW
            for bundle_id in drv.KNOWN_BUNDLE_IDS:
                drv.kextunload(bundle_id)
            time.sleep(5)
        else:
            drv.install()
        # TODO: end of workaround

        atltool = atltoolper.AtlTool(port=self.port)
        reload_phy_fw = self.card not in BERMUDA_CARDS + FELICITY_CARDS
        # reload_phy_fw = False

        pre_install_kickstart_passed = True
        try:
            atltool.kickstart(reload_phy_fw=reload_phy_fw)
        except atltoolper.KickstartError:
            pre_install_kickstart_passed = False

        if pre_install_kickstart_passed:
            current_fw_info = self.get_current_overrides(atltool)

            current_override = {
                "mac": atltool.get_mac_address(),
                "dev_id": current_fw_info[1][1],
                "subven_id": current_fw_info[1][2],
                "subsys_id": current_fw_info[1][3]
            }

        if pre_install_kickstart_passed:
            log.info("Current FW version = {}, requested FW version = {}".format(
                current_fw_info[0], self.actual_version))
            log.info("Current MAC address = {}, requested MAC address = {}".format(
                current_override["mac"], overrides.get("mac", None)))

            is_version_update = self.actual_version != current_fw_info[0]
            if "mac" in overrides:
                is_mac_address_update = current_override["mac"] != overrides["mac"]
            else:
                is_mac_address_update = False
            is_ids_update = False
            for key in ["dev_id", "subven_id", "subsys_id"]:
                if key in overrides:
                    is_ids_update |= current_override[key] != overrides[key]
                else:
                    is_ids_update |= current_override[key] != self.default_overrides[key]

            log.info("Is version update = {}, is mac address update = {}, is ids update = {}".format(
                is_version_update, is_mac_address_update, is_ids_update))

            # # Historically it skipping FW was done due to unstable installation process which leaded to mac hanging
            # # Currently skipping FW installation is not needed.
            # if (is_version_update | is_mac_address_update | is_ids_update) is False and OpSystem().is_mac() and not force:
            #     log.info("Actual firmware meets all requirements, stopping FW installation")
            #     log.info("Installed firmware version is {}".format(self.actual_version))
            #     time.sleep(5)
            #     # Load macOS driver back after burning FW
            #     res = Command(cmd="sudo kextload /System/Library/Extensions/IONetworkingFamily.kext/Contents/"
            #                       "PlugIns/AppleEthernetAquantiaAqtion.kext").run_join(30)
            #     if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            #         raise Exception("Failed to kextload")
            #     log.info("Cold restart is not needed")
            #     return self.POSTINSTALL_NO_RESTART
            # log.info("We do not skip firmware installation at the moment")
        else:
            # This else clause is needed because FirmwareRemote class parses this string to get installed version
            log.info("Current FW version = UNKNOWN, requested FW version = {}".format(self.actual_version))

        original_clx = self.download()
        overrides_to_apply = copy.deepcopy(self.default_overrides)
        overrides_to_apply.update(overrides)
        updated_clx = self._atltool_apply_clx_overrides(original_clx, overrides_to_apply)

        if flashless:
            Command(cmd="sudo flashErase -d {}:".format(atltool.pciutil_port)).run()
            atltool.kickstart(clx_for_flashless=updated_clx, force_flashless=True,
                              reload_phy_fw=reload_phy_fw)
            log.info("Cold restart is not needed")
            return self.POSTINSTALL_NO_RESTART

        self._atltool_burn_clx(updated_clx)

        if not pre_install_kickstart_passed or is_ids_update:
            # If vendor/subvendor IDs were updated we need cold restart
            # Kickstart could be skipped in that case
            log.info("Skipping kickstart and requesting cold restart")
            return self.POSTINSTALL_COLD_RESTART

        atltool.kickstart(reload_phy_fw=reload_phy_fw)

        if OpSystem().is_mac():
            time.sleep(5)
            # Load macOS driver back after burning FW
            res = Command(cmd="sudo kextload /System/Library/Extensions/IONetworkingFamily.kext/Contents/"
                              "PlugIns/AppleEthernetAquantiaAqtion.kext").run_join(30)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to kextload")

        log.info("Cold restart is not needed")
        return self.POSTINSTALL_NO_RESTART

    def _pactool_install(self):
        if OpSystem().is_windows():
            drv = driver.Driver(drv_type=driver.DRV_TYPE_DIAG_WIN_USB, port=self.port, version="latest")
        elif OpSystem().is_linux():
            drv = driver.Driver(drv_type=driver.DRV_TYPE_LINUX_SRC, port=self.port, version="for_install")
        elif OpSystem().is_mac():
            drv = driver.Driver(drv_type=driver.DRV_TYPE_KEXT, port=self.port, version="latest")
        if drv.vendor not in [VENDOR_AQUANTIA, VENDOR_QNAP]:
            raise Exception("Cannot burn FW on non-Aquantia device (founded: {})".format(drv.vendor))
        if OpSystem().is_linux() or OpSystem().is_mac():
            drv.uninstall()
        else:
            drv.install()
        original_clx = self.download()
        log.info("Requested FW version = {}".format(self.actual_version))
        self._pactool_burn_clx(file=original_clx)
        log.info("Hotplug USB device for changes to take effect")
        return self.POSTINSTALL_COLD_RESTART

    def _aeaa_install(self, overrides={}):
        # This method should be executed only on macOS which means that we should check next things
        assert OpSystem().is_mac()

        # The next section is self protection just to check that cycle parameters are configured correctly
        if "dev_id" in overrides:
            assert overrides["dev_id"] == 0x7b1
        if "subven_id" in overrides:
            assert overrides["subven_id"] == 0x106b
        if "subsys_id" in overrides:
            assert overrides["subsys_id"] == 0x187

        drv = driver.Driver(drv_type=driver.DRV_TYPE_KEXT, port=self.port, version="frank/for_install")
        if drv.vendor != VENDOR_AQUANTIA:
            raise Exception("Cannot burn FW on non-Aquantia device (founded: {})".format(drv.vendor))
        drv.install()

        overrides_to_apply = {}
        overrides_to_apply["dev_id"] = 0x7b1
        overrides_to_apply["subven_id"] = 0x106b
        overrides_to_apply["subsys_id"] = 0x187
        if "mac" in overrides:
            overrides_to_apply["mac"] = overrides["mac"]
        else:
            overrides_to_apply["mac"] = get_mac(self.port)

        log.info("Requested FW version = {}".format(self.actual_version))

        original_clx = self.download()
        updated_clx = self._atltool_apply_clx_overrides(original_clx, overrides_to_apply)

        aeaa_wrapper = aeaaper.AeaaWrapper(port=self.port)
        try:
            aeaa_wrapper.nvram(updated_clx)
        finally:
            remove_file(original_clx)
            remove_file(updated_clx)

        aeaa_wrapper.kickstart(reload_phy_fw=self.card not in FELICITY_CARDS)
        time.sleep(5)
        # Reload macOS driver after burning FW
        drv.kextunload('com.apple.driver.AppleEthernetAquantiaAqtion')
        res = Command(cmd="sudo kextload /System/Library/Extensions/IONetworkingFamily.kext/Contents/"
                          "PlugIns/AppleEthernetAquantiaAqtion.kext").run_join(30)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to kextload")

        log.info("Cold restart is not needed")
        return self.POSTINSTALL_NO_RESTART

    def download(self):
        path = os.path.join(self.FW_BUILD_BASE_PATH, self.version, "*.clx").replace("\\", "/")
        clx_files = list_files(path)
        clx_file_name = self._legacy_choose_clx_file(clx_files)
        log.info("The next firmware will be installed: {}".format(clx_file_name))
        file_on_server = os.path.join(self.version, clx_file_name).replace("\\", "/")
        clx_file = download_file(file_on_server)
        log.info("CLX file has been downloaded to {}".format(clx_file))
        return clx_file

    def install(self, overrides={}, flashless=False):
        return self._legacy_install(overrides=overrides)


class FirmwareLocal1x(FirmwareLocal):
    def is_1x(self):
        return True


class FirmwareLocal2x(FirmwareLocal):
    def download(self):

        prefix = 'bin_forCustomers'
        if "bin_forDebug" in self.version:
            prefix = ""

        path = os.path.join(self.FW_BUILD_BASE_PATH, self.version, prefix, "*.clx").replace("\\", "/")
        clx_files = list_files(path)
        clx_file_name = self._legacy_choose_clx_file(clx_files)
        log.info("The next firmware will be installed: {}".format(clx_file_name))
        file_on_server = os.path.join(self.version, prefix, clx_file_name).replace("\\", "/")
        clx_file = download_file(file_on_server)
        log.info("CLX file has been downloaded to {}".format(clx_file))
        return clx_file

    def install(self, overrides={}, flashless=False):
        # if OpSystem().is_mac():
        #     return self._aeaa_install(overrides=overrides, force=force)
        # else:
        return self._atltool_install(overrides=overrides)

    def is_2x(self):
        return True


class FirmwareLocal210x(FirmwareLocal2x):
    def is_2_12x(self):
        return True

    def is_2_11x(self):
        return True

    def is_2_10x(self):
        return True

    def is_2x(self):
        return False


class FirmwareLocal3x(FirmwareLocal):
    def download(self):
        if "3x/" not in self.version and "4x/" not in self.version:
            # This is to make possible install old firmwares like x3/3.0.33/AQR10X/unsigned
            return super(FirmwareLocal3x, self).download()

        if self.bdp is None and self.dirtywake is False and self.sign is False and self.se_enable is False:
            path = os.path.join(self.FW_BUILD_BASE_PATH, self.version, self.card, "*.clx").replace("\\", "/")
            clx_files = list_files(path)
            assert len(clx_files) == 1  # only one clx file for 3x firmware
            file_on_server = os.path.join(self.version, self.card, clx_files[0]).replace("\\", "/")
            clx_file = download_file(file_on_server)
            log.info("CLX file has been downloaded to {}".format(clx_file))
            return clx_file
        elif self.bdp is None and self.dirtywake is False and self.sign is True and self.se_enable is False:
            if self.card == CARD_NIKKI:
                bdp_path = "Customers_AqSign/AQC_107_108/"
            elif self.card in FELICITY_CARDS:
                bdp_path = "Customers_AqSign/AQC_100/"
            elif self.card in BERMUDA_CARDS:
                bdp_path = "Customers_AqSign/AQC_111_112/"
            else:
                raise Exception("Unknown card name")
            path = os.path.join(self.FW_BUILD_BASE_PATH, self.version,
                                bdp_path, "*{}*.clx".format(self.card)).replace("\\", "/")
            clx_files = list_files(path)
            assert len(clx_files) == 1  # only one clx file for 3x firmware
            file_on_server = os.path.join(self.version, bdp_path, clx_files[0]).replace("\\", "/")
            clx_file = download_file(file_on_server)
            log.info("CLX file has been downloaded to {}".format(clx_file))
            return clx_file
        elif self.bdp is not None and self.dirtywake is False and self.sign is False and self.se_enable is False:
            if self.card == "Nikki":
                bdp_path = "Customers/AQC_107_108/"
            elif self.card == CARD_BERMUDA_A0 or self.card == CARD_BERMUDA_B0:
                bdp_path = "Customers/AQC_111_112/"
            elif self.card == "Felicity":
                bdp_path = "Customers/AQC_100/"
            else:
                raise Exception("Unknown card name")
            path = os.path.join(self.FW_BUILD_BASE_PATH, self.version,
                                bdp_path, "*{}*.clx".format(self.bdp)).replace("\\", "/")
            clx_files = list_files(path)
            assert len(clx_files) == 1  # only one clx file for 3x firmware
            file_on_server = os.path.join(self.version, bdp_path, clx_files[0]).replace("\\", "/")
            clx_file = download_file(file_on_server)
            log.info("CLX file has been downloaded to {}".format(clx_file))
            return clx_file
        elif self.dirtywake is True and self.se_enable is False:
            if self.card == "Nikki":
                bdp_path = "Customers/AQC_107_108/"
            elif self.card == CARD_BERMUDA_A0 or self.card == CARD_BERMUDA_B0:
                bdp_path = "Customers/AQC_111_112/"
            else:
                raise Exception("Unknown or unsupported card name")
            path = os.path.join(self.FW_BUILD_BASE_PATH, self.version,
                                bdp_path, "*Dirtywake*.clx").replace("\\", "/")
            clx_files = list_files(path)
            assert len(clx_files) == 1  # only one clx file for 3x firmware
            file_on_server = os.path.join(self.version, bdp_path, clx_files[0]).replace("\\", "/")
            clx_file = download_file(file_on_server)
            log.info("CLX file has been downloaded to {}".format(clx_file))
            return clx_file
        elif self.se_enable is True:
            if self.card == "Nikki":
                bdp_path = "Customers/AQC_107_108_SE/"
            else:
                raise Exception("Unknown or unsupported card name")
            if self.hsd:
                if self.mdi == MDI_NORMAL:
                    bdp_name = "*Nvidia-10G-SE*.clx"
                else:
                    bdp_name = "*Nvidia-swap-10G-SE*.clx"
            else:
                bdp_name = "*Nikki-Automotive*.clx"
            path = os.path.join(self.FW_BUILD_BASE_PATH, self.version, bdp_path, bdp_name).replace("\\", "/")
            clx_files = list_files(path)
            assert len(clx_files) == 1  # only one clx file for 3x firmware
            file_on_server = os.path.join(self.version, bdp_path, clx_files[0]).replace("\\", "/")
            clx_file = download_file(file_on_server)
            log.info("CLX file has been downloaded to {}".format(clx_file))
            return clx_file
        else:
            return super(FirmwareLocal3x, self).download()

    def install(self, overrides={}, flashless=False):
        return self._atltool_install(overrides=overrides, flashless=flashless)

    def is_3x(self):
        return True


class FirmwareLocal4x(FirmwareLocal3x):
    def is_4x(self):
        return True


class FirmwareLocalAtlantic2(FirmwareLocal):
    def download(self):
        if "atlantic2/" in self.version:
            bdp_path = "Customers/AQC_113/"
            if self.dirtywake is True:
                path = os.path.join(self.version, bdp_path, "*DirtyWake-Antigua-*.clx")
            elif self.card == CARD_ANTIGUA_LOM:
                path = os.path.join(self.version, bdp_path, "*X1814_LOM-*.clx")
            else:
                path = os.path.join(self.version, self.card, "*.clx")
            clx_files = list_files(os.path.join(self.FW_BUILD_BASE_PATH, path).replace("\\", "/"))
            if len(clx_files) != 1:
                path = os.path.join(self.version, self.card, "*_nic_*.clx")
                clx_files = list_files(os.path.join(self.FW_BUILD_BASE_PATH, path).replace("\\", "/"))
            assert len(clx_files) == 1  # only one clx file for Antigua firmware
            file_on_server = os.path.join(os.path.dirname(path), os.path.basename(clx_files[0])).replace("\\", "/")
            clx_file = download_file(file_on_server)
            log.info("CLX file has been downloaded to {}".format(clx_file))
            return clx_file

    def install(self, overrides={}, flashless=False):
        drv = driver.Driver(drv_type=driver.DRV_TYPE_DIAG, port=self.port, version="latest")
        if drv.vendor != VENDOR_AQUANTIA:
            raise Exception("Cannot burn FW on non-Aquantia device (founded: {})".format(drv.vendor))

        if OpSystem().is_linux():
            drv.uninstall()
        else:
            drv.install()

        log.info("Requested FW version = {}".format(self.actual_version))

        atltool = atltoolper.AtlTool(port=self.port)

        # Pre-burn kickstart
        try:
            atltool.kickstart2()
        except atltoolper.KickstartError:
            pass

        clx = self.download()
        self._atltool_burn_clx(clx)

        atltool.kickstart2()

        log.info("Cold restart is not needed")
        return self.POSTINSTALL_NO_RESTART

    def is_atlantic2(self):
        return True


class FirmwareLocalPacific(FirmwareLocal):
    def download(self):
        if self.cdrom:
            log.info("Searching FW with CDROM enabled")
            path = os.path.join(self.FW_BUILD_BASE_PATH, self.version, "cdrom", "*.bin").replace("\\", "/")
        else:
            if self.bdp:
                log.info("Searching FW with BDP specified")
                path = os.path.join(self.FW_BUILD_BASE_PATH, self.version, "layouts", "*.bin").replace("\\", "/")
            else:
                path = os.path.join(self.FW_BUILD_BASE_PATH, self.version, "*.bin").replace("\\", "/")

        clx_files = list_files(path)
        if not self.cdrom:
            if not self.bdp:
                clx_file_name = clx_files[0]
            else:
                clx_file_name = next(file for file in clx_files if self.bdp in file)
        else:
            actual_version = get_actual_fw_version(self.version)
            ver_major, ver_minor = actual_version.split(".")[:2]
            if int(ver_major) != 3:
                re_cdrom = re.compile("Common_dongle_[0-9\.-]+_Normal_CDROM.bin", re.DOTALL)
            else:
                re_cdrom = re.compile("Common_cdrom_dongle_\d+.\d+.\d+-\d+_normal.bin", re.DOTALL)
            clx_file_name = next(line for line in clx_files if re_cdrom.search(line))

        log.info("The next firmware will be installed: {}".format(clx_file_name))
        file_on_server = os.path.join(self.version, "cdrom" if self.cdrom else "layouts" if self.bdp else "", clx_file_name).replace("\\", "/")
        clx_file = download_file(file_on_server)
        log.info("CLX file has been downloaded to {}".format(clx_file))
        return clx_file

    def install(self, overrides={}, flashless=False):
        return self._pactool_install()


class FirmwareRemote(Firmware):
    def __init__(self, **kwargs):
        super(FirmwareRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).wait(1500)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to execute remote command")
        if not any(SCRIPT_STATUS_SUCCESS in line for line in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote firmware operation")
        return res["output"]

    def install(self, overrides={}, flashless=False):
        cmd = "cd {} && sudo python firmware.py -p {} -c {} -s {} -v {} --mdi {} --mii {}".format(
            ATF_TOOLS_DIR, self.port, self.card, self.speed, self.version, self.mdi, self.mii)
        if self.pause:
            cmd += " --pause"
        if self.pcirom:
            cmd += " --pcirom {}".format(self.pcirom)
        if self.dirtywake:
            cmd += " --dirtywake"
        if self.sign:
            cmd += " --sign"
        if overrides != {}:
            cmd += " --overrides \"{}\"".format(overrides)
        if self.se_enable:
            cmd += " --se_enable"
        if self.hsd:
            cmd += " --hsd"
        if self.bdp:
            cmd += " -bdp {}".format(self.bdp)
        if self.cdrom:
            cmd += " --cdrom"
        if flashless:
            cmd += " --flashless"
        stdout = self.remote_exec(cmd)

        re_cold_restart = re.compile(".*Skipping kickstart and requesting cold restart.*")
        re_cold_restart_for_fiji = re.compile(".*Hotplug USB device for changes to take effect.*")
        re_warm_restart = re.compile(".*Requesting warm restart.*")
        re_no_restart = re.compile(".*Cold restart is not needed.*")

        is_cold_restart = False
        is_warm_restart = False
        is_no_restart = False

        re_ver = re.compile(".*equested FW version = ([0-9]+\.[0-9]+\.[0-9]+).*", re.DOTALL)
        actual_version = None
        for line in stdout:
            m = re_ver.match(line)
            if m is not None:
                actual_version = m.group(1)
            if re_cold_restart.match(line) is not None:
                is_cold_restart = True
            if re_cold_restart_for_fiji.match(line) is not None:
                is_cold_restart = True
            if re_warm_restart.match(line) is not None:
                is_warm_restart = True
            if re_no_restart.match(line) is not None:
                is_no_restart = True
        if not any([is_cold_restart, is_warm_restart, is_no_restart]):
            raise Exception("Do not know what to do after firmware installation")
        if is_cold_restart & is_warm_restart or is_warm_restart & is_no_restart or is_cold_restart & is_no_restart:
            raise Exception("Too many actions after restart are matched")
        if actual_version is None:
            raise Exception("Installed version is not parsed")
        if is_cold_restart:
            return Firmware.POSTINSTALL_COLD_RESTART
        elif is_warm_restart:
            return Firmware.POSTINSTALL_RESTART
        elif is_no_restart:
            return Firmware.POSTINSTALL_NO_RESTART
        else:
            raise Exception("Never happen")

    def download(self):
        """Downloads needed firmware"""
        cmd = "cd {} && sudo python firmware.py --download -p {} -c {} -s {} -v {} --mdi {} --mii {}".format(
            ATF_TOOLS_DIR, self.port, self.card, self.speed, self.version, self.mdi, self.mii)
        if self.se_enable:
            cmd += " --se_enable"
        if self.hsd:
            cmd += ' --hsd'
        stdout = self.remote_exec(cmd)
        download_path_regex = re.compile('.*CLX file has been downloaded to (\S+).*')
        path = None
        for line in stdout:
            path = download_path_regex.match(line)
            if path is not None:
                break

        if path is None:
            raise Exception("Failed to find out download path from stdout")
        else:
            path = path.group(1)
            return path


class PhyFirmware(object):
    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(PhyFirmwareLocal)
        else:
            return object.__new__(PhyFirmwareRemote)

    def __init__(self, **kwargs):
        # self.phy_control = kwargs["phy_control"]
        self.version = kwargs["version"]
        self.package = kwargs.get("package", None)
        self.board_name = kwargs.get("board_name", None)
        if self.package is None:
            self.package = os.environ.get("DUT_PHY_FW_PACKAGE", '7x7')

        self.part_number = kwargs.get("part_number", None)
        if self.part_number is None:
            self.part_number = os.environ.get("DUT_PHY_FW_PART_NUMBER", 'AQR113')

        self.suffix = kwargs.get("suffix", None)
        if self.suffix is None:
            self.suffix = os.environ.get("DUT_PHY_FW_SUFFIX", None)

        self.mode = kwargs.get("mode", MII_MODE_XFI_SGMII)
        # FIXME: DURTY HACK
        self.mode = 'OCSGMII_MixedMode' if self.mode == MII_MODE_OCSGMII else self.mode

    @abstractmethod
    def download(self):
        pass

    @abstractmethod
    def install(self):
        pass


class PhyFirmwareRemote(PhyFirmware):
    def __init__(self, **kwargs):
        super(PhyFirmwareRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]

    def remote_exec(self, cmd):
       res = Command(cmd=cmd, host=self.host).run()
       if res["returncode"] != 0 or not any(SCRIPT_STATUS_SUCCESS in s for s in res["output"]):
           log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
           raise Exception("Failed to perform remote PHY FW operation")
       return res["output"]

    def download(self):
        cmd = "cd {} && sudo python firmware.py --phy_download "
        self.remote_exec(cmd)

    def install(self):
        cmd = "cd {} && sudo python firmware.py --phy_install --phy_version={} --phy_board_name={} --phy_id={}".\
               format(ATF_TOOLS_DIR, self.version, self.board_name, 0)
        self.remote_exec(cmd)


class PhyFirmwareLocal(PhyFirmware):
    FW_BUILD_BASE_PATH = "/storage/export/builds/firmware/phy"

    PART_NUMBER_TO_PHY_TYPE_MAP = {
        'AQR113': PHY_RHEA,
        'AQR111': PHY_CALYPSO,
        'AQR107': PHY_EUROPA
    }


    def __init__(self, **kwargs):
        super(PhyFirmwareLocal, self).__init__(**kwargs)
        self.phy_control = kwargs["phy_control"]

    def download(self):
        path = os.path.join(self.FW_BUILD_BASE_PATH, self.PART_NUMBER_TO_PHY_TYPE_MAP[self.part_number].lower(),
                            self.version, "*.cld").replace("\\", "/")
        cld_files = list_files(path)

        log.info("Selecting PHY firmware by next parameters: version = {}, package = {}, part number = {}, mode = {}, "
                 "suffix = {}".format(self.version, self.package, self.part_number, self.mode, self.suffix))

        regex = r"[RheCalEur]+_[v0-9\.]+-lab_AQ_([AQR134807]+)_([1247x]+)_[boardcrystal]*[_]*(.*)_ID(.*)\.cld"
        re_cld = re.compile(regex, re.DOTALL)
        for cld_file_name in cld_files:
            m = re_cld.match(cld_file_name)
            if not m:
                continue
            part_number, package, mode, suffix = m.groups()
            if part_number == self.part_number and package == self.package and mode == self.mode:
                if (self.suffix is not None and self.suffix in suffix) or (self.suffix is None):
                    log.info('    found: {}'.format(cld_file_name))
                    break
        else:
            raise Exception("Failed to find needed CLD file")


        file_on_server = os.path.join("phy", self.PART_NUMBER_TO_PHY_TYPE_MAP[self.part_number].lower(), self.version, cld_file_name)
        return download_file(file_on_server)

    def install(self):
        cld_file = self.download()
        self.phy_control.flashBurn(cld_file, resetAfterBurn=False)  # will reset using register 0x1e.0x2681
        log.info("PHY Reset")
        self.phy_control.rmap.cmn.GlobalCommonPorControl_2().phyReset.rmw(self.phy_control, 0x1)
        self.phy_control.pifFlush()
        time.sleep(1)

        log.info("Checking heartbeat ... ")
        phb_1 = self.phy_control.rmap.glb.GlobalReservedStatus_2().nearlySecondsLSW.readValue(self.phy_control)
        time.sleep(1.1)
        phb_2 = self.phy_control.rmap.glb.GlobalReservedStatus_2().nearlySecondsLSW.readValue(self.phy_control)
        if phb_2 <= phb_1:
            raise Exception("PHY is dead after burning")
        log.info("Heartbeat is OK")


class FirmwareArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error(SCRIPT_STATUS_FAILED)
        self.exit(2, "%s: error: %s\n" % (self.prog, message))


if __name__ == "__main__":
    parser = FirmwareArgumentParser()

    parser.add_argument("-p", "--port", help="PCI port", type=str, default="pci1.00.0")
    parser.add_argument("-c", "--card", help="Card name", type=str, choices=KNOWN_CARDS)
    parser.add_argument("-s", "--speed", help="Maximal speed", type=str, default=LINK_SPEED_10G,
                        choices=[LINK_SPEED_5G, LINK_SPEED_10G])
    parser.add_argument("-v", "--version", help="Firmware version", type=str)
    parser.add_argument("-bdp", help="Firmware bdp", type=str)
    parser.add_argument("-md", "--mdi", help="MDI type", type=str, default=MDI_NORMAL,
                        choices=[MDI_NORMAL, MDI_SWAP])
    parser.add_argument("-mi", "--mii", help="MII type", type=str, default=MII_MODE_USX_SGMII,
                        choices=MII_MODES)
    parser.add_argument("--hsd", help="HSD", dest="hsd", action="store_true", default=False)
    parser.add_argument("--pcirom", help="PCIROM version", type=str)
    parser.add_argument("--pause", help="Pause frames enabled", action="store_true", default=False)
    parser.add_argument("--dirtywake", help="Dirtywake enabled", action="store_true", default=False)
    parser.add_argument("--cdrom", help="CDROM for FIji", dest="cdrom", action="store_true", default=False)
    parser.add_argument("--overrides", help="Overrides information", action=SpacedArgAction, nargs='+',
                        dest="overrides")
    parser.add_argument("--download", help="Download firmware clx", action="store_true")
    parser.add_argument("--sign", help="Install signed FW", action="store_true", default=False)
    parser.add_argument("--se_enable", help="Install SE FW on Nikki", action="store_true", default=False)
    parser.add_argument("--flashless", help="Force flashless boot", action="store_true", default=False)
    parser.add_argument("--phy_install", help="Install FW for PHY", action="store_true")
    parser.add_argument("--phy_download", help="Download FW for PHY", action="store_true")
    parser.add_argument("--phy_version", help="FW version for PHY", type=str, default="stable")
    parser.add_argument("--phy_suffix", help="FW suffix for PHY", type=str, default=None)
    parser.add_argument("--phy_board_name", help="Board name PHY", type=str, default=None)
    parser.add_argument("--phy_id", help="PHY id", type=str, default="0")
    args = parser.parse_args()

    try:
        if args.phy_install:
            validation_path = "D:/common_rev1.0_Validation/Validation"
            common_dir = os.path.join(validation_path, "common")
            sys.path.append(common_dir)
            sys.path.append(os.path.join(common_dir, 'PlatformDrivers'))
            sys.path.append(os.path.join(common_dir, 'InstrumentDrivers'))
            # Rhea only
            from phycontrolrhe import PhyControlRhe as PhyControlX

            log.info("Creating remote PHY control using board name {} and phy id {}".format(args.phy_board_name, args.phy_id))
            phy_control = PhyControlX(str(args.phy_board_name), int(args.phy_id), trapDirectAccesses=False)

            phy_firmware = PhyFirmware(phy_control=phy_control,
                                   version=args.phy_version,
                                   suffix=args.phy_suffix)
            phy_firmware.install()
        else:
            overrides = args.overrides if args.overrides is not None else "{}"
            overrides = eval(overrides)
            firmware = Firmware(port=args.port, card=args.card, speed=args.speed, version=args.version, mdi=args.mdi,
                                mii=args.mii, pause=args.pause, pcirom=args.pcirom, dirtywake=args.dirtywake, bdp=args.bdp,
                                sign=args.sign, se_enable=args.se_enable, hsd=args.hsd, cdrom=args.cdrom)
            if args.download:
                firmware.download()
            else:
                firmware.install(overrides=overrides, flashless=args.flashless)
    except Exception:
        log.exception("Firmware failed")
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
