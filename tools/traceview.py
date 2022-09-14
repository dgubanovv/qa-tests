import urlparse
import constants
import zipfile
import io
import shutil
import os
import win32com.client as comclt
import time

from command import Command
from log import get_atf_logger
from utils import get_url_response, remove_file, remove_directory
from ops import OpSystem
from constants import CARD_FIJI, CARD_NIKKI

log = get_atf_logger()

PDB_USB = "aqnicusb.pdb"
PDB_PCI = "aqnic{}.pdb"
ETL = "aq.etl"
TXT = "aq.txt"


class Traceview(object):
    START_PATH = "driver/ndis/aquantia/"
    TV_START_CMD = "traceview -start aqtrace -rt -pdb {}  -f {} -level 7 -flag 0x7fff -v"
    TV_STOP_CMD = "traceview -stop aqtrace -v"
    TV_PROCESS_CMD = "traceview -process {} -pdb {} -o {} -nosummary"

    def __init__(self, version, release_version):
        self.version = version
        self.release_version = release_version
        self.card = (CARD_FIJI if "pacific" in self.version else CARD_NIKKI)
        self.dut_ops = OpSystem()
        self._get_pdb()

    def _get_pdb(self):
        arch = Command(cmd="arch").run_join(2)["output"][0].strip()
        if arch not in constants.KNOWN_ARCHES:
            raise Exception("Unknown system architecture '{}'".format(output))

        if arch in constants.KNOWN_X86_ARCHES:
            arch = "x86"
        else:
            arch = "x64"

        if self.card == CARD_FIJI:
            suburl = urlparse.urljoin(self.START_PATH, "{}/bin/symbols_ver{}.zip".format(self.version, self.release_version))
        else:
            suburl = urlparse.urljoin(self.START_PATH, "{}/bin/symbols/symbols_{}_ver{}.zip".format(self.version, arch, self.release_version))

        url = urlparse.urljoin(constants.BUILDS_SERVER, suburl)
        log.info("Downloading PDB from {}".format(url))
        content = get_url_response(url)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            archive.extractall()

        if self.dut_ops.is_win7():
            sub_dir = "win7"
            posfix = "620"
        elif self.dut_ops.is_win10():
            sub_dir = "win10"
            posfix = "650"
        elif self.dut_ops.is_win8():
            sub_dir = "win8"
            posfix = "630"
        else:
            raise Exception("Wrong OS version is detected")

        if self.card== CARD_FIJI:
            shutil.copy(os.path.join(sub_dir, arch, PDB_USB), ".")
            self.PDB = PDB_USB
        else:
            shutil.copy(os.path.join(sub_dir, PDB_PCI.format(posfix)), ".")
            self.PDB = PDB_PCI.format(posfix)

    def _send_any_key(self):
        wsh = comclt.Dispatch("WScript.Shell")
        wsh.AppActivate("traceview")
        wsh.SendKeys("a")

    def start(self):
        log.info("Start logging for driver: {}".format(self.release_version))
        cmd = Command(cmd=self.TV_START_CMD.format(self.PDB, ETL))
        cmd.run_async()
        time.sleep(2)
        self._send_any_key()
        cmd.join(1)

    def stop(self):
        log.info("Stop logging for driver: {}".format(self.release_version))
        cmd = Command(cmd=self.TV_STOP_CMD)
        cmd.run_async()
        time.sleep(2)
        self._send_any_key()
        cmd.join(1)
        time.sleep(2) # Let the .etl file to be processed

    def parse(self):
        log.info("Start parsing for driver: {}".format(self.release_version))
        cmd = Command(cmd=self.TV_PROCESS_CMD.format(ETL, self.PDB, TXT))
        cmd.run_async()
        time.sleep(3)
        self._send_any_key()
        cmd.join(1)

        with open(TXT, "r") as f:
            logs = f.readlines()

        if len(logs) == 0:
            raise Exception("No data was captured. Please re-run traceview")


        for f in [self.PDB, TXT, ETL, "CONERR$"]:
            remove_file(f)

        return logs
