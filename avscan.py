import codecs
import csv
import socket
import sys
import os
import time
from datetime import datetime
import pytest

if __package__ is None:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.utils import remove_file, remove_directory
from infra.test_base import TestBase
from tools.command import Command
from tools.log import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "avscan"


class AntiVirus(object):
    name = ""
    cmd = ""
    scan_timeout = 1800

    def __init__(self, name, cmd):
        self.name = name
        self.cmd = cmd

    @staticmethod
    def download_folder(folder):
        download_location = "d:\\anti_virus_scan_automation"
        remove_directory(download_location)

        res = Command(cmd="mkdir {}".format(download_location)).run()
        assert res["returncode"] == 0, "Failed to create download location"

        res = Command(cmd="cp -r {} {}".format(folder, download_location)).run()
        assert res["returncode"] == 0, "Failed to download folder '{}'".format(folder)

        return download_location

    def _run(self, folder):
        return Command(cmd='cmd /C ({})'.format(self.cmd.format(folder))).run_join(timeout=self.scan_timeout)

    def scan(self, folder):
        scan_folder = self.download_folder(folder)
        res = self._run(scan_folder)
        if not self.check_output(res):
            raise Exception("'{}' anti-virus scan failed, check the output!".format(self.name))

    def check_output(self, res):
        return res["returncode"] == 0


class Avast(AntiVirus):
    def __init__(self):
        super(Avast, self).__init__("avast", '"C:\\Program Files\\AVAST Software\\Avast\\ashcmd.exe" /p /_ "{}"')


class Kaspersky(AntiVirus):
    def __init__(self):
        super(Kaspersky, self).__init__(
            "kaspersky",
            '"C:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Small Office Security 17.0.0\\avp.com" scan "{}" /i0')


class DrWeb(AntiVirus):
    def __init__(self):
        super(DrWeb, self).__init__("drweb", '"C:\\Program Files\\DrWeb\\dwscancl.exe" "{}" /RP:drweb_scan.log')

    def check_output(self, res):
        # drweb does not print output, need to get it from log file
        Command(cmd="cat drweb_scan.log").run()
        return res["returncode"] == 0


class McAfee(AntiVirus):
    def __init__(self):
        super(McAfee, self).__init__("mcafee", '"C:\\Program Files\\McAfee\\MfeAV\\mfeODS.exe" /custom "{}"')

    def check_output(self, res):
        for line in res["output"]:
            # remove all non-printable symbols
            line = "".join(c for c in line if c.isalnum() or c in ["%", ":", " "])
            log.debug(line)
            # find line like "100% Complete Scanned: 4226 Found: 0 Resolved: 0"
            if "100% Complete" in line and "Found: 0" in line and "Scanned: 0" not in line:
                return True
        return False


class Norton(AntiVirus):
    def __init__(self):
        self.base_path = self.get_base_path()
        self.log_file = "d:\\norton_scan.csv"
        self.start_time = datetime.now()
        super(Norton, self).__init__("norton", '"{}\\Navw32.exe" "{{}}"'.format(self.base_path))

    @staticmethod
    def get_base_path():
        install_path = "C:\\Program Files\\Norton Security\\Engine"
        subfolder = os.listdir(install_path)[0]
        return os.path.join(install_path, subfolder)

    # need to run norton async and then wait till Finish button appears and click it
    def _run(self, folder):
        command = Command(cmd='cmd /C ({})'.format(self.cmd.format(folder)))
        command.run_async()
        time.sleep(30)

        try:
            from pywinauto import Application
            a = Application(backend="uia").connect(title="On-Demand Scan")
            finish_button = a['On-Demand Scan'].child_window(title="Finish", control_type="Button")
            finish_button.wait("visible", timeout=self.scan_timeout)
            finish_button.invoke()
            # make sure window is closed after clicking Finish
            a['On-Demand Scan'].wait_not("visible")
        except Exception as e:
            command.join(self.scan_timeout)
            raise e

    def check_output(self, res):
        # norton starts gui application and does not print anything to console
        # so we need to export its history to csv and parse the last scan results
        remove_file(self.log_file)
        Command(cmd='"{}\\MCUI32.exe" /export {}'.format(self.base_path, self.log_file)).run()

        with codecs.open(self.log_file, 'rU', 'utf-16') as csvFile:
            csvFile.next()  # skip first line with category header
            reader = csv.DictReader(csvFile, quotechar='"', delimiter=',', quoting=csv.QUOTE_MINIMAL,
                                    skipinitialspace=True)
            last_scan_results = reader.next()  # take the first line - it should be last result
            log.info(last_scan_results)

            # make sure we collected correct results
            assert last_scan_results['Task Name'] == 'On-Demand scan', "Cannot get last scan results"
            assert last_scan_results['Activity'] == 'On-Demand scan results', "Cannot get last scan results"
            report_time = datetime.strptime(last_scan_results["Date & Time"], "%m/%d/%Y %I:%M:%S %p")
            assert report_time > self.start_time, "Cannot get last scan results"

            return last_scan_results["Total Security Risks Detected"] == "0"


class TestAvScan(TestBase):
    av_host_mapping = {
            "av001-vm": McAfee,
            "av002-vm": Kaspersky,
            "av003-vm": Norton,
            "av004-vm": DrWeb,
            "av005-vm": Avast
        }

    @classmethod
    def setup_class(cls):
        cls.state.load()
        cls.log_server = os.environ.get("LOG_SERVER", None)
        cls.log_path = os.environ.get("LOG_PATH", None)
        cls.job_id = os.environ.get("JOB_ID", None)
        cls.platform = os.environ.get("PLATFORM", None)
        cls.test = os.environ.get("TEST", "")
        cls.log_server_dir = cls.create_logs_dir_on_log_server()
        cls.dut_hostname = os.environ.get("DUT_HOSTNAME", socket.gethostname())

        if cls.dut_hostname not in cls.av_host_mapping.keys():
            raise Exception("Anti virus software is installed on 'av00x-vm' machines, cannot run on this host")

        cls.working_dir = os.environ.get("WORKING_DIR", None)
        TestBase.log_server = os.environ.get("LOG_SERVER", None)
        TestBase.log_local_dir = cls.working_dir
        TestBase.log_server_dir = None

        cls.scan_folder = os.environ.get("SCAN_FOLDER", None)
        if not cls.scan_folder:
            raise Exception("SCAN_FOLDER parameter is required to run this test")
        cls.scan_folder = cls.scan_folder.replace("/", "\\")

    def get_av_on_host(self, host):
        return self.av_host_mapping[host]()

    def test_avscan(self):
        antivirus = self.get_av_on_host(self.dut_hostname)

        # mcafee is very unstable, need to do reboot before scan
        if isinstance(antivirus, McAfee) and not self.state.skip_reboot:
            self.state.skip_reboot = True
            self.state.update()
            self.restart()

        antivirus.scan(self.scan_folder)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
