import glob
import json
import os
import sys
import tempfile
import time
import timeit
import urlparse
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pytest
import win32service
import win32serviceutil
import _winreg

if __package__ is None:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from msi_installer import MsiInstaller
from infra.test_base import TestBase
from tools.constants import BUILDS_SERVER, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, \
    LINK_SPEED_5G, LINK_SPEED_10G, DIRECTION_RX, DIRECTION_TX, LINK_STATE_UP, LINK_SPEED_AUTO
from tools.command import Command
from tools.killer import Killer
from tools.driver import Driver
from tools.utils import get_atf_logger, get_url_response, upload_directory, remove_directory, download_directory
from tools.virtual_network import VirtualHost, VirtualRouter, VirtualNetwork

log = get_atf_logger()


class AqGamingBase(TestBase):
    # AQGaming python wrapper
    aqgaming = None

    TCP = "TCP"
    TCP_NOT_FRAG = "TCP_NOT_FRAG"
    UDP = "UDP"
    UDP_NOT_FRAG = "UDP_NOT_FRAG"

    BANDWIDTH_TOLERANCE_LOW = 0.4
    BANDWIDTH_TOLERANCE_HIGH = 1.1
    BANDWIDTH_PRIORITY_RATIO = 1.5

    DUT_IP4 = "192.168.0.2"
    DUT_IP4_MASK = "255.255.255.0"
    DUT_IP4_GATEWAY = "192.168.0.1"
    DUT_IP6 = "1001:0000:0000:0000:0000:0000:0000:0002"
    DUT_IP6_PREFIX = "64"
    DUT_IP6_GATEWAY = "1001:0000:0000:0000:0000:0000:0000:0001"

    VIRTUAL_NETWORK_CFG = "~/qa-tests/tools/gaming_vn.imn"
    LOCAL_HOSTS = [VirtualHost("LPC1", "192.168.0.3", "1001:0000:0000:0000:0000:0000:0000:0003", "00:00:00:aa:00:02"),
                   VirtualHost("LPC2", "192.168.0.4", "1001:0000:0000:0000:0000:0000:0000:0004", "00:00:00:aa:00:05")]
    REMOTE_IP4_NETWORK = "10.0.0.0"
    REMOTE_IP4_MASK = "255.255.255.0"
    REMOTE_IP6_NETWORK = "2001:0000:0000:0000:0000:0000:0000:0000"
    REMOTE_IP6_PREFIX = "64"
    REMOTE_HOSTS = [VirtualHost("RPC1", "10.0.0.2", "2001:0000:0000:0000:0000:0000:0000:0002"),
                    VirtualHost("RPC2", "10.0.0.3", "2001:0000:0000:0000:0000:0000:0000:0003")]
    VIRTUAL_ROUTER = VirtualRouter("ROUTER1", DUT_IP4_GATEWAY, DUT_IP6_GATEWAY,
                                   "10.0.0.1", "2001:0000:0000:0000:0000:0000:0000:0001")
    # Gaming package paths
    PACKAGE_PATH = tempfile.gettempdir()
    CERTIFICATE_PATH = os.path.join("tools", "AQApp.cer")
    MSI_PATH = None
    WRAPPER_PATH = None
    CLEANUP_TOOL_URL = "http://qa-nfs01.rdc-lab.marvell.com/qa/testing/aqgaming-cleanup.exe"
    CLEANUP_TOOL_PATH = None

    # Additional tools
    RTT_CLIENT_WIN_URL = "http://qa-nfs01.rdc-lab.marvell.com/qa/testing/rtt/rttclient.exe"
    RTT_CLIENT_WIN_PATH = os.path.join(PACKAGE_PATH, "rttclient.exe")
    RTT_SERVER_LIN_URL = "http://qa-nfs01.rdc-lab.marvell.com/qa/testing/rtt/rttserver"
    RTT_SERVER_LIN_PATH = "/tmp/rttserver"
    RTT_CLIENT_JSON_OUTPUT = os.path.join(PACKAGE_PATH, "rtt.json")

    IPERF_COPY = ""

    # Gaming installation constants
    AQGAMING_SERVICE = "AQGaming"
    AQGAMING_INSTALL_PATH = ["C:/Program Files/Aquantia",
                             "C:/Users/aqtest/AppData/Local/Aquantia",
                             "C:/ProgramData/AQGaming"]
    AQGAMING_SERVICE_BIN_PATH = os.path.join(AQGAMING_INSTALL_PATH[0], "AqApp", "AqApp.exe")
    AQGAMING_DRIVER_FILES = ["C:/Windows/System32/drivers/AQCallout.sys",
                             "C:/Windows/System32/drivers/AQNdisLwf.sys"]
    AQGAMING_AQTION_APP = "AQtion"
    AQGAMING_WMI_PRODUCT_NAME = "AQtion%"
    AQGAMING_SERVICE_LOGS_PATH = "C:/ProgramData/AQGaming/logs/*.log"

    # Gaming registry constants
    REGISTRY_STARTUP_PATHS = [
        (_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
        (_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"),
        (_winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"),
        (_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
        (_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"),
        (_winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"),
        (_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce")
    ]
    REGISTRY_APP_NAME = "AQtion.exe"

    # Service log level
    SERVICE_LOG_CRITICAL = 1
    SERVICE_LOG_DEBUG = 4

    @classmethod
    def setup_class(cls):
        super(AqGamingBase, cls).setup_class()
        cls.MANUAL_SESSION_ID = int(os.environ.get("SESSION_ID", 0))

        cls.log_server_dir = cls.create_logs_dir_on_log_server()

        if cls.dut_gaming_build is None:
            raise Exception("DUT gaming build must be specified to run this test")

        cls.install_firmwares()

        cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
        cls.dut_driver.uninstall()

        cls.download_package()
        cls.download_tools()
        cls.aqgaming_remove()
        cls.dut_driver.install_trusted_certificate(cls.CERTIFICATE_PATH)
        cls.dut_msi_installer = MsiInstaller(cls.MSI_PATH)
        cls.dut_msi_installer.install()
        cls.dut_driver.install()
        cls.cleanup_windows()
        cls.import_aqgaming()

        cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
        if not cls.MANUAL_SESSION_ID:
            cls.lkp_driver.install()

        cls.dut_ifconfig.set_ip_address(cls.DUT_IP4, cls.DUT_IP4_MASK, cls.DUT_IP4_GATEWAY)
        cls.dut_ifconfig.set_ipv6_address(cls.DUT_IP6, cls.DUT_IP6_PREFIX, cls.DUT_IP6_GATEWAY)
        cls.dut_ifconfig.add_route(cls.REMOTE_IP4_NETWORK, cls.REMOTE_IP4_MASK, cls.DUT_IP4_GATEWAY)
        cls.dut_ifconfig.add_route(cls.REMOTE_IP6_NETWORK, cls.REMOTE_IP6_PREFIX, cls.DUT_IP6_GATEWAY)
        cls.dut_ifconfig.set_link_speed(LINK_SPEED_AUTO)

        cls.lkp_virtual_network = VirtualNetwork(conf_file=cls.VIRTUAL_NETWORK_CFG, host=cls.lkp_hostname)
        try:
            if not cls.MANUAL_SESSION_ID:
                cls.lkp_virtual_network.stop_daemon()
                cls.lkp_virtual_network.start_daemon()
                cls.lkp_virtual_network.start_session()
            else:
                cls.lkp_virtual_network.session_id = cls.MANUAL_SESSION_ID

            cls.dut_ifconfig.wait_link_up()
        except Exception as exc:
            cls.virtual_network_cleanup()
            raise exc

        cls.make_iperf_copy()

    @classmethod
    def make_iperf_copy(cls):
        target_dir = os.path.join(cls.log_local_dir, "iperf_copy")
        iperf_copy_exe = os.path.join(target_dir, "iperf3_copy.exe")
        remove_directory(target_dir)
        download_directory("nn-nfs01", "/storage/export/tools/windows/iperf/64", target_dir)
        os.rename(os.path.join(cls.log_local_dir, "iperf_copy", "iperf3.exe"),
                  iperf_copy_exe)
        cls.IPERF_COPY = iperf_copy_exe

    @classmethod
    def teardown_class(cls):
        super(AqGamingBase, cls).teardown_class()
        if not cls.MANUAL_SESSION_ID:
            cls.virtual_network_cleanup()

        cls.aqgaming_kill_service()

        # Upload service logs to server
        if cls.log_server:
            upload_directory(cls.log_server, os.path.dirname(cls.AQGAMING_SERVICE_LOGS_PATH), cls.log_server_dir)

    def setup_method(self, method):
        super(AqGamingBase, self).setup_method(method)
        self.aqgaming.setVerbose(1)
        # Each test must initialize new client
        try:
            activated = self.aqgaming.getParameter(self.aqgaming.AQCOMM_SERVER_ACTUAL_STATE)
            if activated:
                log.info("Deactivating AQGaming client...")
                self.aqgaming_deactivate()
        except Exception as exc:
            log.warn(exc.message)

        try:
            self.aqgaming.clientUnregister()
            time.sleep(3)
        except self.aqgaming.AqgamingError:
            pass

        self.aqgaming_kill_service()
        self.aqgaming_start_service()

    def teardown_method(self, method):
        super(AqGamingBase, self).teardown_method(method)
        log.info("#" * 80)
        log.info("Current latest service log file: {}".format(max(glob.glob(self.AQGAMING_SERVICE_LOGS_PATH))))
        log.info("#" * 80)

        Killer().kill("rttclient")
        Killer(host=self.lkp_hostname).kill("rttserver")
        Killer().kill("iperf3")
        Killer(host=self.lkp_hostname).kill("iperf3")

    @classmethod
    def cleanup_windows(cls):
        # Disable autostart of AQGaming service to prevent affection of next tests
        try:
            exe_name = win32serviceutil.LocateSpecificServiceExe(cls.AQGAMING_SERVICE)
            win32serviceutil.ChangeServiceConfig(None, cls.AQGAMING_SERVICE, startType=win32service.SERVICE_DISABLED,
                                                 exeName=exe_name)
            cls.aqgaming_stop_service()
        except Exception:
            pass

        # Set flash isFirstRun to false to prevent AQCC to setup run on Windows startup
        hkey = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, r"Software\Aquantia\AQtion Command Center", 0,
                               _winreg.KEY_SET_VALUE)
        _winreg.SetValueEx(hkey, "isFirstRun", 0, _winreg.REG_SZ, "false")
        _winreg.CloseKey(hkey)

        # Remove AQGaming app from Windows Startup
        for group, path in cls.REGISTRY_STARTUP_PATHS:
            try:
                hkey = _winreg.OpenKey(group, path, 0, _winreg.KEY_SET_VALUE)
            except Exception:
                continue
            try:
                _winreg.DeleteValue(hkey, cls.REGISTRY_APP_NAME)
            except Exception:
                pass
            finally:
                _winreg.CloseKey(hkey)

    @classmethod
    def download_package(cls):
        base_url = urlparse.urljoin(BUILDS_SERVER, "Gaming/{}/".format(cls.dut_gaming_build))
        package_version = get_url_response(urlparse.urljoin(base_url, "version.txt")).strip()
        log.info("Downloading package {} to {}".format(package_version, cls.PACKAGE_PATH))

        msi_name = "AQtion_Command_Center_x64_v{}.msi".format(package_version)
        content = get_url_response(urlparse.urljoin(base_url, "bin/x64/{}".format(msi_name)))
        cls.MSI_PATH = os.path.join(cls.PACKAGE_PATH, msi_name)
        with open(cls.MSI_PATH, "wb") as f:
            f.write(content)

        wrapper_name = "aqgaming.pyd"
        content = get_url_response(urlparse.urljoin(base_url, "bin/x64/{}".format(wrapper_name)))
        cls.WRAPPER_PATH = os.path.join(cls.PACKAGE_PATH, wrapper_name)
        with open(cls.WRAPPER_PATH, "wb") as f:
            f.write(content)

        cls.CLEANUP_TOOL_PATH = os.path.join(cls.PACKAGE_PATH, "aqgaming-cleanup.exe")
        content = get_url_response(cls.CLEANUP_TOOL_URL)
        with open(cls.CLEANUP_TOOL_PATH, "wb") as f:
            f.write(content)

    @classmethod
    def download_tools(cls):
        content = get_url_response(cls.RTT_CLIENT_WIN_URL)
        with open(cls.RTT_CLIENT_WIN_PATH, "wb") as f:
            f.write(content)

        cmd = "wget -O {} \"{}\"".format(cls.RTT_SERVER_LIN_PATH, cls.RTT_SERVER_LIN_URL)
        res = Command(cmd=cmd, host=cls.lkp_hostname).run_join(20)
        if res["returncode"] != 0:
            raise Exception("Failed to download RTT server to LKP")
        cmd = "sudo chmod +x {}".format(cls.RTT_SERVER_LIN_PATH)
        res = Command(cmd=cmd, host=cls.lkp_hostname).run_join(20)
        if res["returncode"] != 0:
            raise Exception("Failed to change RTT server to executable")

    @classmethod
    def import_aqgaming(cls):
        sys.path.append(cls.PACKAGE_PATH)
        # global aqgaming
        cls.aqgaming = __import__("aqgaming")

    @classmethod
    def aqgaming_kill_service(cls):
        pid_cmd = "sc queryex {} | grep -i PID | awk '{{print $3}}'".format(cls.AQGAMING_SERVICE)
        res = Command(cmd=pid_cmd).run_join(5)
        if res["returncode"] == 0 and res["output"] and res["output"][0] and int(res["output"][0]) != 0:
            Command(cmd="taskkill /F /T /PID {}".format(res["output"][0])).run_join(5)

    @classmethod
    def aqgaming_start_service(cls):
        log.info("Starting {} service...".format(cls.AQGAMING_SERVICE))
        win32serviceutil.StartService(cls.AQGAMING_SERVICE)
        win32serviceutil.WaitForServiceStatus(cls.AQGAMING_SERVICE, win32service.SERVICE_RUNNING, 10)
        time.sleep(5)
        log.info("{} service started".format(cls.AQGAMING_SERVICE))

    @classmethod
    def aqgaming_stop_service(cls):
        log.info("Stopping {} service".format(cls.AQGAMING_SERVICE))
        win32serviceutil.StopService(cls.AQGAMING_SERVICE)
        win32serviceutil.WaitForServiceStatus(cls.AQGAMING_SERVICE, win32service.SERVICE_STOPPED, 10)
        log.info("{} service stopped".format(cls.AQGAMING_SERVICE))

    @classmethod
    def aqgaming_remove(cls):
        # Kill gaming application
        Killer().kill(cls.AQGAMING_AQTION_APP)

        # Kill AQGaming service
        cls.aqgaming_kill_service()

        # Call uninstall for AQGaming product
        Command(cmd="wmic.exe product where \"name like '{}'\" call uninstall".format(
            cls.AQGAMING_WMI_PRODUCT_NAME)).run_join(60)

        # Uninstall leftover drivers
        cmd = "powershell \"Get-WindowsDriver -Online | " \
              "where {$_.ProviderName -like 'Aquantia' -and $_.ClassName -like 'NetService'} | " \
              "select Driver | ft -hidetableheaders\""
        res = Command(cmd=cmd).run_join(10)
        if res["returncode"] == 0 and res["output"]:
            for line in res["output"]:
                if line.startswith("oem"):
                    Command(cmd="pnputil /delete-driver {} /force".format(line.strip())).run_join(10)

        # Delete driver files in case pnputil failed
        for path in cls.AQGAMING_DRIVER_FILES:
            Command(cmd="rm -rf \"{}\"".format(path)).run_join(10)

        # Remove AQGaming local files
        for path in cls.AQGAMING_INSTALL_PATH:
            Command(cmd="rm -rf \"{}\"".format(path)).run_join(10)

        # Call aqgaming_cleanup to cleanup registry
        Command(cmd=cls.CLEANUP_TOOL_PATH).run_join(30)

    @classmethod
    def aqgaming_clientRegister(cls):
        cls.aqgaming.clientRegister()
        time.sleep(3)
        cls.aqgaming.kickLib()
        time.sleep(3)

    @classmethod
    def aqgaming_poll_activated(cls, active):
        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time < 10.0:
            cls.aqgaming.kickLib()
            requested_state = cls.aqgaming.getParameter(cls.aqgaming.AQCOMM_SERVER_REQUESTED_STATE)
            log.debug("AQGaming requested state = {}".format(requested_state))
            if active and not requested_state:
                cls.aqgaming.activate()
                continue
            elif not active and requested_state:
                cls.aqgaming.deactivate()
                continue
            actual_state = cls.aqgaming.getParameter(cls.aqgaming.AQCOMM_SERVER_ACTUAL_STATE)
            log.debug("AQGaming actual state = {}".format(actual_state))
            if (active and actual_state) or (not active and not actual_state):
                break
            time.sleep(1)
        else:
            return False

        return True

    @classmethod
    def aqgaming_activate(cls, retry=True):
        cls.aqgaming.activate()
        time.sleep(1)
        cls.aqgaming.kickLib()
        time.sleep(1)

        assert cls.aqgaming.getParameter(cls.aqgaming.AQCOMM_SERVER_REQUESTED_STATE) == 1, \
            "Requested state parameter didn't set to 1"

        activated = cls.aqgaming_poll_activated(active=True)
        if not activated and retry:
            log.warning("AQGaming client wasn't activated. Cycling through deactivate-activate...")
            cls.aqgaming.deactivate()
            time.sleep(1)
            cls.aqgaming.kickLib()
            time.sleep(1)
            cls.aqgaming.activate()
            time.sleep(1)
            cls.aqgaming.kickLib()
            time.sleep(1)
            activated = cls.aqgaming_poll_activated(active=True)

        if not activated:
            raise Exception("Failed to activate AQGaming client")

    @classmethod
    def aqgaming_deactivate(cls, retry=True):
        cls.aqgaming.deactivate()
        time.sleep(1)
        cls.aqgaming.kickLib()
        time.sleep(1)

        assert cls.aqgaming.getParameter(cls.aqgaming.AQCOMM_SERVER_REQUESTED_STATE) == 0, \
            "Requested state parameter didn't set to 0"

        deactivated = cls.aqgaming_poll_activated(active=False)
        if not deactivated and retry:
            log.warning("AQGaming client wasn't activated. Cycling through activate-deactivate...")
            cls.aqgaming.activate()
            time.sleep(1)
            cls.aqgaming.kickLib()
            time.sleep(1)
            cls.aqgaming.deactivate()
            time.sleep(1)
            cls.aqgaming.kickLib()
            time.sleep(1)
            deactivated = cls.aqgaming_poll_activated(active=False)

        if not deactivated:
            raise Exception("Failed to deactivate AQGaming client")

    @classmethod
    def aqgaming_set_shaper_settings(cls, dn_mbit, up_mbit):
        cls.aqgaming.setParameter(cls.aqgaming.AQCOMM_PARAM_DNLIMIT, dn_mbit * 1000)
        cls.aqgaming.setParameter(cls.aqgaming.AQCOMM_PARAM_UPLIMIT, up_mbit * 1000)
        cls.aqgaming.kickLib()

    @classmethod
    def aqgaming_idle(cls, seconds):
        cls.aqgaming.setVerbose(0)
        for i in range(seconds):
            cls.aqgaming.kickLib()
            time.sleep(1)
        cls.aqgaming.setVerbose(1)

    @classmethod
    def aqgaming_idle_with_timestamps(cls, seconds, start_time, timestamps):
        timestamps.append([int(timeit.default_timer() - start_time), 0])
        cls.aqgaming_idle(seconds)
        timestamps[-1][1] = int(timeit.default_timer() - start_time)

    @classmethod
    def aqgaming_get_site_by_name(cls, name):
        for i in range(5):
            cls.aqgaming.kickLib()

            for id in cls.aqgaming.getSiteIds():
                site = cls.aqgaming.getSiteById(id)
                if name.lower() in site["siteName"].lower():
                    log.debug("Found site '{}': {}".format(name, site))
                    return site

            time.sleep(1)

        log.error("Currently registered sites:")
        for id in cls.aqgaming.getSiteIds():
            log.error(cls.aqgaming.getSiteById(id))
        raise Exception("Failed to find site '{}'".format(name))

    @classmethod
    def aqgaming_get_site_priority_by_name(cls, name):
        return cls.aqgaming_get_site_by_name(name)["priority"]

    @classmethod
    def aqgaming_set_site_priority_by_name(cls, name, priority):
        site = cls.aqgaming_get_site_by_name(name)
        cls.aqgaming.setSitePriority(site["id"], priority)
        cls.aqgaming.kickLib()

    @classmethod
    def aqgaming_get_app_by_name(cls, name):
        for i in range(5):
            cls.aqgaming.kickLib()

            for app_id in cls.aqgaming.getAppIds():
                app = cls.aqgaming.getAppById(app_id)
                if name.lower() in app["exeName"].lower() or name.lower() in app["productName"].lower():
                    log.debug("Found application '{}': {}".format(name, app))
                    return app

            time.sleep(1)

        log.error("Currently registered applications:")
        for app_id in cls.aqgaming.getAppIds():
            log.error(cls.aqgaming.getAppById(app_id))
        raise Exception("Failed to find application '{}'".format(name))

    @classmethod
    def aqgaming_get_app_priority_by_name(cls, name):
        return cls.aqgaming_get_app_by_name(name)["priority"]

    @classmethod
    def aqgaming_set_app_priority_by_name(cls, name, priority):
        app = cls.aqgaming_get_app_by_name(name)
        cls.aqgaming.setAppPriority(app["id"], priority)
        cls.aqgaming.kickLib()

    @classmethod
    def aqgaming_set_service_log_level(cls, log_level):
        hkey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Aquantia\AQGaming", 0, _winreg.KEY_SET_VALUE)
        try:
            _winreg.SetValueEx(hkey, "logLevel", 0, _winreg.REG_DWORD, log_level)
        except Exception:
            log.error("Failed to set service log level")
        finally:
            _winreg.CloseKey(hkey)

    @classmethod
    def virtual_network_cleanup(cls):
        if hasattr(cls, "lkp_virtual_network"):
            for session_id in cls.lkp_virtual_network.list_sessions():
                cls.lkp_virtual_network.kill_session_by_id(session_id)
            cls.lkp_virtual_network.stop_daemon()

    def virtual_network_set_shaping(self, speed_mbit):
        cmd_tmpl = "tc qdisc replace dev eth{} root tbf rate {}mbit burst 32kbit latency 400ms"
        res = self.lkp_virtual_network.virtual_cmd(name=self.VIRTUAL_ROUTER.name,
                                                   cmd=cmd_tmpl.format(0, speed_mbit)).run_join(20)
        if res["returncode"] != 0:
            raise Exception("Failed to set network shaping settings")
        res = self.lkp_virtual_network.virtual_cmd(name=self.VIRTUAL_ROUTER.name,
                                                   cmd=cmd_tmpl.format(1, speed_mbit)).run_join(20)
        if res["returncode"] != 0:
            raise Exception("Failed to set network shaping settings")

    def virtual_network_clear_shaping(self):
        cmd_tmpl = "tc qdisc del dev eth{} root"
        self.lkp_virtual_network.virtual_cmd(name=self.VIRTUAL_ROUTER.name, cmd=cmd_tmpl.format(0)).run_join(20)
        self.lkp_virtual_network.virtual_cmd(name=self.VIRTUAL_ROUTER.name, cmd=cmd_tmpl.format(1)).run_join(20)

    def start_iperf(self, exec_time, dut_address, lkp_name, port=5201, direction=DIRECTION_RX,
                    iperf_bin="iperf3", traffic=TCP, threads=4):
        traffic_args = {self.TCP: "-P {}".format(threads),
                        self.TCP_NOT_FRAG: "-P {} -l 1K".format(threads),
                        self.UDP: "-u -b 10G -l 60K -w 64K",
                        self.UDP_NOT_FRAG: "-u -b 10G -l 1K"}
        client_cmd_str = \
            "iperf3 --json -i 1 {} -t {} -c {} -4 -p {}".format(traffic_args[traffic], exec_time, dut_address, port)
        if direction == DIRECTION_TX:
            client_cmd_str += " -R"
        client_cmd = self.lkp_virtual_network.virtual_cmd(lkp_name, client_cmd_str, silent=True)

        server_cmd_str = "{} --json -s -4 -1 -p {}".format(iperf_bin, port)
        server_cmd = Command(cmd=server_cmd_str, silent=True)

        server_cmd.run_async()
        time.sleep(5)
        client_cmd.run_async()

        return server_cmd, client_cmd

    def collect_iperf(self, server_cmd, client_cmd, timeout=200):
        def iperf_object_pairs(pairs):
            dct = {}
            for key, value in pairs:
                if key in dct:
                    dct[key] = str(dct[key]) + "\n{}".format(value)
                else:
                    dct[key] = value

            return dct

        client_res = client_cmd.join(timeout)
        server_res = server_cmd.join(10)

        if client_res["returncode"] != 0 or client_res["reason"] != Command.REASON_OK:
            if any("No route to host" in line for line in client_res["output"]):
                log.error("RX stuck happened on the system")
                log.error("Stopping all tests to be able to manually investigate the problem")
                pytest.exit("RX stuck")

            log.error(client_res["output"]["error"])
            raise Exception("Iperf client didn't finish by itself")

        if server_res["reason"] != Command.REASON_OK:
            log.error(server_res["output"]["error"])
            raise Exception("Iperf server didn't finish by itself")

        # need to collect receiver performance in TX case
        cmd_result = client_res if "-R" in client_cmd.cmd else server_res

        output = cmd_result["output"]
        if output[0].startswith("warning:"):
            log.error("Iperf warning: {}".format(output[0]))
            output = output[1:]
        output_dict = json.loads("".join(output), object_pairs_hook=iperf_object_pairs)

        if cmd_result["returncode"] != 0:
            if "error" in output_dict:
                log.error("Iperf error:\n{}".format(output_dict["error"]))
            raise Exception("Iperf server failed")

        speeds = []

        for interval in output_dict["intervals"]:
            bits_per_sec = interval["sum"]["bytes"] * 8 / interval["sum"]["seconds"]
            speeds.append(bits_per_sec)
            log.debug("Receiver speed = {} Mbit/s".format(bits_per_sec / 1000 / 1000))

        return speeds

    def start_rtt(self, exec_time, lkp_virtual_host, message_size=64):
        server_cmd_str = self.RTT_SERVER_LIN_PATH
        server_cmd = self.lkp_virtual_network.virtual_cmd(name=lkp_virtual_host.name, cmd=server_cmd_str)

        client_cmd_str = "{} -r {} -m {} -o {} {}".format(self.RTT_CLIENT_WIN_PATH, exec_time, message_size,
                                                          self.RTT_CLIENT_JSON_OUTPUT, lkp_virtual_host.ipv4)
        client_cmd = Command(cmd=client_cmd_str)

        server_cmd.run_async()
        time.sleep(5)
        client_cmd.run_async()

        return client_cmd, (server_cmd, lkp_virtual_host)

    def collect_rtt(self, client_cmd, server_cmd_host):
        client_res = client_cmd.join()

        server_cmd, server_host = server_cmd_host
        server_pid_cmd = self.lkp_virtual_network.virtual_cmd(
            name=server_host.name,
            cmd="ps -ef | grep -i {} | grep -v grep | awk '{{print $2}}'".format(self.RTT_SERVER_LIN_PATH))
        res = server_pid_cmd.run_join(5)
        if res["returncode"] == 0:
            server_kill_cmd = self.lkp_virtual_network.virtual_cmd(
                name=server_host.name, cmd="kill -9 {}".format(" ".join(line.strip() for line in res["output"])))
            server_kill_cmd.run_join(5)
        server_cmd.join(1)

        if client_res["reason"] != Command.REASON_OK:
            raise Exception("RTT client didn't finish by itself")

        client_delays = []
        client_losses = 0
        client_disorder = 0

        with open(self.RTT_CLIENT_JSON_OUTPUT, "r") as f:
            client_dict = json.load(f)

            for trial in client_dict["trials"]:
                if trial["result"] == "OK":
                    client_delays.append(trial["delay"])
                    log.debug("Client RTT = {} us".format(trial["delay"]))
                elif trial["result"] == "DISORDER":
                    client_disorder += 1
                    log.debug("Packet disorder!")
                else:
                    client_losses += 1
                    log.debug("Packet lost!")

        return client_delays, client_losses, client_disorder

    @staticmethod
    def get_link_speed_mbit(link_speed):
        if link_speed == LINK_SPEED_100M:
            return 100
        elif link_speed == LINK_SPEED_1G:
            return 1000
        elif link_speed == LINK_SPEED_2_5G:
            return 2500
        elif link_speed == LINK_SPEED_5G:
            return 5000
        elif link_speed == LINK_SPEED_10G:
            return 10000
        else:
            return 0

    @staticmethod
    def create_bar_plot(name, *args):
        labels = []
        data_arrays = []
        for label_data in args:
            if isinstance(label_data, tuple):
                label, data = label_data
            else:
                label, data = None, label_data
            labels.append(label)
            data_arrays.append(data)
        max_data_len = max(len(data) for data in data_arrays)

        if len(labels) and max_data_len:
            bar_width = 0.2
            index = np.arange(max_data_len)
            fig, ax = plt.subplots(nrows=1, ncols=1)
            for i in range(len(labels)):
                data = data_arrays[i][:]
                if len(data) < max_data_len:
                    data.extend([0] * (max_data_len - len(data)))
                ax.bar(index + (i + 1) * bar_width, data, width=bar_width, align='edge', label=labels[i])
            ax.set_xticks(index)
            fig.tight_layout()
            fig.set_size_inches(40, 20)
            fig.legend()
            fig.savefig(name, dpi=120, bbox_inches='tight')

    def assert_no_performance_degradation(self, expected_speed, actual_values, test_object):
        for i, speed in enumerate(actual_values):
            assert speed > expected_speed * 1000 * 1000 * self.BANDWIDTH_TOLERANCE_LOW, \
                "{} reduced speed to {} Mbit/s".format(test_object, sum(actual_values) / len(actual_values) / 1000 / 1000)

    def assert_speed_is_shaped(self, shaper_value, speeds):
        for i, speed in enumerate(speeds):
            assert speed < shaper_value * 1000 * 1000 * self.BANDWIDTH_TOLERANCE_HIGH, \
                "Speed in interval [{}] is too high: {}".format(i, speed)
            assert speed > shaper_value * 1000 * 1000 * self.BANDWIDTH_TOLERANCE_LOW, \
                "Speed in interval [{}] is too low (performance degradation): {}".format(i, speed)

    def skip_if_bad_performance(self, link_speed, iperf):
        if iperf < link_speed * 1000 * 1000 * self.BANDWIDTH_TOLERANCE_LOW:
            msg = "Something went wrong, iperf performance is to low: {} on {} Mbit/s link".format(
                iperf / 1000 / 1000, link_speed)
            log.warn(msg)
            pytest.skip(msg)
