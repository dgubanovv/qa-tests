import logging
import os
import subprocess
import tempfile
import time
import traceback
import urlparse
import _winreg

from xml.etree import ElementTree
from shutil import move, copy

import pytest
import requests

import tools.command
import tools.driver
import tools.firmware
import tools.ifconfig
import tools.ops
import tools.power
import tools.statistics
import tools.utils

from tools.constants import BUILDS_SERVER, LINK_SPEED_1G, LINK_SPEED_5G, LINK_SPEED_AUTO, \
                            CARD_FIJI
from tools.ops import OpSystem
from tools.utils import get_atf_logger, upload_file
from tools.killer import Killer

from infra.test_base import TestBase, idparametrize

log = get_atf_logger()


def setup_module(module):
    pass
    # import tools._test_setup  # uncomment for manual test setup

    # Test name to be executed
    # os.environ["TEST"] = "GENERIC_JOBS"
    # os.environ["TEST"] = "LAN_JOBS"
    # os.environ["TEST"] = "NDIS_JOBS"

# TODO:
# Tests not in our list:
# 1. CheckConnectivity with AutoFail
# 2. LinkCheck - need to automate cable unplug
# 3. headerPayloadSplit
# 4. MPE_Ethernet

# Create proper job lists for current OS
DUT_OPS = OpSystem()

# Generic jobs
GENERIC_MINIPORT_REQS = "generic/GenericMiniportRequirements.cpp"
GENERIC_OFFLOAD_PARITY = "generic/OffloadParity.cpp"

GENERIC_JOBS = [GENERIC_MINIPORT_REQS]

# LAN jobs
LAN_ADDRESS_CHANGE = "lan/AddressChange.cpp"
LAN_CHECK_CONNECTIVITY = "lan/CheckConnectivity.cpp"
LAN_CONFIG_CHECK = "lan/ConfigCheck.cpp"
LAN_E2E_PERF = "lan/E2EPerf.cpp"
LAN_GLITCH_FREE_DEVICE = "lan/GlitchFreeDevice.cpp"
LAN_INTERRUPT_MODERATION = "lan/InterruptModeration.cpp"
LAN_INVALID_PACKETS = "lan/InvalidPackets.cpp"
LAN_LINK_CHECK = "lan/LinkCheck.cpp"
LAN_MULTICAST = "lan/MultiCast.cpp"
LAN_OFFLOAD_CHECKSUM = "lan/OffloadChecksum.cpp"
LAN_OFFLOAD_LSO = "lan/OffloadLSO.cpp"
LAN_OFFLOAD_MISC = "lan/OffloadMISC.cpp"
LAN_PACKET_FILTERS = "lan/PacketFilters.cpp"
LAN_PM_REQUIREMENTS = "lan/PM_Requirements.cpp"
LAN_PM_WAKE_ON_LINK_CHANGE = "lan/PM_WakeOnLinkChange.cpp"
LAN_RESET = "lan/Reset.cpp"
LAN_SHORT_PACKETS = "lan/ShortPackets.cpp"
LAN_SINGLE_ETHER_TYPE = "lan/SingleEtherType.cpp"
LAN_STANDARDIZED_KEYWORDS = "lan/StandardizedKeywords.cpp"
LAN_STATS = "lan/Stats.cpp"
LAN_TX_FLOW_CTRL = "lan/TxFlowCtrl.cpp"
LAN_VLAN_SEND_RECV = "lan/VlanSendRecv.cpp"

LAN_OFFLOAD_RSC = "lan/OffloadRsc.cpp"  # Win8 and Win8.1 only

LAN_PM_POWER_STATE_TRANSITION = "lan/PM_PowerStateTransition.cpp"
LAN_PM_WOL_MAGIC_PACKET = "lan/PM_WolMagicPacket.cpp"
LAN_PM_WOL_PATTERN = "lan/PM_WolPattern.cpp"
LAN_PM_WOL_REQ = "lan/PM_Requirements.cpp"
LAN_KEEP_ALIVE = "lan/KeepAlive.cpp"

# LAN_JOBS = [LAN_CHECK_CONNECTIVITY,
            # LAN_GLITCH_FREE_DEVICE,
            # LAN_MULTICAST,
            # LAN_SHORT_PACKETS,
            # LAN_RESET,
            # LAN_ADDRESS_CHANGE,
            # LAN_INVALID_PACKETS,
            # LAN_PACKET_FILTERS,
            # LAN_STATS,
            # LAN_STANDARDIZED_KEYWORDS,
            # LAN_CONFIG_CHECK,
            # LAN_KEEP_ALIVE,
            # LAN_PM_POWER_STATE_TRANSITION,
            # LAN_PM_WOL_MAGIC_PACKET,
            # LAN_PM_WOL_PATTERN,
            # LAN_PM_WOL_REQ]

# Exlude some jobs due its cannot be run correctly on our setup (they are covered by regular PM tests)
LAN_JOBS = [LAN_CHECK_CONNECTIVITY,
            LAN_GLITCH_FREE_DEVICE,
            LAN_MULTICAST,
            LAN_SHORT_PACKETS,
            LAN_RESET,
            LAN_ADDRESS_CHANGE,
            LAN_INVALID_PACKETS,
            LAN_PACKET_FILTERS,
            LAN_STATS,
            LAN_STANDARDIZED_KEYWORDS,
            LAN_CONFIG_CHECK,
            LAN_PM_WOL_REQ,
            LAN_OFFLOAD_LSO,
            LAN_OFFLOAD_CHECKSUM]

# NDIS jobs
NDIS_SELECTIVE_SUSPEND = "ndis/SelectiveSuspend.cpp"
NDIS_JOBS = [NDIS_SELECTIVE_SUSPEND]

# Add or remove some tests according to current OS
if DUT_OPS.is_win7():
    GENERIC_JOBS.remove(GENERIC_OFFLOAD_PARITY)
    LAN_JOBS.remove(LAN_E2E_PERF)
    NDIS_JOBS.remove(NDIS_SELECTIVE_SUSPEND)
if DUT_OPS.is_win8() or DUT_OPS.is_win81():
    LAN_JOBS.append(LAN_OFFLOAD_RSC)
if not DUT_OPS.is_win10():
    LAN_JOBS.extend([LAN_PM_POWER_STATE_TRANSITION,
                     LAN_PM_WOL_MAGIC_PACKET,
                     LAN_PM_WOL_PATTERN,
                     LAN_KEEP_ALIVE])

# Jobs dictionary
JOBS = {
    "GENERIC_JOBS": GENERIC_JOBS,
    "LAN_JOBS": LAN_JOBS,
    "NDIS_JOBS": NDIS_JOBS,
}


class NDISBase(TestBase):
    _skip_setup_class = None
    _link_speed = None

    client_cmd_template = '{} /logo /auto /client /target:Miniport /tc:"{}" /support:{} /msg:{} /jobs:"{}"'
    server_cmd_template = 'ndistest.exe /logo /auto /server /support:{} /msg:{} /jobs:server.cpp'

    @classmethod
    def setup_class(cls):
        try:
            super(NDISBase, cls).setup_class()

            cls.dut_ops = OpSystem()
            cls.lkp_ops = OpSystem(host=cls.lkp_hostname)

            if cls._skip_setup_class is False:
                # Set debug/testsigning off
                res = tools.command.Command(cmd="bcdedit | grep debug").run()
                assert res["returncode"] in [0,1], "Failed to execute bcdedit"
                debug_off = (res["output"][0] if len(res["output"]) > 0 else 'Yes')

                res = tools.command.Command(cmd="bcdedit | grep testsigning").run()
                assert res["returncode"] in [0,1], "Failed to execute bcdedit"
                testsign_off = (res["output"][0] if len(res["output"]) > 0 else 'Yes')

                all_off = all("No" in val for val in [debug_off, testsign_off])

                if not all_off:
                    res = tools.command.Command(cmd="bcdedit /set debug off").run()
                    assert res["returncode"] == 0, "Failed to execute bcdedit"
                    res = tools.command.Command(cmd="bcdedit /set testsigning off").run()
                    assert res["returncode"] == 0, "Failed to execute bcdedit"
                    log.info("Rebooting host after bcdedit")
                    time.sleep(3)
                    cls.restart()

                if cls.dut_fw_card not in CARD_FIJI:
                    tools.command.Command(cmd="powershell set-netoffloadglobalsetting -ReceiveSegmentCoalescing Enabled").run()

                log.debug("Current lists of jobs:")
                for k, v in JOBS.items():
                    log.debug("{}: {}".format(k, v))

                if cls.dut_ops.get_name() != cls.lkp_ops.get_name():
                    log.warning("DUT OS and LKP OS are different. Will continue anyway")

                    if not cls.dut_ops.is_windows or not cls.lkp_ops.is_windows():
                        raise Exception("NDIS tests are applicable for Windows only!")

                cls.install_firmwares()
                cls.dut_driver = tools.driver.Driver(port=cls.dut_port, version=cls.dut_drv_version)
                cls.lkp_driver = tools.driver.Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)

                cls.dut_driver.install()
                cls.lkp_driver.install()
                time.sleep(cls.LINK_CONFIG_DELAY)

                internal_k = r"system\CurrentControlSet\Services\NDIS\Parameters"
                key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, internal_k, 0, _winreg.KEY_ALL_ACCESS)
                _winreg.SetValueEx(key, "AllowFlowControlUnderDebugger", 0, _winreg.REG_DWORD, 1)

            # Log dirs
            cls.dut_ndis_exe = cls.get_ndis_exe_path()
            cls.dut_ndis_logs_dir = cls.get_logs_dir_path()

            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            # Machine properties
            log.info("Getting LKP properties")
            lkp_message_mac = cls.lkp_ifconfig.get_management_mac_address()
            log.info("Got LKP management interface MAC address: {}".format(lkp_message_mac))
            cls.lkp_message_guid = cls.lkp_ifconfig.get_guid_by_mac(lkp_message_mac).split(" - ")[-1]
            log.info("Got LKP management interface GUID: {}".format(cls.lkp_message_guid))
            lkp_support_mac = cls.lkp_ifconfig.get_mac_address()
            log.info("Got LKP support interface MAC address: {}".format(lkp_support_mac))
            # cls.lkp_support_guid = cls.lkp_ifconfig.get_guid_by_mac(lkp_support_mac).split(" - ")[-1]
            cls.lkp_support_guid = cls.lkp_ifconfig.get_guid_by_port()
            log.info("Got LKP support interface GUID: {}".format(cls.lkp_support_guid))

            log.info("Getting DUT properties")
            dut_message_mac = cls.dut_ifconfig.get_management_mac_address()
            log.info("Got DUT management interface MAC address: {}".format(dut_message_mac))
            cls.dut_message_guid = cls.dut_ifconfig.get_guid_by_mac(dut_message_mac)
            log.info("Got DUT management interface GUID: {}".format(cls.dut_message_guid))
            cls.dut_device_id = cls.dut_ifconfig.get_wmi_device_id()
            log.info("Got DUT management interface Device ID: {}".format(cls.dut_device_id))

            cls.dut_ifconfig.set_link_speed(cls._link_speed)
            cls.lkp_ifconfig.set_link_speed(cls._link_speed)
            time.sleep(cls.LINK_CONFIG_DELAY)

        except Exception as e:
            log.error(traceback.format_exc(e))
            raise e

    @classmethod
    def teardown_class(cls):
        super(NDISBase, cls).teardown_class()

        tools.command.Command(cmd="bcdedit /set debug on").run()
        tools.command.Command(cmd="bcdedit /set testsigning on").run()
        cls.state.test_cleanup_cold_restart = True

    def setup_method(self, method):
        super(NDISBase, self).setup_method(method)

        log.info("Deleting NDIS tests logs...")
        tools.utils.remove_directory(self.dut_ndis_logs_dir)

    @classmethod
    def get_ndis_exe_path(cls):
        cmd = "where ndistest.exe"
        log.info("Looking for NDISTest.exe. Command: {}".format(cmd))
        output = subprocess.check_output(cmd)
        ndis_path = filter(bool, output.split("\r\n"))
        log.info("Found: {}".format(ndis_path))
        if len(ndis_path) > 1:
            log.warning("Found multiple NDISTest executables!")
            log.warning("Using last one: {}".format(ndis_path[-1]))
        return ndis_path[-1]

    @classmethod
    def get_logs_dir_path(cls):
        log.info("Generating NDISTest log path...")
        exe_dir = os.path.dirname(cls.dut_ndis_exe)
        logs_dir = os.path.join(exe_dir, "logs")
        log.info("Generated: {}".format(logs_dir))
        return logs_dir

    @classmethod
    def get_log_path_to_files(cls):
        log.info("Getting NDISTest tests log path...")
        log_path = os.path.join(cls.dut_ndis_logs_dir, os.listdir(cls.dut_ndis_logs_dir)[0], "run000")
        log.info("NDISTest tests log path: {}".format(log_path))
        return log_path

    def print_fails(self):
        log_local_dir = self.get_log_path_to_files()
        f = os.path.join(log_local_dir, os.listdir(log_local_dir)[0])
        tree = ElementTree.parse(f)
        xmls = tree.findall(".//xml", namespaces=None)
        xml = next(xml for xml in xmls if xml.attrib["name"] == 'Failures')
        faileditems = xml.findall("faileditems")

        log.info("Current fails: ")
        for fail in faileditems:
            faileditem = fail.findall("faileditem")
            for item in faileditem:
                desc = item.find("description")
                log.info(''.join(desc.itertext()))

    def run_server_on_lkp(self):
        Killer(host=self.lkp_hostname).kill("NDISTest")
        time.sleep(1)
        cmd = self.server_cmd_template.format(self.lkp_support_guid, self.lkp_message_guid)
        # server_cmd = tools.command.Command(cmd=cmd, host=self.lkp_hostname)
        # server_running_cmd = tools.command.Command(cmd='tasklist | grep "ndis" -i', host=self.lkp_hostname)

        run_file = "run.bat"
        with open(run_file, "w") as f:
            f.write(cmd)

        upload_file(self.lkp_hostname, run_file, "~/{}".format(run_file))
        run_cmd = "~/{}".format(run_file)

        for tries in range(3):
            log.info("Trying to start NDISTest server on LKP. Attempt: {}/3".format(tries + 1))
            server_cmd = tools.command.Command(cmd=run_cmd, host=self.lkp_hostname)
            server_cmd.run_async()

            time.sleep(10)

            log.info("Checking if NDISTest server is running...")
            server_running_cmd = tools.command.Command(cmd='tasklist | grep "ndis" -i', host=self.lkp_hostname)
            server_running = server_running_cmd.run_join(10)
            if len(server_running["output"]) == 0:
                log.warning("NDISTest server is not running. Trying to restart.")
            else:
                log.info("NDISTest server started")
                return True

        log.error("Couldn't start NDISTest server on LKP")
        log.info("Rebooting LKP")
        tools.power.Power(host=self.lkp_hostname).reboot()
        self.poll_host_offline(self.lkp_hostname, 120)
        if not self.poll_host_alive_and_ready(self.lkp_hostname, 300):
            raise Exception("Couldn't bring host {} back online".format(self.lkp_hostname))

        server_cmd.run_async()
        time.sleep(10)
        server_running = server_running_cmd.run_join(10)
        if len(server_running["output"]) == 0:
            raise Exception("Couldn't start NDISTest server on LKP")
        else:
            log.info("NDISTest server is started")
            return True

    def run_client_on_dut(self, test_name):
        def relocate_logs():
            try:
                log_local_dir = self.get_log_path_to_files()
                log_files = os.listdir(log_local_dir)
                log.info("Moving logs from {} to test directory".format(log_local_dir))
                for log_file in log_files:
                    copy(os.path.join(log_local_dir, log_file), self.test_log_dir)
            except Exception as e:
                log.error("Failed to move log files into another location: {}".format(traceback.format_exc(e)))
                return False

        log.info("Launching NDISTest client on DUT")
        formatted_jobs = test_name.replace("/", "\\")
        client_cmd = self.client_cmd_template.format(self.dut_ndis_exe, self.dut_device_id,
                                                     self.lkp_support_guid, self.dut_message_guid,
                                                     formatted_jobs)
        client_res = tools.command.Command(cmd=client_cmd).run()
        time.sleep(3)
        client_returncode = client_res["returncode"]

        if client_returncode == 0:
            relocate_logs()
            return True
        else:
            log.info("NDISTest client return code: {}".format(client_returncode))
            client_res = tools.command.Command(cmd=client_cmd).run()
            time.sleep(3)
            client_returncode = client_res["returncode"]

            if client_returncode == 4:
                # Try one more time with server reboot
                tools.power.Power(host=self.lkp_hostname).reboot()
                self.poll_host_offline(self.lkp_hostname, 120)
                if not self.poll_host_alive_and_ready(self.lkp_hostname, 300):
                    raise Exception("Couldn't bring host {} back online".format(self.lkp_hostname))

                run_cmd = "~/run.bat"
                server_cmd = tools.command.Command(cmd=run_cmd, host=self.lkp_hostname)
                server_cmd.run_async()
                time.sleep(10)

                server_running = tools.command.Command(cmd='tasklist | grep "ndis" -i', host=self.lkp_hostname).run_join(10)
                if len(server_running["output"]) == 0:
                    raise Exception("Couldn't start NDISTest server on LKP")
                else:
                    log.info("NDISTest server is started")

                client_res = tools.command.Command(cmd=client_cmd).run()
                time.sleep(3)

                client_returncode = client_res["returncode"]
                if client_returncode == 0:
                    relocate_logs()
                    return True
                if client_returncode == 4:
                    log.info("NDISTest client timed out trying to connect to server")
                    log.info("Probably NDISTest server couldn't start on LKP")
                    return False
                elif client_returncode == 1:
                    relocate_logs()
                    log.info("NDIS tests failed. See logs for details")
                    self.print_fails()
                    return False
            elif client_returncode == 1:
                relocate_logs()
                log.info("NDIS tests failed. See logs for details")
                self.print_fails()
                return False

    @idparametrize("test_name", JOBS[os.environ["TEST"]])
    def test_ndis(self, test_name):
        server_res = self.run_server_on_lkp()
        client_res = self.run_client_on_dut(test_name)
        test_result = server_res & client_res
        tools.command.Command(cmd="powercfg /lastwake").run()
        assert test_result


class TestNDIS_AutoNeg(NDISBase):
    _skip_setup_class = False
    _link_speed = LINK_SPEED_AUTO


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
