import json
import io
import os
import sys
from shutil import copyfile, move
import socket
import time
import timeit
import urlparse
import hashlib
import pytest
import requests
import zipfile

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'perf'))

import test_state

from tools.ops import OpSystem
from tools.firmware import get_actual_fw_version
from tools.debug import collect_debug_info, collect_counters


def crazy_import(name):
    import imp
    fp, path, description = imp.find_module(name, sys.path)
    return imp.load_module(name, fp, path, description)


ops = OpSystem()
if ops.is_centos() or ops.is_rhel():

    perf = crazy_import('iperf')
    Iperf = perf.Iperf

    iperf_result = crazy_import('iperf_result')
    IperfResult = iperf_result.IperfResult

else:
    from perf.iperf import Iperf
    from perf.iperf_result import IperfResult

from tools import constants
from tools import driver
from tools import firmware
from tools import ifconfig
from tools import ops
from tools import pcontrol
from tools import ping
from tools import power
from tools import git
from tools import mbuper
from tools.command import Command
from tools.cpu_monitor import CPUMonitor
from tools.iptables import IPTables
from tools.killer import Killer
from tools.ops import OpSystem
from tools.mbuper import download_mbu
from tools.diagper import get_actual_diag_version
from tools.constants import ATF_TOOLS_DIR, BUILDS_SERVER, CHIP_REV_B0, \
    CHIP_REV_B1, KNOWN_LINK_SPEEDS, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_10G, METRIC_SERVER, HTTP_RETRY_COUNT, HTTP_RETRY_INTERVAL, FELICITY_CARDS, CARD_ANTIGUA, \
    LINK_SPEED_NO_LINK, MII_MODE_USX_SGMII, PHY_EUROPA, PHY_CALYPSO, PHY_RHEA, PHY_ANTIGUA, LINK_STATE_DOWN, \
    LINK_STATE_UP, SETUP_PERFORMANCE_MEDIUM, ALL_LINK_SPEEDS
from tools.ptp import PTP
from tools.receive_segment_coalescing import ReceiveSegmentCoalescing
from tools.statistics import Statistics
from tools.utils import remove_directory, str_to_bool, get_url_response, get_atf_logger

log = get_atf_logger()


def idparametrize(name, values, ids=None, fixture=False):
    if ids is None:
        ids = ["{}={}".format(name, v) for v in values]
    return pytest.mark.parametrize(name, values, ids=ids, indirect=fixture)


class TestBase(object):
    RESULT_PASSED = "PASS"
    RESULT_FAILED = "FAIL"
    RESULT_SKIPPED = "SKIPPED"
    RESULT_XFAIL = "XFAIL"

    LINK_CONFIG_DELAY = 25
    DEFAULT_NETMASK_IPV4 = "255.255.0.0"
    DEFAULT_PREFIX_IPV6 = '64'
    NETMASK_IPV4 = "255.255.0.0"
    PREFIX_IPV6 = "64"
    POWER_UP_TIMEOUT = 240
    POWER_DOWN_TIMEOUT = 35
    LED_TIMEOUT = 5

    state = test_state.TestState()

    @classmethod
    def setup_class(cls):
        log.info('Doing test setup...')
        try:
            # check that test name has no space symbols
            test_name = os.environ.get("TEST", '')
            cut_test_name = test_name.replace(' ', '').replace('\t', '').replace('\n', '')
            if cut_test_name != test_name:
                raise ValueError('Test name (os.environ["TEST"], at setup_module function) contains space symbols ' \
                                 '(it can cause problebs with sending output.log to server).')

            TestBase.dut_hostname = os.environ.get("DUT_HOSTNAME", socket.gethostname())
            TestBase.dut_ports = os.environ.get("DUT_PORTS", "").split(";")
            TestBase.dut_dev_ids = os.environ.get("DUT_DEV_IDS", "").split(";")
            TestBase.dut_card_dict = dict(zip(TestBase.dut_ports, TestBase.dut_dev_ids))
            TestBase.dut_port = os.environ.get("DUT_PORT", None)
            TestBase.dut_drv_version = os.environ.get("DUT_DRV_VERSION", None)
            TestBase.dut_drv_cdc = str_to_bool(os.environ.get("DUT_DRV_CDC", "False"))
            TestBase.dut_fw_version = os.environ.get("DUT_FW_VERSION", None)
            TestBase.dut_fw_card = os.environ.get("DUT_FW_CARD", None)
            TestBase.dut_fw_speed = os.environ.get("DUT_FW_SPEED", None)
            TestBase.dut_fw_mdi = os.environ.get("DUT_FW_MDI", None)
            TestBase.dut_fw_mii = os.environ.get("DUT_FW_MII", MII_MODE_USX_SGMII)
            TestBase.dut_fw_pause = str_to_bool(os.environ.get("DUT_FW_PAUSE", "NO"))
            TestBase.dut_fw_pcirom = os.environ.get("DUT_FW_PCIROM", None)
            TestBase.dut_fw_dirtywake = str_to_bool(os.environ.get("DUT_FW_DIRTYWAKE", "NO"))
            dut_dev_id = os.environ.get("DUT_DEV_ID", None)
            TestBase.dut_dev_id = None if dut_dev_id is None else int(dut_dev_id, 16)
            dut_subsys_id = os.environ.get("DUT_SUBSYS_ID", None)
            TestBase.dut_subsys_id = None if dut_subsys_id is None else int(dut_subsys_id, 16)
            dut_subven_id = os.environ.get("DUT_SUBVEN_ID", None)
            TestBase.dut_subven_id = None if dut_subven_id is None else int(dut_subven_id, 16)
            TestBase.dut_usb_connect = os.environ.get("DUT_USB_CONNECT", constants.USB_CONNECT_DIRECT)
            TestBase.dut_bdp = os.environ.get("DUT_BDP", None)
            TestBase.dut_sign = str_to_bool(os.environ.get("DUT_RBL", "False"))
            TestBase.dut_se = str_to_bool(os.environ.get("DUT_SE", "False"))
            TestBase.dut_hsd = str_to_bool(os.environ.get("DUT_HSD", "False"))
            TestBase.dut_flashless = str_to_bool(os.environ.get("DUT_FLASHLESS", "False"))
            TestBase.dut_gaming_build = os.environ.get("GAMING_BUILD", None)

            TestBase.lkp_hostname = os.environ.get("LKP_HOSTNAME", None)
            TestBase.lkp_port = os.environ.get("LKP_PORT", None)
            TestBase.lkp_drv_version = os.environ.get("LKP_DRV_VERSION", None)
            TestBase.lkp_fw_version = os.environ.get("LKP_FW_VERSION", None)
            TestBase.lkp_fw_card = os.environ.get("LKP_FW_CARD", None)
            TestBase.lkp_fw_speed = os.environ.get("LKP_FW_SPEED", None)
            TestBase.lkp_fw_mdi = os.environ.get("LKP_FW_MDI", None)
            TestBase.lkp_fw_mii = os.environ.get("LKP_FW_MII", MII_MODE_USX_SGMII)
            TestBase.lkp_fw_pause = str_to_bool(os.environ.get("LKP_FW_PAUSE", "NO"))
            TestBase.lkp_fw_pcirom = os.environ.get("LKP_FW_PCIROM", None)
            TestBase.lkp_fw_dirtywake = str_to_bool(os.environ.get("LKP_FW_DIRTYWAKE", "NO"))
            lkp_dev_id = os.environ.get("LKP_DEV_ID", None)
            TestBase.lkp_dev_id = None if lkp_dev_id is None else int(lkp_dev_id, 16)
            lkp_subsys_id = os.environ.get("LKP_SUBSYS_ID", None)
            TestBase.lkp_subsys_id = None if lkp_subsys_id is None else int(lkp_subsys_id, 16)
            lkp_subven_id = os.environ.get("LKP_SUBVEN_ID", None)
            TestBase.lkp_subven_id = None if lkp_subven_id is None else int(lkp_subven_id, 16)
            TestBase.lkp_usb_connect = os.environ.get("LKP_USB_CONNECT", constants.USB_CONNECT_DIRECT)
            TestBase.lkp_bdp = os.environ.get("LKP_BDP", None)
            TestBase.lkp_sign = str_to_bool(os.environ.get("LKP_RBL", "False"))
            TestBase.lkp_se = str_to_bool(os.environ.get("LKP_SE", "False"))
            TestBase.lkp_hsd = str_to_bool(os.environ.get("LKP_HSD", "False"))

            TestBase.mbu_version = os.environ.get("MBU_VERSION", None)
            TestBase.diag_version = os.environ.get("DIAG_VERSION", None)
            TestBase.efi_version = os.environ.get("EFI_VERSION", None)

            TestBase.setup_performance = os.environ.get("SETUP_PERFORMANCE", SETUP_PERFORMANCE_MEDIUM)
            TestBase.is_performance_setup = str_to_bool(os.environ.get("PERFORMANCE_SETUP", "False"))

            TestBase.working_dir = os.environ.get("WORKING_DIR", None)
            cable_length = os.environ.get("CABLE_LENGTH", None)
            TestBase.cable_length = int(cable_length) if cable_length is not None else None  # centimeters

            supported_speeds = os.environ.get("SUPPORTED_SPEEDS", None)
            if supported_speeds is not None:
                try:
                    supported_speeds = [s.strip() for s in supported_speeds.split(",")]
                    for speed in supported_speeds:
                        assert speed in ALL_LINK_SPEEDS, "Failed to detect speed: {}".format(speed)
                    # TODO: stupid sorting method below
                    TestBase.supported_speeds = []
                    for speed in ALL_LINK_SPEEDS:
                        if speed in supported_speeds:
                            TestBase.supported_speeds.append(speed)
                except Exception as e:
                    log.error('exception: {}'.format(e))
            else:
                raise Exception("SUPPORTED_SPEEDS evar is required")

            TestBase.skip_fw_install = str_to_bool(os.environ.get("SKIP_FW_INSTALL", "FALSE"))
            TestBase.skip_dut_fw_install = str_to_bool(os.environ.get("SKIP_DUT_FW_INSTALL", "FALSE"))
            TestBase.skip_lkp_fw_install = str_to_bool(os.environ.get("SKIP_LKP_FW_INSTALL", "FALSE"))
            TestBase.skip_drv_install = str_to_bool(os.environ.get("SKIP_DRV_INSTALL", "FALSE"))
            TestBase.skip_dut_drv_install = str_to_bool(os.environ.get("SKIP_DUT_DRV_INSTALL", "FALSE"))
            TestBase.skip_lkp_drv_install = str_to_bool(os.environ.get("SKIP_LKP_DRV_INSTALL", "FALSE"))
            TestBase.MCP_LOG = str_to_bool(os.environ.get("MCP_LOG", "FALSE"))

            TestBase.log_server = os.environ.get("LOG_SERVER", None)
            TestBase.log_path = os.environ.get("LOG_PATH", None)
            TestBase.job_id = os.environ.get("JOB_ID", None)
            TestBase.platform = os.environ.get("PLATFORM", None)
            TestBase.test = os.environ.get("TEST", "")

            TestBase.dut_phy_board_name = os.environ.get("DUT_PHY_BOARD_NAME", None)
            TestBase.dut_phy_type = os.environ.get("DUT_PHY_TYPE", None)
            TestBase.dut_phy_ids = map(int, os.environ.get("DUT_PHY_IDS", "0").split(","))
            TestBase.dut_phy_id_to_mdio_map = map(int, os.environ.get("DUT_PHY_ID_TO_MDIO_MAP", "0").split(","))
            TestBase.dut_phy_fw_version = os.environ.get("DUT_PHY_FW_VERSION", None)
            TestBase.dut_phy_fw_package = os.environ.get("DUT_PHY_FW_PACKAGE", None)
            TestBase.dut_phy_fw_part_number = os.environ.get("DUT_PHY_FW_PART_NUMBER", None)
            TestBase.dut_phy_fw_suffix = os.environ.get("DUT_PHY_FW_SUFFIX", None)

            TestBase.lkp_phy_board_name = os.environ.get("LKP_PHY_BOARD_NAME", None)
            TestBase.lkp_phy_type = os.environ.get("LKP_PHY_TYPE", None)
            TestBase.lkp_phy_ids = map(int, os.environ.get("LKP_PHY_IDS", "0").split(","))
            TestBase.lkp_phy_id_to_mdio_map = map(int, os.environ.get("LKP_PHY_ID_TO_MDIO_MAP", "0").split(","))
            TestBase.lkp_phy_fw_version = os.environ.get("LKP_PHY_FW_VERSION", None)
            TestBase.lkp_phy_fw_package = os.environ.get("LKP_PHY_FW_PACKAGE", None)
            TestBase.lkp_phy_fw_part_number = os.environ.get("LKP_PHY_FW_PART_NUMBER", None)
            TestBase.lkp_phy_fw_suffix = os.environ.get("LKP_PHY_FW_SUFFIX", None)
            TestBase.suspend_enabled = str_to_bool(os.environ.get("SUSPEND_ENABLED", "TRUE"))

            if TestBase.dut_phy_board_name is not None:
                if 'POD' in TestBase.dut_phy_board_name:
                    t6_drv = driver.Driver(port=None, drv_type=driver.DRV_TYPE_T6, version="latest")
                    t6_drv.install()

                TestBase.phy_validation_path = os.environ.get("PHY_VALIDATION_PATH", None)
                if TestBase.phy_validation_path is None:
                    url = "http://qa-nfs01/builds/tools/phy/common_rev1.0_Validation.zip"
                    content = get_url_response(url)
                    with zipfile.ZipFile(io.BytesIO(content)) as archive:
                        archive.extractall()
                    TestBase.phy_validation_path = os.path.abspath("common_rev1.0_Validation")

                common_dir = os.path.join(TestBase.phy_validation_path, "Validation/common")
                sys.path.append(common_dir)
                sys.path.append(os.path.join(common_dir, 'PlatformDrivers'))
                sys.path.append(os.path.join(common_dir, 'InstrumentDrivers'))

                if TestBase.dut_phy_type.lower() == PHY_EUROPA.lower():
                    from phycontroleur import PhyControlEur as PhyControlX
                elif TestBase.dut_phy_type.lower() == PHY_CALYPSO.lower():
                    from phycontrolcal import PhyControlCal as PhyControlX
                elif TestBase.dut_phy_type.lower() == PHY_RHEA.lower():
                    from phycontrolrhe import PhyControlRhe as PhyControlX
                elif TestBase.dut_phy_type.lower() == PHY_ANTIGUA.lower():
                    from phycontrolant import PhyControlAnt as PhyControlX
                else:
                    raise Exception("Unknown PHY type {}".format(TestBase.dut_phy_type))

                TestBase.phy_controls = {}
                for i, phy_id in enumerate(TestBase.dut_phy_ids):
                    if 'POD' in TestBase.dut_phy_board_name:
                        board_name = TestBase.dut_phy_board_name
                    else:
                        board_name = "{}:{}".format(TestBase.dut_phy_board_name, TestBase.dut_phy_id_to_mdio_map[i])
                    log.info("Creating PHY control using bard name {} and phy id {}".format(board_name, phy_id))
                    TestBase.phy_controls[phy_id] = PhyControlX(board_name, phy_id, trapDirectAccesses=False)
                TestBase.phy_control = TestBase.phy_controls[0]

            TestBase.atf_dut_target_os = os.environ.get("ATF_DUT_TARGET_OS", None)
            TestBase.atf_lkp_target_os = os.environ.get("ATF_LKP_TARGET_OS", None)
            TestBase.atf_os = os.environ.get("ATF_OS", None)
            TestBase.atf_home = os.environ.get("ATF_HOME", None)
            TestBase.sfp = os.environ.get("SFP", None)
            if TestBase.sfp is not None:
                assert TestBase.sfp.startswith("ETH") or TestBase.sfp.startswith("OPT") or \
                    TestBase.sfp.startswith("DAC")

            TestBase.log_local_dir = TestBase.working_dir

            if TestBase.dut_port:
                TestBase.DUT_IPV4_ADDR = TestBase.suggest_test_ip_address(TestBase.dut_port, TestBase.dut_hostname)
                TestBase.DUT_IPV6_ADDR = TestBase.suggest_test_ip_address(TestBase.dut_port, TestBase.dut_hostname,
                                                                          ipv6=True)
                TestBase.dut_ifconfig = ifconfig.Ifconfig(port=TestBase.dut_port, host=TestBase.dut_hostname)
                if TestBase.dut_phy_board_name is not None:  # Reinitialize Ifconfig instance if it's needed
                    TestBase.dut_ifconfig = ifconfig.Ifconfig(
                        port=TestBase.dut_port, host=TestBase.dut_hostname,
                        phy_control=TestBase.phy_control, mii=TestBase.dut_fw_mii)

                cls.dut_statistics = Statistics(port=TestBase.dut_port, host=TestBase.dut_hostname)

            if TestBase.lkp_port:
                TestBase.LKP_IPV4_ADDR = TestBase.suggest_test_ip_address(TestBase.lkp_port, TestBase.lkp_hostname)
                TestBase.LKP_IPV6_ADDR = TestBase.suggest_test_ip_address(TestBase.lkp_port, TestBase.lkp_hostname,
                                                                          ipv6=True)

                cls.lkp_ifconfig = ifconfig.Ifconfig(port=TestBase.lkp_port, host=TestBase.lkp_hostname)
                cls.lkp_statistics = Statistics(port=TestBase.lkp_port, host=TestBase.lkp_hostname)

            cls.iptables = IPTables(dut_hostname=TestBase.dut_hostname, lkp_hostname=TestBase.lkp_hostname)

            cls.ptp = PTP(dut_hostname=TestBase.dut_hostname, dut_port=TestBase.dut_port,
                          lkp_hostname=TestBase.lkp_hostname, lkp_port=TestBase.lkp_port)

            cls.dut_ops = OpSystem(host=TestBase.dut_hostname)
            cls.lkp_ops = OpSystem(host=TestBase.lkp_hostname)

            cls.cpu_monitor = CPUMonitor()

            # Sanity check that devices are not lost on PCI
            if cls.dut_port and cls.dut_hostname:
                if not cls.dut_ifconfig.is_device_present():
                    if TestBase.state.dut_dev_present_cold_restart:
                        raise Exception("Failed to resurect device {} on host {}".format(
                            cls.dut_port, cls.dut_hostname))
                    log.warning("Device {} is not present on host {}, cold restaring it".format(
                        cls.dut_port, cls.dut_hostname))
                    TestBase.state.dut_dev_present_cold_restart = True
                    TestBase.state.update()
                    TestBase.cold_restart(cls.dut_hostname)
                else:
                    TestBase.state.dut_dev_present_cold_restart = False
                    TestBase.state.update()

            if cls.lkp_port and cls.lkp_hostname:
                if not cls.lkp_ifconfig.is_device_present():
                    if TestBase.state.lkp_dev_present_cold_restart:
                        raise Exception("Failed to resurect device {} on host {}".format(
                            cls.lkp_port, cls.lkp_hostname))
                    log.warning("Device {} is not present on host {}, cold restaring it".format(
                        cls.lkp_port, cls.lkp_hostname))
                    TestBase.state.lkp_dev_present_cold_restart = True
                    TestBase.state.update()
                    TestBase.cold_restart(cls.lkp_hostname)
                else:
                    TestBase.state.lkp_dev_present_cold_restart = False
                    TestBase.state.update()

            TestBase.GIT_HASH_COMMIT_MY_BRANCH = Command(cmd='git rev-parse HEAD').run()['output']

            for k in sorted(TestBase.__dict__.keys()):
                val = str(TestBase.__dict__[k])
                exceptions = ['staticmethod', 'function', 'classmethod', 'property', 'attribute']
                if not any([name in val for name in exceptions]):
                    try:
                        msg = '{:>25s} -> {} [0x{:x}]'.format(k, val, int(val))
                    except Exception:
                        msg = '{:>25s} -> {}'.format(k, val)
                    log.info(msg)
            try:
                TestBase.send_info()
            except Exception as e:
                log.warning("Can't send version of tools")
                log.exception(e)

            if cls.dut_fw_card == constants.CARD_FIJI:
                cls.usb_2_0 = str_to_bool(os.environ.get("USB_2_0", "FALSE"))
                if cls.dut_usb_connect != constants.USB_CONNECT_DIRECT:
                    from tools.usb_control import USBControl
                    if cls.usb_2_0:
                        USBControl(host=cls.dut_hostname, device=cls.dut_usb_connect).enable_hispeed(0)
                    else:
                        USBControl(host=cls.dut_hostname, device=cls.dut_usb_connect).enable_superspeed(0)
                    time.sleep(2)

            if cls.dut_ops.is_linux():
                output = cls.get_dmesg_output(host=TestBase.dut_hostname, silent=False)
                # TODO: fix file already exists problem
                # cls.save_dmesg_output(output, "dmesg_output_setuptestbase_dut.txt", cls.log_local_dir)

            if cls.lkp_hostname is not None:
                if cls.lkp_ops.is_linux():
                    output = cls.get_dmesg_output(host=TestBase.lkp_hostname, silent=False)
                    # TODO: fix file already exists problem
                    # cls.save_dmesg_output(output, "dmesg_output_setuptestbase_lkp.txt", cls.log_local_dir)

            if cls.dut_fw_card == constants.CARD_FELICITY:
                # Not all Felicity Power Controls may have GPIO cable firmware
                pcontrol.PControl().gpio(cls.dut_hostname, pcontrol.PIN_GPIO, pcontrol.GPIO_ENABLE, False)
            if cls.dut_ops.is_freebsd():
                cls.dut_ifconfig.delete_vlan_ifaces()
            if cls.lkp_ops.is_freebsd():
                cls.lkp_ifconfig.delete_vlan_ifaces()
        except Exception as e:
            log.exception("Test set up error")
            raise e
        log.info('Test setup done. Starting test "{}"...'.format(cls.test))

    def run_iperf(cls, **kwargs):
        is_eee = kwargs.get('is_eee', False)
        is_stat = kwargs.get('is_stat', True)
        lkp_ip = kwargs.get("lkp4", None)
        duplex = kwargs.get('duplex', constants.DUPLEX_FULL)

        if cls.dut_fw_card == constants.CARD_FIJI:
            is_stat = False
        is_fc = kwargs.get('is_fc', True)
        criterion = kwargs.get('criterion', IperfResult.SANITY)

        ReceiveSegmentCoalescing(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname).enable()
        cls.iptables.clean()

        media_opts = [duplex]
        if is_eee:
            media_opts.append("energy-efficient-ethernet")
        if is_fc:
            media_opts.append("flow-control")

        cls.dut_ifconfig.set_media_options(media_opts)
        cls.lkp_ifconfig.set_media_options(media_opts)

        if is_eee:
            # Next link down/up operation is needed to avoid EEE autodisable
            cls.dut_ifconfig.set_link_state(LINK_STATE_DOWN)
            time.sleep(11)
            cls.dut_ifconfig.set_link_state(LINK_STATE_UP)

        current_link_speed = cls.dut_ifconfig.wait_link_up()
        # current_link_speed = cls.dut_ifconfig.get_link_speed()
        assert current_link_speed != LINK_SPEED_NO_LINK, '{} != {}'.format(current_link_speed, 'NO LINK')

        if cls.dut_fw_card == constants.CARD_FIJI and cls.dut_ops.is_linux:
            log.info("Skip for Fiji")
        else:
            cls.dut_ifconfig.check_media_options(media_opts)
            cls.lkp_ifconfig.check_media_options(media_opts)

        if is_eee and is_stat:
            log.info("Statistics counters before test:")
            dut_statistics_before = cls.dut_statistics.get_eee_statistics()

        results = None
        try:
            for i in range(3):
                log.info('iperf #{}'.format(i))

                Killer(host=cls.dut_hostname).kill("iperf3")
                Killer(host=cls.lkp_hostname).kill("iperf3")

                if is_stat:
                    if cls.dut_fw_card not in FELICITY_CARDS:
                        # Collect PHY statistics before test to clear them
                        dut_phy_statistics_before = cls.dut_statistics.get_phy_statistics()
                    if cls.lkp_fw_card not in FELICITY_CARDS:
                        lkp_phy_statistics_before = cls.lkp_statistics.get_phy_statistics()
                    dut_mac_statistics_before = cls.dut_statistics.get_mac_counters()
                    lkp_mac_statistics_before = cls.lkp_statistics.get_mac_counters()

                cls.cpu_monitor.run_async()

                iperf = Iperf(**kwargs)
                result = iperf.run()

                cls.cpu_monitor.join(timeout=1)

                if result != Iperf.IPERF_OK:
                    continue

                results = iperf.get_performance()

                # print statistics
                for res in results:
                    log.info(res)

                # check results
                for res in results:
                    res.check(criterion=criterion)

                cfg = iperf.get_config()

                # send cpu load
                desc, units, mi, ma, av, count = cls.cpu_monitor.get_metric()
                cls.send_metric(desc, units, mi, ma, av, count, "", json.dumps(cfg))

                # send perf metric
                for res in results:
                    cfg['machine'] = res.client
                    metrics = res.get_metrics()
                    for metric in metrics:
                        desc, units, mi, ma, av, count = metric
                        cls.send_metric(desc, units, mi, ma, av, count, "", json.dumps(cfg))

                break
            else:
                collect_counters()
                res = cls.ping(from_host="localhost", to_host=lkp_ip)
                log.info("PING - {}".format("SUCCESS" if res else "FAILED"))
                if not res:
                    collect_debug_info()
                raise Exception("Failed to run iperf 3 times")

            log.info(cls.cpu_monitor.report())
            return results

        finally:
            if is_stat:
                iperf_config = json.dumps(iperf.get_config())

                dut_mac_statistics_after = cls.dut_statistics.get_mac_counters()

                dut_mac_errored_stats = []
                for err_stat in cls.dut_statistics.MAC_ERROR_STATS:
                    err_stat_before = dut_mac_statistics_before[err_stat]
                    err_stat_after = dut_mac_statistics_after[err_stat]

                    if err_stat_before > err_stat_after:
                        if err_stat_after != 0:
                            dut_mac_errored_stats.append((err_stat, err_stat_after))
                    else:
                        if err_stat_after - err_stat_before > 0:
                            dut_mac_errored_stats.append((err_stat, err_stat_after - err_stat_before))

                for k, v in dut_mac_statistics_after.items():
                    if type(v) not in [float, int, long]:
                        # Skip string (and etc) characteristics
                        continue
                    cls.send_metric("iPerf info: " + k, "count", v, v, v, 1, "", iperf_config)
                # LKP MAC
                lkp_mac_statistics_after = cls.lkp_statistics.get_mac_counters()

                lkp_mac_errored_stats = []
                for err_stat in cls.lkp_statistics.MAC_ERROR_STATS:
                    err_stat_before = lkp_mac_statistics_before[err_stat]
                    err_stat_after = lkp_mac_statistics_after[err_stat]

                    if err_stat_before > err_stat_after:
                        if err_stat_after != 0:
                            lkp_mac_errored_stats.append((err_stat, err_stat_after))
                    else:
                        if err_stat_after - err_stat_before > 0:
                            lkp_mac_errored_stats.append((err_stat, err_stat_after - err_stat_before))

                if cls.dut_fw_card not in FELICITY_CARDS:
                    dut_phy_statistics_after = cls.dut_statistics.get_phy_statistics()

                    dut_phy_errored_stats = []
                    for err_stat in cls.dut_statistics.PHY_ERROR_STATS:
                        err_stat_before = dut_phy_statistics_before[err_stat]
                        err_stat_after = dut_phy_statistics_after[err_stat]

                        if err_stat_before > err_stat_after:
                            if err_stat_after != 0:
                                dut_phy_errored_stats.append((err_stat, err_stat_after))
                        else:
                            if err_stat_after - err_stat_before > 0:
                                dut_phy_errored_stats.append((err_stat, err_stat_after - err_stat_before))

                    for k, v in dut_phy_statistics_after.items():
                        if type(v) not in [float, int, long]:
                            # Skip string (and etc) characteristics
                            continue
                        cls.send_metric("iPerf info: " + k, "count", v, v, v, 1, "", iperf_config)
                # LKP PHY
                if cls.lkp_fw_card not in FELICITY_CARDS:
                    lkp_phy_statistics_after = cls.lkp_statistics.get_phy_statistics()

                    lkp_phy_errored_stats = []
                    for err_stat in cls.lkp_statistics.PHY_ERROR_STATS:
                        err_stat_before = lkp_phy_statistics_before[err_stat]
                        err_stat_after = lkp_phy_statistics_after[err_stat]

                        if err_stat_before > err_stat_after:
                            if err_stat_after != 0:
                                lkp_phy_errored_stats.append((err_stat, err_stat_after))
                        else:
                            if err_stat_after - err_stat_before > 0:
                                lkp_phy_errored_stats.append((err_stat, err_stat_after - err_stat_before))
            if is_eee and is_stat:
                log.info("Statistics counters after test:")
                statistics_after = cls.dut_statistics.get_eee_statistics()

                for k, v in statistics_after.items():
                    if statistics_after[k] > dut_statistics_before[k]:
                        log.warning("Counter {} is increased, before: {}, after: {}".format(
                            k, dut_statistics_before[k], statistics_after[k]))

            if is_stat:
                if len(dut_mac_errored_stats) > 0 or (
                        cls.dut_fw_card not in FELICITY_CARDS and len(dut_phy_errored_stats) > 0):
                    log.error("DUT Error couters are increased:\n")
                if len(dut_mac_errored_stats) > 0:
                    log.error("\n".join(["{} increased by {}".format(k, v) for k, v in dut_mac_errored_stats]))
                if cls.dut_fw_card not in FELICITY_CARDS and len(dut_phy_errored_stats) > 0:
                    log.error("\n".join(["{} increased by {}".format(k, v) for k, v in dut_phy_errored_stats]))

            if is_stat:
                if len(lkp_mac_errored_stats) > 0 or (
                        cls.lkp_fw_card not in FELICITY_CARDS and len(lkp_phy_errored_stats) > 0):
                    log.error("LKP Error couters are increased:\n")
                if len(lkp_mac_errored_stats) > 0:
                    log.error("\n".join(["{} increased by {}".format(k, v) for k, v in lkp_mac_errored_stats]))
                if cls.lkp_fw_card not in FELICITY_CARDS and len(lkp_phy_errored_stats) > 0:
                    log.error("\n".join(["{} increased by {}".format(k, v) for k, v in lkp_phy_errored_stats]))

            # The next code is commented because it will fail ALL iperf tests
            # if is_stat and (len(mac_errored_stats) > 0 or len(phy_errored_stats) > 0):
            #     raise Exception("Error counters are increased")

    @classmethod
    def teardown_class(cls):
        pass

    def setup_method(self, method):
        pass

    def teardown_method(self, method):
        try:
            if self.dut_ops.is_linux():
                output = self.get_dmesg_output(host=self.dut_hostname)
                TestBase.save_dmesg_output(output, "dmesg_output_dut.txt", self.test_log_dir)
        except Exception:
            log.warning("Failed to get dmesg for DUT")

        try:
            if self.lkp_hostname is not None:
                if self.lkp_ops.is_linux():
                    output = self.get_dmesg_output(host=self.lkp_hostname)
                    TestBase.save_dmesg_output(output, "dmesg_output_lkp.txt", self.test_log_dir)
        except Exception:
            log.warning("Failed to get dmesg for LKP")

    @classmethod
    def save_dmesg_output(cls, output, fname, fdir):
        if output is not None:
            with open(fname, 'w') as f:
                for line in output:
                    f.write("{}\n".format(line))
            move(fname, fdir)

    @classmethod
    def get_dmesg_output(cls, host=None, silent=True):
        if ops.OpSystem(host=host).is_linux():
            res = Command(cmd='sudo dmesg -c', host=host, silent=silent).run()
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                log.error("Failed dmesg")
                return None
            return res["output"]
        else:
            raise NotImplementedError()

    @classmethod
    def create_logs_dir_on_log_server(cls):
        """Creates a log directory on the log server

        :return: Full path to log directory
        """
        if not all([cls.log_path, cls.test, cls.platform, cls.job_id]):
            return None

        test_dir = os.path.normpath(os.path.join(cls.log_path, cls.test)).replace("\\", "/")
        res = Command(cmd='mkdir "{}"'.format(test_dir), host=cls.log_server, silent=True).run()
        if res["returncode"] != 0 and not any("File exists" in line for line in res["output"]):
            log.error("Failed to create directory {}".format(test_dir))
            log.error(res["output"])
            return None

        platform_dir = os.path.normpath(os.path.join(test_dir, cls.platform)).replace("\\", "/")
        res = Command(cmd='mkdir "{}"'.format(platform_dir), host=cls.log_server, silent=True).run()
        if res["returncode"] != 0 and not any("File exists" in line for line in res["output"]):
            log.error("Failed to create directory {}".format(platform_dir))
            log.error(res["output"])
            return None

        job_id_dir = os.path.normpath(os.path.join(platform_dir, cls.job_id)).replace("\\", "/")
        res = Command(cmd='mkdir "{}"'.format(job_id_dir), host=cls.log_server, silent=True).run()
        if res["returncode"] != 0 and not any("File exists" in line for line in res["output"]):
            log.error("Failed to create directory {}".format(job_id_dir))
            log.error(res["output"])
            return None

        return job_id_dir

    @staticmethod
    def is_host_powered_on(host):
        for i in range(10):
            led_status = pcontrol.PControl().status(host)[0]
            if not bool(led_status):
                return bool(led_status)
        return bool(led_status)

    @staticmethod
    def is_host_alive(host):
        try:
            res = Command(cmd="exit 77", host=host, ssh_connection_timeout=1).run()
            return res["returncode"] == 77
        except Exception:
            return False

    @staticmethod
    def poll_host_alive(host, timeout=60):
        log.info("Starting host polling")
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            if TestBase.is_host_alive(host):
                log.info("Host '{}' is alive".format(host))
                return True
            log.info("Sleeping 5 seconds")
            time.sleep(5)
        return False

    @staticmethod
    def poll_host_offline(host, timeout=60):
        log.info("Starting host polling")
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            if not TestBase.is_host_alive(host):
                log.info("Host {} is offline".format(host))
                return True
            log.info("Sleeping 5 seconds")
            time.sleep(5)
        return False

    @staticmethod
    def poll_host_powered_off(host, timeout=120, retry_interval=15):
        log.info("Starting host polling")
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            if not TestBase.is_host_powered_on(host):
                log.info("Host {} is powered off".format(host))
                return True
            log.info("Sleeping {} seconds".format(retry_interval))
            time.sleep(retry_interval)
        return False

    @staticmethod
    def poll_host_powered_on(host, timeout=120, retry_interval=15):
        log.info("Starting host polling")
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            if TestBase.is_host_powered_on(host):
                log.info("Host {} is powered on".format(host))
                return True
            log.info("Sleeping {} seconds".format(retry_interval))
            time.sleep(retry_interval)
        return False

    @staticmethod
    def is_host_alive_and_ready(host):
        if not TestBase.is_host_alive(host):
            return False
        log.info("Host '{}' is alive, checking agent status".format(host))
        url = "http://nn-ap01.rdc-lab.marvell.com/sched/node/status/{}".format(host)

        response = get_url_response(url)
        res = "TRUE" in response
        if res is False:
            log.debug("Response content: {}".format(response))
            log.info("Agent is not started on host '{}'".format(host))
        return res

    @staticmethod
    def poll_host_alive_and_ready(host, timeout=60):
        log.info("Starting host polling")
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            if TestBase.is_host_alive_and_ready(host):
                log.info("Host '{}' is ready".format(host))
                return True
            log.info("Sleeping 5 seconds")
            time.sleep(5)
        return False

    @staticmethod
    def poll_os_restoration(host, expected_os, test_tool, timeout=635):
        log.info("Starting host OS polling")
        start = timeit.default_timer()
        while timeit.default_timer() - start < timeout:
            if TestBase.is_host_alive_and_ready(host):
                git.clone(test_tool, host)
                current_os = OpSystem(host=host).get_name()
                if current_os == expected_os:
                    log.info("OS {} has been restored successfully on host {}".format(expected_os, host))
                    return True
                return False
            log.info("OS {} is still being restored on host {}".format(expected_os, host))
            log.info("Sleeping {} seconds".format(30))
            time.sleep(30)
        return False

    @staticmethod
    def restore_os(target_os, host):
        remote_ops = ops.OpSystem(host=host)
        if remote_ops.get_name() == target_os:
            log.info("Current and target OS are the same on host {}".format(host))
        else:
            log.info("Restoring OS {} on host {}".format(target_os, host))
            action = remote_ops.request_os_restoration(target_os)
            power.Power(host=host).reboot()
            TestBase.poll_host_offline(host)

            if action == "install":
                timeout = 3000
            else:
                timeout = 900

            test_tool = os.environ.get("TEST_TOOL_VERSION", "LATEST")
            if not TestBase.poll_os_restoration(host, target_os, test_tool, timeout):
                raise Exception("Couldn't restore OS {} on host {}".format(target_os, host))

    @staticmethod
    def cold_restart(host=None):
        """
        this method sent CMD_COLD command to pcontrol with negative delay
        then power off host via power
        then after power led is off for delay perform CMD_COLD command
        CMD_COLD = turn of AC power for 30 sec, then turn it back on
        and power on host by power button
        """
        if host is None or host == "localhost":
            hostname = socket.gethostname()
        else:
            hostname = host
        log.info("Requesting cold restart of host '{}' via power control".format(hostname))
        pcontrol.PControl().cold(hostname, 15000, -5)
        time.sleep(5)  # let agent to send stdout to ATF
        power.Power(host=host).shutdown()
        log.info("Sleeping {} seconds until system going to shut down".format(TestBase.POWER_DOWN_TIMEOUT))
        time.sleep(TestBase.POWER_DOWN_TIMEOUT)
        # By that time local host should already be offline
        if not (host is None or host == "localhost" or host == socket.gethostname()):
            if not TestBase.poll_host_alive(host, TestBase.POWER_UP_TIMEOUT):
                raise Exception("Cold restart of host {} is failed (host didn't turn on)".format(host))
            log.info("Host {} is alive, waiting for agent to start".format(host))
            if not TestBase.poll_host_alive_and_ready(host, TestBase.POWER_UP_TIMEOUT):
                raise Exception("Cold restart of host {} is failed (agent failed to start)".format(host))

    @staticmethod
    def power_off(host=None):
        """
        this method power off host wia power
        then turn AC power off and back on via power control
        """
        if host is None or host == "localhost":
            hostname = socket.gethostname()
        else:
            hostname = host
        pcontrol.PControl().off(hostname, 10000, -5)
        time.sleep(5)  # let agent to send stdout to ATF
        power.Power(host=hostname).shutdown()
        log.info("Sleeping {} seconds until system going to shut down".format(TestBase.POWER_DOWN_TIMEOUT))
        time.sleep(TestBase.POWER_DOWN_TIMEOUT)
        if TestBase.poll_host_powered_off(hostname):
            log.info("Host {} cold off complete".format(hostname))
        else:
            raise Exception('Host {} does not powered off'.format(hostname))

    @staticmethod
    def restart(host=None):
        power.Power(host=host).reboot()
        log.info("Sleeping {} seconds until system going to shut down".format(TestBase.POWER_DOWN_TIMEOUT))
        time.sleep(TestBase.POWER_DOWN_TIMEOUT)
        # By that time local host should already be offline
        if not (host is None or host == "localhost" or host == socket.gethostname()):
            if not TestBase.poll_host_alive_and_ready(host, TestBase.POWER_UP_TIMEOUT):
                raise Exception("Cold restart of host {} is failed".format(host))

    @classmethod
    def get_flash_override(cls):
        dut_flash_override = {}
        lkp_flash_override = {}

        if cls.dut_dev_id is not None:
            dut_flash_override["dev_id"] = cls.dut_dev_id
        if cls.dut_subsys_id is not None:
            dut_flash_override["subsys_id"] = cls.dut_subsys_id
        if cls.dut_subven_id is not None:
            dut_flash_override["subven_id"] = cls.dut_subven_id
        if cls.dut_port is not None:
            dut_flash_override["mac"] = cls.suggest_test_mac_address(cls.dut_port, cls.dut_hostname)

        if cls.lkp_dev_id is not None:
            lkp_flash_override["dev_id"] = cls.lkp_dev_id
        if cls.lkp_subsys_id is not None:
            lkp_flash_override["subsys_id"] = cls.lkp_subsys_id
        if cls.lkp_subven_id is not None:
            lkp_flash_override["subven_id"] = cls.lkp_subven_id
        if cls.lkp_port is not None:
            lkp_flash_override["mac"] = cls.suggest_test_mac_address(cls.lkp_port, cls.lkp_hostname)

        log.info("Flash override data for DUT {}".format(dut_flash_override))
        log.info("Flash override data for LKP {}".format(lkp_flash_override))
        return dut_flash_override, lkp_flash_override

    @classmethod
    def install_firmware(cls, port, card, speed, version, mdi,
                         mii, pause, pcirom, dirtywake, host=None, flash_override={}):
        log.warning("This method is deprecated, please use install_firmwares function")
        fw = firmware.Firmware(port=port, host=host, card=card, speed=speed, version=version, mdi=mdi, mii=mii,
                               pause=pause, pcirom=pcirom, dirtywake=dirtywake)
        log.info("Installing firmware {}".format(version))
        is_cold_restart_needed = fw.install(overrides=flash_override)

        if is_cold_restart_needed:
            cls.cold_restart()

    @classmethod
    def install_firmwares(cls):
        cls.dut_flash_override, cls.lkp_flash_override = cls.get_flash_override()
        if all([cls.dut_fw_version, cls.dut_fw_card]):
            cls.dut_firmware = firmware.Firmware(port=cls.dut_port, card=cls.dut_fw_card, speed=cls.dut_fw_speed,
                                                 version=cls.dut_fw_version, mdi=cls.dut_fw_mdi, mii=cls.dut_fw_mii,
                                                 pause=cls.dut_fw_pause, pcirom=cls.dut_fw_pcirom,
                                                 dirtywake=cls.dut_fw_dirtywake, host=cls.dut_hostname, bdp=cls.dut_bdp,
                                                 sign=cls.dut_sign,
                                                 se_enable=cls.dut_se, hsd=cls.dut_hsd)
            if not (cls.skip_fw_install or cls.skip_dut_fw_install):
                if cls.state.fw_install_cold_restart is True and cls.is_local_host(cls.dut_hostname):
                    log.info("FW installation has been done before reboot")
                    cls.state.fw_install_cold_restart = False
                    cls.state.update()
                else:
                    postinstall_action = cls.dut_firmware.install(
                        overrides=cls.dut_flash_override, flashless=cls.dut_flashless)
                    if postinstall_action == firmware.Firmware.POSTINSTALL_RESTART:
                        cls.restart(cls.dut_hostname)
                    if postinstall_action == firmware.Firmware.POSTINSTALL_COLD_RESTART:
                        if cls.dut_fw_card == constants.CARD_FIJI and \
                                cls.dut_usb_connect in [constants.USB_CONNECT_HUB3P, constants.USB_CONNECT_CSWITCH]:
                            log.info("Cold restarting dongle by disabling USB port")
                            from tools.usb_control import USBControl
                            dut_usb_control = USBControl(host=cls.dut_hostname, device=cls.dut_usb_connect)
                            dut_usb_control.disable(0)
                            time.sleep(20)
                            dut_usb_control.enable(0)
                            if cls.dut_usb_connect != constants.USB_CONNECT_DIRECT:
                                cls.usb_2_0 = str_to_bool(os.environ.get("USB_2_0", "FALSE"))
                                if cls.usb_2_0:
                                    USBControl(host=cls.dut_hostname, device=cls.dut_usb_connect).enable_hispeed(0)
                                else:
                                    USBControl(host=cls.dut_hostname, device=cls.dut_usb_connect).enable_superspeed(0)
                                time.sleep(2)
                        else:
                            if cls.is_local_host(cls.dut_hostname):
                                cls.state.fw_install_cold_restart = True
                                cls.state.update()
                            cls.cold_restart(cls.dut_hostname)

        if all([cls.lkp_fw_version, cls.lkp_fw_card]):
            cls.lkp_firmware = firmware.Firmware(port=cls.lkp_port, card=cls.lkp_fw_card, speed=cls.lkp_fw_speed,
                                                 version=cls.lkp_fw_version, mdi=cls.lkp_fw_mdi, mii=cls.lkp_fw_mii,
                                                 pause=cls.lkp_fw_pause, pcirom=cls.lkp_fw_pcirom,
                                                 dirtywake=cls.lkp_fw_dirtywake, host=cls.lkp_hostname, bdp=cls.lkp_bdp,
                                                 sign=cls.lkp_sign,
                                                 se_enable=cls.lkp_se, hsd=cls.lkp_hsd)
            if not (cls.skip_fw_install or cls.skip_lkp_fw_install):
                if cls.state.fw_install_cold_restart is True and cls.is_local_host(cls.lkp_hostname):
                    log.info("FW installation has been done before reboot")
                    cls.state.fw_install_cold_restart = False
                    cls.state.update()
                else:
                    postinstall_action = cls.lkp_firmware.install(overrides=cls.lkp_flash_override)
                    if postinstall_action == firmware.Firmware.POSTINSTALL_RESTART:
                        cls.restart(cls.lkp_hostname)
                    if postinstall_action == firmware.Firmware.POSTINSTALL_COLD_RESTART:
                        if cls.lkp_fw_card == constants.CARD_FIJI and \
                                cls.lkp_usb_connect in [constants.USB_CONNECT_HUB3P, constants.USB_CONNECT_CSWITCH]:
                            log.info("Cold restarting dongle by disabling USB port")
                            from tools.usb_control import USBControl
                            lkp_usb_control = USBControl(host=cls.lkp_hostname, device=cls.lkp_usb_connect)
                            lkp_usb_control.disable(0)
                            time.sleep(20)
                            lkp_usb_control.enable(0)
                        else:
                            if cls.is_local_host(cls.lkp_hostname):
                                cls.state.fw_install_cold_restart = True
                                cls.state.update()
                            cls.cold_restart(cls.lkp_hostname)

        if hasattr(cls, "dut_phy_board_name") and hasattr(cls, "dut_phy_fw_version") and \
                all([cls.dut_phy_board_name, cls.dut_phy_fw_version]):
            for phy_id in TestBase.dut_phy_ids:
                log.info("Installing PHY firmware on PHY_ID {}".format(phy_id))
                cls.phy_firmware = firmware.PhyFirmware(phy_control=cls.phy_controls[phy_id],
                                                        version=cls.dut_phy_fw_version,
                                                        suffix=cls.dut_phy_fw_suffix)
                if not cls.skip_fw_install:
                    cls.phy_firmware.install()

        if hasattr(cls, "lkp_phy_board_name") and hasattr(cls, "lkp_phy_fw_version") and \
                all([cls.lkp_phy_board_name, cls.lkp_phy_fw_version]):
                log.info("Installing remote PHY firmware on PHY_ID {}".format('0'))
                cls.lkp_phy_firmware = firmware.PhyFirmware(host=cls.lkp_hostname,
                                                            version=cls.lkp_phy_fw_version,
                                                            suffix=cls.dut_phy_fw_suffix,
                                                            board_name=cls.lkp_phy_board_name)
                if not cls.skip_fw_install:
                    cls.lkp_phy_firmware.install()

        # TODO: run readstat for each device
        if cls.dut_fw_card != constants.CARD_FIJI:
            Command(cmd='listDevices', host=cls.dut_hostname).wait(30)
            readstat_cmd = "sudo readstat{}".format("2" if cls.dut_fw_card == CARD_ANTIGUA else "")
            Command(cmd=readstat_cmd, host=cls.dut_hostname).wait(30)

        if cls.lkp_fw_card != constants.CARD_FIJI:
            Command(cmd='listDevices', host=cls.lkp_hostname).wait(30)
            readstat_cmd = "sudo readstat{}".format("2" if cls.lkp_fw_card == CARD_ANTIGUA else "")
            Command(cmd=readstat_cmd, host=cls.lkp_hostname).wait(30)

    @staticmethod
    def is_local_host(host):
        return host is None or host == "localhost" or host == socket.gethostname()

    @staticmethod
    def get_actual_firmware_version(version):
        try:
            suburl = "firmware/{}/version.txt".format(version)
            url = urlparse.urljoin(BUILDS_SERVER, suburl)
            response = get_url_response(url)
            return response.rstrip("\r\n")
        except Exception:
            return version

    @staticmethod
    def get_current_version_efi(version):
        suburl = "tools/efi/{}/version.txt".format(version)
        url = urlparse.urljoin(BUILDS_SERVER, suburl)
        response = get_url_response(url)
        return response.rstrip("\r\n")

    @staticmethod
    def send_info():
        url = os.environ.get("UPDATE_TEST_VERSION_INFO_URL", None)
        if not url:
            return

        data = {}
        if TestBase.dut_fw_version:
            fw = TestBase.get_actual_firmware_version(TestBase.dut_fw_version)
            data["firmware"] = fw
        if TestBase.dut_drv_version:
            if TestBase.dut_hostname:
                drv = driver.Driver(port=TestBase.dut_port,
                                    version=TestBase.dut_drv_version,
                                    host=TestBase.dut_hostname)
            else:
                drv = driver.Driver(port=TestBase.dut_port,
                                    version=TestBase.dut_drv_version)
            data["driver"] = drv.release_version
        if TestBase.lkp_fw_version:
            fw = TestBase.get_actual_firmware_version(TestBase.lkp_fw_version)
            data["firmware_lkp"] = fw
        if TestBase.lkp_drv_version and TestBase.lkp_port:
            if TestBase.lkp_hostname:
                drv = driver.Driver(port=TestBase.lkp_port,
                                    version=TestBase.lkp_drv_version,
                                    host=TestBase.lkp_hostname)
            else:
                drv = driver.Driver(port=TestBase.lkp_port,
                                    version=TestBase.lkp_drv_version)
            data["driver_lkp"] = drv.release_version
        if TestBase.diag_version:
            diag_version = get_actual_diag_version(TestBase.diag_version)
            data["driver"] = "DIAG_{}".format(diag_version)

        data["id"] = TestBase.job_id

        log.info("Sending '{}' to url '{}'".format(str(data), url))
        response = requests.post(url, data=json.dumps(data))

    @staticmethod
    def ping(from_host, to_host, number=1, ipv6=False, src_addr=None, payload_size=0, timeout=None, interval=None,
             margin=0):
        if from_host in [None, "localhost", socket.gethostname()]:
            log.info("Pinging {} from localhost".format(to_host))
            return ping.ping(number, to_host, ipv6, src_addr, payload_size, timeout, interval, margin)
        else:
            log.info("Pinging {} from {}".format(to_host, from_host))
            ip_version = ' --ipv6' if ipv6 else ''
            src_addr_param = '' if src_addr is None else ' --src {}'.format(src_addr)

            if timeout is not None:
                timeout_param = ' -t {}'.format(timeout)
            else:
                timeout_param = ''
            if interval is not None:
                interval_param = ' -i {}'.format(interval)
            else:
                interval_param = ''
            if margin != 0:
                margin_param = ' -m {}'.format(margin)
            else:
                margin_param = ''
            cmd = "cd {} && python ping.py{}{} -n {} {} -l {}{}{}{}".format(
                ATF_TOOLS_DIR, ip_version, src_addr_param, number, to_host, payload_size,
                timeout_param, interval_param, margin_param)

            res = Command(cmd=cmd, host=from_host).run()
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK or \
                    not any(ping.SCRIPT_STATUS_SUCCESS in line for line in res["output"]):
                log.error("Failed to ping host {}".format(to_host))
                return False
            return True

    @staticmethod
    def get_chip_revision(port):
        from tools import atltoolper
        try:
            diag_drv = driver.Driver(port=port, drv_type=driver.DRV_TYPE_DIAG, version="latest")

            if ops.OpSystem().is_windows():
                diag_drv.remove_all_hidden_devices()
                diag_drv.install()

            atltool = atltoolper.AtlToolLocal(port=port)
            chip_rev = atltool.readreg(0x1c)
            time.sleep(5)

            if chip_rev == 0x102:
                return CHIP_REV_B0
            elif chip_rev == 0x10a:
                return CHIP_REV_B1

            raise Exception("Cannot obtain chip revision")
        except Exception as e:
            log.exception(e)
        finally:
            if ops.OpSystem().is_windows():
                diag_drv.uninstall(ignore_remove_errors=True)

    @staticmethod
    def suggest_test_ip_address(port, host=None, ipv6=False):
        if host is None:
            host = socket.gethostname()

        hash_host = hashlib.sha256(host + port)
        hex_host = hash_host.hexdigest()

        if ipv6 is False:
            return "192.168.{}.{}".format(int(hex_host[:2], 16), int(hex_host[2:4], 16))
        else:
            return "4000:0000:0000:0000:1601:bd17:{}:{}".format(hex_host[:4], hex_host[4:8])

    @staticmethod
    def suggest_test_mac_address(port, host=None):
        if host is None:
            host = socket.gethostname()

        hash_host = hashlib.sha256(host + port)
        hex_host = hash_host.hexdigest()
        return "00:17:b6:{}:{}:{}".format(hex_host[:2], hex_host[2:4], hex_host[4:6])

    def bring_host_online(self, host):
        """Make sure host is online (using PControl)"""
        if self.is_host_alive_and_ready(host):
            log.info("Host {} is online".format(host))
        else:
            log.warning("Host {} is not online".format(host))
            # First, make sure host is powered on
            log.info("Checking power status")
            try:
                is_powered = self.is_host_powered_on(host)
            except Exception as exc:
                # Assume that host is powered off (method bring_host_online must be fully executed)
                is_powered = False
            if is_powered:
                log.info("Host {} is powered on".format(host))
            else:
                log.info("Host {} is not powered on".format(host))
                log.info("Sending POWER command")
                pcontrol.PControl().power(host, 500, 0)

                # Check PControl's PWR cmd worked, sometimes it doesn't (PControl's defect?)
                time.sleep(self.LED_TIMEOUT)
                try:
                    is_powered = self.is_host_powered_on(host)
                except Exception as exc:
                    # Assume that host is powered off (method bring_host_online must be fully executed)
                    is_powered = False
                if not is_powered:
                    log.error("POWER CMD didn't work")
                    log.error("Host {} is still not powered on. Manual investigation is needed".format(host))

            # Second, poll host online, after that try cold reboot
            if self.poll_host_alive_and_ready(host, self.POWER_UP_TIMEOUT):
                log.info("Host {} came online".format(host))
            else:
                log.info("Host {} is still offline. Trying to do hard cold reboot".format(host))
                pcontrol.PControl().cold(host, 30000, 0)
                if self.poll_host_alive_and_ready(host, self.POWER_UP_TIMEOUT):
                    log.info("Host {} came online only after hard cold reboot".format(host))
                else:
                    raise Exception("Failed to bring host {} online".format(host))

    @property
    def test_log_dir(self):
        return os.path.join(self.log_local_dir, self.state.current_test_norm)

    @staticmethod
    def enable_dbg_buffer(mbu_wrapper):
        log.info("Enabling FW debug buffer...")
        mbu_wrapper.debug_buffer_enable(True)
        time.sleep(5)
        mbu_wrapper.debug_buffer_reset()
        time.sleep(5)
        log.info("FW debug buffer enabled")

    @staticmethod
    def disable_dbg_buffer(mbu_wrapper):
        log.info("Disabling FW debug buffer...")
        mbu_wrapper.debug_buffer_enable(False)
        time.sleep(5)
        log.info("FW debug buffer disabled")

    @staticmethod
    def cleanup_mbu_wrapper(mbu_wrapper):
        log.info("Destroying MBU wrapper...")
        # self.mbu_wrapper.exit()
        # time.sleep(5)
        # self.mbu_wrapper.cli.destroy()
        # time.sleep(5)
        mbu_wrapper.destroy()
        time.sleep(5)
        log.info("Cleaning up MBU logs...")
        mbu_wrapper.cleanup_logs()
        log.info("MBU wrapper destroyed")

    def copy_mcp_log_to_test_dir(self, mbu_wrapper):
        log.info("Copying MCP log to test directory...")
        mbu_log_dir = os.path.join(mbu_wrapper.mbu_dir, "Logs")
        mcp_log = os.path.join(mbu_log_dir, next(obj for obj in os.listdir(mbu_log_dir) if "mcp" in obj))
        copyfile(mcp_log, os.path.join(self.test_log_dir, "mcp_log.txt"))
        log.info("MCP log {} copied to {}".format(mcp_log, self.test_log_dir))

    def send_metric(self, description, units, _min, _max, avg, count, data, params):
        subtest_name = self.state.current_test
        firmware = self.dut_fw_version
        driver = self.dut_drv_version
        try:
            if hasattr(self, 'dut_driver'):
                driver = self.dut_driver.version
        except Exception as e:
            driver = self.dut_drv_version
            log.exception(e)

        data = {"name": subtest_name, "os": self.dut_ops.get_name(), "units": units, "min": _min, "max": _max,
                "avg": avg, "count": count, "description": description, "data": data, "params": params,
                "firmware": firmware, "driver": driver}
        url = METRIC_SERVER + '{}'.format(self.job_id)
        # log.info("Sending '{}' to url '{}'".format(str(data), url))
        for i in range(HTTP_RETRY_COUNT):
            try:
                response = requests.post(url, data=json.dumps(data))
                if response.status_code != 200:
                    log.warning("Failed to send subtest result message")
                    log.warning("Response content:\n{}".format(response.content))
                    raise RuntimeError("Failed to report subtest result")
                break
            except Exception as exc:
                if i < HTTP_RETRY_COUNT - 1:
                    log.exception("Attempt {} failed. Will retry after {} seconds.".format(i + 1, HTTP_RETRY_INTERVAL))
                    time.sleep(HTTP_RETRY_INTERVAL)
                    log.info('Retrying...')
                    continue
                log.exception(exc)
                return

    def send_metrics(self, metrics):
        for m in metrics:
            self.send_metric(*m)
