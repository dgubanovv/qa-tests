import ctypes
import decimal
import math
import ntpath
import os
import urlparse
import re
import sys
import timeit

import collections
import pytest

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

from tools.mbuper import download_mbu, MbuWrapper, LINK_STATE_UP, LINK_STATE_DOWN
from infra.test_base import TestBase, idparametrize
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, \
    LINK_SPEED_AUTO, LINK_SPEED_NO_LINK

from tools.driver import Driver, DRV_TYPE_DIAG
from tools.utils import get_atf_logger
from tools.drv_iface_cfg import DrvFreqAgjustment
from tools.command import Command
from tools.firmware import NFS_SERVER, BUILDS_SERVER
from tools.utils import get_url_response

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "ptp_counter_sync"
    os.environ["MBU_VERSION"] = "2.10.0.561-master-2.x-ptp_counter_sync_fw-2.x-fix-hal2-path"
    os.environ["DUT_BDP"] = "AQC107-PTPGPIO0"


class ResultItem(
    collections.namedtuple(
        "ResultItem", (
            "mac_sys",
            "mac_counter",
            "phy_sys",
            "phy_counter",
            "sys_diff",
            "total_diff",
        )
    )
):
    __slots__ = ()


class FreqAdjustmentParams(
    collections.namedtuple(
        "FreqAdjustmentParams", (
            "ns_mac",
            "fns_mac",
            "ns_phy",
            "fns_phy",
            "ns_mac_adj",
            "fns_mac_adj",
            "total_ns_mac_adj",
            "total_fns_mac_adj",
        )
    )
):
    __slots__ = ()


class TestPtpCounterSync(TestBase):
    READ_COUNT = 30000
    MAC_REG = re.compile("^1, (\d+), (\d+)$")
    PHY_REG = re.compile("^2, (\d+), (\d+)$")
    GPIO_REG = re.compile("^3, (\d+), (\d+)$")
    CAPS_HI_PTP_AVB_EN = 0x100000
    CHECK_COUNT = 5
    DURATION = int(os.environ.get("DURATION", 600))
    AQ_HW_MAC_COUNTER_HZ = 312500000
    AQ_HW_PHY_COUNTER_HZ = 160000000
    NS_IN_SEC = 1000000000
    FRAC_NS_IN_NS = 0x100000000
    MCP_COUNTER_OVERFLOW_TIME = 51
    MCP_MAP_PATH = "input/rombin"

    @classmethod
    def setup_class(cls):
        super(TestPtpCounterSync, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.dut_driver.install()

            mbu_dir = download_mbu(cls.mbu_version, cls.working_dir)
            cls.mbu_dir = mbu_dir
            cls.dut_mbu = MbuWrapper(mbu_dir=cls.mbu_dir, port=cls.dut_port, version=cls.mbu_version)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def teardown_method(self, method):
        super(TestPtpCounterSync, self).teardown_method(method)
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_mbu.set_link_params_2x(LINK_SPEED_NO_LINK)

    def setup_method(self, method):
        super(TestPtpCounterSync, self).setup_method(method)
        self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)
        self.dut_mbu.set_link_params_2x(LINK_SPEED_NO_LINK)

    def get_adj_params(self, freq, ppb):
        base_ns = ((ppb + self.NS_IN_SEC) * self.NS_IN_SEC) / freq
        nsi = base_ns / self.NS_IN_SEC
        divisor = self.NS_IN_SEC * self.NS_IN_SEC / (base_ns - nsi * self.NS_IN_SEC)
        nsi_frac = self.FRAC_NS_IN_NS * self.NS_IN_SEC / divisor
        return nsi, nsi_frac

    def mac_adj_param_calc(self, ppb):
        ns_phy, fns_phy = self.get_adj_params(self.AQ_HW_PHY_COUNTER_HZ, ppb)
        ns_mac, fns_mac = self.get_adj_params(self.AQ_HW_MAC_COUNTER_HZ, ppb)

        fns_in_sec_phy = self.AQ_HW_PHY_COUNTER_HZ * (fns_phy + self.FRAC_NS_IN_NS * ns_phy)
        log.info("fns_in_sec_phy = {}".format(fns_in_sec_phy))
        fns_in_sec_mac = self.AQ_HW_MAC_COUNTER_HZ * (fns_mac + self.FRAC_NS_IN_NS * ns_mac)
        log.info("fns_in_sec_mac = {}".format(fns_in_sec_mac))

        fault_in_sec_phy = self.FRAC_NS_IN_NS * self.NS_IN_SEC - fns_in_sec_phy
        log.info("fault_in_sec_phy = {}".format(fault_in_sec_phy))
        fault_in_sec_mac = self.FRAC_NS_IN_NS * self.NS_IN_SEC - fns_in_sec_mac
        log.info("fault_in_sec_mac = {}".format(fault_in_sec_mac))
        diff_in_mcp_overflow = (
            fault_in_sec_mac - fault_in_sec_phy
        ) * 4 * self.FRAC_NS_IN_NS / self.AQ_HW_MAC_COUNTER_HZ
        log.info("diff_in_mcp_overflow = {}".format(diff_in_mcp_overflow))
        ns_mac_adj = diff_in_mcp_overflow / self.FRAC_NS_IN_NS
        fns_mac_adj = diff_in_mcp_overflow - ns_mac_adj * self.FRAC_NS_IN_NS
        # Plus one mac counter tick according to FW documentstaion
        total_correction = diff_in_mcp_overflow + ns_mac * self.FRAC_NS_IN_NS + fns_mac
        total_ns_mac_adj = total_correction / self.FRAC_NS_IN_NS
        total_fns_mac_adj = total_correction - total_ns_mac_adj * self.FRAC_NS_IN_NS

        result = FreqAdjustmentParams(
            ns_mac=ns_mac,
            fns_mac=fns_mac,
            ns_phy=ns_phy,
            fns_phy=fns_phy,
            ns_mac_adj=ns_mac_adj,
            fns_mac_adj=fns_mac_adj,
            total_ns_mac_adj=total_ns_mac_adj,
            total_fns_mac_adj=total_fns_mac_adj
        )
        return result

    def apply_freq_adjustment(self, ppb):
        adjustment_params = self.mac_adj_param_calc(ppb)
        log.info("Frequency adjustment with the following parameters: PPB = {}; Calculated: {}".format(
            ppb, adjustment_params
        ))
        freq_adjuster = DrvFreqAgjustment()
        freq_adjuster.caps = self.dut_mbu.readreg(0x36c) | freq_adjuster.caps
        freq_adjuster.ns_mac = ctypes.c_ulong(adjustment_params.ns_mac).value
        freq_adjuster.fns_mac = ctypes.c_ulong(adjustment_params.fns_mac).value
        freq_adjuster.ns_phy = ctypes.c_ulong(adjustment_params.ns_phy).value
        freq_adjuster.fns_phy = ctypes.c_ulong(adjustment_params.fns_phy).value
        freq_adjuster.ns_mac_adj = ctypes.c_ulong(adjustment_params.total_ns_mac_adj).value
        freq_adjuster.fns_mac_adj = ctypes.c_ulong(adjustment_params.total_fns_mac_adj).value
        freq_adjuster.apply(self.dut_mbu, cleanup_fw=False)
        return adjustment_params

    def make_plot(self, diff_ts, avg_diffs, link_speed, ppb, adj_params):
        output_file = os.path.join(self.test_log_dir, "drift_plot.png")
        fig, ax = plt.subplots(nrows=1, ncols=1)
        ax.tick_params(labelsize=8)
        ax.grid(True)
        x_results = [float(item) for item in diff_ts]
        y_results = [float(item) for item in avg_diffs]
        ax.plot(x_results, y_results)
        max_x = max(x_results)
        min_x = min(x_results)
        max_y = max(y_results)
        min_y = min(y_results)

        ax.axhline(y=max(y_results), color='r', linestyle='-')
        ax.axhline(y=min(y_results), color='g', linestyle='-')

        xstep = int(max_x - min_x) / 40
        xstep = 1 if xstep == 0 else xstep
        ystep = (max_y - min_y) / 50
        ystep = 1 if ystep == 0 else ystep

        xx = np.arange(0, math.ceil(x_results[-1]) + xstep, xstep)
        yy = np.arange(min_y - ystep, max_y + ystep, ystep)
        ax.yaxis.label.set_size(40)
        ax.set_xticks(xx)
        ax.set_yticks(yy)
        ax.set_title("Speed:{} PPB:{} mac_ns:{} mac_fns:{} phy_ns:{} phy_fns:{} mac_adj_ns:{} mac_adj_fns:{}".format(
            link_speed, ppb, hex(adj_params.ns_mac), hex(adj_params.fns_mac), hex(adj_params.ns_phy),
            hex(adj_params.fns_phy), hex(adj_params.total_ns_mac_adj), hex(adj_params.total_fns_mac_adj)
        ))
        ax.set_xlabel("Seconds")
        ax.set_ylabel("Phy - Mac counter diff, ns")

        fig.set_size_inches(40, 8)
        fig.savefig(output_file, dpi=300)
        plt.close(fig)

    def mac_phy_sync(self, speed, second_counter, ppb=0):
        drift_tolerance = 8
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        counter_file = os.path.join(self.test_log_dir, "counters.csv")
        self.dut_mbu.writereg(0x36C, self.CAPS_HI_PTP_AVB_EN)
        self.dut_mbu.writereg(0x378, 0x15)
        self.dut_mbu.set_link_params_2x(speed)
        adjustment_params = self.apply_freq_adjustment(ppb)

        if second_counter == "phy":
            second_counter_str = "-p"
            second_reg = self.PHY_REG
        elif second_counter == "gpio":
            second_counter_str = "-g"
            second_reg = self.GPIO_REG
        else:
            raise Exception("Unknown counter type")
        regs = [self.MAC_REG, second_reg]

        avg_diffs = []
        diff_ts = []
        start = timeit.default_timer()
        while (timeit.default_timer() - start) < self.DURATION:
            self.dut_mbu.exec_beton(
                [
                    "tests.testPtpClock -m {} -r {} -c 1 -o {} -l nul".format(
                        second_counter_str, self.READ_COUNT, counter_file
                    )
                ]
            )
            diff_ts.append(timeit.default_timer() - start)
            mac_counter_values = []
            second_counter_values = []
            with open(counter_file, "r") as fileo:
                for line in fileo:
                    for reg in regs:
                        match = reg.match(line)
                        if match:
                            if reg == self.MAC_REG:
                                mac_counter_values.append((int(match.group(1)), int(match.group(2))))
                            else:
                                second_counter_values.append((int(match.group(1)), int(match.group(2))))

            results = []
            os.remove(counter_file)

            for (mac_sys, mac_value), (phy_sys, phy_value) in zip(mac_counter_values, second_counter_values):
                diff = phy_value - mac_value
                corrected_diff = diff - phy_sys + mac_sys
                results.append(
                    ResultItem(
                        mac_sys=mac_sys,
                        mac_counter=mac_value,
                        phy_sys=phy_sys,
                        phy_counter=phy_value,
                        sys_diff=phy_sys - mac_sys,
                        total_diff=corrected_diff,
                    )
                )

            tolerance_ns = 150
            sys_diffs = [item.sys_diff for item in results]
            most_often_sys_diff = max(set(sys_diffs), key=sys_diffs.count)
            log.info("Most often system diff: {}".format(most_often_sys_diff))
            log.info("Results number before filtering: {}".format(len(results)))
            results = [
                # It's needed through out several values from the beginning due to they are affetcted by additional
                # timings. Value found experimetally
                item for item in results[100:]
                if most_often_sys_diff - tolerance_ns < item.sys_diff < most_often_sys_diff + tolerance_ns
            ]
            log.info("Results number after filtering: {}".format(len(results)))
            total_diffs = [item.total_diff for item in results]
            avg_diff = decimal.Decimal(sum(total_diffs))/len(total_diffs)
            avg_diffs.append(avg_diff)

        self.make_plot(diff_ts, avg_diffs, speed, ppb, adjustment_params)

        log.info("Average counter diffs: {}".format([str(item) for item in avg_diffs]))
        expected_drift = decimal.Decimal(
            adjustment_params.ns_mac_adj * self.FRAC_NS_IN_NS + adjustment_params.fns_mac_adj
        ) / self.FRAC_NS_IN_NS
        expected_diff = 2 * drift_tolerance + expected_drift
        diff = max(avg_diffs) - min(avg_diffs)
        log.info("Diff: {}; Expected diff less than {}".format(diff, expected_diff))
        assert diff < expected_diff, "Drift is more than expected. Check plot."
        for num, item in enumerate(avg_diffs[1:], start=1):
            grow = item - avg_diffs[num - 1]
            assert abs(grow) < 2 * drift_tolerance + diff / (len(avg_diffs) - 1), \
                "Measurement error is too high"

    # Weekly
    @idparametrize("ppb", range(-5000, 5100, 200) + [1])
    def test_mac_gpio_sync_weekly_100M(self, ppb):
        self.mac_phy_sync(LINK_SPEED_100M, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 200) + [1])
    def test_mac_gpio_sync_weekly_1G(self, ppb):
        self.mac_phy_sync(LINK_SPEED_1G, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 200) + [1])
    def test_mac_gpio_sync_weekly_2_5G(self, ppb):
        self.mac_phy_sync(LINK_SPEED_2_5G, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 200) + [1])
    def test_mac_gpio_sync_weekly_5G(self, ppb):
        self.mac_phy_sync(LINK_SPEED_5G, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 200) + [1])
    def test_mac_gpio_sync_weekly_10G(self, ppb):
        self.mac_phy_sync(LINK_SPEED_10G, "gpio", ppb=ppb)

    # Nightly
    @idparametrize("ppb", range(-5000, 5100, 1000) + [1])
    def test_mac_gpio_sync_nightly_100M(self, ppb):
        self.mac_phy_sync(LINK_SPEED_100M, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 1000) + [1])
    def test_mac_gpio_sync_nightly_1G(self, ppb):
        self.mac_phy_sync(LINK_SPEED_1G, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 1000) + [1])
    def test_mac_gpio_sync_nightly_2_5G(self, ppb):
        self.mac_phy_sync(LINK_SPEED_2_5G, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 1000) + [1])
    def test_mac_gpio_sync_nightly_5G(self, ppb):
        self.mac_phy_sync(LINK_SPEED_5G, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 1000) + [1])
    def test_mac_gpio_sync_nightly_10G(self, ppb):
        self.mac_phy_sync(LINK_SPEED_10G, "gpio", ppb=ppb)

    # Sanity
    @idparametrize("ppb", range(-4000, 4100, 2000) + [1])
    def test_mac_gpio_sync_sanity_100M(self, ppb):
        self.DURATION = 180
        self.mac_phy_sync(LINK_SPEED_100M, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-4000, 4100, 2000) + [1])
    def test_mac_gpio_sync_sanity_1G(self, ppb):
        self.DURATION = 180
        self.mac_phy_sync(LINK_SPEED_1G, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-4000, 4100, 2000) + [1])
    def test_mac_gpio_sync_sanity_2_5G(self, ppb):
        self.DURATION = 180
        self.mac_phy_sync(LINK_SPEED_2_5G, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-4000, 4100, 2000) + [1])
    def test_mac_gpio_sync_sanity_5G(self, ppb):
        self.DURATION = 180
        self.mac_phy_sync(LINK_SPEED_5G, "gpio", ppb=ppb)

    @idparametrize("ppb", range(-4000, 4100, 2000) + [1])
    def test_mac_gpio_sync_sanity_10G(self, ppb):
        self.DURATION = 180
        self.mac_phy_sync(LINK_SPEED_10G, "gpio", ppb=ppb)

    def list_map_files(self, path):
        path = path.replace("\\", "/")
        res = Command(cmd="ls {}".format(path), host=NFS_SERVER, silent=True).wait(10)
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to list map files on build server")
        log.info("There are {} map files in {} directory".format(len(res["output"]), path))
        return [os.path.basename(line.rstrip("\r\n")) for line in res["output"]]

    def download_map(self, file):
        suburl = "firmware/{}".format(file)
        url = urlparse.urljoin(BUILDS_SERVER, suburl)
        content = get_url_response(url)
        fname = ntpath.basename(file)
        with open(fname, "wb") as f:
            f.write(content)
        return os.path.abspath(fname).replace("\\", "/")

    def get_mcp_map(self):
        path = os.path.join(self.dut_firmware.FW_BUILD_BASE_PATH, self.dut_firmware.version,
                            self.MCP_MAP_PATH, "*atlantic*_map*").replace("\\", "/")

        map_files = self.list_map_files(path)
        log.info("map_files = {}".format(map_files))
        assert len(map_files) == 1  # only one map file for 3x firmware
        path = os.path.join(self.dut_firmware.version, self.MCP_MAP_PATH).replace("\\", "/")
        file_on_server = os.path.join(path, map_files[0]).replace("\\", "/")
        map_file = self.download_map(file_on_server)
        log.info("MAP file has been downloaded to {}".format(map_file))
        return map_file

    def get_mcp_address(self):
        reg = re.compile(".*\.bss\.sync\s+0x([0-9a-fA-F]+)\s+0x[0-9a-fA-F]+.*")
        map_file = self.get_mcp_map()
        address = None
        with open(map_file, 'r') as fileo:
            for line in fileo:
                match = reg.match(line)
                if match:
                    address = int(match.group(1), 16) & 0x1FFFFFFF
                    break
        if address is not None:
            log.info("Found address off .bss.sync: {}".format(address))
            return address
        raise Exception("Failed to find address of .bss.sync in {}".format(map_file))

    def mac_phy_sync_fw(self, speed, ppb=0):
        drift_tolerance = 4
        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        counter_file = os.path.join(self.test_log_dir, "counters.csv")
        self.dut_mbu.writereg(0x36C, self.CAPS_HI_PTP_AVB_EN)
        self.dut_mbu.writereg(0x378, 0x15)
        self.dut_mbu.set_link_params_2x(speed)

        adjustment_params = self.apply_freq_adjustment(ppb)

        avg_diffs = []
        diff_ts = []
        start = timeit.default_timer()
        mcp_offset = self.get_mcp_address()
        fw_reg = re.compile("^4, (\d+), (\d+)$")
        while (timeit.default_timer() - start) < self.DURATION:
            diff_ts.append(timeit.default_timer() - start)
            self.dut_mbu.exec_beton(["tests.testPtpClock -f -a {} -r 32 -o {} -l nul".format(mcp_offset, counter_file)])
            diffs = []
            with open(counter_file, "r") as fileo:
                for line in fileo:
                    match = fw_reg.match(line)
                    if match:
                        mac_counter = int(match.group(1))
                        phy_counter = int(match.group(2))
                        diffs.append(phy_counter - mac_counter)
                avg_diff = decimal.Decimal(sum(diffs)) / len(diffs)
                avg_diffs.append(avg_diff)
            os.remove(counter_file)
        self.make_plot(diff_ts, avg_diffs, speed, ppb, adjustment_params)
        log.info("Average counter diffs: {}".format([str(item) for item in avg_diffs]))
        expected_drift = decimal.Decimal(
            adjustment_params.ns_mac_adj * self.FRAC_NS_IN_NS + adjustment_params.fns_mac_adj
        ) / self.FRAC_NS_IN_NS
        expected_diff = 2 * drift_tolerance + expected_drift
        diff = max(avg_diffs) - min(avg_diffs)
        log.info("Diff: {}; Expected diff less than {}".format(diff, expected_diff))
        assert diff < expected_diff, "Drift is more than expected. Check plot."
        for num, item in enumerate(avg_diffs[1:], start=1):
            grow = item - avg_diffs[num - 1]
            assert abs(grow) < 2 * drift_tolerance + diff / (len(avg_diffs) - 1), \
                "Measurement error is too high"
            
    # Weekly
    @idparametrize("ppb", range(-5000, 5100, 200) + [1])
    def test_fw_sync_weekly_100M(self, ppb):
        self.mac_phy_sync_fw(LINK_SPEED_100M, ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 200) + [1])
    def test_fw_sync_weekly_1G(self, ppb):
        self.mac_phy_sync_fw(LINK_SPEED_1G, ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 200) + [1])
    def test_fw_sync_weekly_2_5G(self, ppb):
        self.mac_phy_sync_fw(LINK_SPEED_2_5G, ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 200) + [1])
    def test_fw_sync_weekly_5G(self, ppb):
        self.mac_phy_sync_fw(LINK_SPEED_5G, ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 200) + [1])
    def test_fw_sync_weekly_10G(self, ppb):
        self.mac_phy_sync_fw(LINK_SPEED_10G, ppb=ppb)

    # Nightly
    @idparametrize("ppb", range(-5000, 5100, 1000) + [1])
    def test_fw_sync_nightly_100M(self, ppb):
        self.mac_phy_sync_fw(LINK_SPEED_100M, ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 1000) + [1])
    def test_fw_sync_nightly_1G(self, ppb):
        self.mac_phy_sync_fw(LINK_SPEED_1G, ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 1000) + [1])
    def test_fw_sync_nightly_2_5G(self, ppb):
        self.mac_phy_sync_fw(LINK_SPEED_2_5G, ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 1000) + [1])
    def test_fw_sync_nightly_5G(self, ppb):
        self.mac_phy_sync_fw(LINK_SPEED_5G, ppb=ppb)

    @idparametrize("ppb", range(-5000, 5100, 1000) + [1])
    def test_fw_sync_nightly_10G(self, ppb):
        self.mac_phy_sync_fw(LINK_SPEED_10G, ppb=ppb)

    # Sanity
    @idparametrize("ppb", range(-4000, 4100, 2000) + [1])
    def test_fw_sync_sanity_100M(self, ppb):
        self.DURATION = 180
        self.mac_phy_sync_fw(LINK_SPEED_100M, ppb=ppb)

    @idparametrize("ppb", range(-4000, 4100, 2000) + [1])
    def test_fw_sync_sanity_1G(self, ppb):
        self.DURATION = 180
        self.mac_phy_sync_fw(LINK_SPEED_1G, ppb=ppb)

    @idparametrize("ppb", range(-4000, 4100, 2000) + [1])
    def test_fw_sync_sanity_2_5G(self, ppb):
        self.DURATION = 180
        self.mac_phy_sync_fw(LINK_SPEED_2_5G, ppb=ppb)

    @idparametrize("ppb", range(-4000, 4100, 2000) + [1])
    def test_fw_sync_sanity_5G(self, ppb):
        self.DURATION = 180
        self.mac_phy_sync_fw(LINK_SPEED_5G, ppb=ppb)

    @idparametrize("ppb", range(-4000, 4100, 2000) + [1])
    def test_fw_sync_sanity_10G(self, ppb):
        self.DURATION = 180
        self.mac_phy_sync_fw(LINK_SPEED_10G, ppb=ppb)


if __name__ == "__main__":
    exec_list = [__file__, "-s", "-v"]
    if len(sys.argv) > 1:
        exec_list.append("-k {}".format(sys.argv[1]))
    pytest.main(exec_list)
