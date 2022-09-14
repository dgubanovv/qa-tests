import os
import math
import re
import shutil
import time
import tempfile

import pytest
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt

import numpy as np

from infra.test_base import TestBase, idparametrize
from tools.utils import get_atf_logger, upload_file
from tools.drv_iface_cfg import DrvEthConfig, OffloadIpInfo
from tools.command import Command
from tools.trafficgen import TrafficGenerator, TrafficStream
from tools.driver import Driver, DRV_TYPE_DIAG
from scapy.all import Ether, IP, ICMP, Raw
from tools.mbuper import MbuWrapper
from tools.power import Power
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_AUTO, \
    LINK_STATE_UP

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "power_metering"


class TestPowerMetering(TestBase):
    JASMINE = "JS12V0B004:11"
    LKP_IP = "192.168.0.2"
    DUT_IP = ["192.168.0.3"]
    GATEWAY = "192.168.0.1"
    AFTER_LINK_UP_DELAY = 30
    NETMASK = "255.255.255.0"
    DUT_MAC = "00:17:b6:00:07:82"
    VOLTAGES = {"VDD": 0.85, "P1V2": 1.2, "P2V1": 2.1}
    MEASURE_SCRIPT = "power_meter_BB.py"

    @classmethod
    def setup_class(cls):
        super(TestPowerMetering, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.install_firmwares()
            cls.beaglebone = os.environ["BEAGLEBONE"]

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version=cls.dut_drv_version,
                                    host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.NETMASK, cls.GATEWAY)

            cls.dut_mbu_wrapper = MbuWrapper(port=cls.dut_port, version=cls.mbu_version, host=cls.dut_hostname)
            cls.dut_power = Power(host=cls.dut_hostname)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestPowerMetering, cls).teardown_class()

    def setup_method(self, method):
        super(TestPowerMetering, self).setup_method(method)

        if not self.is_host_alive_and_ready(self.dut_hostname):
            raise Exception("DUT is not online, can't perform test")

    def teardown_method(self, method):
        super(TestPowerMetering, self).teardown_method(method)

        self.bring_host_online(self.dut_hostname)
        self.dut_power.hibernate_off()

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

    def hibernate_dut(self, retry_interval=15):  # TODO: consider moving this to TestBase
        log.info("Hibernating DUT")
        self.dut_power.hibernate()
        if not self.poll_host_powered_off(self.dut_hostname, retry_interval=retry_interval):
            raise Exception("Couldn't hibernate DUT")
        log.info("DUT is hibernated")

    def configure_board(self, speed):
        self.lkp_ifconfig.set_link_speed(speed=speed)
        cfg = DrvEthConfig()
        cfg.version = 0
        cfg.len = 0x407  # not used
        cfg.mac = self.DUT_MAC
        ips = OffloadIpInfo()
        ips.v4_addr_count = len(self.DUT_IP)
        ips.v4_addresses = self.DUT_IP
        ips.v4_masks = [24] * len(self.DUT_IP)
        cfg.ips = ips
        log.info('Configuring IPv4 addresses: {}'.format(ips.v4_addresses))
        # Apply configuration to FW
        beton_file = os.path.join(self.test_log_dir, "offload_ipv4.txt")
        self.dut_mbu_wrapper.kickstart()
        # cfg.apply(self.mbu_wrapper, beton_file)
        beton_code = cfg.get_beton()
        beton_code.insert(0, "writereg 0x36c 0x0")
        beton_code.insert(1, "pause 2 s")
        with open(beton_file, "w") as f:
            for b in beton_code:
                f.write("{}\n".format(b))
        self.dut_mbu_wrapper.exec_beton(beton_code)
        log.info("Making sure that link is up")
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.AFTER_LINK_UP_DELAY)

    def make_plot(self, results, packet_len, speed):
        fig, ax = plt.subplots(nrows=1, ncols=1)
        ax.tick_params(labelsize=8)
        ax.grid(True)
        ax.plot(results["time"], results["power"])
        ax.axhline(y=max(results["power"]), color='r', linestyle='-')
        ax.axhline(y=min(results["power"]), color='g', linestyle='-')
        min_y = min(results["power"])
        max_y = max(results["power"])
        min_max_range = max_y - min_y
        xstep = 1
        ystep = min_max_range / 10

        xx = np.arange(0, math.ceil(results["time"][-1]) + xstep, xstep)
        yy = np.arange(min_y - ystep, max_y+ystep, ystep)
        ax.yaxis.label.set_size(40)
        ax.set_xticks(xx)
        ax.set_yticks(yy)

        power_plot = "power_plot_{}_plen_{}.png".format(packet_len, speed)
        fig.set_size_inches(int(math.ceil(results["time"][-1]))/6, 30/6)
        fig.savefig(power_plot)
        plt.close(fig)
        shutil.move(power_plot, self.test_log_dir)

    def configure_backgroud_traffic(self, packet_len):
        log.info("Preparing background ping traffic...")
        eth = Ether(src=self.lkp_ifconfig.get_mac_address(), dst=self.DUT_MAC)
        ip = IP(src=self.LKP_IP, dst=self.DUT_IP[0])
        icmp = ICMP()
        empty_len = len(eth / ip / icmp)
        raw = Raw(load="f" * (packet_len - empty_len))
        pkt = eth / ip / icmp / raw

        log.info('pkt length = {}'.format(len(pkt)))
        self.trfgen = TrafficGenerator(port=self.lkp_port)
        stream = TrafficStream()
        stream.type = TrafficStream.STREAM_TYPE_CONTINUOUS
        stream.rate = 2
        stream.duration = -1
        stream.nof_packets = 50
        stream.packets = pkt
        self.trfgen.add_stream(stream)

    def collect_results(self, out):
        regexp = re.compile('Time: (\d*.\d*).*rail: (\w+).*Current: (\d*.\d*)')
        results = {"time": [], "VDD": [], "P1V2": [], "P2V1": []}
        for line in out:
            m = regexp.match(line)
            if m:
                (timestamp, rail_type, value) = m.groups()
                if rail_type == "VDD":
                    results["time"].append(float(timestamp))
                results[rail_type].append(float(value))
        min_len = min(map(len, results.values()))
        for key in results.keys():
            results[key] = results[key][:min_len]
        results["power"] = []
        for i in range(0, min_len):
            results["power"].append(0.0)
            for key in self.VOLTAGES.keys():
                results["power"][i] += results[key][i] * self.VOLTAGES[key]
        return results

    @idparametrize("packet_len,speed", [(0, LINK_SPEED_100M),
                                        (40, LINK_SPEED_100M),
                                        (400, LINK_SPEED_100M),
                                        (500, LINK_SPEED_100M),
                                        (512, LINK_SPEED_100M),
                                        (513, LINK_SPEED_100M),
                                        (512, LINK_SPEED_1G),
                                        (513, LINK_SPEED_1G)])
    def test_power_measurement(self, packet_len, speed):
        self.configure_board(speed)
        self.hibernate_dut()
        self.configure_backgroud_traffic(packet_len)
        log.info("Run measurement on BB...")
        measure_time = 60
        result_folder = "result_{}_{}".format(packet_len, speed)
        Command(cmd="mount -o remount,rw /", host=self.beaglebone, username="root").run()
        atf_home = os.environ.get("ATF_HOME")
        measure_script_path = os.path.join(atf_home, "qa-tests", "tools", self.MEASURE_SCRIPT)
        upload_file(self.beaglebone, measure_script_path, "/home/root", username="root")
        cmd = 'PYTHONPATH="/BER:/BER/lib:/BER/lib/PlatformDrivers" ' \
              'python {} -r VDD_C,P1V2_C,P2V1_C -t {} -f {}'\
              .format(self.MEASURE_SCRIPT, measure_time, result_folder)
        # wait while dut going sleep
        time.sleep(45)
        run_cmd = Command(cmd=cmd, host=self.beaglebone, username="root")
        run_cmd.run_async()
        time.sleep(10)
        log.info("Run traffic...")
        if packet_len != 0:
            self.trfgen.run_async()
        run_cmd.join()
        results = self.collect_results(run_cmd.result["output"])
        clear_logs = Command(cmd="rm -rf {}".format(result_folder), host=self.beaglebone, username="root")
        clear_logs.run()

        log.info("Min power: {}".format(min(results["power"])))
        log.info("Max power: {}".format(max(results["power"])))
        self.make_plot(results, packet_len, speed)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
