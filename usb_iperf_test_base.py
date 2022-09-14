import os
import time
import pytest
import csv
import shutil
import json
import tools.ping

from tools.command import Command
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_5G, LINK_SPEED_2_5G, LINK_SPEED_1G, LINK_SPEED_100M, \
    DIRECTION_RXTX, SPEED_TO_MBITS, DIRECTION_RX, DIRECTION_TX, CARD_FIJI, LINK_SPEED_10G, LINK_SPEED_10M
from tools.usb_control import USBPowerMeterControl
from tools.driver import Driver
from tools.utils import get_atf_logger, str_to_bool
from perf.iperf import Iperf
from tools.killer import Killer
from tools.driver import DRV_TYPE_MAC_CDC, DRV_TYPE_LIN_CDC
from tools.iptables import IPTables
from tools.ops import OpSystem
from infra.test_base import TestBase

log = get_atf_logger()

FC_OFF = "off"
FC_ON = "on"

class TestUsbThroughputBase(TestBase):
    IPERF_TIME = int(os.environ.get("IPERF_TIME", 60))
    TOTAL_RES = []

    @classmethod
    def setup_class(cls):
        super(TestUsbThroughputBase, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.install_firmwares()

            if cls.dut_drv_cdc:
                if cls.dut_ops.is_mac():
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, drv_type=DRV_TYPE_MAC_CDC)
                elif cls.dut_ops.is_linux():
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, drv_type=DRV_TYPE_LIN_CDC)
                else:
                    raise Exception("CDC driver is not supported")
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)

            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port)
            cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port, host=cls.lkp_hostname)

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            time.sleep(cls.LINK_CONFIG_DELAY)

            iptables = IPTables(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname)
            iptables.clean()

            cls.dut_ops = OpSystem()

            if str_to_bool(os.environ.get("LOW_POWER", "FALSE")):
                log.info("Enabling LOW POWER 5G")
                cls.dut_ifconfig.set_advanced_property("LowPower5G", "Enable")
                cls.dut_ifconfig.set_link_down()
                cls.dut_ifconfig.set_link_up()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def teardown_method(self, method):
        super(TestUsbThroughputBase, self).teardown_method(method)
        Killer().kill('iperf3')
        Killer(host=self.lkp_hostname).kill('iperf3')

    def run_iperf(self, pair, direction, fc, tmo=IPERF_TIME, is_udp=False, buffer_num_len=[]):
        log.info("Running iperf for {} seconds".format(tmo))
        curr_speed = self.lkp_ifconfig.get_link_speed()
        if is_udp:
            real_pair = 1
            proc = pair
        else:
            proc = 1
            real_pair = pair

        args = {
            'direction': direction,
            'speed': curr_speed,
            'num_threads': int(real_pair),
            'num_process': int(proc),
            'time': tmo,
            'ipv': 4,
            'buffer_len': 0,
            'is_udp': is_udp,
            'is_eee': False,
            'is_fc': True if fc == FC_ON else False,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
        }

        if is_udp:
            if self.dut_ops.is_windows():
                buffer_len_dict = {LINK_SPEED_10G: '{}'.format(65500),
                                   LINK_SPEED_5G: '{}'.format(65500),
                                   LINK_SPEED_2_5G: '{}'.format(35500),
                                   LINK_SPEED_1G: '{}'.format(8192),
                                   LINK_SPEED_100M: '{}'.format(8192)}
                args.update({'buffer_len': buffer_len_dict[curr_speed]})

            if self.dut_fw_card == CARD_FIJI:
                if self.dut_ops.is_mac():
                    b_dict = {LINK_SPEED_5G: '{}'.format(4000 / int(pair)),
                              LINK_SPEED_2_5G: '{}'.format(2400 / int(pair)),
                              LINK_SPEED_1G: '{}'.format(950 / int(pair)),
                              LINK_SPEED_100M: '{}'.format(100 / int(pair))}
                else:
                    b_dict = {LINK_SPEED_5G: '4000',
                              LINK_SPEED_2_5G: '2400',
                              LINK_SPEED_1G: '950',
                              LINK_SPEED_100M: '100'}
            else:
                b_dict = {LINK_SPEED_10G: '10000',
                          LINK_SPEED_5G: '5000',
                          LINK_SPEED_2_5G: '2500',
                          LINK_SPEED_1G: '1000',
                          LINK_SPEED_100M: '100',
                          LINK_SPEED_10M: '10'}

            args.update({'bandwidth': b_dict[curr_speed]})
            if int(pair) > 1:
                args.update({'buffer_num_len': buffer_num_len})

        nof_att = 3
        for i in range(nof_att):
            log.info("{:#<20}".format("Iteration: {} ".format(i)))
            if self.dut_fw_card in CARD_FIJI:
                usb_power_meter_control = USBPowerMeterControl()
                usb_power_meter_control.run_async(self.dut_usb_connect, False, self.dut_port)

            if not self.dut_ops.is_linux():
                log.info(self.dut_ifconfig.get_media_options(options_to_check=["flow-control", "full-duplex"]))

            time.sleep(3)
            assert tools.ping.ping(4, self.LKP_IPV4_ADDR, src_addr=self.DUT_IPV4_ADDR, margin=25) is True

            iperf = Iperf(**args)
            result = iperf.run()

            if self.dut_fw_card in CARD_FIJI:
                time.sleep(3)
                plot = usb_power_meter_control.join(self.dut_usb_connect, self.dut_port)
                if plot is not None:
                    shutil.move(plot, self.test_log_dir)

            if result != Iperf.IPERF_OK:
                if i == nof_att - 1:
                    raise Exception('Iperf broken. Please rerun iperf.')
                else:
                    continue
            else:
                break

        results = iperf.get_performance()

        if direction in (DIRECTION_RX, DIRECTION_TX):
            metrics = results[0].get_metrics()
            desc, units, mi, ma, av, count = metrics[0]
            return "{:6.2f}".format(av), results
        else:
            metrics_rx = results[0].get_metrics()
            metrics_tx = results[1].get_metrics()
            desc_rx, units_rx, mi_rx, ma_rx, av_rx, count_rx = metrics_rx[0]
            desc_tx, units_tx, mi_tx, ma_tx, av_tx, count_tx = metrics_tx[0]
            return "{:6.2f}/{:6.2f}".format(av_rx, av_tx), results

    def run_iperf_usb(self, pair, direction, speed=LINK_SPEED_AUTO,
                      fc=FC_ON, is_udp=False, buffer_num_len=[]):

        if speed != LINK_SPEED_AUTO and speed not in self.supported_speeds:
            pytest.skip()

        if speed not in self.supported_speeds:
            pytest.skip()

        if fc == FC_OFF:
            self.dut_ifconfig.set_media_options(["full-duplex"])
            self.lkp_ifconfig.set_media_options(["full-duplex"])
        elif fc == FC_ON:
            self.dut_ifconfig.set_media_options(["flow-control", "full-duplex"])
            self.lkp_ifconfig.set_media_options(["full-duplex", "flow-control"])

        if not self.dut_drv_cdc:
            self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.wait_link_up()

        time.sleep(3)
        assert tools.ping.ping(4, self.LKP_IPV4_ADDR, src_addr=self.DUT_IPV4_ADDR, margin=25) is True

        perf, results = self.run_iperf(pair, direction, fc, is_udp=is_udp, buffer_num_len=buffer_num_len)
        self.TOTAL_RES.append([speed, pair, direction, perf, fc, is_udp])

        count = -1
        if self.dut_ops.is_windows() and self.dut_fw_card in CARD_FIJI:
            res_cmd = Command(cmd='powershell "Get-WmiObject -Namespace root/wmi \
-Class Aq_UsbDiagnosticsData | ConvertTo-Json"', silent=True).run()
            j = json.loads("\n".join(res_cmd["output"]))
            if res_cmd["returncode"] != 0:
                log.info("Failed to get Usb Diagnostics Data")
            else:
                count = j["rxErrPacketCount"]

        log.info('>>  +-----------------------------------------------------------------------+ ')
        log.info('>>  Speed: {:6}'.format(speed))
        log.info('>>  Pair: {:6}'.format(pair))
        log.info('>>  Direction: {:6}'.format(direction))
        log.info('>>  Throughput: {:6} Mbps'.format(perf))
        log.info('>>  Flow control: {}'.format(fc))
        if count != -1:
            log.info('>>  Rx Error Packet Count: {}'.format(count))
        log.info('>> +------------------------------------------------------------------------+ ')

        curr_speed = self.lkp_ifconfig.get_link_speed()

        if self.dut_fw_card == CARD_FIJI:
            # Specify bandwidth thresholds for FIJI
            if not self.dut_drv_cdc:
                if curr_speed == LINK_SPEED_2_5G:
                    b = 0.73
                elif curr_speed == LINK_SPEED_5G:
                    b = 0.52
                else:
                    if self.usb_2_0:
                        if curr_speed == LINK_SPEED_1G:
                            if direction == DIRECTION_RXTX:
                                b = 0.01
                                bandwidth = 350
                                self.check_sum_rx_tx_thresholds(SPEED_TO_MBITS[curr_speed], perf, bandwidth)
                            else:
                                b = 0.27
                        else:
                            if direction == DIRECTION_RXTX:
                                b = 0.01
                                bandwidth = 105
                                self.check_sum_rx_tx_thresholds(SPEED_TO_MBITS[curr_speed], perf, bandwidth)
                            else:
                                b = 0.9
                    else:
                        b = 0.80
            elif self.dut_drv_cdc and self.dut_ops.is_mac():
                # On macOS ECM driver there are no multiple packet per one usb block request.
                # So put special thresholds for iperf performance.
                if curr_speed == LINK_SPEED_2_5G:
                    if direction == DIRECTION_RXTX:
                        b = 0.01
                        bandwidth = 1800
                        self.check_sum_rx_tx_thresholds(SPEED_TO_MBITS[curr_speed], perf, bandwidth)
                    else:
                        b = 0.6
                elif curr_speed == LINK_SPEED_5G:
                    if direction == DIRECTION_RXTX:
                        b = 0.01
                        bandwidth = 1800
                        self.check_sum_rx_tx_thresholds(SPEED_TO_MBITS[curr_speed], perf, bandwidth)
                    else:
                        b = 0.3
                elif curr_speed == LINK_SPEED_1G:
                    b = 0.6
                else:
                    b = 0.6
            else:
                if curr_speed == LINK_SPEED_2_5G:
                    b = 0.6
                elif curr_speed == LINK_SPEED_5G:
                    b = 0.3
                elif curr_speed == LINK_SPEED_1G:
                    b = 0.7
                else:
                    b = 0.85
        else:
            # Specify bandwidth thresholds for other cards
            b = 0.94
            


        for res in results:
            res.check(criterion={'b': b, 'l': 0.5})

    def check_sum_rx_tx_thresholds(self, speed, perf, bandwidth):
        av_rx, av_tx = perf.split('/')
        assert float(av_rx) + float(av_tx) > bandwidth, 'Sum of rx and tx bandwidth \
                                                        can not be less than {}'.format(bandwidth)

    def make_report(self):
        log.info('>> DUT speed, LKP speed, Pair, Direction, AVG speed, FC, UDP')
        log.info('>> ------------------------------------------------------------------------------- ')
        for res in self.TOTAL_RES:
            log.info(">>  {}".format(res))
        log.info('>> ------------------------------------------------------------------------------- ')

        csv_file = "usb_iperf.csv"
        self.TOTAL_RES.insert(0, ["Speed, Pair, Direction, AVG speed, FC, UDP"])
        with open(csv_file, 'wb') as f:
            wr = csv.writer(f, dialect='excel')
            wr.writerows(self.TOTAL_RES)
        log.info("Copy file {} to: {}".format(csv_file, self.test_log_dir))
        new_path = os.path.join(self.test_log_dir, os.path.basename(csv_file))
        shutil.move(csv_file, new_path)
