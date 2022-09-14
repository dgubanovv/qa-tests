import os
import time

import numpy
import pytest

from infra.test_base import TestBase
from perf.iperf import Iperf
from perf.iperf_result import IperfResult
from tools.aqpkt import Aqsendp, scapy_pkt_to_aqsendp_str
from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import LINK_STATE_UP, DIRECTION_RXTX, CARD_FIJI, MTU_16000
from tools.driver import Driver, DRV_TYPE_KO
from tools.killer import Killer
from tools.ops import OpSystem
from tools.scapy_tools import ScapyTools
from tools.utils import get_atf_logger
from scapy.all import Ether, IP, TCP, Dot1Q, Raw

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_counters"


class TestDrvCounters(TestBase):
    """
    @description: The TestDrvCounters test is dedicated to verify Driver counters.

    @setup: Two Aquantia devices connected back to back.
    """

    COUNTERS_TO_CHECK = ["InOctets", "InOctetsDma", "InPackets", "InPacketsDma", "OutOctets", "OutOctetsDma",
                         "OutPackets", "OutPacketsDma", "ReceivedBytes", "ReceivedUnicastBytes",
                         "ReceivedUnicastPackets", "SentBytes", "SentUnicastBytes", "SentUnicastPackets"]

    @classmethod
    def setup_class(cls):
        super(TestDrvCounters, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            if cls.dut_fw_card not in CARD_FIJI:
                cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)
            if cls.lkp_fw_card not in CARD_FIJI:
                cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            if cls.dut_fw_card not in CARD_FIJI and cls.dut_atltool_wrapper.is_secure_chips() and \
                    cls.dut_ops.is_linux():
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, flashless_fw=cls.dut_fw_version)
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            if cls.platform and "Tehuti" in cls.platform:
                cls.lkp_driver = Driver(port=cls.lkp_port, version="latest",
                                        host=cls.lkp_hostname, drv_type=DRV_TYPE_KO)
            else:
                cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_iface = cls.dut_ifconfig.get_conn_name()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.DEFAULT_NETMASK_IPV4, None)
            cls.dut_ifconfig.wait_link_up()
            cls.lkp_scapy_tool = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.dut_scapy_tool = ScapyTools(port=cls.dut_port)
            cls.dut_scapy_iface = cls.dut_scapy_tool.get_scapy_iface()
            cls.lkp_scapy_iface = cls.lkp_scapy_tool.get_scapy_iface()
            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
            cls.dut_ifconfig.set_arp(cls.LKP_IPV4_ADDR, cls.lkp_mac)
            cls.lkp_ifconfig.set_arp(cls.DUT_IPV4_ADDR, cls.dut_mac)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestDrvCounters, self).setup_method(method)
        self.lkp_ifconfig.set_ip_address(self.LKP_IPV4_ADDR, self.DEFAULT_NETMASK_IPV4, None)

    def run_counter_test(self, counter_names, counter_get_func, aqsendp,
                         percentile_borders, nof_batches=20):

        counter_values = {c: list() for c in counter_names}
        for i in range(nof_batches):
            counters_before = counter_get_func()
            aqsendp.run()
            counters_after = counter_get_func()

            for k in counter_names:
                counter_values[k].append(counters_after[k] - counters_before[k])

        for counter_name in counter_names:
            log.info("Counter {} values: {}".format(counter_name, counter_values[counter_name]))

        percentiles = []
        for counter_name in counter_names:
            perc = numpy.percentile(counter_values[counter_name], 70)
            log.info("70 percentile for counter {} is {}".format(counter_name, perc))
            percentiles.append(perc)

        for i in range(len(counter_names)):
            assert percentile_borders[i][0] <= percentiles[i] <= percentile_borders[i][1]

    def test_in_ucast_linux(self):
        """
        @description: Check 'InPackets', 'InUCast', 'InPacketsDma', 'InOctets', 'InOctetsDma' counters.

        @steps:
        1. Get Driver counter values.
        2. Send packets from LKP to DUT.
        3. Get Driver counter values after traffic.
        4. Check new counter values.

        @result: All counters have correct value.
        @duration: 1 minutes.
        """
        if not OpSystem().is_linux() or OpSystem().is_freebsd() or "forwarding" in self.dut_drv_version:
            pytest.skip()

        pkt_out = Ether(dst=self.dut_mac, src=self.lkp_mac)
        pkt_no_payload = pkt_out / IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR) / TCP()
        pkt_with_payload = pkt_no_payload / Raw(load='\xff'*100)

        for pkt in [pkt_no_payload, pkt_with_payload]:
            nof_packets = 1000
            counter_names = ['InPackets', 'InUCast', 'InPacketsDma', 'InOctets', 'InOctetsDma']
            counter_func = self.dut_statistics.get_drv_counters
            aqsendp = Aqsendp(count=nof_packets, host=self.lkp_hostname, packet=scapy_pkt_to_aqsendp_str(pkt))
            self.run_counter_test(
                counter_names, counter_func, aqsendp,
                [(nof_packets, nof_packets + 10),
                 (nof_packets, nof_packets + 10),
                 (nof_packets, nof_packets + 10),
                 (max(len(pkt) + 4, 64) * nof_packets, max(len(pkt) + 4, 64) * nof_packets + 1000),
                 (len(pkt) * nof_packets, len(pkt) * nof_packets + 1000)])

    def test_out_ucast_linux(self):
        """
        @description: Check 'OutPackets', 'OutUCast', 'OutPacketsDma', 'OutOctets', 'OutOctetsDma' counters.

        @steps:
        1. Get Driver counter values.
        2. Send packets from DUT to LKP.
        3. Get Driver counter values after traffic.
        4. Check new counter values.

        @result: All counters have correct value.
        @duration: 1 minutes.
        """
        if not OpSystem().is_linux() or "forwarding" in self.dut_drv_version or OpSystem().is_freebsd():
            pytest.skip()

        pkt = Ether(dst=self.lkp_mac, src=self.dut_mac)
        pkt /= IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR) / TCP() / Raw('\xff' * 42)
        nof_packets = 1000
        counter_names = ['OutPackets', 'OutUCast', 'OutPacketsDma', 'OutOctets', 'OutOctetsDma']
        counter_func = self.dut_statistics.get_drv_counters
        aqsendp = Aqsendp(count=nof_packets, host=self.dut_hostname, packet=scapy_pkt_to_aqsendp_str(pkt))
        self.run_counter_test(
            counter_names, counter_func, aqsendp,
            [(nof_packets, nof_packets + 10),
             (nof_packets, nof_packets + 10),
             (nof_packets, nof_packets + 10),
             (max(len(pkt) + 4, 64) * nof_packets, max(len(pkt) + 4, 64) * nof_packets + 1000),
             (len(pkt) * nof_packets, len(pkt) * nof_packets + 1000)])

    def test_in_bcast_packets_linux(self):
        """
        @description: Check Received Broadcast Packets counters.

        @steps:
        1. Get Driver counter values.
        2. Send packets from LKP to DUT.
        3. Get Driver counter values after traffic.
        4. Check new counter values.

        @result: All counters have correct value.
        @duration: 1 minutes.
        """
        if not OpSystem().is_linux() or "forwarding" in self.dut_drv_version or OpSystem().is_freebsd():
            pytest.skip()

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.lkp_mac)
        pkt /= IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR) / TCP() / Raw('\xff' * 42)
        nof_packets = 1000
        counter_names = ['InBCast']
        counter_func = self.dut_statistics.get_drv_counters
        aqsendp = Aqsendp(count=nof_packets, host=self.lkp_hostname, packet=scapy_pkt_to_aqsendp_str(pkt))
        self.run_counter_test(
            counter_names, counter_func, aqsendp,
            [(nof_packets, nof_packets + 10)])

    def test_out_bcast_packets_linux(self):
        """
        @description: Check Sent Broadcast Packets counters.

        @steps:
        1. Get Driver counter values.
        2. Send packets from DUT to LKP.
        3. Get Driver counter values after traffic.
        4. Check new counter values.

        @result: All counters have correct value.
        @duration: 1 minutes.
        """
        if not OpSystem().is_linux() or "forwarding" in self.dut_drv_version or OpSystem().is_freebsd():
            pytest.skip()

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.dut_mac)
        pkt /= IP(src=self.DUT_IPV4_ADDR, dst=self.LKP_IPV4_ADDR) / TCP() / Raw('\xff' * 42)
        nof_packets = 1000
        counter_names = ['OutBCast']
        counter_func = self.dut_statistics.get_drv_counters
        aqsendp = Aqsendp(count=nof_packets, host=self.dut_hostname, packet=scapy_pkt_to_aqsendp_str(pkt))
        self.run_counter_test(
            counter_names, counter_func, aqsendp,
            [(nof_packets, nof_packets + 10)])

    def test_in_mcast_packets_linux(self):
        """
        @description: Check Received Muticast Packets counters.

        @steps:
        1. Get Driver counter values.
        2. Send packets from LKP to DUT.
        3. Get Driver counter values after traffic.
        4. Check new counter values.

        @result: All counters have correct value.
        @duration: 1 minutes.
        """
        if not OpSystem().is_linux() or "forwarding" in self.dut_drv_version or OpSystem().is_freebsd():
            pytest.skip()

        pkt = Ether(dst="01:00:5e:00:00:05", src=self.lkp_mac)
        pkt /= IP(src=self.LKP_IPV4_ADDR, dst="224.0.0.5") / TCP() / Raw('\xff' * 42)
        nof_packets = 1000
        counter_names = ['InMCast']
        counter_func = self.dut_statistics.get_drv_counters
        aqsendp = Aqsendp(count=nof_packets, host=self.lkp_hostname, packet=scapy_pkt_to_aqsendp_str(pkt))
        self.run_counter_test(
            counter_names, counter_func, aqsendp,
            [(nof_packets, nof_packets + 10)])

    def test_out_mcast_packets_linux(self):
        """
        @description: Check Sent Muticast Packets counters.

        @steps:
        1. Get Driver counter values.
        2. Send packets from DUT to LKP.
        3. Get Driver counter values after traffic.
        4. Check new counter values.

        @result: All counters have correct value.
        @duration: 1 minutes.
        """
        if not OpSystem().is_linux() or "forwarding" in self.dut_drv_version or OpSystem().is_freebsd():
            pytest.skip()

        pkt = Ether(dst="01:00:5e:00:00:05", src=self.dut_mac)
        pkt /= IP(src=self.DUT_IPV4_ADDR, dst="224.0.0.5") / TCP() / Raw('\xff' * 42)
        nof_packets = 1000
        counter_names = ['OutMCast']
        counter_func = self.dut_statistics.get_drv_counters
        aqsendp = Aqsendp(count=nof_packets, host=self.dut_hostname, packet=scapy_pkt_to_aqsendp_str(pkt))
        self.run_counter_test(
            counter_names, counter_func, aqsendp,
            [(nof_packets, nof_packets + 10)])

    def test_rx_packets_queue_linux_fwd(self):
        """
        @description: Check Recived Packets per queue counters.

        @steps:
        1. Get Driver counter values.
        2. Send packets from LKP to DUT.
        3. Get Driver counter values after traffic.
        4. Check new counter values.

        @result: All counters have correct value.
        @duration: 1 minutes.
        """
        if not OpSystem().is_linux() or OpSystem().is_freebsd():
            pytest.skip()

        if 'forwarding' in self.dut_drv_version:
            counter_name = 'ring_{}_rx_packets'
        else:
            counter_name = 'Queue[{}] InPackets'

        nof_packets = 1000

        # get rings number
        res = Command(cmd="ethtool -x {} | grep indirection | awk '{{print $9}}'".format(self.dut_iface)).run()
        rings = int(res['output'][0])

        for ring_num in range(rings):
            self.dut_ifconfig.create_vlan_iface(ring_num)
            self.dut_ifconfig.set_link_state(LINK_STATE_UP, vlan_id=ring_num)
            self.dut_ifconfig.wait_link_up(vlan_id=ring_num)

            Command(cmd='ethtool -N {0} flow-type ether vlan {1} m 0xF000 action {1} loc {1}'.format(
                self.dut_iface, ring_num)).run()

            pkt = Ether(dst=self.dut_mac, src=self.lkp_mac) / Dot1Q(vlan=ring_num)
            pkt /= IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR) / TCP()
            lkp_aqsendp = Aqsendp(count=nof_packets, packet=scapy_pkt_to_aqsendp_str(pkt), host=self.lkp_hostname)

            self.run_counter_test([counter_name.format(ring_num)],
                                  self.dut_statistics.get_drv_counters,
                                  lkp_aqsendp,
                                  [(nof_packets, nof_packets + 10)])

    def test_tx_bytes_tx_packets_fwd(self):
        """
        @description: Check Sent Packets and Bytes counters.

        @steps:
        1. Get Driver counter values.
        2. Send packets from DUT to LKP.
        3. Get Driver counter values after traffic.
        4. Check new counter values.

        @result: All counters have correct value.
        @duration: 1 minutes.
        """
        if "forwarding" not in self.dut_drv_version:
            pytest.skip()

        nof_packets = 1000
        pkt = Ether(dst=self.lkp_mac, src=self.dut_mac)
        pkt /= IP(src=self.DUT_IPV4_ADDR, dst=self.LKP_IPV4_ADDR) / TCP() / "99999999999999999999999"
        dut_aqsendp = Aqsendp(count=nof_packets, packet=scapy_pkt_to_aqsendp_str(pkt))

        self.run_counter_test(["tx_bytes", "tx_packets"],
                              self.dut_statistics.get_drv_counters,
                              dut_aqsendp,
                              [(len(pkt) * nof_packets, len(pkt) * nof_packets + 1000),
                               (nof_packets, nof_packets + 10)])

    def test_rx_bytes_rx_packets_fwd(self):
        """
        @description: Check Recived Packets and Bytes counters.

        @steps:
        1. Get Driver counter values.
        2. Send packets from LKP to DUT.
        3. Get Driver counter values after traffic.
        4. Check new counter values.

        @result: All counters have correct value.
        @duration: 1 minutes.
        """
        if "forwarding" not in self.dut_drv_version:
            pytest.skip()

        nof_packets = 1000
        pkt = Ether(dst=self.dut_mac, src=self.lkp_mac)
        pkt /= IP(src=self.LKP_IPV4_ADDR, dst=self.DUT_IPV4_ADDR) / TCP() / "99999999999999999999999"
        lkp_aqsendp = Aqsendp(count=nof_packets, packet=scapy_pkt_to_aqsendp_str(pkt), host=self.lkp_hostname)

        self.run_counter_test(["rx_bytes", "rx_packets"],
                              self.dut_statistics.get_drv_counters,
                              lkp_aqsendp,
                              [(len(pkt) * nof_packets - 1000, len(pkt) * nof_packets + 1000),
                               (nof_packets - 10, nof_packets + 10)])

    def test_in_out_ucast_packet_win(self):
        """
        @description: Check Received and Sent Unicast Packets counters.

        @steps:
        1. Get Driver counter values.
        2. Run bidirection UDP traffic with packet payload length 64 bytes.
        3. Get Driver counter values after traffic.
        4. Check ReceivedUnicastPackets counter.
        5. Check SendUnicastPackets counter.

        @result: All counters have correct value.
        @duration: 1 minutes.
        """
        if not OpSystem().is_windows():
            pytest.skip()
        for i in range(3):
            counters_prev = self.dut_statistics.get_drv_counters()
            log.info('iperf #{}'.format(i))

            Killer(host=self.dut_hostname).kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")
            args = {
                'packets': 50000,
                'time': 17,
                'ipv': 4,
                'buffer_len': 64,
                'direction': DIRECTION_RXTX,
                'criterion': IperfResult.SANITY,
                'is_udp': True,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': self.LKP_IPV4_ADDR,
                'dut4': self.DUT_IPV4_ADDR,
                'bandwidth': 100,
                'speed': self.dut_ifconfig.wait_link_up()
            }

            iperf = Iperf(**args)
            result = iperf.run()

            if result != Iperf.IPERF_OK:
                continue

            results = iperf.get_performance()

            # print statistics
            for res in results:
                log.info(res)

            # check results
            for res in results:
                res.check(criterion=args['criterion'])

            counters_curr = self.dut_statistics.get_drv_counters()
            break

        for k in counters_curr.keys():
            if "ReceivedUnicastPackets" == k:
                counter = int(counters_curr[k]) - int(counters_prev[k])
                resived_unicast_pack = counter
            if "SentUnicastPackets" == k:
                counter = int(counters_curr[k]) - int(counters_prev[k])
                sent_unicast_pack = counter

        assert resived_unicast_pack - 50000 < 50, "counter ReceivedUnicastPackets shows incorrect value, " \
                                                  "expected 50000 actual {}".format(resived_unicast_pack)

        assert sent_unicast_pack - 50000 < 50, "counter SendUnicastPackets shows incorrect value, expected 50000 " \
                                               "actual {}".format(sent_unicast_pack)

    def test_in_out_ucast_byte_win(self):
        """
        @description: Check Received and Sent Unicast Bytes counters.

        @steps:
        1. Set mtu 16000 on both sides.
        2. Get Driver counter values.
        3. Run bidirection UDP traffic with packet payload length 15000 bytes.
        4. Get Driver counter values after traffic.
        5. Check ReceivedUnicastBytes counter.
        6. Check SentUnicastBytes counter.

        @result: All counters have correct value.
        @duration: 1 minutes.
        """
        if not OpSystem().is_windows():
            pytest.skip()
        self.dut_ifconfig.set_mtu(MTU_16000)
        self.lkp_ifconfig.set_mtu(MTU_16000)
        buf_len = 15000
        packet = 1000
        if self.platform and "Switch-Fiji" in self.platform:
            buf_len = 8500
            packet = 2000
        for i in range(3):
            counters_prev = self.dut_statistics.get_drv_counters()
            log.info('iperf #{}'.format(i))

            Killer(host=self.dut_hostname).kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")
            args = {
                'bytes': buf_len * packet,
                'time': 17,
                'ipv': 4,
                'buffer_len': buf_len,
                'direction': DIRECTION_RXTX,
                'criterion': IperfResult.SANITY,
                'is_udp': True,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': self.LKP_IPV4_ADDR,
                'dut4': self.DUT_IPV4_ADDR,
                'bandwidth': 100,
                'speed': self.dut_ifconfig.wait_link_up()
            }
            iperf = Iperf(**args)
            result = iperf.run()

            if result != Iperf.IPERF_OK:
                continue

            results = iperf.get_performance()

            # print statistics
            for res in results:
                log.info(res)

            # check results
            for res in results:
                res.check(criterion=args['criterion'])

            counters_curr = self.dut_statistics.get_drv_counters()
            break

        for k in counters_curr.keys():
            if "ReceivedUnicastBytes" == k:
                counter = int(counters_curr[k]) - int(counters_prev[k])
                resived_unicast_bytes = counter

            if "SentUnicastBytes" == k:
                counter = int(counters_curr[k]) - int(counters_prev[k])
                sent_unicast_bytes = counter

        assert resived_unicast_bytes - (buf_len * packet) < 500 * packet, "counter ReceivedUnicastBytes shows " \
                                                                          "incorrect value, expected {} actual " \
                                                                          "{}".format(buf_len * packet + 500 *
                                                                                      packet, resived_unicast_bytes)

        assert sent_unicast_bytes - (buf_len * packet) < 500 * packet, "counter SentUnicastBytes shows " \
                                                                       "incorrect value, expected {} actual " \
                                                                       "{}".format(buf_len * packet + 500 * packet,
                                                                                   sent_unicast_bytes)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
