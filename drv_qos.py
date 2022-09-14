import os
import time

import pytest

from infra.test_base import TestBase
from perf.iperf_client import IperfClient
from perf.iperf_server import IperfServer
from tools.aqpkt import Aqsendp
from tools.command import Command
from tools.constants import DIRECTION_TX, SPEED_TO_MBITS
from tools.driver import Driver
from tools.scapy_tools import Ether, Dot1Q, IP, Raw
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "drv_qos"


def cmd_run_check(cmd):
    res = Command(cmd=cmd).run()
    assert res["returncode"] == 0, 'Command: "{}" finished with non zero exit code.'.format(cmd)
    return res


class TestDrvQoS(TestBase):
    """
    @description: The TestDrvQoS test is dedicated to verify Driver Quality of Service (QoS) feature.
    Spread RX and TX traffic through TCs

    @setup: Two Aquantia devices connected back to back.
    """

    @classmethod
    def setup_class(cls):
        super(TestDrvQoS, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()
            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.dut_ifconfig.wait_link_up()

            cls.dut_mac = cls.dut_ifconfig.get_mac_address()
            cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
            cls.dut_iface = cls.dut_ifconfig.get_conn_name()

            res = cmd_run_check("ethtool -x {} | grep indirection | awk '{{print $9}}'".format(cls.dut_iface))
            cls.num_qu = int(res['output'][0])

        except Exception:
            log.exception("Failed while setting up class")
            raise

    def teardown_method(self, method):
        cmd_run_check('sudo iptables -t mangle -F')
        cmd_run_check('sudo tc qdisc del dev {} root'.format(self.dut_iface))

    def test_mqprio_egress(self):
        """
        @description: This subtest performs check that driver spread TX traffic through TCs.

        @steps:
        1. Configure QoS rule by 'tc', prio_map shows how skb_prio will be mapped to TC.
        For each skb_prio:
            2. Assign skb_prio to traffic with target destination ip via iptables.
            3. Send traffic.
            4. Check traffic goes to appropriate TC.

        @result: All ckecks are passed.
        @duration: 15 minutes.
        """
        if self.num_qu == 8:
            num_tc = 4
        elif self.num_qu == 4:
            num_tc = 8
        else:
            num_tc = 4

        prio_map = range(num_tc) + [0] * (16 - num_tc)
        mapping = ' '.join(map(str, prio_map))
        set_qdisk = 'sudo tc qdisc add dev {} root mqprio num_tc {} map {}'.format(
            self.dut_iface, num_tc, mapping)
        cmd_run_check(set_qdisk)
        self.dut_ifconfig.wait_link_up()

        nof_packets = 100
        for prio in range(8):
            tc = prio_map[prio]
            target_ip = '192.168.10.1{}'.format(tc)
            self.lkp_ifconfig.set_ip_address(target_ip, self.NETMASK_IPV4, None)
            cmd_run_check('sudo iptables -t mangle -I OUTPUT -p ip '
                          '-d {} -j CLASSIFY --set-class 0:{}'.format(target_ip, tc))

            def get_counter():
                res = 0
                counters = self.dut_statistics.get_drv_counters()
                for q in range(self.num_qu):
                    key = 'TC{} Queue[{}] OutPackets'.format(tc, self.num_qu * tc + q)
                    res += counters[key]
                return res

            counters_before = get_counter()
            self.ping(None, target_ip, nof_packets)
            counters_after = get_counter()

            self.lkp_ifconfig.del_ip_address(target_ip)

            msg = 'Test case: TC: {} transmit packets, expected: {}, actual: {}'.format(
                tc, nof_packets, counters_after - counters_before)
            assert counters_after - counters_before >= nof_packets, msg

    def test_mqprio_ingress(self):
        """
        @description: This subtest performs check that driver spread RX traffic through TCs.

        @steps:
        1. Configure QoS rule by 'tc', prio_map shows how skb_prio will be mapped to TC.
        For each skb_prio:
            2. Send traffic with prio specified in Dot1Q prio.
            3. Check traffic goes to appropriate TC.

        @result: All ckecks are passed.
        @duration: 15 minutes.
        """
        if self.num_qu == 8:
            num_tc = 4
        elif self.num_qu == 4:
            num_tc = 8
        else:
            num_tc = 4

        prio_map = range(num_tc) + [0] * (16 - num_tc)
        mapping = ' '.join(map(str, prio_map))
        set_qdisk = 'sudo tc qdisc add dev {} root mqprio num_tc {} map {}'.format(
            self.dut_iface, num_tc, mapping,)
        cmd_run_check(set_qdisk)
        self.dut_ifconfig.wait_link_up()

        nof_packets = 100
        for prio in range(num_tc):
            tc = prio_map[prio]
            pkt = Ether(dst=self.dut_mac) / Dot1Q(vlan=0, prio=prio) / \
                  IP(dst="192.168.200.2") / Raw(load="some data")

            def get_counter():
                res = 0
                counters = self.dut_statistics.get_drv_counters()
                for q in range(self.num_qu):
                    key = 'TC{} Queue[{}] InPackets'.format(tc, self.num_qu * tc + q)
                    res += counters[key]
                return res

            aqsendp = Aqsendp(count=nof_packets, host=self.lkp_hostname, packet=pkt)

            counters_before = get_counter()
            aqsendp.run()
            counters_after = get_counter()

            msg = 'Test case: TC: {} receive packets, expected: {}, actual: {}'.format(
                tc, nof_packets, counters_after - counters_before)
            assert counters_after - counters_before >= nof_packets, msg

    def test_mqprio_rate_limit_separate_tc(self):
        """
        @description: This subtest performs check that driver spread TX traffic through TCs with rate limitation.

        @steps:
        1. Configure QoS rule by 'tc', prio_map shows how skb_prio will be mapped to TC.
        For each skb_prio:
            2. Assign skb_prio to traffic with target destination ip via iptables.
            3. Send traffic.
            5. Check traffic speed below speed limit.

        @result: All ckecks are passed.
        @duration: 15 minutes.
        """
        if self.num_qu == 8:
            num_tc = 4
        elif self.num_qu == 4:
            num_tc = 8
        else:
            num_tc = 4

        prio_map = range(num_tc) + [0] * (16 - num_tc)
        mapping = ' '.join(map(str, prio_map))
        if num_tc == 4:
            rlimit_str = '200Mbit 500Mbit 1Gbit 0'
            rlimit_mbits = [200, 500, 1000, 10000]
        else:
            rlimit_str = '200Mbit 500Mbit 1Gbit 0 0 1Gbit 500Mbit 200Mbit'
            rlimit_mbits = [200, 500, 1000, 10000, 10000, 1000, 500, 200]
        set_qdisk = 'sudo tc qdisc add dev {} root mqprio num_tc {} map {} ' \
                    'mode channel shaper bw_rlimit max_rate {}' \
                    ''.format(self.dut_iface, num_tc, mapping, rlimit_str)
        cmd_run_check(set_qdisk)
        speed = self.dut_ifconfig.wait_link_up()

        for tc, r_lim in zip(range(num_tc), rlimit_mbits):
            cmd_run_check('sudo iptables -t mangle -F')
            rule = '-p ip -d {} -j CLASSIFY --set-class 0:{}'.format(self.LKP_IPV4_ADDR, tc)
            cmd_run_check('sudo iptables -t mangle -I OUTPUT {}'.format(rule))

            args = {
                'direction': DIRECTION_TX,
                'speed': speed,
                'bandwidth': SPEED_TO_MBITS[speed],
                'num_threads': 1,
                'num_process': 1,
                'time': 27,
                'ipv': 4,
                'buffer_len': 0,
                'is_udp': True,
                'is_eee': False,
                'is_stat': False,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': self.LKP_IPV4_ADDR,
                'dut4': self.DUT_IPV4_ADDR,
            }
            results = self.run_iperf(**args)

            max_speed = max(results[0].bandwidth)
            assert max_speed <= r_lim, 'TC: {} has speed {} exceeding the limit {}'.format(tc, max_speed, r_lim)

    def test_mqprio_rate_limit_simultaneous(self):
        """
        @description: This subtest performs check that driver spread TX traffic through TCs with rate limitation.

        @steps:
        1. Configure QoS rule by 'tc', prio_map shows how skb_prio will be mapped to TC.
        For each skb_prio:
            2. Assign skb_prio to traffic with target destination ip via iptables.
        3. Simultaneously send traffic for each prio.
        5. Check traffic speed below speed limit.

        @result: All ckecks are passed.
        @duration: 15 minutes.
        """
        if self.num_qu == 8:
            num_tc = 4
        elif self.num_qu == 4:
            num_tc = 8
        else:
            num_tc = 4

        prio_map = range(num_tc) + [0] * (16 - num_tc)
        mapping = ' '.join(map(str, prio_map))
        if num_tc == 4:
            rlimit_str = '200Mbit 500Mbit 1Gbit 0'
            rlimit_mbits = [200, 500, 1000, 10000]
        else:
            rlimit_str = '200Mbit 500Mbit 1Gbit 0 0 1Gbit 500Mbit 200Mbit'
            rlimit_mbits = [200, 500, 1000, 10000, 10000, 1000, 500, 200]
        set_qdisk = 'sudo tc qdisc add dev {} root mqprio num_tc {} map {} ' \
                    'mode channel shaper bw_rlimit max_rate {}' \
                    ''.format(self.dut_iface, num_tc, mapping, rlimit_str)
        cmd_run_check(set_qdisk)
        speed = self.dut_ifconfig.wait_link_up()

        iperf_srv = []
        iperf_clt = []
        for tc in range(num_tc):
            target_ip = '192.168.10.1{}'.format(tc)
            self.lkp_ifconfig.set_ip_address(target_ip, self.NETMASK_IPV4, None)
            cmd_run_check('sudo iptables -t mangle -I OUTPUT '
                          '-p ip -d {} -j CLASSIFY --set-class 0:{}'.format(target_ip, tc))
            args = {
                'direction': DIRECTION_TX,
                'speed': speed,
                'bandwidth': SPEED_TO_MBITS[speed],
                'num_threads': 1,
                'num_process': 1,
                'time': 27,
                'ipv': 4,
                'buffer_len': 0,
                'is_udp': True,
                'is_eee': False,
                'is_stat': False,
                'lkp': self.lkp_hostname,
                'dut': self.dut_hostname,
                'lkp4': self.LKP_IPV4_ADDR,
                'dut4': self.DUT_IPV4_ADDR,
            }

            iperf_srv.append(IperfServer(host=self.lkp_hostname, ip_server=target_ip, **args))
            iperf_clt.append(IperfClient(host=self.dut_hostname, ip_server=target_ip, **args))

        results = []
        for srv in iperf_srv:
            srv.run_async()
        time.sleep(3)
        for clt in iperf_clt:
            clt.run_async()

        for srv in iperf_srv:
            results.append(srv.join())
        for clt in iperf_clt:
            clt.join()

        for tc, (res, r_lim) in enumerate(zip(results, rlimit_mbits)):
            max_speed = max(res.bandwidth)
            assert max_speed <= r_lim, 'TC: {} has speed {} exceeding the limit {}'.format(tc, max_speed, r_lim)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
