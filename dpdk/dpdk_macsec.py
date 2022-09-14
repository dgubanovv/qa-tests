import json
import os
import time

import pytest

from dpdk_test_base import TestDPDKBase, run_commands
from tools.command import Command
from tools.constants import LINK_STATE_UP
from trafficgen.traffic_gen import Packets
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "dpdk"


def print_dictionary_to_log(name, d):
    msg = '{}:\n'.format(name)
    for k in sorted(d.keys()):
        msg += '    {}: {}\n'.format(k, d[k])
    log.info(msg)


class TestDPDKMacsec(TestDPDKBase):

    @classmethod
    def setup_class(cls):
        super(TestDPDKMacsec, cls).setup_class()

    def teardown_method(self, method):
        super(TestDPDKMacsec, self).teardown_method(method)
        res = Command(cmd='sudo ip link delete {}'.format('macsec0'), host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot delete MacSec interface on LKP")

    def test_macsec_get_statistics(self):
        self.pytestpmd.exec_cmd('port stop 0')
        self.pytestpmd.exec_cmd('port stop 1')

        self.pytestpmd.exec_cmd('set macsec offload 0 on encrypt on')
        self.pytestpmd.exec_cmd('set macsec sc rx 0 {} 0'.format(self.machines['lkp']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa rx 0 0 0 1 00112200000000000000000000000001')
        self.pytestpmd.exec_cmd('set macsec sc tx 0 {} 0'.format(self.machines['dut']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa tx 0 0 0 1 00112200000000000000000000000001')
        self.pytestpmd.exec_cmd('set fwd macswap')

        self.pytestpmd.exec_cmd('set promisc all on')

        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 88,
            'mac_src': '{}'.format(self.machines['lkp']['mac0']),
            'mac_dst': '{}'.format(self.machines['dut']['mac0']),
            'ipv4_src': '10.10.12.2',
            'ipv4_dst': '10.10.12.3',
            'protocol': 'icmp'
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'duration': 10
        }

        run_commands([
            'sudo ip a',
            'sudo ip link add link {} macsec0 type macsec encrypt on'.format(self.lkp_ifconfig.get_conn_name()),
            'sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 00112200000000000000000000000001',
            'sudo ip macsec add macsec0 rx address {} port 1'.format(self.machines['dut']['mac0']),
            'sudo ip macsec add macsec0 rx address {} port 1 sa 0 pn 1 on key 00 00112200000000000000000000000001'.format(
                self.machines['dut']['mac0']),
            'sudo ip link set dev macsec0 up',
            'sudo ifconfig macsec0 10.10.12.2/24'
        ], host=self.lkp_hostname)

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**generator_args)
        time.sleep(generator_args['duration'] + 1)
        self.traffic_generator.stop()
        time.sleep(5)

        output_dpdk = self.pytestpmd.show_port_xstats(0)
        port = self.dut_port[3:].split('.')
        cmd = 'sudo macsecTool -d {} -s --json'.format(port[0] + ':' + port[1] + '.' + port[2])
        output_tools = json.loads(''.join(Command(cmd=cmd).run()['output']))

        log.info(Command(cmd='ip -s macsec show', host=self.lkp_hostname).run())

        is_equal = True
        for k in sorted(output_dpdk.keys()):
            if k in output_tools.keys():
                if output_dpdk[k] == output_tools[k]:
                    log.info('{:32s}: PASS ({})'.format(k, output_dpdk[k]))
                else:
                    log.info('{:32s}: FAIL ({} != {})'.format(k, output_dpdk[k], output_tools[k]))
                    is_equal = False

        assert is_equal == True, "DPDK statistics is not equal tools statistics"

    def test_macsec_dpdk_off_linux_on(self):

        self.pytestpmd.exec_cmd('port stop 0')
        self.pytestpmd.exec_cmd('port stop 1')

        self.pytestpmd.exec_cmd('set macsec offload 0 off')

        self.pytestpmd.exec_cmd('set macsec sc rx 0 {} 0'.format(self.machines['lkp']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa rx 0 0 0 1 00112200000000000000000000000000')
        self.pytestpmd.exec_cmd('set macsec sc tx 0 {} 0'.format(self.machines['dut']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa tx 0 0 0 1 00112200000000000000000000000000')
        self.pytestpmd.exec_cmd('set fwd macswap')

        self.pytestpmd.exec_cmd('set promisc all on')

        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 666,
            'mac_src': '{}'.format(self.machines['lkp']['mac0']),
            'mac_dst': '{}'.format(self.machines['dut']['mac0']),
            'ipv4_src': '10.10.12.3',
            'ipv4_dst': '10.10.12.3',
            'protocol': 'icmp'
        }

        args = {
            'packets': Packets(**packets_args),
            'duration': 30,
            'delay': 0.01
        }

        run_commands([
            'sudo ip a',
            'sudo ip link add link {} macsec0 type macsec encrypt on'.format(self.lkp_ifconfig.get_conn_name()),
            'sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 00112200000000000000000000000000',
            'sudo ip macsec add macsec0 rx address {} port 1'.format(self.machines['dut']['mac0']),
            'sudo ip macsec add macsec0 rx address {} port 1 sa 0 pn 1 on key 00 00112200000000000000000000000000'.format(
                self.machines['dut']['mac0']),
            'sudo ip link set dev macsec0 up',
            'sudo ifconfig macsec0 10.10.12.2/24'
        ], host=self.lkp_hostname)

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**args)
        time.sleep(args['duration'] + 1)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_xstats(0)
        print_dictionary_to_log('show_port_xstats(0):', output)

        assert output['In_decrypted_octets'] == 0
        assert output['rx_errors'] == 0

    def test_macsec_dpdk_on_linux_off(self):

        self.pytestpmd.exec_cmd('port stop 0')
        self.pytestpmd.exec_cmd('port stop 1')

        self.pytestpmd.exec_cmd('set macsec offload 0 on encrypt on')
        self.pytestpmd.exec_cmd('set macsec sc rx 0 {} 0'.format(self.machines['lkp']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa rx 0 0 0 1 00112200000000000000000000000000')
        self.pytestpmd.exec_cmd('set macsec sc tx 0 {} 0'.format(self.machines['dut']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa tx 0 0 0 1 00112200000000000000000000000000')
        self.pytestpmd.exec_cmd('set fwd macswap')

        self.pytestpmd.exec_cmd('set promisc all on')

        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 666,
            'mac_src': '{}'.format(self.machines['lkp']['mac0']),
            'mac_dst': '{}'.format(self.machines['dut']['mac0']),
            'ipv4_src': '10.10.12.3',
            'ipv4_dst': '10.10.12.3',
            'protocol': 'icmp'
        }

        args = {
            'packets': Packets(**packets_args),
            'duration': 30,
            'delay': 0.01
        }

        run_commands([
            'sudo ip a',
            'sudo ip link add link {} macsec0 type macsec encrypt off'.format(self.lkp_ifconfig.get_conn_name()),
            'sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 00112200000000000000000000000000',
            'sudo ip macsec add macsec0 rx address {} port 1'.format(self.machines['dut']['mac0']),
            'sudo ip macsec add macsec0 rx address {} port 1 sa 0 pn 1 on key 00 00112200000000000000000000000000'.format(
                self.machines['dut']['mac0']),
            'sudo ip link set dev macsec0 up',
            'sudo ifconfig macsec0 10.10.12.2/24'
        ], host=self.lkp_hostname)

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**args)
        time.sleep(args['duration'] + 1)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_xstats(0)
        print_dictionary_to_log('show_port_xstats(0):', output)

        assert output['In_decrypted_octets'] == 0
        assert output['rx_errors'] == 0

    def test_macsec_dpdk_linux(self):

        self.pytestpmd.exec_cmd('port stop 0')
        self.pytestpmd.exec_cmd('port stop 1')

        self.pytestpmd.exec_cmd('set macsec offload 0 on encrypt on replay-protect on')
        self.pytestpmd.exec_cmd('set macsec sc rx 0 {} 0'.format(self.machines['lkp']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa rx 0 0 0 1 00112200000000000000000000000000')
        self.pytestpmd.exec_cmd('set macsec sc tx 0 {} 0'.format(self.machines['dut']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa tx 0 0 0 1 00112200000000000000000000000000')
        self.pytestpmd.exec_cmd('set fwd macswap')

        self.pytestpmd.exec_cmd('set promisc all on')

        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 666,
            'mac_src': '{}'.format(self.machines['lkp']['mac0']),
            'mac_dst': '{}'.format(self.machines['dut']['mac0']),
            'ipv4_src': '10.10.12.2',
            'ipv4_dst': '10.10.12.3',
            'protocol': 'icmp'
        }

        generator_args = {
            'packets': Packets(**packets_args),
            'duration': 30,
            'delay': 0.01
        }

        run_commands([
            'sudo ip a',
            'sudo ip link add link {} macsec0 type macsec encrypt on'.format(self.lkp_ifconfig.get_conn_name()),
            'sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 00112200000000000000000000000000',
            'sudo ip macsec add macsec0 rx address {} port 1'.format(self.machines['dut']['mac0']),
            'sudo ip macsec add macsec0 rx address {} port 1 sa 0 pn 1 on key 00 00112200000000000000000000000000'.format(
                self.machines['dut']['mac0']),
            'sudo ip link set dev macsec0 up',
            'sudo ifconfig macsec0 10.10.12.2/24'
        ], host=self.lkp_hostname)

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**generator_args)
        time.sleep(generator_args['duration'] + 1)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_xstats(0)
        print_dictionary_to_log('show_port_xstats(0):', output)
        log.info(Command(cmd='ip -s macsec show', host=self.lkp_hostname).run())

        assert output['In_decrypted_octets'] > 0
        assert output['rx_errors'] == 0

    def test_macsec_dpdk_linux_huge_packets(self):

        self.pytestpmd.exec_cmd('port stop 0')
        self.pytestpmd.exec_cmd('port stop 1')

        self.pytestpmd.exec_cmd('set macsec offload 0 on encrypt on replay-protect on')
        self.pytestpmd.exec_cmd('set macsec sc rx 0 {} 0'.format(self.machines['lkp']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa rx 0 0 0 1 00112200000000000000000000000000')
        self.pytestpmd.exec_cmd('set macsec sc tx 0 {} 0'.format(self.machines['dut']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa tx 0 0 0 1 00112200000000000000000000000000')
        self.pytestpmd.exec_cmd('set fwd macswap')

        self.pytestpmd.exec_cmd('set promisc all on')

        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 1400,
            'mac_src': '{}'.format(self.machines['lkp']['mac0']),
            'mac_dst': '{}'.format(self.machines['dut']['mac0']),
            'ipv4_src': '10.10.12.2',
            'ipv4_dst': '10.10.12.3',
            'protocol': 'udp'
        }

        args = {
            'packets': Packets(**packets_args),
            'duration': 60
        }

        run_commands([
            'sudo ip a',
            'sudo ip link add link {} macsec0 type macsec encrypt on'.format(self.lkp_ifconfig.get_conn_name()),
            'sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 00112200000000000000000000000000',
            'sudo ip macsec add macsec0 rx address {} port 1'.format(self.machines['dut']['mac0']),
            'sudo ip macsec add macsec0 rx address {} port 1 sa 0 pn 1 on key 00 00112200000000000000000000000000'.format(
                self.machines['dut']['mac0']),
            'sudo ip link set dev macsec0 up',
            'sudo ifconfig macsec0 10.10.12.2/24'
        ], host=self.lkp_hostname)

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**args)
        time.sleep(args['duration'] + 1)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_xstats(0)
        print_dictionary_to_log('show_port_xstats(0):', output)

        assert output['In_decrypted_octets'] > 0
        assert output['rx_errors'] == 0

    def test_macsec_dpdk_linux_replay_protect(self):

        self.pytestpmd.exec_cmd('port stop 0')
        self.pytestpmd.exec_cmd('port stop 1')

        self.pytestpmd.exec_cmd('set macsec offload 0 on encrypt on replay-protect on')
        self.pytestpmd.exec_cmd('set macsec sc rx 0 {} 0'.format(self.machines['lkp']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa rx 0 0 0 1 ffffffffffffffffffffffffffffffff')
        self.pytestpmd.exec_cmd('set macsec sc tx 0 {} 0'.format(self.machines['dut']['mac0']))
        self.pytestpmd.exec_cmd('set macsec sa tx 0 0 0 1 ffffffffffffffffffffffffffffffff')
        self.pytestpmd.exec_cmd('set fwd macswap')

        self.pytestpmd.exec_cmd('set promisc all on')

        self.pytestpmd.exec_cmd('port start all')

        packets_args = {
            'pktsize': 1024,
            'mac_src': '{}'.format(self.machines['lkp']['mac0']),
            'mac_dst': '{}'.format(self.machines['dut']['mac0']),
            'ipv4_src': '10.10.12.3',
            'ipv4_dst': '10.10.12.3',
            'protocol': 'udp',
            'count': 4
        }

        args = {
            'packets': Packets(**packets_args),
            'duration': 35,
            'delay': 0.01
        }

        run_commands([
            'sudo ip a',
            'sudo ip link add link {} macsec0 type macsec encrypt on'.format(self.lkp_ifconfig.get_conn_name()),
            'sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 ffffffffffffffffffffffffffffffff',
            'sudo ip macsec add macsec0 rx address {} port 1'.format(self.machines['dut']['mac0']),
            'sudo ip macsec add macsec0 rx address {} port 1 sa 0 pn 1 on key 00 ffffffffffffffffffffffffffffffff'.format(
                self.machines['dut']['mac0']),
            'sudo ip link set dev macsec0 up',
            'sudo ifconfig macsec0 10.10.12.2/24'
        ], host=self.lkp_hostname)

        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        self.pytestpmd.wait_linkup(0)
        self.pytestpmd.wait_linkup(1)

        self.traffic_generator.start(**args)
        time.sleep(args['duration'] + 1)
        self.traffic_generator.stop()

        output = self.pytestpmd.show_port_xstats(0)
        print_dictionary_to_log('show_port_xstats(0):', output)

        assert output['In_decrypted_octets'] > 0
        # assert output['rx_missed_errors'] == 0
        assert output['rx_errors'] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
