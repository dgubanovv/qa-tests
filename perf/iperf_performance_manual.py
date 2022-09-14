import argparse
import os
import sys
import numpy

from iperf import Iperf
from iperf_result import IperfResult
from tools.cpu_monitor import CPUMonitor
from tools.iptables import IPTables
from tools.lom import LightsOutManagement
from tools.receive_segment_coalescing import ReceiveSegmentCoalescing

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

from tools.ops import OpSystem
from tools.ifconfig import Ifconfig
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G
from tools.constants import LINK_SPEED_AUTO, DIRECTION_RX, DIRECTION_TX, DIRECTION_RXTX
from tools.utils import get_atf_logger
from tools.killer import Killer

log = get_atf_logger()

# CONSTANTS
LINK_SPEED_DIC = {
    LINK_SPEED_100M: 100,
    LINK_SPEED_1G: 1000,
    LINK_SPEED_2_5G: 2500,
    LINK_SPEED_5G: 5000,
    LINK_SPEED_10G: 10000
}
SPEEDS = [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]

TRIES = 5
MTUS = [1500, 9000]
NETMASK = '255.255.255.0'

# EDIT THESE LINES
DUT_PORT = "pci193.00.0"
LKP_PORT = "pci193.00.0"

args = {
    'direction': DIRECTION_RX,
    'speed': LINK_SPEED_AUTO,
    'num_threads': 2,
    'num_process': 1,
    'time': 10,
    'ipv': 4,
    'buffer_len': 0,
    'window': 0,
    'is_udp': False,
    'is_eee': False,
    'is_ptp': False,
    'bandwidth': 0,
    'criterion': IperfResult.SANITY,

    'dut': 'mm07',
    'dut4': '192.168.0.218',

    'lkp': 'mm08',
    'lkp4': '192.168.0.219',
}


def run_iperf():
    Killer(host=args['dut']).kill("iperf3")
    Killer(host=args['lkp']).kill("iperf3")

    cpu_monitor = CPUMonitor()

    for t in range(TRIES):
        cpu_monitor.run_async()
        iperf = Iperf(**args)
        result = iperf.run()

        cpu_monitor.join(timeout=1)

        if result != Iperf.IPERF_OK:
            continue

        results = iperf.get_performance()
        cpu_avg = cpu_monitor.get_metric()[4]
        return results, cpu_avg

    raise Exception('{}/{} tryies to run iperf and all are failed'.format(TRIES, TRIES))


def report(results, protocol):
    fmt_tcp = "MTU = {:4},    RX = {:6.1f} Mbits/sec CPU:{:5.1f}%,    TX = {:6.1f} Mbits/sec CPU:{:5.1f}%, \
               RXTX = {:6.1f}/{:6.1f} Mbits/sec CPU:{:5.1f}%"

    fmt_udp = "\nMTU = {:4},    RX = {:6.1f} ({:3.1f}%) Mbits/sec                       CPU:{:3.1f}% \n" \
              "               TX = {:6.1f} ({:3.1f}%) Mbits/sec                         CPU:{:3.1f}% \n" \
              "             RXTX = {:6.1f} ({:3.1f}%) / {:6.1f} ({:3.1f}%) Mbits/sec    CPU:{:3.1f}% \n"

    for speed, data in results.items():
        log.info("\nResults for {}    speed: {}".format(protocol.upper(), speed))
        for mtu, perf in data.items():
            if args['is_udp']:
                log.info(fmt_udp.format(mtu,
                                        perf[DIRECTION_RX][0][0], perf[DIRECTION_RX][0][1], perf[DIRECTION_RX][1],
                                        perf[DIRECTION_TX][0][0], perf[DIRECTION_TX][0][1], perf[DIRECTION_TX][1],
                                        perf[DIRECTION_RXTX][0][0], perf[DIRECTION_RXTX][0][2],
                                        perf[DIRECTION_RXTX][0][1], perf[DIRECTION_RXTX][0][3],
                                        perf[DIRECTION_RXTX][1]))
            else:
                log.info(fmt_tcp.format(mtu,
                                        (perf[DIRECTION_RX][0]), (perf[DIRECTION_RX][1]),
                                        (perf[DIRECTION_TX][0]), (perf[DIRECTION_TX][1]),
                                        (perf[DIRECTION_RXTX][0][0]), (perf[DIRECTION_RXTX][0][1]),
                                        (perf[DIRECTION_RXTX][1])))


def run_benchmark(input_args):
    # tune config
    args['is_udp'] = True if input_args.protocol == 'udp' else False
    if OpSystem().is_mac():
        args.update({'window': '512k'})

    # setup
    ReceiveSegmentCoalescing(dut_hostname=args['dut'], lkp_hostname=args['lkp']).enable()
    iptables = IPTables(dut_hostname=None, lkp_hostname=args['lkp'])
    iptables.clean()

    dut_ifconfig = Ifconfig(port=DUT_PORT)
    lkp_ifconfig = Ifconfig(port=LKP_PORT, host=args['lkp'])

    dut_ifconfig.set_ip_address(args['dut4'], NETMASK, None)
    lkp_ifconfig.set_ip_address(args['lkp4'], NETMASK, None)

    results = {}
    for speed in SPEEDS:
        results[speed] = {}
        for mtu in MTUS:
            results[speed][mtu] = {}

    # run tests
    for speed in SPEEDS:
        dut_ifconfig.set_link_speed(speed)
        lkp_ifconfig.set_link_speed(speed)

        for mtu in MTUS:
            dut_ifconfig.set_mtu(mtu)
            lkp_ifconfig.set_mtu(mtu)

            assert dut_ifconfig.wait_link_up() == speed
            assert lkp_ifconfig.wait_link_up() == speed

            if input_args.lom is not None:
                dut_lom_cntrl = LightsOutManagement(port=DUT_PORT)
                lkp_lom_cntrl = LightsOutManagement(port=LKP_PORT, host=args['lkp'])
                if input_args.lom == 'True':
                    dut_lom_cntrl.LoM_enable()
                    lkp_lom_cntrl.LoM_enable()
                elif input_args.lom == 'False':
                    dut_lom_cntrl.LoM_disable()
                    lkp_lom_cntrl.LoM_disable()

            if args['is_udp']:
                if OpSystem().is_mac():
                    # Packet length for MacOS performance setups
                    args['buffer_len'] = 15000 if mtu == 1500 else 25000
                else:
                    # Packet length for other OS performance setups
                    args['buffer_len'] = 8192 if mtu == 1500 else 1450
                b_dict = {LINK_SPEED_10G: '9950', LINK_SPEED_5G: '4950', LINK_SPEED_2_5G: '2495',
                          LINK_SPEED_1G: '995', LINK_SPEED_100M: '99'}
                args.update({'bandwidth': b_dict[speed]})
            args['speed'] = speed

            # rx
            args['direction'] = DIRECTION_RX
            rx_results = []
            rx_cpu_results = []
            for i in range(input_args.count):
                rx_res, cpu_usg = run_iperf()
                if args['is_udp']:
                    rx_results.append((numpy.average(rx_res[0].bandwidth[2:-2]), numpy.average(rx_res[0].lost[2:-2])))
                else:
                    rx_results.append(numpy.average(rx_res[0].bandwidth[2:-2]))
                rx_cpu_results.append(cpu_usg)

            ind = rx_results.index(max(rx_results))
            results[speed][mtu][DIRECTION_RX] = (rx_results[ind], rx_cpu_results[ind])

            args['direction'] = DIRECTION_TX
            tx_results = []
            tx_cpu_results = []
            for i in range(input_args.count):
                tx_res, cpu_usg = run_iperf()
                if args['is_udp']:
                    tx_results.append((numpy.average(tx_res[0].bandwidth[2:-2]), numpy.average(tx_res[0].lost[2:-2])))
                else:
                    tx_results.append(numpy.average(tx_res[0].bandwidth[2:-2]))
                tx_cpu_results.append(cpu_usg)

            ind = tx_results.index(max(tx_results))
            results[speed][mtu][DIRECTION_TX] = (tx_results[ind], tx_cpu_results[ind])

            args['direction'] = DIRECTION_RXTX
            rxtx_results = []
            rxtx_cpu_results = []
            for i in range(input_args.count):
                rxtx_res, cpu_usg = run_iperf()
                if args['is_udp']:
                    rxtx_results.append((numpy.average(rxtx_res[0].bandwidth[2:-2]),
                                         numpy.average(rxtx_res[1].bandwidth[2:-2]),
                                         numpy.average(rxtx_res[0].lost[2:-2]),
                                         numpy.average(rxtx_res[1].lost[2:-2])))
                else:
                    rxtx_results.append(
                        (numpy.average(rxtx_res[0].bandwidth[2:-2]), numpy.average(rxtx_res[1].bandwidth[2:-2])))

                rxtx_cpu_results.append(cpu_usg)

            max_val = rxtx_results[0][0] + rxtx_results[0][1]
            max_i = 0
            for i in range(1, len(rxtx_results)):
                if rxtx_results[i][0] + rxtx_results[i][1] > max_val:
                    max_val = rxtx_results[i][0] + rxtx_results[i][1]
                    max_i = i

            results[speed][mtu][DIRECTION_RXTX] = (rxtx_results[max_i], rxtx_cpu_results[max_i])

    report(results, input_args.protocol)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='Iperf performance')
    parser.add_argument('--protocol', default='tcp', choices=['tcp', 'udp'])
    parser.add_argument('--count', type=int, default=3, help='amount of run iperf')
    parser.add_argument('--lom', default=None, choices=['True', 'False'])
    input_args = parser.parse_args()
    run_benchmark(input_args)
