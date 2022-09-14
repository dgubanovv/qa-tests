import os
import time
import pytest


if __package__ is None:
    import sys
    from os import path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))


from infra.test_base import TestBase, idparametrize
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G
from tools.command import Command
from tools.communicate import send_performance_results, PerfRecord
from trafficgen.traffic_gen import Packets

from dpdk_test_base import TestDPDKBase, PATH_TO_CONFIG_TXT, filter_match_get
from tools.utils import get_atf_logger


log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "dpdk-perf"


class TestDPDKPerf(TestDPDKBase):

    @classmethod
    def setup_class(cls):
        super(TestDPDKPerf, cls).setup_class()

    def report(self, name=''):
        log.info('>> REPORT: ----------------------------------------------------------------------- ')
        log.info('>> | {:75s} | '.format(name))
        log.info('>> ------------------------------------------------------------------------------- ')
        log.info('>> |       Packet |      Mpps |              pps | line rate (%) | Bitrate (Mbps)| ')
        log.info('>> ------------------------------------------------------------------------------- ')

        results = []

        gmin = 1 << 31

        for k in sorted(self.reports.keys(), key=lambda x: float(x)):
            ps = int(k)
            pps = max(self.reports[k]) if len(self.reports[k]) > 0 else 0
            mpps = pps / 1000000.0
            bps = ps * pps * 8
            mbps = bps / 1000000.0
            lr = 100.0 * (mbps / 10000.0)
            msg = '>> | {:>12d} | {:9.2f} | {:>16d} | {:13.2f} | {:13.2f} | '.format(ps, mpps, pps, lr, mbps)
            log.info(msg)
            gmin = min(gmin, mbps)

            results.append(PerfRecord('Mbps', mbps, mbps, mbps, 1, 'Performance', '{{"packet_size": {}}}'.format(ps)))
            results.append(PerfRecord('Mpps', mpps, mpps, mpps, 1, 'Performance', '{{"packet_size": {}}}'.format(ps)))

        log.info('>> ------------------------------------------------------------------------------- ')
        name = TestBase.state.current_test if TestBase.state.current_test else "DPDK"
        send_performance_results(results, self.atf_os, self.job_id, name)

        assert gmin > 0, 'Bandwidth must be more 0'

    def test_performance_test_testpmd_multicore(self):
        self.reports = {}

        # generate config
        config = [
            'set verbose 1',
            'set log global 4',
            'set log pmd 4',

            'set portlist 0,1',
            'show config fwd',

            'port stop all',

            'port config all rxq 8',
            'port config all txq 8',

            'set stat_qmap rx 0 0 0',
            'set stat_qmap rx 0 1 1',
            'set stat_qmap rx 0 2 2',
            'set stat_qmap rx 0 3 3',
            'set stat_qmap rx 0 4 4',
            'set stat_qmap rx 0 5 5',
            'set stat_qmap rx 0 6 6',
            'set stat_qmap rx 0 7 7',

            'set stat_qmap tx 0 0 0',
            'set stat_qmap tx 0 1 1',
            'set stat_qmap tx 0 2 2',
            'set stat_qmap tx 0 3 3',
            'set stat_qmap tx 0 4 4',
            'set stat_qmap tx 0 5 5',
            'set stat_qmap tx 0 6 6',
            'set stat_qmap tx 0 7 7',

            'port config 0 rxq 0 ring_size 65535',
            'port config 0 rxq 1 ring_size 65535',
            'port config 0 rxq 2 ring_size 65535',
            'port config 0 rxq 3 ring_size 65535',
            'port config 0 rxq 4 ring_size 65535',
            'port config 0 rxq 5 ring_size 65535',
            'port config 0 rxq 6 ring_size 65535',
            'port config 0 rxq 7 ring_size 65535',

            'port config 0 txq 0 ring_size 65535',
            'port config 0 txq 1 ring_size 65535',
            'port config 0 txq 2 ring_size 65535',
            'port config 0 txq 3 ring_size 65535',
            'port config 0 txq 4 ring_size 65535',
            'port config 0 txq 5 ring_size 65535',
            'port config 0 txq 6 ring_size 65535',
            'port config 0 txq 7 ring_size 65535',

            'port config 1 rxq 0 ring_size 65535',
            'port config 1 rxq 1 ring_size 65535',
            'port config 1 rxq 2 ring_size 65535',
            'port config 1 rxq 3 ring_size 65535',
            'port config 1 rxq 4 ring_size 65535',
            'port config 1 rxq 5 ring_size 65535',
            'port config 1 rxq 6 ring_size 65535',
            'port config 1 rxq 7 ring_size 65535',

            'port config 1 txq 0 ring_size 65535',
            'port config 1 txq 1 ring_size 65535',
            'port config 1 txq 2 ring_size 65535',
            'port config 1 txq 3 ring_size 65535',
            'port config 1 txq 4 ring_size 65535',
            'port config 1 txq 5 ring_size 65535',
            'port config 1 txq 6 ring_size 65535',
            'port config 1 txq 7 ring_size 65535',

            'port config all burst 512',

            'port start 0',
            'port start 1',

            'port config all rss default',

            'set link-up port 0',
            'set link-up port 1',

            'show port info all',

            'set fwd macswap',
            'start'
        ]

        with open(PATH_TO_CONFIG_TXT, 'w') as f:
            for line in config:
                f.write(line + '\n')

        self.public_file(PATH_TO_CONFIG_TXT)

        for ps in self.PACKET_SIZE:
            packets_args = {
                'pktsize': ps
            }

            args = {
                'packets': Packets(**packets_args),
                'duration': 35
            }

            self.traffic_generator.start(**args)

            # run test
            result = self.run_app(command='./app/dpdk-testpmd',
                                  params_pmd = '-l 1-10 -n 4',
                                  params = '--portmask=0xf --nb-cores=8 --stats-period=3 --cmdline-file={}'.format(PATH_TO_CONFIG_TXT),
                                  timeout=35)

            arr = filter_match_get(result['output'], '\s*Rx-pps:\s+(\d+)')[5:-5]
            self.reports[str(ps)] = list(map(lambda x: int(x), arr))
            self.traffic_generator.stop()
            time.sleep(1)

        self.report('Testpmd: multicore (8 cores)')

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_performance_test_testpmd(self, speed):
        self.lkp_ifconfig.set_link_speed(speed)

        self.reports = {}
        for ps in self.PACKET_SIZE:
            packets_args = {
                'pktsize': ps
            }

            args = {
                'packets': Packets(**packets_args),
                'duration': 35
            }

            self.traffic_generator.start(**args)

            # run test
            result = self.run_app(command='./app/dpdk-testpmd',
                                  params_pmd = '-l 5,6 -n 4',
                                  params = '--auto-start --stats-period=3 --portmask=0x3 --txd=2048 --rxd=2048 --txq=2 --rxq=2',
                                  timeout=35)

            arr = filter_match_get(result['output'], '\s*Rx-pps:\s+(\d+)')[5:-5]
            self.reports[str(ps)] = list(map(lambda x: int(x), arr))

            self.traffic_generator.stop()
            time.sleep(1)

        self.report('Testpmd: single cores: {}'.format(speed))


    def test_performance_test_loopback(self):
        self.reports = {}
        for ps in self.PACKET_SIZE:
            packets_args = {
                'pktsize': ps
            }

            args = {
                'packets': Packets(**packets_args),
                'duration': 35
            }

            self.traffic_generator.start(**args)

            result = self.run_app(command='./examples/dpdk-loopback',
                                  params_pmd = '-l 1,2,3,5 -n 2 -w 0000:{} -w 0000:{}'.format(
                                      self.machines['dut']['port0'], self.machines['dut']['port1']),
                                  params='-p 0xf --config="(0,0,1),(0,1,2),(1,0,3),(1,1,5)"',
                                  timeout=35)

            arr = filter_match_get(result['output'], 'rx: (\d+)pps/\d+Mbps tx: \d+pps/\d+Mbps drops: \d+')[5:-5]
            self.reports[str(ps)] = list(map(lambda x: int(x), arr))

            self.traffic_generator.stop()
            time.sleep(1)

        self.report('loopback')


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
