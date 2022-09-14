import multiprocessing
import os
import shutil
import time

import pytest
from scapy.utils import wrpcap

from dpdk_test_base import TestDPDKBase
from tools.command import Command
from tools.sniffer import Sniffer
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


class TestDPDKEEPROM(TestDPDKBase):

    @classmethod
    def setup_class(cls):
        super(TestDPDKEEPROM, cls).setup_class()

    def test_testsute_read_eeprom(self):
        cmd = 'cd /home/aqtest/dpdk_make/examples/ethtool/ethtool-app/build/app && echo "eeprom {} port{}.eeprom" | sudo ./ethtool --'

        command = Command(cmd=cmd.format(3, 3))
        command.run_join(timeout=30)
        ba = []
        with open('/home/aqtest/dpdk_make/examples/ethtool/ethtool-app/build/app/port3.eeprom', 'rb') as f:
            ba = f.read(120)

        vendor_name = ba[20:36]
        log.info('VENDOR: [{}]'.format(vendor_name))
        log.info('ALL DUMP: [{}]'.format(ba))
        assert vendor_name != ''


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
