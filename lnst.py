import os
import re
import pytest
import xml.etree.ElementTree as ET

from tools.command import Command
from tools.lnst_test_base import TestLNSTBase
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "lnst"


class XMLConfig:
    def __init__(self, infile):
        self.tree = ET.parse(infile)
        self.root = self.tree.getroot()

    def replace_define(self, tag, value):
        e = self.root.find(".//alias/[@name='{}']".format(tag))
        e.set('value', str(value))

    def replace_machines(self, machines):
        lst = self.root.findall('.//host')
        for i in range(len(lst)):
            lst[i].set('id', machines[i])

    def remove(self, tag):
        e = self.root.find(".//alias/[@name='{}']".format(tag))
        if e is not None:
            self.root.remove(e)

    def save(self, outfile):
        self.tree.write(outfile)


def copy_config_from_lnst_master(path):
    full_path = os.path.join('/home/aqtest/lnst/', path)
    new_filename = os.path.join('/tmp/', os.path.basename(path))
    cmd = "sudo -u aqtest scp aqtest@lnst-master:{} {}".format(full_path, new_filename)
    res = Command(cmd=cmd).run()
    if res["returncode"] != 0:
        raise Exception("Failed to transfer file")
    return new_filename


def copy_config_to_lnst_master(ifile, ofile):
    cmd = "sudo -u aqtest scp {} aqtest@lnst-master:{}".format(ifile, os.path.join('/home/aqtest/lnst/', ofile))
    res = Command(cmd=cmd).run()
    if res["returncode"] != 0:
        raise Exception("Failed to transfer file")


class TestLNST(TestLNSTBase):

    @classmethod
    def setup_class(cls):
        super(TestLNST, cls).setup_class()

    def _netperf(self, kwargs):
        ipv = 'ipv' + str(kwargs.get('ipv', 4))
        nperf_protocols = kwargs.get('stream', 'tcp')
        pc0, pc1 = self.machines_names[self.machines[0]], self.machines_names[self.machines[1]]
        hosts = [pc0, pc1]

        xml_config = 'recipes/regression_tests/phase1/simple_netperf_{}_{}.xml'.format(pc0, pc1)

        infile = copy_config_from_lnst_master('recipes/regression_tests/phase1/simple_netperf.xml')

        xml = XMLConfig(infile)
        xml.replace_define("ipv", ipv)
        xml.replace_define("nperf_protocols", nperf_protocols)
        xml.remove("driver")
        xml.replace_machines(hosts)
        xml.save(infile)

        copy_config_to_lnst_master(infile, xml_config)

        result = self.run_test(xml_config)

        output = str(result['output'])
        re_fail = re.compile('\s+=+ SUMMARY =+(.*)')

        f_fail = re_fail.findall(output, re.DOTALL)
        log.debug('FAIL_LOG: {}'.format(f_fail))

        if len(f_fail) > 0:
            if len(re.findall('FAIL', f_fail[0], re.DOTALL)) > 0:
                assert False, "Output of the test has FAIL"
        else:
            assert False, "Output is corrupt"


    def test_netperf_ipv4_tcp(self):
        args = {'ipv': 4, 'stream': 'tcp'}
        self._netperf(args)

    def test_netperf_ipv6_tcp(self):
        args = {'ipv': 6, 'stream': 'tcp'}
        self._netperf(args)

    def test_netperf_ipv4_udp(self):
        args = {'ipv': 4, 'stream': 'udp'}
        self._netperf(args)

    def test_netperf_ipv6_udp(self):
        args = {'ipv': 6, 'stream': 'udp'}
        self._netperf(args)

    def test_netperf_ipv4_sctp(self):
        args = {'ipv': 4, 'stream': 'sctp'}
        self._netperf(args)

    def test_netperf_ipv6_sctp(self):
        args = {'ipv': 6, 'stream': 'sctp'}
        self._netperf(args)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
