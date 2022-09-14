import os
import pytest
import sys
import tempfile

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../"))  # TODO: is that needed???
from infra.test_base_swx import TestBaseSwx
from tools.constants import DIRECTION_RXTX, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, \
    LINK_SPEED_5G, LINK_SPEED_10G, LINK_SPEED_AUTO, LINK_STATE_UP
from perf.iperf import Iperf
from tools.killer import Killer
from tools.switch_manager import SwitchManager, SWITCH_VENDOR_AQUANTIA_SMBUS
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    os.environ["TEST"] = "switch_mac_learning_table_test"
    os.environ["DUT_PORT"] = "pci1.00.0"
    os.environ["SWX_PORT_0_LKP"] = "at011-rog:pci1.00.0"
    os.environ["SWX_PORT_1_LKP"] = "at151-rog:pci1.00.0"
    os.environ["SWX_PORT_2_LKP"] = "at193-z370:pci1.00.0"
    os.environ["SWX_PORT_3_LKP"] = "at194-z370:pci1.00.0"
    os.environ["SUPPORTED_SPEEDS"] = "10G"
    os.environ["WORKING_DIR"] = tempfile.gettempdir()


class TestEgressShaping(TestBaseSwx):
    IPERF_EXEC_TIME = 10

    @classmethod
    def setup_class(cls):
        super(TestEgressShaping, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.NETMASK_IPV4 = cls.DEFAULT_NETMASK_IPV4

            for swx_port, info in cls.SWX_PORT_TO_LKP_MAP.items():
                cls.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"] = cls.suggest_test_ip_address(
                    cls.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"], cls.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"])
                ifcfg = cls.get_lkp_ifconfig(swx_port)
                ifcfg.set_ip_address(cls.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"], cls.NETMASK_IPV4, None)
                ifcfg.set_link_speed(LINK_SPEED_AUTO)

                ifcfg.set_link_state(LINK_STATE_UP)

                assert ifcfg.wait_link_up() is not None

            cls.swx_mngr = SwitchManager(vendor=SWITCH_VENDOR_AQUANTIA_SMBUS)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        self.swx_mngr.reset()
        self.swx_mngr.defcfg()
        self.swx_mngr.enable_rate_shaper()
        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            Killer(host=self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"]).kill("iperf3")

    def test_default_10g(self):
        """Test default 10 Gbps"""

        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            if swx_port == 0:
                continue
            args = {
                'speed': LINK_SPEED_10G,
                'tolerance': 32,
                'lkp_hostname': self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                'lkp4': self.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"]
            }

            self.common_shaping_test(args)

    def test_5g(self):
        """Test 5 Gbps"""

        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            self.swx_mngr.set_egress_rate(5, swx_port)

        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            if swx_port == 0:
                continue
            args = {
                'speed': LINK_SPEED_5G,
                'tolerance': 10,
                'lkp_hostname': self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                'lkp4': self.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"]
            }

            self.common_shaping_test(args)

    def test_2_5g(self):
        """Test 2.5 Gbps"""

        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            self.swx_mngr.set_egress_rate(2.5, swx_port)

        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            if swx_port == 0:
                continue
            args = {
                'speed': LINK_SPEED_2_5G,
                'tolerance': 10,
                'lkp_hostname': self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                'lkp4': self.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"]
            }

            self.common_shaping_test(args)

    def test_1g(self):
        """Test 1 Gbps"""

        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            self.swx_mngr.set_egress_rate(1, swx_port)

        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            if swx_port == 0:
                continue
            args = {
                'speed': LINK_SPEED_1G,
                'tolerance': 10,
                'lkp_hostname': self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                'lkp4': self.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"]
            }

            self.common_shaping_test(args)

    def test_500m(self):
        """Test 500 Mbps"""

        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            self.swx_mngr.set_egress_rate(0.5, swx_port)

        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            if swx_port == 0:
                continue
            args = {
                'speed': 500,
                'tolerance': 10,
                'lkp_hostname': self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                'lkp4': self.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"]
            }

            self.common_shaping_test(args)

    def test_100m(self):
        """Test 100 Mbps"""

        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            self.swx_mngr.set_egress_rate(0.1, swx_port)

        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            if swx_port == 0:
                continue
            args = {
                'speed': LINK_SPEED_100M,
                'tolerance': 10,
                'lkp_hostname': self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                'lkp4': self.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"]
            }

            self.common_shaping_test(args)

    def common_shaping_test(self, args):
        kwargs = {
            'direction': DIRECTION_RXTX,
            'num_threads': 1,
            'num_process': 4,
            'time': self.IPERF_EXEC_TIME,
            'ipv': 4,
            'buffer_len': 65500,
            'dut4': self.SWX_PORT_TO_LKP_MAP[0]["ipv4_addr"]
        }
        args.update(kwargs)
        iperf = Iperf(**args)
        result = iperf.run()
        assert result == 1


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
