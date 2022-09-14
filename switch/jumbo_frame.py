import os
import sys
import tempfile

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../"))  # TODO: is that needed???
from infra.test_base_swx import TestBaseSwx
from tools.constants import LINK_SPEED_10G, LINK_STATE_UP, LINK_SPEED_AUTO, MTU_16000
from tools.switch_manager import SwitchManager, SWITCH_VENDOR_AQUANTIA_SMBUS
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    os.environ["DUT_PORT"] = "pci36.00.0"
    os.environ["SWX_PORT_1_LKP"] = "at190-ab350:pci38.00.0"
    os.environ["SWX_PORT_2_LKP"] = "at189-b350:pci36.00.0"
    os.environ["SUPPORTED_SPEEDS"] = "10G"
    os.environ["WORKING_DIR"] = tempfile.gettempdir()
    os.environ["TEST"] = "swx_jumbo_frame_test"


class TestSwxJumboFrame(TestBaseSwx):
    DEFAULT_MAX_FRAME_SIZE = 0x600

    @classmethod
    def setup_class(cls):
        super(TestSwxJumboFrame, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.NETMASK_IPV4 = cls.DEFAULT_NETMASK_IPV4

            for swx_port, info in cls.SWX_PORT_TO_LKP_MAP.items():
                cls.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"] = cls.suggest_test_ip_address(
                    cls.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"], cls.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"])
                ifcfg = cls.get_lkp_ifconfig(swx_port)
                ifcfg.set_ip_address(cls.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"], cls.NETMASK_IPV4, None)
                # TODO if using Little Nikki we need to set autoneg on to bring the link up
                # Can be set to 10G when using Felicity only
                ifcfg.set_link_speed(LINK_SPEED_AUTO)
                # ifcfg.set_link_speed(LINK_SPEED_10G)
                ifcfg.set_link_state(LINK_STATE_UP)
                ifcfg.set_mtu(MTU_16000)
                assert ifcfg.wait_link_up() is not None
                # assert ifcfg.wait_link_up() == LINK_SPEED_10G

            cls.swx_mngr = SwitchManager(vendor=SWITCH_VENDOR_AQUANTIA_SMBUS)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        self.swx_mngr.defcfg()

    def configure_max_frame_size(self, port_idx, max_frame_size):
        # port_idx == -1 means all available ports
        for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
            if swx_port == port_idx or port_idx == -1:
                self.swx_mngr.set_max_frame_size(swx_port, max_frame_size)

    def verify_max_frame_size(self, port_idx, max_frame_size):
        # port_idx == -1 means all available ports
        available_ports = self.SWX_PORT_TO_LKP_MAP.keys()
        for swx_port in available_ports:
            if swx_port == port_idx or port_idx == -1:
                for another_swx_port in available_ports:
                    if swx_port == another_swx_port:
                        # Do not ping self to self
                        continue
                    assert self.ping(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                                     self.SWX_PORT_TO_LKP_MAP[another_swx_port]["ipv4_addr"],
                                     number=3,
                                     payload_size=max_frame_size - 42 - 4)  # 42 is len of all headers, 4 is FCS

                    if max_frame_size < 16334:  # We cannot send bigger packet due to maximum MTU
                        assert not self.ping(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                                             self.SWX_PORT_TO_LKP_MAP[another_swx_port]["ipv4_addr"],
                                             number=3,
                                             payload_size=max_frame_size - 42 - 4 + 1)

    def run_max_frame_size_test(self, max_frame_size):
        self.configure_max_frame_size(-1, max_frame_size)
        self.verify_max_frame_size(-1, max_frame_size)

    # def test_default_max_frame_size(self):
    #     for swx_port in self.SWX_PORT_TO_LKP_MAP.keys():
    #         self.swx_mngr.readreg_msm(0x14, swx_port)
    #     self.verify_max_frame_size(-1, 0x600)

    def test_max_frame_size_1000(self):
        self.run_max_frame_size_test(1000)

    def test_max_frame_size_3000(self):
        self.run_max_frame_size_test(3000)

    def test_max_frame_size_5000(self):
        self.run_max_frame_size_test(5000)

    def test_max_frame_size_9000(self):
        self.run_max_frame_size_test(9000)

    def test_max_frame_size_16333(self):
        self.run_max_frame_size_test(16333)

    def test_max_frame_size_16334(self):
        self.run_max_frame_size_test(16334)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
