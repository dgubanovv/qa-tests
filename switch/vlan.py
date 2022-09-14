import os
import pytest
import sys
import tempfile

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../"))  # TODO: is that needed???
from infra.test_base_swx import TestBaseSwx
from scapy.all import *
from tools.utils import get_atf_logger
from tools.constants import LINK_SPEED_AUTO, LINK_STATE_UP
from tools.scapy_tools import ScapyTools
from tools.sniffer import Sniffer
from tools.switch_manager import SwitchManager, SWITCH_VENDOR_AQUANTIA_SMBUS, SWITCH_VENDOR_CISCO
from tools import trafficgen

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


class TestVlan(TestBaseSwx):
    # SNIFF_EXEC_TIME = 10

    @classmethod
    def setup_class(cls):
        super(TestVlan, cls).setup_class()

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

            # cls.scapy_iface_0 = ScapyTools(port=cls.SWX_PORT_TO_LKP_MAP[0]["lkp_port"],
            #                              host=cls.SWX_PORT_TO_LKP_MAP[0]["lkp_hostname"]).get_scapy_iface()
            # cls.scapy_iface_1 = ScapyTools(port=cls.SWX_PORT_TO_LKP_MAP[1]["lkp_port"],
            #                              host=cls.SWX_PORT_TO_LKP_MAP[1]["lkp_hostname"]).get_scapy_iface()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        self.swx_mngr.reset()
        self.swx_mngr.defcfg()
        self.swx_mngr.clear_mac_table()

    def test_untagged_traffic_to_untagged_port(self):
        """Untagged traffic to untagged port"""





if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
