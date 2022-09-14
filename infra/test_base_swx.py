import os

from test_base import TestBase
from tools.atltoolper import AtlTool
from tools.ifconfig import Ifconfig
from tools.utils import get_atf_logger

log = get_atf_logger()


class TestBaseSwx(TestBase):

    MAX_NOF_SWITCH_PORTS = 4

    @classmethod
    def setup_class(cls):
        super(TestBaseSwx, cls).setup_class()

        try:
            cls.SWX_PORT_TO_LKP_MAP = {}
            for i in range(cls.MAX_NOF_SWITCH_PORTS):
                lkp_info = os.environ.get("SWX_PORT_{}_LKP".format(i), None)
                if lkp_info is not None:
                    lkp_hostname, lkp_port = lkp_info.split(":")
                    # Remember port and hostname of each LKP
                    cls.SWX_PORT_TO_LKP_MAP[i] = {"lkp_hostname": lkp_hostname, "lkp_port": lkp_port}

                    # Initialize Ifconfig object for each LKP
                    setattr(cls, "lkp_{}_ifconfig".format(i), Ifconfig(port=lkp_port, host=lkp_hostname))
                    # Initialize AtlTool object for each LKP
                    a = AtlTool(port=lkp_port, host=lkp_hostname)
                    setattr(cls, "lkp_{}_atltool".format(i), a)
                    # Remember MAC address of each LKP
                    cls.SWX_PORT_TO_LKP_MAP[i]["mac_address"] = a.get_mac_address()
                else:
                    log.warning("There is no info about LKP connected to switch port {}".format(i))
        except Exception:
            log.exception("Failed while setting up class")

    @classmethod
    def get_lkp_ifconfig(cls, switch_port):
        return getattr(cls, "lkp_{}_ifconfig".format(switch_port))
