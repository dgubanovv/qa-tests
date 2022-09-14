import argparse
import sys
import time
import traceback

from atltoolper import AtlTool
from constants import VENDOR_AQUANTIA
from driver import Driver
from utils import get_atf_logger

SCRIPT_STATUS_SUCCESS = "[KICKSTART-SUCCESS]"
SCRIPT_STATUS_FAILED = "[KICKSTART-FAILED]"

log = get_atf_logger()


def kickstart(pci_port, reload_phy, drv_uninstall):
    drv = Driver(port=pci_port, drv_type="diag", version="latest")
    drv.install()

    if drv.vendor != VENDOR_AQUANTIA:
        raise Exception("Cannot burn kicktart non-Aquantia device")

    atltool_wrapper = AtlTool(port=pci_port)
    atltool_wrapper.kickstart(reload_phy_fw=reload_phy)

    if drv_uninstall:
        drv.uninstall(ignore_remove_errors=True)
    time.sleep(5)


class KickstartArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error("\n{}\n".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = KickstartArgumentParser()
    parser.add_argument("-p", "--port", help="PCI port, i.e. pci1.00.0, ...", required=True, type=str)
    parser.add_argument("--phy", help="Kickstart PHY", choices=["True", "False"], default="True")
    parser.add_argument("--drv_uninstall", help="Try to uninstall any driver", choices=["True", "False"],
                        default="True")
    args = parser.parse_args()
    args.phy = True if args.phy == "True" else False
    args.drv_uninstall = True if args.drv_uninstall == 'True' else False

    try:
        kickstart(args.port, args.phy, args.drv_uninstall)
    except Exception:
        traceback.print_exc(limit=10, file=sys.stderr)
        exit(SCRIPT_STATUS_FAILED)

    log.info(SCRIPT_STATUS_SUCCESS)
