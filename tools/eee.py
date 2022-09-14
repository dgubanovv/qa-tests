import time

from constants import LINK_STATE_DOWN, LINK_STATE_UP
from tools import ifconfig
from tools.command import Command
from tools.ops import OpSystem


class EEE:
    ALL = 0
    DUT = 1
    LKP = 2

    def __init__(self, dut_hostname, dut_port, lkp_hostname, lkp_port):

        self.dut_ifconfig = ifconfig.Ifconfig(port=dut_port, host=dut_hostname)
        self.lkp_ifconfig = ifconfig.Ifconfig(port=lkp_port, host=lkp_hostname)

        self.op_sys_dut = OpSystem(host=dut_hostname)
        self.op_sys_lkp = OpSystem(host=lkp_hostname)

    def enable(self, c=ALL):
        media_opts = ["full-duplex", "flow-control", "energy-efficient-ethernet"]
        command_host = 'sudo sysctl -w net.inet.icmp.icmplim=0'

        if c == EEE.ALL or c == EEE.DUT:
            if self.op_sys_dut.is_mac():
                command_run_host = Command(cmd=command_host, host=self.dut_hostname)
                command_run_host.run()

        if c == EEE.ALL or c == EEE.LKP:
            if self.op_sys_lkp.is_mac():
                command_run_lkp = Command(cmd=command_host, host=self.lkp_hostname)
                command_run_lkp.run()

        if c == EEE.ALL or c == EEE.DUT:
            self.dut_ifconfig.set_media_options(media_opts)
            # self.lkp_ifconfig.set_media_options(media_opts)  # required for Windows case
            self.dut_ifconfig.set_link_state(LINK_STATE_DOWN)

        if c == EEE.ALL or c == EEE.LKP:
            self.lkp_ifconfig.set_media_options(media_opts)  # required for Windows case
            self.lkp_ifconfig.set_link_state(LINK_STATE_DOWN)

        if c == EEE.ALL or c == EEE.DUT:
            self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        if c == EEE.ALL or c == EEE.LKP:
            self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

        if c == EEE.ALL or c == EEE.DUT:
            self.dut_ifconfig.wait_link_up()

        if c == EEE.ALL or c == EEE.LKP:
            self.lkp_ifconfig.wait_link_up()

        self.dut_ifconfig.check_media_options(media_opts)
        self.lkp_ifconfig.check_media_options(media_opts)

    def disable(self, c=ALL):
        media_opts = ["full-duplex"]

        if c == EEE.ALL or c == EEE.DUT:
            self.dut_ifconfig.set_media_options(media_opts)
            # On Buffalo switch sometimes link becomes UP very slow, so we use 300 sec timeout here
            self.dut_ifconfig.wait_link_up(timeout=300, retry_interval=5)
            time.sleep(5)
            self.dut_ifconfig.check_media_options(media_opts)

        if c == EEE.ALL or c == EEE.LKP:
            self.lkp_ifconfig.set_media_options(media_opts)
            # On Buffalo switch sometimes link becomes UP very slow, so we use 300 sec timeout here
            self.lkp_ifconfig.wait_link_up(timeout=300, retry_interval=5)
            time.sleep(5)
            self.lkp_ifconfig.check_media_options(media_opts)

