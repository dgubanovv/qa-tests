from tools import ifconfig
from tools.command import Command
from tools.ops import OpSystem


class PTP:
    def __init__(self, dut_hostname, dut_port, lkp_hostname, lkp_port):

        self.dut_hostname = dut_hostname
        self.lkp_hostname = lkp_hostname

        self.dut_ifconfig = ifconfig.Ifconfig(port=dut_port, host=dut_hostname)
        self.lkp_ifconfig = ifconfig.Ifconfig(port=lkp_port, host=lkp_hostname)

        self.op_sys_dut = OpSystem(host=dut_hostname)
        self.op_sys_lkp = OpSystem(host=lkp_hostname)

    def enable(self):
        if self.op_sys_dut.is_mac():
            dut_eth_name = self.dut_ifconfig.get_conn_name()
            lkp_eth_name = self.lkp_ifconfig.get_conn_name()

            command = 'echo "domain add link {}" | /dos/qa/macos/timesyncutil'

            self.command_timesync_dut = Command(cmd=command.format(dut_eth_name), host=self.dut_hostname)
            self.command_timesync_dut.run_async()

            self.command_timesync_lkp = Command(cmd=command.format(lkp_eth_name), host=self.lkp_hostname)
            self.command_timesync_lkp.run_async()

    def disable(self):
        if self.op_sys_dut.is_mac():
            self.command_timesync_dut.join(timeout=1)
            self.command_timesync_lkp.join(timeout=1)
