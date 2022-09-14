from tools.command import Command
from tools.ops import OpSystem


class ReceiveSegmentCoalescing:
    def __init__(self, dut_hostname, lkp_hostname):
        self.dut_hostname = dut_hostname
        self.lkp_hostname = lkp_hostname
        self.op_sys_dut = OpSystem(host=dut_hostname)
        self.op_sys_lkp = OpSystem(host=lkp_hostname)

    def _run_command(self, cmd):
        if self.op_sys_dut.is_windows():
            if not self.op_sys_dut.is_win7():
                c = Command(cmd=cmd, host=self.dut_hostname)
                c.run()

        if self.op_sys_lkp.is_windows():
            if not self.op_sys_lkp.is_win7():
                c = Command(cmd=cmd, host=self.lkp_hostname)
                c.run()

    def enable(self):
        self._run_command("powershell set-netoffloadglobalsetting -ReceiveSegmentCoalescing Enabled")

    def disable(self):
        self._run_command("powershell set-netoffloadglobalsetting -ReceiveSegmentCoalescing Disabled")
