from tools.command import Command
from tools.ops import OpSystem


class IPTables:
    def __init__(self, dut_hostname, lkp_hostname):
        self.lkp_hostname = lkp_hostname
        self.dut_hostname = dut_hostname
        self.op_sys_dut = OpSystem(host=dut_hostname)
        self.op_sys_lkp = OpSystem(host=lkp_hostname)

    def clean(self):
        if self.op_sys_dut.is_linux():
            c = Command(cmd='sudo iptables -F && sudo iptables -X && sudo ip6tables -F && sudo ip6tables -X',
                        host=self.dut_hostname)
            c.run()

        if self.op_sys_lkp.is_linux():
            c = Command(cmd='sudo iptables -F && sudo iptables -X && sudo ip6tables -F && sudo ip6tables -X',
                        host=self.lkp_hostname)
            c.run()
