import json

from command import Command
from utils import get_atf_logger

log = get_atf_logger()


class Aq_UsbNetAdapter(object):
    CMD_TMPL = "powershell \"(gwmi -Namespace root\\wmi -class Aq_UsbNetAdapter).{} | ConvertTo-Json\""

    def __init__(self, host=None):
        self.host = host

    def _run_cmd(self, cmd):
        res = Command(cmd=cmd, host=self.host, silent=True).run_join(10)
        if res["returncode"] != 0:
            log.error("WMI returned non-0 exit code. Output:\n{}".format("\n".join(res["output"])))
        return res

    def ReadReg8(self, addr):
        cmd = self.CMD_TMPL.format("ReadReg8({:#x})".format(addr))
        res = self._run_cmd(cmd)
        if res["returncode"] != 0:
            raise Exception("Failed to read MAC register using WMI")
        dict = json.loads("\n".join(res["output"]))
        return dict["value"]

    def ReadReg(self, addr, count):
        cmd = self.CMD_TMPL.format("ReadReg({:#x}, {})".format(addr, count))
        res = self._run_cmd(cmd)
        if res["returncode"] != 0:
            raise Exception("Failed to read MAC registers using WMI")
        dict = json.loads("\n".join(res["output"]))
        if dict["byteCount"] != count:
            raise Exception("Actual bytes read = {}, requested = {}".format(dict["byteCount"], count))
        return dict["buffer"]

    def Reinitialize(self, hard):
        cmd = self.CMD_TMPL.format("Reinitialize({})".format(int(hard)))
        res = self._run_cmd(cmd)
        if res["returncode"] != 0:
            raise Exception("Failed to reset datapath using WMI")

    def RestartSerdes(self):
        cmd = self.CMD_TMPL.format("RestartSerdes()")
        res = self._run_cmd(cmd)
        if res["returncode"] != 0:
            raise Exception("Failed to restart serdes using WMI")

    def datapath_soft_reset(self):
        self.Reinitialize(False)

    def datapath_hard_reset(self):
        self.Reinitialize(True)
