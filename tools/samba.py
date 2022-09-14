from command import Command
from ops import OpSystem


class Samba(object):
    def __init__(self, host=None):
        self.host = host
        self.ops = OpSystem(host=host)

    def stop(self):
        if self.ops.is_linux():
            res = Command(cmd='sudo service smbd stop', host=self.host).run_join(10)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to stop Samba service")
            res = Command(cmd='sudo service nmbd stop', host=self.host).run_join(10)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to stop Samba NetBios service")
        else:
            pass

    def start(self):
        if self.ops.is_linux():
            res = Command(cmd='sudo service smbd start', host=self.host).run_join(10)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to start Samba service")
            res = Command(cmd='sudo service nmbd start', host=self.host).run_join(10)
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("Failed to start Samba NetBios service")
        else:
            pass
