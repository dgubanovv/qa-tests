import multiprocessing

from tools.command import Command, Priority
from tools.ops import OpSystem

class HeavyLoad(object):
    def __init__(self, **kwargs):
        self.cpu = kwargs.get('cpu', -1)
        self.hdd = kwargs.get('hdd', 0)
        self.io = kwargs.get('io', 0)
        self.vm = kwargs.get('vm', 0)

        self.timeout = kwargs.get('timeout', 0)
        self.host = kwargs.get('host', None)
        self.priority = kwargs.get('priority', Priority.NORMAL)

        self.cpu = multiprocessing.cpu_count() if self.cpu == -1 else self.cpu
        self.hdd = multiprocessing.cpu_count() if self.hdd == -1 else self.hdd
        self.io = multiprocessing.cpu_count() if self.io == -1 else self.io
        self.vm = multiprocessing.cpu_count() if self.vm == -1 else self.vm

        self.ops = OpSystem(host=self.host)


    def run(self, timeout):
        self.run_async()
        self.join(timeout)

    def run_async(self):
        cmd = 'stress'
        cmd += ' --cpu {} '.format(self.cpu) if self.cpu > 0 else ''
        cmd += ' --hdd {} '.format(self.hdd) if self.hdd > 0 else ''
        cmd += ' --io {} '.format(self.io) if self.io > 0 else ''
        cmd += ' --vm {} '.format(self.vm) if self.vm > 0 else ''
        cmd += ' --timeout {} '.format(self.timeout) if self.timeout > 0 else ''

        self.cmd = Command(cmd=cmd, host=self.host, priority=self.priority)
        self.cmd.run_async()

    def join(self, timeout=60):
        self.cmd.join(timeout)
