
if __package__ is None:
    import sys
    from os import path

    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from tools.command import Command
from tools.log import get_atf_logger

log = get_atf_logger()


def run_commands(cmds, host=None, timeout=180, skip_fail=False):
    log.info('run commands: {}'.format('\n'.join(cmds)))
    for cmd in cmds:
        if cmd != '':
            command = Command(cmd=cmd, host=host)
            result = command.run_join(timeout)
            if skip_fail == False:
                assert result['returncode'] == 0, 'Fail to execute: {}'.format(cmd)


class ModuleTestPMD(object):
    def __init__(self, host, ports):
        self.ports = ports
        self.host = host
        self.ft = True

    def exec_cmds(self, cmds):
        log.info('run commands: {}'.format('\n'.join(cmds)))
        for cmd in cmds:
            self.exec_cmd(cmd)

    def __getattr__(self, item):

        if self.ft:
            print ('ModuleTestPMD.' + str(item))

            commands = [
                'sudo rmmod atlantic',
                'sudo modprobe uio_pci_generic',
                'cd /home/aqtest/dpdk_ninja && sudo ./usertools/dpdk-devbind.py --bind=uio_pci_generic {}'.
                    format(" ".join(self.ports))
            ]
            run_commands(commands, host=self.host, skip_fail=True)

            import sys
            sys.path.append('/home/aqtest/dpdk_ninja/build_meson/app/')
            import libpytestpmd
            self.pytestpmd = libpytestpmd

            #for port_name in self.ports:
            #    self.pytestpmd.exec_cmd("port attach {}".format(port_name))

            self.ft = False

        return getattr(self.pytestpmd, item)
