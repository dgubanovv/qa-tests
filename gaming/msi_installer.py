import os

from tools.command import Command
from tools.log import get_atf_logger

log = get_atf_logger()


class MsiInstaller(object):
    # https://docs.microsoft.com/en-us/windows/desktop/msi/error-codes
    ERROR_SUCCESS = 0
    ERROR_UNKNOWN_PRODUCT = 1605
    ERROR_SUCCESS_REBOOT_REQUIRED = 3010

    def __init__(self, path):
        if not os.path.exists(path):
            raise Exception("File '{}' doesn't exist".format(path))
        self.path = path
        self.cmd_tmpl = "start /wait msiexec /quiet /passive /norestart /{} {}"

    def install(self, logfile=None):
        cmd = self.cmd_tmpl.format("i", self.path)
        if logfile is not None:
            cmd += " /l*vx {}".format(logfile)
        install_cmd = Command(cmd=cmd)
        install_res = install_cmd.run()
        if install_res["returncode"] != MsiInstaller.ERROR_SUCCESS:
            if install_res["returncode"] == MsiInstaller.ERROR_SUCCESS_REBOOT_REQUIRED:
                log.warn("Installer requested reboot for MSI '{}'".format(self.path))
            else:
                raise Exception("Failed to install MSI package '{}'".format(self.path))

    def uninstall(self, logfile=None):
        cmd = self.cmd_tmpl.format("x", self.path)
        if logfile is not None:
            cmd += " /l*vx {}".format(logfile)
        uninstall_cmd = Command(cmd=cmd)
        uninstall_res = uninstall_cmd.run()
        if uninstall_res["returncode"] != MsiInstaller.ERROR_SUCCESS:
            if uninstall_res["returncode"] == MsiInstaller.ERROR_UNKNOWN_PRODUCT:
                log.warn("Product from MSI '{}' wasn't found in the system".format(self.path))
            else:
                raise Exception("Failed to uninstall MSI package '{}'".format(self.path))
