import _winreg
import tempfile
import os

from tools.command import Command
from tools.killer import Killer
from tools.utils import get_url_response


class InstallBrowserException(Exception):
    pass


class Browser(object):
    name = ""

    def __init__(self, name):
        self.name = name

    def run(self, url="", timeout=30):
        return Command(cmd='start {browser} "{url}"'.format(browser=self.name, url=url)).run_join(timeout)

    def kill(self):
        Command(cmd="taskkill /T /IM {}*".format(self.name)).run_join(5)
        Killer().kill(self.name)

    def __del__(self):
        self.kill()


class InternetExplorer(Browser):
    def __init__(self):
        super(InternetExplorer, self).__init__("iexplore")

        # setup msn.com start page in IE registry key to prevent "choose start page" dialog
        hkey = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Internet Explorer\Main", 0,
                               _winreg.KEY_SET_VALUE)
        _winreg.SetValueEx(hkey, "Start Page", 0, _winreg.REG_SZ, "http://www.msn.com/")
        _winreg.CloseKey(hkey)


class Edge(Browser):
    def __init__(self):
        super(Edge, self).__init__("microsoft-edge")

    def run(self, url="", timeout=30):
        return Command(cmd='start {browser}:"{url}"'.format(browser=self.name, url=url)).run_join(timeout)

    def kill(self):
        Command(cmd="taskkill /T /IM MicrosoftEdge*").run_join(5)
        Killer().kill("MicrosoftEdge")


class InstallableBrowser(Browser):
    repo_url = "http://qa-nfs01.rdc-lab.marvell.com/qa/testing/browsers/"

    def __init__(self, name, installer_file, arguments):
        super(InstallableBrowser, self).__init__(name)

        self.installer_file = installer_file
        self.install_arguments = arguments

        if self.run(timeout=5)["returncode"] != 0:
            self._install()
        self.kill()

    @staticmethod
    def _download_installer(src):
        tempdir = tempfile.gettempdir()
        installer_path = os.path.join(tempdir, os.path.basename(src))

        content = get_url_response(src)
        with open(installer_path, "wb") as f:
            f.write(content)

        return installer_path

    def _install(self):
        installer_path = self._download_installer(self.repo_url + self.installer_file)

        cmd = 'start "installing {name}" /wait "{installer}" {args}'.format(
            name=self.name, installer=installer_path, args=self.install_arguments)

        if Command(cmd=cmd).run_join(200)["returncode"] != 0:
            raise InstallBrowserException("cannot install {}".format(self.name))


class Chrome(InstallableBrowser):
    def __init__(self):
        super(Chrome, self).__init__("chrome", "ChromeSetup.exe", "/silent /install")


class Firefox(InstallableBrowser):
    def __init__(self):
        super(Firefox, self).__init__("firefox", "Firefox Setup 63.0.3.exe", "-ms")


class Opera(InstallableBrowser):
    def __init__(self):
        super(Opera, self).__init__("opera", "Opera_57.0.3098.87_Setup_x64.exe", "/silent")

    def run(self, url="", timeout=30):
        launcher = "%appdata%\..\Local\programs\Opera\launcher.exe"
        return Command(cmd='start {launcher} "{url}"'.format(launcher=launcher, url=url)).run_join(timeout)


class Yandex(InstallableBrowser):
    def __init__(self):
        super(Yandex, self).__init__("browser", "Yandex.exe", "/silent")
