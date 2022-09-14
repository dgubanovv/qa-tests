from queue import Queue
import os
import re
import subprocess
import socket
import sys
import threading
import time
import timeit
import uuid

from killable_process.killableprocess import Popen
from constants import WIN_OSES
from log import get_atf_logger

log = get_atf_logger()


class Priority(object):
    REALTIME = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


LINUX_PRIORITY = {
    Priority.REALTIME: 'sudo nice -n -18 ',
    Priority.HIGH: 'sudo nice -n -5 ',
    Priority.NORMAL: '',
    Priority.LOW: 'nice -n 19 '
}

WINDOWS_PRIORITY = {
    Priority.REALTIME: 'start /b /realtime ',
    Priority.HIGH: 'start /b /high ',
    Priority.NORMAL: '',
    Priority.LOW: 'start /b /low '
}


class Command(object):
    REASON_NONE = -1
    REASON_OK = 0
    REASON_TIMEOUT = 1
    REASON_FAIL = 2
    DEFAULT_SSH_CONNECTION_TIMEOUT = 10

    def _get_remote_os(self):
        os_name = sys.platform
        if self.host not in [None, "localhost", socket.gethostname()]:
            cmd = "ssh {} aqtest@{} 'bash {}'".format(self.ssh_options, self.host,
                                                      'python -c "import sys; print sys.platform"')
            self._run_worker(cmd=cmd)
            os_name = self.result["output"]

        return 'win' if 'win' in os_name else 'linux'

    def __init__(self, **kwargs):
        self.cmd = kwargs["cmd"]
        self.host = kwargs.get("host", None)
        if self.host in [None, "localhost", socket.gethostname()] and os.environ["ATF_OS"] in WIN_OSES:
            # If localhost and Windows remove sudo usage
            if "sudo " in self.cmd:
                log.info("Removing sudo usage on Windows from command '{}'".format(self.cmd))
                self.cmd = self.cmd.replace("sudo ", "")
                log.info("New command is '{}'".format(self.cmd))
        self.silent = kwargs.get("silent", False)
        self.priority = kwargs.get("priority", Priority.NORMAL)
        self.live_output = kwargs.get("live_output", False)
        if self.live_output:
            self.silent = True
        self.ssh_connection_timeout = kwargs.get("ssh_connection_timeout", self.DEFAULT_SSH_CONNECTION_TIMEOUT)
        self.ssh_options = "-o \"StrictHostKeyChecking no\" -o \"ConnectTimeout {}\"".format(
            self.ssh_connection_timeout)
        self.output = Queue.Queue()
        self.result = {"output": None, "returncode": None, "reason": self.REASON_NONE}

        # processing cmd
        if self.host is not None:
            self.cmd = self.cmd.replace("&&", ";")
        if self.priority != Priority.NORMAL:
            self.PRIORITY_OS = WINDOWS_PRIORITY if 'win' in self._get_remote_os() else LINUX_PRIORITY
            self.cmd = self.PRIORITY_OS[self.priority] + self.cmd

        if self.host not in [None, "localhost", socket.gethostname()]:
            if "'" in self.cmd or "\"" in self.cmd:
                self.remote_bash_fname = self._prepare_remote_bash_file(self.cmd)
                additional = ""
                if "freebsd" in sys.platform:
                    additional = "--login"
                self.exec_cmd = "ssh {} aqtest@{} 'bash {} {}'".format(self.ssh_options, self.host, additional,
                                                                       self.remote_bash_fname)
            else:
                if "freebsd" in sys.platform and not self.cmd.startswith('bash'):
                    self.cmd = "bash --login -c \"{}\"".format(self.cmd)
                self.exec_cmd = "ssh {} aqtest@{} '{}'".format(self.ssh_options, self.host, self.cmd)

        else:
            self.exec_cmd = self.cmd

    def _check_callbacks(self, line, output_callbacks=None):
        if output_callbacks is not None:
            for pattern, func in output_callbacks:
                if pattern in line:
                    log.info("Called callback {} on pattern '{}'".format(func, pattern))
                    func(pattern)

    def _enqueue_output(self, stdout, stderr, output_callbacks=None):
        try:
            for line in iter(stdout.readline, ''):
                if "Permanently added" in line and "to the list of known hosts" in line:
                    continue
                if "Last login:" in line:
                    continue

                self._check_callbacks(line, output_callbacks)

                self.output.put(line.rstrip())

                if self.live_output:
                    log.info(line.rstrip())

        except Exception:
            pass

    def _prepare_remote_bash_file(self, cmd):
        file_name = str(uuid.uuid4()) + ".sh"
        with open(file_name, "w") as f:
            f.write(cmd)
        scp_cmd = "scp {} aqtest@{}:~/".format(file_name, self.host)
        log.info("Running command '{}' on localhost".format(scp_cmd))
        subprocess.check_output(scp_cmd, shell=True)
        rm_cmd = "rm -f {}".format(file_name)
        log.info("Running command '{}' on localhost".format(rm_cmd))
        subprocess.check_output(rm_cmd, shell=True)
        return file_name

    def _run_async(self, cmd, output_callbacks=None):
        self.proc = Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        self.log_thread = threading.Thread(target=self._enqueue_output, args=(self.proc.stdout,
                                                                              self.proc.stderr, output_callbacks))
        self.log_thread.daemon = True
        self.log_thread.start()
        self.result = {"output": [], "returncode": None, "reason": None}

    def _join(self, timeout=None):
        if self.proc is None:
            return self.result
        else:
            start_time = timeit.default_timer()
            killed = False

            while self.proc.poll() is None:
                if timeout is not None and timeit.default_timer() - start_time > timeout:
                    # We use wait instead of kill here because wait has specific implementation in killable process
                    self.proc.wait(timeout=0)
                    killed = True
                    log.warning("Command '{}' timeout({}), killing it".format(self.cmd, timeout))
                time.sleep(0.5)

            self.log_thread.join(120)

            self.result["returncode"] = self.proc.returncode
            self.result["reason"] = self.REASON_OK if killed is False else self.REASON_TIMEOUT

            while not self.output.empty():
                self.result["output"].append(self.output.get())

            self.proc = None
            self.log_thread = None

            log.info("Command '{}' on {} is ended, return code {}, reason {}".format(
                self.cmd,
                "localhost" if self.host is None else self.host,
                self.result["returncode"],
                self.result["reason"]))

            if self.silent is False:
                log.debug("Command output:")
                if self.host not in [None, "localhost", socket.gethostname()]:
                    log.debug("\n    ".join(["", "-" * 80] + self.result["output"] + ["-" * 80]))
                else:
                    log.debug("\n".join(["", "-" * 80] + self.result["output"] + ["-" * 80]))

            if self.host is not None and hasattr(self, "remote_bash_fname"):
                rm_cmd = "ssh -o \"StrictHostKeyChecking no\" aqtest@{} 'rm -f {}'".format(self.host,
                                                                                           self.remote_bash_fname)
                log.info("Running command '{}' on localhost".format(rm_cmd))
                subprocess.check_output(rm_cmd, shell=True)

            for line in self.result["output"]:
                if "'sudo' is not recognized" in line:
                    log.warning("!!! DEBUGGING SUDO !!!")

                    for check_cmd in ["set", "env", "where sudo", "sudo ololo", "sudo atltool -h"]:
                        if self.host is not None:
                            ccmd = "ssh -o \"StrictHostKeyChecking no\" aqtest@{} '{}'".format(self.host, check_cmd)
                        else:
                            ccmd = check_cmd
                        log.warning("Running '{}'".format(ccmd))
                        log.warning(">>>> =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
                        proc = subprocess.Popen(ccmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        stdout, stderr = proc.communicate()
                        log.warning("STDOUT:")
                        for line in stdout.splitlines():
                            log.warning(line)
                        log.warning("STDERR:")
                        for line in stderr.splitlines():
                            log.warning(line)
                        log.warning("<<<< =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
                    if sys.platform == "win32":
                        try:
                            import winreg
                        except ImportError:
                            import _winreg as winreg

                        path = r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
                        hklm = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                        key = winreg.OpenKey(hklm, path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
                        value = winreg.QueryValueEx(key, "Path")[0]
                        log.info("WINREG {}".format(value))
                    break

        return self.result

    def _run_worker(self, cmd, output_callbacks=None):
        self._run_async(cmd, output_callbacks=output_callbacks)
        return self._join()

    def run(self, output_callbacks=None):
        log.info("Running '{}' command on {} synchronously".format(self.cmd,
                                                                   "localhost" if self.host is None else self.host))

        self.result = self._run_worker(self.exec_cmd, output_callbacks)

        if sys.platform == "win32" and len(self.result["output"]) > 0 and \
                "Connection timed out" in self.result["output"][0] and \
                self.host not in [None, "localhost", socket.gethostname()]:
            log.info("Command '{}' on {} is ended, return code {}, reason {}, retrying after DNS flush".format(
                self.cmd,
                "localhost" if self.host is None else self.host,
                self.result["returncode"],
                self.result["reason"]))

            # Try flush DNS cache and one more time
            dns_cmd = "ipconfig /flushdns"
            log.info("Running command '{}' on localhost".format(dns_cmd))
            subprocess.check_output(dns_cmd, shell=True, stderr=subprocess.STDOUT)

            try:
                output = subprocess.check_output("ping {}".format(self.host), shell=True, stderr=subprocess.STDOUT)
                log.debug(output)
            except subprocess.CalledProcessError as e:
                log.debug(e.output)
            log.debug("Resolved hostname: {}".format(socket.gethostbyname(self.host)))

            self.output = Queue.Queue()
            # try again
            self.result = self._run_worker(self.exec_cmd, output_callbacks)

        return self.result

    def run_async(self, output_callbacks=None):
        log.info("Running '{}' command on {} asynchronously".format(self.cmd,
                                                                    "localhost" if self.host is None else self.host))
        self._run_async(self.exec_cmd, output_callbacks=output_callbacks)

    def join(self, timeout=None):
        return self._join(timeout=timeout)

    def run_join(self, timeout=None):
        self.run_async()
        return self.join(timeout)

    def wait(self, timeout=None):
        return self.run_join(timeout=timeout)

    def send_stdin(self, queue):
        """
        Sending messages from queue and make pauses between messages

        :param queue is a list of dicts with command and pauses where command is a string, pause is a number
        Example of queue: [{'pause': 10, 'command': '%message1%'}, {'pause': 5, 'command': 'message2'}]
        """
        log.info("Sending messages from queue {} to stdin...".format(queue))
        for item in queue:
            log.info("Writing {} to stdin...".format(item["command"].rstrip()))
            self.proc.stdin.write(item["command"])
            time.sleep(item["pause"])
        log.info("Stop sending to stdin.")


class CommandRemoteQnx(Command):
    def __init__(self, **kwargs):
        super(CommandRemoteQnx, self).__init__(**kwargs)
        self.host = self.host[3:]  # remove "qnx" at the beginning

        # This part of code refactors all command call that use qa-tests's python scripts
        # It replaces "cd qa-tests/tools" to "cd /tmp"
        # And calls sh scripts instead of python with the same parameters
        re_cmd_hack = re.compile(".*cd qa-tests/tools && python ([a-zA-Z0-9]+)\.py.*", re.DOTALL)
        m = re_cmd_hack.match(self.cmd)
        if m is not None:
            script_name = m.group(1)
            re_cmd_hack = re.compile(".*.py (.*)", re.DOTALL)
            params = re_cmd_hack.match(self.cmd).group(1)
            self.cmd = "cd /tmp && sh {}.sh {}".format(script_name, params)
