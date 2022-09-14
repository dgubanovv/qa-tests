import time
import threading
import argparse
import sys
import socket
from abc import abstractmethod, ABCMeta

import serial.tools.list_ports
import serial

from constants import ATF_TOOLS_DIR
from utils import get_atf_logger
from command import Command

SCRIPT_STATUS_SUCCESS = "[UART-SUCCESS]"
SCRIPT_STATUS_FAILED = "[UART-FAILED]"

log = get_atf_logger()


class Uart(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(UartLocal)
        else:
            return object.__new__(UartRemote)

    def __init__(self, **kwargs):
        self.rate = kwargs.get("rate", 57600)

    @abstractmethod
    def run_async(self):
        pass

    @abstractmethod
    def join(self):
        pass


class UartLocal(Uart):
    def __init__(self, **kwargs):
        super(UartLocal, self).__init__(**kwargs)
        self.port = kwargs.get("port", self.get_port())
        self.remote_exec = False
        self.data = []

        Command(cmd="sudo chmod 666 {}".format(self.port)).run_join(5)

    def get_port(self):
        ports = serial.tools.list_ports.comports()
        for p in ports:
            if "USB Serial Port" in p.description or "FT232R USB UART" in p.description:
                return p.device

        raise Exception("No UART is connected")

    def _start_log(self):
        log.info("Starting UART thread")
        if not self.remote_exec:
            self.go = True
            action_to_stop = self.go
        else:
            action_to_stop = True

        try:
            ser = serial.Serial(self.port, self.rate, timeout=2)
        except Exception as e:
            if "could not open port" in str(e):
                log.error("Port is not opened, no data will be captured")
                return

        try:
            while action_to_stop:
                size = ser.inWaiting()
                if size:
                    data = ser.read(size)
                    if self.remote_exec:
                        sys.stdout.write(data.rstrip())
                        sys.stdout.flush()
                    else:
                        self.data.append(data.rstrip())
                else:
                    time.sleep(0.5)

                if not self.remote_exec:
                    action_to_stop = self.go

        except Exception as e:
            log.error("UART error: \n{}".format(e))

    def run_async(self):
        self.t = threading.Thread(target=self._start_log, args=())
        self.t.daemon = True
        self.t.start()

    def join(self):
        log.info("Stopping UART thread")
        self.go = False
        time.sleep(2)
        self.t.join()

        if len(self.data) == 0:
            log.warning("No data captured")

        return self.data


class UartArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error(SCRIPT_STATUS_FAILED)
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


class UartRemote(Uart):
    def __init__(self, **kwargs):
        super(UartRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.cmd_start = "cd {} && python uart.py ".format(ATF_TOOLS_DIR)

    def run_async(self):
        cmd = self.cmd_start + "-c run"
        self.cmd_obj = Command(cmd=cmd, host=self.host, silent=True)
        self.cmd_obj.run_async()

    def join(self):
        res = self.cmd_obj.join(timeout=0)
        return res["output"]


if __name__ == "__main__":
    parser = UartArgumentParser()
    parser.add_argument("-c", "--command", help="Command to be performed",
                        choices=["run"],
                        type=str, required=True)
    args = parser.parse_args()

    try:
        uart = Uart()

        if args.command == "run":
            uart.remote_exec = True
            uart._start_log()

    except Exception as e:
        log.exception("UART failed")
        log.error(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
