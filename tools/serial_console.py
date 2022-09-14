import os
import time
import timeit

import serial

from tools.utils import get_atf_logger

log = get_atf_logger()

CTRL_C_SYMBOL = "\x03"


class SerialConsole(object):
    def __init__(self, serial_device_name,
                 path_to_console_log="/tmp/console_log.log"):
        self.serial_port = serial.Serial(serial_device_name, 115200, timeout=0)
        log_filename, log_file_extension = os.path.splitext(path_to_console_log)
        if log_file_extension != "":
            self.path_to_console_log = log_filename + time.strftime("_%Y-%m-%d_%H-%M-%S") + log_file_extension
        else:
            self.path_to_console_log = log_filename + time.strftime("_%Y-%m-%d_%H-%M-%S") + ".log"

    def clean_output(self):
        if self.serial_port.inWaiting() > 0:
            self.serial_port.read_all()

    def write_to_serial(self, message):
        self.serial_port.write(message + "\n")
        out = "Message \"" + message + "\" is writed to serial port " + self.serial_port.name
        # log.debug(out)
        return out

    def read_from_serial(self):
        out = ""
        time.sleep(2)
        while self.serial_port.inWaiting() > 0:
            out += self.serial_port.read(1)
        with open(self.path_to_console_log, 'a') as console_log:
            console_log.write(out + "\n")
        # log.debug("read from serial port" + self.serial_port.name + ":\n" + out)
        return out

    def run_in_serial(self, cmd, quiet=0, timeout=20):
        out = ""
        output = ""
        self.write_to_serial("\n")
        self.write_to_serial(cmd)
        max_time = timeit.default_timer() + timeout
        while self.serial_port.inWaiting() == 0 and timeit.default_timer() < max_time:
            time.sleep(0.1)
        if timeit.default_timer() > max_time:
            self.write_to_serial(CTRL_C_SYMBOL)
            out = "Command " + cmd + " exicuting is interrapted by timeout!"
        else:
            while "#" not in output and timeit.default_timer() < max_time:
                output = output + self.read_from_serial()
            if timeit.default_timer() >= max_time:
                self.write_to_serial(CTRL_C_SYMBOL)
                time.sleep(1)
                output = output + self.read_from_serial()
                out = "Command " + cmd + " exicuting is interrapted by timeout! Command output:\n" + output
            out = "Command " + cmd + " exicuted. Command output:\n" + "-" * 80 + "\n" + output + "\n" + "-" * 80
        if quiet == 0:
            log.info(out)
        return out

    def scp_file_from_host(self, host, remote_path, local_path, quiet=0, timeout=20):
        out = ""
        output = ""
        self.write_to_serial("scp aqtest@" + host + ":" + remote_path + " " + local_path)
        max_time = timeit.default_timer() + timeout
        while self.serial_port.inWaiting() == 0 and timeit.default_timer() < max_time:
            time.sleep(0.1)
        if timeit.default_timer() > max_time:
            self.write_to_serial(CTRL_C_SYMBOL)
            out = "SCP FAILED"
        else:
            while "(yes/no)" not in output and timeit.default_timer() < max_time:
                output = output + self.read_from_serial()
            if timeit.default_timer() >= max_time:
                self.write_to_serial(CTRL_C_SYMBOL)
                time.sleep(1)
                output = output + self.read_from_serial()
                out = "SCP FAILED"
            else:
                self.write_to_serial("yes")
                while "password:" not in output and timeit.default_timer() < max_time:
                    output = output + self.read_from_serial()
                if timeit.default_timer() >= max_time:
                    self.write_to_serial(CTRL_C_SYMBOL)
                    time.sleep(1)
                    output = output + self.read_from_serial()
                    out = "SCP FAILED"
                else:
                    self.write_to_serial("aq90#$rt")
                    while "100%" and "#" not in output and timeit.default_timer() < max_time:
                        output = output + self.read_from_serial()
                    if timeit.default_timer() >= max_time:
                        self.write_to_serial(CTRL_C_SYMBOL)
                        time.sleep(1)
                        output = output + self.read_from_serial()
                        out = "SCP FAILED"
                    else:
                        out = "SCP SUCCESS"
        if quiet == 0:
            log.info(out)
        return out

    def scp_dir_from_host(self, host, remote_path, local_path, quiet=0, timeout=20):
        out = ""
        output = ""
        self.write_to_serial("scp -r aqtest@" + host + ":" + remote_path + " " + local_path)
        max_time = timeit.default_timer() + timeout
        while self.serial_port.inWaiting() == 0 and timeit.default_timer() < max_time:
            time.sleep(0.1)
        if timeit.default_timer() > max_time:
            self.write_to_serial(CTRL_C_SYMBOL)
            out = "SCP FAILED"
        else:
            while "(yes/no)" not in output and timeit.default_timer() < max_time:
                output = output + self.read_from_serial()
            if timeit.default_timer() >= max_time:
                self.write_to_serial(CTRL_C_SYMBOL)
                time.sleep(1)
                output = output + self.read_from_serial()
                out = "SCP FAILED"
            else:
                self.write_to_serial("yes")
                while "password:" not in output and time.time() < max_time:
                    output = output + self.read_from_serial()
                if timeit.default_timer() >= max_time:
                    self.write_to_serial(CTRL_C_SYMBOL)
                    time.sleep(1)
                    output = output + self.read_from_serial()
                    out = "SCP FAILED"
                else:
                    self.write_to_serial("aq90#$rt")
                    while "100%" and "#" not in output and timeit.default_timer() < max_time:
                        output = output + self.read_from_serial()
                    if timeit.default_timer() >= max_time:
                        self.write_to_serial(CTRL_C_SYMBOL)
                        time.sleep(1)
                        output = output + self.read_from_serial()
                        out = "SCP FAILED"
                    elif "100%" and "#" not in output:
                        out = "SCP FAILED"
                    else:
                        out = "SCP SUCCESS"
        if quiet == 0:
            log.info(out)
        return out
