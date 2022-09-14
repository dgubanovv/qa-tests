import argparse
import socket
import math
import os
import threading
import time
import random
import string

import numpy as np

from abc import ABCMeta, abstractmethod

import brainstem

from brainstem.result import Result
from command import Command
from constants import ATF_TOOLS_DIR
from utils import get_atf_logger

log = get_atf_logger()

SCRIPT_STATUS_SUCCESS = "[USB-CONTROL-SUCCESS]"
SCRIPT_STATUS_FAILED = "[USB-CONTROL-FAILED]"


def connect_device(dev, ser):
    try:
        if ser:
            try:
                ser = int(ser, 16)
            except ValueError:
                raise Exception("CONNECT DEVICE:"
                                "Serial number should be hexadecimal!")

        if ser:
            serial_log_str = "module with serial number {}".format(ser)
        else:
            serial_log_str = "first module found"
        log.info("CONNECT DEVICE: Creating {} and connecting to {}".format(
            dev, serial_log_str))

        if dev == "USBHub3p":
            stem = brainstem.stem.USBHub3p()
        elif dev == "USBCSwitch":
            stem = brainstem.stem.USBCSwitch()
        else:
            raise Exception("CONNECT DEVICE: Only 'USBHub3p' or "
                            "'USBCSwitch' are supported")

        if ser:
            result = stem.discoverAndConnect(brainstem.link.Spec.USB, ser)
        else:
            result = stem.discoverAndConnect(brainstem.link.Spec.USB)

        if result == Result.NO_ERROR:
            model = get_model(stem)
            actual_serial = get_serial(stem)
            log.info("CONNECT DEVICE: Connected to {} with serial number {}".
                     format(model, actual_serial))
        else:
            raise Exception("Could not find a module")
    except Exception as e:
        stem = None
        log.info("CONNECT DEVICE: {}".format(e))
    return stem


def disconnect_device(stem):
    log.info("DISCONNECT DEVICE: Disconnecting from module")
    try:
        stem.disconnect()
        # This is done to raise exception if device was never connected
        is_connected(stem)
    except (UnboundLocalError, AttributeError):
        log.warning("DISCONNECT DEVICE: Never connected to module")


def is_connected(stem):
    try:
        version = stem.system.getVersion().value
    except AttributeError:
        raise Exception("CHECK CONNECTION: Module is not connected")
    return version


def get_model(stem):
    if is_connected(stem):
        model_values = [0, 19, 21]
        model_names = [None, "USBHub3p", "USBCSwitch"]
        return model_names[model_values.index(stem.system.getModel().value)]
    raise Exception("GET MODULE: Module is not connected")


def get_serial(stem):
    return hex(stem.system.getSerialNumber().value)


def enable_port(stem, p=0):
    log.info("ENABLE PORT: Enabling port {}".format(p))

    model = get_model(stem)

    if model == "USBCSwitch":
        stem.mux.setChannel(p)
        stem.usb.setPortEnable(0)
        stem.mux.setEnable(1)

    count = 0
    err = Result.BUSY
    while err == Result.BUSY and count < 5:
        if model == "USBCSwitch":
            err = stem.mux.setEnable(1)
        elif model == "USBHub3p":
            err = stem.usb.setPortEnable(p)
        time.sleep(0.05)
        count += 1

    if err != Result.NO_ERROR:
        raise Exception("ENABLE PORT: Error {} encountered "
                        "enabling the connection".format(err))
    else:
        log.info("ENABLE PORT: {} port {} enabled".format(model, p))

    return True


def disable_port(stem, p=0):
    log.info("DISABLE PORT: Disabling port {}".format(p))

    model = get_model(stem)

    if model == "USBCSwitch":
        stem.mux.setChannel(p)
        stem.usb.setPortDisable(0)
        stem.mux.setEnable(1)

    count = 0
    err = Result.BUSY
    while err == Result.BUSY and count < 5:
        if model == "USBCSwitch":
            err = stem.mux.setEnable(1)
        elif model == "USBHub3p":
            err = stem.usb.setPortDisable(p)
        time.sleep(0.05)
        count += 1

    if err != Result.NO_ERROR:
        raise Exception("DISABLE PORT: Error {} encountered "
                        "disabling the connection".format(err))
    else:
        log.info("DISABLE PORT: {} port {} disabled".format(model, p))

    return True


def enable(dev, ser, p, it=None, delay=None):
    stem = None

    try:
        stem = connect_device(dev, ser)
        is_connected(stem)

        enable_port(stem, p)
        if iter is not None and delay is not None:
            for i in range(it):
                time.sleep(delay)
                disable_port(stem, p)
                time.sleep(delay)
                enable_port(stem, p)
    finally:
        disconnect_device(stem)


def disable(dev, ser, p):
    stem = None

    try:
        stem = connect_device(dev, ser)
        is_connected(stem)

        disable_port(stem, p)
    finally:
        disconnect_device(stem)


def flip_cable(dev, ser, p):
    stem = None

    try:
        stem = connect_device(dev, ser)
        is_connected(stem)

        model = get_model(stem)

        if model != "USBCSwitch":
            raise Exception("USBCSwitch device is only supported to perform "
                            "this kind of operation.")

        flip_state = stem.usb.getCableFlip(p).value
        log.info("FLIP CABLE: Current flip state: {}".format(flip_state))

        flip_state = int(not flip_state)
        log.info("FLIP CABLE: Switching to flip state: {}".format(flip_state))

        err = stem.usb.setCableFlip(p, flip_state)

        if err != Result.NO_ERROR:
            raise Exception("FLIP CABLE: Error {} encountered "
                            "flipping the cable".format(err))
        else:
            log.info("FLIP CABLE: New flip state: {}".
                     format(stem.usb.getCableFlip(p).value))
    except Exception as e:
        log.error("FLIP CABLE: ERROR: {}".format(e))
    finally:
        disconnect_device(stem)


def enable_power(dev, ser, p):
    stem = None

    try:
        stem = connect_device(dev, ser)
        is_connected(stem)

        log.info("ENABLE POWER: Enabling power on port {}".format(p))

        err = stem.usb.setPowerEnable(p)

        if err != Result.NO_ERROR:
            raise Exception("ENABLE POWER: Error {} encountered "
                            "enabling the power".format(err))
        else:
            log.info("ENABLE POWER: Power enabled on port {}".format(p))
    except Exception as e:
        log.error("ENABLE POWER: ERROR: {}".format(e))
    finally:
        disconnect_device(stem)


def disable_power(dev, ser, p):
    stem = None

    try:
        stem = connect_device(dev, ser)
        is_connected(stem)

        log.info("DISABLE POWER: Disabling power on port {}".format(p))

        err = stem.usb.setPowerDisable(p)

        if err != Result.NO_ERROR:
            raise Exception("DISABLE POWER: Error {} encountered "
                            "disabling the power".format(err))
        else:
            log.info("DISABLE POWER: Power disabled on port {}".format(p))
    except Exception as e:
        log.error("DISABLE POWER: ERROR: {}".format(e))
    finally:
        disconnect_device(stem)


def enable_data(dev, ser, p):
    stem = None

    try:
        stem = connect_device(dev, ser)
        is_connected(stem)

        log.info("ENABLE DATA: Enabling data on port {}".format(p))

        err = stem.usb.setDataEnable(p)

        if err != Result.NO_ERROR:
            raise Exception("ENABLE DATA: Error {} encountered "
                            "enabling the data".format(err))
        else:
            log.info("ENABLE DATA: Data enabled on port {}".format(p))
    except Exception as e:
        log.error("ENABLE DATA: ERROR: {}".format(e))
    finally:
        disconnect_device(stem)


def disable_data(dev, ser, p):
    stem = None

    try:
        stem = connect_device(dev, ser)
        is_connected(stem)

        log.info("DISABLE DATA: Disabling data on port {}".format(p))

        err = stem.usb.setDataDisable(p)

        if err != Result.NO_ERROR:
            raise Exception("DISABLE DATA: Error {} encountered "
                            "disabling the data".format(err))
        else:
            log.info("DISABLE DATA: Data disabled on port {}".format(p))
    except Exception as e:
        log.error("DISABLE DATA: ERROR: {}".format(e))
    finally:
        disconnect_device(stem)


def enable_hispeed(dev, ser, p):
    stem = None

    try:
        stem = connect_device(dev, ser)
        is_connected(stem)

        log.info("ENABLE HISPEED: Enabling HiSpeed on port {}".format(p))

        err = stem.usb.setHiSpeedDataEnable(p)

        if err != Result.NO_ERROR:
            raise Exception("ENABLE HISPEED: Error {} encountered "
                            "enabling HiSpeed".format(err))
        else:
            log.info("ENABLE HISPEED: HiSpeed enabled on port {}".format(p))
    except Exception as e:
        log.error("ENABLE HISPEED: ERROR: {}".format(e))
    finally:
        disconnect_device(stem)


def disable_hispeed(dev, ser, p):
    stem = None

    try:
        stem = connect_device(dev, ser)
        is_connected(stem)

        log.info("DISABLE HISPEED: Disabling HiSpeed on port {}".format(p))

        err = stem.usb.setHiSpeedDataDisable(p)

        if err != Result.NO_ERROR:
            raise Exception("DISABLE HISPEED: Error {} encountered "
                            "disabling HiSpeed".format(err))
        else:
            log.info("DISABLE HISPEED: HiSpeed disabled on port {}".format(p))
    except Exception as e:
        log.error("DISABLE HISPEED: ERROR: {}".format(e))
    finally:
        disconnect_device(stem)


def enable_superspeed(dev, ser, p):
    stem = None

    try:
        stem = connect_device(dev, ser)
        is_connected(stem)

        log.info("ENABLE SUPERSPEED: Enabling SuperSpeed on port {}".format(p))

        err = stem.usb.setSuperSpeedDataEnable(p)

        if err != Result.NO_ERROR:
            raise Exception("ENABLE SUPERSPEED: Error {} encountered "
                            "enabling SuperSpeed".format(err))
        else:
            log.info("ENABLE SUPERSPEED: SuperSpeed enabled on port {}".
                     format(p))
    except Exception as e:
        log.error("ENABLE SUPERSPEED: ERROR: {}".format(e))
    finally:
        disconnect_device(stem)


def disable_superspeed(dev, ser, p):
    stem = None

    try:
        stem = connect_device(dev, ser)
        is_connected(stem)

        log.info("DISABLE SUPERSPEED: Disabling SuperSpeed on port {}".
                 format(p))

        err = stem.usb.setSuperSpeedDataDisable(p)

        if err != Result.NO_ERROR:
            raise Exception("DISABLE SUPERSPEED: Error {} encountered "
                            "disabling SuperSpeed".format(err))
        else:
            log.info("DISABLE SUPERSPEED: SuperSpeed disabled on port {}".
                     format(p))
    except Exception as e:
        log.error("DISABLE SUPERSPEED: ERROR: {}".format(e))
    finally:
        disconnect_device(stem)


class USBControl(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost" or host == socket.gethostname():
            return object.__new__(USBControlLocal)
        else:
            return object.__new__(USBControlRemote)

    def __init__(self, **kwargs):
        self.device = kwargs["device"]

    @abstractmethod
    def enable(self, port):
        pass

    @abstractmethod
    def disable(self, port):
        pass


class USBControlLocal(USBControl):
    def enable(self, port):
        enable(self.device, None, port)

    def disable(self, port):
        disable(self.device, None, port)

    def enable_hispeed(self, port):
        enable_hispeed(self.device, None, port)

    def disable_hispeed(self, port):
        disable_hispeed(self.device, None, port)

    def enable_superspeed(self, port):
        enable_superspeed(self.device, None, port)

    def disable_superspeed(self, port):
        disable_superspeed(self.device, None, port)

class USBControlRemote(USBControl):
    def __init__(self, **kwargs):
        super(USBControlRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.cmd_start = "cd {} && python usb_control.py -d {} ".format(ATF_TOOLS_DIR, self.device)

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).run()
        if res["returncode"] != 0 or not any(SCRIPT_STATUS_SUCCESS in s for s in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote USB control operation")
        return res["output"]

    def exec_async(self, cmd, timeout=None):
        self.command = Command(cmd=cmd, host=self.host, timeout=timeout)
        self.command.run_async()
        return self

    def exec_join(self, timeout=None):
        return self.command.join(timeout)

    def enable(self, port):
        cmd = self.cmd_start + "-c enable_port -p {}".format(port)
        self.remote_exec(cmd)

    def disable(self, port):
        cmd = self.cmd_start + "-c disable_port -p {}".format(port)
        self.remote_exec(cmd)

    def enable_hispeed(self, port):
        cmd = self.cmd_start + "-c enable_hispeed -p {}".format(port)
        self.remote_exec(cmd)

    def disable_hispeed(self, port):
        cmd = self.cmd_start + "-c disable_hispeed -p {}".format(port)
        self.remote_exec(cmd)

    def enable_superspeed(self, port):
        cmd = self.cmd_start + "-c enable_superspeed -p {}".format(port)
        self.remote_exec(cmd)

    def disable_superspeed(self, port):
        cmd = self.cmd_start + "-c disable_superspeed -p {}".format(port)
        self.remote_exec(cmd)


class USBPowerMeterControl(object):

    def make_plot(self, diff_ts, avg_diffs, dev, port, name, name_file):
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(nrows=1, ncols=1)
        ax.tick_params(labelsize=8)
        ax.grid(True)
        x_results = [float(item) for item in diff_ts]
        y_results = [float(item) for item in avg_diffs]
        ax.plot(x_results, y_results)

        max_y = max(y_results)
        min_y = min(y_results)
        max_x = max(x_results)

        ax.axhline(y=max(y_results), color='r', linestyle='-')
        ax.axhline(y=min(y_results), color='g', linestyle='-')

        xstep = max_x / 30
        xstep = 1 if xstep == 0 else xstep
        ystep = (max_y - min_y) / 20
        ystep = 1 if ystep == 0 else ystep

        plt.axis([0, math.ceil(x_results[-1]) + xstep, min_y - ystep, max_y + ystep])

        xx = np.arange(xstep, math.ceil(x_results[-1]) + xstep, xstep)
        yy = np.arange(min_y - ystep, max_y + ystep, ystep)
        ax.yaxis.label.set_size(40)
        ax.set_xticks(xx)
        ax.set_yticks(yy)
        ax.set_title("usb_{}_port_{}.log".format(dev, port))
        ax.set_xlabel("time(s)")
        ax.set_ylabel(name)

        fig.set_size_inches(38, 8)
        fig.savefig(name_file, dpi=300)
        plt.close(fig)

        return name_file

    def run_async(self, dev, ser, p, raw=False):
        self.t = threading.Thread(target=self.__run_in_thread, args=(dev, ser, p))
        self.t.daemon = True
        self.t.start()
        self.raw = raw

    def __run_in_thread(self, dev, ser, p):
        self.go = True
        self.current = []
        self.measurement_count = 0
        self.stem = None
        self.times = []

        try:
            log.info("MEASURE POWER: Starting power measuring")

            self.stem = connect_device(dev, ser)
            is_connected(self.stem)
            enable_port(self.stem, p)

            start_time = time.time()
            if dev == "USBHub3p":
                real_port = p
            elif dev == "USBCSwitch":
                real_port = 0

            while self.go:
                ua = self.stem.usb.getPortCurrent(real_port)
                if ua.error == Result.NO_ERROR:
                    self.current += [ua.value]
                    self.measurement_count += 1
                    curr_time = time.time()
                    self.times += [curr_time - start_time]

                else:
                    log.info("MEASURE POWER: Failed to get port current: {}".format(ua.error))

        except Exception as e:
            log.error("MEASURE POWER: ERROR: {}".format(e))

    def join(self, dev, port):
        self.go = False
        self.t.join()
        disconnect_device(self.stem)

        if self.measurement_count > 0:
            self.current = [(self.current[i]) / 10 ** 6. for i in range(self.measurement_count)]
            max_current = "{0:.4f}".format(max(self.current))
            avg_current = "{0:.4f}".format(sum(self.current) / self.measurement_count)

            log.info("===== SCRIPT RESULT =====")
            log.info("MEASUREMENT COUNT: {}".format(self.measurement_count))
            log.info("MAX CURRENT:       {} A".format(max_current))
            log.info("AVG CURRENT:       {} A".format(avg_current))
            log.info("=========================")

            if self.raw:
                return self.current

            return self.make_plot(self.times, self.current, dev, port, "CURRENT(A)", "cur_plot{}.png".format(
                                ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(4)])))

        else:
            log.warning("MEASURE POWER: No measurements were performed. "
                        "Log file will not be generated")
            return None


class USBArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error("\n{}\n".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "%s: error: %s\n" % (self.prog, message))


if __name__ == "__main__":
    parser = USBArgumentParser()
    parser.add_argument("-t", "--time", help="Measurement time (sec)",
                        type=float)
    parser.add_argument("-p", "--port", help="Port number starting from 0",
                        type=int)
    parser.add_argument("-d", "--device", help="Device type",
                        choices=["USBHub3p", "USBCSwitch"])
    parser.add_argument("-s", "--serial", help="Device serial number")
    parser.add_argument("-c", "--command", help="Command",
                        choices=["power_meter_total", "flip_cable",
                                 "enable_port", "disable_port",
                                 "disable_power",
                                 "enable_power", "disable_data", "enable_data",
                                 "enable_hispeed", "disable_hispeed",
                                 "enable_superspeed", "disable_superspeed"],
                        required=True)
    args = parser.parse_args()

    duration = 10 if args.time is None else args.time
    port = 0 if args.port is None else args.port
    device = "USBCSwitch" if args.device is None else args.device
    serial = False if args.serial is None else args.serial
    command = args.command

    # print "=== SCRIPT PARAMETERS ==="
    # print "COMMAND:           {}".format(command)
    # print "DEVICE:            {}".format(device)
    # print "DEVICE SERIAL:     {}".format(serial)
    # print "DEVICE PORT:       {}".format(port)
    # print "DURATION:          {} sec".format(duration)
    # print "========================="
    try:
        usb_power_meter_control = USBPowerMeterControl()
        if command == "power_meter_total":
            usb_power_meter_control.run_async(device, serial, port)
            if command == "end_power_meter_total":
                usb_power_meter_control.join(device, port)
        elif command == "flip_cable":
            flip_cable(device, serial, port)
        elif command == "enable_port":
            enable(device, serial, port)
        elif command == "disable_port":
            disable(device, serial, port)
        elif command == "enable_power":
            enable_power(device, serial, port)
        elif command == "disable_power":
            disable_power(device, serial, port)
        elif command == "enable_data":
            enable_data(device, serial, port)
        elif command == "disable_data":
            disable_data(device, serial, port)
        elif command == "enable_hispeed":
            enable_hispeed(device, serial, port)
        elif command == "disable_hispeed":
            disable_hispeed(device, serial, port)
        elif command == "enable_superspeed":
            enable_superspeed(device, serial, port)
        elif command == "disable_superspeed":
            disable_superspeed(device, serial, port)
        else:
            print "UNKNOWN COMMAND"
    except Exception as e:
        log.exception(e)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
