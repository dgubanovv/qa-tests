import time

from tools.utils import get_atf_logger

log = get_atf_logger()


class NvidiaBoardPower(object):
    def __init__(self, serial_console):
        self.serial_console = serial_console

    def power_on(self):
        self.serial_console.clean_output()
        output = ""
        self.serial_console.write_to_serial("poweron")
        while self.serial_console.serial_port.inWaiting() == 0:
            time.sleep(0.1)
        while "Command Executed" not in output:
            output += self.serial_console.read_from_serial()
# to do: add check that system is loaded!
        time.sleep(15)
        log.info("Command executed. Board power on")

    def power_off(self):
        self.serial_console.clean_output()
        output = ""
        self.serial_console.write_to_serial("poweroff")
        while self.serial_console.serial_port.inWaiting() == 0:
            time.sleep(0.1)
        while "Command Executed" not in output:
            output += self.serial_console.read_from_serial()
        time.sleep(5)
        log.info("Command executed. Board power off")

    def aurixreset(self):
        self.serial_console.clean_output()
        output = ""
        self.serial_console.write_to_serial("aurixreset")
        while self.serial_console.serial_port.inWaiting() == 0:
            time.sleep(0.1)
        while ("Drive AX Aurix Serial Console" not in output and
               "Drive safety startup evaluation completed!" not in output):
            output += self.serial_console.read_from_serial()
        time.sleep(15)
        log.info("Command executed. Aurix is reseted")

    def tegrareset_x1(self):
        self.serial_console.clean_output()
        output = ""
        self.serial_console.write_to_serial("\ntegrareset x1")
        while self.serial_console.serial_port.inWaiting() == 0:
            time.sleep(0.1)
        while "Command Executed" not in output:
            output += self.serial_console.read_from_serial()
        time.sleep(15)
        log.info("Command executed. Tegra x1 is reseted")

    def tegrareset_x2(self):
        self.serial_console.clean_output()
        output = ""
        self.serial_console.write_to_serial("\ntegrareset x2")
        while self.serial_console.serial_port.inWaiting() == 0:
            time.sleep(0.1)
        while "Command Executed" not in output:
            output += self.serial_console.read_from_serial()
        time.sleep(15)
        log.info("Command executed. Tegra x2 is reseted")
