import os
import sys
import time
import pytest
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.command import Command
from tools.utils import get_atf_logger
from a2_reboot_test_base import Atlantic2RebootBase

log = get_atf_logger()

def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_reboot"


class TestAtlantic2HotReset(Atlantic2RebootBase):
    def test_many_hot_reset(self):
        self.cold_restart(host=self.dut_hostname)
        cmd = Command(cmd="sudo lspci -s {} -vv | grep LnkSta".format(self.get_iface_name(self.dut_port)),
                      host=self.dut_hostname)
        res = cmd.run()
        log.info("{:#<60}".format('SNPS BEFORE RUNNING 100 ITERAIONS'))
        cmd = Command(cmd="sudo readstat2 --snps".format(self.get_iface_name(self.dut_port)), host=self.dut_hostname)
        res = cmd.run()
        self.verify_preset_reg()
        self.dev_not_found, self.switched_to_gen_3, self.switched_to_gen_2, self.switched_to_gen_1,\
        self.wrong_pci_width = 0, 0, 0, 0, 0
        for i in range(self.REBOOT_COUNT):
            log.info( "{:#<60}".format(''))
            log.info("Hot reset iteration: {}".format(i))
            log.info( "{:#<60}".format(''))
            self.verify_hot_reset(i)
        log.info("{:#<60}".format(''))
        log.info("\nDevice not found: {}\nSwitched to Gen3: {}\nSwitched to Gen2: {}\nSwitched to Gen1: {}\nWrong PCI width: {}"\
                .format(self.dev_not_found, self.switched_to_gen_3, self.switched_to_gen_2, self.switched_to_gen_1, self.wrong_pci_width))

class TestAtlantic2ChangeSpeedGen(Atlantic2RebootBase):
    def test_many_gen_speed_change(self):
        self.cold_restart(host=self.dut_hostname)
        cmd = Command(cmd="sudo lspci -s {} -vv | grep LnkSta".format(self.get_iface_name(self.dut_port)),
                        host=self.dut_hostname)
        res = cmd.run()
        log.info("{:#<60}".format('SNPS BEFORE RUNNING 100 ITERAIONS'))
        cmd = Command(cmd="sudo readstat2 --snps".format(self.get_iface_name(self.dut_port)), host=self.dut_hostname)
        res = cmd.run()
        self.verify_preset_reg()
        self.dev_not_found, self.switched_to_gen_3, self.switched_to_gen_2, self.switched_to_gen_1,\
        self.wrong_pci_width = 0, 0, 0, 0, 0
        for i in range(self.REBOOT_COUNT):
            log.info( "{:#<60}".format(''))
            log.info("Gen speed change iteration: {}".format(i))
            log.info( "{:#<60}".format(''))
            self.verify_gen_speed_change(i)
        log.info("{:#<60}".format(''))
        log.info("\nDevice not found: {}\nSwitched to Gen3: {}\nSwitched to Gen2: {}\nSwitched to Gen1: {}\nWrong PCI width: {}"\
                    .format(self.dev_not_found, self.switched_to_gen_3, self.switched_to_gen_2, self.switched_to_gen_1, self.wrong_pci_width))

class TestAtlantic2GenSpeedChangeWithEqBit(Atlantic2RebootBase):
    def test_many_gen_speed_change_with_eq_bit(self):
        self.cold_restart(host=self.dut_hostname)
        cmd = Command(cmd="sudo lspci -s {} -vv | grep LnkSta".format(self.get_iface_name(self.dut_port)),
                        host=self.dut_hostname)
        res = cmd.run()
        log.info("{:#<60}".format('SNPS BEFORE RUNNING 100 ITERAIONS'))
        cmd = Command(cmd="sudo readstat2 --snps".format(self.get_iface_name(self.dut_port)), host=self.dut_hostname)
        res = cmd.run()
        self.verify_preset_reg()
        self.dev_not_found, self.switched_to_gen_3, self.switched_to_gen_2, self.switched_to_gen_1,\
        self.wrong_pci_width = 0, 0, 0, 0, 0
        for i in range(self.REBOOT_COUNT):
            log.info( "{:#<60}".format(''))
            log.info("Gen speed change iteration wiht eq: {}".format(i))
            log.info( "{:#<60}".format(''))
            self.verify_gen_speed_change_eq_bit(i)
        log.info("{:#<60}".format(''))
        log.info("\nDevice not found: {}\nSwitched to Gen3: {}\nSwitched to Gen2: {}\nSwitched to Gen1: {}\nWrong PCI width: {}"\
            .format(self.dev_not_found, self.switched_to_gen_3, self.switched_to_gen_2, self.switched_to_gen_1, self.wrong_pci_width))

class TestAtlantic2WarmReboot(Atlantic2RebootBase):
    def test_many_warm_reboots(self):
        self.cold_restart(host=self.dut_hostname)
        cmd = Command(cmd="sudo lspci -s {} -vv | grep LnkSta".format(self.get_iface_name(self.dut_port)),
                      host=self.dut_hostname)
        res = cmd.run()
        log.info("{:#<60}".format('SNPS BEFORE RUNNING 100 ITERAIONS'))
        cmd = Command(cmd="sudo readstat2 --snps", host=self.dut_hostname)
        res = cmd.run()
        log.info("{:#<60}".format('EFUSE REGS BEFORE RUNNING 100 ITERAIONS'))
        self.verify_preset_reg()
        self.dev_not_found, self.switched_to_gen_3, self.switched_to_gen_2, self.switched_to_gen_1,\
        self.wrong_pci_width = 0, 0, 0, 0, 0
        for i in range(self.REBOOT_COUNT):
            log.info( "{:#<60}".format(''))
            log.info("Warm reboot iteration: {}".format(i))
            log.info( "{:#<60}".format(''))
            self.verify_reboot(i)
        log.info("{:#<60}".format(''))
        log.info("\nDevice not found: {}\nSwitched to Gen3: {}\nSwitched to Gen2: {}\nSwitched to Gen1: {}\nWrong PCI width: {}"\
                .format(self.dev_not_found, self.switched_to_gen_3, self.switched_to_gen_2, self.switched_to_gen_1, self.wrong_pci_width))

class TestAtlantic2ColdReboot(Atlantic2RebootBase):
    def test_many_cold_reboots(self):
        self.cold_restart(host=self.dut_hostname)
        cmd = Command(cmd="sudo lspci -s {} -vv | grep LnkSta".format(self.get_iface_name(self.dut_port)),
                        host=self.dut_hostname)
        res = cmd.run()
        log.info("{:#<60}".format('SNPS BEFORE RUNNING 100 ITERAIONS'))
        cmd = Command(cmd="sudo readstat2 --snps", host=self.dut_hostname)
        res = cmd.run()
        log.info("{:#<60}".format('EFUSE REGS BEFORE RUNNING 100 ITERAIONS'))
        self.verify_preset_reg()
        self.dev_not_found, self.switched_to_gen_3, self.switched_to_gen_2, self.switched_to_gen_1,\
        self.wrong_pci_width = 0, 0, 0, 0, 0
        for i in range(self.REBOOT_COUNT):
            log.info( "{:#<60}".format(''))
            log.info("Cold reboot iteration: {}".format(i))
            log.info("{:#<60}".format(''))
            self.verify_cold_boot(i)
        log.info( "{:#<60}".format(''))
        log.info("\nDevice not found: {}\nSwitched to Gen3: {}\nSwitched to Gen2: {}\nSwitched to Gen1: {}\nWrong PCI width: {}"\
                .format(self.dev_not_found, self.switched_to_gen_3, self.switched_to_gen_2, self.switched_to_gen_1, self.wrong_pci_width))

if __name__ == "__main__":
    args = [__file__, "-s", "-v"]
    if len(sys.argv) > 1:
        args.extend(["-k", sys.argv[-1]])
    pytest.main(args)
