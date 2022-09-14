import os
import sys
import time
import pytest
import re
import threading
import shutil
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from infra.test_base import TestBase

from tools.driver import Driver, DRV_TYPE_LINUX_SRC
from tools.atltoolper import AtlTool
from tools.fw_a2_drv_iface_cfg import FirmwareA2Config
from tools.ifconfig import LINK_STATE_UP
from tools.utils import get_atf_logger, get_domain_bus_dev_func, get_bus_dev_func
from tools.power import Power
from tools import pcontrol
from tools.ops import OpSystem
from tools.command import Command
from tools.fw_a2_drv_iface_structures import DRIVER_INTERFACE_IN, DRIVER_INTERFACE_OUT
from hlh.register import Register
from tools.hwaccess import HwAccess


log = get_atf_logger()


LTSSM_MAP = {0x0: "S_DETECT_QUIET",
             0x1: "S_DETECT_ACT",
             0x2: "S_POLL_ACTIVE",
             0x3: "S_POLL_COMPLIANCE",
             0x4: "S_POLL_CONFIG",
             0x5: "S_PRE_DETECT_QUIET",
             0x6: "S_DETECT_WAIT",
             0x7: "S_CFG_LINKWD_START",
             0x8: "S_CFG_LINKWD_ACEPT",
             0x9: "S_CFG_LANENUM_WAI",
             0xA: "S_CFG_LANENUM_ACEPT",
             0xB: "S_CFG_COMPLETE",
             0xC: "S_CFG_IDLE",
             0xD: "S_RCVRY_LOCK",
             0xE: "S_RCVRY_SPEED",
             0xF: "S_RCVRY_RCVRCFG",
             0x10: "S_RCVRY_IDLE",
             0x11: "S_L0",
             0x12: "S_L0S",
             0x13: "S_L123_SEND_EIDLE",
             0x14: "S_L1_IDLE",
             0x15: "S_L2_IDLE",
             0x16: "S_L2_WAKE",
             0x17: "S_DISABLED_ENTRY",
             0x18: "S_DISABLED_IDLE",
             0x19: "S_DISABLED",
             0x1A: "S_LPBK_ENTRY",
             0x1B: "S_LPBK_ACTIVE",
             0x1C: "S_LPBK_EXIT",
             0x1D: "S_LPBK_EXIT_TIMEOUT",
             0x1E: "S_HOT_RESET_ENTRY",
             0x1F: "S_HOT_RESET",
             0x20: "S_RCVRY_EQ0",
             0x21: "S_RCVRY_EQ1",
             0x22: "S_RCVRY_EQ2",
             0x23: "S_RCVRY_EQ3",
             }



class Atlantic2RebootBase(TestBase):

    REBOOT_COUNT = int(os.environ.get("REBOOT_COUNT", 5))
    CURR_REBOOT = 0
    BEFORE_PING_DELAY = 10
    AFTER_TURNOFF_DELAY = 30

    DUT_IP4_ADDR = "192.168.0.3"
    LKP_IP4_ADDR = "192.168.0.2"
    NETMASK_IPV4 = "255.255.255.0"
    PCIE_BRIDGE_PORT = str(os.environ.get("PCIE_BRIDGE_PORT", "02:02.0"))
    T6_NAME = os.environ.get("T6_NAME", 'AQT6C0089:I2C')

    @classmethod
    def setup_class(cls):
        cls.security = True
        super(Atlantic2RebootBase, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.install_firmwares()
            cls.dut_ops = OpSystem(host=cls.dut_hostname)
            if cls.dut_ops.is_linux():
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname,
                                        drv_type=DRV_TYPE_LINUX_SRC)
            else:
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
            # cls.dut_driver.install()
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            # cls.lkp_driver.install()


            # cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            # cls.lkp_atltool_wrapper = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            cls.dut_power = Power(host=cls.dut_hostname)


            # port, _, __ = get_bus_dev_func(cls.dut_port)
            # res = Command(cmd="sudo flashErase2 -d {}:".format(hex(int(port)))).run_join(10)
            # assert res["returncode"] == 0

            # res = Command(cmd='sudo atltool -wr 0x3000 0x1 -d {}'.format(hex(int(port))), host=cls.dut_hostname).run()
            # assert res["returncode"] == 0

            try:
                c = Command(cmd='sudo rmmod ftdi_sio').run()
            except Exception as e:
                pass

            time.sleep(1)
            # cls.lkp_atltool_smbus = HwAccess(t6_name=cls.T6_NAME, i2c_addr=0x79)
            cls.lkp_atltool_smbus = AtlTool(host=cls.dut_hostname, port=cls.dut_port)
            # Add driver interface structures to globals, so ctypes_struct_helper module could find them
            import __builtin__
            __builtin__.DRIVER_INTERFACE_IN = DRIVER_INTERFACE_IN
            __builtin__.DRIVER_INTERFACE_OUT = DRIVER_INTERFACE_OUT
            # cls.fw_config = FirmwareA2Config(cls.dut_atltool_wrapper)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def teardown_method(self, method):
        super(Atlantic2RebootBase, self).teardown_method(method)
        if self.t.isAlive():
            self.stop_poll_ltsmm(9999, state='')
            self.process_data(9999)
            self.dump_phy(9999)

        # self.bring_host_online(self.dut_hostname)

    def configure_datapath(self):
        self.lkp_ifconfig.set_ip_address(self.LKP_IP4_ADDR, self.NETMASK_IPV4, None)
        self.dut_ifconfig.set_ip_address(self.DUT_IP4_ADDR, self.NETMASK_IPV4, None)
        self.dut_ifconfig.set_link_state(LINK_STATE_UP)
        self.lkp_ifconfig.set_link_state(LINK_STATE_UP)

    @staticmethod
    def get_iface_name(port):
        domain, bus, dev, func = get_domain_bus_dev_func(port)
        return "{:04x}:{:02x}:{:02x}.{:x}".format(domain, bus, dev, func)

    def trig_gpio_0(self):
        reg_3698 = Register(self.lkp_atltool_smbus.readreg(0x3698))
        reg_3698[1] = 0x0
        self.lkp_atltool_smbus.writereg(0x3698, reg_3698.get())
        assert reg_3698[2:3] == 0x3

        reg_3690 = Register(self.lkp_atltool_smbus.readreg(0x3690))
        reg_3690[0] = 0x1
        self.lkp_atltool_smbus.writereg(0x3690, reg_3690.get())

        reg_3684 = Register(self.lkp_atltool_smbus.readreg(0x3684))
        assert reg_3684[0] == 0x1

        reg_3694 = Register(self.lkp_atltool_smbus.readreg(0x3694))
        reg_3694[0] = 0x1
        self.lkp_atltool_smbus.writereg(0x3694, reg_3694.get())

        reg_3684 = Register(self.lkp_atltool_smbus.readreg(0x3684))
        assert reg_3684[0] == 0x0


    def verify_device_is_present(self):
        log.info("Verifying device is present")
        cmd = Command(cmd="lspci -s {}".format(self.get_iface_name(self.dut_port)), host=self.dut_hostname)
        res = cmd.run()
        domain, bus, dev, func = get_domain_bus_dev_func(self.dut_port)
        if not "{:02x}:{:02x}.{:x}".format(bus, dev, func) in "".join(res["output"]):
            # self.trig_gpio_0()
            log.warning("WARN: Device is not found on pci: {}".format(self.get_iface_name(self.dut_port)))
            self.dev_not_found += 1
            # raise Exception("WARN: Device is not found on pci: {}".format(self.get_iface_name(self.dut_port)))
        # assert "{:02x}:{:02x}.{:x}".format(bus, dev, func) in "".join(res["output"])

        log.info("{:#<60}".format('EUFUSE PRESET REGS IN ITERATION'))
        self.verify_preset_reg()


    def verify_pcie_gen_and_width(self, gen=os.environ.get("DUT_PCI_GEN", None)):
        log.info("Verifying PCI GEN and width")
        pci_status_regex = r"\s*LnkSta:\s*Speed\s*(\d+\.?\d?)GT\/s.*Width\s*x(\d+),.*"
        cmd = Command(cmd="sudo lspci -s {} -vv | grep LnkSta".format(self.get_iface_name(self.dut_port)),
                      host=self.dut_hostname)
        res = cmd.run()

        for line in res["output"]:
            m = re.search(pci_status_regex, line)
            if m:
                pci_status = m
                break

        if pci_status is None:
            raise Exception("Failed to check PCIe status. Status string is:\n{}".format(res))
        pci_gen_speed, pci_width = pci_status.group(1), int(pci_status.group(2))

        supported_gen_type = gen
        supported_pci_width = int(os.environ.get("DUT_PCI_WIDTH", "4"))

        if "4" in supported_gen_type:
            # assert pci_gen_speed == "16", "Expected pci_gen_speed for Gen4 should be 16, but got: {}".format(pci_gen_speed)
            if pci_gen_speed != "16":
                # self.trig_gpio_0()
                log.warning("WARN: Expected pci_gen_speed for Gen4 should be 16, but got: {}".format(pci_gen_speed))

                gens = {"8": self.switched_to_gen_3,
                     "5": self.switched_to_gen_2,
                     "2.5": self.switched_to_gen_1}

                gens[pci_gen_speed] += 1
                # raise Exception("WARN: Expected pci_gen_speed for Gen4 should be 16, but got: {}".format(pci_gen_speed))
        elif "3" in supported_gen_type:
            assert pci_gen_speed == "8", "Expected pci_gen_speed for Gen3 should be 8, but got: {}".format(pci_gen_speed)
        elif "2" in supported_gen_type:
            assert pci_gen_speed == "5", "Expected pci_gen_speed for Gen2 should be 5, but got: {}".format(pci_gen_speed)

        # assert supported_pci_width == pci_width, "PCIe width should be {} but got: {}".format(supported_pci_width, pci_width)
        if supported_pci_width != pci_width:
            # self.trig_gpio_0()
            log.warning("WARN: PCIe width should be {} but got: {}".format(supported_pci_width, pci_width))
            self.wrong_pci_width += 1
            # raise Exception("WARN: PCIe width should be {} but got: {}".format(supported_pci_width, pci_width))
        # self.lkp_atltool_smbus.close()
        # log.info("{:#<60}".format('SNPS IN ITERATION, PCI_GEN_EXPECTED: {}'.format(gen)))
        # cmd = Command(cmd="sudo readstat2 --snps -d {}".format(self.T6_NAME), silent=True)
        # res = cmd.run()
        # self.readstat = res["output"]
        # self.lkp_atltool_smbus.open()
        time.sleep(2)

    def verify_heart_beat(self):
        heart_beat_1 = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.macHealthMonitor.macHeartBeat")
        time.sleep(2)
        heart_beat_2 = self.fw_config.read_drv_iface_struct_field("DRIVER_INTERFACE_OUT.macHealthMonitor.macHeartBeat")

        assert heart_beat_2 > heart_beat_1, "MAC heart beat is not ticking"
        # if heart_beat_2 == heart_beat_1:
            # log.info("WARNING: MAC heart beat is not ticking")

    def verify_link_up(self):
        self.configure_datapath()
        self.lkp_ifconfig.wait_link_up(LINK_STATE_UP)

    def verify_ping(self):
        self.ping(self.lkp_hostname, self.DUT_IP4_ADDR, 8, ipv6=False, src_addr=self.LKP_IP4_ADDR)  # TODO Temporary workaround
        assert self.ping(self.lkp_hostname, self.DUT_IP4_ADDR, 16, ipv6=False, src_addr=self.LKP_IP4_ADDR) is True, \
                "Failed to ping {} from {}".format(self.DUT_IP4_ADDR, self.LKP_IP4_ADDR)

    def verify_preset_reg(self):
        reg_16890 = self.lkp_atltool_smbus.readreg(0x16890)
        reg_168a8 = self.lkp_atltool_smbus.readreg(0x168a8)
        self.preset_regs = []

        self.preset_regs.append("**** PRESET REGS BEFORE CHANGING 0x16890 and 0x168a8 ****")
        for r in [(0x16890, reg_16890), (0x168a8, reg_168a8)]:
            reg, val  = r[0], r[1]
            str = "Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                    reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF)

            log.info(str)
            self.preset_regs.append(str)

        self.preset_regs.append("\n\n**** PRESET REGS AFTER CHANGING 0x16890 and 0x168a8 ****")
        reg_16890 = Register(reg_16890)
        reg_16890[24:25] = 0x0
        self.lkp_atltool_smbus.writereg(0x16890, reg_16890.get())
        time.sleep(0.5)
        reg_168a8 = self.lkp_atltool_smbus.readreg(0x168a8)
        str = "Register 0X168A8 after setting 0x16890.25:24 to 0x0 : 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                    reg_168a8, (reg_168a8 >> 24) & 0xFF, (reg_168a8 >> 16) & 0xFF, (reg_168a8 >> 8) & 0xFF, reg_168a8 & 0xFF)
        self.preset_regs.append(str)

        reg_16890 = Register(self.lkp_atltool_smbus.readreg(0x16890))
        reg_16890[24:25] = 0x1
        self.lkp_atltool_smbus.writereg(0x16890, reg_16890.get())
        time.sleep(0.5)
        reg_168a8 = self.lkp_atltool_smbus.readreg(0x168a8)

        str = "Register 0X168A8 after setting 0x16890.25:24 to 0x1 : 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                    reg_168a8, (reg_168a8 >> 24) & 0xFF, (reg_168a8 >> 16) & 0xFF, (reg_168a8 >> 8) & 0xFF, reg_168a8 & 0xFF)
        self.preset_regs.append(str)

    def _verify_ltssm(self):
        self.ltssms = ['-LTSSM-']
        self.ltssms_sd = ['-0x162A0-']
        self.reg_0x162CCs = ['-0x162CC-']
        self.reg_0x162D0s = ['-0x162D0-']
        self.reg_0x162D4s = ['-0x162D4-']

        while self.go:
            ltssm = Register(self.lkp_atltool_smbus.readreg(0x16728))
            sd_status_ltssm = Register(self.lkp_atltool_smbus.readreg(0x162A0))
            reg_0x162CC = Register(self.lkp_atltool_smbus.readreg(0x162CC))
            reg_0x162D0 = Register(self.lkp_atltool_smbus.readreg(0x162D0))
            reg_0x162D4 = Register(self.lkp_atltool_smbus.readreg(0x162D4))

            try:
                curr_ltsmm = LTSSM_MAP[ltssm[0:5]]
            except KeyError:
                curr_ltsmm = hex(ltssm[0:5])

            self.ltssms.append(curr_ltsmm)
            self.ltssms_sd.append(hex(sd_status_ltssm[0:31]))
            self.reg_0x162CCs.append(hex(reg_0x162CC[0:31]))
            self.reg_0x162D0s.append(hex(reg_0x162D0[0:31]))
            self.reg_0x162D4s.append(hex(reg_0x162D4[0:31]))


    def start_poll_ltsmm(self):
        self.go = True
        self.t = threading.Thread(target=self._verify_ltssm, args=())
        self.t.daemon = True
        self.t.start()

    def stop_poll_ltsmm(self, i, state=''):
        self.go = False
        time.sleep(2)
        self.t.join()

        # self.process_data(i, state=state)

    def process_data(self, i, state=''):
        short_ltssm = []

        n = 1
        for idx in range(1, len(self.ltssms)):
            if (self.ltssms[idx] != self.ltssms[idx-1] or self.ltssms_sd[idx] != self.ltssms_sd[idx-1] or \
                self.reg_0x162CCs[idx] != self.reg_0x162CCs[idx-1] or self.reg_0x162D0s[idx] != self.reg_0x162D0s[idx-1] or \
                self.reg_0x162D4s[idx] != self.reg_0x162D4s[idx-1]):

                short_ltssm.append("{:<10}{:20}{:13}{:13}{:13}{:13}".\
                    format(n, self.ltssms[idx-1], self.ltssms_sd[idx-1], self.reg_0x162CCs[idx-1], self.reg_0x162D0s[idx-1], self.reg_0x162D4s[idx-1]))

                n = 1
            else:
                n += 1
        short_ltssm.append("{:<10}{:20}{:13}{:13}{:13}{:13}".\
                    format(n, self.ltssms[-1], self.ltssms_sd[-1], self.reg_0x162CCs[-1], self.reg_0x162D0s[-1], self.reg_0x162D4s[-1]))


        out_file = "ltsmm_log_{}_{}.txt".format(i, state)
        with open(out_file, 'w') as f:
            f.write('\n'.join(line for line in short_ltssm))

        shutil.move(out_file, self.test_log_dir)

        out_file = "readstat_preset_{}_{}.txt".format(i, state)
        with open(out_file, 'w') as f:
            f.write('\n'.join(line for line in self.readstat))
            f.write('\n\n{}'.format("========== PRESET REGISTERS ==========\n"))
            f.write('\n'.join(line for line in self.preset_regs))

        shutil.move(out_file, self.test_log_dir)


    def dump_phy(self,i):
        self.lkp_atltool_smbus.close()
        time.sleep(1)

        Command(cmd="sudo atltool2 -wr 0x1594 0x1 -d {}".format(self.T6_NAME), silent=True).run()
        time.sleep(1)

        start_phy = 0x40000
        end_phy = 0x5FFFC
        cmd = Command(cmd="sudo atltool2 -rr 0x{:08x}:0x{:08x} -d {}".format(start_phy, end_phy,  self.T6_NAME), silent=True)
        res = cmd.run()

        out_file = "phy_log_{}.txt".format(i)
        with open(out_file, 'w') as f:
            f.write('\n'.join(line for line in res["output"]))

        shutil.move(out_file, self.test_log_dir)
        self.lkp_atltool_smbus.open()

    def init_hot_reset(self, i):
        # Clear hot reset bit
        self.lkp_atltool_smbus.readreg(0x1f20)

        res = Command(cmd="sudo lspci -tv | grep Aquantia", host=self.dut_hostname).run()
        str = res["output"][0].split()[0]
        re_bridge = re.compile("([0-9]{2}\.[0-9])", re.DOTALL)
        m = re_bridge.search(str)

        if m:
            b_addr = m.group(1)
        else:
            raise Exception("Bridge address not found")

        # b_addr = self.PCIE_BRIDGE_PORT

        res = Command(cmd="sudo setpci -s {} BRIDGE_CONTROL".format(b_addr), host=self.dut_hostname).run()
        init_val = int(res["output"][0], 16)

        # self.start_poll_ltsmm()
        time.sleep(2)
        new_val = init_val | 0x40
        res = Command(cmd="sudo setpci -s {} BRIDGE_CONTROL={}".format(b_addr, hex(new_val)), host=self.dut_hostname).run()
        time.sleep(1)
        res = Command(cmd="sudo setpci -s {} BRIDGE_CONTROL={}".format(b_addr, hex(init_val)), host=self.dut_hostname).run()
        time.sleep(1)

        domain, bus, dev, func = get_domain_bus_dev_func(self.dut_port)
        res = Command(cmd="echo 1 | sudo tee /sys/bus/pci/devices/0000\:{:02x}\:{:02x}.{:x}/remove".format(bus, dev, func), \
                     host=self.dut_hostname).run()
        time.sleep(1)
        assert res["returncode"] == 0

        res = Command(cmd="echo 1 | sudo tee /sys/bus/pci/rescan", host=self.dut_hostname).run()
        time.sleep(1)
        assert res["returncode"] == 0
        time.sleep(2)

        # self.stop_poll_ltsmm(i)

        reg1f20 = self.lkp_atltool_smbus.readreg(0x1f20)
        assert (reg1f20 >> 0xb) & 1 == 0x1, "Hot reset was not applied"

    def get_pcie_express_cap_ofset(self):
        res = Command(cmd="sudo lspci -s {} -vvvv".format(self.PCIE_BRIDGE_PORT), host=self.dut_hostname).run()
        str = "\n".join(res["output"])
        re_pcie_express_cap_ofset = re.compile(r".+\[(\w+)\] Express.+Root Port")
        m = re_pcie_express_cap_ofset.search(str)
        pcie_express_cap_ofset = ""
        if m:
            pcie_express_cap_ofset = m.group(1)
            log.info("found pcie_express_cap_ofset from lspci output: {}".format(pcie_express_cap_ofset))
            return pcie_express_cap_ofset
        else:
            raise Exception("PCI express Capability ofset not found")

    def get_link_control2_register(self, pcie_express_cap_ofset):
        res = Command(cmd="sudo setpci -s {} 0x{}+0x30.W".\
            format(self.PCIE_BRIDGE_PORT, pcie_express_cap_ofset), host=self.dut_hostname).run()
        link_control2_register = int(res["output"][0], 16)

        return link_control2_register

    def set_link_control2_register(self, pcie_express_cap_ofset, value):
        res = Command(cmd="sudo setpci -s {} 0x{}+0x30.W={}".\
            format(self.PCIE_BRIDGE_PORT, pcie_express_cap_ofset, hex(value)), host=self.dut_hostname).run()

    def get_link_control_register(self, pcie_express_cap_ofset):
        res = Command(cmd="sudo setpci -s {} 0x{}+0x10.W".\
            format(self.PCIE_BRIDGE_PORT, pcie_express_cap_ofset), host=self.dut_hostname).run()
        link_control_register = int(res["output"][0], 16)
        return link_control_register

    def set_link_control_register(self, pcie_express_cap_ofset, value):
        res = Command(cmd="sudo setpci -s {} 0x{}+0x10.W={}".\
            format(self.PCIE_BRIDGE_PORT, pcie_express_cap_ofset, hex(value)), host=self.dut_hostname).run()

    def get_pcie_express_ext_cap_ofset(self):
        res = Command(cmd="sudo lspci -s {} -vvvv".format(self.PCIE_BRIDGE_PORT), host=self.dut_hostname).run()
        str = "\n".join(res["output"])
        re_pcie_express_ext_cap_ofset = re.compile(r".+\[(\w+)[..\s].*]\s\#19")
        m = re_pcie_express_ext_cap_ofset.search(str)
        pcie_express_ext_cap_ofset = ""
        if m:
            pcie_express_ext_cap_ofset = m.group(1)
            log.info("found pcie_express_ext_cap_ofset from lspci output: {}".format(pcie_express_ext_cap_ofset))
            return pcie_express_ext_cap_ofset
        else:
            raise Exception("PCI express Extended Capability ofset not found")

    def get_link_control_3_register(self, pcie_express_ext_cap_ofset):
        res = Command(cmd="sudo setpci -s {} 0x{}+0x4.W".\
            format(self.PCIE_BRIDGE_PORT, pcie_express_ext_cap_ofset), host=self.dut_hostname).run()

        link_control_3_register = int(res["output"][0], 16)
        return link_control_3_register

    def set_link_control_3_register(self, pcie_express_ext_cap_ofset, value):
        res = Command(cmd="sudo setpci -s {} 0x{}+0x4.W={}".\
            format(self.PCIE_BRIDGE_PORT, pcie_express_ext_cap_ofset, hex(value)), host=self.dut_hostname).run()

    def init_gen_change_speed(self, i, eq_bit=False):
        log.info("Start PCIe Link Speed change")

        # get pcie_express_cap_ofset from lspci output
        pcie_express_cap_ofset = self.get_pcie_express_cap_ofset()
        # get link control 2 register
        link_control2_register = self.get_link_control2_register(pcie_express_cap_ofset)
        if link_control2_register & 0b1111 != 0b0100:
            raise Exception("Initial target link speed != 16GT/s : link_control2_register = {}".\
            format(link_control2_register))
        # set 8GT/s in target link speed field in link control 2 register
        link_control2_register = ((link_control2_register >> 4) << 4) | 0b0011
        log.info("set 8GT/s in target link speed field in link control 2 register = {}".\
                format(bin(link_control2_register)))

        self.set_link_control2_register(pcie_express_cap_ofset, link_control2_register)
        # get link control register
        link_control_register = self.get_link_control_register(pcie_express_cap_ofset)
        # set retrain link bit in link control register
        link_control_register = link_control_register | 0b100000
        log.info("set retrain link bit in link control register = {}".format(bin(link_control_register)))

        self.start_poll_ltsmm()
        time.sleep(2)
        self.set_link_control_register(pcie_express_cap_ofset, link_control_register)
        time.sleep(1)
        self.stop_poll_ltsmm(i, state="for_8GTS_neg")

        # check PCIe link speed 8GT/s
        self.verify_pcie_gen_and_width(gen="3")

        if eq_bit:
            # get pcie_express_ext_cap_ofset from lspci output
            pcie_express_ext_cap_ofset = self.get_pcie_express_ext_cap_ofset()
            # get link control 3 register
            link_control_3_register = self.get_link_control_3_register(pcie_express_ext_cap_ofset)
            # set Perform Equalization bit in link control 3 register
            link_control_3_register = link_control_3_register | 0b1
            log.info("set Perform Equalization bit in link control 3 register = {}".format(bin(link_control_3_register)))
            self.set_link_control_3_register(pcie_express_ext_cap_ofset, link_control_3_register)

        # get link control 2 register
        link_control2_register = self.get_link_control2_register(pcie_express_cap_ofset)
        if link_control2_register & 0b1111 != 0b0011:
            raise Exception("Current target link speed != 8GT/s, link_control2_register = {}".format(link_control2_register))

        # set 16GT/s in target link speed field in link control 2 register
        link_control2_register = ((link_control2_register >> 4) << 4) | 0b0100
        log.info("set 16GT/s in target link speed field in link control 2 register = {}".format(bin(link_control2_register)))
        self.set_link_control2_register(pcie_express_cap_ofset, link_control2_register)
        # get link control register
        link_control_register = self.get_link_control_register(pcie_express_cap_ofset)
        # set retrain link bit in link control register
        link_control_register = link_control_register | 0b100000
        log.info("set retrain link bit in link control register = {}".format(bin(link_control_register)))

        self.start_poll_ltsmm()
        time.sleep(2)
        self.set_link_control_register(pcie_express_cap_ofset, link_control_register)
        time.sleep(1)
        self.stop_poll_ltsmm(i, state="for_16GTS_neg")

        # check PCIe link speed 16GT/s
        self.verify_pcie_gen_and_width(gen="4")


    def _cold_restart(self, i):
        from tools import pcontrol, power
        log.info("Requesting cold restart of host '{}' via power control".format(self.dut_hostname))
        pcontrol.PControl().cold(self.dut_hostname, 20000, -5)
        time.sleep(5)  # let agent to send stdout to ATF

        # self.start_poll_ltsmm()
        power.Power(host=self.dut_hostname).shutdown()
        log.info("Sleeping {} seconds until system going to shut down".format(self.POWER_DOWN_TIMEOUT))
        time.sleep(self.POWER_DOWN_TIMEOUT)

        if not self.poll_host_alive(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("Cold restart of host {} is failed (host didn't turn on)".format(self.dut_hostname))
        log.info("Host {} is alive, waiting for agent to start".format(self.dut_hostname))
        # self.stop_poll_ltsmm(i)

        if not self.poll_host_alive_and_ready(self.dut_hostname, self.POWER_UP_TIMEOUT):
            raise Exception("Cold restart of host {} is failed (agent failed to start)".format(self.dut_hostname))


    def verify_card_after_start(self):
        # self.verify_ltssm()
        self.verify_device_is_present()
        self.verify_pcie_gen_and_width()
        # self.verify_heart_beat()
        # self.verify_link_up()
        # log.info("Sleep before ping.")
        # time.sleep(self.BEFORE_PING_DELAY)
        # self.verify_ping()

    def verify_reboot(self, i):
        log.info("Call warm reboot")
        # self.start_poll_ltsmm()
        self.dut_power.reboot()
        time.sleep(self.AFTER_TURNOFF_DELAY)
        if not self.poll_host_alive_and_ready(self.dut_hostname, 120):
            raise Exception("Failed to reboot DUT")
        # self.stop_poll_ltsmm(i)
        self.verify_card_after_start()
        # self.process_data(i)
        # self.dump_phy(i)

    def verify_cold_boot(self, i):
        log.info("Call cold boot")
        self._cold_restart(i)
        self.verify_card_after_start()
        # self.process_data(i)
        # self.dump_phy(i)

    def verify_hot_reset(self, i):
        log.info("Call hot reset")
        # self.start_poll_ltsmm()
        self.init_hot_reset(i)
        # self.stop_poll_ltsmm(i)
        self.verify_card_after_start()
        # self.process_data(i)
        # self.dump_phy(i)

    def verify_gen_speed_change(self, i):
        log.info("Call Gen4 speed change")
        # self.start_poll_ltsmm()
        self.init_gen_change_speed(i)
        # self.stop_poll_ltsmm(i)
        self.verify_card_after_start()
        # self.process_data(i)
        # self.dump_phy(i)

    def verify_gen_speed_change_eq_bit(self, i):
        log.info("Call Gen4 speed change with Eq bit")
        self.start_poll_ltsmm()
        self.init_gen_change_speed(i, eq_bit=True)
        self.stop_poll_ltsmm(i)
        self.verify_card_after_start()
        self.process_data(i)
        # self.dump_phy(i)