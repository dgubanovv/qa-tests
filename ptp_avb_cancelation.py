import os
import pytest
import re
import shutil
import time

from tools import ifconfig
from tools.utils import get_atf_logger
from tools.power import Power
from tools import command
from tools.killer import Killer
from tools import constants
from tools import virtual_audio
from tools.macos_ptp_avb_base import TestMacPtpAvbBase
from tools.driver import Driver
from tools import atltoolper


log = get_atf_logger()


def setup_module(module): 
    os.environ["TEST"] = "ptp_avb_cancelation"


class TestMacPtpAvbCancelation(TestMacPtpAvbBase):
    STREAM_TIME = 60
    DTRACE = bool(os.environ.get("DTRACE", False))
    MEMORY = bool(os.environ.get("MEMORY", False))
    RETRY_CNT = 3
    SLEEP_AFTER_STREAM_STOPPING = 30
    RING_HEADS = [0x7c0c, 0x7e0c, 0x800c, 0x820c]
    RING_TAILS = [0x7c10, 0x7e10, 0x8010, 0x8210]
    TPB_REGISTERS = [0x7918 + 0 * 0x10, 0x7918 + 1 * 0x10, 0x7918 + 2 * 0x10, 0x7918 + 3 * 0x10, ]
    MEM_ADDRESSES = [0x1fb16658, 0x1fb17ed4]
    MEM_SIZES = [0x380, 0x8060]
    MEMS = zip(MEM_ADDRESSES, MEM_SIZES)
    ROUND_TRIP_LIMIT = 2000
    SKIP_INSTALL = bool(os.environ.get("SKIP_INSTALL", False))
    CHECK_NUMBER = 3

    @classmethod
    def setup_class(cls):
        super(TestMacPtpAvbCancelation, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.dut_power = Power()
            cls.lkp_power = Power(host=cls.lkp_hostname)
            cls.dut_killer = Killer()
            cls.lkp_killer = Killer(host=cls.lkp_hostname)
            cls.NETMASK_IPV4 = "255.255.0.0"
            if not cls.state.skip_class_setup:
                if not cls.SKIP_INSTALL:
                    cls.install_firmwares()
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
                    cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
                    cls.lkp_driver.install()
                    cls.dut_driver.install()

                log.debug("WORKING_DIR: {}".format(cls.working_dir))
                cls.state.skip_class_setup = True
                cls.state.update()
                cls.lkp_power.reboot()
                cls.dut_power.reboot()
                time.sleep(30)
            else:
                cls.DUT_IPV4_ADDR = cls.suggest_test_ip_address(cls.dut_port)
                cls.LKP_IPV4_ADDR = cls.suggest_test_ip_address(cls.lkp_port, cls.lkp_hostname)
                if cls.LKP_IPV4_ADDR == cls.DUT_IPV4_ADDR:
                    octets = cls.LKP_IPV4_ADDR.split(".")
                    octets[-1] = str(int(octets[-1]) + 1)
                    cls.LKP_IPV4_ADDR = ".".join(octets)
                cls.dut_virtual_audio = virtual_audio.VirtualAudio(port=cls.dut_port)
                cls.lkp_virtual_audio = virtual_audio.VirtualAudio(host=cls.lkp_hostname, port=cls.lkp_port)
                cls.dut_atltool = atltoolper.AtlTool(port=cls.dut_port)
                cls.start_time = None

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e
        
    def teardown_method(self, method):
        super(TestMacPtpAvbCancelation, self).teardown_method(method)
        self.lkp_killer.kill("avbstreamtx")
        self.lkp_killer.kill("avbstreamrx")
        virtual_audio.VirtualAudio(host=self.lkp_hostname, port=self.lkp_port).disable_virtual_audio()

    def setup_method(self, method):
        super(TestMacPtpAvbCancelation, self).setup_method(method)
        self.lkp_killer.kill("avbstreamtx")
        self.lkp_killer.kill("avbstreamrx")
        virtual_audio.VirtualAudio(host=self.lkp_hostname, port=self.lkp_port).disable_virtual_audio()

    def check_rings_head_equals_tail(self, host, iface, ring_nums=range(4)):
        regex = re.compile("^Size\s+(\d+)\s+Head\s+(\d+)\s+Tail\s+(\d+)\s+Pending\s+(\d+)$")
        head_tails = []
        for ring in xrange(len(self.RING_HEADS)):
            output = command.Command(
                cmd="sudo aeaa_util rings -i {} -t{} | grep Head".format(iface, ring),
                host=host
            ).run_join(5)["output"]
            match = None
            for line in output:
                match = regex.match(line)
                if match:
                    break
        
            assert match, "Unexpected command output"
            head = match.group(2)
            tail = match.group(3)
            pend = match.group(4)
            log.info("Head = {}; Tail = {}; Pending = {}".format(head, tail, pend))
            head_tails.append((head, tail, pend))
        additional_regs = range(0x368, 0x37c + 1, 4)

        log.info("READING RING REGISTERS")

        results = {reg: self.dut_atltool.readreg(reg) for reg in self.RING_HEADS}
        # Wait for possible tail update
        time.sleep(5)
        for reg in self.RING_TAILS:
            results.update({reg: self.dut_atltool.readreg(reg)})
        additional_results_1 = {}
        additional_results_2 = {}
        log.info("READING ADDITIONAL REGISTERS")
        for reg in additional_regs:
            additional_results_1.update({reg: self.dut_atltool.readreg(reg)})
        for reg in additional_regs:
            additional_results_2.update({reg: self.dut_atltool.readreg(reg)})

        if self.MEMORY:
            mems = {}
            for mem_address, mem_size in self.MEMS:
                mems.update({mem_address: self.dut_atltool.readmem(mem_address, mem_size)})

        log.info("READING TPB")

        tpb_results = {}
        for reg in self.TPB_REGISTERS:
            # TPB registers should be read twice due to BLH bits
            self.dut_atltool.readreg(reg)
            tpb_results.update({reg: self.dut_atltool.readreg(reg)})

        log.info("-----------------------REPORT-----------------------------")
        # for head, tail, pend in head_tails:
        #     log.info("Head: {}; Tail: {}; Pending: {}".format(head, tail, pend))
        log.info("Ring registers:")
        for head, tail in zip(self.RING_HEADS, self.RING_TAILS):
            head_val = results[head]
            tail_val = results[tail]
            log.info("Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                head, 
                head_val, 
                (head_val >> 24) & 0xFF, 
                (head_val >> 16) & 0xFF, 
                (head_val >> 8) & 0xFF, 
                head_val & 0xFF)
            )
            log.info("Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                tail,
                tail_val,
                (tail_val >> 24) & 0xFF,
                (tail_val >> 16) & 0xFF,
                (tail_val >> 8) & 0xFF,
                tail_val & 0xFF)
            )

        log.info("Additional registers:")
        for reg in additional_regs:
            val = additional_results_1[reg]
            log.info("Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))
        for reg in additional_regs:
            val = additional_results_2[reg]
            log.info("Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))

        if self.MEMORY:
            log.info("Memory data:")
            for num, mem_address in enumerate(self.MEM_ADDRESSES, start=0):
                log.info(
                    "{} bytes of MCP memory data at address {}:\n{}".format(
                        hex(self.MEM_SIZES[num]),
                        "0x{:08x}".format(mem_address),
                        ["0x{:08x}".format(item) for item in mems[mem_address]]
                    )
                )
        log.info("TPB registers:")
        for reg in self.TPB_REGISTERS:
            val = tpb_results[reg]
            log.info("Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(
                reg, val, (val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF))

        log.info("-----------------------REPORT-----------------------------")
        time.sleep(10)

        for ring_num, (head, tail) in enumerate(zip(self.RING_HEADS, self.RING_TAILS)):
            if ring_num in ring_nums:
                head_val = results[head]
                tail_val = results[tail]

                head_high_word = tail_val & 0xffff0000 >> 16
                head_low_word = tail_val & 0xffff
                tail_low_word = head_val & 0xffff

                assert tail_low_word == head_high_word == head_low_word, \
                    "Hardware head-tail mismatch: {} == {} == {}".format(tail_low_word, head_high_word, head_low_word)

        # Remove after fix from driver team
        skip_rings = [0, 3]
        log.warning("SKIPPED RINGS: {}".format(skip_rings))
        for num, values in enumerate(head_tails):
            if num not in skip_rings:
                head, tail, pend = values
                assert head == tail

    def get_mcp_log(self, collect_time=5):
        if self.MCP_LOG is True:
            bin_file, txt_file = self.dut_atltool.debug_buffer_enable(True)
            time.sleep(collect_time)
            self.dut_atltool.debug_buffer_enable(False)
            if os.path.exists(self.mcp_log_file):
                cmd = command.Command(cmd="cat {} >> {}".format(txt_file, self.mcp_log_file))
            else:
                cmd = command.Command(cmd="cat {} > {}".format(txt_file, self.mcp_log_file))
            cmd.run_join(10)
            command.Command(cmd='cat {}'.format(self.mcp_log_file)).run_join(10)
            shutil.copy(bin_file, self.test_log_dir)
            shutil.copy(txt_file, self.test_log_dir)
            time.sleep(2)
    
    def setup_link(self, speed):
        self.dut_ifconfig.set_link_speed(speed)
        self.lkp_ifconfig.set_link_speed(speed)
        self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, self.NETMASK_IPV4, None)
        self.lkp_ifconfig.set_ip_address(self.LKP_IPV4_ADDR, self.NETMASK_IPV4, None)
        self.dut_ifconfig.set_link_state(constants.LINK_STATE_UP)
        self.lkp_ifconfig.set_link_state(constants.LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        
    def link_down(self, speed):
        """
        Test scenario:

        1) Configure link on both sides
        2) Enable virtual-audio on DUT
        3) Start collecting system logs
        4) Wait self.stream_time
        5) Stop collecting logs
        6) Check pdelays if ptp is synced
        7) Make link down on LKP
        8) Check rings
        9) Start collecting system logs
        10) Enable virtual-audio on DUT
        11) Wait self.stream_time
        12) Stop collecting logs
        13) Check pdelays if ptp is synced
        """
        self.mcp_log_file = "/tmp/dummy.log"
        self.get_mcp_log(collect_time=10)
        dut_iface = self.dut_ifconfig.get_conn_name()
        self.setup_link(speed)

        self.get_mcp_log()
        self.mcp_log_file = os.path.join(self.test_log_dir, "mcp_link_down_{}.txt".format(speed))
        for check_num in xrange(self.CHECK_NUMBER):
            self.dut_log_file = os.path.join(
                self.test_log_dir, "dut_log_before_link_down_{}_{}.txt".format(speed, check_num)
            )
            dut_delays_cmd = self.start_delay_log(self.dut_hostname, self.dut_log_file, 1)
            self.dut_virtual_audio.enable_virtual_audio()
            if speed == ifconfig.LINK_SPEED_100M:
                self.dut_virtual_audio.set_avb_device_config(virtual_audio.CONFIG_1_STREAM)
            else:
                self.dut_virtual_audio.set_avb_device_config(virtual_audio.CONFIG_8_STREAMS)

            if self.DTRACE:
                dtrace_file = os.path.join(self.test_log_dir, "dut_dtrace_link_down_{}.txt".format(speed))
                dtrace_cmd = command.Command(
                    cmd="sudo dtrace -s /usr/local/bin/aeaa_script.d -Z -q &> {}".format(dtrace_file)
                )
                dtrace_cmd.run_async()
                time.sleep(7)

            time.sleep(self.STREAM_TIME)
            dut_delays_cmd.join(0)
            self.check_delays(None, None, self.dut_log_file, None, make_plot=False)
            self.lkp_ifconfig.set_link_state(constants.LINK_STATE_DOWN)
            self.lkp_ifconfig.wait_link_down()
            time.sleep(5)
            self.get_mcp_log()

            if self.DTRACE:
                dtrace_cmd.join(0)
                self.dut_killer.kill("dtrace")

            self.check_rings_head_equals_tail(self.dut_hostname, dut_iface)

            self.dut_log_file = os.path.join(
                self.test_log_dir, "dut_log_after_link_down_{}_{}.txt".format(speed, check_num)
            )

            self.lkp_ifconfig.set_link_state(constants.LINK_STATE_UP)
            self.dut_ifconfig.wait_link_up()
            dut_delays_cmd = self.start_delay_log(self.dut_hostname, self.dut_log_file, 1)
            time.sleep(self.STREAM_TIME)
            dut_delays_cmd.join(0)
            # Check if synched
            self.check_delays(None, None, self.dut_log_file, None, make_plot=False)
            self.get_mcp_log()

    def test_link_down_100m(self):
        self.link_down(constants.LINK_SPEED_100M)

    def test_link_down_1g(self):
        self.link_down(constants.LINK_SPEED_1G)

    def stream_stop(self, speed):
        """
        Test scenario:

        1) Configure link on both sides
        2) Enable virtual-audio on DUT
        3) Start collecting system logs
        4) Wait self.stream_time
        5) Stop collecting logs
        6) Check pdelays if ptp is synced
        7) Disable virtual-audio on DUT
        8) Check rings
        9) Start collecting system logs
        10) Enable virtual-audio on DUT
        11) Wait self.stream_time
        12) Stop collecting logs
        13) Check pdelays if ptp is synced
        """
        self.mcp_log_file = "/tmp/dummy.log"
        self.get_mcp_log(collect_time=10)
        dut_iface = self.dut_ifconfig.get_conn_name()
        self.setup_link(speed)
        self.mcp_log_file = os.path.join(self.test_log_dir, "mcp_link_down_{}.txt".format(speed))

        for check_num in xrange(self.CHECK_NUMBER):
            self.dut_log_file = os.path.join(
                self.test_log_dir, "dut_log_before_stream_stop_{}_{}.txt".format(speed, check_num)
            )
            self.mcp_log_file = os.path.join(
                self.test_log_dir, "mcp_stream_stop_{}_{}.txt".format(speed, check_num)
            )
            dut_delays_cmd = self.start_delay_log(self.dut_hostname, self.dut_log_file, 1)

            self.lkp_virtual_audio.enable_virtual_audio()
            if speed == ifconfig.LINK_SPEED_100M:
                self.lkp_virtual_audio.set_avb_device_config(virtual_audio.CONFIG_1_STREAM)
            else:
                self.lkp_virtual_audio.set_avb_device_config(virtual_audio.CONFIG_8_STREAMS)

            if self.DTRACE:
                dtrace_file = os.path.join(self.test_log_dir, "dut_dtrace_stream_stop_{}.txt".format(speed))
                dtrace_cmd = command.Command(
                    cmd="sudo dtrace -s /usr/local/bin/aeaa_script.d -Z -q &> {}".format(dtrace_file)
                )
                dtrace_cmd.run_async()
                time.sleep(7)

            time.sleep(self.STREAM_TIME)
            dut_delays_cmd.join(0)
            # Check if synched
            self.check_delays(None, None, self.dut_log_file, None, make_plot=False)
            self.lkp_virtual_audio.disable_virtual_audio()
            time.sleep(15)
            self.get_mcp_log()

            if self.DTRACE:
                dtrace_cmd.join(0)
                self.dut_killer.kill("dtrace")
            self.check_rings_head_equals_tail(self.dut_hostname, dut_iface, ring_nums=[1, 3])
            self.dut_log_file = os.path.join(
                self.test_log_dir, "dut_log_after_stream_stop_{}_{}.txt".format(speed, check_num)
            )
            self.lkp_virtual_audio.enable_virtual_audio()
            time.sleep(5)
            dut_delays_cmd = self.start_delay_log(self.dut_hostname, self.dut_log_file, 1)
            time.sleep(self.STREAM_TIME)
            dut_delays_cmd.join(0)
            # Check if synched
            self.check_delays(None, None, self.dut_log_file, None, make_plot=False)
            self.get_mcp_log()

    def test_stream_stop_100m(self):
        self.stream_stop(constants.LINK_SPEED_100M)

    def test_stream_stop_1g(self):
        self.stream_stop(constants.LINK_SPEED_1G)

    def change_speed(self, lkp_old_speed, lkp_new_speed):
        """
        Test scenario:

        1) Configure link on both sides
        2) Enable virtual-audio on DUT
        3) Start collecting system logs
        4) Wait self.stream_time
        5) Stop collecting logs
        6) Check pdelays if ptp is synced
        7) Switch link speed
        8) Start collecting system logs
        9) Wait self.stream_time
        10) Stop collecting logs
        11) Check pdelays if ptp is synced
        """
        if lkp_old_speed == lkp_new_speed:
            pytest.skip("Skip changing same speed")

        self.mcp_log_file = "/tmp/dummy.log"
        self.get_mcp_log(collect_time=10)

        self.dut_log_file = os.path.join(
            self.test_log_dir, "dut_log_before_change_speed_{}_{}.txt".format(lkp_old_speed, lkp_new_speed)
        )
        self.mcp_log_file = os.path.join(
            self.test_log_dir, "mcp_change_speed_{}_{}.txt".format(lkp_old_speed, lkp_new_speed)
        )

        self.setup_link(lkp_old_speed)

        self.dut_virtual_audio.enable_virtual_audio()
        if lkp_old_speed == ifconfig.LINK_SPEED_100M:
            self.dut_virtual_audio.set_avb_device_config(virtual_audio.CONFIG_1_STREAM)
        else:
            self.dut_virtual_audio.set_avb_device_config(virtual_audio.CONFIG_8_STREAMS)

        dut_delays_cmd = self.start_delay_log(self.dut_hostname, self.dut_log_file, 1)
        time.sleep(self.STREAM_TIME)
        dut_delays_cmd.join(0)
        # Check if synched
        self.check_delays(None, None, self.dut_log_file, None, make_plot=False)

        # Start dtarce right before link switch
        if self.DTRACE:
            dtrace_file = os.path.join(
                self.test_log_dir, "dut_dtrace_change_speed_{}_{}.txt".format(lkp_old_speed, lkp_new_speed)
            )
            dtrace_cmd = command.Command(
                cmd="sudo dtrace -s /usr/local/bin/aeaa_script.d -Z -q &> {}".format(dtrace_file)
            )
            dtrace_cmd.run_async()
            time.sleep(7)

        self.dut_ifconfig.set_link_speed(lkp_new_speed)
        self.lkp_ifconfig.set_link_speed(lkp_new_speed)
        self.dut_ifconfig.wait_link_up()

        time.sleep(10)
        self.dut_log_file = os.path.join(
            self.test_log_dir, "dut_log_after_change_speed_{}_{}.txt".format(lkp_old_speed, lkp_new_speed)
        )
        self.lkp_log_file = os.path.join(
            self.test_log_dir, "lkp_log_after_change_speed_{}_{}.txt".format(lkp_old_speed, lkp_new_speed)
        )

        dut_delays_cmd = self.start_delay_log(self.dut_hostname, self.dut_log_file, 1)
        time.sleep(self.STREAM_TIME)
        dut_delays_cmd.join(0)
        # Check if synched
        self.check_delays(None, None, self.dut_log_file, None, make_plot=False)

        if self.DTRACE:
            dtrace_cmd.join(0)
            self.dut_killer.kill("dtrace")

        self.get_mcp_log()

    def test_change_speed_100m_1g(self):
        self.change_speed(constants.LINK_SPEED_100M, constants.LINK_SPEED_1G)

    def test_change_speed_1g_100m(self):
        self.change_speed(constants.LINK_SPEED_1G, constants.LINK_SPEED_100M)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
