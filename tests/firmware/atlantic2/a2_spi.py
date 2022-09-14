import ctypes
import os
import struct
import sys
import time
import timeit

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import pytest

from infra.test_base import TestBase, idparametrize

from tools.driver import Driver, DRV_TYPE_DIAG
from tools.atltoolper import AtlTool
from tools.ctypes_struct_helper import hal_reg_factory
from tools.command import Command
from tools.utils import get_atf_logger

log = get_atf_logger()

################################################################################
# Constants
################################################################################

SPI_DMA_MODE_MAILBOX = 0
SPI_DMA_MODE_BUFFER = 1
SPI_DMA_MODE_DC = 2

SPI_DMA_STATE_IDLE = 0
SPI_DMA_STATE_START_WAIT = 1
SPI_DMA_STATE_START = 2
SPI_DMA_STATE_ADDR = 3
SPI_DMA_STATE_DATA = 4
SPI_DMA_STATE_DONE_WAIT = 5
SPI_DMA_STATE_HOLD = 6
SPI_DMA_STATE_RESET = 7

WINBOND_OPCODES = {
    "read_data": 0x03,
    "fast_read": 0x0B,
    "fast_read_dual_output": 0x3B
}

SPI_DMA_BUFFER0_ADDR = 0x14800
SPI_DMA_BUFFER1_ADDR = 0x14840

################################################################################
# HAL registers
################################################################################

SPI_DMA_State_bits = [
    ("PIF_SPI_DMA_State", ctypes.c_uint32, 3),
    ("Reserved", ctypes.c_uint32, 29)
]

SPI_DMA_Mode_bits = [
    ("PIF_SPI_DMA_Mode", ctypes.c_uint32, 2),
    ("Reserved", ctypes.c_uint32, 30)
]

SPI_DMA_Reset_bits = [
    ("pif_spi_dma_reset", ctypes.c_uint32, 1),
    ("Reserved", ctypes.c_uint32, 31)
]

SPI_DMA_Config_bits = [
    ("SPI_DMA_OPCODE", ctypes.c_uint32, 8),
    ("SPI_DMA_Clock_Divide", ctypes.c_uint32, 8),
    ("SPI_DMA_Address_Length", ctypes.c_uint32, 2),
    ("Reserved0", ctypes.c_uint32, 2),
    ("SPI_DMA_Dummy_Length", ctypes.c_uint32, 3),
    ("Reserved1", ctypes.c_uint32, 1),
    ("SPI_DMA_fast_mode", ctypes.c_uint32, 1),
    ("Reserved2", ctypes.c_uint32, 7)
]

SPI_DMA_Status_1_bits = [
    ("pif_spi_dma_curr_num_xfers", ctypes.c_uint32, 20),
    ("Reserved0", ctypes.c_uint32, 4),
    ("SPI_DMA_Buf0_Data_Rdy", ctypes.c_uint32, 1),
    ("SPI_DMA_Buf1_Data_Rdy", ctypes.c_uint32, 1),
    ("Reserved1", ctypes.c_uint32, 6)
]

SPI_DMA_Address_bits = [
    ("pif_spi_dma_start_addr", ctypes.c_uint32, 24),
    ("Reserved", ctypes.c_uint32, 8)
]

SPI_DMA_Num_Xfers_bits = [
    ("pif_spi_dma_num_xfers", ctypes.c_uint32, 20),
    ("Reserved", ctypes.c_uint32, 12)
]

SPI_DMA_Control_bits = [
    ("pif_spi_dma_start", ctypes.c_uint32, 1),
    ("pif_spi_dma_done", ctypes.c_uint32, 1),
    ("pif_spi_dma_data_avail", ctypes.c_uint32, 1),
    ("Reserved0", ctypes.c_uint32, 13),
    ("SPI_DMA_Buf0_Read_ACK", ctypes.c_uint32, 1),
    ("SPI_DMA_Buf1_Read_ACK", ctypes.c_uint32, 1),
    ("Reserved1", ctypes.c_uint32, 14)
]

SPI_DMA_Data_Read_bits = [
    ("pif_spi_dma_read_data", ctypes.c_uint32, 32)
]

Global_NVR_Provisioning_3_bits = [
    ("SPI_AHB_Opcode", ctypes.c_uint32, 8),
    ("SPI_AHB_Clock_Divide", ctypes.c_uint32, 8),
    ("SPI_AHB_Address_Length", ctypes.c_uint32, 2),
    ("Reserved0", ctypes.c_uint32, 2),
    ("SPI_AHB_Dummy_Length", ctypes.c_uint32, 3),
    ("Reserved1", ctypes.c_uint32, 1),
    ("SPI_AHB_Data_Length", ctypes.c_uint32, 3),
    ("Reserved2", ctypes.c_uint32, 5)
]

SPI_DMA_State = hal_reg_factory(0x38, SPI_DMA_State_bits)
SPI_DMA_Mode = hal_reg_factory(0x3C, SPI_DMA_Mode_bits)
SPI_DMA_Reset = hal_reg_factory(0x40, SPI_DMA_Reset_bits)
SPI_DMA_Config = hal_reg_factory(0x44, SPI_DMA_Config_bits)
SPI_DMA_Status_1 = hal_reg_factory(0x4C, SPI_DMA_Status_1_bits)
SPI_DMA_Address = hal_reg_factory(0x50, SPI_DMA_Address_bits)
SPI_DMA_Num_Xfers = hal_reg_factory(0x54, SPI_DMA_Num_Xfers_bits)
SPI_DMA_Control = hal_reg_factory(0x58, SPI_DMA_Control_bits)
SPI_DMA_Data_Read = hal_reg_factory(0x5C, SPI_DMA_Data_Read_bits)
Global_NVR_Provisioning_3 = hal_reg_factory(0x538, Global_NVR_Provisioning_3_bits)


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_spi"


class TestA2SPI(TestBase):
    @classmethod
    def setup_class(cls):
        super(TestA2SPI, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.dut_driver = Driver(port=cls.dut_port, version="latest", host=cls.dut_hostname,
                                    drv_type=DRV_TYPE_DIAG)
            cls.dut_driver.install()
            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)

            cls.SPI_DMA_State = SPI_DMA_State(cls.dut_atltool_wrapper)
            cls.SPI_DMA_Mode = SPI_DMA_Mode(cls.dut_atltool_wrapper)
            cls.SPI_DMA_Reset = SPI_DMA_Reset(cls.dut_atltool_wrapper)
            cls.SPI_DMA_Config = SPI_DMA_Config(cls.dut_atltool_wrapper)
            cls.SPI_DMA_Status_1 = SPI_DMA_Status_1(cls.dut_atltool_wrapper)
            cls.SPI_DMA_Address = SPI_DMA_Address(cls.dut_atltool_wrapper)
            cls.SPI_DMA_Num_Xfers = SPI_DMA_Num_Xfers(cls.dut_atltool_wrapper)
            cls.SPI_DMA_Control = SPI_DMA_Control(cls.dut_atltool_wrapper)
            cls.SPI_DMA_Data_Read = SPI_DMA_Data_Read(cls.dut_atltool_wrapper)
            cls.Global_NVR_Provisioning_3 = Global_NVR_Provisioning_3(cls.dut_atltool_wrapper)

            cls.burn_pattern_to_flash()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def burn_pattern_to_flash(cls):
        cls.pattern_dwords = []

        for i in range(2 * 1024 * 1024 / 4):
            dw = ((i & 0xFFFF) << 16) | (i & 0xFFFF)
            cls.pattern_dwords.append(dw)

        with open("test_pattern.clx", "wb") as clx_fp:
            for i in range(len(cls.pattern_dwords)):
                clx_fp.write(struct.pack("<I", cls.pattern_dwords[i]))

        # Reset to release flash interface
        cls.dut_atltool_wrapper.writereg(0x3000, 0x1)
        time.sleep(3)

        res = Command(cmd="sudo flashBurn2 -d {} \
            test_pattern.clx".format(cls.dut_atltool_wrapper.pciutil_port)).run_join(180)
        if res["returncode"] != 0:
            raise Exception("Failed to burn test pattern to FLASH")

        # Perform reset to kill currently running FW and exit to RBL
        cls.dut_atltool_wrapper.writereg(0x3000, 0x1)
        time.sleep(1)

    @classmethod
    def teardown_class(cls):
        super(TestA2SPI, cls).teardown_class()

    def setup_method(self, method):
        super(TestA2SPI, self).setup_method(method)

    def teardown_method(self, method):
        super(TestA2SPI, self).teardown_method(method)
        self.dut_atltool_wrapper.silent = False

    def reset_spi_dma(self):
        self.SPI_DMA_Reset.bits.pif_spi_dma_reset = 1
        self.SPI_DMA_Reset.write()

        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time < 1.0:
            self.SPI_DMA_State.read()
            if self.SPI_DMA_State.bits.PIF_SPI_DMA_State == SPI_DMA_STATE_IDLE:
                log.info("SPI DMA reset completed. Time: {:.10f} s".format(timeit.default_timer() - start_time))
                return

        raise Exception("SPI DMA reset timeout")

    def configire_spi_dma(self, opcode, clock_div, dummy_len, fast_mode):
        self.SPI_DMA_Config.bits.SPI_DMA_OPCODE = opcode
        self.SPI_DMA_Config.bits.SPI_DMA_Clock_Divide = clock_div
        self.SPI_DMA_Config.bits.SPI_DMA_Address_Length = 3
        self.SPI_DMA_Config.bits.SPI_DMA_Dummy_Length = dummy_len
        self.SPI_DMA_Config.bits.SPI_DMA_fast_mode = fast_mode
        self.SPI_DMA_Config.write()

    def read_spi_dma(self, mode, addr, dw_count):
        assert mode in [SPI_DMA_MODE_MAILBOX, SPI_DMA_MODE_BUFFER]

        if mode == SPI_DMA_MODE_BUFFER:
            assert dw_count % 16 == 0, "SPI DMA can only read 16 dwords at a time"

        self.SPI_DMA_State.read()
        if self.SPI_DMA_State.bits.PIF_SPI_DMA_State != SPI_DMA_STATE_IDLE:
            raise Exception("Wrong SPI DMA state: {}".format(self.SPI_DMA_State.bits.PIF_SPI_DMA_State))

        self.SPI_DMA_Mode.bits.PIF_SPI_DMA_Mode = mode
        self.SPI_DMA_Mode.write()

        self.SPI_DMA_Address.bits.pif_spi_dma_start_addr = addr
        self.SPI_DMA_Address.write()

        self.SPI_DMA_Num_Xfers.bits.pif_spi_dma_num_xfers = dw_count
        self.SPI_DMA_Num_Xfers.write()

        self.SPI_DMA_Control.dword = 0
        self.SPI_DMA_Control.bits.pif_spi_dma_start = 1
        self.SPI_DMA_Control.write()

        read_data = []

        dma_done = False
        read_done = False
        next_buff_idx = 0

        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time < dw_count * 0.05:
            if len(read_data) > dw_count:
                log.error("SPI DMA is not finished when expected")
                self.SPI_DMA_State.read()
                self.SPI_DMA_Status_1.read()
                log.error("SPI DMA wants to read {} \
                    more dwords".format(self.SPI_DMA_Status_1.bits.pif_spi_dma_curr_num_xfers))
                log.error("Current SPI DMA state: {}".format(self.SPI_DMA_State.bits.PIF_SPI_DMA_State))
                raise Exception("SPI DMA is not finished when expected")

            if mode == SPI_DMA_MODE_MAILBOX:
                self.SPI_DMA_Control.read()

                if self.SPI_DMA_Control.bits.pif_spi_dma_data_avail == 1:
                    self.SPI_DMA_Data_Read.read()
                    read_data.append(self.SPI_DMA_Data_Read.bits.pif_spi_dma_read_data)

                if self.SPI_DMA_Control.bits.pif_spi_dma_done == 1:
                    break
            elif mode == SPI_DMA_MODE_BUFFER:
                if not dma_done:
                    self.SPI_DMA_Control.read()
                    if self.SPI_DMA_Control.bits.pif_spi_dma_done == 1:
                        dma_done = True

                self.SPI_DMA_Status_1.read()

                if next_buff_idx == 0 and self.SPI_DMA_Status_1.bits.SPI_DMA_Buf0_Data_Rdy == 1:
                    for i in range(16):
                        read_data.append(self.dut_atltool_wrapper.readreg(SPI_DMA_BUFFER0_ADDR + i * 4))

                    self.SPI_DMA_Control.dword = 0
                    self.SPI_DMA_Control.bits.SPI_DMA_Buf0_Read_ACK = 1
                    self.SPI_DMA_Control.write()

                    next_buff_idx = 1

                if next_buff_idx == 1 and self.SPI_DMA_Status_1.bits.SPI_DMA_Buf1_Data_Rdy == 1:
                    for i in range(16):
                        read_data.append(self.dut_atltool_wrapper.readreg(SPI_DMA_BUFFER1_ADDR + i * 4))

                    self.SPI_DMA_Control.dword = 0
                    self.SPI_DMA_Control.bits.SPI_DMA_Buf1_Read_ACK = 1
                    self.SPI_DMA_Control.write()

                    next_buff_idx = 0

                if len(read_data) == dw_count:
                    read_done = True

                if dma_done and read_done:
                    break
        else:
            log.error("Timeout waiting for SPI DMA Done bit")
            self.SPI_DMA_State.read()
            log.error("Current SPI DMA State: {}".format(self.SPI_DMA_State.bits.PIF_SPI_DMA_State))
            raise Exception("Timeout waiting for SPI DMA Done bit")

        if len(read_data) == dw_count:
            return read_data
        else:
            log.error("SPI DMA finished too early")
            log.error("Expected to read {} dwords, read only {}".format(dw_count, len(read_data)))
            raise Exception("SPI DMA finished too early")

    def configure_spi_ahb(self, opcode, clock_div, dummy_len):
        self.Global_NVR_Provisioning_3.bits.SPI_AHB_Opcode = opcode
        self.Global_NVR_Provisioning_3.bits.SPI_AHB_Clock_Divide = clock_div
        self.Global_NVR_Provisioning_3.bits.SPI_AHB_Address_Length = 3
        self.Global_NVR_Provisioning_3.bits.SPI_AHB_Dummy_Length = dummy_len
        self.Global_NVR_Provisioning_3.bits.SPI_AHB_Data_Length = 4
        self.Global_NVR_Provisioning_3.write()

    def test_sanity_mailbox_buffer_read(self):
        self.reset_spi_dma()
        self.configire_spi_dma(WINBOND_OPCODES["read_data"], 0x14, 0, 0)

        read_data_mailbox = self.read_spi_dma(SPI_DMA_MODE_MAILBOX, 0, 32)
        read_data_buffer = self.read_spi_dma(SPI_DMA_MODE_BUFFER, 0, 32)

        for i in range(32):
            if not (read_data_mailbox[i] == read_data_buffer[i] == self.pattern_dwords[i]):
                log.error("Data mismatch:")
                log.error("Expected:        {:08X}".format(self.pattern_dwords[i]))
                log.error("SPI DMA Mailbox: {:08X}".format(self.pattern_dwords[i]))
                log.error("SPI DMA Buffer:  {:08X}".format(self.pattern_dwords[i]))
                raise Exception("Read data mismatch")

    @idparametrize("fast_mode", [False, True])
    @idparametrize("clock_div", [0x1, 0x2, 0x14, 0xC, 0x8, 0x6, 0x4, 0x3])
    @idparametrize("opcode", ["read_data", "fast_read", "fast_read_dual_output"])
    # @idparametrize("opcode,clock_div,fast_mode", [("fast_read_dual_output", 0xA, True)])
    def test_spi_dma_buffer(self, opcode, clock_div, fast_mode):
        if clock_div in [0x1, 0x2]:
            pytest.skip()
        self.reset_spi_dma()
        dummy_len = 1 if opcode != "read_data" else 0
        self.configire_spi_dma(WINBOND_OPCODES[opcode], clock_div, dummy_len, int(fast_mode))

        log.info("Configured SPI DMA with next parameters:")
        log.info("Clock Divide = 0x{:02X}".format(clock_div))
        log.info("Flash Read Opcode = 0x{:02X} (dummy length {})".format(WINBOND_OPCODES[opcode], dummy_len))
        log.info("Fast Mode Enabled = {}".format(fast_mode))

        self.dut_atltool_wrapper.silent = True

        iterations = 100
        total_time = 0
        correct_reads = 0

        for i in range(iterations):
            start_time = timeit.default_timer()
            read_data = self.read_spi_dma(SPI_DMA_MODE_BUFFER, 0, len(self.pattern_dwords))
            end_time = timeit.default_timer()

            if read_data == self.pattern_dwords:
                total_time += end_time - start_time
                correct_reads += 1

        log.info("Total correct reads: {} out of {}".format(correct_reads, iterations))
        log.info("Success rate: {:.2f}%".format(100.0 * correct_reads / iterations))
        if clock_div == 0x3:
            if correct_reads != 100:
                pytest.xfail(reason="Expected fail for small clock div")
        log.info("Mean read time: {:.10f}".format(total_time / correct_reads))

        if correct_reads != iterations:
            raise Exception("Not all reads were successfull")

    @idparametrize("clock_div", [0x1, 0x2, 0x14, 0xC, 0x8, 0x6, 0x4, 0x3])
    @idparametrize("opcode", ["read_data", "fast_read", "fast_read_dual_output"])
    # @idparametrize("opcode,clock_div", [("read_data", 0x2)])
    def test_spi_ahb_bar4(self, opcode, clock_div):
        if clock_div in [0x1, 0x2]:
            pytest.skip()
        dummy_len = 1 if opcode != "read_data" else 0
        self.configure_spi_ahb(WINBOND_OPCODES[opcode], clock_div, dummy_len)

        log.info("Configured SPI AHB with next parameters:")
        log.info("Clock Divide = 0x{:02X}".format(clock_div))
        log.info("Flash Read Opcode = 0x{:02X} (dummy length {})".format(WINBOND_OPCODES[opcode], dummy_len))

        log.info("Trying to read first 32 dwords from BAR4...")
        read_data = self.dut_atltool_wrapper.read_bar4(0, 32 * 4)
        assert read_data == self.pattern_dwords[:32], "Read data mismatch"
        log.info("Reading the rest of test data from BAR4...")
        read_data.extend(self.dut_atltool_wrapper.read_bar4(32 * 4, (len(self.pattern_dwords) - 32) * 4))
        assert read_data == self.pattern_dwords, "Read data mismatch"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
