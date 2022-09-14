import os
import random
import re
import tempfile
import time

import pytest
from smbus import SMBus as SMBusHostWrapper

from tools.atltoolper import AtlTool
from tools.command import Command
from tools.constants import FELICITY_CARDS
from tools.driver import Driver
from tools.ops import OpSystem
from tools.utils import get_atf_logger

from infra.test_base import TestBase

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "felicity_fpga"


class FelicityFpga(object):
    # FPGA registers
    SMBUS_CFG = 0x00
    SMBUS_CMD = 0x01
    SMBUS_TX_DATA = 0x02
    SMBUS_CLOCK_LOW = 0x03
    SMBUS_TIME_OUT_CFG = 0x04
    SMBUS_SLAVE_CFG = 0x05
    SMBUS_TX_DATA1 = 0x06
    SMBUS_TX_DATA2 = 0x07
    SMBUS_SDA_S_H = 0x08
    SMBUS_INT_MASK = 0x09
    SMBUS_CLOCK_HIGH = 0x0A
    SMBUS_TARGET_ADDR = 0x0B
    SMBUS_STATUS1 = 0x10
    SMBUS_STATUS2 = 0x11
    SMBUS_RX_DATA = 0x12
    SMBUS_CRC8 = 0x13
    SMBUS_STATE = 0x14
    SFP_CONTROL = 0x18
    SFP_STATUS = 0x19
    REVISION = 0x1E
    DEBUG = 0x1F

    # SMBus Commands
    SMB_WRITE = 0x00
    SMB_READ = 0x01

    # SMB config bits - smb prov1
    SMB_SLV_STR = (1 << 0x0)
    SMB_FLT_BYPASS = (1 << 0x1)
    MDIO_PRE_DSBL = (1 << 0x2)
    SMB_RESET = (1 << 0x3)
    SMB_SW_ADDR = (1 << 0x4)
    SMB_SCL_FORCE = (1 << 0x5)
    SMB_SDA_FORCE = (1 << 0x6)

    # SMB command bits - smb prov2
    TX_NACK = (1 << 0x0)
    TX_ACK = (0 << 0x0)
    STOP = (1 << 0x1)
    START = (1 << 0x2)
    ARP_EN = (1 << 0x3)
    DATA_REQ_ACK = (1 << 0x4)

    # SMB slave configuration bits - smb prov6
    SLAVE_ADDR1_EN = (1 << 0)  # different from Atlantic
    SLAVE_ADDR1_SHIFT = 1
    SLAVE_ADDR1_MASK = (0x7F << SLAVE_ADDR1_SHIFT)
    SLAVE_ADDR2_EN = (1 << 8)  # different from Atlantic
    SLAVE_ADDR2_SHIFT = 9
    SLAVE_ADDR2_MASK = (0x7F << SLAVE_ADDR2_SHIFT)

    # SMB SDA setup/hold - smb prov9
    SMB_HOLD_SHIFT = 0
    SMB_HOLD_MASK = (0xFF << SMB_HOLD_SHIFT)
    SMB_SETUP_SHIFT = 8
    SMB_SETUP_MASK = (0xFF << SMB_SETUP_SHIFT)

    # SMB status bits
    BUS_IDLE = (1 << 15)
    SLAVE_ACTIVE = (1 << 14)
    DATA_REQUEST = (1 << 13)
    MASTER_ACTIVE = (1 << 12)

    RX_VALID = (1 << 11)
    MTX_EMPTY = (1 << 10)
    STX1_EMPTY = (1 << 9)
    STX2_EMPTY = (1 << 8)

    UNDERRUN = (1 << 7)
    OVERRUN = (1 << 6)
    RX_NACK = (1 << 5)
    LOST_ARB = (1 << 4)

    TIMEOUT = (1 << 3)
    REP_START = (1 << 2)
    STOP_DET = (1 << 1)
    ARP_COL = (1 << 0)

    # SMB status2 bits
    SDA = (1 << 6)
    SCL = (1 << 5)
    DATA_HOLD = (1 << 4)
    ADDR_HOLD = (1 << 3)
    SLAVE2 = (1 << 2)
    BUS_BUSY = (1 << 1)
    S_READ = (1 << 0)

    # SFP control
    SFP_TX_DIS_EN = (1 << 12)
    SFP_RS1_EN = (1 << 9)
    SFP_RS0_EN = (1 << 8)
    SFP_TX_DIS = (1 << 4)
    SFP_RS1 = (1 << 1)
    SFP_RS0 = (1 << 0)

    # SFP status
    SFP_TX_FAULT = (1 << 0)

    # Atlantic MDIO interface
    GLOBAL_CONTROL_2 = 0x0404
    MDIO_CONFIG = 0x0280
    MDIO_CONTROL = 0x0284
    MDIO_WRITE_DATA = 0x0288
    MDIO_ADDRESS = 0x028C
    MDIO_READ_DATA = 0x0290
    PIF_SMB_ALERT = 0x06F4

    MDIO_READ_CMD = 0x9000
    MDIO_WRITE_CMD = 0xA000
    MDIO_ADDRESS_CMD = 0xB000
    MDIO_READ_INC_CMD = 0xD000
    MDIO_BUSY = 0x80000000

    PHY = 0

    CLAUSE45 = (1 << 0)
    CLAUSE22 = (0 << 0)
    PREAMBLE_DISABLE = (1 << 1)
    MDIO_HOLD = (2 << 2)
    MDIO_CLK_DIV = (7 << 5)
    # MDIO_CLK_DIV (16 << 5)

    INT_TIMEOUT = 100000
    SLAVE_1_ADDR = 0x3c

    def __init__(self, atltool_wrapper):
        self.atltool_wrapper = atltool_wrapper

    def readreg(self, addr):
        addr &= 0x1f
        self.atltool_wrapper.writereg(self.MDIO_CONTROL, self.MDIO_READ_CMD | self.PHY << 5 | addr)
        for i in range(10000):
            status = self.atltool_wrapper.readreg(self.MDIO_CONTROL)
            if ~status & self.MDIO_BUSY:
                break
        else:
            raise Exception("Failed to read FPGA register")
        val = self.atltool_wrapper.readreg(self.MDIO_READ_DATA)
        log.info("FPGA Register 0x{:04x}: 0x{:04x} : {:08b} {:08b}".format(addr, val, (val >> 8) & 0xFF, val & 0xFF))
        return val

    def writereg(self, addr, val):
        addr &= 0x1f
        self.atltool_wrapper.writereg(self.MDIO_WRITE_DATA, val)
        self.atltool_wrapper.writereg(self.MDIO_CONTROL, self.MDIO_WRITE_CMD | self.PHY << 5 | addr)
        for i in range(10000):
            status = self.atltool_wrapper.readreg(self.MDIO_CONTROL)
            if ~status & self.MDIO_BUSY:
                log.info("FPGA Register 0x{:04x}: 0x{:04x} written".format(addr, val))
                break
        else:
            raise Exception("Failed to read FPGA register")

    # TODO: 0x3c extract to constant
    def smbus_set_slave_1_address(self, addr=0x3c, enable=True):
        if enable:
            enable_slave_1 = addr << 1 | 1
        else:
            enable_slave_1 = 0
        self.writereg(self.SMBUS_SLAVE_CFG, enable_slave_1)

    def smbus_enumerate(self):
        # enable interrupts
        self.writereg(self.SMBUS_INT_MASK, self.DATA_REQUEST | self.TIMEOUT | self.LOST_ARB)

        # clear out-of-data status
        self.writereg(self.SMBUS_STATUS1, 0xFFFF)  # clears write 1 to clear
        self.readreg(self.SMBUS_STATUS1)  # clears LH and LL bits

        smb_address = 0x08
        smb_addresses_responded = []
        while smb_address < 0xF0:
            self.writereg(self.SMBUS_TARGET_ADDR, smb_address | self.SMB_WRITE)
            self.writereg(self.SMBUS_CMD, self.START)
            for i in range(100000):
                if self.atltool_wrapper.readreg(self.PIF_SMB_ALERT) != 0:
                    break

            status1 = self.readreg(self.SMBUS_STATUS1)
            if status1 & self.DATA_REQUEST:
                self.writereg(self.SMBUS_CMD, self.STOP | self.TX_NACK | self.DATA_REQ_ACK)
                if ~status1 & self.RX_NACK:
                    smb_addresses_responded.append(smb_address)
            else:
                print "status1 = %x" % status1
                if status1 & self.TIMEOUT:
                    raise Exception("Bus timeout")

                if status1 & self.LOST_ARB:
                    raise Exception("Lost arbitration")

            smb_address += 2

        # clear out-of-data status
        self.writereg(self.SMBUS_STATUS1, 0xFFFF)  # clears write 1 to clear
        self.readreg(self.SMBUS_STATUS1)  # clears LH and LL bits

        log.info("Responded addresses: [{}]".format(",".join("0x{:02x}".format(x) for x in smb_addresses_responded)))
        return smb_addresses_responded

    def smbus_wait_interrupt(self):
        # we can't wait forever
        for _ in range(self.INT_TIMEOUT):
            if self.atltool_wrapper.readreg(self.PIF_SMB_ALERT) != 0:
                log.info("SMBus interrupt catched")
                return
        raise Exception("No interrupt")

    def common_init(self):
        # Reset the MIPs processor
        # Clock gate the MIPs CPU subsystem to prevent interference
        self.atltool_wrapper.writereg(self.GLOBAL_CONTROL_2, 0x8000)

        # change to clause 22
        self.atltool_wrapper.writereg(self.MDIO_CONFIG, self.CLAUSE22 | self.MDIO_HOLD | self.MDIO_CLK_DIV)

        # disable preamble
        self.writereg(self.SMBUS_CFG, self.MDIO_PRE_DSBL)
        self.atltool_wrapper.writereg(self.MDIO_CONFIG,
                                      self.CLAUSE22 | self.PREAMBLE_DISABLE | self.MDIO_HOLD | self.MDIO_CLK_DIV)


class TestFelicityFpga(TestBase):
    """
    @description: The felicity FPGA test is dedicated to test SMBus protocol realized in the firmware of FPGA.

    @setup: Filecity card with FPGA.
    """

    SMB_BUS = 6
    DRAM_SMB_ADDRESS = 0x50

    @classmethod
    def setup_class(cls):
        super(TestFelicityFpga, cls).setup_class()

        # Self check
        assert cls.dut_fw_card in FELICITY_CARDS
        assert OpSystem().is_linux() is True

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            dut_driver.uninstall()

            Command(cmd="sudo modprobe i2c-i801").run()

            cls.atltool_wrapper = AtlTool(port=cls.dut_port)
            cls.fpga_wrapper = FelicityFpga(cls.atltool_wrapper)
            cls.fpga_wrapper.common_init()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def smbus_enumerate_from_host(self):
        re_data = re.compile(r"^[0-9a-f]+: ([0-9a-f\- ]{47}).*", re.DOTALL)
        res = Command(cmd="sudo i2cdetect -y 6").run()
        if res["returncode"] != 0:
            raise Exception("Failed to enumerate SMBus")

        smb_addresses_responded = []
        for line in res["output"]:
            m = re_data.match(line)
            if m is not None:
                log.info("'{}'".format(m.group(1)))
                data = m.group(1).rstrip()
                data = data.split(" ")
                for d in data:
                    if "-" in d:
                        continue
                    if d == "":
                        continue
                    smb_addresses_responded.append(int(d, 16))
        return smb_addresses_responded

    def dump_dram_spd(self, bus, addr):
        re_data = re.compile(r"^[0-9a-f]+: ([0-9a-f ]{48}).*", re.DOTALL)
        res = Command(cmd="sudo i2cdump -y {} 0x{:02x}".format(bus, addr)).run()
        if res["returncode"] != 0:
            raise Exception("Failed to dump SPD")

        dump = []
        for line in res["output"]:
            m = re_data.match(line)
            if m is not None:
                data = m.group(1).rstrip()
                data = data.split(" ")
                for d in data:
                    dump.append(int(d, 16))

        return dump

    def test_master_enumerate_bus(self):
        """
        @description: This subtest enumerates all SMBus devices on the bus using FPGA as SMBus master.

        @steps:
        1. Disable slave addresses on FPGA.
        2. Enumerate SMBus devices using i2cdetect.
        3. Enumerate devices using FPGA.
        4. Make sure that both results are equal.

        @result: Devices are correctly enumerated.
        @duration: 3 seconds.
        """
        self.fpga_wrapper.smbus_set_slave_1_address(enable=False)

        addrs_from_host = self.smbus_enumerate_from_host()
        addrs_from_fpga = self.fpga_wrapper.smbus_enumerate()
        for i, addr in enumerate(addrs_from_host):
            assert addr == addrs_from_fpga[i] / 2

    def test_master_read_dram_spd(self):
        """
        @description: This subtest reads DRAM SPD content using FPGA as SMBus master.

        @steps:
        1. Dump DRAM SPD content using i2cdump tool.
        2. Read DRAM SPD content using FPGA.
        3. Compare results.

        @result: Results are equal.
        @duration: 3 seconds.
        """

        length = 256
        spd_data_from_host = self.dump_dram_spd(self.SMB_BUS, self.DRAM_SMB_ADDRESS)
        assert len(spd_data_from_host) == length

        # restart with a read transaction
        self.fpga_wrapper.writereg(FelicityFpga.SMBUS_TARGET_ADDR, self.DRAM_SMB_ADDRESS * 2 | FelicityFpga.SMB_READ)
        self.fpga_wrapper.writereg(FelicityFpga.SMBUS_CMD, FelicityFpga.START | FelicityFpga.DATA_REQ_ACK)

        # each interrupt will return a byte of data
        i = length
        spd_data_from_fpga = []
        while i > 0:
            # and wait for an interupt
            self.fpga_wrapper.smbus_wait_interrupt()

            # check interrupt cause
            status1 = self.fpga_wrapper.readreg(FelicityFpga.SMBUS_STATUS1)
            if ~status1 & FelicityFpga.DATA_REQUEST:
                raise Exception("-9")
            if status1 & FelicityFpga.LOST_ARB:
                raise Exception("Lost arbitration")

            # pick up the returned data
            read_data = self.fpga_wrapper.readreg(FelicityFpga.SMBUS_RX_DATA)

            # last byte has to be NACKed to ensure that we can issue a STOP
            if i == 1:
                self.fpga_wrapper.writereg(FelicityFpga.SMBUS_CMD,
                                           FelicityFpga.STOP | FelicityFpga.TX_NACK | FelicityFpga.DATA_REQ_ACK)
            else:
                self.fpga_wrapper.writereg(FelicityFpga.SMBUS_CMD, FelicityFpga.TX_ACK | FelicityFpga.DATA_REQ_ACK)
            spd_data_from_fpga.append(read_data)

            i -= 1

        time.sleep(2)
        assert spd_data_from_host == spd_data_from_fpga

    def test_slave_write_from_host(self):
        """
        @description: This subtest checks that FPGA (slave mode) can read data propagated from host.

        @steps:
        1. Set FPGA slave 1 address.
        2. In the loop 20 times perform:
            a. Asynchronous write data from host using i2cset tool.
            b. Wait for SMBus interrupt.
            c. Read data from SMBus using FPGA.
            d. Check that readed data is equal to written one.


        @result: Results are equal.
        @duration: 3 seconds.
        """

        nof_reads = 20

        # Enable interrupts
        self.fpga_wrapper.writereg(FelicityFpga.SMBUS_INT_MASK, FelicityFpga.DATA_REQUEST | FelicityFpga.TIMEOUT)

        # Clear out-of-data status
        self.fpga_wrapper.writereg(FelicityFpga.SMBUS_STATUS1, 0xFFFF)  # Write 1 to clear
        self.fpga_wrapper.readreg(FelicityFpga.SMBUS_STATUS1)  # Clears LH and LL bits

        # Activate slave 1 address
        self.fpga_wrapper.smbus_set_slave_1_address()

        for i in range(nof_reads):
            # Write data from host
            byte_to_write = random.randint(100, 200)
            log.info("Writing byte 0x{:02x} from host".format(byte_to_write))
            cmd = Command(cmd="sudo i2cset -y 6 0x3c 0x{:02x}".format(byte_to_write))
            cmd.run_async()

            # DATA_REQUEST interrupt should be asserted
            self.fpga_wrapper.smbus_wait_interrupt()
            status1 = self.fpga_wrapper.readreg(FelicityFpga.SMBUS_STATUS1)

            assert status1 & FelicityFpga.RX_VALID  # Make sure RX_VALID bit is high
            assert status1 & FelicityFpga.DATA_REQUEST  # Make sure that interrupt is DATA_REQUEST

            data = self.fpga_wrapper.readreg(FelicityFpga.SMBUS_RX_DATA)
            self.fpga_wrapper.writereg(FelicityFpga.SMBUS_CMD, FelicityFpga.DATA_REQ_ACK)
            cmd.join(1)
            assert byte_to_write == data

            log.info("Status after read")
            status1 = self.fpga_wrapper.readreg(FelicityFpga.SMBUS_STATUS1)

            assert status1 & FelicityFpga.STOP_DET  # Make sure STOP_DETECTED bit is high
            assert status1 & FelicityFpga.BUS_IDLE  # Make sure BUS_IDLE bit is high

    def test_slave_read_from_host(self):
        """
        @description: This subtest checks that FPGA (slave mode) can write data to SMBus.

        @steps:
        1. Set FPGA slave 1 address.
        2. In the loop 20 times perform:
            a. Write data to TX buffer.
            b. Read data from host.
            c. Check that readed data is equals to written one.

        @result: Results are equal.
        @duration: 3 seconds.
        """

        nof_writes = 20
        smb_host_wrapper = SMBusHostWrapper(self.SMB_BUS)

        # Enable interrupts
        self.fpga_wrapper.writereg(FelicityFpga.SMBUS_INT_MASK, FelicityFpga.DATA_REQUEST | FelicityFpga.TIMEOUT)

        # Clear out-of-data status
        self.fpga_wrapper.writereg(FelicityFpga.SMBUS_STATUS1, 0xFFFF)  # Write 1 to clear
        self.fpga_wrapper.readreg(FelicityFpga.SMBUS_STATUS1)  # Clears LH and LL bits

        # Activate slave 1 address
        self.fpga_wrapper.smbus_set_slave_1_address()

        for i in range(nof_writes):
            byte_to_write = random.randint(100, 200)
            log.info("Writing byte 0x{:02x} from host".format(byte_to_write))

            self.fpga_wrapper.writereg(FelicityFpga.SMBUS_TX_DATA1, byte_to_write)
            status1 = self.fpga_wrapper.readreg(FelicityFpga.SMBUS_STATUS1)
            assert ~status1 & FelicityFpga.STX1_EMPTY  # Means that STX1_EMPTY is not empty after write

            data = smb_host_wrapper.read_byte(FelicityFpga.SLAVE_1_ADDR)
            assert data == byte_to_write

            # DATA_REQUEST interrupt should be asserted
            self.fpga_wrapper.smbus_wait_interrupt()
            status1 = self.fpga_wrapper.readreg(FelicityFpga.SMBUS_STATUS1)

            assert status1 & FelicityFpga.DATA_REQUEST  # Make sure that interrupt is DATA_REQUEST
            assert status1 & FelicityFpga.RX_NACK  # Make sure RX_NACK bit is high
            assert status1 & FelicityFpga.STOP_DET  # Make sure STOP_DETECTED bit is high
            assert status1 & FelicityFpga.BUS_IDLE  # Make sure BUS_IDLE bit is high


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
