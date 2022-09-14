"""Hardware access module.

This module contain hardware access layer implementations.
"""
import time
import timeit

from abc import abstractmethod
from hwi import hardwareInterfaceFTDI as hwi
from tools.utils import get_atf_logger

log = get_atf_logger()


class HWIface(object):
    """This is superbase class for all types of HW access implementations.
    """
    def __init__(self, **kwargs):
        """Class constructor.
        """

    def open(self):
        """Open HW Adapter.
        """

    def close(self):
        """Close HW Adapter.
        """

    @abstractmethod
    def readreg(self, addr):
        """Read register value.

        Parameters
        ----------
        addr : int
            Register address to read from.

        Returns
        ----------
        int
            Register value.
        """

    @abstractmethod
    def writereg(self, addr, val):
        """Write register value.

        Parameters
        ----------
        addr : int
            Register address to read from.
        val : int
            Value to be written.
        """


class HwAccess(HWIface):
    """This is base class for all types of HW access implementations.
    """
    # pylint: disable = abstract-method
    # pylint: disable = super-init-not-called
    def __init__(self, **kwargs):
        """Class constructor.
        """

    def __new__(cls, **kwargs):
        # pylint: disable = unused-argument
        return HwAccessFTDI(**kwargs)


class HwAccessFTDI(HWIface):
    """This is class for FTDI type of HW access.
    """
    def __init__(self, t6_name=None, i2c_addr=None):
        """Class constructor.

        Parameters
        ----------
        t6_name : str
            T6 device name to connect. String format: "AQT6C0079:I2C"
        i2c_addr : int
            I2C slave address. Default value: 0x79. Valid range: [0x0...0x7f]
        """
        super(HwAccessFTDI, self).__init__(t6_name=t6_name, i2c_addr=i2c_addr)
        if not(t6_name is None or isinstance(t6_name, str)):
            raise TypeError("T6 name must be string or None!")
        self.t6_name = t6_name
        if not isinstance(i2c_addr, int):
            raise TypeError("I2C address must be integer!")
        if not 0x0 <= i2c_addr <= 0x7f:
            raise ValueError("I2C address must be in between 0x0 and 0x7f!")
        if hwi.HW_Initialize() != 1:
            raise Exception("Couldn't initialize HW Interface FTDI")
        self._device_list = hwi.HW_DeviceList()
        if len(self._device_list) == 0:
            raise Exception("No FTDI device found! Try sudo?")
        if t6_name is None:
            try:
                t6_name = [x for x in self._device_list if x.endswith("I2C")][0]
            except IndexError:
                raise RuntimeError("No suitable FTDI device found. Available FTDI devices: {}".
                                   format("\n".join(self._device_list)))
        self._index = self._device_list.index(t6_name)
        self._i2c_addr = i2c_addr
        self.open()
        log.info("FTDI device initialized: {}, I2C address: 0x{:02x}".format(self._device_list[self._index],
                                                                             self._i2c_addr))

    def open(self):
        """Open HW Adapter.
        """
        hwi.HW_OpenAdapter(self._index)
        hwi.HW_SetDeviceParameters(self._index, 0, 1)

    def close(self):
        """Close HW Adapter.
        """
        hwi.HW_CloseAdapter(self._index)

    def readreg(self, addr):
        """Read register value.

        Parameters
        ----------
        addr : int
            Register address to read from.

        Returns
        ----------
        int
            Register value.
        """
        if not isinstance(addr, int):
            raise TypeError("Address must be integer!")

        try:
            val = hwi.HW_Read32(self._index, self._i2c_addr, addr)
            # log.debug("Register 0x{:08x}: 0x{:08x} : {:08b} {:08b} {:08b} {:08b}".format(addr, val, (val >> 24) & 0xFF,
                                                                                         # (val >> 16) & 0xFF,
                                                                                         # (val >> 8) & 0xFF,
                                                                                         # val & 0xFF))
            return val
        except IOError as exception:
            log.error("HW_Read32 method failed!", tag=self.t6_name)
            raise exception

    def writereg(self, addr, val):
        """Write register value.

        Parameters
        ----------
        addr : int
            Register address to read from.
        val : int
            Value to be written.
        """
        if not isinstance(addr, int):
            raise TypeError("Address must be integer!")
        if not isinstance(val, int):
            raise TypeError("Value must be integer!")

        try:
            hwi.HW_Write32(self._index, self._i2c_addr, addr, val)
            # log.debug("Register 0x{:08x}: 0x{:08x} written".format(addr, val), tag=self.t6_name)
        except IOError as exception:
            log.error("HW_Write32 method failed!", tag=self.t6_name)
            raise exception

