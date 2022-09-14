import argparse
import ctypes
import struct

ALIGN_DOWN = lambda val, align: (val // align) * align
ALIGN_UP = lambda val, align: (((val - 1) // align) + 1) * align


def hal_reg_factory(addr, fields):
    class _bits(ctypes.Structure):
        _pack_ = 1
        _fields_ = fields

    class _reg(ctypes.Union):
        _addr = addr

        _pack_ = 1
        _fields_ = [
            ("bits", _bits),
            ("dword", ctypes.c_uint32)
        ]

        def __init__(self, atltoolper, *args, **kwargs):
            super(_reg, self).__init__(*args, **kwargs)
            self.atltoolper = atltoolper

        def read(self):
            self.dword = self.atltoolper.readreg(self._addr)

        def write(self):
            self.atltoolper.writereg(self._addr, self.dword)

    return _reg


def dump_struct_stdout(s, struct_name=None):
    print("{}:".format(struct_name if struct_name is not None else s))
    for f_desc in s._fields_:
        print("    {} = {}".format(f_desc[0], getattr(s, f_desc[0])))


def dump_struct_log(s, print_func, struct_name=None):
    print_func("{}:".format(struct_name if struct_name is not None else s))
    for f_desc in s._fields_:
        print_func("    {} = {}".format(f_desc[0], getattr(s, f_desc[0])))


def get_struct_field(s, name):
    for f_desc in s._fields_:
        f_name = f_desc[0]
        f_type = f_desc[1]
        if f_name == name:
            return getattr(s, name), f_type

    raise Exception("Failed to find field '{}' in struct {}".format(name, s))


def get_global_struct_field(path="", global_struct=None):
    parts = path.split(".")

    if global_struct is not None:
        s = global_struct
    else:
        if parts[0] in globals():
            s = globals()[parts[0]]
        else:
            import __builtin__
            s = getattr(__builtin__, parts[0])

    s_type = None
    byte_offset = 0
    bit_offset = 0
    byte_size = 0
    bit_size = 0

    for i in range(1, len(parts)):
        f, s = get_struct_field(s, parts[i])

        byte_offset += f.offset

        if i == len(parts) - 1:
            s_type = s
            bit_size = (f.size & 0xFFFF0000) >> 16
            if bit_size == 0:
                byte_size = f.size
                bit_offset = 0
            else:
                byte_size = bit_size // 8
                bit_offset = f.size & 0xFFFF

    return s_type, byte_offset, byte_size, bit_offset, bit_size


def mif_read_bytes(atltoolper, addr, size):
    reg_addr_start = ALIGN_DOWN(addr, 4)
    reg_addr_end = ALIGN_UP(addr + size, 4)

    s = b""

    vals = atltoolper.readregs(range(reg_addr_start, reg_addr_end, 4))
    for val in vals:
        s += struct.pack("<I", val)

    return s[addr - reg_addr_start:addr - reg_addr_start + size]


def mif_write_bytes(atltoolper, addr, data):
    reg_addr_start = ALIGN_DOWN(addr, 4)
    reg_addr_end = ALIGN_UP(addr + len(data), 4)

    data_aligned = b""

    if reg_addr_start < addr:
        reg_data = struct.pack("<I", atltoolper.readreg(reg_addr_start))
        data_aligned += reg_data[:addr - reg_addr_start]

    data_aligned += data

    if (addr + len(data)) % 4:
        end_addr = addr + len(data)
        last_reg_addr = ALIGN_DOWN(end_addr, 4)
        reg_data = struct.pack("<I", atltoolper.readreg(last_reg_addr))
        data_aligned += reg_data[-(4 - (end_addr - last_reg_addr)):]

    reg_val_pairs = []
    for reg in range(reg_addr_start, reg_addr_end, 4):
        val = struct.unpack("<I", data_aligned[reg - reg_addr_start:reg - reg_addr_start + 4])[0]
        reg_val_pairs.append((reg, val))

    atltoolper.writeregs(reg_val_pairs)


def read_struct_field(atltoolper, path, base_offset=0, global_struct=None):
    s_type, byte_offset, byte_size, _, bit_size = get_global_struct_field(path=path, global_struct=global_struct)

    if bit_size == 0:
        data_bytes = mif_read_bytes(atltoolper, base_offset + byte_offset, byte_size)
        data_struct = s_type.from_buffer_copy(data_bytes)
        if issubclass(s_type, (ctypes.c_int, ctypes.c_uint)):
            return data_struct.value
        else:
            return data_struct
    else:
        # Memory management in case of bitfields is complicated
        # Try to get parent struct instead
        parts = path.split(".")
        parent_path = ".".join(parts[:-1])
        child_name = parts[-1]

        s_type, byte_offset, byte_size, _, __ = get_global_struct_field(path=parent_path, global_struct=global_struct)

        if not issubclass(s_type, ctypes.Structure):
            raise Exception("Parent of {} is not a struct".format(path))

        data_bytes = mif_read_bytes(atltoolper, base_offset + byte_offset, byte_size)
        data_struct = s_type.from_buffer_copy(data_bytes)

        return getattr(data_struct, child_name)


def write_struct_field(atltoolper, path, data, base_offset=0, global_struct=None):
    s_type, byte_offset, byte_size, _, bit_size = get_global_struct_field(path=path, global_struct=global_struct)

    if bit_size == 0:
        if issubclass(s_type, (ctypes.c_int, ctypes.c_uint)) and isinstance(data, (int, long)):
            data = s_type(data)

        if not isinstance(data, s_type):
            raise Exception("{} ({}) is not an instance of {}".format(data, type(data), s_type))

        data_bytes = buffer(data)[:]

        mif_write_bytes(atltoolper, base_offset + byte_offset, data_bytes)
    else:
        if not isinstance(data, (int, long)):
            raise Exception("{} ({}) is not an integer".format(data, type(data)))

        # Memory management in case of bitfields is complicated
        # Try to get parent struct instead
        parts = path.split(".")
        parent_path = ".".join(parts[:-1])
        child_name = parts[-1]

        s_type, byte_offset, byte_size, _, __ = get_global_struct_field(path=parent_path, global_struct=global_struct)

        if not issubclass(s_type, ctypes.Structure):
            raise Exception("Parent of {} is not a struct".format(path))

        data_bytes = mif_read_bytes(atltoolper, base_offset + byte_offset, byte_size)
        parent_struct = s_type.from_buffer_copy(data_bytes)
        setattr(parent_struct, child_name, data)
        data_bytes = buffer(parent_struct)[:]

        mif_write_bytes(atltoolper, base_offset + byte_offset, data_bytes)


if __name__ == "__main__":
    from atltoolper import AtlTool
    from fw_a2_drv_iface_structures import *

    parser = argparse.ArgumentParser(description="Print register offset of the field")
    parser.add_argument("-p", "--path", help="Path of the field", required=True)
    parser.add_argument("-r", "--read", help="Read the field and display its contents", action="store_true")
    args = parser.parse_args()

    base_offset = 0

    if args.path.startswith("DRIVER_INTERFACE_IN"):
        base_offset = 0x12000
    elif args.path.startswith("DRIVER_INTERFACE_OUT"):
        base_offset = 0x13000

    s_type, byte_offset, byte_size, bit_offset, bit_size = get_global_struct_field(args.path)

    reg_addr = base_offset + byte_offset

    if args.read:
        if base_offset == 0:
            raise Exception("Can't read the field which path doesn't start with DRIVER_INTERFACE_IN(OUT)")

        atltool = AtlTool(port="pci1.00.0")

        field = read_struct_field(atltool, args.path, base_offset=base_offset)

    print(args.path + ":")
    print("    Type: {}".format(s_type))
    print("    Address: 0x{:08X}".format(reg_addr))
    print("    Size (bytes): {}".format(byte_size))
    print("    Shift: {}".format(bit_offset))
    print("    Size (bits): {}".format(bit_size))

    if args.read:
        if isinstance(field, ctypes.Structure):
            dump_struct_stdout(field)
        elif isinstance(field, ctypes.Array):
            print("{}:".format(s_type))
            for v in field:
                print(v)
        else:
            print("{}:".format(s_type))
            print(field)
