# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-std=c++14', '-target', 'i386-Linux', '-I/home/aqtest/mips-mti-elf/2017.10-08/mips-mti-elf/include/', '-I/home/aqtest/mips-mti-elf/2017.10-08/mips-mti-elf/include/c++/6.3.0/', '-I/home/aqtest/mips-mti-elf/2017.10-08/mips-mti-elf/include/c++/6.3.0/mips-mti-elf/micromips-r2-hard-nan2008-newlib/lib/', '-I/home/aqtest/atlantic2/firmware/src', '-I/home/aqtest/atlantic2/firmware/src/include']
# WORD_SIZE is: 4
# POINTER_SIZE is: 4
# LONGDOUBLE_SIZE is: 12
#
import ctypes


c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 12:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*12

# if local wordsize is same as target, keep ctypes pointer function.
if ctypes.sizeof(ctypes.c_void_p) == 4:
    POINTER_T = ctypes.POINTER
else:
    # required to access _ctypes
    import _ctypes
    # Emulate a pointer class using the approriate c_int32/c_int64 type
    # The new class should have :
    # ['__module__', 'from_param', '_type_', '__dict__', '__weakref__', '__doc__']
    # but the class should be submitted to a unique instance for each base type
    # to that if A == B, POINTER_T(A) == POINTER_T(B)
    ctypes._pointer_t_type_cache = {}
    def POINTER_T(pointee):
        # a pointer should have the same length as LONG
        fake_ptr_base_type = ctypes.c_uint32 
        # specific case for c_void_p
        if pointee is None: # VOID pointer type. c_void_p.
            pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
            clsname = 'c_void'
        else:
            clsname = pointee.__name__
        if clsname in ctypes._pointer_t_type_cache:
            return ctypes._pointer_t_type_cache[clsname]
        # make template
        class _T(_ctypes._SimpleCData,):
            _type_ = 'I'
            _subtype_ = pointee
            def _sub_addr_(self):
                return self.value
            def __repr__(self):
                return '%s(%d)'%(clsname, self.value)
            def contents(self):
                raise TypeError('This is not a ctypes pointer.')
            def __init__(self, **args):
                raise TypeError('This is not a ctypes pointer. It is not instanciable.')
        _class = type('LP_%d_%s'%(4, clsname), (_T,),{}) 
        ctypes._pointer_t_type_cache[clsname] = _class
        return _class



__int8_t = ctypes.c_byte
__uint8_t = ctypes.c_ubyte
__int16_t = ctypes.c_int16
__uint16_t = ctypes.c_uint16
__int32_t = ctypes.c_int32
__uint32_t = ctypes.c_uint32
__int64_t = ctypes.c_int64
__uint64_t = ctypes.c_uint64
__int_least8_t = ctypes.c_byte
__uint_least8_t = ctypes.c_ubyte
__int_least16_t = ctypes.c_int16
__uint_least16_t = ctypes.c_uint16
__int_least32_t = ctypes.c_int32
__uint_least32_t = ctypes.c_uint32
__int_least64_t = ctypes.c_int64
__uint_least64_t = ctypes.c_uint64
__intmax_t = ctypes.c_int64
__uintmax_t = ctypes.c_uint64
__intptr_t = ctypes.c_int32
__uintptr_t = ctypes.c_uint32
int_least8_t = ctypes.c_byte
uint_least8_t = ctypes.c_ubyte
int_least16_t = ctypes.c_int16
uint_least16_t = ctypes.c_uint16
int_least32_t = ctypes.c_int32
uint_least32_t = ctypes.c_uint32
int_least64_t = ctypes.c_int64
uint_least64_t = ctypes.c_uint64
int_fast8_t = ctypes.c_byte
uint_fast8_t = ctypes.c_ubyte
int_fast16_t = ctypes.c_int16
uint_fast16_t = ctypes.c_uint16
int_fast32_t = ctypes.c_int32
uint_fast32_t = ctypes.c_uint32
int_fast64_t = ctypes.c_int64
uint_fast64_t = ctypes.c_uint64
int8_t = ctypes.c_int8
uint8_t = ctypes.c_uint8
int16_t = ctypes.c_int16
uint16_t = ctypes.c_uint16
int32_t = ctypes.c_int32
uint32_t = ctypes.c_uint32
int64_t = ctypes.c_int64
uint64_t = ctypes.c_uint64
intmax_t = ctypes.c_int64
uintmax_t = ctypes.c_uint64
intptr_t = ctypes.c_int32
uintptr_t = ctypes.c_uint32
__blkcnt_t = ctypes.c_int32
__blksize_t = ctypes.c_int32
__fsblkcnt_t = ctypes.c_uint64
__fsfilcnt_t = ctypes.c_uint32
_off_t = ctypes.c_int32
__pid_t = ctypes.c_int32
__dev_t = ctypes.c_int16
__uid_t = ctypes.c_uint16
__gid_t = ctypes.c_uint16
__id_t = ctypes.c_uint32
__ino_t = ctypes.c_uint16
__mode_t = ctypes.c_uint32
_off64_t = ctypes.c_int64
__off_t = ctypes.c_int32
__loff_t = ctypes.c_int64
__key_t = ctypes.c_int32
_fpos_t = ctypes.c_int32
__size_t = ctypes.c_uint32
_ssize_t = ctypes.c_int32
__ssize_t = ctypes.c_int32
class struct__0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte),
     ]

_mbstate_t = struct__0
_flock_t = ctypes.c_int32
_iconv_t = POINTER_T(None)
__clock_t = ctypes.c_uint32
__time_t = ctypes.c_int32
__clockid_t = ctypes.c_uint32
__timer_t = ctypes.c_uint32
__sa_family_t = ctypes.c_ubyte
__socklen_t = ctypes.c_uint32
__nlink_t = ctypes.c_uint16
__suseconds_t = ctypes.c_int32
__useconds_t = ctypes.c_uint32
__va_list = POINTER_T(ctypes.c_char)
_LOCK_T = ctypes.c_int32
_LOCK_RECURSIVE_T = ctypes.c_int32
__ULong = ctypes.c_uint32
class struct___locale_t(ctypes.Structure):
    pass

class struct__Bigint(ctypes.Structure):
    pass

struct__Bigint._pack_ = True # source:False
struct__Bigint._fields_ = [
    ('_next', POINTER_T(struct__Bigint)),
    ('_k', ctypes.c_int32),
    ('_maxwds', ctypes.c_int32),
    ('_sign', ctypes.c_int32),
    ('_wds', ctypes.c_int32),
    ('_x', ctypes.c_uint32 * 1),
]

class struct___tm(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('__tm_sec', ctypes.c_int32),
    ('__tm_min', ctypes.c_int32),
    ('__tm_hour', ctypes.c_int32),
    ('__tm_mday', ctypes.c_int32),
    ('__tm_mon', ctypes.c_int32),
    ('__tm_year', ctypes.c_int32),
    ('__tm_wday', ctypes.c_int32),
    ('__tm_yday', ctypes.c_int32),
    ('__tm_isdst', ctypes.c_int32),
     ]

class struct__on_exit_args(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('_fnargs', POINTER_T(None) * 32),
    ('_dso_handle', POINTER_T(None) * 32),
    ('_fntypes', ctypes.c_uint32),
    ('_is_cxa', ctypes.c_uint32),
     ]

class struct__atexit(ctypes.Structure):
    pass

struct__atexit._pack_ = True # source:False
struct__atexit._fields_ = [
    ('_next', POINTER_T(struct__atexit)),
    ('_ind', ctypes.c_int32),
    ('_fns', POINTER_T(ctypes.CFUNCTYPE(None)) * 32),
    ('_on_exit_args', struct__on_exit_args),
]

class struct___sbuf(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('_base', POINTER_T(ctypes.c_ubyte)),
    ('_size', ctypes.c_int32),
     ]

class struct___sFILE(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte),
     ]

__FILE = struct___sFILE
class struct__glue(ctypes.Structure):
    pass

struct__glue._pack_ = True # source:False
struct__glue._fields_ = [
    ('_next', POINTER_T(struct__glue)),
    ('_niobs', ctypes.c_int32),
    ('_iobs', POINTER_T(struct___sFILE)),
]

class struct__rand48(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('_seed', ctypes.c_uint16 * 3),
    ('_mult', ctypes.c_uint16 * 3),
    ('_add', ctypes.c_uint16),
     ]

# _impure_ptr = POINTER_T(struct__reent) # Variable POINTER_T(struct__reent)
# _global_impure_ptr = POINTER_T(struct__reent) # Variable POINTER_T(struct__reent)
HOST_MODE_INVALID = 0 # Variable ctypes.c_uint32
HOST_MODE_ACTIVE = 1 # Variable ctypes.c_uint32
HOST_MODE_SLEEP_PROXY = 2 # Variable ctypes.c_uint32
HOST_MODE_LOW_POWER = 3 # Variable ctypes.c_uint32
HOST_MODE_SHUTDOWN = 4 # Variable ctypes.c_uint32

# values for enumeration 'c__Ea_MEMORY_MAILBOX_STATUS_FAIL'
c__Ea_MEMORY_MAILBOX_STATUS_FAIL__enumvalues = {
    0: 'MEMORY_MAILBOX_STATUS_FAIL',
    1: 'MEMORY_MAILBOX_STATUS_SUCCESS',
}
MEMORY_MAILBOX_STATUS_FAIL = 0
MEMORY_MAILBOX_STATUS_SUCCESS = 1
c__Ea_MEMORY_MAILBOX_STATUS_FAIL = ctypes.c_int # enum

# values for enumeration 'c__Ea_MEMORY_MAILBOX_TARGET_MEMORY'
c__Ea_MEMORY_MAILBOX_TARGET_MEMORY__enumvalues = {
    0: 'MEMORY_MAILBOX_TARGET_MEMORY',
    1: 'MEMORY_MAILBOX_TARGET_MDIO',
}
MEMORY_MAILBOX_TARGET_MEMORY = 0
MEMORY_MAILBOX_TARGET_MDIO = 1
c__Ea_MEMORY_MAILBOX_TARGET_MEMORY = ctypes.c_int # enum

# values for enumeration 'c__Ea_MEMORY_MAILBOX_OPERATION_READ'
c__Ea_MEMORY_MAILBOX_OPERATION_READ__enumvalues = {
    0: 'MEMORY_MAILBOX_OPERATION_READ',
    1: 'MEMORY_MAILBOX_OPERATION_WRITE',
}
MEMORY_MAILBOX_OPERATION_READ = 0
MEMORY_MAILBOX_OPERATION_WRITE = 1
c__Ea_MEMORY_MAILBOX_OPERATION_READ = ctypes.c_int # enum

# values for enumeration 'WAKE_REASON'
WAKE_REASON__enumvalues = {
    0: 'WAKE_REASON_UNKNOWN',
    1: 'WAKE_REASON_PANIC',
    2: 'WAKE_REASON_MAGIC_PACKET',
    3: 'WAKE_REASON_LINK',
    4: 'WAKE_REASON_RESERVED_01',
    5: 'WAKE_REASON_RESERVED_02',
    6: 'WAKE_REASON_MDNS',
    7: 'WAKE_REASON_ADDR_GUARD',
    8: 'WAKE_REASON_PING',
    9: 'WAKE_REASON_SYN',
    10: 'WAKE_REASON_UDP',
    11: 'WAKE_REASON_PATTERN',
    12: 'WAKE_REASON_TCPKA',
    13: 'WAKE_REASON_TIMER',
}
WAKE_REASON_UNKNOWN = 0
WAKE_REASON_PANIC = 1
WAKE_REASON_MAGIC_PACKET = 2
WAKE_REASON_LINK = 3
WAKE_REASON_RESERVED_01 = 4
WAKE_REASON_RESERVED_02 = 5
WAKE_REASON_MDNS = 6
WAKE_REASON_ADDR_GUARD = 7
WAKE_REASON_PING = 8
WAKE_REASON_SYN = 9
WAKE_REASON_UDP = 10
WAKE_REASON_PATTERN = 11
WAKE_REASON_TCPKA = 12
WAKE_REASON_TIMER = 13
WAKE_REASON = ctypes.c_int # enum
class struct_linkOptions_s(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('linkUp', ctypes.c_uint32, 1),
    ('linkRenegotiate', ctypes.c_uint32, 1),
    ('minimalLinkSpeed', ctypes.c_uint32, 1),
    ('internalLoopback', ctypes.c_uint32, 1),
    ('externalLoopback', ctypes.c_uint32, 1),
    ('rate_10M_hd', ctypes.c_uint32, 1),
    ('rate_100M_hd', ctypes.c_uint32, 1),
    ('rate_1G_hd', ctypes.c_uint32, 1),
    ('rate_10M', ctypes.c_uint32, 1),
    ('rate_100M', ctypes.c_uint32, 1),
    ('rate_1G', ctypes.c_uint32, 1),
    ('rate_2P5G', ctypes.c_uint32, 1),
    ('rate_N2P5G', ctypes.c_uint32, 1),
    ('rate_5G', ctypes.c_uint32, 1),
    ('rate_N5G', ctypes.c_uint32, 1),
    ('rate_10G', ctypes.c_uint32, 1),
    ('eee_100M', ctypes.c_uint32, 1),
    ('eee_1G', ctypes.c_uint32, 1),
    ('eee_2P5G', ctypes.c_uint32, 1),
    ('eee_5G', ctypes.c_uint32, 1),
    ('eee_10G', ctypes.c_uint32, 1),
    ('_21', ctypes.c_uint32, 3),
    ('pauseRx', ctypes.c_uint32, 1),
    ('pauseTx', ctypes.c_uint32, 1),
    ('_24', ctypes.c_uint32, 1),
    ('downshift', ctypes.c_uint32, 1),
    ('downshiftRetry', ctypes.c_uint32, 4),
     ]

linkOptions_t = struct_linkOptions_s
class struct_linkControl_s(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('operatingMode', ctypes.c_uint32, 4),
    ('disableCrcCorruption', ctypes.c_uint32, 1),
    ('discardShortFrames', ctypes.c_uint32, 1),
    ('flowControlMode', ctypes.c_uint32, 1),
    ('disableLengthCheck', ctypes.c_uint32, 1),
    ('discardErroredFrames', ctypes.c_uint32, 1),
    ('controlFrameEnable', ctypes.c_uint32, 1),
    ('enableTxPadding', ctypes.c_uint32, 1),
    ('enableCrcForwarding', ctypes.c_uint32, 1),
    ('enableFramePaddingRemovalRx', ctypes.c_uint32, 1),
    ('promiscuousMode', ctypes.c_uint32, 1),
    ('_11', ctypes.c_uint32, 18),
     ]

linkControl_t = struct_linkControl_s
class struct_thermalControl_s(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('shutdownEnable', ctypes.c_uint32, 1),
    ('warningEnable', ctypes.c_uint32, 1),
    ('_2', ctypes.c_uint32, 6),
    ('shutdownTempThreshold', ctypes.c_uint32, 8),
    ('warningColdTempThreshold', ctypes.c_uint32, 8),
    ('warningHotTempThreshold', ctypes.c_uint32, 8),
     ]

thermalControl_t = struct_thermalControl_s
class class_DrvThermalControl(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte * 4),
     ]

macAddress_t = ctypes.c_ubyte * 6
class struct_c__SA_sleepProxy_t(ctypes.Structure):
    pass

class struct_c__SA_sleepProxy_t_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('arpResponder', ctypes.c_uint32, 1),
    ('echoResponder', ctypes.c_uint32, 1),
    ('igmpClient', ctypes.c_uint32, 1),
    ('echoTruncate', ctypes.c_uint32, 1),
    ('addressGuard', ctypes.c_uint32, 1),
    ('ignoreFragmentedEcho', ctypes.c_uint32, 1),
    ('_6', ctypes.c_uint32, 2),
    ('echoMaxLen', ctypes.c_uint32, 16),
    ('PADDING_0', ctypes.c_uint32, 8),
    ('ipv4', ctypes.c_uint32 * 8),
    ('_9', ctypes.c_uint32, 32),
    ('_10', ctypes.c_uint32, 32),
    ('_11', ctypes.c_uint32, 32),
    ('_12', ctypes.c_uint32, 32),
    ('_13', ctypes.c_uint32, 32),
    ('_14', ctypes.c_uint32, 32),
    ('_15', ctypes.c_uint32, 32),
    ('_16', ctypes.c_uint32, 32),
     ]

class struct_c__SA_sleepProxy_t_2(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('nsResponder', ctypes.c_uint32, 1),
    ('echoResponder', ctypes.c_uint32, 1),
    ('mldClient', ctypes.c_uint32, 1),
    ('echoTruncate', ctypes.c_uint32, 1),
    ('addressGuard', ctypes.c_uint32, 1),
    ('ignoreFragmentedEcho', ctypes.c_uint32, 1),
    ('_6', ctypes.c_uint32, 2),
    ('echoMaxLen', ctypes.c_uint32, 16),
    ('PADDING_0', ctypes.c_uint32, 8),
    ('ipv6', ctypes.c_uint32 * 4 * 16),
     ]

class struct_c__SA_sleepProxy_t_4(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ports', ctypes.c_uint16 * 16),
     ]

class struct_ka6Offloads_s(ctypes.Structure):
    pass

class struct_ka6Offload_s(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('operationTimeout', ctypes.c_uint32),
    ('local_port', ctypes.c_uint16),
    ('remote_port', ctypes.c_uint16),
    ('remote_mac_addr', ctypes.c_ubyte * 6),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('_4', ctypes.c_uint32, 32),
    ('_5', ctypes.c_uint32, 32),
    ('_6', ctypes.c_uint32, 16),
    ('winSize', ctypes.c_uint32, 16),
    ('seq_num', ctypes.c_uint32),
    ('ack_num', ctypes.c_uint32),
    ('local_ip', ctypes.c_uint32 * 4),
    ('remote_ip', ctypes.c_uint32 * 4),
     ]

struct_ka6Offloads_s._pack_ = True # source:False
struct_ka6Offloads_s._fields_ = [
    ('retryCount', ctypes.c_uint32, 5),
    ('PADDING_0', ctypes.c_uint32, 27),
#     ('_1', ctypes.c_uint32, 0),
    ('retryInterval', ctypes.c_uint32),
    ('offloads', struct_ka6Offload_s * 16),
]

class struct_c__SA_sleepProxy_t_0(ctypes.Structure):
    pass

class struct_c__SA_sleepProxy_t_0_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('mask', ctypes.c_uint32 * 4),
    ('crc32', ctypes.c_uint32),
     ]

struct_c__SA_sleepProxy_t_0._pack_ = True # source:False
struct_c__SA_sleepProxy_t_0._fields_ = [
    ('wakeOnMagicPacket', ctypes.c_uint32, 1),
    ('wakeOnPattern', ctypes.c_uint32, 1),
    ('wakeOnLinkUp', ctypes.c_uint32, 1),
    ('wakeOnLinkDown', ctypes.c_uint32, 1),
    ('wakeOnPing', ctypes.c_uint32, 1),
    ('wakeOnTimer', ctypes.c_uint32, 1),
    ('wakeOnLinkMacMethod', ctypes.c_uint32, 1),
    ('_7', ctypes.c_uint32, 1),
    ('restoreLinkBeforeWakeup', ctypes.c_uint32, 1),
    ('_9', ctypes.c_uint32, 23),
    ('linkUpTimeout', ctypes.c_uint32),
    ('linkDownTimeout', ctypes.c_uint32),
    ('timer', ctypes.c_uint32),
    ('wakeUpPatterns', struct_c__SA_sleepProxy_t_0_0 * 8),
]

class struct_c__SA_sleepProxy_t_3(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ports', ctypes.c_uint16 * 16),
     ]

class struct_c__SA_sleepProxy_t_7(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('rrCount', ctypes.c_uint32),
    ('rrBufLen', ctypes.c_uint32),
    ('idxOffset', ctypes.c_uint32),
    ('rrOffset', ctypes.c_uint32),
     ]

class struct_ka4Offloads_s(ctypes.Structure):
    pass

class struct_ka4Offload_s(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('operationTimeout', ctypes.c_uint32),
    ('local_port', ctypes.c_uint16),
    ('remote_port', ctypes.c_uint16),
    ('remote_mac_addr', ctypes.c_ubyte * 6),
    ('PADDING_0', ctypes.c_ubyte * 2),
    ('_4', ctypes.c_uint32, 32),
    ('_5', ctypes.c_uint32, 32),
    ('_6', ctypes.c_uint32, 16),
    ('winSize', ctypes.c_uint32, 16),
    ('seq_num', ctypes.c_uint32),
    ('ack_num', ctypes.c_uint32),
    ('local_ip', ctypes.c_uint32),
    ('remote_ip', ctypes.c_uint32),
     ]

struct_ka4Offloads_s._pack_ = True # source:False
struct_ka4Offloads_s._fields_ = [
    ('retryCount', ctypes.c_uint32, 5),
    ('PADDING_0', ctypes.c_uint32, 27),
#     ('_1', ctypes.c_uint32, 0),
    ('retryInterval', ctypes.c_uint32),
    ('offloads', struct_ka4Offload_s * 16),
]

struct_c__SA_sleepProxy_t._pack_ = True # source:False
struct_c__SA_sleepProxy_t._fields_ = [
    ('wakeOnLan', struct_c__SA_sleepProxy_t_0),
    ('ipv4Offload', struct_c__SA_sleepProxy_t_1),
    ('ipv6Offload', struct_c__SA_sleepProxy_t_2),
    ('tcpPortOffload', struct_c__SA_sleepProxy_t_3),
    ('udpPortOffload', struct_c__SA_sleepProxy_t_4),
    ('ka4Offload', struct_ka4Offloads_s),
    ('ka6Offload', struct_ka6Offloads_s),
    ('mdns', struct_c__SA_sleepProxy_t_7),
]

sleepProxy_t = struct_c__SA_sleepProxy_t
class struct_c__SA_pauseQuanta_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('quanta_10M', ctypes.c_uint16),
    ('threshold_10M', ctypes.c_uint16),
    ('quanta_100M', ctypes.c_uint16),
    ('threshold_100M', ctypes.c_uint16),
    ('quanta_1G', ctypes.c_uint16),
    ('threshold_1G', ctypes.c_uint16),
    ('quanta_2P5G', ctypes.c_uint16),
    ('threshold_2P5G', ctypes.c_uint16),
    ('quanta_5G', ctypes.c_uint16),
    ('threshold_5G', ctypes.c_uint16),
    ('quanta_10G', ctypes.c_uint16),
    ('threshold_10G', ctypes.c_uint16),
     ]

pauseQuanta_t = struct_c__SA_pauseQuanta_t
class struct_c__SA_dataBufferStatus_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('dataOffset', ctypes.c_uint32),
    ('dataLength', ctypes.c_uint32),
     ]

dataBufferStatus_t = struct_c__SA_dataBufferStatus_t
class struct_c__SA_deviceCapabilities_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('finiteFlashless', ctypes.c_uint32, 1),
    ('cableDiag', ctypes.c_uint32, 1),
    ('ncsi', ctypes.c_uint32, 1),
    ('avb', ctypes.c_uint32, 1),
    ('_4', ctypes.c_uint32, 28),
    ('_5', ctypes.c_uint32, 32),
     ]

deviceCapabilities_t = struct_c__SA_deviceCapabilities_t
class struct_c__SA_version_t(ctypes.Structure):
    pass

class struct_phy_version_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('major', ctypes.c_uint32, 8),
    ('minor', ctypes.c_uint32, 8),
    ('build', ctypes.c_uint32, 16),
     ]

class struct_bundle_version_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('major', ctypes.c_uint32, 8),
    ('minor', ctypes.c_uint32, 8),
    ('build', ctypes.c_uint32, 16),
     ]

class struct_mac_version_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('major', ctypes.c_uint32, 8),
    ('minor', ctypes.c_uint32, 8),
    ('build', ctypes.c_uint32, 16),
     ]

struct_c__SA_version_t._pack_ = True # source:False
struct_c__SA_version_t._fields_ = [
    ('bundle', struct_bundle_version_t),
    ('mac', struct_mac_version_t),
    ('phy', struct_phy_version_t),
    ('_3', ctypes.c_uint32, 32),
]

version_t = struct_c__SA_version_t
class struct_c__SA_linkStatus_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('linkState', ctypes.c_uint32, 4),
    ('linkRate', ctypes.c_uint32, 4),
    ('pauseTx', ctypes.c_uint32, 1),
    ('pauseRx', ctypes.c_uint32, 1),
    ('eee', ctypes.c_uint32, 1),
    ('duplex', ctypes.c_uint32, 1),
    ('_6', ctypes.c_uint32, 4),
    ('_7', ctypes.c_uint32, 16),
     ]

linkStatus_t = struct_c__SA_linkStatus_t
class struct_c__SA_wolStatus_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('wakeCount', ctypes.c_uint32, 8),
    ('wakeReason', ctypes.c_uint32, 8),
    ('wakeUpPacketLength', ctypes.c_uint32, 12),
    ('wakeUpPatternNumber', ctypes.c_uint32, 3),
    ('_4', ctypes.c_uint32, 1),
    ('wakeUpPacket', ctypes.c_uint32 * 379),
     ]

wolStatus_t = struct_c__SA_wolStatus_t
class struct_c__SA_macHealthMonitor_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('macReady', ctypes.c_uint32, 1),
    ('macFault', ctypes.c_uint32, 1),
    ('_2', ctypes.c_uint32, 6),
    ('macTemperature', ctypes.c_uint32, 8),
    ('macHeartBeat', ctypes.c_uint32, 16),
    ('macFaultCode', ctypes.c_uint32, 16),
    ('_6', ctypes.c_uint32, 16),
     ]

macHealthMonitor_t = struct_c__SA_macHealthMonitor_t
class struct_c__SA_phyHealthMonitor_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('phyReady', ctypes.c_uint32, 1),
    ('phyFault', ctypes.c_uint32, 1),
    ('phyHotWarning', ctypes.c_uint32, 1),
    ('_3', ctypes.c_uint32, 5),
    ('phyTemperature', ctypes.c_uint32, 8),
    ('phyHeartBeat', ctypes.c_uint32, 16),
    ('phyFaultCode', ctypes.c_uint32, 16),
    ('_7', ctypes.c_uint32, 16),
     ]

phyHealthMonitor_t = struct_c__SA_phyHealthMonitor_t
class struct_c__SA_deviceLinkCaps_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('_0', ctypes.c_uint32, 3),
    ('internalLoopback', ctypes.c_uint32, 1),
    ('externalLoopback', ctypes.c_uint32, 1),
    ('rate_10M_hd', ctypes.c_uint32, 1),
    ('rate_100M_hd', ctypes.c_uint32, 1),
    ('rate_1G_hd', ctypes.c_uint32, 1),
    ('rate_10M', ctypes.c_uint32, 1),
    ('rate_100M', ctypes.c_uint32, 1),
    ('rate_1G', ctypes.c_uint32, 1),
    ('rate_2P5G', ctypes.c_uint32, 1),
    ('rate_N2P5G', ctypes.c_uint32, 1),
    ('rate_5G', ctypes.c_uint32, 1),
    ('rate_N5G', ctypes.c_uint32, 1),
    ('rate_10G', ctypes.c_uint32, 1),
    ('_14', ctypes.c_uint32, 1),
    ('eee_100M', ctypes.c_uint32, 1),
    ('eee_1G', ctypes.c_uint32, 1),
    ('eee_2P5G', ctypes.c_uint32, 1),
    ('_18', ctypes.c_uint32, 1),
    ('eee_5G', ctypes.c_uint32, 1),
    ('_20', ctypes.c_uint32, 1),
    ('eee_10G', ctypes.c_uint32, 1),
    ('pauseRx', ctypes.c_uint32, 1),
    ('pauseTx', ctypes.c_uint32, 1),
    ('pfc', ctypes.c_uint32, 1),
    ('downshift', ctypes.c_uint32, 1),
    ('downshiftRetry', ctypes.c_uint32, 4),
     ]

deviceLinkCaps_t = struct_c__SA_deviceLinkCaps_t
class struct_c__SA_sleepProxyCaps_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ipv4Offload', ctypes.c_uint32, 1),
    ('ipv6Offload', ctypes.c_uint32, 1),
    ('tcpPortOffload', ctypes.c_uint32, 1),
    ('udpPortOffload', ctypes.c_uint32, 1),
    ('ka4Offload', ctypes.c_uint32, 1),
    ('ka6Offload', ctypes.c_uint32, 1),
    ('mdnsOffload', ctypes.c_uint32, 1),
    ('wakeOnPing', ctypes.c_uint32, 1),
    ('wakeOnMagicPacket', ctypes.c_uint32, 1),
    ('wakeOnPattern', ctypes.c_uint32, 1),
    ('wakeOnTimer', ctypes.c_uint32, 1),
    ('wakeOnLink', ctypes.c_uint32, 1),
    ('wakePatternsCount', ctypes.c_uint32, 4),
    ('ipv4Count', ctypes.c_uint32, 8),
    ('ipv6Count', ctypes.c_uint32, 8),
    ('tcpPortOffloadCount', ctypes.c_uint32, 8),
    ('udpPortOffloadCount', ctypes.c_uint32, 8),
    ('tcp4KaCount', ctypes.c_uint32, 8),
    ('tcp6KaCount', ctypes.c_uint32, 8),
    ('igmpOffload', ctypes.c_uint32, 1),
    ('mldOffload', ctypes.c_uint32, 1),
    ('_21', ctypes.c_uint32, 30),
     ]

sleepProxyCaps_t = struct_c__SA_sleepProxyCaps_t
class struct_c__SA_lkpLinkCaps_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('_0', ctypes.c_uint32, 5),
    ('rate_10M_hd', ctypes.c_uint32, 1),
    ('rate_100M_hd', ctypes.c_uint32, 1),
    ('rate_1G_hd', ctypes.c_uint32, 1),
    ('rate_10M', ctypes.c_uint32, 1),
    ('rate_100M', ctypes.c_uint32, 1),
    ('rate_1G', ctypes.c_uint32, 1),
    ('rate_2P5G', ctypes.c_uint32, 1),
    ('rate_N2P5G', ctypes.c_uint32, 1),
    ('rate_5G', ctypes.c_uint32, 1),
    ('rate_N5G', ctypes.c_uint32, 1),
    ('rate_10G', ctypes.c_uint32, 1),
    ('_12', ctypes.c_uint32, 1),
    ('eee_100M', ctypes.c_uint32, 1),
    ('eee_1G', ctypes.c_uint32, 1),
    ('eee_2P5G', ctypes.c_uint32, 1),
    ('_16', ctypes.c_uint32, 1),
    ('eee_5G', ctypes.c_uint32, 1),
    ('_18', ctypes.c_uint32, 1),
    ('eee_10G', ctypes.c_uint32, 1),
    ('pauseRx', ctypes.c_uint32, 1),
    ('pauseTx', ctypes.c_uint32, 1),
    ('_22', ctypes.c_uint32, 6),
     ]

lkpLinkCaps_t = struct_c__SA_lkpLinkCaps_t
class struct_c__SA_coreDump_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('reg0', ctypes.c_uint32),
    ('reg1', ctypes.c_uint32),
    ('reg2', ctypes.c_uint32),
    ('hi', ctypes.c_uint32),
    ('lo', ctypes.c_uint32),
    ('regs', ctypes.c_uint32 * 32),
     ]

coreDump_t = struct_c__SA_coreDump_t
class struct_c__SA_trace_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('syncCounter', ctypes.c_uint32),
    ('memBuffer', ctypes.c_uint32 * 511),
     ]

trace_t = struct_c__SA_trace_t
class struct_c__SA_cableDiagControl_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('startDiag', ctypes.c_uint32, 1),
    ('_1', ctypes.c_uint32, 7),
    ('waitTimeoutSec', ctypes.c_uint32, 8),
    ('_3', ctypes.c_uint32, 16),
     ]

cableDiagControl_t = struct_c__SA_cableDiagControl_t
class class_DrvCableDiagControl(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte * 4),
     ]

class struct_c__SA_cableDiagLaneData_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('resultCode', ctypes.c_uint32, 8),
    ('dist', ctypes.c_uint32, 8),
    ('farDist', ctypes.c_uint32, 8),
    ('_3', ctypes.c_uint32, 8),
     ]

cableDiagLaneData_t = struct_c__SA_cableDiagLaneData_t
class struct_c__SA_cableDiagStatus_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('laneData', struct_c__SA_cableDiagLaneData_t * 4),
    ('transactId', ctypes.c_uint32, 8),
    ('status', ctypes.c_uint32, 4),
    ('_3', ctypes.c_uint32, 20),
     ]

cableDiagStatus_t = struct_c__SA_cableDiagStatus_t
class struct_c__SA_statistics_t(ctypes.Structure):
    pass

class struct_c__SA_statistics_t_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('txUnicastOctets', ctypes.c_uint64),
    ('txMulticastOctets', ctypes.c_uint64),
    ('txBroadcastOctets', ctypes.c_uint64),
    ('rxUnicastOctets', ctypes.c_uint64),
    ('rxMulticastOctets', ctypes.c_uint64),
    ('rxBroadcastOctets', ctypes.c_uint64),
    ('txUnicastFrames', ctypes.c_uint32),
    ('txMulticastFrames', ctypes.c_uint32),
    ('txBroadcastFrames', ctypes.c_uint32),
    ('txErrors', ctypes.c_uint32),
    ('rxUnicastFrames', ctypes.c_uint32),
    ('rxMulticastFrames', ctypes.c_uint32),
    ('rxBroadcastFrames', ctypes.c_uint32),
    ('rxDroppedFrames', ctypes.c_uint32),
    ('rxErrorFrames', ctypes.c_uint32),
    ('txGoodFrames', ctypes.c_uint32),
    ('rxGoodFrames', ctypes.c_uint32),
     ]

class struct_c__SA_statistics_t_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('linkUp', ctypes.c_uint32),
    ('linkDown', ctypes.c_uint32),
     ]

struct_c__SA_statistics_t._pack_ = True # source:False
struct_c__SA_statistics_t._fields_ = [
    ('link', struct_c__SA_statistics_t_0),
    ('msm', struct_c__SA_statistics_t_1),
    ('_1', ctypes.c_uint32),
    ('mainLoopCycles', ctypes.c_uint32),
    ('_2', ctypes.c_uint32),
]

statistics_t = struct_c__SA_statistics_t
class struct_c__SA_filter_caps_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('L2FilterBaseIndex', ctypes.c_ubyte, 6),
    ('FlexFilterMask', ctypes.c_ubyte, 2),
    ('L2FilterCount', ctypes.c_ubyte, 8),
    ('EtFilterBaseIndex', ctypes.c_ubyte),
    ('EtFilterCount', ctypes.c_ubyte),
    ('VlFilterBaseIndex', ctypes.c_ubyte),
    ('VlFilterCount', ctypes.c_ubyte),
    ('V4FilterBaseIndex', ctypes.c_ubyte, 4),
    ('V4FilterCount', ctypes.c_ubyte, 4),
    ('V6FilterBaseIndex', ctypes.c_ubyte, 4),
    ('V6FilterCount', ctypes.c_ubyte, 4),
    ('L4PFilterBaseIndex', ctypes.c_ubyte, 4),
    ('L4PFilterCount', ctypes.c_ubyte, 4),
    ('L4FlexFilterBaseIndex', ctypes.c_ubyte, 4),
    ('L4FlexFilterCount', ctypes.c_ubyte, 4),
    ('ArIndexBaseIndex', ctypes.c_ubyte, 8),
    ('ArIndexCount', ctypes.c_ubyte),
     ]

filter_caps_t = struct_c__SA_filter_caps_t
class struct_c__SA_request_policy_t(ctypes.Structure):
    pass

class struct_c__SA_request_policy_t_2(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('accept', ctypes.c_ubyte, 1),
    ('promisc', ctypes.c_ubyte, 1),
    ('rxQueueTcIndex', ctypes.c_ubyte, 5),
    ('queueOrTc', ctypes.c_ubyte, 1),
     ]

class struct_c__SA_request_policy_t_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('accept', ctypes.c_ubyte, 1),
    ('_1', ctypes.c_ubyte, 1),
    ('rxQueueTcIndex', ctypes.c_ubyte, 5),
    ('queueOrTc', ctypes.c_ubyte, 1),
     ]

class struct_c__SA_request_policy_t_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('accept', ctypes.c_ubyte, 1),
    ('_1', ctypes.c_ubyte, 1),
    ('rxQueueTcIndex', ctypes.c_ubyte, 5),
    ('queueOrTc', ctypes.c_ubyte, 1),
     ]

struct_c__SA_request_policy_t._pack_ = True # source:False
struct_c__SA_request_policy_t._fields_ = [
    ('promisc', struct_c__SA_request_policy_t_0),
    ('bcast', struct_c__SA_request_policy_t_1),
    ('mcast', struct_c__SA_request_policy_t_2),
    ('_3', ctypes.c_ubyte, 8),
]

request_policy_t = struct_c__SA_request_policy_t
class class_RequestPolicy(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte * 4),
     ]

class struct_c__SA_management_status_t(ctypes.Structure):
    pass

class struct_c__SA_management_status_t_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('enable', ctypes.c_uint32, 1),
    ('PADDING_0', ctypes.c_uint32, 31),
#     ('_1', ctypes.c_uint32, 0),
     ]

struct_c__SA_management_status_t._pack_ = True # source:False
struct_c__SA_management_status_t._fields_ = [
    ('macAddress', ctypes.c_ubyte * 6),
    ('vlan', ctypes.c_uint16),
    ('flags', struct_c__SA_management_status_t_0),
    ('_3', ctypes.c_uint32, 32),
    ('_4', ctypes.c_uint32, 32),
    ('_5', ctypes.c_uint32, 32),
    ('_6', ctypes.c_uint32, 32),
    ('_7', ctypes.c_uint32, 32),
]

management_status_t = struct_c__SA_management_status_t
class union_c__UA_DRIVER_INTERFACE_IN(ctypes.Union):
    pass

class struct_c__UA_DRIVER_INTERFACE_IN_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('mtu', ctypes.c_uint32),
    ('_1', ctypes.c_uint32, 32),
    ('macAddress', ctypes.c_ubyte * 6),
    ('_3', ctypes.c_uint16, 16),
    ('linkControl', linkControl_t),
    ('_5', ctypes.c_uint32, 32),
    ('linkOptions', linkOptions_t),
    ('_7', ctypes.c_uint32, 32),
    ('thermalControl', thermalControl_t),
    ('_9', ctypes.c_uint32, 32),
    ('sleepProxyConfig', sleepProxy_t),
    ('_11', ctypes.c_uint32, 32),
    ('pauseQuanta', struct_c__SA_pauseQuanta_t * 8),
    ('cableDiagControl', cableDiagControl_t),
    ('_14', ctypes.c_uint32, 32),
    ('dataBufferStatus', dataBufferStatus_t),
    ('_16', ctypes.c_uint32, 32),
    ('requestPolicy', request_policy_t),
     ]

union_c__UA_DRIVER_INTERFACE_IN._pack_ = True # source:False
union_c__UA_DRIVER_INTERFACE_IN._fields_ = [
    ('_0', struct_c__UA_DRIVER_INTERFACE_IN_0),
    ('u32', ctypes.c_uint32 * 1),
    ('PADDING_0', ctypes.c_ubyte * 2648),
]

DRIVER_INTERFACE_IN = struct_c__UA_DRIVER_INTERFACE_IN_0
class struct_c__SA_DRIVER_INTERFACE_OUT(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('transactionCounter', ctypes.c_uint32),
    ('version', version_t),
    ('linkStatus', linkStatus_t),
    ('wolStatus', wolStatus_t),
    ('_4', ctypes.c_uint32, 32),
    ('_5', ctypes.c_uint32, 32),
    ('macHealthMonitor', macHealthMonitor_t),
    ('_7', ctypes.c_uint32, 32),
    ('_8', ctypes.c_uint32, 32),
    ('phyHealthMonitor', phyHealthMonitor_t),
    ('_10', ctypes.c_uint32, 32),
    ('_11', ctypes.c_uint32, 32),
    ('cableDiagStatus', cableDiagStatus_t),
    ('_13', ctypes.c_uint32, 32),
    ('deviceLinkCaps', deviceLinkCaps_t),
    ('_15', ctypes.c_uint32, 32),
    ('sleepProxyCaps', sleepProxyCaps_t),
    ('_17', ctypes.c_uint32, 32),
    ('lkpLinkCaps', lkpLinkCaps_t),
    ('_19', ctypes.c_uint32, 32),
    ('coreDump', coreDump_t),
    ('_21', ctypes.c_uint32, 32),
    ('stats', statistics_t),
    ('_23', ctypes.c_uint32, 32),
    ('filterCaps', filter_caps_t),
    ('deviceCaps', deviceCapabilities_t),
    ('_26', ctypes.c_uint32, 32),
    ('managementStatus', management_status_t),
    ('_28', ctypes.c_uint32, 32),
    ('addDriverOutAddress', ctypes.c_uint32),
    ('reserve', ctypes.c_uint32 * 19),
    ('trace', trace_t),
     ]

DRIVER_INTERFACE_OUT = struct_c__SA_DRIVER_INTERFACE_OUT
__driver_interface_in = None # Variable union_c__UA_DRIVER_INTERFACE_IN
__driver_interface_out = struct_c__SA_DRIVER_INTERFACE_OUT # Variable struct_c__SA_DRIVER_INTERFACE_OUT
class struct_AdditionalDriverOut(ctypes.Structure):
    pass

class struct_AdditionalDriverOut_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('channleA', ctypes.c_uint16),
    ('channleB', ctypes.c_uint16),
    ('channleC', ctypes.c_uint16),
    ('channleD', ctypes.c_uint16),
     ]

struct_AdditionalDriverOut._pack_ = True # source:False
struct_AdditionalDriverOut._fields_ = [
    ('SnrOperatingMargin', struct_AdditionalDriverOut_0),
]

class class_DriverInterface(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte),
     ]

__all__ = \
    ['DRIVER_INTERFACE_IN', 'DRIVER_INTERFACE_OUT',
    'HOST_MODE_ACTIVE', 'HOST_MODE_INVALID', 'HOST_MODE_LOW_POWER',
    'HOST_MODE_SHUTDOWN', 'HOST_MODE_SLEEP_PROXY',
    'MEMORY_MAILBOX_OPERATION_READ', 'MEMORY_MAILBOX_OPERATION_WRITE',
    'MEMORY_MAILBOX_STATUS_FAIL', 'MEMORY_MAILBOX_STATUS_SUCCESS',
    'MEMORY_MAILBOX_TARGET_MDIO', 'MEMORY_MAILBOX_TARGET_MEMORY',
    'WAKE_REASON', 'WAKE_REASON_ADDR_GUARD', 'WAKE_REASON_LINK',
    'WAKE_REASON_MAGIC_PACKET', 'WAKE_REASON_MDNS',
    'WAKE_REASON_PANIC', 'WAKE_REASON_PATTERN', 'WAKE_REASON_PING',
    'WAKE_REASON_RESERVED_01', 'WAKE_REASON_RESERVED_02',
    'WAKE_REASON_SYN', 'WAKE_REASON_TCPKA', 'WAKE_REASON_TIMER',
    'WAKE_REASON_UDP', 'WAKE_REASON_UNKNOWN', '_LOCK_RECURSIVE_T',
    '_LOCK_T', '__FILE', '__ULong', '__blkcnt_t', '__blksize_t',
    '__clock_t', '__clockid_t', '__dev_t', '__driver_interface_in',
    '__driver_interface_out', '__fsblkcnt_t', '__fsfilcnt_t',
    '__gid_t', '__id_t', '__ino_t', '__int16_t', '__int32_t',
    '__int64_t', '__int8_t', '__int_least16_t', '__int_least32_t',
    '__int_least64_t', '__int_least8_t', '__intmax_t', '__intptr_t',
    '__key_t', '__loff_t', '__mode_t', '__nlink_t', '__off_t',
    '__pid_t', '__sa_family_t', '__size_t', '__socklen_t',
    '__ssize_t', '__suseconds_t', '__time_t', '__timer_t', '__uid_t',
    '__uint16_t', '__uint32_t', '__uint64_t', '__uint8_t',
    '__uint_least16_t', '__uint_least32_t', '__uint_least64_t',
    '__uint_least8_t', '__uintmax_t', '__uintptr_t', '__useconds_t',
    '__va_list', '_flock_t', '_fpos_t', 
    '_iconv_t',  '_mbstate_t', '_off64_t', '_off_t',
    '_ssize_t', 'c__Ea_MEMORY_MAILBOX_OPERATION_READ',
    'c__Ea_MEMORY_MAILBOX_STATUS_FAIL',
    'c__Ea_MEMORY_MAILBOX_TARGET_MEMORY', 'cableDiagControl_t',
    'cableDiagLaneData_t', 'cableDiagStatus_t',
    'class_DriverInterface', 'class_DrvCableDiagControl',
    'class_DrvThermalControl', 'class_RequestPolicy', 'coreDump_t',
    'dataBufferStatus_t', 'deviceCapabilities_t', 'deviceLinkCaps_t',
    'filter_caps_t', 'int16_t', 'int32_t', 'int64_t', 'int8_t',
    'int_fast16_t', 'int_fast32_t', 'int_fast64_t', 'int_fast8_t',
    'int_least16_t', 'int_least32_t', 'int_least64_t', 'int_least8_t',
    'intmax_t', 'intptr_t', 'linkControl_t', 'linkOptions_t',
    'linkStatus_t', 'lkpLinkCaps_t', 'macAddress_t',
    'macHealthMonitor_t', 'management_status_t', 'pauseQuanta_t',
    'phyHealthMonitor_t', 'request_policy_t', 'sleepProxyCaps_t',
    'sleepProxy_t', 'statistics_t', 'struct_AdditionalDriverOut',
    'struct_AdditionalDriverOut_0', 'struct__0', 'struct__Bigint',
    'struct___locale_t', 'struct___sFILE', 'struct___sbuf',
    'struct___tm', 'struct__atexit', 'struct__glue',
    'struct__on_exit_args', 'struct__rand48',
    'struct_bundle_version_t', 'struct_c__SA_DRIVER_INTERFACE_OUT',
    'struct_c__SA_cableDiagControl_t',
    'struct_c__SA_cableDiagLaneData_t',
    'struct_c__SA_cableDiagStatus_t', 'struct_c__SA_coreDump_t',
    'struct_c__SA_dataBufferStatus_t',
    'struct_c__SA_deviceCapabilities_t',
    'struct_c__SA_deviceLinkCaps_t', 'struct_c__SA_filter_caps_t',
    'struct_c__SA_linkStatus_t', 'struct_c__SA_lkpLinkCaps_t',
    'struct_c__SA_macHealthMonitor_t',
    'struct_c__SA_management_status_t',
    'struct_c__SA_management_status_t_0',
    'struct_c__SA_pauseQuanta_t', 'struct_c__SA_phyHealthMonitor_t',
    'struct_c__SA_request_policy_t',
    'struct_c__SA_request_policy_t_0',
    'struct_c__SA_request_policy_t_1',
    'struct_c__SA_request_policy_t_2',
    'struct_c__SA_sleepProxyCaps_t', 'struct_c__SA_sleepProxy_t',
    'struct_c__SA_sleepProxy_t_0', 'struct_c__SA_sleepProxy_t_0_0',
    'struct_c__SA_sleepProxy_t_1', 'struct_c__SA_sleepProxy_t_2',
    'struct_c__SA_sleepProxy_t_3', 'struct_c__SA_sleepProxy_t_4',
    'struct_c__SA_sleepProxy_t_7', 'struct_c__SA_statistics_t',
    'struct_c__SA_statistics_t_0', 'struct_c__SA_statistics_t_1',
    'struct_c__SA_trace_t', 'struct_c__SA_version_t',
    'struct_c__SA_wolStatus_t', 'struct_c__UA_DRIVER_INTERFACE_IN_0',
    'struct_ka4Offload_s', 'struct_ka4Offloads_s',
    'struct_ka6Offload_s', 'struct_ka6Offloads_s',
    'struct_linkControl_s', 'struct_linkOptions_s',
    'struct_mac_version_t', 'struct_phy_version_t',
    'struct_thermalControl_s', 'thermalControl_t', 'trace_t',
    'uint16_t', 'uint32_t', 'uint64_t', 'uint8_t', 'uint_fast16_t',
    'uint_fast32_t', 'uint_fast64_t', 'uint_fast8_t',
    'uint_least16_t', 'uint_least32_t', 'uint_least64_t',
    'uint_least8_t', 'uintmax_t', 'uintptr_t',
    'union_c__UA_DRIVER_INTERFACE_IN', 'version_t', 'wolStatus_t']
assert ctypes.sizeof(macAddress_t) == 0x6, "macAddress invalid size"
assert ctypes.sizeof(linkOptions_t) == 0x4, "linkOptions invalid size"
assert ctypes.sizeof(thermalControl_t) == 0x4, "thermalControl invalid size"
assert ctypes.sizeof(sleepProxy_t) == 0x958, "sleepProxy invalid size"
assert ctypes.sizeof(pauseQuanta_t) == 0x18, "pauseQuanta invalid size"
assert ctypes.sizeof(cableDiagControl_t) == 0x4, "cableDiagControl invalid size"
assert ctypes.sizeof(version_t) == 0x10, "version invalid size"
assert ctypes.sizeof(linkStatus_t) == 0x4, "linkStatus invalid size"
assert ctypes.sizeof(wolStatus_t) == 0x5F0, "wolStatus invalid size"
assert ctypes.sizeof(macHealthMonitor_t) == 0x8, "macHealthMonitor invalid size"
assert ctypes.sizeof(phyHealthMonitor_t) == 0x8, "phyHealthMonitor invalid size"
assert ctypes.sizeof(cableDiagStatus_t) == 0x14, "cableDiagStatus invalid size"
assert ctypes.sizeof(deviceLinkCaps_t) == 0x4, "deviceLinkCaps invalid size"
assert ctypes.sizeof(sleepProxyCaps_t) == 0xC, "sleepProxyCaps invalid size"
assert ctypes.sizeof(lkpLinkCaps_t) == 0x4, "lkpLinkCaps invalid size"
assert ctypes.sizeof(coreDump_t) == 0x94, "coreDump invalid size"
assert ctypes.sizeof(trace_t) == 0x800, "trace invalid size"
assert ctypes.sizeof(statistics_t) == 0x70, "statistics invalid size"
assert ctypes.sizeof(filter_caps_t) == 0x0C, "filter_caps_t invalid size"
assert ctypes.sizeof(dataBufferStatus_t) == 0x8, "databufferstatus invalid size"
assert ctypes.sizeof(deviceCapabilities_t) == 0x8, "deviceCapabilities_t invalid size"
assert ctypes.sizeof(request_policy_t) == 4, "request_policy_t invalid size"
assert ctypes.sizeof(management_status_t) == 0x20, "management_status_t invalid size"
assert DRIVER_INTERFACE_IN.mtu.offset == 0, "mtu invalid offset"
assert DRIVER_INTERFACE_IN.macAddress.offset == 0x8, "macAddress invalid offset"
assert DRIVER_INTERFACE_IN.linkControl.offset == 0x10, "linkControl invalid offset"
assert DRIVER_INTERFACE_IN.linkOptions.offset == 0x18, "linkOptions invalid offset"
assert DRIVER_INTERFACE_IN.thermalControl.offset == 0x20, "thermalControl invalid offset"
assert DRIVER_INTERFACE_IN.sleepProxyConfig.offset == 0x28, "sleepProxy invalid offset"
assert DRIVER_INTERFACE_IN.pauseQuanta.offset == 0x984, "pauseQuanta invalid offset"
assert DRIVER_INTERFACE_IN.cableDiagControl.offset == 0xA44, "cableDiagControl invalid offset"
assert DRIVER_INTERFACE_IN.dataBufferStatus.offset == 0xA4C, "cableDiagControl invalid offset"
assert DRIVER_INTERFACE_IN.requestPolicy.offset == 0xA58, "requestPolicy invalid offset"
assert DRIVER_INTERFACE_OUT.version.offset == 0x04, "version invalid offset"
assert DRIVER_INTERFACE_OUT.linkStatus.offset == 0x14, "linkStatus invalid offset"
assert DRIVER_INTERFACE_OUT.wolStatus.offset == 0x18, "wolStatus invalid offset"
assert DRIVER_INTERFACE_OUT.macHealthMonitor.offset == 0x610, "macHealthMonitor invalid offset"
assert DRIVER_INTERFACE_OUT.phyHealthMonitor.offset == 0x620, "phyHealthMonitor invalid offset"
assert DRIVER_INTERFACE_OUT.cableDiagStatus.offset == 0x630, "cableDiagStatus invalid offset"
assert DRIVER_INTERFACE_OUT.deviceLinkCaps.offset == 0x648, "deviceLinkCaps invalid offset"
assert DRIVER_INTERFACE_OUT.sleepProxyCaps.offset == 0x650, "sleepProxyCaps invalid offset"
assert DRIVER_INTERFACE_OUT.lkpLinkCaps.offset == 0x660, "lkpLinkCaps invalid offset"
assert DRIVER_INTERFACE_OUT.coreDump.offset == 0x668, "coreDump invalid offset"
assert DRIVER_INTERFACE_OUT.stats.offset == 0x700, "stats invalid offset"
assert DRIVER_INTERFACE_OUT.filterCaps.offset == 0x774, "filterCaps invalid offset"
assert DRIVER_INTERFACE_OUT.deviceCaps.offset == 0x780, "deviceCaps invalid offset"
assert DRIVER_INTERFACE_OUT.managementStatus.offset == 0x78C, "managementStatus invalid offset"
assert DRIVER_INTERFACE_OUT.trace.offset == 0x800, "trace invalid offset"
assert sleepProxy_t.wakeOnLan.offset % 4 == 0, "wakeOnLan in sleepProxy_t invalid offset"
assert sleepProxy_t.ipv4Offload.offset % 4 == 0, "ipv4Offload in sleepProxy_t invalid offset"
assert sleepProxy_t.ipv6Offload.offset % 4 == 0, "ipv6Offload in sleepProxy_t invalid offset"
assert sleepProxy_t.tcpPortOffload.offset % 4 == 0, "tcpPortOffload in sleepProxy_t invalid offset"
assert sleepProxy_t.udpPortOffload.offset % 4 == 0, "udpPortOffload in sleepProxy_t invalid offset"
assert sleepProxy_t.ka4Offload.offset % 4 == 0, "ka4Offload in sleepProxy_t invalid offset"
assert sleepProxy_t.ka6Offload.offset % 4 == 0, "ka4Offload in sleepProxy_t invalid offset"
assert sleepProxy_t.mdns.offset % 4 == 0, "mdns in sleepProxy_t invalid offset"