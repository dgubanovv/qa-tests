import os
import random
import re
import subprocess
import sys
import time
import timeit
import unittest
import socket

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../tools"))

from phy_ptp_cfg import PhyAccessBer, PtpFiltersEgressEnableConfig, PtpFiltersIngressEnableConfig, \
    PtpTimestampingEgressEnableConfig, PtpTimestampingIngressEnableConfig, PtpConfig, LINK_SPEED_1G, LINK_SPEED_10G, \
    SecEgressEnableConfig, SecIngressEnableConfig, LINK_SPEED_100M, LINK_SPEED_2_5G, LINK_SPEED_5G


ETH_TYPE_IPv4 = 0x0800
ETH_TYPE_IPv6 = 0x86dd
PROTOCOL_UDP = 0x11


class Header(object):
    def __div__(self, other):
        # print "!!! %s %s" % (type(self), type(other))
        if type(other) == VlanHeader:
            # print "0x%x" % (other.tpid)
            assert type(self) == EthernetHeader
            if not hasattr(self, "vlan_headers"):
                self.vlan_headers = []
                self.vlan_headers.append(other)
                self.data[12:12] = other.data
            else:
                self.vlan_headers.append(other)
                self.data[16:16] = other.data
            return self
        assert isinstance(other, Header)
        return Packet(data=self.data + other.data)

    def __str__(self):
        sdata = ""
        for d in self.data:
            sdata += "%02x" % (d)
        return sdata

    def _apply_properties(self, **kwargs):
        for k, v in kwargs.items():
            if k == "data":
                continue
            if k not in self.ALLOWED_KEYS:
                raise Exception("Key %s is not known, allowed keys are %s" % (k, self.ALLOWED_KEYS))
            setattr(self, k, v)


class EthernetHeader(Header):
    ALLOWED_KEYS = ["dst", "src", "type"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0] * 14)
        self._apply_properties(**kwargs)

    def get_dst(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % \
            (self.data[0], self.data[1], self.data[2], self.data[3], self.data[4], self.data[5])

    def set_dst(self, value):
        data = value.split(":")
        for i in range(6):
            self.data[i] = int(data[i], 16)

    dst = property(get_dst, set_dst)

    def get_src(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % \
            (self.data[6], self.data[7], self.data[8], self.data[9], self.data[10], self.data[11])

    def set_src(self, value):
        data = value.split(":")
        for i in range(6, 12):
            self.data[i] = int(data[i - 6], 16)

    src = property(get_src, set_src)

    def get_type(self):
        return self.data[12] << 8 | self.data[13]

    def set_type(self, value):
        self.data[12] = (value >> 8) & 0xff
        self.data[13] = value & 0xff

    type = property(get_type, set_type)


class VlanHeader(Header):
    ALLOWED_KEYS = ["tpid", "pcp", "dei", "vid"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x81, 0x00] + [0] * 2)
        self._apply_properties(**kwargs)

    def get_tpid(self):
        return (self.data[0] << 8) | self.data[1]

    def set_tpid(self, value):
        self.data[0] = (value >> 8) & 0xff
        self.data[1] = value & 0xff

    tpid = property(get_tpid, set_tpid)

    def get_pcp(self):
        return (self.data[2] & 0xe0) >> 5

    def set_pcp(self, value):
        self.data[2] = (self.data[2] & 0x1f) | ((value & 0x7) << 5)

    pcp = property(get_pcp, set_pcp)

    def get_dei(self):
        return (self.data & 0x10) >> 4

    def set_dei(self, value):
        self.data[2] = (self.data[2] & 0xef) | ((value & 0x1) << 4)

    dei = property(get_dei, set_dei)

    def get_vid(self):
        return (self.data[2] & 0xf) << 4 | self.data[3]

    def set_vid(self, value):
        self.data[2] = (self.data[2] & 0xf0) | ((value >> 8) & 0xf)
        self.data[3] = value & 0xff

    vid = property(get_vid, set_vid)


class PtpV2Header(Header):
    def __new__(cls, **kwargs):
        data = kwargs.get("data", None)
        if data is not None:
            if (data[0] & 0xf) == 0x0:
                return object.__new__(PtpV2SyncHeader)
            if (data[0] & 0xf) == 0x1:
                return object.__new__(PtpV2DelayRequestHeader)
            if (data[0] & 0xf) == 0x2:
                return object.__new__(PtpV2PathDelayRequestHeader)
            if (data[0] & 0xf) == 0x3:
                return object.__new__(PtpV2PathDelayResponseHeader)
            if (data[0] & 0xf) == 0x8:
                return object.__new__(PtpV2FollowUpHeader)
            if (data[0] & 0xf) == 0xa:
                return object.__new__(PtpV2PathDelayResponseFollowUpHeader)
            if (data[0] & 0xf) == 0xb:
                return object.__new__(PtpV2AnnounceHeader)
            return object.__new__(PtpV2FakeHeader)
        else:
            return object.__new__(cls)

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0] * 46)

    def get_transport_specific(self):
        return (self.data[0] >> 4) & 0xf

    def set_transport_specific(self, value):
        self.data[0] = (self.data[0] & 0xf) | ((value & 0xf) << 4)

    transport_specific = property(get_transport_specific, set_transport_specific)

    def get_message_id(self):
        return self.data[0] & 0xf

    def set_message_id(self, value):
        self.data[0] = ((self.data[0] & 0xf0) | (value & 0xf))

    message_id = property(get_message_id, set_message_id)

    def get_ptp_version(self):
        return self.data[1] & 0xf

    def set_ptp_version(self, value):
        self.data[1] = ((self.data[1] & 0xf0) | (value & 0xf))

    ptp_version = property(get_ptp_version, set_ptp_version)

    def get_message_length(self):
        return (self.data[2] << 8) | self.data[3]

    def set_message_length(self, value):
        self.data[2] = (value >> 8) & 0xff
        self.data[3] = value & 0xff

    message_length = property(get_message_length, set_message_length)

    def get_subdomain_number(self):
        return self.data[4]

    def set_subdomain_number(self, value):
        self.data[4] = value & 0xff

    subdomain_number = property(get_subdomain_number, set_subdomain_number)

    def get_flags(self):
        return (self.data[6] << 8) | self.data[7]

    def set_flags(self, value):
        self.data[6] = (value >> 8) & 0xff
        self.data[7] = value & 0xff

    flags = property(get_flags, set_flags)

    def get_correction(self):
        return (self.data[8] << 40) | (self.data[9] << 32) | (self.data[10] << 24) | (self.data[11] << 16) |\
               (self.data[12] << 8) | self.data[13]

    def set_correction(self, value):
        self.data[8] = (value >> 40) & 0xff
        self.data[9] = (value >> 32) & 0xff
        self.data[10] = (value >> 24) & 0xff
        self.data[11] = (value >> 16) & 0xff
        self.data[12] = (value >> 8) & 0xff
        self.data[13] = value & 0xff

    correction = property(get_correction, set_correction)

    def get_clock_identity(self):
        return (self.data[20] << 56) | (self.data[21] << 48) | (self.data[22] << 40) | (self.data[23] << 32) |\
               (self.data[24] << 24) | (self.data[25] << 16) | (self.data[26] << 8) | self.data[27]

    def set_clock_identity(self, value):
        self.data[20] = (value >> 56) & 0xff
        self.data[21] = (value >> 48) & 0xff
        self.data[22] = (value >> 40) & 0xff
        self.data[23] = (value >> 32) & 0xff
        self.data[24] = (value >> 24) & 0xff
        self.data[25] = (value >> 16) & 0xff
        self.data[26] = (value >> 8) & 0xff
        self.data[27] = value & 0xff

    clock_identity = property(get_clock_identity, set_clock_identity)

    def get_source_port_id(self):
        return (self.data[28] << 8) | self.data[29]

    def set_source_port_id(self, value):
        self.data[28] = (value >> 8) & 0xff
        self.data[29] = value & 0xff

    source_port_id = property(get_source_port_id, set_source_port_id)

    def get_sequence_id(self):
        return (self.data[30] << 8) | self.data[31]

    def set_sequence_id(self, value):
        self.data[30] = (value >> 8) & 0xff
        self.data[31] = value & 0xff

    sequence_id = property(get_sequence_id, set_sequence_id)

    def get_control(self):
        return self.data[32]

    def set_control(self, value):
        self.data[32] = value & 0xff

    control = property(get_control, set_control)

    def get_log_message_period(self):
        return self.data[33]

    def set_log_message_period(self, value):
        self.data[33] = value & 0xff

    log_message_period = property(get_log_message_period, set_log_message_period)

    def get_ts_1(self):
        sec = (self.data[-12] << 40) | (self.data[-11] << 32) | (self.data[-10] << 24) | (self.data[-9] << 16) |\
              (self.data[-8] << 8) | self.data[-7]
        ns = (self.data[-6] << 24) | (self.data[-5] << 16) | (self.data[-4] << 8) | self.data[-3]
        return sec * 1000000000 + ns

    def set_ts_1(self):
        raise NotImplementedError()

    ts_1 = property(get_ts_1, set_ts_1)

    def get_ts_2(self):
        sec = (self.data[-24] << 40) | (self.data[-23] << 32) | (self.data[-22] << 24) | (self.data[-21] << 16) |\
              (self.data[-20] << 8) | self.data[-19]
        ns = (self.data[-18] << 24) | (self.data[-17] << 16) | (self.data[-16] << 8) | self.data[-15]
        return sec * 1000000000 + ns

    def set_ts_2(self):
        raise NotImplementedError()

    ts_2 = property(get_ts_2, set_ts_2)


class PtpV2SyncHeader(PtpV2Header):
    ALLOWED_KEYS = ["transport_specific", "message_id", "ptp_version", "message_length", "subdomain_number",
                    "flags", "correction", "clock_identity", "source_port_id", "sequence_id", "control",
                    "log_message_period", "origin_timestamp"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x00, 0x02, 0x00, 0x2c] + [0] * 40)
        self._apply_properties(**kwargs)

    def get_origin_timestamp(self):
        sec = (self.data[34] << 40) | (self.data[35] << 32) | (self.data[36] << 24) | (self.data[37] << 16) |\
              (self.data[38] << 8) | self.data[39]
        ns = (self.data[40] << 24) | (self.data[41] << 16) | (self.data[42] << 8) | self.data[43]
        return sec * 1000000000 + ns

    def set_origin_timestamp(self, value):
        sec = value // 1000000000
        ns = value - sec * 1000000000
        self.data[34] = (sec >> 40) & 0xff
        self.data[35] = (sec >> 32) & 0xff
        self.data[36] = (sec >> 24) & 0xff
        self.data[37] = (sec >> 16) & 0xff
        self.data[38] = (sec >> 8) & 0xff
        self.data[39] = sec & 0xff
        self.data[40] = (ns >> 24) & 0xff
        self.data[41] = (ns >> 16) & 0xff
        self.data[42] = (ns >> 8) & 0xff
        self.data[43] = ns & 0xff

    origin_timestamp = property(get_origin_timestamp, set_origin_timestamp)


class PtpV2FakeHeader(PtpV2SyncHeader):
    pass


class PtpV2DelayRequestHeader(PtpV2Header):
    ALLOWED_KEYS = ["transport_specific", "message_id", "ptp_version", "message_length", "subdomain_number",
                    "flags", "correction", "clock_identity", "source_port_id", "sequence_id", "control",
                    "log_message_period", "origin_timestamp"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x1, 0x2, 0x00, 0x2c] + [0] * 40)
        self._apply_properties(**kwargs)

    def get_origin_timestamp(self):
        sec = (self.data[34] << 40) | (self.data[35] << 32) | (self.data[36] << 24) | (self.data[37] << 16) |\
              (self.data[38] << 8) | self.data[39]
        ns = (self.data[40] << 24) | (self.data[41] << 16) | (self.data[42] << 8) | self.data[43]
        return sec * 1000000000 + ns

    def set_origin_timestamp(self, value):
        sec = value // 1000000000
        ns = value - sec * 1000000000
        self.data[34] = (sec >> 40) & 0xff
        self.data[35] = (sec >> 32) & 0xff
        self.data[36] = (sec >> 24) & 0xff
        self.data[37] = (sec >> 16) & 0xff
        self.data[38] = (sec >> 8) & 0xff
        self.data[39] = sec & 0xff
        self.data[40] = (ns >> 24) & 0xff
        self.data[41] = (ns >> 16) & 0xff
        self.data[42] = (ns >> 8) & 0xff
        self.data[43] = ns & 0xff

    origin_timestamp = property(get_origin_timestamp, set_origin_timestamp)


class PtpV2FollowUpHeader(PtpV2Header):
    ALLOWED_KEYS = ["transport_specific", "message_id", "ptp_version", "message_length", "subdomain_number",
                    "flags", "correction", "clock_identity", "source_port_id", "sequence_id", "control",
                    "log_message_period", "precise_origin_timestamp"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x08, 0x02, 0x00, 0x2c] + [0] * 40)
        self._apply_properties(**kwargs)

    def get_precise_origin_timestamp(self):
        sec = (self.data[34] << 40) | (self.data[35] << 32) | (self.data[36] << 24) | (self.data[37] << 16) |\
              (self.data[38] << 8) | self.data[39]
        ns = (self.data[40] << 24) | (self.data[41] << 16) | (self.data[42] << 8) | self.data[43]
        return sec * 1000000000 + ns

    def set_precise_origin_timestamp(self, value):
        sec = value // 1000000000
        ns = value - sec * 1000000000
        self.data[34] = (sec >> 40) & 0xff
        self.data[35] = (sec >> 32) & 0xff
        self.data[36] = (sec >> 24) & 0xff
        self.data[37] = (sec >> 16) & 0xff
        self.data[38] = (sec >> 8) & 0xff
        self.data[39] = sec & 0xff
        self.data[40] = (ns >> 24) & 0xff
        self.data[41] = (ns >> 16) & 0xff
        self.data[42] = (ns >> 8) & 0xff
        self.data[43] = ns & 0xff

    precise_origin_timestamp = property(get_precise_origin_timestamp, set_precise_origin_timestamp)


class PtpV2PathDelayRequestHeader(PtpV2Header):
    ALLOWED_KEYS = ["transport_specific", "message_id", "ptp_version", "message_length", "subdomain_number",
                    "flags", "correction", "clock_identity", "source_port_id", "sequence_id", "control",
                    "log_message_period", "origin_timestamp"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x2, 0x2, 0x00, 0x36] + [0] * 50)
        self._apply_properties(**kwargs)

    def get_origin_timestamp(self):
        sec = (self.data[34] << 40) | (self.data[35] << 32) | (self.data[36] << 24) | (self.data[37] << 16) |\
              (self.data[38] << 8) | self.data[39]
        ns = (self.data[40] << 24) | (self.data[41] << 16) | (self.data[42] << 8) | self.data[43]
        return sec * 1000000000 + ns

    def set_origin_timestamp(self, value):
        sec = value // 1000000000
        ns = value - sec * 1000000000
        self.data[34] = (sec >> 40) & 0xff
        self.data[35] = (sec >> 32) & 0xff
        self.data[36] = (sec >> 24) & 0xff
        self.data[37] = (sec >> 16) & 0xff
        self.data[38] = (sec >> 8) & 0xff
        self.data[39] = sec & 0xff
        self.data[40] = (ns >> 24) & 0xff
        self.data[41] = (ns >> 16) & 0xff
        self.data[42] = (ns >> 8) & 0xff
        self.data[43] = ns & 0xff

    origin_timestamp = property(get_origin_timestamp, set_origin_timestamp)


class PtpV2PathDelayResponseHeader(PtpV2Header):
    ALLOWED_KEYS = ["transport_specific", "message_id", "ptp_version", "message_length", "subdomain_number",
                    "flags", "correction", "clock_identity", "source_port_id", "sequence_id", "control",
                    "log_message_period", "request_receipt_timestamp", "requesting_source_port_identity",
                    "requesting_source_port_id"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x03, 0x02, 0x00, 0x36] + [0] * 50)
        self._apply_properties(**kwargs)

    def get_request_receipt_timestamp(self):
        sec = (self.data[34] << 40) | (self.data[35] << 32) | (self.data[36] << 24) | (self.data[37] << 16) |\
              (self.data[38] << 8) | self.data[39]
        ns = (self.data[40] << 24) | (self.data[41] << 16) | (self.data[42] << 8) | self.data[43]
        return sec * 1000000000 + ns

    def set_request_receipt_timestamp(self, value):
        sec = value // 1000000000
        ns = value - sec * 1000000000
        self.data[34] = (sec >> 40) & 0xff
        self.data[35] = (sec >> 32) & 0xff
        self.data[36] = (sec >> 24) & 0xff
        self.data[37] = (sec >> 16) & 0xff
        self.data[38] = (sec >> 8) & 0xff
        self.data[39] = sec & 0xff
        self.data[40] = (ns >> 24) & 0xff
        self.data[41] = (ns >> 16) & 0xff
        self.data[42] = (ns >> 8) & 0xff
        self.data[43] = ns & 0xff

    request_receipt_timestamp = property(get_request_receipt_timestamp, set_request_receipt_timestamp)

    def get_requesting_source_port_identity(self):
        return (self.data[44] << 56) | (self.data[45] << 48) | (self.data[46] << 40) | (self.data[47] << 32) |\
               (self.data[48] << 24) | (self.data[49] << 16) | (self.data[50] << 8) | self.data[51]

    def set_requesting_source_port_identity(self, value):
        self.data[44] = (value >> 56) & 0xff
        self.data[45] = (value >> 48) & 0xff
        self.data[46] = (value >> 40) & 0xff
        self.data[47] = (value >> 32) & 0xff
        self.data[48] = (value >> 24) & 0xff
        self.data[49] = (value >> 16) & 0xff
        self.data[50] = (value >> 8) & 0xff
        self.data[51] = value & 0xff

    requesting_source_port_identity = property(get_requesting_source_port_identity,
                                               set_requesting_source_port_identity)

    def get_requesting_source_port_id(self):
        return (self.data[52] << 8) | self.data[53]

    def set_requesting_source_port_id(self, value):
        self.data[52] = (value >> 8) & 0xff
        self.data[53] = value & 0xff

    requesting_source_port_id = property(get_requesting_source_port_id, set_requesting_source_port_id)


class PtpV2PathDelayResponseFollowUpHeader(PtpV2Header):
    ALLOWED_KEYS = ["transport_specific", "message_id", "ptp_version", "message_length", "subdomain_number",
                    "flags", "correction", "clock_identity", "source_port_id", "sequence_id", "control",
                    "log_message_period", "response_origin_timestamp", "requesting_source_port_identity",
                    "requesting_source_port_id"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x0a, 0x02, 0x00, 0x36] + [0] * 50)
        self._apply_properties(**kwargs)

    def get_response_origin_timestamp(self):
        sec = (self.data[34] << 40) | (self.data[35] << 32) | (self.data[36] << 24) | (self.data[37] << 16) |\
              (self.data[38] << 8) | self.data[39]
        ns = (self.data[40] << 24) | (self.data[41] << 16) | (self.data[42] << 8) | self.data[43]
        return sec * 1000000000 + ns

    def set_response_origin_timestamp(self, value):
        sec = value // 1000000000
        ns = value - sec * 1000000000
        self.data[34] = (sec >> 40) & 0xff
        self.data[35] = (sec >> 32) & 0xff
        self.data[36] = (sec >> 24) & 0xff
        self.data[37] = (sec >> 16) & 0xff
        self.data[38] = (sec >> 8) & 0xff
        self.data[39] = sec & 0xff
        self.data[40] = (ns >> 24) & 0xff
        self.data[41] = (ns >> 16) & 0xff
        self.data[42] = (ns >> 8) & 0xff
        self.data[43] = ns & 0xff

    response_origin_timestamp = property(get_response_origin_timestamp, set_response_origin_timestamp)

    def get_requesting_source_port_identity(self):
        return (self.data[44] << 56) | (self.data[45] << 48) | (self.data[46] << 40) | (self.data[47] << 32) |\
               (self.data[48] << 24) | (self.data[49] << 16) | (self.data[50] << 8) | self.data[51]

    def set_requesting_source_port_identity(self, value):
        self.data[44] = (value >> 56) & 0xff
        self.data[45] = (value >> 48) & 0xff
        self.data[46] = (value >> 40) & 0xff
        self.data[47] = (value >> 32) & 0xff
        self.data[48] = (value >> 24) & 0xff
        self.data[49] = (value >> 16) & 0xff
        self.data[50] = (value >> 8) & 0xff
        self.data[51] = value & 0xff

    requesting_source_port_identity = property(get_requesting_source_port_identity,
                                               set_requesting_source_port_identity)

    def get_requesting_source_port_id(self):
        return (self.data[52] << 8) | self.data[53]

    def set_requesting_source_port_id(self, value):
        self.data[52] = (value >> 8) & 0xff
        self.data[53] = value & 0xff

    requesting_source_port_id = property(get_requesting_source_port_id, set_requesting_source_port_id)


class PtpV2AnnounceHeader(PtpV2Header):
    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x0b, 0x02, 0x00, 0x40] + [0] * 60)
        self._apply_properties(**kwargs)


class IPv4Header(Header):
    ALLOWED_KEYS = ["version", "ihl", "dscp", "ecn", "length", "identification", "flags",
                    "ttl", "protocol", "checksum", "src", "dst"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x45] + [0] * 19)
        self._apply_properties(**kwargs)

    def get_version(self):
        return (self.data[0] >> 4) & 0xf

    def set_version(self, value):
        self.data[0] = (self.data[0] & 0xf) | ((value & 0xf) << 4)

    version = property(get_version, set_version)

    def get_ihl(self):
        return (self.data[0] & 0xf)

    def set_ihl(self, value):
        self.data[0] = (self.data[0] & 0xf0) | value & 0xf

    ihl = property(get_ihl, set_ihl)

    def get_dscp(self):
        return self.data[1]

    def set_dscp(self, value):
        self.data[1] = value & 0xff

    dscp = property(get_dscp, set_dscp)

    def get_length(self):
        return self.data[2] << 8 | self.data[3]

    def set_length(self, value):
        self.data[2] = (value >> 8) & 0xff
        self.data[3] = value & 0xff

    length = property(get_length, set_length)

    def get_identification(self):
        return self.data[4] << 8 | self.data[5]

    def set_identification(self, value):
        self.data[4] = (value >> 8) & 0xff
        self.data[5] = value & 0xff

    identification = property(get_identification, set_identification)

    def get_flags(self):
        return self.data[6] << 8 | self.data[7]

    def set_flags(self, value):
        self.data[6] = (value >> 8) & 0xff
        self.data[7] = value & 0xff

    flags = property(get_flags, set_flags)

    def get_ttl(self):
        return self.data[8]

    def set_ttl(self, value):
        self.data[8] = value & 0xff

    ttl = property(get_ttl, set_ttl)

    def get_protocol(self):
        return self.data[9]

    def set_protocol(self, value):
        self.data[9] = value & 0xff

    protocol = property(get_protocol, set_protocol)

    def get_checksum(self):
        return self.data[10] << 8 | self.data[11]

    def set_checksum(self, value):
        self.data[10] = (value >> 8) & 0xff
        self.data[11] = value & 0xff

    checksum = property(get_checksum, set_checksum)

    def get_src(self):
        return "%d.%d.%d.%d" % (self.data[12], self.data[13], self.data[14], self.data[15])

    def set_src(self, value):
        data = value.split(".")
        for i in range(4):
            self.data[i + 12] = int(data[i])

    src = property(get_src, set_src)

    def get_dst(self):
        return "%d.%d.%d.%d" % (self.data[16], self.data[17], self.data[18], self.data[19])

    def set_dst(self, value):
        data = value.split(".")
        for i in range(4):
            self.data[i + 16] = int(data[i])

    dst = property(get_dst, set_dst)


class IPv6Header(Header):
    ALLOWED_KEYS = ["version", "traffic_class", "flow_label", "payload_length",
                    "next_header", "hop_limit", "src", "dst"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x60] + [0] * 39)
        self._apply_properties(**kwargs)

    def get_version(self):
        return (self.data[0] >> 4) & 0xf

    def set_version(self, value):
        self.data[0] = (self.data[0] & 0xf) | ((value & 0xf) << 4)

    version = property(get_version, set_version)

    def get_traffic_class(self):
        return ((self.data[0] & 0xf) << 4) | (self.data[1] & 0xf0 >> 4)

    def set_traffic_class(self, value):
        self.data[0] = (self.data[0] & 0xf0) | ((value & 0xf0) >> 4)
        self.data[1] = (self.data[1] & 0xf) | ((value & 0xf) << 4)

    traffic_class = property(get_traffic_class, set_traffic_class)

    def get_flow_label(self):
        return ((self.data[1] & 0xf) << 16) | (self.data[2] << 8) | self.data[3]

    def set_flow_label(self, value):
        self.data[1] = (self.data[1] & 0xf0) | ((value >> 16) & 0xf)

    flow_label = property(get_traffic_class, set_traffic_class)

    def get_payload_length(self):
        return (self.data[4] << 8) | self.data[5]

    def set_payload_length(self, value):
        self.data[4] = (value >> 8) & 0xff
        self.data[5] = value & 0xff

    payload_length = property(get_payload_length, set_payload_length)

    def get_next_header(self):
        return self.data[6]

    def set_next_header(self, value):
        self.data[6] = value & 0xff

    next_header = property(get_next_header, set_next_header)

    def get_hop_limit(self):
        return self.data[7]

    def set_hop_limit(self, value):
        self.data[7] = value & 0xff

    hop_limit = property(get_hop_limit, set_hop_limit)

    def get_src(self):
        return "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x" % \
            (self.data[8], self.data[9], self.data[10], self.data[11], self.data[12], self.data[13],
             self.data[14], self.data[15], self.data[16], self.data[17], self.data[18], self.data[19],
             self.data[20], self.data[21], self.data[22], self.data[23])

    def set_src(self, value):
        data = value.split(":")
        assert len(data) == 8
        for i in range(8):
            assert len(data[i]) == 4
            msw = data[i][:2]
            lsw = data[i][2:]
            self.data[8 + i * 2] = int(msw, 16)
            self.data[8 + i * 2 + 1] = int(lsw, 16)

    src = property(get_src, set_src)

    def get_dst(self):
        return "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x" % \
            (self.data[24], self.data[25], self.data[26], self.data[27], self.data[28], self.data[29],
             self.data[30], self.data[31], self.data[32], self.data[33], self.data[34], self.data[35],
             self.data[36], self.data[37], self.data[38], self.data[39])

    def set_dst(self, value):
        data = value.split(":")
        assert len(data) == 8
        for i in range(8):
            assert len(data[i]) == 4
            msw = data[i][:2]
            lsw = data[i][2:]
            self.data[24 + i * 2] = int(msw, 16)
            self.data[24 + i * 2 + 1] = int(lsw, 16)

    dst = property(get_dst, set_dst)


class UdpHeader(Header):
    ALLOWED_KEYS = ["src", "dst", "length", "checksum"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x0] * 8)
        self._apply_properties(**kwargs)

    def get_src(self):
        return (self.data[0] << 8) | self.data[1]

    def set_src(self, value):
        self.data[0] = (value >> 8) & 0xff
        self.data[1] = value & 0xff

    src = property(get_src, set_src)

    def get_dst(self):
        return (self.data[2] << 8) | self.data[3]

    def set_dst(self, value):
        self.data[2] = (value >> 8) & 0xff
        self.data[3] = value & 0xff

    dst = property(get_dst, set_dst)

    def get_length(self):
        return (self.data[4] << 8) | self.data[5]

    def set_length(self, value):
        self.data[4] = (value >> 8) & 0xff
        self.data[5] = value & 0xff

    length = property(get_length, set_length)

    def get_checksum(self):
        return (self.data[6] << 8) | self.data[7]

    def set_checksum(self, value):
        self.data[6] = (value >> 8) & 0xff
        self.data[7] = value & 0xff

    checksum = property(get_checksum, set_checksum)


class NtpHeader(Header):
    ALLOWED_KEYS = ["flags", "peer_clock_stratum", "peer_polling_interval", "peer_clock_precision", "root_delay"]

    def __init__(self, **kwargs):
        self.data = kwargs.get("data", [0x0] * 48)
        self._apply_properties(**kwargs)

    def get_flags(self):
        return self.data[0]

    def set_flags(self, value):
        self.data[0] = value & 0xff

    flags = property(get_flags, set_flags)

    def get_peer_clock_stratum(self):
        return self.data[1]

    def set_peer_clock_stratum(self, value):
        self.data[1] = value & 0xff

    peer_clock_stratum = property(get_peer_clock_stratum, set_peer_clock_stratum)

    def get_peer_clock_precision(self):
        return self.data[3]

    def set_peer_clock_precision(self, value):
        self.data[3] = value & 0xff

    peer_clock_precision = property(get_peer_clock_precision, set_peer_clock_precision)

    def get_root_delay(self):
        return self.data[3]

    def set_root_delay(self, value):
        self.data[3] = value & 0xff

    root_delay = property(get_root_delay, set_root_delay)


class Packet(object):
    def __init__(self, data):
        self.data = data

    def __getitem__(self, key):
        if key == 0 or key == EthernetHeader:
            return EthernetHeader(data=self.data[0:14])
        if key == 1:
            if self[0].type == 0x88f7:
                return PtpV2Header(data=self.data[14:])
            if self[0].type == ETH_TYPE_IPv4:
                IPv4Header(data=self.data[14:])
        if key in [PtpV2SyncHeader, PtpV2DelayRequestHeader, PtpV2FollowUpHeader, PtpV2PathDelayRequestHeader,
                   PtpV2PathDelayResponseHeader, PtpV2PathDelayResponseFollowUpHeader, PtpV2AnnounceHeader,
                   IPv4Header, IPv6Header]:
            return key(data=self.data[14:])

    def __str__(self):
        sdata = ""
        for d in self.data:
            sdata += "%02x" % (d)
        return sdata

    def __len__(self):
        return len(self.data)

    def __div__(self, other):
        assert isinstance(other, Header)
        return Packet(data=self.data + other.data)

    def get_crc16(self, data):
        i = 0
        s = 0
        while i < len(data):
            s += (data[i] << 8) + data[i + 1]
            i += 2
        while s > 0xffff:
            res = 0
            while s != 0:
                res += (s & 0xffff)
                s >>= 16
            s = res
        return ~s

    def calculate_checksums(self):
        if self[0].type == ETH_TYPE_IPv4:
            ipv4_header_len = self[IPv4Header].ihl * 4
            ipv4_header_data = self.data[14: 14 + ipv4_header_len]
            ipv4_header_data[10] = 0
            ipv4_header_data[11] = 0
            ipv4_header_crc = self.get_crc16(ipv4_header_data)
            self.data[14 + 10] = (ipv4_header_crc >> 8) & 0xff
            self.data[14 + 11] = ipv4_header_crc & 0xff


def read_pcap(file_path):
    packets = []
    try:
        f = open(file_path, "rb")
        f.read(24)  # global header
        while True:
            ph = f.read(16)
            if ph == "":
                break
            # ts_sec = ord(ph[3]) << 24 | ord(ph[2]) << 16 | ord(ph[1]) << 8 | ord(ph[0])
            # ts_usec = ord(ph[7]) << 24 | ord(ph[6]) << 16 | ord(ph[5]) << 8 | ord(ph[4])
            incl_len = ord(ph[11]) << 24 | ord(ph[10]) << 16 | ord(ph[9]) << 8 | ord(ph[8])
            # orig_len = ord(ph[15]) << 24 | ord(ph[14]) << 16 | ord(ph[13]) << 8 | ord(ph[12])

            pkt = []
            for i in range(incl_len):
                pkt.append(ord(f.read(1)))

            packets.append(Packet(data=pkt))
        return packets
    finally:
        f.close()


class TestPhyPtpBase(unittest.TestCase):
    SRC_MAC = "00:17:b6:48:25:8a"
    DST_MAC_IEEE_1588_0 = "01:1B:19:00:00:00"
    DST_MAC_IEEE_1588_1 = "01:80:c2:00:00:0e"
    PTP_ETH_TYPE = 0x88f7
    PATH_DELAY_RESPONSE_PAYLOAD = "03020036000002000000000000000000000000000017b6ff"\
        "fe5758590001014e057f00005b854d1229c4ac5b0017b6fffe3016180001"
    LKP_IP_ADDR = "192.168.0.217"
    LKP_MAC_ADDR = "00:17:b6:db:8d:bb"
    LKP_HOSTNAME = "at217-tuf"
    DIRECTION_EGRESS = "EGRESS"
    DIRECTION_INGRESS = "INGRESS"
    LINK_SPEED = LINK_SPEED_1G

    def setUp(self):
        # TODO: hardcoded

        hostname = socket.gethostname()
        if hostname == "at068-h81m":
            self.pa = PhyAccessBer(validation_path="D:/common_rev1.0_Validation/Validation",
                                   board="mPODC0044:MDIO",
                                   phyid=0)
            self.LKP_HOSTNAME = "at069-h81m"
        elif hostname == "sj254-b85m":
            self.pa = PhyAccessBer(validation_path="S:/wa/common_rev1.0_Validation/Validation",
                                   board="M0CRRV0C0170-R1S12V0A017",
                                   phyid=0)
            self.LKP_HOSTNAME = "sj255-h97m"
        elif hostname == "at257-prime":
            self.pa = PhyAccessBer(validation_path="D:/iloz/common_rev1.0_Validation/Validation",
                                   board="POD77DA004:MDIO",
                                   phyid=0)
            self.LKP_HOSTNAME = "at258-prime"
        else:
            self.pa = PhyAccessBer(validation_path="D:/common_rev1.0_Validation/Validation",
                                   board="ES07V0A089",
                                   phyid=0)
            self.LKP_HOSTNAME = "at217-tuf"

    def extract_egress_ts(self, poll=False, timeout=10):
        PTP_TS_READ_CNT = 10  # 1 x SeqId + 1 x xxx + 3 x sec + 2 x ns + 3 x yyy
        PTP_HEADER_TS_READ_CNT = 2  # 1 x SeqId + 1 x xxx
        PTP_SEC_TS_READ_CNT = 3  # 3 x sec
        PTP_NS_TS_READ_CNT = 2  # 2 x ns
        PTP_BASE_TS_READ_CNT = PTP_HEADER_TS_READ_CNT + PTP_SEC_TS_READ_CNT + PTP_NS_TS_READ_CNT

        stream_id = 0
        sec = 0
        ns = 0

        def poll_ptp_egr_ts_ready():
            print "Polling PTP Egress packet time stamp ready bit"
            start = timeit.default_timer()
            while timeit.default_timer() - start < timeout:
                val = self.pa.readphyreg(0x3, 0xcc06)
                pkt_ready = val & 0x1
                ts_ready = (val & 0x2) >> 1
                pkt_buf_overflow_err = (val & 0x4) >> 2
                pkt_cor_field_err = (val & 0x8) >> 3
                pkt_buf_parity_err = (val & 0x10) >> 4
                ts_buf_parity_err = (val & 0x20) >> 5
                pkt_pipeline_parity_err = (val & 0x40) >> 6
                pkt_pipeline_fifo_err = (val & 0x80) >> 7
                pkt_received = (val & 0x100) >> 8
                pkt_remove_err = (val & 0x200) >> 9
                pkt_ready_fifo_parity_err = (val & 0x400) >> 0xa
                pkt_ready_fifo_err = (val & 0x800) >> 0xb
                ts_buf_overflow_err = (val & 0x1000) >> 0xc
                pkt_status_fifo_err = (val & 0x2000) >> 0xd
                pkt_gap_fifo_parity_err = (val & 0x4000) >> 0xe
                pkt_gap_fifo_err = (val & 0x8000) >> 0xf
                if any([pkt_cor_field_err, pkt_buf_parity_err, ts_buf_parity_err, pkt_pipeline_parity_err,
                        pkt_pipeline_fifo_err, pkt_remove_err, pkt_ready_fifo_parity_err, pkt_ready_fifo_err,
                        pkt_status_fifo_err, pkt_gap_fifo_parity_err, pkt_gap_fifo_err]):
                    print "!!! ERROR DETECTED"
                    print "pkt_ready", pkt_ready
                    print "ts_ready", ts_ready
                    print "pkt_buf_overflow_err", pkt_buf_overflow_err
                    print "pkt_cor_field_err", pkt_cor_field_err
                    print "pkt_buf_parity_err", pkt_buf_parity_err
                    print "ts_buf_parity_err", ts_buf_parity_err
                    print "pkt_pipeline_parity_err", pkt_pipeline_parity_err
                    print "pkt_pipeline_fifo_err", pkt_pipeline_fifo_err
                    print "pkt_received", pkt_received
                    print "pkt_remove_err", pkt_remove_err
                    print "pkt_ready_fifo_parity_err", pkt_ready_fifo_parity_err
                    print "pkt_ready_fifo_err", pkt_ready_fifo_err
                    print "ts_buf_overflow_err", ts_buf_overflow_err
                    print "pkt_status_fifo_err", pkt_status_fifo_err
                    print "pkt_gap_fifo_parity_err", pkt_gap_fifo_parity_err
                    print "pkt_gap_fifo_err", pkt_gap_fifo_err
                    # raise Exception("Vendor alarm error")
                if ts_ready:
                    print "PTP Egress packet time stamp is ready"
                    break
                else:
                    time.sleep(0.1)
            else:
                raise Exception("No egress timestamp after %d seconds waiting" % (timeout))

        print "Extracting egress timestamp"

        if poll:
            poll_ptp_egr_ts_ready()

        self.pa.writephyreg(3, 0xC640, 0)
        for i in range(PTP_TS_READ_CNT):
            val = self.pa.readphyreg(0x3, 0xc935)
            self.pa.writephyreg(3, 0xC640, 1)
            self.pa.writephyreg(3, 0xC640, 0)

            if i < 2:
                stream_id |= (val & 0xffff) << (16 * (PTP_HEADER_TS_READ_CNT - 1 - i))
            elif i < PTP_BASE_TS_READ_CNT:
                if i < PTP_HEADER_TS_READ_CNT + PTP_SEC_TS_READ_CNT:
                    sec |= (val & 0xffff) << (16 * (PTP_HEADER_TS_READ_CNT + PTP_SEC_TS_READ_CNT - 1 - i))
                else:
                    ns |= (val & 0xffff) << (16 * (PTP_BASE_TS_READ_CNT - 1 - i))

        print "Egress timestamp info: stream_id 0x%08x sec 0x%08x ns 0x%08x" % (stream_id, sec, ns)
        return stream_id, sec * 1000000000 + ns

    def extract_ingress_ts(self, poll=False, timeout=10):
        PTP_TS_READ_CNT = 10  # 1 x SeqId + 1 x xxx + 3 x sec + 2 x ns + 3 x yyy
        PTP_HEADER_TS_READ_CNT = 2  # 1 x SeqId + 1 x xxx
        PTP_SEC_TS_READ_CNT = 3  # 3 x sec
        PTP_NS_TS_READ_CNT = 2  # 2 x ns
        PTP_BASE_TS_READ_CNT = PTP_HEADER_TS_READ_CNT + PTP_SEC_TS_READ_CNT + PTP_NS_TS_READ_CNT

        stream_id = 0
        sec = 0
        ns = 0

        def poll_ptp_ing_ts_ready():
            print "Polling PTP Ingress packet time stamp ready bit"
            start = timeit.default_timer()
            while timeit.default_timer() - start < timeout:
                val = self.pa.readphyreg(0x3, 0xec09)
                pkt_ready = val & 0x1
                ts_ready = (val & 0x2) >> 1
                pkt_buf_overflow_err = (val & 0x4) >> 2
                pkt_cor_field_err = (val & 0x8) >> 3
                pkt_buf_parity_err = (val & 0x10) >> 4
                ts_buf_parity_err = (val & 0x20) >> 5
                pkt_pipeline_parity_err = (val & 0x40) >> 6
                pkt_pipeline_fifo_err = (val & 0x80) >> 7
                pkt_received = (val & 0x100) >> 8
                pkt_remove_err = (val & 0x200) >> 9
                pkt_ready_fifo_parity_err = (val & 0x400) >> 0xa
                pkt_ready_fifo_err = (val & 0x800) >> 0xb
                pkt_gap_fifo_parity_err = (val & 0x1000) >> 0xc
                pkt_gap_fifo_err = (val & 0x2000) >> 0xd
                pkt_status_fifo_err = (val & 0x4000) >> 0xe
                ts_buf_overflow_err = (val & 0x8000) >> 0xf
                if any([pkt_cor_field_err, pkt_buf_parity_err, ts_buf_parity_err, pkt_pipeline_parity_err,
                        pkt_pipeline_fifo_err, pkt_remove_err, pkt_ready_fifo_parity_err, pkt_ready_fifo_err,
                        pkt_status_fifo_err, pkt_gap_fifo_parity_err, pkt_gap_fifo_err]):
                    print "!!! ERROR DETECTED"
                    print "pkt_ready", pkt_ready
                    print "ts_ready", ts_ready
                    print "pkt_buf_overflow_err", pkt_buf_overflow_err
                    print "pkt_cor_field_err", pkt_cor_field_err
                    print "pkt_buf_parity_err", pkt_buf_parity_err
                    print "ts_buf_parity_err", ts_buf_parity_err
                    print "pkt_pipeline_parity_err", pkt_pipeline_parity_err
                    print "pkt_pipeline_fifo_err", pkt_pipeline_fifo_err
                    print "pkt_received", pkt_received
                    print "pkt_remove_err", pkt_remove_err
                    print "pkt_ready_fifo_parity_err", pkt_ready_fifo_parity_err
                    print "pkt_ready_fifo_err", pkt_ready_fifo_err
                    print "ts_buf_overflow_err", ts_buf_overflow_err
                    print "pkt_status_fifo_err", pkt_status_fifo_err
                    print "pkt_gap_fifo_parity_err", pkt_gap_fifo_parity_err
                    print "pkt_gap_fifo_err", pkt_gap_fifo_err
                    # raise Exception("Vendor alarm error")
                if ts_ready:
                    print "PTP Ingress packet time stamp is ready"
                    break
                else:
                    time.sleep(0.1)
            else:
                raise Exception("No ingress timestamp after %d seconds waiting" % (timeout))

        print "Extracting ingress timestamp"

        if poll:
            poll_ptp_ing_ts_ready()

        self.pa.writephyreg(3, 0xE620, 0)
        for i in range(PTP_TS_READ_CNT):
            val = self.pa.readphyreg(0x3, 0xE905)
            self.pa.writephyreg(3, 0xE620, 1)
            self.pa.writephyreg(3, 0xE620, 0)

            if i < 2:
                stream_id |= (val & 0xffff) << (16 * (PTP_HEADER_TS_READ_CNT - 1 - i))
            elif i < PTP_BASE_TS_READ_CNT:
                if i < PTP_HEADER_TS_READ_CNT + PTP_SEC_TS_READ_CNT:
                    sec |= (val & 0xffff) << (16 * (PTP_HEADER_TS_READ_CNT + PTP_SEC_TS_READ_CNT - 1 - i))
                else:
                    ns |= (val & 0xffff) << (16 * (PTP_BASE_TS_READ_CNT - 1 - i))

        print "Ingress timestamp info: stream_id 0x%08x sec 0x%08x ns 0x%08x" % (stream_id, sec, ns)
        return stream_id, sec * 1000000000 + ns

    def cleanup_ts(self):
        ts = -1
        while ts != 0:
            _, ts = self.extract_egress_ts(poll=False)
        ts = -1
        while ts != 0:
            _, ts = self.extract_ingress_ts(poll=False)

    def send_packet(self, packet, host=None):
        cmd = "aqsendp -p %s" % (str(packet))
        if host is not None:
            cmd = "ssh aqtest@%s 'sudo %s'" % (host, cmd)

        print "Sending %s packet %s" % ("egress" if host is None else "ingress", str(packet))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        output, _ = p.communicate()

    def send_l2_packet(self, dst_mac, src_mac, eth_type, payload, host=None):
        data = dst_mac.replace(":", "") + src_mac.replace(":", "") + "%04x" % (eth_type) + payload
        cmd = "aqsendp -p %s" % (data)
        if host is not None:
            cmd = "ssh aqtest@%s 'sudo %s'" % (host, cmd)

        print "Sending packet %s" % (data)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        output, _ = p.communicate()

    def __uncapitalize(self, s):
        return s[:1].lower() + s[1:] if s else ""

    def verify_stream_id_and_egress_ts_are_zero(self, msg=None):
        stream_id, ts = self.extract_egress_ts()
        self.assertTrue(stream_id == 0, "Stream ID should be zero because " + self.__uncapitalize(msg))
        self.assertTrue(ts == 0, "Timestamp should be zero because " + self.__uncapitalize(msg))

    def verify_stream_id_and_ingress_ts_are_zero(self, msg=None):
        stream_id, ts = self.extract_ingress_ts()
        self.assertTrue(stream_id == 0, "Stream ID should be zero because " + self.__uncapitalize(msg))
        self.assertTrue(ts == 0, "Timestamp should be zero because " + self.__uncapitalize(msg))

    def verify_stream_id_and_egress_ts_are_not_zero(self, msg):
        stream_id, ts = self.extract_egress_ts()
        self.pa.readphyreg(0x3, 0xcc06)
        self.assertTrue(stream_id != 0, "Stream ID should not be zero because " + self.__uncapitalize(msg))
        self.assertTrue(ts != 0, "Timestamp should not be zero because " + self.__uncapitalize(msg))

    def verify_stream_id_and_ingress_ts_are_not_zero(self, msg):
        stream_id, ts = self.extract_ingress_ts()
        self.assertTrue(stream_id != 0, "Stream ID should not be zero because " + self.__uncapitalize(msg))
        self.assertTrue(ts != 0, "Timestamp should not be zero because " + self.__uncapitalize(msg))

    def begin_capture(self, _time, _file, iface=None, filter=None, host=None):
        ctx = {}

        if host is not None:
            cmd = "ssh aqtest@%s 'python -c \"import sys; print sys.platform\"'" % (host)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            output, _ = p.communicate()

            is_remote_os_win = False
            if "win" in output:
                is_remote_os_win = True
                iface = "Ethernet 2"
            else:
                iface = "enp1s0"

        # p = subprocess.Popen("tshark -D", stdout=subprocess.PIPE, shell=True)
        # output, _ = p.communicate()

        # if iface is not None:
        # idx = -1
        # re_idx_iface = re.compile(r"^([0-9]+)\. .* \((Ethernet [0-9]+)\).*", re.DOTALL)
        # for line in output.split("\n"):
        #     if iface in line:
        #         m = re_idx_iface.match(line)
        #         if m is not None:
        #             idx = int(m.group(1))
        #         else:
        #             raise Exception("Failed to find iface")

        if host is None or is_remote_os_win:
            # We are running on Windows for sure if host is None
            cmd = "tshark -a duration:%d -F pcap -w %s" % (_time, _file)
        else:
            cmd = "sudo timeout %d tcpdump -w %s" % (_time, _file)


        if filter is not None:
            cmd += " -f \"%s\"" % (filter)
        if iface is not None:
            cmd += " -i \"%s\"" % (iface)

        if host is not None:
            cmd = "ssh aqtest@%s '%s'" % (host, cmd)

        print cmd
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

        cbuf = ""
        cbuf_max_len = 15
        patterns = ["listening on", "Capturing on"]

        while True:
            if proc.poll() is not None:
                break
            ch = proc.stdout.read(1)
            if len(cbuf) >= cbuf_max_len:
                cbuf = cbuf[1:]
            cbuf += ch

            if any(p in cbuf for p in patterns):
                break

        print "Capturing has been started"

        ctx["proc"] = proc
        ctx["file"] = _file
        ctx["host"] = host

        return ctx

    def end_capture(self, ctx):
        while ctx["proc"].poll() is None:
            print "Waiting for capture process end"
            time.sleep(1)
        if ctx["host"] is not None:
            cmd = "scp aqtest@%s:%s ./" % (ctx["host"], ctx["file"])
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            output, _ = p.communicate()

        return read_pcap(ctx["file"])

    def reset_egress_ptp_fifo(self):
        val = self.pa.readphyreg(0x3, 0xc63e)
        val |= 0x1 << 0xf
        self.pa.writephyreg(0x3, 0xc63e, val)
        val = val & ~(0x1 << 0xf)
        self.pa.writephyreg(0x3, 0xc63e, val)
        time.sleep(1)

    def reset_ingress_ptp_fifo(self):
        val = self.pa.readphyreg(0x3, 0xe61e)
        val |= 0x1 << 0xf
        self.pa.writephyreg(0x3, 0xe61e, val)
        val = val & ~(0x1 << 0xf)
        self.pa.writephyreg(0x3, 0xe61e, val)
        time.sleep(1)

    def phy_basic_config(self, speed):
        pc = PtpConfig(speed=speed)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.apply(self.pa)
        time.sleep(1)

    def read_ptp_clock(self):
        val = self.pa.readphyreg(0x3, 0xc60a)
        self.pa.writephyreg(0x3, 0xc60a, val & ~0x10)  # set bit 4 to zero
        self.pa.writephyreg(0x3, 0xc60a, val | 0x10)  # set bit 4 to one
        self.pa.writephyreg(0x3, 0xc60a, val & ~0x10)  # set bit 4 to zero

        sec_0_15 = self.pa.readphyreg(0x3, 0xc900)
        sec_16_31 = self.pa.readphyreg(0x3, 0xc901)
        sec_32_47 = self.pa.readphyreg(0x3, 0xc902)
        ns_0_15 = self.pa.readphyreg(0x3, 0xc903)
        ns_16_31 = self.pa.readphyreg(0x3, 0xc904)
        # frac_ns_0_15 = self.pa.readphyreg(0x3, 0xc905)
        # frac_ns_16_31 = self.pa.readphyreg(0x3, 0xc906)
        # frac_sec_0_15 = self.pa.readphyreg(0x3, 0xc907)
        # frac_sec_16_31 = self.pa.readphyreg(0x3, 0xc908)

        return (sec_32_47 << 32 | sec_16_31 << 16 | sec_0_15) * 1000000000 + (ns_16_31 << 16 | ns_0_15)

    def send_upd_background_traffic(self, pkt_size, _time):
        # proc = subprocess.Popen(
        #     "netsh interface ip add neighbors \"%s\" %s %s" % ("Ethernet 2",
        #                                                        self.LKP_IP_ADDR,
        #                                                        self.LKP_MAC_ADDR.replace(":", "-")),
        #     stdout=subprocess.PIPE, shell=True)
        proc = subprocess.Popen(
            "netsh interface ip add neighbors \"%s\" %s %s" % ("Ethernet 2",
                                                               "192.168.0.69",
                                                               "00-17-b6-60-99-ff"),
            stdout=subprocess.PIPE, shell=True)
        proc.communicate()

        f = open("send_udp.py", "w")
        f.write("import socket\n")
        f.write("import sys\n")
        f.write("import timeit\n")
        f.write("import time\n")
        f.write("sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n")
        f.write("server_address = ('192.168.0.69', 10000)\n")
        f.write("data = 'f' * (%d - 42)\n" % (pkt_size))
        f.write("start = timeit.default_timer()\n")
        f.write("while timeit.default_timer() - start < %d:\n" % (_time))
        f.write("    sock.sendto(data, server_address)\n")
        # f.write("    time.sleep(0.001)\n")
        f.write("sock.close()\n")
        f.close()

        return subprocess.Popen("python send_udp.py", stdout=subprocess.PIPE, shell=True)


class TestPhyPtpL2EgressFilter(TestPhyPtpBase):
    """
    @description: The PHY PTP L2 egress filter test group is dedicated to verify L2 egress filter functionality, i. e.
    PTP packet filtering by destination mac address, ethernet type and vlan id.

    @setup: Felicity <-> PHY (Europa, Calypso, Rhea) <-> LilNikki
    """

    def setUp(self):
        super(TestPhyPtpL2EgressFilter, self).setUp()
        self.phy_basic_config()
        self.cleanup_ts()

    def phy_basic_config(self):
        pc = PtpConfig(speed=self.LINK_SPEED)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.apply(self.pa)

    def test_egress_l2_filter_dst_mac_ieee1588_0(self):
        """
        @description: This subtest verifies that egress packets with destination MAC 01:1B:19:00:00:00 are filtered
        correctly and packets are timestamped.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:1B:19:00:00:00.
        2. Send PDelayResponse packet from Felicity to LilNikki with destination MAC address 01:1B:19:00:00:00.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersEgressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersEgressEnableConfig.PTP_L2_IEEE_1588_0
        cfg.apply(self.pa)

        self.send_l2_packet(self.DST_MAC_IEEE_1588_0, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_not_zero("dst mac matches filter")

    def test_egress_l2_filter_dst_mac_ieee1588_0_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if egress filter is configured to match 01:1B:19:00:00:00 destination
        MAC address, packets with different MAC address are not timestamped.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:1B:19:00:00:00.
        2. Send PDelayResponse packet from Felicity to LilNikki with destination MAC address 00:17:b6:01:02:03.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersEgressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersEgressEnableConfig.PTP_L2_IEEE_1588_0
        cfg.apply(self.pa)

        invalid_dst_mac = "00:17:b6:01:02:03"
        self.send_l2_packet(invalid_dst_mac, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_zero("dst mac doesn't match filter")

    def test_egress_l2_filter_dst_mac_ieee1588_1(self):
        """
        @description: This subtest verifies that egress packets with destination MAC 01:80:c2:00:00:0e are filtered
        correctly and packets are timestamped.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:80:c2:00:00:0e.
        2. Send PDelayResponse packet from Felicity to LilNikki with destination MAC address 01:80:c2:00:00:0e.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersEgressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersEgressEnableConfig.PTP_L2_IEEE_1588_1
        cfg.apply(self.pa)

        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_not_zero("dst mac matches filter")

    def test_egress_l2_filter_dst_mac_ieee1588_1_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if egress filter is configured to match 01:80:c2:00:00:0e destination
        MAC address, packets with different MAC address are not timestamped.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:80:c2:00:00:0e.
        2. Send PDelayResponse packet from Felicity to LilNikki with destination MAC address 00:17:b6:01:02:03.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersEgressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersEgressEnableConfig.PTP_L2_IEEE_1588_1
        cfg.apply(self.pa)

        invalid_dst_mac = "00:17:b6:01:02:03"
        self.send_l2_packet(invalid_dst_mac, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_zero("dst mac doesn't match filter")

    def test_egress_l2_filter_dst_mac_ieee1588_0_and_ieee1588_1(self):
        """
        @description: This subtest verifies egress packet filtering for both 01:1B:19:00:00:00 and 01:80:c2:00:00:0e
        destination MAC addresses.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:1B:19:00:00:00 and 01:80:c2:00:00:0e.
        2. Send PDelayResponse packet from Felicity to LilNikki with destination MAC address 01:1B:19:00:00:00.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        4. Send PDelayResponse packet from Felicity to LilNikki with destination MAC address 01:80:c2:00:00:0e.
        5. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Both packets were timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersEgressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersEgressEnableConfig.PTP_L2_IEEE_1588_0 | \
            PtpFiltersEgressEnableConfig.PTP_L2_IEEE_1588_1
        cfg.apply(self.pa)

        self.send_l2_packet(self.DST_MAC_IEEE_1588_0, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_not_zero("dst mac matches filter")

        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_not_zero("dst mac matches filter")

    def test_egress_l2_filter_dst_mac_ieee1588_0_and_ieee1588_1_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that when both 01:1B:19:00:00:00 and 01:80:c2:00:00:0e
        destination MAC addresses matching enabled, packets with invalid MAC will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:1B:19:00:00:00 and 01:80:c2:00:00:0e.
        2. Send PDelayResponse packet from Felicity to LilNikki with destination MAC address 00:17:b6:01:02:03.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersEgressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersEgressEnableConfig.PTP_L2_IEEE_1588_0 | \
            PtpFiltersEgressEnableConfig.PTP_L2_IEEE_1588_1
        cfg.apply(self.pa)

        invalid_dst_mac = "00:17:b6:01:02:03"
        self.send_l2_packet(invalid_dst_mac, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_zero("dst mac doesn't match filter")

    def test_egress_l2_filter_dst_mac_custom(self):
        """
        @description: This subtest verifies custom destination MAC filter.

        @steps:
        1. Apply basic PTP configuration with custom destination MAC filter 00:17:b6:01:02:03.
        2. Send PDelayResponse packet from Felicity to LilNikki with destination MAC address 00:17:b6:01:02:03.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        custom_dst_mac = "00:17:b6:01:02:03"

        cfg = PtpFiltersEgressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersEgressEnableConfig.PTP_L2_CUSTOM
        cfg.mac_dest_addr = custom_dst_mac
        cfg.apply(self.pa)

        self.send_l2_packet(custom_dst_mac, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_not_zero("custom dst mac matches filter")

    def test_egress_l2_filter_dst_mac_custom_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if egress filter is configured to match custom destination
        MAC address, packets with different MAC address are not timestamped.

        @steps:
        1. Apply basic PTP configuration with custom destination MAC filter 00:17:b6:01:02:03.
        2. Send PDelayResponse packet from Felicity to LilNikki with destination MAC address 00:17:b6:01:02:04.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        custom_dst_mac = "00:17:b6:01:02:03"
        invalid_dst_mac = "00:17:b6:01:02:04"

        cfg = PtpFiltersEgressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersEgressEnableConfig.PTP_L2_CUSTOM
        cfg.mac_dest_addr = custom_dst_mac
        cfg.apply(self.pa)

        self.send_l2_packet(invalid_dst_mac, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_zero("custom dst mac doesn't match filter")

    def test_egress_l2_filter_no_dst_mac(self):
        """
        @description: This subtest verifies disable of destination MAC filtering.

        @steps:
        1. Apply basic PTP configuration and disable destination MAC filtering.
        2. Send PDelayResponse packet from Felicity to LilNikki with random destination MAC address.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersEgressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersEgressEnableConfig.PTP_L2_IEEE_1588_OFF
        cfg.apply(self.pa)

        self.send_l2_packet("7f:54:22:81:ab:cd", self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_not_zero("no check for dst mac")

    def test_egress_l2_filter_eth_type_ieee1588(self):
        """
        @description: This subtest verifies ETH type 0x88f7 filter.

        @steps:
        1. Apply basic PTP configuration for ETH type 0x88f7.
        2. Send PDelayResponse packet from Felicity to LilNikki with ETH type 0x88f7.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_not_zero("eth type matches filter")

    def test_egress_l2_filter_eth_type_ieee1588_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if ETH type 0x88f7 filter has been configured, PTP packets with
        invalid ETH type will not be timestamped.

        @steps:
        1. Apply basic PTP configuration for ETH type 0x88f7.
        2. Send PDelayResponse packet from Felicity to LilNikki with ETH type 0xffff.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        invalid_eth_type = 0xffff
        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, invalid_eth_type,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_zero("eth type doesn't match filter")

    def test_egress_l2_filter_eth_type_custom(self):
        """
        @description: This subtest verifies custom ETH type filter.

        @steps:
        1. Apply basic PTP configuration for custom ETH type 0xffff.
        2. Send PDelayResponse packet from Felicity to LilNikki with ETH type 0xffff.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        custom_eth_type = 0xffff
        cfg = PtpFiltersEgressEnableConfig()
        cfg.l2_eth_type_filter_cfg = PtpFiltersEgressEnableConfig.PTP_L2_ETH_CUSTOM
        cfg.ethertype = custom_eth_type
        cfg.apply(self.pa)

        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, custom_eth_type,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_not_zero("custom eth type matches filter")

    def test_egress_l2_filter_eth_type_custom_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that when custom ETH type filter is applied, packets with invalid
        ETH type will not be timestamped.

        @steps:
        1. Apply basic PTP configuration for custom ETH type 0xabcd.
        2. Send PDelayResponse packet from Felicity to LilNikki with ETH type 0xabce.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        custom_eth_type = 0xabcd
        invalid_eth_type = custom_eth_type + 1
        cfg = PtpFiltersEgressEnableConfig()
        cfg.l2_eth_type_filter_cfg = PtpFiltersEgressEnableConfig.PTP_L2_ETH_CUSTOM
        cfg.ethertype = custom_eth_type
        cfg.apply(self.pa)

        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, invalid_eth_type,
                            self.PATH_DELAY_RESPONSE_PAYLOAD)

        self.verify_stream_id_and_egress_ts_are_zero("custom eth type doesn't match filter")

    def test_egress_l2_filter_no_vlan_support_but_tagged(self):
        """
        @description: This subtest verifies that when vlan support is disabled tagged packets will not be
        timestamped.

        @steps:
        1. Apply basic PTP configuration with disabled vlan support.
        2. Send tagged PDelayResponse packet from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersEgressEnableConfig()
        cfg.vlan_support = False
        cfg.apply(self.pa)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_0, src="68:05:ca:62:2e:df", type=self.PTP_ETH_TYPE)

        pkt = eth / VlanHeader() / PtpV2SyncHeader()
        self.send_packet(pkt)
        self.verify_stream_id_and_egress_ts_are_zero("vlan is disabled")

    def test_egress_l2_filter_vlan(self):
        """
        @description: This subtest verifies that when vlan support is enabled both tagged and untagged packets
        will be timestamped.

        @steps:
        1. Apply basic PTP configuration with enabled vlan support.
        2. Send untagged PTPv2 sync packet from Felicity to LilNikki.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        4. Send tagged PTPv2 sync packet from Felicity to LilNikki.
        5. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        6. Send tagged PTPv2 sync packet from Felicity to LilNikki but put invalid tpid into vlan header.
        7. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        cfg = PtpFiltersEgressEnableConfig()
        cfg.vlan_support = True
        cfg.apply(self.pa)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_0, src="68:05:ca:62:2e:df", type=self.PTP_ETH_TYPE)

        pkt = eth / PtpV2SyncHeader()
        self.send_packet(pkt)
        self.verify_stream_id_and_egress_ts_are_not_zero("vlan is enabled")

        pkt = eth / VlanHeader() / PtpV2SyncHeader()
        self.send_packet(pkt)
        self.verify_stream_id_and_egress_ts_are_not_zero("vlan is enabled")

        pkt = eth / VlanHeader(tpid=0x1234) / PtpV2SyncHeader()
        self.send_packet(pkt)
        self.verify_stream_id_and_egress_ts_are_zero("vlan is enabled")

    def test_egress_l2_filter_vlan_double_tagged(self):
        """
        @description: This subtest verifies double tagged vlan support.

        @steps:
        1. Apply basic PTP configuration with enabled double tagged vlan support.
        2. Send tagged PTPv2 sync packet from Felicity to LilNikki.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        4. Send tagged PTPv2 sync packet with tpid = 0x88a8 from Felicity to LilNikki.
        5. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        6. Send double tagged PTPv2 sync packet from Felicity to LilNikki.
        7. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        cfg = PtpFiltersEgressEnableConfig()
        cfg.vlan_support = True
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.stacked_vlan_id = 0x88a8
        ptc.apply(self.pa)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_0, src="68:05:ca:62:2e:df", type=self.PTP_ETH_TYPE)

        pkt = eth / VlanHeader(tpid=0x8100) / PtpV2SyncHeader()
        self.send_packet(pkt)
        self.verify_stream_id_and_egress_ts_are_not_zero("vlan is enabled")

        pkt = eth / VlanHeader(tpid=0x88a8) / PtpV2SyncHeader()
        self.send_packet(pkt)
        self.verify_stream_id_and_egress_ts_are_not_zero("vlan is enabled")

        pkt = eth / VlanHeader(tpid=0x88a8) / VlanHeader(tpid=0x8100) / PtpV2SyncHeader()
        self.send_packet(pkt)
        self.verify_stream_id_and_egress_ts_are_not_zero("vlan is enabled")


class TestPhyPtpL2IngressFilter(TestPhyPtpBase):
    """
    @description: The PHY PTP L2 ingress filter test group is dedicated to verify L2 ingress filter functionality, i. e.
    PTP packet filtering by destination mac address, ethernet type and vlan id.

    @setup: Felicity <-> PHY (Europa, Calypso, Rhea) <-> LilNikki
    """

    def setUp(self):
        super(TestPhyPtpL2IngressFilter, self).setUp()
        self.phy_basic_config()
        self.cleanup_ts()

    def phy_basic_config(self):
        pc = PtpConfig(speed=LINK_SPEED_1G)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.apply(self.pa)

    def test_ingress_l2_filter_dst_mac_ieee1588_0(self):
        """
        @description: This subtest verifies that ingress packets with destination MAC 01:1B:19:00:00:00 are filtered
        correctly and packets are timestamped.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:1B:19:00:00:00.
        2. Send PDelayResponse packet from LilNikki to Felicity with destination MAC address 01:1B:19:00:00:00.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersIngressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersIngressEnableConfig.PTP_L2_IEEE_1588_0
        cfg.apply(self.pa)

        self.send_l2_packet(self.DST_MAC_IEEE_1588_0, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_not_zero("dst mac matches filter")

    def test_ingress_l2_filter_dst_mac_ieee1588_0_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if ingress filter is configured to match 01:1B:19:00:00:00 destination
        MAC address, packets with different MAC address are not timestamped.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:1B:19:00:00:00.
        2. Send PDelayResponse packet from LilNikki to Felicity with destination MAC address 00:17:b6:01:02:03.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersIngressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersIngressEnableConfig.PTP_L2_IEEE_1588_0
        cfg.apply(self.pa)

        invalid_dst_mac = "00:17:b6:01:02:03"
        self.send_l2_packet(invalid_dst_mac, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_zero("dst mac doesn't match filter")

    def test_ingress_l2_filter_dst_mac_ieee1588_1(self):
        """
        @description: This subtest verifies that ingress packets with destination MAC 01:80:c2:00:00:0e are filtered
        correctly and packets are timestamped.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:80:c2:00:00:0e.
        2. Send PDelayResponse packet from LilNikki to Felicity with destination MAC address 01:80:c2:00:00:0e.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersIngressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersIngressEnableConfig.PTP_L2_IEEE_1588_1
        cfg.apply(self.pa)

        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_not_zero("dst mac matches filter")

    def test_ingress_l2_filter_dst_mac_ieee1588_1_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if ingress filter is configured to match 01:80:c2:00:00:0e destination
        MAC address, packets with different MAC address are not timestamped.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:80:c2:00:00:0e.
        2. Send PDelayResponse packet from LilNikki to Felicity with destination MAC address 00:17:b6:01:02:03.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersIngressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersIngressEnableConfig.PTP_L2_IEEE_1588_1
        cfg.apply(self.pa)

        invalid_dst_mac = "00:17:b6:01:02:03"
        self.send_l2_packet(invalid_dst_mac, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_zero("dst mac doesn't match filter")

    def test_ingress_l2_filter_dst_mac_ieee1588_0_and_ieee1588_1(self):
        """
        @description: This subtest verifies ingress packet filtering for both 01:1B:19:00:00:00 and 01:80:c2:00:00:0e
        destination MAC addresses.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:1B:19:00:00:00 and 01:80:c2:00:00:0e.
        2. Send PDelayResponse packet from LilNikki to Felicity with destination MAC address 01:1B:19:00:00:00.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        4. Send PDelayResponse packet from LilNikki to Felicity with destination MAC address 01:80:c2:00:00:0e.
        5. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Both packets were timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersIngressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersIngressEnableConfig.PTP_L2_IEEE_1588_0 | \
            PtpFiltersIngressEnableConfig.PTP_L2_IEEE_1588_1
        cfg.apply(self.pa)

        self.send_l2_packet(self.DST_MAC_IEEE_1588_0, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_not_zero("dst mac matches filter")

        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_not_zero("dst mac matches filter")

    def test_ingress_l2_filter_dst_mac_ieee1588_0_and_ieee1588_1_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that when both 01:1B:19:00:00:00 and 01:80:c2:00:00:0e
        destination MAC addresses matching enabled, packets with invalid MAC will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with destination PTP mac address matching 01:1B:19:00:00:00 and 01:80:c2:00:00:0e.
        2. Send PDelayResponse packet from LilNikki to Felicity with destination MAC address 00:17:b6:01:02:03.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersIngressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersIngressEnableConfig.PTP_L2_IEEE_1588_0 | \
            PtpFiltersIngressEnableConfig.PTP_L2_IEEE_1588_1
        cfg.apply(self.pa)

        invalid_dst_mac = "00:17:b6:01:02:03"
        self.send_l2_packet(invalid_dst_mac, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_zero("dst mac doesn't match filter")

    def test_ingress_l2_filter_dst_mac_custom(self):
        """
        @description: This subtest verifies custom destination MAC filter.

        @steps:
        1. Apply basic PTP configuration with custom destination MAC filter 00:17:b6:01:02:03.
        2. Send PDelayResponse packet from LilNikki to Felicity with destination MAC address 00:17:b6:01:02:03.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        custom_dst_mac = "00:17:b6:01:02:03"

        cfg = PtpFiltersIngressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersIngressEnableConfig.PTP_L2_CUSTOM
        cfg.mac_dest_addr = custom_dst_mac
        cfg.apply(self.pa)

        self.send_l2_packet(custom_dst_mac, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_not_zero("custom dst mac matches filter")

    def test_ingress_l2_filter_dst_mac_custom_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if ingress filter is configured to match custom destination
        MAC address, packets with different MAC address are not timestamped.

        @steps:
        1. Apply basic PTP configuration with custom destination MAC filter 00:17:b6:01:02:03.
        2. Send PDelayResponse packet from LilNikki to Felicity with destination MAC address 00:17:b6:01:02:04.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        custom_dst_mac = "00:17:b6:01:02:03"
        invalid_dst_mac = "00:17:b6:01:02:04"

        cfg = PtpFiltersIngressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersIngressEnableConfig.PTP_L2_CUSTOM
        cfg.mac_dest_addr = custom_dst_mac
        cfg.apply(self.pa)

        self.send_l2_packet(invalid_dst_mac, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_zero("custom dst mac doesn't match filter")

    def test_ingress_l2_filter_no_dst_mac(self):
        """
        @description: This subtest verifies disable of destination MAC filtering.

        @steps:
        1. Apply basic PTP configuration and disable destination MAC filtering.
        2. Send PDelayResponse packet from LilNikki to Felicity with random destination MAC address.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersIngressEnableConfig()
        cfg.l2_filter_cfg = PtpFiltersIngressEnableConfig.PTP_L2_IEEE_1588_OFF
        cfg.apply(self.pa)

        self.send_l2_packet("7f:54:22:81:ab:cd", self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_not_zero("no check for dst mac")

    def test_ingress_l2_filter_eth_type_ieee1588(self):
        """
        @description: This subtest verifies ETH type 0x88f7 filter.

        @steps:
        1. Apply basic PTP configuration for ETH type 0x88f7.
        2. Send PDelayResponse packet from LilNikki to Felicity with ETH type 0x88f7.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_not_zero("eth type matches filter")

    def test_ingress_l2_filter_eth_type_ieee1588_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if ETH type 0x88f7 filter has been configured, PTP packets with
        invalid ETH type will not be timestamped.

        @steps:
        1. Apply basic PTP configuration for ETH type 0x88f7.
        2. Send PDelayResponse packet from LilNikki to Felicity with ETH type 0xffff.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        invalid_eth_type = 0xffff
        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, invalid_eth_type,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_zero("eth type doesn't match filter")

    def test_ingress_l2_filter_eth_type_custom(self):
        """
        @description: This subtest verifies custom ETH type filter.

        @steps:
        1. Apply basic PTP configuration for custom ETH type 0xffff.
        2. Send PDelayResponse packet from LilNikki to Felicity with ETH type 0xffff.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: The packet has been timestamped.
        @duration: 1 second.
        """

        custom_eth_type = 0xffff
        cfg = PtpFiltersIngressEnableConfig()
        cfg.l2_eth_type_filter_cfg = PtpFiltersIngressEnableConfig.PTP_L2_ETH_CUSTOM
        cfg.ethertype = custom_eth_type
        cfg.apply(self.pa)

        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, custom_eth_type,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_not_zero("custom eth type matches filter")

    def test_ingress_l2_filter_eth_type_custom_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that when custom ETH type filter is applied, packets with invalid
        ETH type will not be timestamped.

        @steps:
        1. Apply basic PTP configuration for custom ETH type 0xabcd.
        2. Send PDelayResponse packet from LilNikki to Felicity with ETH type 0xabce.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        custom_eth_type = 0xabcd
        invalid_eth_type = custom_eth_type + 1
        cfg = PtpFiltersIngressEnableConfig()
        cfg.l2_eth_type_filter_cfg = PtpFiltersIngressEnableConfig.PTP_L2_ETH_CUSTOM
        cfg.ethertype = custom_eth_type
        cfg.apply(self.pa)

        self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, invalid_eth_type,
                            self.PATH_DELAY_RESPONSE_PAYLOAD, host=self.LKP_HOSTNAME)

        self.verify_stream_id_and_ingress_ts_are_zero("custom eth type doesn't match filter")

    def test_ingress_l2_filter_no_vlan_support_but_tagged(self):
        """
        @description: This subtest verifies that when vlan support is disabled tagged packets will not be
        timestamped.

        @steps:
        1. Apply basic PTP configuration with disabled vlan support.
        2. Send tagged PDelayResponse packet from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: The packet was not timestamped.
        @duration: 1 second.
        """

        cfg = PtpFiltersIngressEnableConfig()
        cfg.vlan_support = False
        cfg.apply(self.pa)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_0, src="68:05:ca:62:2e:df", type=self.PTP_ETH_TYPE)

        pkt = eth / VlanHeader() / PtpV2SyncHeader()
        self.send_packet(pkt, self.LKP_HOSTNAME)
        self.verify_stream_id_and_egress_ts_are_zero("vlan is disabled")

    def test_ingress_l2_filter_vlan(self):
        """
        @description: This subtest verifies that when vlan support is enabled both tagged and untagged packets
        will be timestamped.

        @steps:
        1. Apply basic PTP configuration with enabled vlan support.
        2. Send untagged PTPv2 sync packet from LilNikki to Felicity.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        4. Send tagged PTPv2 sync packet from LilNikki to Felicity.
        5. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        6. Send tagged PTPv2 sync packet from LilNikki to Felicity but put invalid tpid into vlan header.
        7. Make sure that packet was not timestamped by checking timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        cfg = PtpFiltersIngressEnableConfig()
        cfg.vlan_support = True
        cfg.apply(self.pa)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_0, src="68:05:ca:62:2e:df", type=self.PTP_ETH_TYPE)

        pkt = eth / PtpV2SyncHeader()
        self.send_packet(pkt, host=self.LKP_HOSTNAME)
        self.verify_stream_id_and_ingress_ts_are_not_zero("vlan is enabled")

        pkt = eth / VlanHeader() / PtpV2SyncHeader()
        self.send_packet(pkt, host=self.LKP_HOSTNAME)
        self.verify_stream_id_and_ingress_ts_are_not_zero("vlan is enabled")

        pkt = eth / VlanHeader(tpid=0x1234) / PtpV2SyncHeader()
        self.send_packet(pkt, host=self.LKP_HOSTNAME)
        self.verify_stream_id_and_ingress_ts_are_zero("vlan is enabled")

    def test_ingress_l2_filter_vlan_double_tagged(self):
        """
        @description: This subtest verifies double tagged vlan support.

        @steps:
        1. Apply basic PTP configuration with enabled double tagged vlan support.
        2. Send tagged PTPv2 sync packet from LilNikki to Felicity.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        4. Send tagged PTPv2 sync packet with tpid = 0x88a8 from LilNikki to Felicity.
        5. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        6. Send double tagged PTPv2 sync packet from LilNikki to Felicity.
        7. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        cfg = PtpFiltersIngressEnableConfig()
        cfg.vlan_support = True
        cfg.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.stacked_vlan_id = 0x88a8
        ptc.apply(self.pa)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_0, src="68:05:ca:62:2e:df", type=self.PTP_ETH_TYPE)

        pkt = eth / VlanHeader(tpid=0x8100) / PtpV2SyncHeader()
        self.send_packet(pkt, host=self.LKP_HOSTNAME)
        self.verify_stream_id_and_ingress_ts_are_not_zero("vlan is enabled")

        pkt = eth / VlanHeader(tpid=0x88a8) / PtpV2SyncHeader()
        self.send_packet(pkt, host=self.LKP_HOSTNAME)
        self.verify_stream_id_and_ingress_ts_are_not_zero("vlan is enabled")

        pkt = eth / VlanHeader(tpid=0x88a8) / VlanHeader(tpid=0x8100) / PtpV2SyncHeader()
        self.send_packet(pkt, host=self.LKP_HOSTNAME)
        self.verify_stream_id_and_ingress_ts_are_not_zero("vlan is enabled")


class TestPhyPtpIPv4FilterBase(TestPhyPtpBase):
    ETH_HEADER = EthernetHeader(dst="01:00:5e:00:00:6b", src="68:05:ca:62:2e:df", type=ETH_TYPE_IPv4)
    UDP_HEADER = UdpHeader(src=319, dst=319, length=62)

    def setUp(self):
        super(TestPhyPtpIPv4FilterBase, self).setUp()

    def phy_basic_config(self, speed, is_ipv4_udp, ipv4_filter_cfg, ipv4_custom_addr="0.0.0.0"):
        raise NotImplementedError()

    def verify_stream_id_and_ts_are_not_zero(self, msg):
        raise NotImplementedError()

    def verify_stream_id_and_ts_are_zero(self, msg):
        raise NotImplementedError()

    def send_pkt(self, packet):
        raise NotImplementedError()

    def run_test_ipv4_dest_addr_off(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_OFF)
        self.cleanup_ts()

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.0.107")
        packet = self.ETH_HEADER / ipv4 / self.UDP_HEADER / PtpV2PathDelayRequestHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_not_zero("dest ip address matching is off")

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="111.222.88.33")
        packet = self.ETH_HEADER / ipv4 / self.UDP_HEADER / PtpV2PathDelayResponseHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_not_zero("dest ip address matching is off")

    def run_test_ipv4_dest_addr_custom(self):
        custom_ipv4 = "192.168.0.51"
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_CUSTOM,
                              custom_ipv4)
        self.cleanup_ts()

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst=custom_ipv4)
        packet = self.ETH_HEADER / ipv4 / self.UDP_HEADER / PtpV2PathDelayRequestHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_not_zero("dest ip address matches filter")

        # Now make sure that another dest IP address doesn't match filter
        invalid_custom_ipv4 = "192.168.0.52"
        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst=invalid_custom_ipv4)
        packet = self.ETH_HEADER / ipv4 / self.UDP_HEADER / PtpV2PathDelayResponseHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("dest ip address doesn't math filter")

        # Now make sure that standard dest IP address doesn't match filter
        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.1.129")
        packet = self.ETH_HEADER / ipv4 / self.UDP_HEADER / PtpV2PathDelayResponseHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("dest ip address doesn't math filter")

    def verify_all_headers(self, ipv4_header, should_be_timestamped):
        for header in [PtpV2SyncHeader, PtpV2DelayRequestHeader, PtpV2FollowUpHeader,
                       PtpV2PathDelayRequestHeader, PtpV2PathDelayResponseHeader,
                       PtpV2PathDelayResponseFollowUpHeader]:
            packet = self.ETH_HEADER / ipv4_header / self.UDP_HEADER / header()
            packet.calculate_checksums()
            self.send_pkt(packet)
            if should_be_timestamped:
                self.verify_stream_id_and_ts_are_not_zero("dest ip address matches filter")
            else:
                self.verify_stream_id_and_ts_are_zero("dest ip address doesn't match filter")

    def run_test_ipv4_dest_addr_129(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_129)
        self.cleanup_ts()

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.1.129")

        self.verify_all_headers(ipv4, should_be_timestamped=True)

    def run_test_ipv4_dest_addr_129_but_invalid_in_packet(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_129)
        self.cleanup_ts()

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="223.0.1.129")

        self.verify_all_headers(ipv4, should_be_timestamped=False)

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.1.130")

        self.verify_all_headers(ipv4, should_be_timestamped=False)

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.0.107")

        self.verify_all_headers(ipv4, should_be_timestamped=False)

    def run_test_ipv4_dest_addr_130_132(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_130_132)
        self.cleanup_ts()

        for ip_lsw in [130, 131, 132]:
            ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                              protocol=PROTOCOL_UDP, src="192.168.0.138",
                              dst="224.0.1.%d" % (ip_lsw))

            self.verify_all_headers(ipv4, should_be_timestamped=True)

    def run_test_ipv4_dest_addr_130_132_but_invalid_in_packet(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_130_132)
        self.cleanup_ts()

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.1.133")

        self.verify_all_headers(ipv4, should_be_timestamped=False)

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="112.112.0.3")

        self.verify_all_headers(ipv4, should_be_timestamped=False)

    def run_test_ipv4_dest_addr_107(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_107)
        self.cleanup_ts()

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.0.107")

        self.verify_all_headers(ipv4, should_be_timestamped=True)

    def run_test_ipv4_dest_addr_107_but_invalid_in_packet(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_107)
        self.cleanup_ts()

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.0.108")

        self.verify_all_headers(ipv4, should_be_timestamped=False)

    def run_test_ipv4_not_ip_proto(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_129)
        self.cleanup_ts()

        eth = EthernetHeader(dst="01:00:5e:00:00:6b", src="68:05:ca:62:2e:df", type=ETH_TYPE_IPv4 + 1)
        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.1.129")

        packet = eth / ipv4 / self.UDP_HEADER / PtpV2SyncHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("not ip proto")

    def run_test_ipv4_not_udp_proto(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_129)
        self.cleanup_ts()

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP + 1, src="192.168.0.138", dst="224.0.1.129")

        packet = self.ETH_HEADER / ipv4 / self.UDP_HEADER / PtpV2SyncHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("not udp proto")

    def run_test_ipv4_no_udp_header(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_129)
        self.cleanup_ts()

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP + 1, src="192.168.0.138", dst="224.0.1.129")

        packet = self.ETH_HEADER / ipv4 / PtpV2SyncHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("there is no udp header")

    def run_test_ipv4_no_ptp_header(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_129)
        self.cleanup_ts()

        eth = EthernetHeader(dst="01:00:5e:00:00:6b", src="68:05:ca:62:2e:df", type=ETH_TYPE_IPv4)
        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.1.129")

        packet = eth / ipv4 / self.UDP_HEADER
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("there is no ptp header")

    def run_test_ipv4_too_big_ihl(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_129)
        self.cleanup_ts()

        ipv4 = IPv4Header(version=4, ihl=40, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.1.129")

        packet = self.ETH_HEADER / ipv4 / self.UDP_HEADER / PtpV2SyncHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("ihl is checked")

    def run_test_ipv4_invalid_checksum(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_129)
        self.cleanup_ts()

        ipv4 = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                          protocol=PROTOCOL_UDP, checksum=0xfafa, src="192.168.0.138", dst="224.0.1.129")

        packet = self.ETH_HEADER / ipv4 / self.UDP_HEADER / PtpV2SyncHeader()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_not_zero("checksum is not checked")


class TestPhyPtpIPv4EgressFilter(TestPhyPtpIPv4FilterBase):
    """
    @description: The PHY PTP IPv4 egress filter test group is dedicated to verify IPv4 egress filter functionality,
    i. e. PTP packet filtering by destination IPv4 address.

    @setup: Felicity <-> PHY (Europa, Calypso, Rhea) <-> LilNikki
    """

    def phy_basic_config(self, speed, is_ipv4_udp, ipv4_filter_cfg, ipv4_custom_addr="0.0.0.0"):
        pc = PtpConfig(speed=self.LINK_SPEED)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.ipv4_udp = is_ipv4_udp
        cfg.ipv4_filter_cfg = ipv4_filter_cfg
        cfg.ipv4_dest_addr = ipv4_custom_addr
        cfg.udp_port_cfg = PtpFiltersEgressEnableConfig.PTP_1588_PORT_319_NTP_SNTP_PORT_123
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.apply(self.pa)

        time.sleep(1)

    def verify_stream_id_and_ts_are_not_zero(self, msg):
        self.verify_stream_id_and_egress_ts_are_not_zero(msg)

    def verify_stream_id_and_ts_are_zero(self, msg):
        self.verify_stream_id_and_egress_ts_are_zero(msg)

    def send_pkt(self, packet):
        self.send_packet(packet)

    def test_egress_ipv4_dest_addr_off(self):
        """
        @description: This subtest verifies disable of egress destination IPv4 address filter.

        @steps:
        1. Apply basic PTP configuration with disabled egress destination IPv4 address matching.
        2. Send PDelayRequest packet over UDP protocol with random destination IPv4 address from Felicity to LilNikki.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        self.run_test_ipv4_dest_addr_off()

    def test_egress_ipv4_dest_addr_custom(self):
        """
        @description: This subtest verifies custom egress destination IPv4 address filter.

        @steps:
        1. Apply basic PTP configuration with custom egress destination IPv4 address matching.
        2. Send PDelayRequest packet over UDP protocol with correct destination IPv4 address from Felicity to LilNikki.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        4. Send PDelayRequest packet over UDP protocol with wrong destination IPv4 address from Felicity to LilNikki.
        5. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_dest_addr_custom()

    def test_egress_ipv4_dest_addr_129(self):
        """
        @description: This subtest verifies 224.0.1.129 egress destination IPv4 address filter.

        @steps:
        1. Apply basic PTP configuration with 224.0.1.129 egress destination IPv4 address matching.
        2. For each PTP packet type construct the packet over UDP with destination IPv4 address 224.0.1.129 and send it
        from Felicity to LilNikki.
        3. For each packet make sure that it was timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_129()

    def test_egress_ipv4_dest_addr_129_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if 224.0.1.129 egress destination IPv4 address matching is enabled,
        packets with invalid address will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with 224.0.1.129 egress destination IPv4 address matching.
        2. For each PTP packet type construct the packet over UDP with random destination IPv4 address and send it
        from Felicity to LilNikki.
        3. For each packet make sure that it was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_129_but_invalid_in_packet()

    def test_egress_ipv4_dest_addr_130_132(self):
        """
        @description: This subtest verifies 224.0.1.130, 224.0.1.131 and 224.0.1.132 destination IPv4
        address matching.

        @steps:
        1. Apply basic PTP configuration with 224.0.1.130, 224.0.1.131 and 224.0.1.132 egress destination
        IPv4 address matching.
        2. For each PTP packet type and for each address construct the packet over UDP and send it
        from Felicity to LilNikki.
        3. For each packet make sure that it was timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_130_132()

    def test_egress_ipv4_dest_addr_130_132_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if 224.0.1.130, 224.0.1.131 and 224.0.1.132 destination IPv4
        address matching enabled, packets with invalid address will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with 224.0.1.130, 224.0.1.131 and 224.0.1.132 egress destination IPv4
        address matching.
        2. For each PTP packet type construct the packet over UDP with random destination IPv4 address and send it
        from Felicity to LilNikki.
        3. For each packet make sure that it was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_130_132_but_invalid_in_packet()

    def test_egress_ipv4_dest_addr_107(self):
        """
        @description: This subtest verifies 224.0.0.107 egress destination IPv4 address filter.

        @steps:
        1. Apply basic PTP configuration with 224.0.0.107 egress destination IPv4 address matching.
        2. For each PTP packet type construct the packet over UDP with destination IPv4 address 224.0.0.107 and send it
        from Felicity to LilNikki.
        3. For each packet make sure that it was timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_107()

    def test_egress_ipv4_dest_addr_107_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if 224.0.0.107 egress destination IPv4 address matching is enabled,
        packets with invalid address will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with 224.0.0.107 egress destination IPv4 address matching.
        2. For each PTP packet type construct the packet over UDP with random destination IPv4 address and send it
        from Felicity to LilNikki.
        3. For each packet make sure that it was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_107_but_invalid_in_packet()

    def test_egress_ipv4_not_ip_proto(self):
        """
        @description: This is negative test that verifies if proto field of Ethernet header is not IPv4 the packet
        shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4 but set not IPv4 proto field in Ethernet header and send it
        from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_not_ip_proto()

    def test_egress_ipv4_not_udp_proto(self):
        """
        @description: This is negative test that verifies if proto field of IPv4 header is not UDP the packet
        shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4 but set not UDP proto field in IPv4 header and send it
        from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_not_udp_proto()

    def test_egress_ipv4_no_udp_header(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with IPv4 header but without UDP
        header shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4, remove UDP header from it and send it from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_no_udp_header()

    def test_egress_ipv4_no_ptp_header(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with missing PTP
        header shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4, remove PTP header from it and send it from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_no_ptp_header()

    def test_egress_ipv4_too_big_ihl(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with too big IHL field value in IPv4
        header shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4, set very big value to IHL field of IPv4 header and send it
        from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_too_big_ihl()

    def test_egress_ipv4_invalid_checksum(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with incorrect IPv4 checksum
        shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4, set invalid IPv4 checksum and send it from Felicity to LilNikki.
        3. Make sure that packet was timestamped by checking egress timestamp FIFO because checksum field
        shall not be parsed.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_invalid_checksum()


class TestPhyPtpIPv4IngressFilter(TestPhyPtpIPv4FilterBase):
    """
    @description: The PHY PTP IPv4 ingress filter test group is dedicated to verify IPv4 ingress filter functionality,
    i. e. PTP packet filtering by destination IPv4 address.

    @setup: Felicity <-> PHY (Europa, Calypso, Rhea) <-> LilNikki
    """

    def phy_basic_config(self, speed, is_ipv4_udp, ipv4_filter_cfg, ipv4_custom_addr="0.0.0.0"):
        pc = PtpConfig(speed=self.LINK_SPEED)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.ipv4_udp = is_ipv4_udp
        cfg.ipv4_filter_cfg = ipv4_filter_cfg
        cfg.ipv4_dest_addr = ipv4_custom_addr
        cfg.udp_port_cfg = PtpFiltersEgressEnableConfig.PTP_1588_PORT_319_NTP_SNTP_PORT_123
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.apply(self.pa)

        time.sleep(1)

    def verify_stream_id_and_ts_are_not_zero(self, msg):
        self.verify_stream_id_and_ingress_ts_are_not_zero(msg)

    def verify_stream_id_and_ts_are_zero(self, msg):
        self.verify_stream_id_and_ingress_ts_are_zero(msg)

    def send_pkt(self, packet):
        self.send_packet(packet, self.LKP_HOSTNAME)

    def test_ingress_ipv4_dest_addr_off(self):
        """
        @description: This subtest verifies disable of ingress destination IPv4 address filter.

        @steps:
        1. Apply basic PTP configuration with disabled ingress destination IPv4 address matching.
        2. Send PDelayRequest packet over UDP protocol with random destination IPv4 address from LilNikki to Felicity.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        self.run_test_ipv4_dest_addr_off()

    def test_ingress_ipv4_dest_addr_129(self):
        """
        @description: This subtest verifies 224.0.1.129 ingress destination IPv4 address filter.

        @steps:
        1. Apply basic PTP configuration with 224.0.1.129 ingress destination IPv4 address matching.
        2. For each PTP packet type construct the packet over UDP with destination IPv4 address 224.0.1.129 and send it
        from LilNikki to Felicity.
        3. For each packet make sure that it was timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_129()

    def test_ingress_ipv4_dest_addr_129_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if 224.0.1.129 ingress destination IPv4 address matching is enabled,
        packets with invalid address will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with 224.0.1.129 ingress destination IPv4 address matching.
        2. For each PTP packet type construct the packet over UDP with random destination IPv4 address and send it
        from LilNikki to Felicity.
        3. For each packet make sure that it was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_129_but_invalid_in_packet()

    def test_ingress_ipv4_dest_addr_130_132(self):
        """
        @description: This subtest verifies 224.0.1.130, 224.0.1.131 and 224.0.1.132 destination IPv4
        address matching.

        @steps:
        1. Apply basic PTP configuration with 224.0.1.130, 224.0.1.131 and 224.0.1.132 ingress destination
        IPv4 address matching.
        2. For each PTP packet type and for each address construct the packet over UDP and send it
        from LilNikki to Felicity.
        3. For each packet make sure that it was timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_130_132()

    def test_ingress_ipv4_dest_addr_130_132_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if 224.0.1.130, 224.0.1.131 and 224.0.1.132 destination IPv4
        address matching enabled, packets with invalid address will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with 224.0.1.130, 224.0.1.131 and 224.0.1.132 ingress destination IPv4
        address matching.
        2. For each PTP packet type construct the packet over UDP with random destination IPv4 address and send it
        from LilNikki to Felicity.
        3. For each packet make sure that it was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_130_132_but_invalid_in_packet()

    def test_ingress_ipv4_dest_addr_107(self):
        """
        @description: This subtest verifies 224.0.0.107 ingress destination IPv4 address filter.

        @steps:
        1. Apply basic PTP configuration with 224.0.0.107 ingress destination IPv4 address matching.
        2. For each PTP packet type construct the packet over UDP with destination IPv4 address 224.0.0.107 and send it
        from LilNikki to Felicity.
        3. For each packet make sure that it was timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_107()

    def test_ingress_ipv4_dest_addr_107_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if 224.0.0.107 ingress destination IPv4 address matching is enabled,
        packets with invalid address will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with 224.0.0.107 ingress destination IPv4 address matching.
        2. For each PTP packet type construct the packet over UDP with random destination IPv4 address and send it
        from LilNikki to Felicity.
        3. For each packet make sure that it was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv4_dest_addr_107_but_invalid_in_packet()

    def test_ingress_ipv4_not_ip_proto(self):
        """
        @description: This is negative test that verifies if proto field of Ethernet header is not IPv4 the packet
        shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4 but set not IPv4 proto field in Ethernet header and send it
        from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_not_ip_proto()

    def test_ingress_ipv4_not_udp_proto(self):
        """
        @description: This is negative test that verifies if proto field of IPv4 header is not UDP the packet
        shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4 but set not UDP proto field in IPv4 header and send it
        from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_not_udp_proto()

    def test_ingress_ipv4_no_udp_header(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with IPv4 header but without UDP
        header shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4, remove UDP header from it and send it from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_no_udp_header()

    def test_ingress_ipv4_no_ptp_header(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with missing PTP
        header shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4, remove PTP header from it and send it from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_no_ptp_header()

    def test_ingress_ipv4_too_big_ihl(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with too big IHL field value in IPv4
        header shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4, set very big value to IHL field of IPv4 header and send it
        from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_too_big_ihl()

    def test_ingress_ipv4_invalid_checksum(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with incorrect IPv4 checksum
        shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv4, set invalid IPv4 checksum and send it from LilNikki to Felicity.
        3. Make sure that packet was timestamped by checking ingress timestamp FIFO because checksum field
        shall not be parsed.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv4_invalid_checksum()


class TestPhyPtpIPv6FilterBase(TestPhyPtpBase):
    ETH_HEADER = EthernetHeader(dst="01:00:5e:00:00:6b", src="68:05:ca:62:2e:df", type=ETH_TYPE_IPv6)
    UDP_HEADER = UdpHeader(src=319, dst=319, length=62)
    STANDARD_DEST_IPv6_FF01_181 = "ff01:0000:0000:0000:0000:0000:0000:0181"
    STANDARD_DEST_IPv6_FF02_6B = "ff02:0000:0000:0000:0000:0000:0000:006b"

    def setUp(self):
        super(TestPhyPtpIPv6FilterBase, self).setUp()

    def phy_basic_config(self, speed, is_ipv6_udp, ipv6_filter_cfg,
                         ipv6_custom_addr="0000:0000:0000:0000:0000:0000:0000:0000"):
        raise NotImplementedError()

    def verify_stream_id_and_ts_are_not_zero(self, msg):
        raise NotImplementedError()

    def verify_stream_id_and_ts_are_zero(self, msg):
        raise NotImplementedError()

    def send_pkt(self, packet):
        raise NotImplementedError()

    def run_test_ipv6_dest_addr_off(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV6_IEEE_1588_OFF)
        self.cleanup_ts()

        ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                          hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf",
                          dst="ff02:0000:0000:0000:0000:0000:0000:006b")
        packet = self.ETH_HEADER / ipv6 / self.UDP_HEADER / PtpV2PathDelayRequestHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_not_zero("dest ipv6 address matching is off")

        ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                          hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf",
                          dst="ff02:eeee:ffff:dddd:1111:2222:3333:4444")
        packet = self.ETH_HEADER / ipv6 / self.UDP_HEADER / PtpV2PathDelayRequestHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_not_zero("dest ipv6 address matching is off")

    def run_test_ipv6_dest_addr_custom(self):
        custom_ipv6 = "fe80:0000:0000:0000:6a05:caff:fe62:dddd"
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV6_IEEE_1588_CUSTOM,
                              custom_ipv6)
        self.cleanup_ts()

        ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                          hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf",
                          dst=custom_ipv6)
        packet = self.ETH_HEADER / ipv6 / self.UDP_HEADER / PtpV2SyncHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_not_zero("dest ipv6 address matches filter")

        # Now make sure that another dest IP address doesn't match filter
        invalid_custom_ipv6 = "fe80:0000:0000:0000:6a05:caff:fe62:dddf"
        ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                          hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf",
                          dst=invalid_custom_ipv6)
        packet = self.ETH_HEADER / ipv6 / self.UDP_HEADER / PtpV2PathDelayRequestHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("dest ipv6 address doesn't math filter")

        # Now make sure that standard dest IP address doesn't match filter
        ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                          hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf",
                          dst=self.STANDARD_DEST_IPv6_FF01_181)
        packet = self.ETH_HEADER / ipv6 / self.UDP_HEADER / PtpV2PathDelayResponseHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("dest ipv6 address doesn't math filter")

    def verify_all_headers(self, ipv6_header, should_be_timestamped):
        for header in [PtpV2SyncHeader, PtpV2DelayRequestHeader, PtpV2FollowUpHeader,
                       PtpV2PathDelayRequestHeader, PtpV2PathDelayResponseHeader,
                       PtpV2PathDelayResponseFollowUpHeader]:
            packet = self.ETH_HEADER / ipv6_header / self.UDP_HEADER / header()
            packet.calculate_checksums()
            self.send_pkt(packet)
            if should_be_timestamped:
                self.verify_stream_id_and_ts_are_not_zero("dest ip address matches filter")
            else:
                self.verify_stream_id_and_ts_are_zero("dest ip address doesn't match filter")

    def run_test_ipv6_dest_addr_ff0x_181(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV6_IEEE_1588_FF0X_181)
        self.cleanup_ts()

        for lsw_addr in range(0x10):
            dst = "%04x" % (0xff00 + lsw_addr) + self.STANDARD_DEST_IPv6_FF01_181[4:]
            ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                              hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf", dst=dst)

            self.verify_all_headers(ipv6, should_be_timestamped=True)

    def run_test_ipv6_dest_addr_ff0x_181_but_invalid_in_packet(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV6_IEEE_1588_FF0X_181)
        self.cleanup_ts()

        for dst_ipv6 in ["ff10:0000:0000:0000:0000:0000:0000:0181", "ff00:0000:0000:0000:0000:0000:0000:0182",
                         "ff00:0000:0000:0000:0000:0000:0000:0180", "1f00:0000:0000:0000:0000:0000:0000:0181"]:
            ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                              hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf", dst=dst_ipv6)

            self.verify_all_headers(ipv6, should_be_timestamped=False)

    def run_test_ipv6_dest_addr_ff02_6b(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV6_IEEE_1588_FF02_6B)
        self.cleanup_ts()

        ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                          hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf",
                          dst=self.STANDARD_DEST_IPv6_FF02_6B)

        self.verify_all_headers(ipv6, should_be_timestamped=True)

    def run_test_ipv6_dest_addr_ff02_6b_but_invalid_in_packet(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV6_IEEE_1588_FF02_6B)
        self.cleanup_ts()

        for dst_ipv6 in ["ff02:0000:0000:0000:0000:0000:0000:006c", "ff02:0000:0000:0000:0000:0000:0000:006a",
                         "ff01:0000:0000:0000:0000:0000:0000:006a", "ff03:0000:0000:0000:0000:0000:0000:006a"]:
            ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                              hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf", dst=dst_ipv6)

            self.verify_all_headers(ipv6, should_be_timestamped=False)

    def run_test_ipv6_not_ip_proto(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV6_IEEE_1588_FF02_6B)
        self.cleanup_ts()

        eth = EthernetHeader(dst="01:00:5e:00:00:6b", src="68:05:ca:62:2e:df", type=ETH_TYPE_IPv6 + 1)
        ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                          hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf",
                          dst=self.STANDARD_DEST_IPv6_FF02_6B)

        packet = eth / ipv6 / self.UDP_HEADER / PtpV2SyncHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("not ip proto")

    def run_test_ipv6_not_udp_proto(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV6_IEEE_1588_FF02_6B)
        self.cleanup_ts()

        ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP + 1,
                          hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf",
                          dst=self.STANDARD_DEST_IPv6_FF02_6B)

        packet = self.ETH_HEADER / ipv6 / self.UDP_HEADER / PtpV2SyncHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("not udp proto")

    def run_test_ipv6_no_udp_header(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV6_IEEE_1588_FF02_6B)
        self.cleanup_ts()

        ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                          hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf",
                          dst=self.STANDARD_DEST_IPv6_FF02_6B)

        packet = self.ETH_HEADER / ipv6 / PtpV2SyncHeader()
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("there is no udp header")

    def run_test_ipv6_no_ptp_header(self):
        self.phy_basic_config(self.LINK_SPEED, True, PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_129)
        self.cleanup_ts()

        eth = EthernetHeader(dst="01:00:5e:00:00:6b", src="68:05:ca:62:2e:df", type=ETH_TYPE_IPv6)
        ipv6 = IPv6Header(version=6, traffic_class=0, flow_label=0, payload_length=64, next_header=PROTOCOL_UDP,
                          hop_limit=1, src="fe80:0000:0000:0000:6a05:caff:fe62:2edf",
                          dst=self.STANDARD_DEST_IPv6_FF02_6B)

        packet = eth / ipv6 / self.UDP_HEADER
        packet.calculate_checksums()
        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_zero("there is no ptp header")


class TestPhyPtpIPv6EgressFilter(TestPhyPtpIPv6FilterBase):
    """
    @description: The PHY PTP IPv6 egress filter test group is dedicated to verify IPv6 egress filter functionality,
    i. e. PTP packet filtering by destination IPv6 address.

    @setup: Felicity <-> PHY (Europa, Calypso, Rhea) <-> LilNikki
    """

    def phy_basic_config(self, speed, is_ipv6_udp, ipv6_filter_cfg,
                         ipv6_custom_addr="0000:0000:0000:0000:0000:0000:0000:0000"):
        pc = PtpConfig(speed=speed)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.ipv6_udp = is_ipv6_udp
        cfg.ipv6_filter_cfg = ipv6_filter_cfg
        cfg.ipv6_dest_addr = ipv6_custom_addr
        cfg.udp_port_cfg = PtpFiltersEgressEnableConfig.PTP_1588_PORT_319_NTP_SNTP_PORT_123
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.apply(self.pa)

        time.sleep(1)

    def verify_stream_id_and_ts_are_not_zero(self, msg):
        self.verify_stream_id_and_egress_ts_are_not_zero(msg)

    def verify_stream_id_and_ts_are_zero(self, msg):
        self.verify_stream_id_and_egress_ts_are_zero(msg)

    def send_pkt(self, packet):
        self.send_packet(packet)

    def test_egress_ipv6_dest_addr_off(self):
        """
        @description: This subtest verifies disable of egress destination IPv6 address filter.

        @steps:
        1. Apply basic PTP configuration with disabled egress destination IPv6 address matching.
        2. Send PDelayRequest packet over UDP protocol with random destination IPv6 address from Felicity to LilNikki.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        self.run_test_ipv6_dest_addr_off()

    def test_egress_ipv6_dest_addr_custom(self):
        """
        @description: This subtest verifies custom egress destination IPv6 address filter.

        @steps:
        1. Apply basic PTP configuration with custom egress destination IPv6 address matching.
        2. Send PDelayRequest packet over UDP protocol with correct destination IPv6 address from Felicity to LilNikki.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        4. Send PDelayRequest packet over UDP protocol with wrong destination IPv6 address from Felicity to LilNikki.
        5. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv6_dest_addr_custom()

    def test_egress_ipv6_dest_addr_ff0x_181(self):
        """
        @description: This subtest verifies ff0x:0000:0000:0000:0000:0000:0000:0181 egress destination IPv6 address
        group filter.

        @steps:
        1. Apply basic PTP configuration with ff0x:0000:0000:0000:0000:0000:0000:0181 egress destination
        IPv6 address matching.
        2. For each PTP packet type and for each address in group ff0x:0000:0000:0000:0000:0000:0000:0181 construct
        PTP packet over UDP and send it from Felicity to LilNikki.
        3. For each packet make sure that it was timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv6_dest_addr_ff0x_181()

    def test_egress_ipv6_dest_addr_ff0x_181_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if ff0x:0000:0000:0000:0000:0000:0000:0181 egress destination
        IPv6 address group matching is enabled, packets with invalid address will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with ff0x:0000:0000:0000:0000:0000:0000:0181 egress destination
        IPv6 address matching.
        2. For each PTP packet type construct the packet over UDP with random destination IPv6 address and send it
        from Felicity to LilNikki.
        3. For each packet make sure that it was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv6_dest_addr_ff0x_181_but_invalid_in_packet()

    def test_egress_ipv6_dest_addr_ff02_6b(self):
        """
        @description: This subtest verifies ff02:0000:0000:0000:0000:0000:0000:006b egress destination IPv6 address
        filter.

        @steps:
        1. Apply basic PTP configuration with ff02:0000:0000:0000:0000:0000:0000:006b egress destination
        IPv6 address matching.
        2. For each PTP packet type construct PTP packet over UDP with destination IPv6 address
        ff02:0000:0000:0000:0000:0000:0000:006b and send it from Felicity to LilNikki.
        3. For each packet make sure that it was timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv6_dest_addr_ff02_6b()

    def test_egress_ipv6_dest_addr_ff02_6b_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if ff02:0000:0000:0000:0000:0000:0000:006b egress destination
        IPv6 address matching is enabled, packets with invalid address will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with ff02:0000:0000:0000:0000:0000:0000:006b egress destination
        IPv6 address matching.
        2. For each PTP packet type construct the packet over UDP with random destination IPv6 address and send it
        from Felicity to LilNikki.
        3. For each packet make sure that it was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv6_dest_addr_ff02_6b_but_invalid_in_packet()

    def test_egress_ipv6_not_ip_proto(self):
        """
        @description: This is negative test that verifies if proto field of Ethernet header is not IPv6 the packet
        shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv6 but set not IPv6 proto field in Ethernet header and send it
        from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv6_not_ip_proto()

    def test_egress_ipv6_not_udp_proto(self):
        """
        @description: This is negative test that verifies if proto field of IPv6 header is not UDP the packet
        shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv6 but set not UDP proto field in IPv6 header and send it
        from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv6_not_udp_proto()

    def test_egress_ipv6_no_udp_header(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with IPv6 header but without UDP
        header shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv6, remove UDP header from it and send it from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv6_no_udp_header()

    def test_egress_ipv6_no_ptp_header(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with missing PTP
        header shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv6, remove PTP header from it and send it from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv6_no_ptp_header()


class TestPhyPtpIPv6IngressFilter(TestPhyPtpIPv6FilterBase):
    """
    @description: The PHY PTP IPv6 ingress filter test group is dedicated to verify IPv6 ingress filter functionality,
    i. e. PTP packet filtering by destination IPv6 address.

    @setup: Felicity <-> PHY (Europa, Calypso, Rhea) <-> LilNikki
    """

    def phy_basic_config(self, speed, is_ipv6_udp, ipv6_filter_cfg,
                         ipv6_custom_addr="0000:0000:0000:0000:0000:0000:0000:0000"):
        pc = PtpConfig(speed=speed)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.ipv6_udp = is_ipv6_udp
        cfg.ipv6_filter_cfg = ipv6_filter_cfg
        cfg.ipv6_dest_addr = ipv6_custom_addr
        cfg.udp_port_cfg = PtpFiltersIngressEnableConfig.PTP_1588_PORT_319_NTP_SNTP_PORT_123
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.apply(self.pa)

        time.sleep(1)

    def verify_stream_id_and_ts_are_not_zero(self, msg):
        self.verify_stream_id_and_ingress_ts_are_not_zero(msg)

    def verify_stream_id_and_ts_are_zero(self, msg):
        self.verify_stream_id_and_ingress_ts_are_zero(msg)

    def send_pkt(self, packet):
        self.send_packet(packet, host=self.LKP_HOSTNAME)

    def test_ingress_ipv6_dest_addr_off(self):
        """
        @description: This subtest verifies disable of ingress destination IPv6 address filter.

        @steps:
        1. Apply basic PTP configuration with disabled ingress destination IPv6 address matching.
        2. Send PDelayRequest packet over UDP protocol with random destination IPv6 address from LilNikki to Felicity.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        self.run_test_ipv6_dest_addr_off()

    def test_ingress_ipv6_dest_addr_custom(self):
        """
        @description: This subtest verifies custom ingress destination IPv6 address filter.

        @steps:
        1. Apply basic PTP configuration with custom ingress destination IPv6 address matching.
        2. Send PDelayRequest packet over UDP protocol with correct destination IPv6 address from LilNikki to Felicity.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.
        4. Send PDelayRequest packet over UDP protocol with wrong destination IPv6 address from LilNikki to Felicity.
        5. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv6_dest_addr_custom()

    def test_ingress_ipv6_dest_addr_ff0x_181(self):
        """
        @description: This subtest verifies ff0x:0000:0000:0000:0000:0000:0000:0181 ingress destination IPv6 address
        group filter.

        @steps:
        1. Apply basic PTP configuration with ff0x:0000:0000:0000:0000:0000:0000:0181 ingress destination
        IPv6 address matching.
        2. For each PTP packet type and for each address in group ff0x:0000:0000:0000:0000:0000:0000:0181 construct
        PTP packet over UDP and send it from LilNikki to Felicity.
        3. For each packet make sure that it was timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv6_dest_addr_ff0x_181()

    def test_ingress_ipv6_dest_addr_ff0x_181_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if ff0x:0000:0000:0000:0000:0000:0000:0181 ingress destination
        IPv6 address group matching is enabled, packets with invalid address will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with ff0x:0000:0000:0000:0000:0000:0000:0181 ingress destination
        IPv6 address matching.
        2. For each PTP packet type construct the packet over UDP with random destination IPv6 address and send it
        from LilNikki to Felicity.
        3. For each packet make sure that it was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv6_dest_addr_ff0x_181_but_invalid_in_packet()

    def test_ingress_ipv6_dest_addr_ff02_6b(self):
        """
        @description: This subtest verifies ff02:0000:0000:0000:0000:0000:0000:006b ingress destination IPv6 address
        filter.

        @steps:
        1. Apply basic PTP configuration with ff02:0000:0000:0000:0000:0000:0000:006b ingress destination
        IPv6 address matching.
        2. For each PTP packet type construct PTP packet over UDP with destination IPv6 address
        ff02:0000:0000:0000:0000:0000:0000:006b and send it from LilNikki to Felicity.
        3. For each packet make sure that it was timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv6_dest_addr_ff02_6b()

    def test_ingress_ipv6_dest_addr_ff02_6b_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if ff02:0000:0000:0000:0000:0000:0000:006b ingress destination
        IPv6 address matching is enabled, packets with invalid address will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with ff02:0000:0000:0000:0000:0000:0000:006b ingress destination
        IPv6 address matching.
        2. For each PTP packet type construct the packet over UDP with random destination IPv6 address and send it
        from LilNikki to Felicity.
        3. For each packet make sure that it was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 3 seconds.
        """

        self.run_test_ipv6_dest_addr_ff02_6b_but_invalid_in_packet()

    def test_ingress_ipv6_not_ip_proto(self):
        """
        @description: This is negative test that verifies if proto field of Ethernet header is not IPv6 the packet
        shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv6 but set not IPv6 proto field in Ethernet header and send it
        from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv6_not_ip_proto()

    def test_ingress_ipv6_not_udp_proto(self):
        """
        @description: This is negative test that verifies if proto field of IPv6 header is not UDP the packet
        shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv6 but set not UDP proto field in IPv6 header and send it
        from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv6_not_udp_proto()

    def test_ingress_ipv6_no_udp_header(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with IPv6 header but without UDP
        header shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv6, remove UDP header from it and send it from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv6_no_udp_header()

    def test_ingress_ipv6_no_ptp_header(self):
        """
        @description: This is negative test that verifies that invalid PTP packet with missing PTP
        header shall not be timestamped.

        @steps:
        1. Apply basic PTP configuration.
        2. Construct PTP packet over UDP IPv6, remove PTP header from it and send it from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: All checks are passed.
        @duration: 1 second.
        """

        self.run_test_ipv6_no_ptp_header()


class TestPhyPtpUdpFilterBase(TestPhyPtpBase):
    ETH_HEADER = EthernetHeader(dst="01:00:5e:00:00:6b", src="68:05:ca:62:2e:df", type=ETH_TYPE_IPv4)
    IP_HEADER = IPv4Header(version=4, ihl=5, dscp=0, length=0x52, identification=0x8905, flags=0x4000, ttl=1,
                           protocol=PROTOCOL_UDP, src="192.168.0.138", dst="224.0.1.129")

    def setUp(self):
        super(TestPhyPtpUdpFilterBase, self).setUp()

    def phy_basic_config(self, speed, udp_port_cfg, custom_dest_port=0):
        raise NotImplementedError()

    def verify_stream_id_and_ts_are_not_zero(self, msg):
        raise NotImplementedError()

    def verify_stream_id_and_ts_are_zero(self, msg):
        raise NotImplementedError()

    def send_pkt(self, packet):
        raise NotImplementedError()

    def run_test_udp_dest_port_off(self):
        self.phy_basic_config(self.LINK_SPEED, PtpFiltersEgressEnableConfig.PTP_1588_PORT_OFF)

        for dest_port in [319, 320, 321, 4444, 12345]:
            print "Testing destination port %d" % (dest_port)
            udp = UdpHeader(src=random.randint(1000, 5000), dst=dest_port, length=62)
            packet = self.ETH_HEADER / self.IP_HEADER / udp / PtpV2PathDelayRequestHeader()
            packet.calculate_checksums()

            self.send_pkt(packet)
            self.verify_stream_id_and_ts_are_not_zero("dest port matching is off")

    def run_test_udp_dest_port_319(self):
        self.phy_basic_config(self.LINK_SPEED, PtpFiltersEgressEnableConfig.PTP_1588_PORT_319_NTP_SNTP_PORT_123)

        udp = UdpHeader(src=random.randint(1000, 5000), dst=319, length=62)
        packet = self.ETH_HEADER / self.IP_HEADER / udp / PtpV2PathDelayRequestHeader()
        packet.calculate_checksums()

        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_not_zero("dest port matches filter")

    def run_test_udp_dest_port_319_but_invalid_in_packet(self):
        self.phy_basic_config(self.LINK_SPEED, PtpFiltersEgressEnableConfig.PTP_1588_PORT_319_NTP_SNTP_PORT_123)

        for dest_port in [318, 320, 4444, 12345]:
            print "Testing destination port %d" % (dest_port)
            udp = UdpHeader(src=random.randint(1000, 5000), dst=dest_port, length=62)
            packet = self.ETH_HEADER / self.IP_HEADER / udp / PtpV2PathDelayRequestHeader()
            packet.calculate_checksums()

            self.send_pkt(packet)
            self.verify_stream_id_and_ts_are_zero("dest port doesn't match filter")

    def run_test_udp_dest_port_320(self):
        self.phy_basic_config(self.LINK_SPEED, PtpFiltersEgressEnableConfig.PTP_1588_PORT_320_NTP_SNTP_PORT_NONE)

        udp = UdpHeader(src=random.randint(1000, 5000), dst=320, length=62)
        packet = self.ETH_HEADER / self.IP_HEADER / udp / PtpV2PathDelayRequestHeader()
        packet.calculate_checksums()

        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_not_zero("dest port matches filter")

    def run_test_udp_dest_port_320_but_invalid_in_packet(self):
        self.phy_basic_config(self.LINK_SPEED, PtpFiltersEgressEnableConfig.PTP_1588_PORT_319_NTP_SNTP_PORT_123)

        for dest_port in [321, 319, 4444, 12345]:
            print "Testing destination port %d" % (dest_port)
            udp = UdpHeader(src=random.randint(1000, 5000), dst=dest_port, length=62)
            packet = self.ETH_HEADER / self.IP_HEADER / udp / PtpV2PathDelayRequestHeader()
            packet.calculate_checksums()

            self.send_pkt(packet)
            self.verify_stream_id_and_ts_are_zero("dest port doesn't match filter")

    def run_test_udp_dest_port_custom(self):
        custom_dest_port = 4444
        self.phy_basic_config(self.LINK_SPEED, PtpFiltersEgressEnableConfig.PTP_1588_PORT_CUSTOM, custom_dest_port)

        udp = UdpHeader(src=random.randint(1000, 5000), dst=custom_dest_port, length=62)
        packet = self.ETH_HEADER / self.IP_HEADER / udp / PtpV2PathDelayRequestHeader()
        packet.calculate_checksums()

        self.send_pkt(packet)
        self.verify_stream_id_and_ts_are_not_zero("custom dest port matches filter")

    def run_test_udp_dest_port_custom_but_invalid_in_packet(self):
        custom_dest_port = 5555
        self.phy_basic_config(self.LINK_SPEED, PtpFiltersEgressEnableConfig.PTP_1588_PORT_CUSTOM, custom_dest_port)

        for dest_port in [5554, 319, 320, 4444]:
            print "Testing destination port %d" % (dest_port)
            udp = UdpHeader(src=random.randint(1000, 5000), dst=dest_port, length=62)
            packet = self.ETH_HEADER / self.IP_HEADER / udp / PtpV2PathDelayRequestHeader()
            packet.calculate_checksums()

            self.send_pkt(packet)
            self.verify_stream_id_and_ts_are_zero("custom dest port doesn't match filter")


class TestPhyPtpUdpEgressFilter(TestPhyPtpUdpFilterBase):
    """
    @description: The PHY PTP UDP egress filter test group is dedicated to verify UDP egress filter functionality,
    i. e. PTP packet filtering by destination UDP port.

    @setup: Felicity <-> PHY (Europa, Calypso, Rhea) <-> LilNikki
    """

    def setUp(self):
        super(TestPhyPtpUdpEgressFilter, self).setUp()

    def phy_basic_config(self, speed, udp_port_cfg, custom_dest_port=0):
        pc = PtpConfig(speed=speed)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.ipv4_udp = True
        cfg.ipv4_filter_cfg = PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_OFF
        cfg.udp_port_cfg = udp_port_cfg
        cfg.udp_dest_port = custom_dest_port
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.apply(self.pa)

        time.sleep(1)

    def verify_stream_id_and_ts_are_not_zero(self, msg):
        self.verify_stream_id_and_egress_ts_are_not_zero(msg)

    def verify_stream_id_and_ts_are_zero(self, msg):
        self.verify_stream_id_and_egress_ts_are_zero(msg)

    def send_pkt(self, packet):
        self.send_packet(packet)

    def test_egress_udp_dest_port_319(self):
        """
        @description: This subtest verifies egress UDP destination port 319 filter.

        @steps:
        1. Apply basic PTP configuration with enabled egress destination UDP port 319 matching.
        2. Send PDelayRequest packet over IPv4 UDP with destination port 319 from Felicity to LilNikki.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_319()

    def test_egress_udp_dest_port_319_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if egress UDP destination port 319 filter matching is enabled,
        PTP packets with different port will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with enabled egress destination UDP port 319 matching.
        2. Send PDelayRequest packet over IPv4 UDP with random destination port from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: Packet was not timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_319_but_invalid_in_packet()

    def test_egress_udp_dest_port_320(self):
        """
        @description: This subtest verifies egress UDP destination port 320 filter.

        @steps:
        1. Apply basic PTP configuration with enabled egress destination UDP port 320 matching.
        2. Send PDelayRequest packet over IPv4 UDP with destination port 320 from Felicity to LilNikki.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_320()

    def test_egress_udp_dest_port_320_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if egress UDP destination port 320 filter matching is enabled,
        PTP packets with different port will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with enabled egress destination UDP port 320 matching.
        2. Send PDelayRequest packet over IPv4 UDP with random destination port from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: Packet was not timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_320_but_invalid_in_packet()

    def test_egress_udp_dest_port_custom(self):
        """
        @description: This subtest verifies custom egress UDP destination port filter.

        @steps:
        1. Apply basic PTP configuration with enabled custom egress destination UDP port matching.
        2. Send PDelayRequest packet over IPv4 UDP with custom destination port from Felicity to LilNikki.
        3. Extract egress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_custom()

    def test_egress_udp_dest_port_custom_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if custom egress UDP destination port filter matching is enabled,
        PTP packets with different port will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with enabled custom egress destination UDP port matching.
        2. Send PDelayRequest packet over IPv4 UDP with random destination port from Felicity to LilNikki.
        3. Make sure that packet was not timestamped by checking egress timestamp FIFO.

        @result: Packet was not timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_custom_but_invalid_in_packet()


class TestPhyPtpUdpIngressFilter(TestPhyPtpUdpFilterBase):
    """
    @description: The PHY PTP UDP ingress filter test group is dedicated to verify UDP ingress filter functionality,
    i. e. PTP packet filtering by destination UDP port.

    @setup: Felicity <-> PHY (Europa, Calypso, Rhea) <-> LilNikki
    """

    def setUp(self):
        super(TestPhyPtpUdpIngressFilter, self).setUp()

    def phy_basic_config(self, speed, udp_port_cfg, custom_dest_port=0):
        pc = PtpConfig(speed=speed)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.ipv4_udp = True
        cfg.ipv4_filter_cfg = PtpFiltersEgressEnableConfig.PTP_IPV4_IEEE_1588_OFF
        cfg.udp_port_cfg = udp_port_cfg
        cfg.udp_dest_port = custom_dest_port
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.apply(self.pa)

        time.sleep(1)

    def verify_stream_id_and_ts_are_not_zero(self, msg):
        self.verify_stream_id_and_ingress_ts_are_not_zero(msg)

    def verify_stream_id_and_ts_are_zero(self, msg):
        self.verify_stream_id_and_ingress_ts_are_zero(msg)

    def send_pkt(self, packet):
        self.send_packet(packet, host=self.LKP_HOSTNAME)

    def test_ingress_udp_dest_port_319(self):
        """
        @description: This subtest verifies ingress UDP destination port 319 filter.

        @steps:
        1. Apply basic PTP configuration with enabled ingress destination UDP port 319 matching.
        2. Send PDelayRequest packet over IPv4 UDP with destination port 319 from LilNikki to Felicity.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_319()

    def test_ingress_udp_dest_port_319_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if ingress UDP destination port 319 filter matching is enabled,
        PTP packets with different port will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with enabled ingress destination UDP port 319 matching.
        2. Send PDelayRequest packet over IPv4 UDP with random destination port from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: Packet was not timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_319_but_invalid_in_packet()

    def test_ingress_udp_dest_port_320(self):
        """
        @description: This subtest verifies ingress UDP destination port 320 filter.

        @steps:
        1. Apply basic PTP configuration with enabled ingress destination UDP port 320 matching.
        2. Send PDelayRequest packet over IPv4 UDP with destination port 320 from LilNikki to Felicity.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_320()

    def test_ingress_udp_dest_port_320_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if ingress UDP destination port 320 filter matching is enabled,
        PTP packets with different port will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with enabled ingress destination UDP port 320 matching.
        2. Send PDelayRequest packet over IPv4 UDP with random destination port from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: Packet was not timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_320_but_invalid_in_packet()

    def test_ingress_udp_dest_port_custom(self):
        """
        @description: This subtest verifies custom ingress UDP destination port filter.

        @steps:
        1. Apply basic PTP configuration with enabled custom ingress destination UDP port matching.
        2. Send PDelayRequest packet over IPv4 UDP with custom destination port from LilNikki to Felicity.
        3. Extract ingress timestamp from timestamp FIFO, make sure that timestamp and stream id are not zero.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_custom()

    def test_ingress_udp_dest_port_custom_but_invalid_in_packet(self):
        """
        @description: This subtest verifies that if custom ingress UDP destination port filter matching is enabled,
        PTP packets with different port will not be timestamped.

        @steps:
        1. Apply basic PTP configuration with enabled custom ingress destination UDP port matching.
        2. Send PDelayRequest packet over IPv4 UDP with random destination port from LilNikki to Felicity.
        3. Make sure that packet was not timestamped by checking ingress timestamp FIFO.

        @result: Packet was not timestamped.
        @duration: 1 second.
        """

        self.run_test_udp_dest_port_custom_but_invalid_in_packet()


class TestPhyPtpEgressTsAction(TestPhyPtpBase):
    """
    @description: The PHY PTP egress timestamp action test group is dedicated to verify timestamp actor.

    @setup: Felicity <-> PHY (Europa, Calypso, Rhea) <-> LilNikki
    """

    def setUp(self):
        super(TestPhyPtpEgressTsAction, self).setUp()
        self.phy_basic_config(speed=LINK_SPEED_1G)

    def test_egress_ts_action_none_for_all_packets(self):
        """
        @description: This subtest verifies that timestamp action type none doesn't modify egress timestamp.

        @steps:
        1. Apply basic PTP configuration with disabled timestamp action.
        2. For all PTP packet types send the packet from Felicity to LilNikki.
        3. Make sure that packet was timestamped by checking egress timestamp FIFO.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        ptc = PtpTimestampingEgressEnableConfig()
        for k in ptc.ieee1588v2_ts_act.keys():
            ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_NONE
        ptc.apply(self.pa)

        time.sleep(1)

        self.cleanup_ts()

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)

        packet = eth / PtpV2SyncHeader()
        self.send_packet(packet)
        self.verify_stream_id_and_egress_ts_are_not_zero("sync packet matches filter")

        time.sleep(0.1)

        packet = eth / PtpV2DelayRequestHeader()
        self.send_packet(packet)
        self.verify_stream_id_and_egress_ts_are_not_zero("delay request packet matches filter")

        time.sleep(0.1)

        packet = eth / PtpV2PathDelayRequestHeader()
        self.send_packet(packet)
        self.verify_stream_id_and_egress_ts_are_not_zero("path delay request packet matches filter")

        time.sleep(0.1)

        packet = eth / PtpV2PathDelayResponseHeader()
        self.send_packet(packet)
        self.verify_stream_id_and_egress_ts_are_not_zero("path delay response packet matches filter")

        time.sleep(0.1)

        packet = eth / PtpV2PathDelayRequestHeader(message_id=0xd)  # but user defined message id
        self.send_packet(packet)
        self.verify_stream_id_and_egress_ts_are_not_zero("path delay request packet matches filter")

    def test_egress_ts_action_append_for_all_packets(self):
        """
        @description: This subtest verifies that timestamp action append concatenates egress timestamp to the packet.

        @steps:
        1. Apply basic PTP configuration with timestamp action append.
        2. For all PTP packet types send the packet from Felicity to LilNikki.
        3. Dump packets on LilNikki side, make sure that timestamp is appended to the end of packet.

        @result: Timestamp was appended.
        @duration: 1 second.
        """

        ptc = PtpTimestampingEgressEnableConfig()
        for k in ptc.ieee1588v2_ts_act.keys():
            ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_APPEND
        ptc.apply(self.pa)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)

        def send_and_verify(l3_header):
            print "\nVerifying %s packet type" % (type(l3_header))
            packet = eth / l3_header
            ctx = self.begin_capture(2, "cap.pcap", filter="ether proto 0x88f7", host=self.LKP_HOSTNAME)
            self.send_packet(packet)
            packets = self.end_capture(ctx)
            self.assertEqual(1, len(packets))
            egr_ts = packets[0][1].ts_1
            print "Egress timestamp in packet %d" % (egr_ts)
            self.assertTrue(egr_ts > 0)
            print ""

        send_and_verify(PtpV2SyncHeader(origin_timestamp=0xaabb))
        send_and_verify(PtpV2DelayRequestHeader())
        send_and_verify(PtpV2PathDelayRequestHeader())
        send_and_verify(PtpV2PathDelayResponseHeader())
        send_and_verify(PtpV2PathDelayRequestHeader(message_id=0xd))  # but user defined message id

    def test_egress_ts_action_overwrite_for_all_packets(self):
        """
        @description: This subtest verifies that timestamp action overwrite modifies origin timestamp of the packet.

        @steps:
        1. Apply basic PTP configuration with timestamp action overwrite.
        2. For all PTP packet types send the packet from Felicity to LilNikki.
        3. Dump packets on LilNikki side, make sure that origin timestamp was overwritten.

        @result: Timestamp was overwritten.
        @duration: 1 second.
        """

        ptc = PtpTimestampingEgressEnableConfig()
        for k in ptc.ieee1588v2_ts_act.keys():
            ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_OVERWRITE
        ptc.apply(self.pa)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)

        def send_and_verify(l3_header):
            print "\nVerifying %s packet type" % (type(l3_header))
            packet = eth / l3_header
            ctx = self.begin_capture(2, "cap.pcap", filter="ether proto 0x88f7", host=self.LKP_HOSTNAME)
            self.send_packet(packet)
            packets = self.end_capture(ctx)
            self.assertEqual(1, len(packets))

            def verify_ts_overwritten(origin_ts, overwritten_ts):
                print "Original TS %d, overwritten TS %d" % (origin_ts, overwritten_ts)
                self.assertNotEqual(origin_ts, overwritten_ts,
                                    "Origin timestamp field must be overwritten")

            if type(l3_header) == PtpV2SyncHeader:
                verify_ts_overwritten(l3_header.origin_timestamp, packets[0][PtpV2SyncHeader].origin_timestamp)
            elif type(l3_header) == PtpV2DelayRequestHeader:
                verify_ts_overwritten(l3_header.origin_timestamp, packets[0][PtpV2DelayRequestHeader].origin_timestamp)
            elif type(l3_header) == PtpV2PathDelayRequestHeader:
                verify_ts_overwritten(l3_header.origin_timestamp,
                                      packets[0][PtpV2PathDelayRequestHeader].origin_timestamp)
            elif type(l3_header) == PtpV2PathDelayResponseHeader:
                verify_ts_overwritten(l3_header.request_receipt_timestamp,
                                      packets[0][PtpV2PathDelayResponseHeader].request_receipt_timestamp)

        send_and_verify(PtpV2SyncHeader(origin_timestamp=999 * 1000000000 + 12345))
        send_and_verify(PtpV2DelayRequestHeader(origin_timestamp=888 * 1000000000 + 12345))
        send_and_verify(PtpV2PathDelayRequestHeader(origin_timestamp=777 * 1000000000 + 12345))
        send_and_verify(PtpV2PathDelayResponseHeader(request_receipt_timestamp=666 * 1000000000 + 12345))
        # but user defined message id
        send_and_verify(PtpV2SyncHeader(message_id=0xd, origin_timestamp=555 * 1000000000 + 12345))

    def test_egress_ts_action_remove_for_all_packets(self):
        """
        @description: This subtest verifies that timestamp action remove deletes timestamp from the end of the packet.

        @steps:
        1. Apply basic PTP configuration with timestamp action remove.
        2. For all PTP packet types send the packet with appended timestamp from Felicity to LilNikki.
        3. Dump packets on LilNikki side, make sure that appended timestamp was removed.

        @result: Timestamp was removed.
        @duration: 1 second.
        """

        ptc = PtpTimestampingEgressEnableConfig()
        for k in ptc.ieee1588v2_ts_act.keys():
            ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_REMOVE
        ptc.apply(self.pa)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)

        # def send_and_verify(l3_header):
        #     print "\nVerifying %s packet type" % (type(l3_header))
        #     packet = eth / l3_header
        #     ctx = self.begin_capture(2, "cap.pcap", filter="ether proto 0x88f7", host=self.LKP_HOSTNAME)
        #     self.send_packet(packet)
        #     packets = self.end_capture(ctx)
        #     self.assertEqual(1, len(packets))

        #     def verify_ts_removed(origin_ts, overwritten_ts):
        #         print "Original TS %d, overwritten TS %d" % (origin_ts, overwritten_ts)
        #         self.assertNotEqual(origin_ts, overwritten_ts,
        #                             "Origin timestamp field must be overwritten")
        #         self.assertEqual(overwritten_ts, 0)

        #     if type(l3_header) == PtpV2SyncHeader:
        #         verify_ts_removed(l3_header.origin_timestamp, packets[0][PtpV2SyncHeader].origin_timestamp)
        #     elif type(l3_header) == PtpV2DelayRequestHeader:
        #         verify_ts_removed(l3_header.origin_timestamp, packets[0][PtpV2DelayRequestHeader].origin_timestamp)
        #     elif type(l3_header) == PtpV2PathDelayRequestHeader:
        #         verify_ts_removed(l3_header.origin_timestamp, packets[0][PtpV2PathDelayRequestHeader].origin_timestamp)
        #     elif type(l3_header) == PtpV2PathDelayResponseHeader:
        #         verify_ts_removed(l3_header.request_receipt_timestamp,
        #                           packets[0][PtpV2PathDelayResponseHeader].request_receipt_timestamp)

        def send_and_verify(l3_header):
            padding = [0xff] * 40
            append_ts = [0x11] * 12
            print "\nVerifying %s packet type" % (type(l3_header))
            packet = eth / l3_header
            packet.data += padding + append_ts
            ctx = self.begin_capture(2, "cap.pcap", filter="ether proto 0x88f7", host=self.LKP_HOSTNAME)
            self.send_packet(packet)
            packets = self.end_capture(ctx)
            self.assertEqual(1, len(packets))

            def verify_ts_removed(origin_ts, overwritten_ts):
                print "Original TS %d, overwritten TS %d" % (origin_ts, overwritten_ts)
                self.assertNotEqual(origin_ts, overwritten_ts,
                                    "Origin timestamp field must be overwritten")
                self.assertEqual(overwritten_ts, 0)

            if type(l3_header) == PtpV2SyncHeader:
                verify_ts_removed(l3_header.origin_timestamp, packets[0][PtpV2SyncHeader].origin_timestamp)
            elif type(l3_header) == PtpV2DelayRequestHeader:
                verify_ts_removed(l3_header.origin_timestamp, packets[0][PtpV2DelayRequestHeader].origin_timestamp)
            elif type(l3_header) == PtpV2PathDelayRequestHeader:
                verify_ts_removed(l3_header.origin_timestamp, packets[0][PtpV2PathDelayRequestHeader].origin_timestamp)
            elif type(l3_header) == PtpV2PathDelayResponseHeader:
                verify_ts_removed(l3_header.request_receipt_timestamp,
                                  packets[0][PtpV2PathDelayResponseHeader].request_receipt_timestamp)

        send_and_verify(PtpV2SyncHeader(origin_timestamp=999 * 1000000000 + 12345))
        # send_and_verify(PtpV2DelayRequestHeader(origin_timestamp=888 * 1000000000 + 12345))
        # send_and_verify(PtpV2PathDelayRequestHeader(origin_timestamp=777 * 1000000000 + 12345))
        # send_and_verify(PtpV2PathDelayResponseHeader(request_receipt_timestamp=666 * 1000000000 + 12345))
        # but user defined message id
        # send_and_verify(PtpV2SyncHeader(message_id=0xd, origin_timestamp=555 * 1000000000 + 12345))


class TestPhyPtpIngressTsAction(TestPhyPtpBase):
    """
     @description: The PHY PTP ingress timestamp action test group is dedicated to verify timestamp actor.

     @setup: Felicity <-> PHY (Europa, Calypso, Rhea) <-> LilNikki
     """

    def setUp(self):
        super(TestPhyPtpIngressTsAction, self).setUp()
        self.phy_basic_config(speed=LINK_SPEED_1G)

    def test_ingress_ts_action_none_for_all_packets(self):
        """
        @description: This subtest verifies that timestamp action type none doesn't modify ingress timestamp.

        @steps:
        1. Apply basic PTP configuration with disabled timestamp action.
        2. For all PTP packet types send the packet from LilNikki to Felicity.
        3. Make sure that packet was timestamped by checking ingress timestamp FIFO.

        @result: Packet has been timestamped.
        @duration: 1 second.
        """

        ptc = PtpTimestampingIngressEnableConfig()
        for k in ptc.ieee1588v2_ts_act.keys():
            ptc.ieee1588v2_ts_act[k] = PtpTimestampingIngressEnableConfig.TS_ACT_NONE
        ptc.apply(self.pa)

        time.sleep(1)

        self.cleanup_ts()

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)

        packet = eth / PtpV2SyncHeader()
        self.send_packet(packet, host=self.LKP_HOSTNAME)
        self.verify_stream_id_and_ingress_ts_are_not_zero("sync packet matches filter")

        time.sleep(0.1)

        packet = eth / PtpV2DelayRequestHeader()
        self.send_packet(packet, host=self.LKP_HOSTNAME)
        self.verify_stream_id_and_ingress_ts_are_not_zero("delay request packet matches filter")

        time.sleep(0.1)

        packet = eth / PtpV2PathDelayRequestHeader()
        self.send_packet(packet, host=self.LKP_HOSTNAME)
        self.verify_stream_id_and_ingress_ts_are_not_zero("path delay request packet matches filter")

        time.sleep(0.1)

        packet = eth / PtpV2PathDelayResponseHeader()
        self.send_packet(packet, host=self.LKP_HOSTNAME)
        self.verify_stream_id_and_ingress_ts_are_not_zero("path delay response packet matches filter")

        time.sleep(0.1)

        packet = eth / PtpV2PathDelayRequestHeader(message_id=0xd)  # but user defined message id
        self.send_packet(packet, host=self.LKP_HOSTNAME)
        self.verify_stream_id_and_ingress_ts_are_not_zero("path delay request packet matches filter")

    def test_ingress_ts_action_append_for_all_packets(self):
        """
         @description: This subtest verifies that timestamp action append concatenates ingress timestamp to the packet.

         @steps:
         1. Apply basic PTP configuration with timestamp action append.
         2. For all PTP packet types send the packet from LilNikki to Felicity.
         3. Dump packets on Felicity side, make sure that timestamp is appended to the end of packet.

         @result: Timestamp was appended.
         @duration: 1 second.
         """

        ptc = PtpTimestampingIngressEnableConfig()
        for k in ptc.ieee1588v2_ts_act.keys():
            ptc.ieee1588v2_ts_act[k] = PtpTimestampingIngressEnableConfig.TS_ACT_APPEND
        ptc.apply(self.pa)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)

        def send_and_verify(l3_header):
            print "\nVerifying %s packet type" % (type(l3_header))
            packet = eth / l3_header
            ctx = self.begin_capture(2, "cap.pcap", filter="ether proto 0x88f7")
            self.send_packet(packet, host=self.LKP_HOSTNAME)
            packets = self.end_capture(ctx)
            self.assertEqual(1, len(packets))
            ing_ts = packets[0][1].ts_1
            print "Ingress timestamp in packet %d" % (ing_ts)
            self.assertTrue(ing_ts > 0)
            print ""

        send_and_verify(PtpV2SyncHeader())
        send_and_verify(PtpV2DelayRequestHeader())
        send_and_verify(PtpV2PathDelayRequestHeader())
        send_and_verify(PtpV2PathDelayResponseHeader())
        send_and_verify(PtpV2PathDelayRequestHeader(message_id=0xd))  # but user defined message id

    def test_ingress_ts_action_overwrite_for_all_packets(self):
        """
        @description: This subtest verifies that timestamp action overwrite modifies origin timestamp of the packet.

        @steps:
        1. Apply basic PTP configuration with timestamp action overwrite.
        2. For all PTP packet types send the packet from LilNikki to Felicity.
        3. Dump packets on Felicity side, make sure that origin timestamp was overwritten.

        @result: Timestamp was overwritten.
        @duration: 1 second.
        """

        ptc = PtpTimestampingIngressEnableConfig()
        for k in ptc.ieee1588v2_ts_act.keys():
            ptc.ieee1588v2_ts_act[k] = PtpTimestampingIngressEnableConfig.TS_ACT_OVERWRITE
        ptc.apply(self.pa)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)

        def send_and_verify(l3_header):
            print "\nVerifying %s packet type" % (type(l3_header))
            packet = eth / l3_header
            ctx = self.begin_capture(2, "cap.pcap", filter="ether proto 0x88f7")
            self.send_packet(packet, host=self.LKP_HOSTNAME)
            packets = self.end_capture(ctx)
            self.assertEqual(1, len(packets))

            def verify_ts_overwritten(origin_ts, overwritten_ts):
                print "Original TS %d, overwritten TS %d" % (origin_ts, overwritten_ts)
                self.assertNotEqual(origin_ts, overwritten_ts,
                                    "Origin timestamp field must be overwritten")

            if type(l3_header) == PtpV2SyncHeader:
                verify_ts_overwritten(l3_header.origin_timestamp, packets[0][PtpV2SyncHeader].origin_timestamp)
            elif type(l3_header) == PtpV2DelayRequestHeader:
                verify_ts_overwritten(l3_header.origin_timestamp, packets[0][PtpV2DelayRequestHeader].origin_timestamp)
            elif type(l3_header) == PtpV2PathDelayRequestHeader:
                verify_ts_overwritten(l3_header.origin_timestamp,
                                      packets[0][PtpV2PathDelayRequestHeader].origin_timestamp)
            elif type(l3_header) == PtpV2PathDelayResponseHeader:
                verify_ts_overwritten(l3_header.request_receipt_timestamp,
                                      packets[0][PtpV2PathDelayResponseHeader].request_receipt_timestamp)

        send_and_verify(PtpV2SyncHeader(origin_timestamp=999 * 1000000000 + 12345))
        send_and_verify(PtpV2DelayRequestHeader(origin_timestamp=888 * 1000000000 + 12345))
        send_and_verify(PtpV2PathDelayRequestHeader(origin_timestamp=777 * 1000000000 + 12345))
        send_and_verify(PtpV2PathDelayResponseHeader(request_receipt_timestamp=666 * 1000000000 + 12345))
        # but user defined message id
        send_and_verify(PtpV2SyncHeader(message_id=0xd, origin_timestamp=555 * 1000000000 + 12345))

    def test_ingress_ts_action_remove_for_all_packets(self):
        """
        @description: This subtest verifies that timestamp action remove deletes timestamp from the end of the packet.

        @steps:
        1. Apply basic PTP configuration with timestamp action remove.
        2. For all PTP packet types send the packet with appended timestamp from LilNikki to Felicity.
        3. Dump packets on Felicity side, make sure that appended timestamp was removed.

        @result: Timestamp was removed.
        @duration: 1 second.
        """

        ptc = PtpTimestampingIngressEnableConfig()
        for k in ptc.ieee1588v2_ts_act.keys():
            ptc.ieee1588v2_ts_act[k] = PtpTimestampingIngressEnableConfig.TS_ACT_REMOVE
        ptc.apply(self.pa)

        time.sleep(1)

        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)

        def send_and_verify(l3_header):
            print "\nVerifying %s packet type" % (type(l3_header))
            packet = eth / l3_header
            ctx = self.begin_capture(2, "cap.pcap", filter="ether proto 0x88f7")
            self.send_packet(packet, host=self.LKP_HOSTNAME)
            packets = self.end_capture(ctx)
            self.assertEqual(1, len(packets))

            def verify_ts_removed(origin_ts, overwritten_ts):
                print "Original TS %d, overwritten TS %d" % (origin_ts, overwritten_ts)
                self.assertNotEqual(origin_ts, overwritten_ts,
                                    "Origin timestamp field must be overwritten")
                self.assertEqual(overwritten_ts, 0)

            if type(l3_header) == PtpV2SyncHeader:
                verify_ts_removed(l3_header.origin_timestamp, packets[0][PtpV2SyncHeader].origin_timestamp)
            elif type(l3_header) == PtpV2DelayRequestHeader:
                verify_ts_removed(l3_header.origin_timestamp, packets[0][PtpV2DelayRequestHeader].origin_timestamp)
            elif type(l3_header) == PtpV2PathDelayRequestHeader:
                verify_ts_removed(l3_header.origin_timestamp, packets[0][PtpV2PathDelayRequestHeader].origin_timestamp)
            elif type(l3_header) == PtpV2PathDelayResponseHeader:
                verify_ts_removed(l3_header.request_receipt_timestamp,
                                  packets[0][PtpV2PathDelayResponseHeader].request_receipt_timestamp)

        send_and_verify(PtpV2SyncHeader(origin_timestamp=999 * 1000000000 + 12345))
        send_and_verify(PtpV2DelayRequestHeader(origin_timestamp=888 * 1000000000 + 12345))
        send_and_verify(PtpV2PathDelayRequestHeader(origin_timestamp=777 * 1000000000 + 12345))
        send_and_verify(PtpV2PathDelayResponseHeader(request_receipt_timestamp=666 * 1000000000 + 12345))
        # but user defined message id
        send_and_verify(PtpV2SyncHeader(message_id=0xd, origin_timestamp=555 * 1000000000 + 12345))


class TestPhyPtpEgressCorrectionAction(TestPhyPtpBase):
    """
     @description: The PHY PTP egress correction action test group is dedicated to verify correction actor.

     @setup: Felicity <-> PHY (Europa, Calypso, Rhea) with Net_Side-SIF_facing_loopback
     """

    def setUp(self):
        super(TestPhyPtpEgressCorrectionAction, self).setUp()
        self.phy_basic_config(speed=LINK_SPEED_1G)

    def send_packet_and_get_new_correction(self, l3_header):
        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)
        packet = eth / l3_header
        ctx = self.begin_capture(2, "cap.pcap", filter="ether proto 0x88f7", host=self.LKP_HOSTNAME)
        self.send_packet(packet)
        packets = self.end_capture(ctx)
        self.assertEqual(1, len(packets))
        return packets[0][1].correction

    def send_packet_and_get_new_correction_loopback(self, l3_header):
        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)
        packet = eth / l3_header
        ctx = self.begin_capture(2, "cap.pcap", filter="ether proto 0x88f7")
        self.send_packet(packet)
        packets = self.end_capture(ctx)
        self.assertEqual(2, len(packets))
        return packets[1][1].correction

    def test_egress_cor_action_no_change_for_all_packets(self):
        """
        @description: This subtest verifies that egress correction action no change doesnt modify correction field.

        @steps:
        1. Apply basic PTP configuration with correction action no change.
        2. For all PTP packet types send the packet with some correction field value on Felicity.
        3. Dump packets on Felicity side, make sure that correction was not changed.

        @result: Correction was not changed.
        @duration: 1 second.
        """

        ptc = PtpTimestampingEgressEnableConfig()
        for k in ptc.ieee1588v2_cor_act.keys():
            ptc.ieee1588v2_cor_act[k] = PtpTimestampingEgressEnableConfig.COR_ACT_NO_CHANGE
        ptc.apply(self.pa)

        time.sleep(1)

        correction_before = 1111

        correction_after = self.send_packet_and_get_new_correction(PtpV2SyncHeader(correction=correction_before))
        self.assertEqual(correction_before, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2DelayRequestHeader(correction=correction_before))
        self.assertEqual(correction_before, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2PathDelayRequestHeader(correction=correction_before))
        self.assertEqual(correction_before, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2PathDelayResponseHeader(correction=correction_before))
        self.assertEqual(correction_before, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2SyncHeader(message_id=0xd, correction=correction_before))  # but user defined message id
        self.assertEqual(correction_before, correction_after)

    # def test_egress_cor_action_correction_plus_ts_minus_appendts_plus_offset_for_all_packets(self):
    #     # TODO: this test is not finished!!!
    #     cor_offset = 0
    #     eps = 600000000  # 600 milliseconds epsilon
    #     ptc = PtpTimestampingEgressEnableConfig()
    #     ptc.cor_offset = cor_offset << 16
    #     for k in ptc.ieee1588v2_cor_act.keys():
    #         ptc.ieee1588v2_cor_act[k] = \
    #             PtpTimestampingEgressEnableConfig.COR_ACT_CORRECTION_PLUS_TIMESTAMP_MINUS_TIMESTAMPAPPEND_PLUS_OFFSET
    #     ptc.apply(self.pa)

    #     time.sleep(1)

    #     correction_before = 0x0

    #     clock_before = self.read_ptp_clock()
    #     print "!!! clock_before", clock_before
    #     sync = PtpV2SyncHeader(origin_timestamp=10, correction=correction_before)
    #     timestamp_append = [0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    #     sync.data += timestamp_append
    #     sync.message_length += len(timestamp_append)
    #     correction_after = self.send_packet_and_get_new_correction_loopback(sync)
    #     print "!!! correction_after", correction_after
    #     print "!!! correction_after - clock_before", correction_after - clock_before

    def test_egress_cor_action_correction_plus_offset_for_all_packets(self):
        """
        @description: This subtest verifies that egress correction action correction_plus_offset adds offset value to
        the correction field.

        @steps:
        1. Apply basic PTP configuration with correction action correction_plus_offset with some offset value.
        2. For all PTP packet types send the packet with some correction field value on Felicity.
        3. Dump packets on Felicity side, make sure that correction was changed and equals to original value
        plus offset.

        @result: Correction was changed.
        @duration: 1 second.
        """

        cor_offset = 0xbb
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.cor_offset = cor_offset << 16
        for k in ptc.ieee1588v2_cor_act.keys():
            ptc.ieee1588v2_cor_act[k] = PtpTimestampingEgressEnableConfig.COR_ACT_CORRECTION_PLUS_OFFSET
        ptc.apply(self.pa)

        time.sleep(1)

        correction_before = 0

        correction_after = self.send_packet_and_get_new_correction(PtpV2SyncHeader(correction=correction_before))
        self.assertEqual(correction_before + cor_offset, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2DelayRequestHeader(correction=correction_before))
        self.assertEqual(correction_before + cor_offset, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2PathDelayRequestHeader(correction=correction_before))
        self.assertEqual(correction_before + cor_offset, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2PathDelayResponseHeader(correction=correction_before))
        self.assertEqual(correction_before + cor_offset, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2SyncHeader(message_id=0xd, correction=correction_before))  # but user defined message id
        self.assertEqual(correction_before + cor_offset, correction_after)

    def test_egress_cor_action_correction_plus_timestamp_plus_offset_for_all_packets(self):
        """
        @description: This subtest verifies that cegress orrection action correction_plus_timestamp_plus_offset adds
        egress timestamp and offset to the correction field.

        @steps:
        1. Apply basic PTP configuration with correction action correction_plus_timestamp_plus_offset with
        some offset value.
        2. For all PTP packet types send the packet with some correction field value on Felicity.
        3. Dump packets on Felicity side, make sure that correction was changed and equals to original value
        plus offset plus egress timestamp.

        @result: Correction was changed.
        @duration: 1 second.
        """

        cor_offset = 0xffaf
        eps = 600000000  # 600 milliseconds epsilon
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.cor_offset = cor_offset << 16
        for k in ptc.ieee1588v2_cor_act.keys():
            ptc.ieee1588v2_cor_act[k] = PtpTimestampingEgressEnableConfig.COR_ACT_CORRECTION_PLUS_TIMESTAMP_PLUS_OFFSET
        ptc.apply(self.pa)

        time.sleep(1)

        correction_before = 10000000000

        clock_before = self.read_ptp_clock()
        correction_after = self.send_packet_and_get_new_correction(PtpV2SyncHeader(correction=correction_before))
        self.assertTrue(correction_before + clock_before + cor_offset - eps < correction_after)
        self.assertTrue(correction_after < correction_before + clock_before + cor_offset + eps)

        clock_before = self.read_ptp_clock()
        correction_after = self.send_packet_and_get_new_correction(
            PtpV2DelayRequestHeader(correction=correction_before))
        self.assertTrue(correction_before + clock_before + cor_offset - eps < correction_after)
        self.assertTrue(correction_after < correction_before + clock_before + cor_offset + eps)

        clock_before = self.read_ptp_clock()
        correction_after = self.send_packet_and_get_new_correction(
            PtpV2PathDelayRequestHeader(correction=correction_before))
        self.assertTrue(correction_before + clock_before + cor_offset - eps < correction_after)
        self.assertTrue(correction_after < correction_before + clock_before + cor_offset + eps)

        clock_before = self.read_ptp_clock()
        correction_after = self.send_packet_and_get_new_correction(
            PtpV2PathDelayResponseHeader(correction=correction_before))
        self.assertTrue(correction_before + clock_before + cor_offset - eps < correction_after)
        self.assertTrue(correction_after < correction_before + clock_before + cor_offset + eps)

        clock_before = self.read_ptp_clock()
        correction_after = self.send_packet_and_get_new_correction(
            PtpV2SyncHeader(message_id=0xd, correction=correction_before))  # but user defined message id
        self.assertTrue(correction_before + clock_before + cor_offset - eps < correction_after)
        self.assertTrue(correction_after < correction_before + clock_before + cor_offset + eps)

    # def test_egress_cor_action_correction_minus_timestamp_plus_offset_for_all_packets(self):
    #     # TODO: this test is not finished!!!
    #     cor_offset = 0
    #     eps = 600000000  # 600 milliseconds epsilon
    #     ptc = PtpTimestampingEgressEnableConfig()
    #     ptc.cor_offset = cor_offset << 16
    #     for k in ptc.ieee1588v2_cor_act.keys():
    #         ptc.ieee1588v2_cor_act[k] = \
    #             PtpTimestampingEgressEnableConfig.COR_ACT_CORRECTION_MINUS_TIMESTAMP_PLUS_OFFSET
    #     ptc.apply(self.pa)7

    #     time.sleep(1)

    #     clock_before = self.read_ptp_clock()
    #     correction_before = clock_before
    #     # correction_before = 0
    #     correction_after = self.send_packet_and_get_new_correction(PtpV2SyncHeader(correction=correction_before))
    #     print correction_before - clock_before + cor_offset - eps < correction_after
    #     print correction_after < correction_before - clock_before + cor_offset + eps
    #     print "clock_before                   ", clock_before
    #     print "correction_before              ", correction_before
    #     print "correction_after               ", correction_after
    #     print "correction_after - cor_offset  ", correction_after - cor_offset
    #     print "correction_after - clock_before", correction_after - clock_before
    #     self.assertTrue(correction_before - clock_before + cor_offset - eps < correction_after)
    #     self.assertTrue(correction_after < correction_before - clock_before + cor_offset + eps)


class TestPhyPtpIngressCorrectionAction(TestPhyPtpBase):
    """
     @description: The PHY PTP ingress correction action test group is dedicated to verify correction actor.

     @setup: Felicity <-> PHY (Europa, Calypso, Rhea) <-> LilNikki
     """

    def setUp(self):
        super(TestPhyPtpIngressCorrectionAction, self).setUp()
        self.phy_basic_config(speed=LINK_SPEED_1G)

    def send_packet_and_get_new_correction(self, l3_header):
        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)
        packet = eth / l3_header
        ctx = self.begin_capture(2, "cap.pcap", filter="ether proto 0x88f7")
        self.send_packet(packet, host=self.LKP_HOSTNAME)
        packets = self.end_capture(ctx)
        self.assertEqual(1, len(packets))
        return packets[0][1].correction

    def send_packet_and_get_new_correction_loopback(self, l3_header):
        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)
        packet = eth / l3_header
        ctx = self.begin_capture(2, "cap.pcap", filter="ether proto 0x88f7")
        self.send_packet(packet)
        packets = self.end_capture(ctx)
        self.assertEqual(2, len(packets))
        return packets[1][1].correction

    def test_ingress_cor_action_no_change_for_all_packets(self):
        """
        @description: This subtest verifies that ingress correction action no change doesnt modify correction field.

        @steps:
        1. Apply basic PTP configuration with correction action no change.
        2. For all PTP packet types send the packet with some correction field value from LilNikki to Felicity.
        3. Dump packets on Felicity side, make sure that correction was not changed.

        @result: Correction was not changed.
        @duration: 1 second.
        """

        ptc = PtpTimestampingIngressEnableConfig()
        for k in ptc.ieee1588v2_cor_act.keys():
            ptc.ieee1588v2_cor_act[k] = PtpTimestampingIngressEnableConfig.COR_ACT_NO_CHANGE
        ptc.apply(self.pa)

        time.sleep(1)

        correction_before = 4321

        correction_after = self.send_packet_and_get_new_correction(PtpV2SyncHeader(correction=correction_before))
        self.assertEqual(correction_before, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2DelayRequestHeader(correction=correction_before))
        self.assertEqual(correction_before, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2PathDelayRequestHeader(correction=correction_before))
        self.assertEqual(correction_before, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2PathDelayResponseHeader(correction=correction_before))
        self.assertEqual(correction_before, correction_after)

        correction_after = self.send_packet_and_get_new_correction(
            PtpV2SyncHeader(message_id=0xd, correction=correction_before))  # but user defined message id
        self.assertEqual(correction_before, correction_after)

    # def test_egress_cor_action_correction_plus_ts_minus_appendts_plus_offset_for_all_packets(self):
    #     # TODO: this test is not finished!!!
    #     cor_offset = 0
    #     eps = 600000000  # 600 milliseconds epsilon
    #     ptc = PtpTimestampingEgressEnableConfig()
    #     for k in ptc.ieee1588v2_ts_act.keys():
    #         ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_APPEND
    #     ptc.apply(self.pa)
    #     # ptc = PtpTimestampingIngressEnableConfig()
    #     # ptc.cor_offset = cor_offset << 16
    #     # for k in ptc.ieee1588v2_cor_act.keys():
    #     #     ptc.ieee1588v2_cor_act[k] = \
    #     #         PtpTimestampingIngressEnableConfig.COR_ACT_CORRECTION_PLUS_TIMESTAMP_MINUS_TIMESTAMPAPPEND_PLUS_OFFSET
    #     # ptc.apply(self.pa)

    #     time.sleep(1)

    #     correction_before = 0x0

    #     clock_before = self.read_ptp_clock()
    #     print "!!! clock_before", clock_before
    #     sync = PtpV2SyncHeader(origin_timestamp=10, correction=correction_before)
    #     # timestamp_append = [0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    #     # sync.data += timestamp_append
    #     # sync.message_length += len(timestamp_append)
    #     correction_after = self.send_packet_and_get_new_correction_loopback(sync)
    #     print "!!! correction_after", correction_after
    #     print "!!! correction_after - clock_before", correction_after - clock_before


class TestPhyPtpTimestampOffset(TestPhyPtpBase):
    """
     @description: The PHY PTP timestamp offset test group is dedicated to verify timestamp offset modificator.

     @setup: Felicity <-> PHY (Europa, Calypso, Rhea) with Net_Side-SIF_facing_loopback
     """

    # These tests must be executed on loopback!

    def setUp(self):
        super(TestPhyPtpTimestampOffset, self).setUp()

    def get_avg_ts_diff(self, times=20):
        eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)
        packet = eth / PtpV2SyncHeader()

        diffs = []
        for i in range(20):
            self.send_packet(packet)
            _, egress_ts = self.extract_egress_ts(poll=True)
            _, ingress_ts = self.extract_ingress_ts(poll=True)
            diffs.append(ingress_ts - egress_ts)
        return sum(diffs) / float(len(diffs))

    def phy_basic_config(self, speed, egr_ts_ns_offset, egr_ts_offset_sign, ing_ts_ns_offset, ing_ts_offset_sign):
        pc = PtpConfig(speed=speed)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.pkt_ifg_threshold = 0x7
        ptc.ts_ns_offset = egr_ts_ns_offset
        ptc.ts_offset_sign = egr_ts_offset_sign
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.pkt_ifg_threshold = 0x7
        ptc.ts_ns_offset = ing_ts_ns_offset
        ptc.ts_offset_sign = ing_ts_offset_sign
        ptc.apply(self.pa)

        time.sleep(1)

    def test_egress_timestamp_plus_offset_without_overflow(self):
        """
        @description: This subtest verifies that egress timestamp offset with positive sign works correctly.

        @steps:
        1. Apply basic PTP configuration with positive offset for both egress and ingress, but offset value is 0.
        2. In the loop many times send PTP packet, calculate average round trip value.
        3. Apply basic PTP configuration with positive offset for both egress and ingress, egress offset
        is not zero, ingress offset is zero.
        4. In the loop many times send PTP packet, calculate average round trip value.
        5. Compare average roundtrip values, make sure that average rt value with offset plus offset is almost equal
        to average rt value without offset.

        @result: Egress offset is applied.
        @duration: 1 second.
        """

        eps = 5

        self.phy_basic_config(self.LINK_SPEED,
                              0, PtpTimestampingEgressEnableConfig.OFFSET_ACT_ADD,
                              0, PtpTimestampingIngressEnableConfig.OFFSET_ACT_ADD)

        avg_diff_without_offset = self.get_avg_ts_diff()

        egress_ts_offset = 30000
        self.phy_basic_config(self.LINK_SPEED,
                              egress_ts_offset, PtpTimestampingEgressEnableConfig.OFFSET_ACT_ADD,
                              0, PtpTimestampingIngressEnableConfig.OFFSET_ACT_ADD)

        avg_diff_with_offset = self.get_avg_ts_diff()

        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset < 0)
        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset + egress_ts_offset > -eps)
        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset + egress_ts_offset < eps)

    def test_egress_timestamp_minus_offset_without_overflow(self):
        """
        @description: This subtest verifies that egress timestamp offset with negative sign works correctly.

        @steps:
        1. Apply basic PTP configuration with positive offset for both egress and ingress, but offset value is 0.
        2. In the loop many times send PTP packet, calculate average round trip value.
        3. Apply basic PTP configuration with negative offset for both egress and ingress, egress offset
        is not zero, ingress offset is zero.
        4. In the loop many times send PTP packet, calculate average round trip value.
        5. Compare average roundtrip values, make sure that average rt value with offset minus offset is almost equal
        to average rt value without offset.

        @result: Egress offset is applied.
        @duration: 1 second.
        """

        eps = 5

        self.phy_basic_config(self.LINK_SPEED,
                              0, PtpTimestampingEgressEnableConfig.OFFSET_ACT_ADD,
                              0, PtpTimestampingIngressEnableConfig.OFFSET_ACT_ADD)

        avg_diff_without_offset = self.get_avg_ts_diff()

        egress_ts_offset = 20000
        self.phy_basic_config(self.LINK_SPEED,
                              egress_ts_offset, PtpTimestampingEgressEnableConfig.OFFSET_ACT_SUBTRACT,
                              0, PtpTimestampingIngressEnableConfig.OFFSET_ACT_ADD)

        avg_diff_with_offset = self.get_avg_ts_diff()

        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset > 0)
        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset - egress_ts_offset > -eps)
        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset - egress_ts_offset < eps)

    def test_ingress_timestamp_plus_offset_without_overflow(self):
        """
        @description: This subtest verifies that ingress timestamp offset with positive sign works correctly.

        @steps:
        1. Apply basic PTP configuration with positive offset for both egress and ingress, but offset value is 0.
        2. In the loop many times send PTP packet, calculate average round trip value.
        3. Apply basic PTP configuration with positive offset for both egress and ingress, egress offset
        is zero, ingress offset is not zero.
        4. In the loop many times send PTP packet, calculate average round trip value.
        5. Compare average roundtrip values, make sure that average rt value with offset minus offset is almost equal
        to average rt value without offset.

        @result: Egress offset is applied.
        @duration: 1 second.
        """

        eps = 5

        self.phy_basic_config(self.LINK_SPEED,
                              0, PtpTimestampingEgressEnableConfig.OFFSET_ACT_ADD,
                              0, PtpTimestampingIngressEnableConfig.OFFSET_ACT_ADD)

        avg_diff_without_offset = self.get_avg_ts_diff()

        ingress_ts_offset = 30000
        self.phy_basic_config(self.LINK_SPEED,
                              0, PtpTimestampingEgressEnableConfig.OFFSET_ACT_ADD,
                              ingress_ts_offset, PtpTimestampingIngressEnableConfig.OFFSET_ACT_ADD)

        avg_diff_with_offset = self.get_avg_ts_diff()

        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset > 0)
        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset - ingress_ts_offset > -eps)
        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset - ingress_ts_offset < eps)

    def test_ingress_timestamp_minus_offset_without_overflow(self):
        """
        @description: This subtest verifies that ingress timestamp offset with negative sign works correctly.

        @steps:
        1. Apply basic PTP configuration with positive offset for both egress and ingress, but offset value is 0.
        2. In the loop many times send PTP packet, calculate average round trip value.
        3. Apply basic PTP configuration with negative offset for both egress and ingress, egress offset
        is zero, ingress offset is not zero.
        4. In the loop many times send PTP packet, calculate average round trip value.
        5. Compare average roundtrip values, make sure that average rt value with offset plus offset is almost equal
        to average rt value without offset.

        @result: Egress offset is applied.
        @duration: 1 second.
        """

        eps = 5

        self.phy_basic_config(LINK_SPEED_1G,
                              0, PtpTimestampingEgressEnableConfig.OFFSET_ACT_ADD,
                              0, PtpTimestampingIngressEnableConfig.OFFSET_ACT_ADD)

        avg_diff_without_offset = self.get_avg_ts_diff()

        ingress_ts_offset = 20000
        self.phy_basic_config(LINK_SPEED_1G,
                              0, PtpTimestampingEgressEnableConfig.OFFSET_ACT_ADD,
                              ingress_ts_offset, PtpTimestampingIngressEnableConfig.OFFSET_ACT_SUBTRACT)

        avg_diff_with_offset = self.get_avg_ts_diff()

        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset < 0)
        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset + ingress_ts_offset > -eps)
        self.assertTrue(avg_diff_with_offset - avg_diff_without_offset + ingress_ts_offset < eps)


class TestPhyPtpEuropaIssues(TestPhyPtpBase):
    def setUp(self):
        super(TestPhyPtpEuropaIssues, self).setUp()

    def phy_basic_config(self, speed):
        pc = PtpConfig(speed=speed)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        ptc.apply(self.pa)

        time.sleep(1)

    def analyse_egr_ing_ts_in_cap_file(self, _file):
        egress_ts = []
        ingress_ts = []

        packets = read_pcap(_file)
        for p in packets:
            if len(p) == 92:
                sec = p[68] << 40 | p[69] << 32 | p[70] << 24 | p[71] << 16 | p[72] << 8 | p[73]
                ns = p[74] << 24 | p[75] << 16 | p[76] << 8 | p[77]
                egr_ts = sec * 1000000000 + ns
                egress_ts.append(egr_ts)
                sec = p[80] << 40 | p[81] << 32 | p[82] << 24 | p[83] << 16 | p[84] << 8 | p[85]
                ns = p[86] << 24 | p[87] << 16 | p[88] << 8 | p[89]
                ing_ts = sec * 1000000000 + ns
                ingress_ts.append(ing_ts)

        assert len(egress_ts) == len(ingress_ts)

        # Self protection against bug
        if ingress_ts[0] - egress_ts[0] < 0:
            egress_ts = egress_ts[:-1]
            ingress_ts = ingress_ts[1:]
        if ingress_ts[0] - egress_ts[0] < 0:
            raise Exception("Something goes wrong")

        return egress_ts, ingress_ts

    # def test_ololo(self):
    #     pc = PtpConfig(speed=LINK_SPEED_1G)
    #     pc.apply(self.pa)
    #     cfg = PtpFiltersEgressEnableConfig()
    #     cfg.apply(self.pa)
    #     cfg = PtpFiltersIngressEnableConfig()
    #     cfg.apply(self.pa)
    #     ptc = PtpTimestampingEgressEnableConfig()
    #     for k in ptc.ieee1588v2_ts_act.keys():
    #         ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_APPEND
    #     ptc.apply(self.pa)
    #     ptc = PtpTimestampingIngressEnableConfig()
    #     for k in ptc.ieee1588v2_ts_act.keys():
    #         ptc.ieee1588v2_ts_act[k] = PtpTimestampingIngressEnableConfig.TS_ACT_REMOVE
    #     ptc.apply(self.pa)

    #     time.sleep(1)

    #     eth = EthernetHeader(dst=self.DST_MAC_IEEE_1588_1, src=self.SRC_MAC, type=self.PTP_ETH_TYPE)
    #     ptp = PtpV2SyncHeader(origin_timestamp=0xaabb)
    #     self.send_packet(eth / ptp)

    # def test_roundtrip_with_background_traffic(self):
    #     exec_time = 10
    #     cap_file = "cap.pcap"

    #     # pc = PtpConfig(speed=LINK_SPEED_1G)
    #     # pc.apply(self.pa)
    #     # cfg = PtpFiltersEgressEnableConfig()
    #     # cfg.apply(self.pa)
    #     # cfg = PtpFiltersIngressEnableConfig()
    #     # cfg.apply(self.pa)
    #     # ptc = PtpTimestampingEgressEnableConfig()
    #     # ptc.ieee1588v2_ts_act = {
    #     #     "sync": PtpTimestampingEgressEnableConfig.TS_ACT_APPEND,
    #     #     "delay": PtpTimestampingEgressEnableConfig.TS_ACT_APPEND,
    #     #     "pdelay": PtpTimestampingEgressEnableConfig.TS_ACT_APPEND,
    #     #     "presp": PtpTimestampingEgressEnableConfig.TS_ACT_APPEND,
    #     #     "user": PtpTimestampingEgressEnableConfig.TS_ACT_APPEND,
    #     # }
    #     # ptc.apply(self.pa)
    #     # ptc = PtpTimestampingIngressEnableConfig()
    #     # ptc.apply(self.pa)

    #     cap_proc = self.capture(_time=exec_time + 5, file=cap_file, filter="ether proto 0x88f7")
    #     # cap_proc = self.capture(_time=exec_time + 5, file=cap_file)
    #     time.sleep(1)
    #     send_proc = self.send_upd_background_traffic(pkt_size=1000, _time=exec_time)

    #     cmd = "aqsendp " + self.DST_MAC_IEEE_1588_0 + self.SRC_MAC + \
    #         "%04x" % (self.PTP_ETH_TYPE) + self.PATH_DELAY_RESPONSE_PAYLOAD
    #     while send_proc.poll() is None:
    #         os.system("aqsendp 011B190000000017b648258a88f703020036000002000000000000000000000000000017b6fffe5758590001014e057f00005b854d1229c4ac5b0017b6fffe3016180001")
    #         self.pa.readphyreg(0x3, 0xec09)
    #         self.pa.readphyreg(0x3, 0xec09)

    #     time.sleep(1)
    #     os.system("aqsendp 011B190000000017b648258a88f703020036000002000000000000000000000000000017b6fffe5758590001014e057f00005b854d1229c4ac5b0017b6fffe3016180001")
    #     os.system("aqsendp 011B190000000017b648258a88f703020036000002000000000000000000000000000017b6fffe5758590001014e057f00005b854d1229c4ac5b0017b6fffe3016180001")
    #     os.system("aqsendp 011B190000000017b648258a88f703020036000002000000000000000000000000000017b6fffe5758590001014e057f00005b854d1229c4ac5b0017b6fffe3016180001")

    #     while cap_proc.poll() is None:
    #         print "Waiting fop capture process ready"
    #         time.sleep(1)

    #     # min_roundtrip, max_roundtrip = self.analyse_egr_ing_ts_in_cap_file(_file=cap_file)
    #     # variation = max_roundtrip - min_roundtrip
    #     # print "MIN roundtrip = %d, MAX roundtrip = %d, VARIATION = %d" % (min_roundtrip, max_roundtrip, variation)

    # def test_roundtrip_with_background_traffic(self):
        # exec_time = 10

        # pc = PtpConfig(speed=LINK_SPEED_1G)
        # pc.apply(self.pa)
        # cfg = PtpFiltersEgressEnableConfig()
        # cfg.apply(self.pa)
        # cfg = PtpFiltersIngressEnableConfig()
        # cfg.apply(self.pa)
        # ptc = PtpTimestampingEgressEnableConfig()
        # for k in ptc.ieee1588v2_ts_act.keys():
        #     ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_NONE
        # ptc.apply(self.pa)
        # ptc = PtpTimestampingIngressEnableConfig()
        # for k in ptc.ieee1588v2_ts_act.keys():
        #     ptc.ieee1588v2_ts_act[k] = PtpTimestampingIngressEnableConfig.TS_ACT_NONE
        # ptc.apply(self.pa)

        # time.sleep(1)
        # send_proc = self.send_upd_background_traffic(pkt_size=1000, _time=exec_time)

        # while send_proc.poll() is None:
        #     self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
        #                         self.PATH_DELAY_RESPONSE_PAYLOAD)
        #     egr_stream_id, egr_ts = self.extract_egress_ts()
        #     ing_stream_id, ing_ts = self.extract_ingress_ts()

        # time.sleep(1)
        # os.system("aqsendp 011B190000000017b648258a88f703020036000002000000000000000000000000000017b6fffe5758590001014e057f00005b854d1229c4ac5b0017b6fffe3016180001")
        # os.system("aqsendp 011B190000000017b648258a88f703020036000002000000000000000000000000000017b6fffe5758590001014e057f00005b854d1229c4ac5b0017b6fffe3016180001")
        # os.system("aqsendp 011B190000000017b648258a88f703020036000002000000000000000000000000000017b6fffe5758590001014e057f00005b854d1229c4ac5b0017b6fffe3016180001")

        # while cap_proc.poll() is None:
        #     print "Waiting fop capture process ready"
        #     time.sleep(1)

        # self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
        #                     self.PATH_DELAY_RESPONSE_PAYLOAD)

        # while True:
        #     egr_stream_id, egr_ts = self.extract_egress_ts()
        #     if egr_ts == 0:
        #         break
        # while True:
        #     ing_stream_id, ing_ts = self.extract_ingress_ts()
        #     if ing_ts == 0:
        #         break

        # time.sleep(2)

    # def test_extract_ts(self):
    #     self.phy_basic_config(LINK_SPEED_1G)
    #     self.reset_egress_ptp_fifo()
    #     self.reset_ingress_ptp_fifo()

    #     os.system("aqsendp 0180c200000e0017b648258a88f703020036000002000000000000000000000000000017b6fffe5758590001014e057f00005b854d1229c4ac5b0017b6fffe3016180001")
    #     self.pa.readphyreg(0x3, 0xc934)  # egress ts count
    #     self.pa.readphyreg(0x3, 0xe904)  # ingress ts count
    #     self.pa.readphyreg(0x3, 0xcc06)  # egress alarms
    #     self.pa.readphyreg(0x3, 0xec09)  # ingress alarms
    #     egr_stream_id, egr_ts = self.extract_egress_ts(poll=False)
    #     ing_stream_id, ing_ts = self.extract_ingress_ts(poll=False)
    #     print egr_ts, ing_ts

    # def run_test_roundtrip_with_background_traffic(self, pkt_size, exec_time, max_rt, max_var):
    #     pc = PtpConfig(speed=LINK_SPEED_1G)
    #     pc.apply(self.pa)
    #     cfg = PtpFiltersEgressEnableConfig()
    #     cfg.apply(self.pa)
    #     cfg = PtpFiltersIngressEnableConfig()
    #     cfg.apply(self.pa)
    #     ptc = PtpTimestampingEgressEnableConfig()
    #     ptc.apply(self.pa)
    #     ptc = PtpTimestampingIngressEnableConfig()
    #     ptc.apply(self.pa)

    #     time.sleep(2)

    #     egress_ts = []
    #     ingress_ts = []

    #     self.cleanup_ts()
    #     time.sleep(5)

    #     send_proc = self.send_upd_background_traffic(pkt_size=pkt_size, _time=exec_time)

    #     max_nof_ptp = 10
    #     nof_ptp = 0
    #     while send_proc.poll() is None and nof_ptp < max_nof_ptp:
    #         self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
    #                             self.PATH_DELAY_RESPONSE_PAYLOAD)

    #         try:
    #             egr_stream_id, egr_ts = self.extract_egress_ts(poll=True, timeout=1)
    #             ing_stream_id, ing_ts = self.extract_ingress_ts(poll=True, timeout=1)

    #             egress_ts.append(egr_ts)
    #             ingress_ts.append(ing_ts)
    #             nof_ptp += 1
    #         except Exception:
    #             pass

    #     print "Egress timestamps:", egress_ts
    #     print "Ingress timestamps:", ingress_ts

    #     round_trips = [ingress_ts[i] - egress_ts[i] for i in range(len(egress_ts))]

    #     print "Roundrips:", round_trips
    #     var = max(round_trips) - min(round_trips)
    #     print "Min roundtrip", min(round_trips)
    #     print "Max roundtrip", max(round_trips)
    #     print "Roundtrip variation", var

    #     for i in range(len(egress_ts)):
    #         self.assertTrue(egress_ts[i] > 0, "Egress timestamp should be positive: %d" % (egress_ts[i]))
    #         self.assertTrue(ingress_ts[i] > 0, "Ingress timestamp should be positive: %d" % (ingress_ts[i]))
    #     for rt in round_trips:
    #         self.assertTrue(rt > 0)
    #         self.assertTrue(rt < max_rt, "Too big roundtrip: %d" % (rt))
    #     self.assertTrue(var < max_var, "Too big roundtrip variation: %d" % (var))

    # def test_roundtrip_with_background_traffic_125b(self):
    #     self.run_test_roundtrip_with_background_traffic(125, 30, 2000, 200)

    # def test_roundtrip_with_background_traffic_250b(self):
    #     self.run_test_roundtrip_with_background_traffic(250, 30, 3000, 500)

    # def test_roundtrip_with_background_traffic_500b(self):
    #     self.run_test_roundtrip_with_background_traffic(500, 30, 5000, 2000)

    # def test_roundtrip_with_background_traffic_1000b(self):
    #     self.run_test_roundtrip_with_background_traffic(1000, 30, 8000, 3000)

    # def test_roundtrip_with_background_traffic_1200b(self):
    #     self.run_test_roundtrip_with_background_traffic(1200, 5, 8000, 3000)

    # def test_roundtrip_with_background_traffic_1400b(self):
    #     self.run_test_roundtrip_with_background_traffic(1400, 30, 8000, 3000)

    # def test_roundtrip_with_background_traffic_using_fifo(self):
    #     pkt_size = 1400
    #     exec_time = 10

    #     pc = PtpConfig(speed=LINK_SPEED_1G)
    #     pc.apply(self.pa)
    #     cfg = PtpFiltersEgressEnableConfig()
    #     cfg.apply(self.pa)
    #     cfg = PtpFiltersIngressEnableConfig()
    #     cfg.apply(self.pa)
    #     ptc = PtpTimestampingEgressEnableConfig()
    #     for k in ptc.ieee1588v2_ts_act.keys():
    #         ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_NONE
    #     ptc.apply(self.pa)
    #     ptc = PtpTimestampingIngressEnableConfig()
    #     for k in ptc.ieee1588v2_ts_act.keys():
    #         ptc.ieee1588v2_ts_act[k] = PtpTimestampingIngressEnableConfig.TS_ACT_NONE
    #     ptc.apply(self.pa)

    #     time.sleep(1)

    #     egress_ts = []
    #     ingress_ts = []

    #     send_proc = self.send_upd_background_traffic(pkt_size=pkt_size, _time=exec_time)
    #     time.sleep(1)

    #     while send_proc.poll() is None:
    #         self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
    #                             self.PATH_DELAY_RESPONSE_PAYLOAD)

    #         egr_stream_id, egr_ts = self.extract_egress_ts(poll=True)
    #         ing_stream_id, ing_ts = self.extract_ingress_ts(poll=True)

    #         egress_ts.append(egr_ts)
    #         ingress_ts.append(ing_ts)

    #     print "Egress timestamps:", egress_ts
    #     print "Ingress timestamps:", ingress_ts

    #     round_trips = [ingress_ts[i] - egress_ts[i] for i in range(len(egress_ts))]

    #     print "Roundrips:", round_trips
    #     print "Roundtrip variation", max(round_trips) - min(round_trips)

    #     for i in range(len(egress_ts)):
    #         self.assertTrue(egress_ts[i] > 0, "Timestamp should be positive")
    #         self.assertTrue(ingress_ts[i] > 0, "Timestamp should be positive")
    #     for rt in round_trips:
    #         self.assertTrue(rt > 0)
    #     self.assertTrue(max(round_trips) - min(round_trips) < 20, "Too big roundtrip variation")

    # def test_roundtrip_without_background_traffic_using_fifo(self):
    #     pc = PtpConfig(speed=LINK_SPEED_1G)
    #     pc.apply(self.pa)
    #     cfg = PtpFiltersEgressEnableConfig()
    #     cfg.apply(self.pa)
    #     cfg = PtpFiltersIngressEnableConfig()
    #     cfg.apply(self.pa)
    #     ptc = PtpTimestampingEgressEnableConfig()
    #     for k in ptc.ieee1588v2_ts_act.keys():
    #         ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_NONE
    #     ptc.apply(self.pa)
    #     ptc = PtpTimestampingIngressEnableConfig()
    #     for k in ptc.ieee1588v2_ts_act.keys():
    #         ptc.ieee1588v2_ts_act[k] = PtpTimestampingIngressEnableConfig.TS_ACT_NONE
    #     ptc.apply(self.pa)

    #     time.sleep(1)

    #     egress_ts = []
    #     ingress_ts = []

    #     for i in range(100):
    #         self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
    #                             self.PATH_DELAY_RESPONSE_PAYLOAD)

    #         egr_stream_id, egr_ts = self.extract_egress_ts(poll=True)
    #         ing_stream_id, ing_ts = self.extract_ingress_ts(poll=True)

    #         egress_ts.append(egr_ts)
    #         ingress_ts.append(ing_ts)

    #     print "Egress timestamps:", egress_ts
    #     print "Ingress timestamps:", ingress_ts

    #     round_trips = [ingress_ts[i] - egress_ts[i] for i in range(len(egress_ts))]

    #     print "Roundrips:", round_trips
    #     print "Roundtrip variation", max(round_trips) - min(round_trips)

    #     for i in range(len(egress_ts)):
    #         self.assertTrue(egress_ts[i] > 0, "Timestamp should be positive")
    #         self.assertTrue(ingress_ts[i] > 0, "Timestamp should be positive")
    #     for rt in round_trips:
    #         self.assertTrue(rt > 0)
    #     self.assertTrue(max(round_trips) - min(round_trips) < 20, "Too big roundtrip variation")

    # def test_roundtrip_with_background_traffic_using_pcap(self):
    #     exec_time = 10
    #     cap_file = "cap.pcap"
    #     pkt_size = 100

    #     pc = PtpConfig(speed=LINK_SPEED_1G)
    #     pc.apply(self.pa)
    #     cfg = PtpFiltersEgressEnableConfig()
    #     cfg.apply(self.pa)
    #     cfg = PtpFiltersIngressEnableConfig()
    #     cfg.apply(self.pa)
    #     ptc = PtpTimestampingEgressEnableConfig()
    #     for k in ptc.ieee1588v2_ts_act.keys():
    #         ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_APPEND
    #     ptc.apply(self.pa)
    #     ptc = PtpTimestampingIngressEnableConfig()
    #     for k in ptc.ieee1588v2_ts_act.keys():
    #         ptc.ieee1588v2_ts_act[k] = PtpTimestampingIngressEnableConfig.TS_ACT_APPEND
    #     ptc.apply(self.pa)

    #     send_proc = self.send_upd_background_traffic(pkt_size=pkt_size, _time=exec_time)
    #     time.sleep(1)
    #     ctx = self.begin_capture(exec_time - 2, cap_file, filter="ether proto 0x88f7")

    #     while ctx["proc"].poll() is None:
    #         self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
    #                             self.PATH_DELAY_RESPONSE_PAYLOAD)
    #         time.sleep(0.01)

    #     while send_proc.poll() is None:
    #         print "Waiting for background traffic stop"
    #         time.sleep(1)

    #     egress_ts = []
    #     ingress_ts = []
    #     packets = self.end_capture(ctx)
    #     for p in packets:
    #         if len(p) not in [68, 92]:
    #             raise Exception("Invalid packet length %d" % (len(p)))
    #         if len(p) == 92:
    #             egress_ts.append(p[1].ts_2)
    #             ingress_ts.append(p[1].ts_1)

    #     roundtrips = []
    #     for i in range(50):
    #         roundtrips.append(ingress_ts[i] - egress_ts[i])

    #     print "Min roundtrip", min(roundtrips)
    #     print "Max roundtrip", max(roundtrips)
    #     var = max(roundtrips) - min(roundtrips)
    #     print "Variation", var
    #     self.assertTrue(var < 20, "Too big roundtrip variation: %d" % (var))

    # def test_roundtrip_without_background_traffic_using_pcap(self):
    #     exec_time = 10
    #     cap_file = "cap.pcap"

    #     pc = PtpConfig(speed=LINK_SPEED_1G)
    #     pc.apply(self.pa)
    #     cfg = PtpFiltersEgressEnableConfig()
    #     cfg.apply(self.pa)
    #     cfg = PtpFiltersIngressEnableConfig()
    #     cfg.apply(self.pa)
    #     ptc = PtpTimestampingEgressEnableConfig()
    #     for k in ptc.ieee1588v2_ts_act.keys():
    #         ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_APPEND
    #     ptc.apply(self.pa)
    #     ptc = PtpTimestampingIngressEnableConfig()
    #     for k in ptc.ieee1588v2_ts_act.keys():
    #         ptc.ieee1588v2_ts_act[k] = PtpTimestampingIngressEnableConfig.TS_ACT_APPEND
    #     ptc.apply(self.pa)

    #     ctx = self.begin_capture(exec_time, cap_file, filter="ether proto 0x88f7")

    #     nof_sent_packets = 0
    #     while ctx["proc"].poll() is None:
    #         # self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
    #         #                     self.PATH_DELAY_RESPONSE_PAYLOAD)
    #         os.system("aqsendp 0180c200000e0017b648258a88f703020036000002000000000000000000000000000017b6fffe5758590001014e057f00005b854d1229c4ac5b0017b6fffe3016180001")
    #         nof_sent_packets += 1

    #     egress_ts = []
    #     ingress_ts = []
    #     packets = self.end_capture(ctx)
    #     for p in packets:
    #         if len(p) not in [68, 92]:
    #             raise Exception("Invalid packet length %d" % (len(p)))
    #         if len(p) == 92:
    #             egress_ts.append(p[1].ts_2)
    #             ingress_ts.append(p[1].ts_1)

    #     roundtrips = []
    #     for i in range(50):
    #         roundtrips.append(ingress_ts[i] - egress_ts[i])

    #     print "Min roundtrip", min(roundtrips)
    #     print "Max roundtrip", max(roundtrips)
    #     var = max(roundtrips) - min(roundtrips)
    #     print "Variation", var
    #     print "Nof sent packets", nof_sent_packets
    #     self.assertTrue(var < 20, "Too big roundtrip variation: %d" % (var))

    # def test_egress_ts_fifo_count(self):
    #     self.phy_basic_config()
    #     self.reset_egress_ptp_fifo()

    #     for nof_packets in range(16):

    #         for i in range(nof_packets):
    #             self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
    #                                 self.PATH_DELAY_RESPONSE_PAYLOAD)
    #             time.sleep(0.05)

    #         time.sleep(0.5)

    #         nof_ts_in_fifo = self.pa.readphyreg(0x3, 0xc934)
    #         self.assertEqual(nof_packets, nof_ts_in_fifo,
    #                          "Expected to have %d egress timestamps in FIFO, actual %d" %
    #                          (nof_packets, nof_ts_in_fifo))

    #         egr_timestamps = []
    #         for i in range(nof_ts_in_fifo):
    #             _, ts = self.extract_egress_ts(poll=False)
    #             egr_timestamps.append(ts)

    #         for i in range(1, len(egr_timestamps)):
    #             self.assertTrue(egr_timestamps[i] > egr_timestamps[i - 1])


class TestPhyPtpRoundtripFifo(TestPhyPtpBase):
    """
     @description: The PHY PTP roundtrip test group is dedicated to verify PTP packet roundtrip variation.

     @setup: Felicity <-> PHY (Europa, Calypso, Rhea) with Net_Side-SIF_facing_loopback
     """


    LINK_SPEED = LINK_SPEED_2_5G

    def setUp(self):
        super(TestPhyPtpRoundtripFifo, self).setUp()
        self.phy_basic_config(self.LINK_SPEED)

    def phy_basic_config(self, speed):
        pc = PtpConfig(speed=speed)
        pc.apply(self.pa)
        cfg = PtpFiltersEgressEnableConfig()
        cfg.apply(self.pa)
        cfg = PtpFiltersIngressEnableConfig()
        cfg.apply(self.pa)
        ptc = PtpTimestampingEgressEnableConfig()
        for k in ptc.ieee1588v2_ts_act.keys():
            ptc.ieee1588v2_ts_act[k] = PtpTimestampingEgressEnableConfig.TS_ACT_NONE
        ptc.apply(self.pa)
        ptc = PtpTimestampingIngressEnableConfig()
        for k in ptc.ieee1588v2_ts_act.keys():
            ptc.ieee1588v2_ts_act[k] = PtpTimestampingIngressEnableConfig.TS_ACT_NONE
        ptc.apply(self.pa)

        time.sleep(3)

    def get_roundtrips_without_bg_traffic(self, nof_checks=100):
        egress_ts = []
        ingress_ts = []

        for i in range(100):
            # Prepare path delay response packet and send it via Felicity
            self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
                                self.PATH_DELAY_RESPONSE_PAYLOAD)

            # Extract egress and ingress timestamps
            egr_stream_id, egr_ts = self.extract_egress_ts(poll=True)
            ing_stream_id, ing_ts = self.extract_ingress_ts(poll=True)

            # Put them to the array
            egress_ts.append(egr_ts)
            ingress_ts.append(ing_ts)

        # Calculate roundtrips for each packet
        round_trips = [ingress_ts[i] - egress_ts[i] for i in range(len(egress_ts))]
        print round_trips

        # Return data
        return egress_ts, ingress_ts, round_trips

    def get_roundtrips_with_bg_traffic(self, exec_time, pkt_size):
        egress_ts = []
        ingress_ts = []

        send_proc = self.send_upd_background_traffic(pkt_size=pkt_size, _time=exec_time)
        time.sleep(1)

        while send_proc.poll() is None:
            self.send_l2_packet(self.DST_MAC_IEEE_1588_1, self.SRC_MAC, self.PTP_ETH_TYPE,
                                self.PATH_DELAY_RESPONSE_PAYLOAD)

            egr_stream_id, egr_ts = self.extract_egress_ts(poll=True)
            ing_stream_id, ing_ts = self.extract_ingress_ts(poll=True)

            egress_ts.append(egr_ts)
            ingress_ts.append(ing_ts)

        round_trips = [ingress_ts[i] - egress_ts[i] for i in range(len(egress_ts))]
        print round_trips

        return egress_ts, ingress_ts, round_trips

    # def test_roundtrip_without_background_traffic_using_fifo(self):
    #     self.cleanup_ts()

    #     egress_ts, ingress_ts, round_trips = self.get_roundtrips_without_bg_traffic()
    #     print "Roundtrip variation", max(round_trips) - min(round_trips)

    #     for i in range(len(egress_ts)):
    #         self.assertTrue(egress_ts[i] > 0, "Timestamp should be positive")
    #         self.assertTrue(ingress_ts[i] > 0, "Timestamp should be positive")
    #     for rt in round_trips:
    #         self.assertTrue(rt > 0)
    #     self.assertTrue(max(round_trips) - min(round_trips) <= 40, "Too big roundtrip variation")

    # def test_roundtrip_without_background_traffic_using_fifo_sec_bypass_mss(self):
    #     cfg = SecEgressEnableConfig()
    #     cfg.bypass_mss = False
    #     cfg.bypass_parser = False
    #     cfg.apply(self.pa)

    #     cfg = SecIngressEnableConfig()
    #     cfg.bypass_mss = False
    #     cfg.bypass_parser = False
    #     cfg.apply(self.pa)

    #     time.sleep(3)

    #     egress_ts, ingress_ts, round_trips = self.get_roundtrips_without_bg_traffic()
    #     print "Roundtrip variation", max(round_trips) - min(round_trips)

    #     for i in range(len(egress_ts)):
    #         self.assertTrue(egress_ts[i] > 0, "Timestamp should be positive")
    #         self.assertTrue(ingress_ts[i] > 0, "Timestamp should be positive")
    #     for rt in round_trips:
    #         self.assertTrue(rt > 0)
    #     self.assertTrue(max(round_trips) - min(round_trips) < 20, "Too big roundtrip variation")

    # def test_roundtrip_with_background_traffic_using_fifo(self):
    #     # cfg = SecEgressEnableConfig()
    #     # cfg.bypass_mss = False
    #     # cfg.bypass_parser = False
    #     # cfg.apply(self.pa)

    #     # cfg = SecIngressEnableConfig()
    #     # cfg.bypass_mss = False
    #     # cfg.bypass_parser = False
    #     # cfg.apply(self.pa)

    #     # time.sleep(3)

    #     self.cleanup_ts()

    #     egress_ts, ingress_ts, round_trips = self.get_roundtrips_with_bg_traffic(10, 1400)
    #     print "Roundtrip variation", max(round_trips) - min(round_trips)

    #     for i in range(len(egress_ts)):
    #         self.assertTrue(egress_ts[i] > 0, "Timestamp should be positive")
    #         self.assertTrue(ingress_ts[i] > 0, "Timestamp should be positive")
    #     for rt in round_trips:
    #         self.assertTrue(rt > 0)
    #     self.assertTrue(max(round_trips) - min(round_trips) < 20, "Too big roundtrip variation")

    # def test_rt_var_without_bg_traffic_sgmii_100m(self):
    #     """
    #     @description: This subtest verifies PTP roundtrip variation without background traffic on 100M SGMII.

    #     @steps:
    #     1. Set 100M SGMII link, setup Net_Side-SIF_facing_loopback, apply basic PTP configuration.
    #     2. In the loop send PTP packets and extract egress and ingress timestamps.
    #     3. Calculate roundtrip variation, make sure it's <= 40 ns.

    #     @result: Roundtrip variation <= 40 ns.
    #     @duration: 1 second.
    #     """
    #     assert 1 == 1

    # def test_rt_var_without_bg_traffic_sgmii_1g(self):
    #     """
    #     @description: This subtest verifies PTP roundtrip variation without background traffic on 1G SGMII.

    #     @steps:
    #     1. Set 1G SGMII link, setup Net_Side-SIF_facing_loopback, apply basic PTP configuration.
    #     2. In the loop send PTP packets and extract egress and ingress timestamps.
    #     3. Calculate roundtrip variation, make sure it's <= 40 ns.

    #     @result: Roundtrip variation <= 40 ns.
    #     @duration: 1 second.
    #     """
    #     assert 1 == 1

    # def test_rt_var_without_bg_traffic_ocsgmii_2_5g(self):
    #     """
    #     @description: This subtest verifies PTP roundtrip variation without background traffic on 2.5G OCSGMII.

    #     @steps:
    #     1. Set 2.5G OCSGMII link, setup Net_Side-SIF_facing_loopback, apply basic PTP configuration.
    #     2. In the loop send PTP packets and extract egress and ingress timestamps.
    #     3. Calculate roundtrip variation, make sure it's <= 40 ns.

    #     @result: Roundtrip variation <= 40 ns.
    #     @duration: 1 second.
    #     """
    #     assert 1 == 1

    # def test_rt_var_without_bg_traffic_xfidiv2_5g(self):
    #     """
    #     @description: This subtest verifies PTP roundtrip variation without background traffic on 5G XFI/2.

    #     @steps:
    #     1. Set 5G XFI/2 link, setup Net_Side-SIF_facing_loopback, apply basic PTP configuration.
    #     2. In the loop send PTP packets and extract egress and ingress timestamps.
    #     3. Calculate roundtrip variation, make sure it's <= 40 ns.

    #     @result: Roundtrip variation <= 40 ns.
    #     @duration: 1 second.
    #     """
    #     assert 1 == 1

    # def test_rt_var_without_bg_traffic_xfi_10g(self):
    #     """
    #     @description: This subtest verifies PTP roundtrip variation without background traffic on 10G XFI.

    #     @steps:
    #     1. Set 10G XFI link, setup Net_Side-SIF_facing_loopback, apply basic PTP configuration.
    #     2. In the loop send PTP packets and extract egress and ingress timestamps.
    #     3. Calculate roundtrip variation, make sure it's <= 40 ns.

    #     @result: Roundtrip variation <= 40 ns.
    #     @duration: 1 second.
    #     """
    #     assert 1 == 1

    # def test_rt_var_with_bg_traffic_sgmii_100m(self):
    #     """
    #     @description: This subtest verifies PTP roundtrip variation with background traffic on 100M SGMII.

    #     @steps:
    #     1. Set 100M SGMII link, setup Net_Side-SIF_facing_loopback, apply basic PTP configuration.
    #     2. Send UDP 1400 byte length packets in the loop as fast as it's possible.
    #     3. In the loop send PTP packets and extract egress and ingress timestamps.
    #     4. Calculate roundtrip variation, make sure it's <= 40 ns.

    #     @result: Roundtrip variation <= 40 ns.
    #     @duration: 1 second.
    #     """
    #     assert 1 == 1

    # def test_rt_var_with_bg_traffic_sgmii_1g(self):
    #     """
    #     @description: This subtest verifies PTP roundtrip variation with background traffic on 1G SGMII.

    #     @steps:
    #     1. Set 1G SGMII link, setup Net_Side-SIF_facing_loopback, apply basic PTP configuration.
    #     2. Send UDP 1400 byte length packets in the loop as fast as it's possible.
    #     3. In the loop send PTP packets and extract egress and ingress timestamps.
    #     4. Calculate roundtrip variation, make sure it's <= 40 ns.

    #     @result: Roundtrip variation <= 40 ns.
    #     @duration: 1 second.
    #     """
    #     assert 1 == 1

    # def test_rt_var_with_bg_traffic_ocsgmii_2_5g(self):
    #     """
    #     @description: This subtest verifies PTP roundtrip variation with background traffic on 2.5G OCSGMII.

    #     @steps:
    #     1. Set 2.5G OCSGMII link, setup Net_Side-SIF_facing_loopback, apply basic PTP configuration.
    #     2. Send UDP 1400 byte length packets in the loop as fast as it's possible.
    #     3. In the loop send PTP packets and extract egress and ingress timestamps.
    #     4. Calculate roundtrip variation, make sure it's <= 40 ns.

    #     @result: Roundtrip variation <= 40 ns.
    #     @duration: 1 second.
    #     """
    #     assert 1 == 1

    # def test_rt_var_with_bg_traffic_xfidiv2_5g(self):
    #     """
    #     @description: This subtest verifies PTP roundtrip variation with background traffic on 5G XFI/2.

    #     @steps:
    #     1. Set 5G XFI/2 link, setup Net_Side-SIF_facing_loopback, apply basic PTP configuration.
    #     2. Send UDP 1400 byte length packets in the loop as fast as it's possible.
    #     3. In the loop send PTP packets and extract egress and ingress timestamps.
    #     4. Calculate roundtrip variation, make sure it's <= 40 ns.

    #     @result: Roundtrip variation <= 40 ns.
    #     @duration: 1 second.
    #     """
    #     assert 1 == 1

    # def test_rt_var_with_bg_traffic_xfi_10g(self):
    #     """
    #     @description: This subtest verifies PTP roundtrip variation with background traffic on 10G XFI.

    #     @steps:
    #     1. Set 10G XFI link, setup Net_Side-SIF_facing_loopback, apply basic PTP configuration.
    #     2. Send UDP 1400 byte length packets in the loop as fast as it's possible.
    #     3. In the loop send PTP packets and extract egress and ingress timestamps.
    #     4. Calculate roundtrip variation, make sure it's <= 40 ns.

    #     @result: Roundtrip variation <= 40 ns.
    #     @duration: 1 second.
    #     """
    #     assert 1 == 1

if __name__ == '__main__':
    unittest.main()
