# -*- encoding: utf-8 -*-
"""
Small module for use with the wake on lan protocol.
"""

from __future__ import absolute_import
from __future__ import unicode_literals

import argparse

import os
import logging
import logging.config
import socket
import struct
import sys
import traceback
import yaml

log = logging.getLogger("atf")
if len(log.handlers) == 0:
    fdir = os.path.dirname(os.path.abspath(__file__))
    log_cfg_file = os.path.join(fdir, "../tools/logging.conf")
    with open(log_cfg_file, "r") as f:
        log_cfg_data = yaml.load(f)
    logging.config.dictConfig(log_cfg_data)

SCRIPT_STATUS_SUCCESS = "[WOL-SUCCESS]"
SCRIPT_STATUS_FAILED = "[WOL-FAILED]"

BROADCAST_IP = '255.255.255.255'
DEFAULT_PORT = 9


def create_magic_packet(macaddress):
    """
    Create a magic packet which can be used for wake on lan using the
    mac address given as a parameter.

    Keyword arguments:
    :arg macaddress: the mac address that should be parsed into a magic
                     packet.

    """
    if len(macaddress) == 12:
        pass
    elif len(macaddress) == 17:
        sep = macaddress[2]
        macaddress = macaddress.replace(sep, '')
    else:
        raise ValueError('Incorrect MAC address format: {}'.format(macaddress))

    # Pad the synchronization stream
    data = b'FFFFFFFFFFFF' + (macaddress * 16).encode()
    send_data = b''

    # Split up the hex values in pack
    for i in range(0, len(data), 2):
        send_data += struct.pack(b'B', int(data[i: i + 2], 16))
    return send_data


def send_magic_packet(*macs, **kwargs):
    """
    Wakes the computer with the given mac address if wake on lan is
    enabled on that host.

    Keyword arguments:
    :arguments macs: One or more macaddresses of machines to wake.
    :key ip_address: the ip address of the host to send the magic packet
                     to (default "255.255.255.255")
    :key port: the port of the host to send the magic packet to
               (default 9)

    """
    packets = []
    ip = kwargs.pop('ip_address', BROADCAST_IP)
    port = kwargs.pop('port', DEFAULT_PORT)
    for k in kwargs:
        raise TypeError('send_magic_packet() got an unexpected keyword '
                        'argument {!r}'.format(k))

    for mac in macs:
        packet = create_magic_packet(mac)
        packets.append(packet)

    log.info("Connecting AF_INET socket to {} on port {}".format(ip, port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.connect((ip, port))
    for packet in packets:
        log.info("Packet data:\n{}".format(packet.encode("hex")))
        bytes_sent = sock.send(packet)
        log.info("Bytes sent: {}".format(bytes_sent))
    sock.close()


class WoLArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error("\n{}\n".format(SCRIPT_STATUS_FAILED))
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    try:
        parser = WoLArgumentParser()
        parser.add_argument("-m", "--mac", help="Destination MAC address",
                            type=str, required=True)
        parser.add_argument("-a", "--address", help="Distination IP address",
                            type=str, default=BROADCAST_IP)
        args = parser.parse_args()
    except Exception:
        log.exception("Failed to parse ping arguments")
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    try:
        send_magic_packet(args.mac, ip_address=args.address)
    except Exception:
        traceback.print_exc(limit=10, file=sys.stderr)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
