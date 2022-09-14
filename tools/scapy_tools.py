import argparse
import json
import random
import re
import string
import struct
import sys
import time
import timeit
import traceback

from abc import abstractmethod, ABCMeta

import ifconfig

from command import Command
from constants import ATF_TOOLS_DIR
from sniffer import Sniffer
from utils import get_atf_logger, get_compressed_ipv6, SpacedArgAction

from scapy import plist, sendrecv
from scapy.all import conf, dnstypes, fragment, fragment6, send, sendp, sndrcv, sniff, \
    ARP, Ether, DNS, DNSQR, DNSRR, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptDstLLAddr, \
    ICMPv6NDOptSrcLLAddr, IP, IPv6, IPv6ExtHdrFragment, TCP, Raw, UDP, RandString, SetGen, Dot1Q

if sys.platform == "win32":
    from scapy.all import ifaces, pcapdnet

SCRIPT_STATUS_SUCCESS = "[SCAPY-SUCCESS]"
SCRIPT_STATUS_FAILED = "[SCAPY-FAILED]"

log = get_atf_logger()

RE_IP_V4 = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")
RE_IP_V6 = re.compile(r"[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*"
                      ":[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*")

MULTICAST_MDNS_IP4 = "224.0.0.251"
MULTICAST_MDNS_IP6 = "FF02:0000:0000:0000:0000:0000:0000:00FB"

MULTICAST_ND_IP6 = "FF02:0000:0000:0000:0000:0000:0000:0001"

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
EMPTY_MAC = "00:00:00:00:00:00"
MULTICAST_MDNS_MAC_IP4 = "01:00:5E:00:00:FB"
MULTICAST_MDNS_MAC_IP6 = "33:33:00:00:00:FB"


def restart_npf_driver():
    Command(cmd='net stop npf').run()
    Command(cmd='net start npf').run()


def get_ns_multicast_ip(dstip):
    ip = "ff02:0000:0000:0000:0000:0001:ff"
    ip += dstip[-7:]
    return ip


def get_ipv6_multicast_mac(dstip):
    mac = "33:33:"
    mac += dstip[-9:-7] + ":" + dstip[-7:-5] + ":" + dstip[-4:-2] + ":" + dstip[-2:]
    return mac


def get_l2_scapy_socket(iface):
    return conf.L2socket(iface=iface)


def expand_packet(p):
    """Forms a list of packet layers"""
    if p:
        yield p
        while p.payload:
            p = p.payload
            yield p


def get_scapy_iface(port):
    if sys.platform == "win32":
        # workaround for 'WMI returned a syntax error: you're probably running inside a thread' exception
        import pythoncom
        pythoncom.CoInitialize()

        from utils import get_wmi_network_adapter
        network_adapter = get_wmi_network_adapter(port)
        guid = network_adapter.GUID

        def find_scapy_iface(name):
            ifaces.reload()
            return name if name in ifaces else None

        scapy_iface_name = find_scapy_iface(guid)

        if scapy_iface_name is None:
            log.info("Dnet ifaces before fail:")
            for dnet_iface in pcapdnet.dnet.intf():
                log.info(dnet_iface)
            raise Exception("Couldn't get scapy iface. Reboot is required or there is no link")

        scapy_face = ifaces[scapy_iface_name]

        if scapy_face.is_invalid():
            restart_npf_driver()
            scapy_iface_name = find_scapy_iface(guid)
            if scapy_iface_name is None:
                log.error("Current scapy ifaces:\n{}".format(ifaces))
                raise Exception("Failed to find scapy interface for port {}".format(port))
            scapy_face = ifaces[scapy_iface_name]
            if scapy_face.is_invalid():
                raise Exception("PCAP driver didn't recognize scapy iface {}".format(scapy_iface_name))
        # On Windows return instance of NetworkInterface class
        return scapy_face
    elif sys.platform == "darwin":
        scapy_iface_name = ifconfig.get_macos_network_adapter_name(port)
    elif "freebsd" in sys.platform:
        scapy_iface_name = ifconfig.get_freebsd_network_adapter_name(port)
    else:
        scapy_iface_name = ifconfig.get_linux_network_adapter_name(port)

    return scapy_iface_name


def send_packet_no_fragmentation(port, dstip, sport=None, dport=None, size=None, iface=None):
    # TODO: use L2 socket to send packet
    """Send single IP/TCP packet without fragmentating it"""
    scapy_iface = iface if iface is not None else get_scapy_iface(port)

    pkt = IP(dst=dstip) / TCP()

    pkt.sport = sport if sport is not None else random.randint(1024, 65535)
    pkt.dport = dport if dport is not None else random.randint(1024, 65535)

    if size is not None:
        payload_size = size - len(pkt)
        if payload_size > 0:
            pkt = pkt / Raw(RandString(payload_size))

    log.debug("Next packet will be sent")
    log.debug("Length = {}".format(len(pkt)))
    pkt.show()

    send(pkt, iface=scapy_iface)


def arping(port, dstip, srcip, dstmac=None, srcmac=None, iface=None):
    scapy_iface = iface if iface is not None else get_scapy_iface(port)
    pkt = ScapyTools.get_address_resolution_packet(
        srcmac=srcmac if srcmac else ifconfig.Ifconfig(port=port).get_mac_address(),
        dstip=dstip, srcip=srcip, dstmac=dstmac)
    log.debug("Next packet will be used as address request")
    log.debug("Length = {}".format(len(pkt)))
    pkt.show()

    sock = get_l2_scapy_socket(scapy_iface)
    ans, unans = sndrcv(sock, pkt, timeout=4)

    macs = []
    for s, r in ans:
        if r.haslayer("ARP"):
            macs.append(r.src)
        elif r.haslayer("ICMPv6ND_NA"):
            macs.append(r.lladdr)
        else:
            log.error("Received wrong packet type: {}".format(r))

    sock.close()

    if len(macs) == 0:
        log.info("Didn't receive a reply for address resolution request")
    elif len(macs) > 1:
        log.warning("Received multiple address resolution replies")
    for mac in macs:
        log.info("Arping reply = {}".format(mac))

    return macs


def wake_on_port(port, dstip, srcip, dstmac, dport, protocol, srcmac=None, sport=None, size=0, iface=None):
    assert protocol in ["tcp", "udp"]

    scapy_iface = iface if iface is not None else get_scapy_iface(port)

    pkt = ScapyTools.get_wake_on_port_packet(
        dstmac=dstmac, srcmac=srcmac if srcmac else ifconfig.Ifconfig(port=port).get_mac_address(),
        dstip=dstip, srcip=srcip, protocol=protocol, dport=dport, sport=sport, size=size)

    log.debug("Next packet will be sent")
    log.debug("Length = {}".format(len(pkt)))
    pkt.show()

    sendp(pkt, iface=scapy_iface)


def wake_on_fragments(port, dstip, srcip, dstmac, srcmac=None, frag_number=20, iface=None):
    scapy_iface = iface if iface is not None else get_scapy_iface(port)
    frags = fragment(IP(src=srcip, dst=dstip) / ICMP(type=8) / Raw(load='H' * 12000), fragsize=600)
    l2 = Ether(type=2048)
    l2.src = srcmac if srcmac is not None else ifconfig.Ifconfig(port=port).get_mac_address()
    l2.dst = dstmac
    for frag in frags:
        pkt = l2 / frag
        log.debug("Next fragment will be sent")
        log.debug("Length = {}".format(len(pkt)))
        pkt.show()

        sendp(pkt, iface=scapy_iface)


def ping_query(port, dstip, srcip, dstmac=None, srcmac=None, number=1, interval=1.0, size=0, flood=False, iface=None):
    scapy_iface = iface if iface is not None else get_scapy_iface(port)
    pkt = ScapyTools.get_echo_request_packet(
        srcmac=srcmac if srcmac else ifconfig.Ifconfig(port=port).get_mac_address(),
        dstip=dstip, srcip=srcip, dstmac=dstmac, size=size)
    log.debug("Next packet will be used as ICMP echo request")
    log.debug("Length = {}".format(len(pkt)))
    pkt.show()

    sock = get_l2_scapy_socket(scapy_iface)

    if flood is True:
        sendrecv.__gen_send(sock, pkt, count=number)
        ans = unans = None
    else:
        ans, unans = sndrcv(sock, [pkt] * number, inter=interval, timeout=number / 10 + 2)

    sock.close()
    return ans, unans


def ping_sendrecv_verify(port, dstip, srcip, dstmac=None, srcmac=None, number=1, interval=1.0, size=0, flood=False,
                         iface=None):
    if dstmac is None:
        log.warning("Destination MAC is not specified, broadcast MAC will be used instead")

    ans, unans = ping_query(port, dstip, srcip, dstmac, srcmac, number, interval, size, flood, iface)
    if flood is False:
        if len(unans) > 0 or len(ans) != number:
            log.info("Received {} answers. Missing {}".format(len(ans), len(unans)))
            return False
        log.info("Received correct number of answers: {}".format(number))
        for s, r in ans:
            if r.haslayer("IP"):
                r_src = r["IP"].src
                expected = dstip
            elif r.haslayer("IPv6"):
                r_src = r["IPv6"].src
                expected = get_compressed_ipv6(dstip)
            else:
                log.info("Received wrong packet type: {}".format(r))
                return False
            if r_src.lower() != expected.lower():
                log.info("Received answer from wrong host: {}".format(r_src))
                return False
    return True


class MDNSRecord(object):
    def __init__(self, rec_type, question, answers, ttl=None, priority=None, weight=None, port=None):
        assert rec_type in ["TXT", "PTR", "SRV", "A", "AAAA"]
        assert type(answers) is list
        self.type = rec_type
        self.question = question
        self.answers = answers  # Empty list when the answer doesn't matter
        self.ttl = ttl
        self.priority = priority
        self.weight = weight
        self.port = port

    @classmethod
    def from_dict(cls, data):
        assert type(data) is dict
        assert "type" in data.keys()
        assert "question" in data.keys()
        assert "answers" in data.keys() and type(data["answers"]) is list
        answers = [answer.encode("utf-8") for answer in data["answers"] if answer != "None"]
        ttl = data.get("ttl", None)
        priority = data.get("priority", None)
        weight = data.get("weight", None)
        port = data.get("port", None)
        return cls(data["type"].encode("utf-8"), data["question"].encode("utf-8"), answers, ttl, priority, weight, port)

    def to_dict(self):
        data = {
            "type": self.type,
            "question": self.question,
            "answers": self.answers,
            "ttl": self.ttl,
            "priority": self.priority,
            "weight": self.weight,
            "port": self.port
        }

        return data


def get_mdns_answers(mdns_pkt):
    pkt_answers = list(expand_packet(mdns_pkt.an))
    pkt_additional = list(expand_packet(mdns_pkt.ar))

    log.info("Checking ANCOUNT, ARCOUNT fields")
    assert mdns_pkt.ancount == len(pkt_answers) and mdns_pkt.arcount == len(pkt_additional), \
        "ANCOUNT, ARCOUNT fields don't match actual records count"
    log.info("ANCOUNT = {}, ARCOUNT = {}, fields are OK".format(mdns_pkt.ancount, mdns_pkt.arcount))

    def parse_rr(mdns_rr):
        rr_type = dnstypes[mdns_rr.type]
        if rr_type == "SRV":
            priority = mdns_rr.priority
            weight = mdns_rr.weight
            port = mdns_rr.port
            data = mdns_rr.target
        else:
            priority = None
            weight = None
            port = None
            data = "".join(mdns_rr.rdata)
        return MDNSRecord(rr_type, mdns_rr.rrname, [data], ttl=mdns_rr.ttl, priority=priority, weight=weight, port=port)

    answers = []
    for mdns_rr in pkt_answers:
        rr = parse_rr(mdns_rr)
        log.info("mDNS answer: {} ({})".format(unicode(rr.answers[0], errors='ignore'), rr.type))
        answers.append(rr)

    additional = []
    for mdns_rr in pkt_additional:
        rr = parse_rr(mdns_rr)
        log.info("mDNS additional record: {} ({}) - {}".format(rr.question, rr.type,
                                                               unicode(rr.answers[0], errors='ignore')))
        additional.append(rr)

    return answers, additional


def mdns_query(port, srcip, queries, dstip=None, dstmac=None, srcmac=None, size=0, fragment_size=1480, iface=None):
    query_pkt = ScapyTools.get_mdns_query(
        srcip=srcip, srcmac=srcmac if srcmac else ifconfig.Ifconfig(port=port).get_mac_address(), queries=queries,
        dstip=dstip, dstmac=dstmac, size=size)

    log.debug("Prepared mDNS query:")
    log.debug("Length = {}".format(len(query_pkt)))
    query_pkt.show()

    fragments = ScapyTools.fragment_packet(query_pkt, fragment_size)
    if len(fragments) > 1:
        if IP in fragments[0] and UDP not in fragments[0]:
            fragments[0][IP].decode_payload_as(UDP)
        log.debug("Fragments:")
        for pkt in fragments:
            log.debug("Length = {} - {}".format(len(pkt), pkt.summary()))

    return ScapyTools.sendrecv1(port=port, pkts=fragments, to_ans=query_pkt, iface=iface)


def check_answer_records(expected_rrs, received_rrs):
    try:
        # exp_number = sum(len(record.answers) for record in expected_rrs)
        # assert exp_number == len(received_rrs), \
        #     "Received incorrect number of records: {}. Expected: {}".format(len(received_rrs), exp_number)
        # log.info("Received correct number of records: {}".format(len(received_rrs)))
        for record in expected_rrs:  # Try to find answers for all records
            for rec_answer in record.answers:  # Try to find all answers for that type of record
                if record.type == "AAAA":  # Expected answer should be IPv6
                    expected_answer = get_compressed_ipv6(rec_answer)
                elif record.type == "A":  # Expected answer should be IPv4
                    expected_answer = rec_answer
                else:
                    expected_answer = rec_answer.split(".")[0]

                answered = False
                for pkt_answer in received_rrs:
                    if pkt_answer.type == record.type and expected_answer in pkt_answer.answers[0]:
                        if pkt_answer.type in ["TXT", "PTR", "SRV"]:
                            assert len(pkt_answer.answers[0]) <= len(record.answers[0]) + 1, \
                                "Received too long answer: {}".format(pkt_answer.answers[0])
                        log.info("Received correct answer for record: {} ({}) - {}".format(record.question, record.type,
                                                                                           expected_answer))
                        if record.ttl:  # If user wants to check ttl
                            assert record.ttl == pkt_answer.ttl, "Received answer with incorrect TTL: {}. " \
                                                                 "Expected: {}".format(pkt_answer.ttl, record.ttl)
                            log.info("TTL is correct: {}".format(pkt_answer.ttl))
                        if record.type == "SRV":  # Check additional fields
                            if record.priority:
                                assert record.priority == pkt_answer.priority, \
                                    "Received answer with incorrect priority: {}. " \
                                    "Expected: {}".format(pkt_answer.priority, record.priority)
                                log.info("Priority is correct: {}".format(pkt_answer.priority))
                            if record.weight:
                                assert record.weight == pkt_answer.weight, \
                                    "Received answer with incorrect weight: {}. " \
                                    "Expected: {}".format(pkt_answer.weight, record.weight)
                                log.info("Weight is correct: {}".format(pkt_answer.weight))
                            if record.port:
                                assert record.port == pkt_answer.port, \
                                    "Received answer with incorrect port: {}. Expected: {}".format(
                                        pkt_answer.port, record.port)
                                log.info("Port is correct: {}".format(pkt_answer.port))
                        answered = True
                        break
                if answered is not True:
                    log.error("Didn't receive answer for record: {} ({}) - {}".format(record.question, record.type,
                                                                                      expected_answer))
                    return False
    except AssertionError as exc:
        log.error("AssertionError occurred while checking for received records:")
        log.exception(exc.message)
        return False
    return True


def mdns_sendrecv_verify(port, srcip, queries, dstip=None, dstmac=None, srcmac=None, size=0, expected_ip=None,
                         additional_records=None, fragment_size=1480, iface=None):
    """
    Send mDNS request with multiple questions
    **queries** is a list of MDNSRecord objects
    """
    assert len(queries) > 0

    if dstip is None:
        log.info("Destination IP is not specified, multicast IP will be used")
    if dstmac is None:
        log.info("Destination MAC is not specified, multicast MAC will be used")
    if expected_ip is None:
        log.info("Expected IP is not specified, listening answer from any IP")
    else:
        log.info("Expecting answer from IP: {}".format(expected_ip))

    # Disable check for IP src and dst for answers
    log.info("Disabling check for correct src answer IP")
    conf.checkIPaddr = False
    ans, unans = mdns_query(port, srcip, queries, dstip, dstmac, srcmac, size, fragment_size, iface)
    # Enable check back (because it is global)
    conf.checkIPaddr = True

    if len(unans) > 0 or len(ans) != 1:
        log.error("Received incorrect number of packets: {}. Missing {}".format(len(ans), len(unans)))
        return False
    s, r = ans[0]

    log.info("Received packet")
    log.info("Length = {}".format(len(r)))
    r.show()

    # Check for received packet's address
    if dstip is not None or expected_ip is not None:
        if r.haslayer("IP"):
            r_src = r["IP"].src
            expected = expected_ip if expected_ip is not None else dstip
        elif r.haslayer("IPv6"):
            r_src = r["IPv6"].src
            expected = get_compressed_ipv6(expected_ip) if expected_ip is not None else get_compressed_ipv6(dstip)
        else:
            log.error("Received wrong packet type: {}".format(r))
            return False
        if r_src.lower() != expected.lower():
            log.error("Received answer from wrong host: {}".format(r_src))
            return False

    pkt_ans, pkt_add = get_mdns_answers(r)

    log.info("Checking for expected mDNS answers")
    res = check_answer_records(queries, pkt_ans)
    if not res:
        return False
    if additional_records is not None:
        log.info("Checking for additional mDNS answers")
        res = check_answer_records(additional_records, pkt_add)
        if not res:
            return False

    log.info("All answers are correct")
    return True


def send_raw_magic_packet(port, dstmac, srcmac=None, broadcast=False, iface=None):
    scapy_iface = iface if iface is not None else get_scapy_iface(port)
    pkt = ScapyTools.get_raw_magic_packet(
        dstmac=dstmac, srcmac=srcmac if srcmac else ifconfig.Ifconfig(port=port).get_mac_address())
    if broadcast:
        pkt[Ether].dst = BROADCAST_MAC
    send_packet(port, pkt, scapy_iface)


def send_udp_magic_packet(port, srcip, dstmac, dstip=None, srcmac=None, broadcast=False, iface=None):
    if dstip is None:
        log.warning("Destination IP is not specified, multicast IP will be used instead")
    scapy_iface = iface if iface is not None else get_scapy_iface(port)
    pkt = ScapyTools.get_udp_magic_packet(
        dstmac=dstmac, srcmac=srcmac if srcmac else ifconfig.Ifconfig(port=port).get_mac_address(), srcip=srcip,
        dstip=dstip)
    if broadcast:
        pkt[Ether].dst = BROADCAST_MAC
    send_packet(port, pkt, scapy_iface)


def send_packet(port, pkt, iface=None, fragment_size=1480):
    scapy_iface = iface if iface is not None else get_scapy_iface(port)

    p = pkt if pkt.haslayer(Ether) else Ether() / pkt

    if len(pkt) > fragment_size and (IP in pkt or IPv6 in pkt):
        fragments = ScapyTools.fragment_packet(pkt, fragment_size)
    else:
        fragments = [pkt]

    if len(fragments) > 1:
        log.info("Fragments:")
        for fr in fragments:
            log.info("Length = {} - {}".format(len(fr), fr.summary()))

    for item in fragments:
        log.info("Next packet will be sent")
        log.info("Length = {}".format(len(p)))
        item.show()

        sendp(item, iface=scapy_iface)


def replay_pcap(port, file_name, iface=None):
    scapy_iface = iface if iface is not None else get_scapy_iface(port)

    pkts = sniff(offline=file_name)
    pkts_count = len(pkts)

    log.info("Sending {} packets".format(pkts_count))
    start = timeit.default_timer()
    sock = get_l2_scapy_socket(scapy_iface)
    for i, pkt in enumerate(pkts):
        try:
            sock.send(pkt)
        except Exception as exc:
            log.error("Error {}: {}".format(i + 1, exc.message))
            pkts_count -= 1
    sock.close()
    end = timeit.default_timer()
    log.info("Finished to send {} packets in {} seconds".format(pkts_count, end - start))


class ScapyTools(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost":
            return object.__new__(ScapyToolsLocal)
        else:
            return object.__new__(ScapyToolsRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]

    @staticmethod
    def fragment_packet(pkt, fragment_size=1480):
        # TODO: handle the case if packet structure is different than Ether / IP
        if IP in pkt:
            eth = pkt[Ether].copy()
            eth.remove_payload()
            ip_pkt = pkt.getlayer(IP).copy()

            ip_frags = fragment(ip_pkt, fragment_size)
            pkt_list = [eth / ip_f for ip_f in ip_frags]
        elif IPv6 in pkt:
            if len(pkt) > fragment_size:
                eth = pkt[Ether].copy()
                eth.remove_payload()
                ip_layer = pkt[IPv6].copy()
                payload = ip_layer.payload
                ip_layer.remove_payload()

                ip_pkt = ip_layer / IPv6ExtHdrFragment() / payload
                ip_frags = fragment6(ip_pkt, fragment_size)
                pkt_list = [eth / ip_f for ip_f in ip_frags]
            else:
                pkt_list = [pkt]
        else:
            raise Exception("Can't fragment non-IP packet")

        return pkt_list

    @staticmethod
    def sendrecv1(port, pkts, to_ans=None, timeout=2, iface=None):
        """Send packets from *pkts* and expect 1 answer to either packet *pkt_to_ans* (if not None) or pkts[0]"""
        if not isinstance(pkts, list) and not isinstance(pkts, SetGen):
            pkts_to_send = [pkts]
        else:
            pkts_to_send = [pkt for pkt in pkts]
        if to_ans is None:
            pkt_to_ans = pkts_to_send[0]
        else:
            pkt_to_ans = to_ans

        scapy_iface = iface if iface else get_scapy_iface(port)
        sock = get_l2_scapy_socket(scapy_iface)

        ans = []

        def callback(pkt):
            if pkt.answers(pkt_to_ans):
                ans.append(pkt)
                raise KeyboardInterrupt()

        sn = Sniffer(port=port, timeout=timeout, lfilter=lambda p: p[Ether].src != pkt_to_ans[Ether].src)
        sn.run_async(iface=scapy_iface, callback=callback)
        time.sleep(0.1)  # Let sniffer initialize
        for pkt in pkts_to_send:
            sock.send(pkt)
        sniffed = sn.join()

        sock.close()

        log.info("Received {} packets, got {} answers".format(len(sniffed), 1 if ans else 0))

        if ans:
            return plist.SndRcvList(res=[(pkt_to_ans, ans[0])]), plist.PacketList(name="Unanswered")
        else:
            return plist.SndRcvList(), plist.PacketList(res=[pkt_to_ans], name="Unanswered")

    @staticmethod
    def get_mdns_query(srcip, srcmac, queries, dstip=None, dstmac=None, size=0):
        eth = Ether()
        eth.src = srcmac

        # mDNS port is 5353
        udp = UDP(sport=5353, dport=5353)

        question_records = DNSQR(qtype=queries[0].type, qname=queries[0].question)
        for i in range(1, len(queries)):
            question_records /= DNSQR(qtype=queries[i].type, qname=queries[i].question)
        mdns = DNS(rd=1, ad=1, ar=[DNSRR(type="OPT")], qd=question_records)

        if RE_IP_V4.match(srcip) is not None:
            if dstip is not None and RE_IP_V4.match(dstip) is None:
                raise Exception("Wrong IPv4 format: {}".format(dstip))
            eth.dst = dstmac if dstmac is not None else MULTICAST_MDNS_MAC_IP4
            ip = IP(dst=dstip if dstip is not None else MULTICAST_MDNS_IP4, src=srcip)
            query_pkt = eth / ip / udp / mdns
            payload_size = size - len(query_pkt)
            if payload_size > 0:
                query_pkt = query_pkt / Raw(load=RandString(payload_size))
        elif RE_IP_V6.match(srcip) is not None:
            if dstip is not None and RE_IP_V6.match(dstip) is None:
                raise Exception("Wrong IPv6 format: {}".format(dstip))
            eth.dst = dstmac if dstmac is not None else MULTICAST_MDNS_MAC_IP6
            ip = IPv6(dst=dstip if dstip is not None else MULTICAST_MDNS_IP6, src=srcip)
            query_pkt = eth / ip / udp / mdns
            payload_size = size - len(query_pkt)
            if payload_size > 0:
                query_pkt.data = RandString(payload_size)
        else:
            raise ValueError("Got wrong IP address (regex not matched): {}".format(srcip))

        return query_pkt

    @staticmethod
    def get_raw_magic_packet(dstmac, srcmac):
        magic_payload = ("ffffffffffff" + (dstmac.replace(dstmac[2], "") * 16)).decode("hex")
        pkt = Ether(dst=dstmac, src=srcmac, type=0x0842) / Raw(load=magic_payload)
        return pkt

    @staticmethod
    def get_udp_magic_packet(dstmac, srcmac, srcip, dstip=None):
        magic_payload = ("ffffffffffff" + (dstmac.replace(dstmac[2], "") * 16)).decode("hex")
        l2 = Ether(dst=dstmac, src=srcmac)
        if RE_IP_V4.match(srcip) is not None:
            l3 = IP(src=srcip, dst=dstip if dstip is not None else "255.255.255.255")
        elif RE_IP_V6.match(srcip) is not None:
            l3 = IPv6(src=srcip, dst=dstip if dstip is not None else "ff02::1")
        else:
            log.error("Got wrong IP addresses (regex not matched): {}".format(srcip))
            raise ValueError("Wrong IP addresses")
        l4 = UDP(sport=random.randint(1024, 65535), dport=9)
        pkt = l2 / l3 / l4 / Raw(load=magic_payload)
        return pkt

    @staticmethod
    def get_address_resolution_packet(srcmac, dstip, srcip, dstmac=None):
        l2 = Ether(src=srcmac)
        if RE_IP_V4.match(dstip) is not None and RE_IP_V4.match(srcip) is not None:
            l2.dst = dstmac if dstmac else BROADCAST_MAC
            l3 = ARP(pdst=dstip, psrc=srcip, hwsrc=l2.src)
        elif RE_IP_V6.match(dstip) is not None and RE_IP_V6.match(srcip) is not None:
            # https://keepingitclassless.net/2011/10/neighbor-solicitation-ipv6s-replacement-for-arp/
            l3 = IPv6(dst=get_ns_multicast_ip(dstip), src=srcip) / ICMPv6ND_NS(tgt=dstip) / \
                 ICMPv6NDOptSrcLLAddr(lladdr=l2.src)
            l2.dst = dstmac if dstmac else get_ipv6_multicast_mac(get_ns_multicast_ip(dstip))
        else:
            raise ValueError("Got wrong IP addresses (regex not matched): {} - {}".format(dstip, srcip))
        pkt = l2 / l3
        return pkt

    @staticmethod
    def get_echo_request_packet(srcmac, dstip, srcip, dstmac=None, size=0, seq=0):
        l2 = Ether(dst=dstmac if dstmac else BROADCAST_MAC, src=srcmac)

        if RE_IP_V4.match(dstip) is not None and RE_IP_V4.match(srcip) is not None:
            l3 = IP(dst=dstip, src=srcip) / ICMP(seq=seq)
            payload_size = size - len(l2 / l3)
            if payload_size > 0:
                l3 = l3 / Raw(load=str(RandString(payload_size)))
        elif RE_IP_V6.match(dstip) is not None and RE_IP_V6.match(srcip) is not None:
            l3 = IPv6(dst=dstip, src=srcip) / ICMPv6EchoRequest(id=0x0001, seq=seq)
            payload_size = size - len(l2 / l3)
            if payload_size > 0:
                l3.data = str(RandString(payload_size))
        else:
            ValueError("Got wrong IP addresses (regex not matched): {} - {}".format(dstip, srcip))
        pkt = l2 / l3
        return pkt

    @staticmethod
    def get_wake_on_port_packet(dstmac, srcmac, dstip, srcip, protocol, dport, sport=None, size=0):
        assert protocol in ["tcp", "udp"]

        l2 = Ether(dst=dstmac, src=srcmac)

        if RE_IP_V4.match(dstip) is not None and RE_IP_V4.match(srcip) is not None:
            l3 = IP(src=srcip, dst=dstip)
        elif RE_IP_V6.match(dstip) is not None and RE_IP_V6.match(srcip) is not None:
            l3 = IPv6(src=srcip, dst=dstip)
        else:
            raise ValueError("Got wrong IP addresses (regex not matched): {} - {}".format(dstip, srcip))

        srcport = sport if sport is not None else random.randint(1024, 65535)
        if protocol == "tcp":
            l4 = TCP(sport=srcport, dport=dport)
        else:
            l4 = UDP(sport=srcport, dport=dport)

        pkt = l2 / l3 / l4
        payload_size = size - len(pkt)
        if payload_size > 0:
            pkt = pkt / Raw(load=RandString(payload_size))

        return pkt

    @abstractmethod
    def get_scapy_iface(self):
        pass

    @abstractmethod
    def send_packet_no_fragmentation(self, dstip, sport=None, dport=None, size=None, iface=None):
        pass

    @abstractmethod
    def arping(self, dstip, srcip, dstmac=None, srcmac=None, iface=None):
        pass

    @abstractmethod
    def wake_on_port(self, dstip, srcip, dstmac, dport, protocol, srcmac=None, sport=None, size=0, iface=None):
        pass

    @abstractmethod
    def wake_on_fragments(self, dstip, srcip, dstmac, srcmac=None, frag_number=20, iface=None):
        pass

    @abstractmethod
    def ping(self, dstip, srcip, dstmac=None, srcmac=None, number=1, interval=1.0, size=0, flood=False, iface=None):
        pass

    @abstractmethod
    def mdns_request(self, srcip, queries, dstip=None, dstmac=None, srcmac=None, size=0, expected_ip=None,
                     additional_records=None, fragment_size=1480, iface=None):
        """
        **records** and **additional_records** are lists of **MDNSQuery** objects
        """
        pass

    @abstractmethod
    def send_raw_magic_packet(self, dstmac, srcmac=None, broadcast=False, iface=None):
        pass

    @abstractmethod
    def send_udp_magic_packet(self, srcip, dstmac, dstip=None, srcmac=None, broadcast=False, iface=None):
        pass

    @abstractmethod
    def send_packet(self, pkt, iface=None, fragment_size=1480):
        pass

    @abstractmethod
    def replay_pcap(self, file_name, iface=None):
        pass


class ScapyToolsLocal(ScapyTools):
    def get_scapy_iface(self):
        return get_scapy_iface(self.port)

    def send_packet_no_fragmentation(self, dstip, sport=None, dport=None, size=None, iface=None):
        send_packet_no_fragmentation(self.port, dstip, sport, dport, size, iface)

    def arping(self, dstip, srcip, dstmac=None, srcmac=None, iface=None):
        return arping(self.port, dstip, srcip, dstmac, srcmac, iface)

    def wake_on_port(self, dstip, srcip, dstmac, dport, protocol, srcmac=None, sport=None, size=0, iface=None):
        wake_on_port(self.port, dstip, srcip, dstmac, dport, protocol, srcmac, sport, size, iface)

    def wake_on_fragments(self, dstip, srcip, dstmac, srcmac=None, frag_number=20, iface=None):
        wake_on_fragments(self.port, dstip, srcip, dstmac, srcmac, frag_number, iface)

    def ping(self, dstip, srcip, dstmac=None, srcmac=None, number=1, interval=1.0, size=0, flood=False, iface=None):
        return ping_sendrecv_verify(self.port, dstip, srcip, dstmac, srcmac, number, interval, size, flood, iface)

    def mdns_request(self, srcip, queries, dstip=None, dstmac=None, srcmac=None, size=0, expected_ip=None,
                     additional_records=None, fragment_size=1480, iface=None):
        return mdns_sendrecv_verify(self.port, srcip, queries, dstip, dstmac, srcmac, size, expected_ip,
                                    additional_records, fragment_size, iface)

    def send_raw_magic_packet(self, dstmac, srcmac=None, broadcast=False, iface=None):
        send_raw_magic_packet(self.port, dstmac, srcmac, broadcast, iface)

    def send_udp_magic_packet(self, srcip, dstmac, dstip=None, srcmac=None, broadcast=False, iface=None):
        send_udp_magic_packet(self.port, srcip, dstmac, dstip, srcmac, broadcast, iface)

    def send_packet(self, pkt, iface=None, fragment_size=1480):
        send_packet(self.port, pkt, iface, fragment_size)

    def replay_pcap(self, file_name, iface=None):
        replay_pcap(self.port, file_name, iface)


class ScapyToolsRemote(ScapyTools):
    RE_IFACE = re.compile(r".*Iface = ([a-zA-Z0-9\-\{\}]+)", re.DOTALL)
    RE_ARPING_REPLY = re.compile(r".*Arping reply = ([a-zA-Z0-9:\-]+)", re.DOTALL)
    RE_PING_RESULT = re.compile(r".*Ping result = (True|False)", re.DOTALL)
    RE_MDNS_RESULT = re.compile(r".*mDNS result = (True|False)", re.DOTALL)

    def __init__(self, **kwargs):
        super(ScapyToolsRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]
        self.cmd_start = "cd ~/{} && sudo python scapy_tools.py -p {} ".format(ATF_TOOLS_DIR, self.port)

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).run()
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to execute remote command")
        if not any(SCRIPT_STATUS_SUCCESS in line for line in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote scapy operation")
        return res["output"]

    def get_scapy_iface(self):
        cmd = self.cmd_start + "-c getiface"
        stdout = self.remote_exec(cmd)
        for line in stdout:
            m = self.RE_IFACE.match(line)
            if m is not None:
                return m.group(1)
        raise Exception("Failed to obtain scapy iface (regex is not matched)")

    def send_packet_no_fragmentation(self, dstip, sport=None, dport=None, size=None, iface=None):
        cmd = self.cmd_start + "-c sendsingle -di {}".format(dstip)
        if sport is not None:
            cmd += " -sp {}".format(sport)
        if dport is not None:
            cmd += " -dp {}".format(dport)
        if size is not None:
            cmd += " -s {}".format(size)
        if iface is not None:
            cmd += " -i {}".format(iface)
        self.remote_exec(cmd)

    def arping(self, dstip, srcip, dstmac=None, srcmac=None, iface=None):
        cmd = self.cmd_start + "-c arping -di {} -si {}".format(dstip, srcip)
        if dstmac is not None:
            cmd += " -dm {}".format(dstmac)
        if srcmac is not None:
            cmd += " -sm {}".format(srcmac)
        if iface is not None:
            cmd += " -i {}".format(iface)
        stdout = self.remote_exec(cmd)
        macs = []
        for line in stdout:
            m = self.RE_ARPING_REPLY.match(line)
            if m is not None:
                macs.append(m.group(1))
        return macs

    def wake_on_port(self, dstip, srcip, dstmac, dport, protocol, srcmac=None, sport=None, size=0, iface=None):
        cmd = self.cmd_start + "-c wakeonport -di {} -si {} -dm {} -dp {} -pr {}".format(dstip, srcip, dstmac, dport,
                                                                                         protocol)
        if srcmac is not None:
            cmd += " -sm {}".format(srcmac)
        if sport is not None:
            cmd += " -sp {}".format(sport)
        if size != 0:
            cmd += " -s {}".format(size)
        if iface is not None:
            cmd += " -i {}".format(iface)
        self.remote_exec(cmd)

    def wake_on_fragments(self, dstip, srcip, dstmac, srcmac=None, frag_number=20, iface=None):
        cmd = self.cmd_start + "-c wakeonfrag -di {} -si {} -dm {}".format(dstip, srcip, dstmac)
        if srcmac is not None:
            cmd += " -sm {}".format(srcmac)
        if iface is not None:
            cmd += " -i {}".format(iface)
        self.remote_exec(cmd)

    def ping(self, dstip, srcip, dstmac=None, srcmac=None, number=1, interval=1.0, size=0, flood=False, iface=None):
        cmd = self.cmd_start + "-c ping -di {} -si {}".format(dstip, srcip)
        if dstmac is not None:
            cmd += " -dm {}".format(dstmac)
        if srcmac is not None:
            cmd += " -sm {}".format(srcmac)
        if number != 1:
            cmd += " -n {}".format(number)
        if interval != 1.0:
            cmd += " -iv {}".format(interval)
        if size != 0:
            cmd += " -s {}".format(size)
        if flood is True:
            cmd += " -f"
        if iface is not None:
            cmd += " -i {}".format(iface)
        stdout = self.remote_exec(cmd)
        for line in stdout:
            m = self.RE_PING_RESULT.match(line)
            if m is not None:
                return m.group(1) == "True"
        raise Exception("Failed to do remote ping command")

    def mdns_request(self, srcip, queries, dstip=None, dstmac=None, srcmac=None, size=0, expected_ip=None,
                     additional_records=None, fragment_size=1480, iface=None):
        q_rrs = [record.to_dict() for record in queries]
        q_rrs_arg = json.dumps(q_rrs)
        cmd = self.cmd_start + "-c mdns -si {} -q '{}'".format(srcip, q_rrs_arg)
        if additional_records is not None:
            add_rrs = [record.to_dict() for record in additional_records]
            add_rrs_arg = json.dumps(add_rrs)
            cmd += " -ar '{}'".format(add_rrs_arg)
        if dstip is not None:
            cmd += " -di {}".format(dstip)
        if dstmac is not None:
            cmd += " -dm {}".format(dstmac)
        if srcmac is not None:
            cmd += " -sm {}".format(srcmac)
        if size != 0:
            cmd += " -s {}".format(size)
        if expected_ip is not None:
            cmd += " -ei {}".format(expected_ip)
        if fragment_size != 1480:
            cmd += " -fr {}".format(fragment_size)
        if iface is not None:
            cmd += " -i {}".format(iface)
        stdout = self.remote_exec(cmd)
        for line in stdout:
            m = self.RE_MDNS_RESULT.match(line)
            if m is not None:
                return m.group(1) == "True"
        raise Exception("Failed to find remote mDNS command result. Regex not matched")

    def send_raw_magic_packet(self, dstmac, srcmac=None, broadcast=False, iface=None):
        cmd = self.cmd_start + "-c sendmagicraw -dm {}".format(dstmac)
        if srcmac is not None:
            cmd += " -sm {}".format(srcmac)
        if broadcast is True:
            cmd += " -b"
        if iface is not None:
            cmd += " -i {}".format(iface)
        self.remote_exec(cmd)

    def send_udp_magic_packet(self, srcip, dstmac, dstip=None, srcmac=None, broadcast=False, iface=None):
        cmd = self.cmd_start + "-c sendmagicudp -si {} -dm {}".format(srcip, dstmac)
        if dstip is not None:
            cmd += " -di {}".format(dstip)
        if srcmac is not None:
            cmd += " -sm {}".format(srcmac)
        if broadcast is True:
            cmd += " -b"
        if iface is not None:
            cmd += " -i {}".format(iface)
        self.remote_exec(cmd)

    def send_packet(self, pkt, iface=None, fragment_size=1480):
        cmd = self.cmd_start + "-c sendpacket -pk \"{}\"".format(str(pkt).encode("hex"))
        if iface is not None:
            cmd += " -i {}".format(iface)
        if fragment_size != 1480:
            cmd += " -fr {}".format(fragment_size)
        self.remote_exec(cmd)

    def replay_pcap(self, file_name, iface=None):
        cmd = self.cmd_start + "-c replaypcap -fn \"{}\"".format(file_name)
        if iface is not None:
            cmd += " -i {}".format(iface)
        self.remote_exec(cmd)


class ScapyToolsArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error(SCRIPT_STATUS_FAILED)
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = ScapyToolsArgumentParser()
    parser.add_argument("-c", "--command", help="Command to be performed",
                        choices=["getiface",
                                 "sendsingle",
                                 "arping",
                                 "wakeonport",
                                 "wakeonfrag",
                                 "ping",
                                 "mdns",
                                 "sendmagicraw",
                                 "sendmagicudp",
                                 "sendpacket",
                                 "replaypcap"
                                 ],
                        type=str, required=True)
    parser.add_argument("-p", "--port", help="PCI port, i.e. pci1.00.0, ...",
                        type=str, required=True)
    parser.add_argument("-i", "--iface", help="Scapy iface name, i.e. eth11, ...",
                        type=str)
    parser.add_argument("-si", "--srcip", help="Source IP address",
                        type=str)
    parser.add_argument("-di", "--dstip", help="Destination IP address",
                        type=str)
    parser.add_argument("-sm", "--srcmac", help="Source MAC address",
                        type=str)
    parser.add_argument("-dm", "--dstmac", help="Destination MAC address",
                        type=str)
    parser.add_argument("-sp", "--sport", help="Source port",
                        type=int)
    parser.add_argument("-dp", "--dport", help="Destination port",
                        type=int)
    parser.add_argument("-s", "--size", help="Size of packets to send (including all headers)",
                        type=int, default=0)
    parser.add_argument("-n", "--number", help="Number of packets to send",
                        type=int, default=1)
    parser.add_argument("-iv", "--interval", help="How long to wait in seconds between sending each packet",
                        type=float, default=1.0)
    parser.add_argument('-f', '--flood', help="Only send requests without waiting for reply with 0 interval",
                        action='store_true', default=False)
    parser.add_argument("-pr", "--protocol", help="Protocol to use",
                        choices=["tcp", "udp", "raw"], type=str)
    parser.add_argument("-ei", "--expected_ip", help="Expected answer IP address",
                        type=str)
    parser.add_argument("-q", "--queries", help="mDNS queries to send (python code for list of dictionaries)",
                        type=str, action=SpacedArgAction, nargs="+")
    parser.add_argument("-ar", "--additional_records", help="mDNS additional records for lookup in received packet",
                        type=str, action=SpacedArgAction, nargs="+")
    parser.add_argument("-b", "--broadcast", help="Send packet to broadcast MAC address (used in magic packet tools)",
                        action="store_true", default=False)
    parser.add_argument("-pk", "--packet", help="Scapy packet to be sent, converted using command() method",
                        type=str, action=SpacedArgAction, nargs="+")
    parser.add_argument("-fn", "--file_name", help="File name of pcap trace",
                        type=str, action=SpacedArgAction, nargs="+")
    parser.add_argument("-fr", "--fragment", help="Fragment size",
                        type=int, default=1480)
    args = parser.parse_args()

    if args.iface == "None":
        args.iface = None
    if args.expected_ip == "None":
        args.expected_ip = None
    if args.additional_records == "None":
        args.additional_records = None

    # Convert iface name on Windows to NetworkInterface instance
    if sys.platform == "win32" and args.iface is not None:
        ifaces.reload()
        args.iface = ifaces[args.iface]

    try:
        scapy_obj = ScapyToolsLocal(port=args.port)

        if args.command == "getiface":
            iface = scapy_obj.get_scapy_iface()
            if sys.platform == "win32":
                iface = iface.guid
            log.info("Iface = {}".format(iface))
        elif args.command == "sendsingle":
            if args.dstip is None:
                log.error("To send packet destination IP must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            log.info("Trying to send single packet")
            scapy_obj.send_packet_no_fragmentation(args.dstip, args.sport, args.dport, args.size, args.iface)
        elif args.command == "arping":
            if args.dstip is None or args.srcip is None:
                log.error("To use arping command source and destination IPs must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            macs = scapy_obj.arping(args.dstip, args.srcip, args.dstmac, args.srcmac, args.iface)
            if len(macs) > 0:
                log.info("Arping result = True")
            else:
                log.info("Arping result = False")
        elif args.command == "wakeonport":
            if args.dstip is None or args.srcip is None or args.dport is None or args.protocol not in ["tcp", "udp"]:
                log.error("To send wake-on-port packet next arguments must be specified: "
                          "destination IP, source IP, destination port, destination MAC, protocol type")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            scapy_obj.wake_on_port(args.dstip, args.srcip, args.dstmac, args.dport, args.protocol,
                                   args.srcmac, args.sport, args.size, args.iface)
        elif args.command == "wakeonfrag":
            if args.dstip is None or args.srcip is None:
                log.error("To send fragments next arguments must be specified: "
                          "destination IP, source IP, destination MAC")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            scapy_obj.wake_on_fragments(args.dstip, args.srcip, args.dstmac, args.srcmac, iface=args.iface)
        elif args.command == "ping":
            if args.dstip is None or args.srcip is None:
                log.error("To ping host, destination and source IPs must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            ping_res = scapy_obj.ping(args.dstip, args.srcip, args.dstmac, args.srcmac, args.number,
                                      args.interval, args.size, args.flood, args.iface)
            log.info("Ping result = {}".format(ping_res))
        elif args.command == "mdns":
            if args.srcip is None or args.queries is None:
                log.error("To send mDNS request, source IP and MDNS records must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            queries_arr = json.loads(args.queries)
            queries = [MDNSRecord.from_dict(query_dict) for query_dict in queries_arr]
            if args.additional_records is not None:
                add_rrs_arr = json.loads(args.additional_records)
                add_rrs = [MDNSRecord.from_dict(record_dict) for record_dict in add_rrs_arr]
            else:
                add_rrs = None
            mdns_res = scapy_obj.mdns_request(args.srcip, queries, args.dstip, args.dstmac, args.srcmac, args.size,
                                              args.expected_ip, add_rrs, args.fragment, args.iface)
            log.info("mDNS result = {}".format(mdns_res))
        elif args.command == "sendmagicraw":
            if args.dstmac is None:
                log.error("To send raw magic packet, destination MAC must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            scapy_obj.send_raw_magic_packet(args.dstmac, args.srcmac, args.broadcast, args.iface)
        elif args.command == "sendmagicudp":
            if args.dstmac is None:
                log.error("To send udp magic packet, destination MAC and source IP must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            scapy_obj.send_udp_magic_packet(args.srcip, args.dstmac, args.dstip, args.srcmac, args.broadcast,
                                            args.iface)
        elif args.command == "sendpacket":
            if args.packet is None:
                log.error("To send a packet, scapy packet command must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            is_hex_string = lambda s: all(c in string.hexdigits for c in s)
            if is_hex_string(args.packet):
                pkt = Ether(args.packet.decode("hex"))
            else:
                pkt = eval(args.packet.replace("//", "/"))
            scapy_obj.send_packet(pkt, args.iface, args.fragment)
        elif args.command == "replaypcap":
            if args.file_name is None:
                log.error("To replay pcap file, file name must be specified")
                log.error(SCRIPT_STATUS_FAILED)
                exit(1)
            scapy_obj.replay_pcap(args.file_name, args.iface)
    except Exception as exc:
        traceback.print_exc(limit=10, file=sys.stderr)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
