import os
import sys
import tempfile
import time

import pytest
from scapy.all import Ether, Raw

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../"))  # TODO: is that needed???
from infra.test_base_swx import TestBaseSwx
from perf.iperf import IperfClient, IperfServer
from tools.killer import Killer
from tools.switch_manager import SwitchManager, SWITCH_VENDOR_AQUANTIA_SMBUS
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    os.environ["DUT_PORT"] = "pci36.00.0"
    os.environ["SWX_PORT_0_LKP"] = "at157-b350:pci36.00.0"
    os.environ["SWX_PORT_1_LKP"] = "at189-b350:pci36.00.0"
    os.environ["SWX_PORT_2_LKP"] = "at190-ab350:pci38.00.0"
    os.environ["SWX_PORT_3_LKP"] = "at206-prime:pci37.00.0"
    os.environ["SUPPORTED_SPEEDS"] = "10G"
    os.environ["WORKING_DIR"] = tempfile.gettempdir()
    os.environ["TEST"] = "swx_jumbo_frame_test"


class TestSwxJumboFrame(TestBaseSwx):
    NOF_PINGS = 5
    IPERF_ARGS = {'num_threads': 1,
                  'num_process': 1,
                  'time': 30,
                  'ipv': 4}

    @classmethod
    def setup_class(cls):
        super(TestSwxJumboFrame, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            for swx_port, info in cls.SWX_PORT_TO_LKP_MAP.items():
                cls.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"] = cls.suggest_test_ip_address(
                    cls.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"], cls.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"])
                # ifcfg = cls.get_lkp_ifconfig(swx_port)
                # ifcfg.set_ip_address(cls.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"], cls.DEFAULT_NETMASK_IPV4, None)
                # ifcfg.set_link_speed(LINK_SPEED_1G)
                # ifcfg.set_link_state(LINK_STATE_UP)
                # ifcfg.set_mtu(16334)
                # assert ifcfg.wait_link_up() is not None

            cls.swx_mngr = SwitchManager(vendor=SWITCH_VENDOR_AQUANTIA_SMBUS)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        self.swx_mngr.reset()
        self.swx_mngr.defcfg()

    def disable_mirroring(self):
        log.info("Disabling ingress mirroring on all ports")
        for swx_port, _ in self.SWX_PORT_TO_LKP_MAP.items():
            self.swx_mngr.set_ingress_port_mirroring(swx_port, None)

        log.info("Disabling egress mirroring on all ports")
        for swx_port, _ in self.SWX_PORT_TO_LKP_MAP.items():
            self.swx_mngr.set_egress_port_mirroring(swx_port, None)

    def create_eth_packet(self, payload_size, dst_mac, src_mac):
        l2 = Ether(dst=dst_mac, src=src_mac, type=0xffff)
        raw = Raw("\xff" * payload_size)
        pkt = l2 / raw
        return pkt

    # def test_ingress_mirroring_from_one_to_another(self):
    #     for swx_port_from, info_from in self.SWX_PORT_TO_LKP_MAP.items():
    #         for swx_port_to, info_to in self.SWX_PORT_TO_LKP_MAP.items():
    #             if swx_port_from == swx_port_to:
    #                 continue
    #             log.info("TESTING INGRESS MIRRORING FROM PORT {} TO PORT {}".format(swx_port_from, swx_port_to))
    #             self.disable_mirroring()
    #             self.swx_mngr.set_ingress_port_mirroring(swx_port_from, swx_port_to)

    #             ports_to_ping = list(Set(self.SWX_PORT_TO_LKP_MAP.keys()) - Set([swx_port_from, swx_port_to]))
    #             port_to_ping = random.choice(ports_to_ping)
    #             log.info("Pings will come to port {} and be forwarded to port {}".format(swx_port_from, port_to_ping))
    #             log.info("All pings requests coming to port {} will be mirrored to port {}".format(
    #                 swx_port_from, swx_port_to))

    #             # Ping one time to learn switch
    #             self.ping(info_from["lkp_hostname"], self.SWX_PORT_TO_LKP_MAP[port_to_ping]["ipv4_addr"], number=1)

    #             sniffer = Sniffer(host=info_to["lkp_hostname"],
    #                               port=info_to["lkp_port"],
    #                               timeout=self.NOF_PINGS + 10 + 5)
    #             sniffer.run_async()
    #             time.sleep(10)

    #             self.ping(info_from["lkp_hostname"],
    #                       self.SWX_PORT_TO_LKP_MAP[port_to_ping]["ipv4_addr"],
    #                       number=self.NOF_PINGS,
    #                       timeout=1)

    #             packets = sniffer.join(timeout=self.NOF_PINGS + 10 + 5 + 30)
    #             nof_ping_requests = 0
    #             for p in packets:
    #                 log.info("Captured frame: {}".format(p.__repr__()))
    #                 if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x8:
    #                     nof_ping_requests += 1
    #                 if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x0:
    #                     raise Exception("Ping reply is captured which means that egress is also mirrored")
    #             assert nof_ping_requests == self.NOF_PINGS

    # def test_ingress_mirroring_from_one_to_many(self):
    #     sniffer_tmo = self.NOF_PINGS + 10 + 5
    #     for swx_port_ping_from, info_from in self.SWX_PORT_TO_LKP_MAP.items():
    #         for swx_port_ping_to, info_to in self.SWX_PORT_TO_LKP_MAP.items():
    #             if swx_port_ping_from == swx_port_ping_to:
    #                 continue

    #             ports_to_mirror = list(
    #                 Set(self.SWX_PORT_TO_LKP_MAP.keys()) - Set([swx_port_ping_from, swx_port_ping_to]))
    #             assert len(ports_to_mirror) > 1
    #             port_to_mirror_1 = random.choice(ports_to_mirror)
    #             ports_to_mirror.remove(port_to_mirror_1)
    #             port_to_mirror_2 = random.choice(ports_to_mirror)
    #             log.info("TESTING INGRESS MIRRORING FROM PORT {} TO PORTS {} and {}".format(
    #                 swx_port_ping_from, port_to_mirror_1, port_to_mirror_2))

    #             self.disable_mirroring()
    #             self.swx_mngr.set_ingress_port_mirroring(swx_port_ping_from, port_to_mirror_1)
    #             self.swx_mngr.set_ingress_port_mirroring(swx_port_ping_from, port_to_mirror_2)

    #             info_to_1 = self.SWX_PORT_TO_LKP_MAP[port_to_mirror_1]
    #             info_to_2 = self.SWX_PORT_TO_LKP_MAP[port_to_mirror_2]

    #             # Ping one time to learn switch
    #             self.ping(info_from["lkp_hostname"], info_to["ipv4_addr"], number=1)

    #             log.info("Pings will come to port {} and be forwarded to port {}".format(
    #                 swx_port_ping_from, swx_port_ping_to))
    #             log.info("All pings requests coming to port {} will be mirrored to ports {} and {}".format(
    #                 swx_port_ping_from, port_to_mirror_1, port_to_mirror_2))

    #             sniffer_to_1 = Sniffer(host=info_to_1["lkp_hostname"], port=info_to_1["lkp_port"], timeout=sniffer_tmo)
    #             sniffer_to_2 = Sniffer(host=info_to_2["lkp_hostname"], port=info_to_2["lkp_port"], timeout=sniffer_tmo)
    #             sniffer_to_1.run_async()
    #             sniffer_to_2.run_async()
    #             time.sleep(10)

    #             self.ping(info_from["lkp_hostname"],
    #                       info_to["ipv4_addr"],
    #                       number=self.NOF_PINGS,
    #                       timeout=1)

    #             packets_1 = sniffer_to_1.join(timeout=sniffer_tmo)
    #             packets_2 = sniffer_to_2.join(timeout=sniffer_tmo)
    #             for sp, parr in [(port_to_mirror_1, packets_1), (port_to_mirror_2, packets_2)]:
    #                 nof_ping_requests = 0
    #                 for p in parr:
    #                     log.info("Captured frame for port {}: {}".format(sp, p.__repr__()))
    #                     if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x8:
    #                         nof_ping_requests += 1
    #                     if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x0:
    #                         raise Exception("Ping reply is captured which means that egress is also mirrored")
    #                 # assert nof_ping_requests == self.NOF_PINGS
    #                 assert nof_ping_requests > 0  # TODO: currently some packets are dropped

    # def test_ingress_mirroring_many_to_one(self):
    #     sniffer_tmo = self.NOF_PINGS + 10 + 5
    #     prts = self.SWX_PORT_TO_LKP_MAP.keys()
    #     list_of_port_pairs = [(prts[p1], prts[p2]) for p1 in range(len(prts)) for p2 in range(p1 + 1, len(prts))]

    #     for swx_port_ping_from_1, swx_port_ping_from_2 in list_of_port_pairs:
    #         info_ping_from_1 = self.SWX_PORT_TO_LKP_MAP[swx_port_ping_from_1]
    #         info_ping_from_2 = self.SWX_PORT_TO_LKP_MAP[swx_port_ping_from_2]

    #         ports_to_ping = list(
    #             Set(self.SWX_PORT_TO_LKP_MAP.keys()) - Set([swx_port_ping_from_1, swx_port_ping_from_2]))
    #         port_to_ping = random.choice(ports_to_ping)
    #         ports_to_ping.remove(port_to_ping)
    #         port_to_mirror = random.choice(ports_to_ping)
    #         log.info("TESTING INGRESS MIRRORING FROM PORTS {} and {} TO PORT {}".format(
    #             swx_port_ping_from_1, swx_port_ping_from_2, port_to_mirror))

    #         self.disable_mirroring()
    #         self.swx_mngr.set_ingress_port_mirroring(swx_port_ping_from_1, port_to_mirror)
    #         self.swx_mngr.set_ingress_port_mirroring(swx_port_ping_from_2, port_to_mirror)

    #         info_ping_to = self.SWX_PORT_TO_LKP_MAP[port_to_ping]
    #         info_mirror = self.SWX_PORT_TO_LKP_MAP[port_to_mirror]

    #         # Ping one time to learn switch
    #         self.ping(info_ping_from_1["lkp_hostname"], info_ping_to["ipv4_addr"], number=1)
    #         self.ping(info_ping_from_2["lkp_hostname"], info_ping_to["ipv4_addr"], number=1)

    #         log.info("Pings will come to ports {} and {} and be forwarded to port {}".format(
    #             swx_port_ping_from_1, swx_port_ping_from_2, port_to_ping))
    #         log.info("All pings requests coming to ports {} and {} will be mirrored to port {}".format(
    #             swx_port_ping_from_1, swx_port_ping_from_2, port_to_mirror))

    #         sniffer = Sniffer(host=info_mirror["lkp_hostname"], port=info_mirror["lkp_port"], timeout=sniffer_tmo)
    #         sniffer.run_async()
    #         time.sleep(10)

    #         self.ping(info_ping_from_1["lkp_hostname"],
    #                   info_ping_to["ipv4_addr"],
    #                   number=self.NOF_PINGS,
    #                   timeout=1)

    #         packets = sniffer.join(timeout=sniffer_tmo)
    #         nof_ping_requests = 0
    #         for p in packets:
    #             log.info("Captured frame for port {}: {}".format(swx_port_ping_from_1, p.__repr__()))
    #             if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x8:
    #                 nof_ping_requests += 1
    #             if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x0:
    #                 raise Exception("Ping reply is captured which means that egress is also mirrored")
    #         # assert nof_ping_requests == self.NOF_PINGS
    #         assert nof_ping_requests > 0  # TODO: currently some packets are dropped

    #         sniffer = Sniffer(host=info_mirror["lkp_hostname"], port=info_mirror["lkp_port"], timeout=sniffer_tmo)
    #         sniffer.run_async()
    #         time.sleep(10)

    #         self.ping(info_ping_from_2["lkp_hostname"],
    #                   info_ping_to["ipv4_addr"],
    #                   number=self.NOF_PINGS,
    #                   timeout=1)

    #         packets = sniffer.join(timeout=sniffer_tmo)
    #         nof_ping_requests = 0
    #         for p in packets:
    #             log.info("Captured frame for port {}: {}".format(swx_port_ping_from_2, p.__repr__()))
    #             if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x8:
    #                 nof_ping_requests += 1
    #             if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x0:
    #                 raise Exception("Ping reply is captured which means that egress is also mirrored")
    #         # assert nof_ping_requests == self.NOF_PINGS
    #         assert nof_ping_requests > 0  # TODO: currently some packets are dropped

    # def test_egress_mirroring_from_one_to_another(self):
    #     for swx_port_from, info_from in self.SWX_PORT_TO_LKP_MAP.items():
    #         for swx_port_to, info_to in self.SWX_PORT_TO_LKP_MAP.items():
    #             if swx_port_from == swx_port_to:
    #                 continue
    #             log.info("TESTING EGRESS MIRRORING FROM PORT {} TO PORT {}".format(swx_port_from, swx_port_to))
    #             self.disable_mirroring()
    #             self.swx_mngr.set_egress_port_mirroring(swx_port_from, swx_port_to)

    #             ports_to_ping = list(Set(self.SWX_PORT_TO_LKP_MAP.keys()) - Set([swx_port_from, swx_port_to]))
    #             port_to_ping = random.choice(ports_to_ping)
    #             log.info("Pings will come to port {} and be forwarded to port {}".format(swx_port_from, port_to_ping))
    #             log.info("All pings replies coming to port {} will be mirrored to port {}".format(
    #                 swx_port_from, swx_port_to))

    #             # Ping one time to learn switch
    #             self.ping(info_from["lkp_hostname"],
    #                       self.SWX_PORT_TO_LKP_MAP[port_to_ping]["ipv4_addr"],
    #                       number=1)

    #             tcpdump = Tcpdump(host=info_to["lkp_hostname"],
    #                               port=info_to["lkp_port"],
    #                               timeout=self.NOF_PINGS + 5)
    #             tcpdump.run_async()

    #             self.ping(info_from["lkp_hostname"],
    #                       self.SWX_PORT_TO_LKP_MAP[port_to_ping]["ipv4_addr"],
    #                       number=self.NOF_PINGS,
    #                       timeout=1)

    #             packets = tcpdump.join(timeout=self.NOF_PINGS + 10)
    #             nof_ping_replies = 0
    #             for p in packets:
    #                 log.info("Captured frame: {}".format(p.__repr__()))
    #                 if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x0:
    #                     nof_ping_replies += 1
    #                 if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x8:
    #                     raise Exception("Ping request is captured which means that ingress is also mirrored")
    #             # assert nof_ping_replies == self.NOF_PINGS
    #             assert nof_ping_replies > 0  # TODO: currently some packets are dropped

    # def test_egress_mirroring_from_one_to_many(self):
    #     sniffer_tmo = self.NOF_PINGS + 10
    #     for swx_port_ping_from, info_from in self.SWX_PORT_TO_LKP_MAP.items():
    #         for swx_port_ping_to, info_to in self.SWX_PORT_TO_LKP_MAP.items():
    #             if swx_port_ping_from == swx_port_ping_to:
    #                 continue

    #             ports_to_mirror = list(
    #                 Set(self.SWX_PORT_TO_LKP_MAP.keys()) - Set([swx_port_ping_from, swx_port_ping_to]))
    #             assert len(ports_to_mirror) > 1
    #             port_to_mirror_1 = random.choice(ports_to_mirror)
    #             ports_to_mirror.remove(port_to_mirror_1)
    #             port_to_mirror_2 = random.choice(ports_to_mirror)
    #             log.info("TESTING INGRESS MIRRORING FROM PORT {} TO PORTS {} and {}".format(
    #                 swx_port_ping_from, port_to_mirror_1, port_to_mirror_2))

    #             self.disable_mirroring()
    #             self.swx_mngr.set_egress_port_mirroring(swx_port_ping_from, port_to_mirror_1)
    #             self.swx_mngr.set_egress_port_mirroring(swx_port_ping_from, port_to_mirror_2)

    #             info_to_1 = self.SWX_PORT_TO_LKP_MAP[port_to_mirror_1]
    #             info_to_2 = self.SWX_PORT_TO_LKP_MAP[port_to_mirror_2]

    #             # Ping one time to learn switch
    #             self.ping(info_from["lkp_hostname"], info_to["ipv4_addr"], number=1)

    #             log.info("Pings will come to port {} and be forwarded to port {}".format(
    #                 swx_port_ping_from, swx_port_ping_to))
    #             log.info("All pings replies coming to port {} will be mirrored to ports {} and {}".format(
    #                 swx_port_ping_from, port_to_mirror_1, port_to_mirror_2))

    #             tcpdump_to_1 = Tcpdump(host=info_to_1["lkp_hostname"], port=info_to_1["lkp_port"], timeout=sniffer_tmo)
    #             tcpdump_to_1.run_async()

    #             self.ping(info_from["lkp_hostname"], info_to["ipv4_addr"],
    #                       number=self.NOF_PINGS, timeout=1)

    #             packets_1 = tcpdump_to_1.join(timeout=sniffer_tmo)
    #             nof_ping_requests = 0
    #             for p in packets_1:
    #                 log.info("Captured frame for port {}: {}".format(port_to_mirror_1, p.__repr__()))
    #                 if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x0:
    #                     nof_ping_requests += 1
    #                 if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x8:
    #                     raise Exception("Ping request is captured which means that ingress is also mirrored")
    #             # assert nof_ping_requests == self.NOF_PINGS
    #             assert nof_ping_requests > 0  # TODO: currently some packets are dropped

    #             tcpdump_to_2 = Tcpdump(host=info_to_2["lkp_hostname"], port=info_to_2["lkp_port"], timeout=sniffer_tmo)
    #             tcpdump_to_2.run_async()

    #             self.ping(info_from["lkp_hostname"], info_to["ipv4_addr"],
    #                       number=self.NOF_PINGS, timeout=1)

    #             packets_2 = tcpdump_to_2.join(timeout=sniffer_tmo)
    #             nof_ping_requests = 0
    #             for p in packets_2:
    #                 log.info("Captured frame for port {}: {}".format(port_to_mirror_1, p.__repr__()))
    #                 if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x0:
    #                     nof_ping_requests += 1
    #                 if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x8:
    #                     raise Exception("Ping request is captured which means that ingress is also mirrored")
    #             # assert nof_ping_requests == self.NOF_PINGS
    #             assert nof_ping_requests > 0  # TODO: currently some packets are dropped

    # def test_egress_mirroring_many_to_one(self):
    #     sniffer_tmo = self.NOF_PINGS + 10
    #     prts = self.SWX_PORT_TO_LKP_MAP.keys()
    #     list_of_port_pairs = [(prts[p1], prts[p2]) for p1 in range(len(prts)) for p2 in range(p1 + 1, len(prts))]

    #     for swx_port_ping_from_1, swx_port_ping_from_2 in list_of_port_pairs:
    #         info_ping_from_1 = self.SWX_PORT_TO_LKP_MAP[swx_port_ping_from_1]
    #         info_ping_from_2 = self.SWX_PORT_TO_LKP_MAP[swx_port_ping_from_2]

    #         ports_to_ping = list(
    #             Set(self.SWX_PORT_TO_LKP_MAP.keys()) - Set([swx_port_ping_from_1, swx_port_ping_from_2]))
    #         port_to_ping = random.choice(ports_to_ping)
    #         ports_to_ping.remove(port_to_ping)
    #         port_to_mirror = random.choice(ports_to_ping)
    #         log.info("TESTING INGRESS MIRRORING FROM PORTS {} and {} TO PORT {}".format(
    #             swx_port_ping_from_1, swx_port_ping_from_2, port_to_mirror))

    #         self.disable_mirroring()
    #         self.swx_mngr.set_egress_port_mirroring(swx_port_ping_from_1, port_to_mirror)
    #         self.swx_mngr.set_egress_port_mirroring(swx_port_ping_from_2, port_to_mirror)

    #         info_ping_to = self.SWX_PORT_TO_LKP_MAP[port_to_ping]
    #         info_mirror = self.SWX_PORT_TO_LKP_MAP[port_to_mirror]

    #         # Ping one time to learn switch
    #         self.ping(info_ping_from_1["lkp_hostname"], info_ping_to["ipv4_addr"], number=1)
    #         self.ping(info_ping_from_2["lkp_hostname"], info_ping_to["ipv4_addr"], number=1)

    #         log.info("Pings will come to ports {} and {} and be forwarded to port {}".format(
    #             swx_port_ping_from_1, swx_port_ping_from_2, port_to_ping))
    #         log.info("All pings requests coming to ports {} and {} will be mirrored to port {}".format(
    #             swx_port_ping_from_1, swx_port_ping_from_2, port_to_mirror))

    #         tcpdmp = Tcpdump(host=info_mirror["lkp_hostname"], port=info_mirror["lkp_port"], timeout=sniffer_tmo)
    #         tcpdmp.run_async()

    #         self.ping(info_ping_from_1["lkp_hostname"],
    #                   info_ping_to["ipv4_addr"],
    #                   number=self.NOF_PINGS,
    #                   timeout=1)

    #         packets = tcpdmp.join(timeout=sniffer_tmo)
    #         nof_ping_requests = 0
    #         for p in packets:
    #             log.info("Captured frame for port {}: {}".format(swx_port_ping_from_1, p.__repr__()))
    #             if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x0:
    #                 nof_ping_requests += 1
    #             if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x8:
    #                 raise Exception("Ping request is captured which means that ingress is also mirrored")
    #         # assert nof_ping_requests == self.NOF_PINGS
    #         assert nof_ping_requests > 0  # TODO: currently some packets are dropped

    #         tcpdmp = Tcpdump(host=info_mirror["lkp_hostname"], port=info_mirror["lkp_port"], timeout=sniffer_tmo)
    #         tcpdmp.run_async()

    #         self.ping(info_ping_from_2["lkp_hostname"],
    #                   info_ping_to["ipv4_addr"],
    #                   number=self.NOF_PINGS,
    #                   timeout=1)

    #         packets = tcpdmp.join(timeout=sniffer_tmo)
    #         nof_ping_requests = 0
    #         for p in packets:
    #             log.info("Captured frame for port {}: {}".format(swx_port_ping_from_2, p.__repr__()))
    #             if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x0:
    #                 nof_ping_requests += 1
    #             if p[0].type == 0x800 and p[1].proto == 0x01 and p[2].type == 0x8:
    #                 raise Exception("Ping request is captured which means that ingress is also mirrored")
    #         # assert nof_ping_requests == self.NOF_PINGS
    #         assert nof_ping_requests > 0  # TODO: currently some packets are dropped

    def test_ingress_mirroring_iperf(self):
        ports = self.SWX_PORT_TO_LKP_MAP.items()
        skip_ports = [0]
        for swx_port_client, info_client in ports:
            if swx_port_client in skip_ports:
                continue
            swx_port_server = (swx_port_client + 1) % len(ports)
            swx_port_mirror = (swx_port_client + 2) % len(ports)

            log.info("TESTING INGRESS MIRRORING FROM PORT {} TO PORT {}".format(swx_port_client, swx_port_mirror))

            self.disable_mirroring()
            self.swx_mngr.set_ingress_port_mirroring(swx_port_client, swx_port_mirror)

            Killer(host=self.SWX_PORT_TO_LKP_MAP[swx_port_client]["lkp_hostname"]).kill("iperf3")
            Killer(host=self.SWX_PORT_TO_LKP_MAP[swx_port_server]["lkp_hostname"]).kill("iperf3")

            iperf_server = IperfServer(host=self.SWX_PORT_TO_LKP_MAP[swx_port_server]["lkp_hostname"],
                                       **self.IPERF_ARGS)
            iperf_client = IperfClient(host=self.SWX_PORT_TO_LKP_MAP[swx_port_client]["lkp_hostname"],
                                       ip_server=self.SWX_PORT_TO_LKP_MAP[swx_port_server]["ipv4_addr"],
                                       **self.IPERF_ARGS)

            msm_cnt_client_before = getattr(self, "lkp_{}_atltool".format(swx_port_client)).get_msm_counters()
            msm_cnt_server_before = getattr(self, "lkp_{}_atltool".format(swx_port_server)).get_msm_counters()
            msm_cnt_mirror_before = getattr(self, "lkp_{}_atltool".format(swx_port_mirror)).get_msm_counters()

            iperf_server.run_async()
            time.sleep(5)  # Make sure iperf server is initialized
            iperf_client.run_async()

            log.info("Sleeping {} seconds while iperf is running".format(self.IPERF_ARGS["time"]))
            time.sleep(self.IPERF_ARGS["time"])

            iperf_client.join(120)
            iperf_server.join(1)

            msm_cnt_client_after = getattr(self, "lkp_{}_atltool".format(swx_port_client)).get_msm_counters()
            msm_cnt_server_after = getattr(self, "lkp_{}_atltool".format(swx_port_server)).get_msm_counters()
            msm_cnt_mirror_after = getattr(self, "lkp_{}_atltool".format(swx_port_mirror)).get_msm_counters()

            msm_tx_gfm_client = msm_cnt_client_after["tx_gfm"] - msm_cnt_client_before["tx_gfm"]
            msm_rx_gfm_server = msm_cnt_server_after["rx_gfm"] - msm_cnt_server_before["rx_gfm"]
            msm_rx_gfm_mirror = msm_cnt_mirror_after["rx_gfm"] - msm_cnt_mirror_before["rx_gfm"]

            log.info("Number of transmitted frames:        {}".format(msm_tx_gfm_client))
            log.info("Number of received frames on server: {}".format(msm_rx_gfm_server))
            log.info("Number of received frames on mirror: {}".format(msm_rx_gfm_mirror))

            assert abs(msm_rx_gfm_mirror - msm_tx_gfm_client) <= msm_tx_gfm_client / 1000.0


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
