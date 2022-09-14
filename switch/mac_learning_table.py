import os
import pytest
import sys
import tempfile

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../"))  # TODO: is that needed???
from infra.test_base_swx import TestBaseSwx
from scapy.all import *
from tools.utils import get_atf_logger
from tools.constants import LINK_SPEED_AUTO, LINK_STATE_UP
from tools.scapy_tools import ScapyTools
from tools.sniffer import Sniffer
from tools.switch_manager import SwitchManager, SWITCH_VENDOR_AQUANTIA_SMBUS, SWITCH_VENDOR_CISCO
from tools import trafficgen

log = get_atf_logger()


def setup_module(module):
    os.environ["TEST"] = "switch_mac_learning_table_test"
    os.environ["DUT_PORT"] = "pci1.00.0"
    os.environ["SWX_PORT_0_LKP"] = "at011-rog:pci1.00.0"
    os.environ["SWX_PORT_1_LKP"] = "at151-rog:pci1.00.0"
    os.environ["SWX_PORT_2_LKP"] = "at193-z370:pci1.00.0"
    os.environ["SWX_PORT_3_LKP"] = "at194-z370:pci1.00.0"
    os.environ["SUPPORTED_SPEEDS"] = "10G"
    os.environ["WORKING_DIR"] = tempfile.gettempdir()


class TestMacLearningTable(TestBaseSwx):
    SNIFF_EXEC_TIME = 10

    @classmethod
    def setup_class(cls):
        super(TestMacLearningTable, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.NETMASK_IPV4 = cls.DEFAULT_NETMASK_IPV4

            for swx_port, info in cls.SWX_PORT_TO_LKP_MAP.items():
                cls.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"] = cls.suggest_test_ip_address(
                    cls.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"], cls.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"])
                ifcfg = cls.get_lkp_ifconfig(swx_port)
                ifcfg.set_ip_address(cls.SWX_PORT_TO_LKP_MAP[swx_port]["ipv4_addr"], cls.NETMASK_IPV4, None)
                ifcfg.set_link_speed(LINK_SPEED_AUTO)

                ifcfg.set_link_state(LINK_STATE_UP)

                assert ifcfg.wait_link_up() is not None

            cls.swx_mngr = SwitchManager(vendor=SWITCH_VENDOR_AQUANTIA_SMBUS)

            cls.scapy_iface_0 = ScapyTools(port=cls.SWX_PORT_TO_LKP_MAP[0]["lkp_port"],
                                         host=cls.SWX_PORT_TO_LKP_MAP[0]["lkp_hostname"]).get_scapy_iface()
            cls.scapy_iface_1 = ScapyTools(port=cls.SWX_PORT_TO_LKP_MAP[1]["lkp_port"],
                                         host=cls.SWX_PORT_TO_LKP_MAP[1]["lkp_hostname"]).get_scapy_iface()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        self.swx_mngr.reset()
        self.swx_mngr.defcfg()
        self.swx_mngr.clear_mac_table()

    def test_mac_learning_after_ping(self):
        """Simple MAC learning table test. One packet to one port"""
        available_ports = self.SWX_PORT_TO_LKP_MAP.keys()

        # Ping from all to all
        for swx_port in available_ports:
            for another_swx_port in available_ports:
                if swx_port == another_swx_port:
                    # Do not ping self to self
                    continue
                assert self.ping(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                                 self.SWX_PORT_TO_LKP_MAP[another_swx_port]["ipv4_addr"], number=1)

        # Get mac table
        mac_table = self.swx_mngr.get_mac_address_table()
        log.info("MAC table\n {}".format(mac_table))

        # Check mac table
        for swx_port in available_ports:
            mac_address = self.SWX_PORT_TO_LKP_MAP[swx_port]["mac_address"]
            port = self.swx_mngr.find_mac_table_entry(mac_address, mac_table)
            log.info("Port entry for LKP {} from switch MAC table is {}".format(mac_address, port))
            assert port == swx_port

    def test_seven_src_mac_to_each_port(self):
        """Multiple MACs"""
        available_ports = self.SWX_PORT_TO_LKP_MAP.keys()
        mac_src_list = ["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc",
                        "dd:dd:dd:dd:dd:dd", "ee:ee:ee:ee:ee:ee", "11:22:33:44:55:66", "12:34:56:78:90:ab"]
        mac_dst = "ff:ff:ff:ff:ff:ff"

        # Send packets. One for each src_mac
        for swx_port in available_ports:
            if swx_port == 0:
                sniffer = Sniffer(host=self.SWX_PORT_TO_LKP_MAP[1]["lkp_hostname"],
                              port=self.SWX_PORT_TO_LKP_MAP[1]["lkp_port"], timeout=self.SNIFF_EXEC_TIME)
                sniffer.run_async(iface=self.scapy_iface_1)
            else:
                sniffer = Sniffer(host=self.SWX_PORT_TO_LKP_MAP[0]["lkp_hostname"],
                              port=self.SWX_PORT_TO_LKP_MAP[0]["lkp_port"], timeout=self.SNIFF_EXEC_TIME)
                sniffer.run_async(iface=self.scapy_iface_0)

            log.info("Send packets from {}".format(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"]))
            self._send_traffic(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                                self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"], mac_dst, mac_src_list)
            time.sleep(1)

            # Check received traffic
            sniffed = sniffer.join(timeout=self.SNIFF_EXEC_TIME)
            pkt_count = 0
            for frame in sniffed:
                if frame.type == 0xffff:
                    pkt_count += 1
                    log.debug("Sniffed frame with source MAC address {}".format(frame["Ethernet"].src))
            log.info("Check traffic loses")
            log.debug("Received {} packets".format(pkt_count))
            assert pkt_count == len(mac_src_list)

            # Get mac table
            mac_table = self.swx_mngr.get_mac_address_table()
            log.debug("MAC table\n {}".format(mac_table))

            # Check mac table
            for mac_addr in mac_src_list:
                port = self.swx_mngr.find_mac_table_entry(mac_addr, mac_table)
                log.info("Port entry for LKP {} from switch MAC table is {}".format(mac_addr, port))
                assert port == swx_port

    def test_max_amount_of_mac_addresses(self):
        """Max size of MAC learning table"""
        mac_addr_num = self.MAX_NOF_SWITCH_PORTS * 1024
        mac_src_list = self._create_uniq_mac_list(mac_addr_num)
        mac_dst = "ff:ff:ff:ff:ff:ff"
        available_ports = self.SWX_PORT_TO_LKP_MAP.keys()

        # Send packets. One for each src_mac
        for swx_port in available_ports:
            log.info("Test sending traffic from {} port".format(swx_port))
            if swx_port == 0:
                sniffer = Sniffer(host=self.SWX_PORT_TO_LKP_MAP[1]["lkp_hostname"],
                              port=self.SWX_PORT_TO_LKP_MAP[1]["lkp_port"], timeout=self.SNIFF_EXEC_TIME)
                sniffer.run_async(iface=self.scapy_iface_1)
            else:
                sniffer = Sniffer(host=self.SWX_PORT_TO_LKP_MAP[0]["lkp_hostname"],
                              port=self.SWX_PORT_TO_LKP_MAP[0]["lkp_port"], timeout=self.SNIFF_EXEC_TIME)
                sniffer.run_async(iface=self.scapy_iface_0)

            log.info("Send packets from {}".format(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"]))
            self._send_traffic(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                                self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"], mac_dst, mac_src_list)
            time.sleep(1)

            # Check received traffic
            sniffed = sniffer.join(timeout=self.SNIFF_EXEC_TIME)
            pkt_count = 0
            for frame in sniffed:
                if frame.type == 0xffff:
                    pkt_count += 1
            #        log.debug("Sniffed frame with source MAC address {}".format(frame["Ethernet"].src))
            log.info("Check traffic loses")
            log.debug("Received {} packets".format(pkt_count))
            assert pkt_count == mac_addr_num

            # Get mac table
            mac_table = self.swx_mngr.get_mac_address_table()
            #log.debug("MAC table\n {}".format(mac_table))

            # Check mac table
            missed_addrs = []
            wrong_addr_map = []
            for mac_addr in mac_src_list:
                port = self.swx_mngr.find_mac_table_entry(mac_addr, mac_table)
            #    log.debug("Port entry for LKP {} from switch MAC table is {}".format(mac_addr, port))
                if port is None:
                    missed_addrs.append(mac_addr)
                elif port != swx_port:
                    wrong_addr_map.append({port: mac_addr})

            addr_stored_num = self.swx_mngr.get_mac_addrs_num()
            log.info("Number of stored mac addresses {}".format(addr_stored_num))
            assert addr_stored_num == mac_addr_num
            log.info("Missed MAC addresses \n {}\n".format(missed_addrs))
            assert len(missed_addrs) <= self.MAX_NOF_SWITCH_PORTS   # 4 addresses may collide with real addresses of the hosts connected to the switch
            log.info("Wrongly mapped MAC addresses \n {}\n".format(wrong_addr_map))
            assert wrong_addr_map == []

    def test_oversize_mac_addresses(self):
        """MAC learning table overflow"""
        mac_addr_num = self.MAX_NOF_SWITCH_PORTS * 1024 + 1
        mac_src_list = self._create_uniq_mac_list(mac_addr_num)
        mac_dst = "ff:ff:ff:ff:ff:ff"
        available_ports = self.SWX_PORT_TO_LKP_MAP.keys()

        # Send packets. One for each src_mac
        for swx_port in available_ports:
            log.info("Test sending traffic from {} port".format(swx_port))
            if swx_port == 0:
                sniffer = Sniffer(host=self.SWX_PORT_TO_LKP_MAP[1]["lkp_hostname"],
                              port=self.SWX_PORT_TO_LKP_MAP[1]["lkp_port"], timeout=self.SNIFF_EXEC_TIME)
                sniffer.run_async(iface=self.scapy_iface_1)
            else:
                sniffer = Sniffer(host=self.SWX_PORT_TO_LKP_MAP[0]["lkp_hostname"],
                              port=self.SWX_PORT_TO_LKP_MAP[0]["lkp_port"], timeout=self.SNIFF_EXEC_TIME)
                sniffer.run_async(iface=self.scapy_iface_0)

            log.info("Send packets from {}".format(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"]))
            self._send_traffic(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                                self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"], mac_dst, mac_src_list[:mac_addr_num - 1])
            time.sleep(1)

            # Check received traffic
            sniffed = sniffer.join(timeout=self.SNIFF_EXEC_TIME)
            pkt_count = 0
            for frame in sniffed:
                if frame.type == 0xffff:
                    pkt_count += 1
            #        log.debug("Sniffed frame with source MAC address {}".format(frame["Ethernet"].src))
            log.info("Check traffic loses")
            log.debug("Received {} packets".format(pkt_count))
            assert pkt_count == mac_addr_num - 1

            # Get mac table
            mac_table = self.swx_mngr.get_mac_address_table()
            #log.debug("MAC table\n {}".format(mac_table))

            # Check mac table
            missed_addrs = []
            wrong_addr_map = []
            for mac_addr in mac_src_list[:mac_addr_num - 1]:
                port = self.swx_mngr.find_mac_table_entry(mac_addr, mac_table)
            #    log.debug("Port entry for LKP {} from switch MAC table is {}".format(mac_addr, port))
                if port is None:
                    missed_addrs.append(mac_addr)
                elif port != swx_port:
                    wrong_addr_map.append({port: mac_addr})

            addr_stored_num = self.swx_mngr.get_mac_addrs_num()
            log.info("Number of stored mac addresses {}".format(addr_stored_num))
            assert addr_stored_num == mac_addr_num - 1
            log.info("Missed MAC addresses \n {}\n".format(missed_addrs))
            assert len(missed_addrs) <= self.MAX_NOF_SWITCH_PORTS   # 4 addresses may collide with real addresses of the hosts connected to the switch
            log.info("Wrongly mapped MAC addresses \n {}\n".format(wrong_addr_map))
            assert wrong_addr_map == []

            # Send one more packet to check oversize table
            self._send_traffic(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                               self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"], mac_dst, [mac_src_list[mac_addr_num - 1]])

            # Get mac table
            mac_table = self.swx_mngr.get_mac_address_table()
            #log.debug("MAC table\n {}".format(mac_table))

            # Check mac table
            log.info("Searching for a MAC address of the sent packet")
            port = self.swx_mngr.find_mac_table_entry(mac_src_list[mac_addr_num - 1], mac_table)
            log.info("Found {}".format({port: mac_src_list[mac_addr_num - 1]}))
            assert port == swx_port

    def test_dublicate_mac_addr(self):
        """Dublicate MAC addresses on different ports"""
        available_ports = self.SWX_PORT_TO_LKP_MAP.keys()
        mac_src = "aa:aa:aa:aa:aa:aa"
        mac_dst = "ff:ff:ff:ff:ff:ff"

        # Send packets
        for swx_port in available_ports:
            log.info("Send packets from {}".format(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"]))
            self._send_traffic(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                                self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"], mac_dst, [mac_src])
            time.sleep(1)

            # Get mac table
            mac_table = self.swx_mngr.get_mac_address_table()
            log.debug("MAC table\n {}".format(mac_table))

            # Check mac table
            port = self.swx_mngr.find_mac_table_entry(mac_src, mac_table)
            log.info("Port entry for LKP {} from switch MAC table is {}".format(mac_src, port))
            assert port == swx_port

    def test_entry_timeout(self):
        """MAC learning table entry timeout"""
        available_ports = self.SWX_PORT_TO_LKP_MAP.keys()
        timeout = 15
        mac_src = "aa:aa:aa:aa:aa:aa"
        mac_dst = "ff:ff:ff:ff:ff:ff"

        # Enable ager
        self.swx_mngr.set_ager_state(True)

        # Set entry timeout
        log.info("Set ager timeout 15 sec")
        self.swx_mngr.set_ager_time(timeout * 1000)

        # Send packets
        for swx_port in available_ports:
            log.info("Send a packet from {}".format(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"]))
            self._send_traffic(self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                                self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"], mac_dst, [mac_src])

            port = self.swx_mngr.find_mac_table_entry(mac_src)
            log.info("Port entry for LKP {} from switch MAC table is {}".format(mac_src, port))
            assert port == swx_port

            log.info("Wait {} sec to ager timeout is expired".format(timeout))
            time.sleep(timeout)

            port = self.swx_mngr.find_mac_table_entry(mac_src)
            log.info("Port entry for LKP {} from switch MAC table is {}".format(mac_src, port))
            assert port is None

    def test_static_entry(self):
        """Static MAC entry"""
        mac_src = "aa:aa:aa:aa:aa:aa"
        mac_dst = "bb:bb:bb:bb:bb:bb"
        available_ports = self.SWX_PORT_TO_LKP_MAP.keys()

        for swx_port in available_ports:
            log.info("Checking static MAC entry for port {}".format(swx_port))

            log.info("Adding mac entry")
            self.swx_mngr.add_static_mac_entry(mac_dst, swx_port)

            if swx_port == 0:
                scapy_iface = self.scapy_iface_0
            elif swx_port == 1:
                scapy_iface = self.scapy_iface_1
            else:
                scapy_iface = ScapyTools(port=self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"],
                       host=self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"]).get_scapy_iface()
            sniffer = Sniffer(host=self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_hostname"],
                              port=self.SWX_PORT_TO_LKP_MAP[swx_port]["lkp_port"], timeout=self.SNIFF_EXEC_TIME)
            sniffer.run_async(iface=scapy_iface)

            if swx_port == 0:
                log.info("Send packet from {}".format(self.SWX_PORT_TO_LKP_MAP[1]["lkp_hostname"]))
                self._send_traffic(self.SWX_PORT_TO_LKP_MAP[1]["lkp_hostname"],
                                   self.SWX_PORT_TO_LKP_MAP[1]["lkp_port"], mac_dst, [mac_src])
            else:
                log.info("Send packet from {}".format(self.SWX_PORT_TO_LKP_MAP[0]["lkp_hostname"]))
                self._send_traffic(self.SWX_PORT_TO_LKP_MAP[0]["lkp_hostname"],
                                   self.SWX_PORT_TO_LKP_MAP[0]["lkp_port"], mac_dst, [mac_src])

            # Check received packet
            sniffed = sniffer.join(timeout=self.SNIFF_EXEC_TIME)
            dst = None
            for frame in sniffed:
                if frame.type == 0xffff:
                    dst = frame["Ethernet"].dst
                    log.debug("Sniffed frame with destination MAC address {}".format(dst))
                    assert dst == mac_dst
                    continue
            assert dst is not None

            # Check mac table
            port = self.swx_mngr.find_mac_table_entry(mac_dst)
            log.info("Port entry for address {} from switch MAC table is {}".format(mac_dst, port))
            assert port == swx_port


    @staticmethod
    def __get_payload(size, fixed_pattern="\xff"):
        return fixed_pattern * size

    def __create_eth_packet(self, size, dst_mac, src_mac):
        l2 = Ether(dst=dst_mac, src=src_mac, type=0xffff)
        raw = Raw(self.__get_payload(size - len(l2)))
        pkt = l2 / raw
        return pkt

    def _send_traffic(self, host, port, dst_mac, src_mac_list):
        pkts = []
        nof_packets = 0
        for addr in src_mac_list:
            pkts.append(self.__create_eth_packet(100, dst_mac, addr))
            nof_packets += 1
        tg = trafficgen.TrafficGenerator(host=host, port=port)
        s = trafficgen.TrafficStream()
        s.type = trafficgen.TrafficStream.STREAM_TYPE_CONTINUOUS
        s.nof_packets = nof_packets
        s.packets = pkts
        s.rate = 1024
        #s.duration = 4
        tg.add_stream(s)
        tg.add_traffic_file()
        tg.run()
        tg.remove_traffic_file()

    @staticmethod
    def _create_uniq_mac_list(size):
        initial_val = 0x1a1b1c1d1111
        mac_src = ["1a:1b:1c:1d:11:11"]
        for i in range(1, size):
            new_val = initial_val ^ i
            current_mac = str(hex(new_val))[2:14]
            current_mac = current_mac[:2] + ":" + current_mac[2:4] + ":" + current_mac[4:6] + \
                          ":" + current_mac[6:8] + ":" + current_mac[8:10] + ":" + current_mac[10:]
            mac_src.append(current_mac)
        return mac_src


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
