import shutil

import pytest

from infra.test_base import TestBase, idparametrize
from scapy.all import *
# from scapy.all import Ether, Dot1Q, IP, ICMP, UDP, Raw, wrpcap, MACsecSA
# from scapy.contrib.macsec import *
from hlh.phy import PHY
from tools.atltoolper import AtlTool
from tools.aqpkt import Aqsendp, scapy_pkt_to_aqsendp_str
from tools.tcpdump import Tcpdump
from tools.command import Command
from tools.constants import LINK_STATE_UP, ENABLE, PHY_RHEA, LINK_SPEED_10G
from tools.driver import Driver
from tools.macsectool import MacsecTool
from tools.utils import get_atf_logger

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "MacSec_PHY_Test"


class TestMacsec(TestBase):
    MACSEC_IFACE = "macsec0"
    DUT_IP_ADDRESS = "10.10.12.1"
    LKP_IP_ADDRESS = "10.10.12.2"

    @classmethod
    def setup_class(cls):
        super(TestMacsec, cls).setup_class()
        cls.log_server_dir = cls.create_logs_dir_on_log_server()

        cls.install_firmwares()

        cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version, host=cls.dut_hostname)
        cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
        cls.dut_driver.install()
        cls.lkp_driver.install()

        cls.dut_atltool = AtlTool(port=cls.dut_port)
        cls.dut_macsec = MacsecTool(port=cls.dut_port, device=cls.dut_phy_board_name)
        cls.dut_mac = cls.dut_ifconfig.get_mac_address()
        cls.lkp_mac = cls.lkp_ifconfig.get_mac_address()
        cls.dut_iface = cls.dut_ifconfig.get_conn_name()
        cls.lkp_iface = cls.lkp_ifconfig.get_conn_name()

        cls.NETMASK_IPV4 = "255.255.0.0"
        cls.NETMASK_DEC_FORMAT = 16

        cls.dut_ifconfig.set_ip_address(cls.DUT_IP_ADDRESS, cls.NETMASK_IPV4, None)

        cls.lkp_ifconfig.set_link_state(LINK_STATE_UP)
        cls.dut_ifconfig.set_link_state(LINK_STATE_UP)
        speed = cls.dut_ifconfig.wait_link_up()

        # Enable macsec
        if cls.dut_phy_board_name is not None:
            cls.dut_phy = PHY(phy_control=cls.phy_controls[0])
            cls.dut_phy.set_security_bit(speed, ENABLE)
            cls.phy_controls[0].close()

    def setup_linux_macsec(self, macsec_iface, key, tx_pn=1, rx_pn=1):
        Command(cmd='sudo ip link delete {}'.format(macsec_iface), host=self.lkp_hostname).run()
        Command(cmd='sudo ip a', host=self.lkp_hostname).run()
        # res = Command(cmd='sudo ip link add link {} {} type macsec encrypt on protect on replay on window 0'.format(
        res = Command(cmd='sudo ip link add link {} {} type macsec encrypt on protect on'.format(
                self.lkp_iface, macsec_iface), host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot add MacSec interface on LKP")
        res = Command(cmd='sudo ip macsec add {} tx sa 0 pn {} on key 01 {}'.format(macsec_iface, tx_pn, key),
                      host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot add TX SA to MacSec interface on LKP")
        res = Command(cmd='sudo ip macsec add {} rx address {} port 1'.
                      format(macsec_iface, self.dut_ifconfig.get_mac_address()), host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot add MacSec RX SC on LKP")
        res = Command(cmd='sudo ip macsec add {} rx address {} port 1 sa 0 pn {} on key 00 {}'.
                      format(macsec_iface, self.dut_ifconfig.get_mac_address(), rx_pn, key), host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot add RX SA to MacSec interface on LKP")
        res = Command(cmd='sudo ip link set dev {} up'.format(macsec_iface), host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot put up MacSec link on LKP")
        res = Command(cmd='sudo ifconfig {} {}/{}'.format(macsec_iface, self.LKP_IP_ADDRESS, self.NETMASK_DEC_FORMAT),
                      host=self.lkp_hostname).run()
        Command(cmd='sudo ip macsec show {}'.format(macsec_iface), host=self.lkp_hostname).run()
        if res["returncode"] != 0:
            raise Exception("Cannot set IP address to MacSec interface on LKP")

    def dump_macsec_cfg(self, cfg_name='dut_macsec.cfg'):
        self.dut_macsec.dump_conf(cfg_name)
        shutil.move(cfg_name, self.test_log_dir)

    def dump_macsec_yaml(self):
        shutil.copy('macsec.yaml', self.test_log_dir)

    def send_macsec_traffic(self, pkt_count, pkt_rate, iface, host, pkt=None):
        if pkt is None:
            size = 100
            l2 = Ether(src=self.lkp_mac, dst=self.dut_mac)
            raw = Raw("\xff" * (size - len(l2)))
            pkt = l2 / raw

        aqsendp_pkt = scapy_pkt_to_aqsendp_str(pkt)
        lkp_aqsendp = Aqsendp(
            packet=aqsendp_pkt, count=pkt_count, rate=pkt_rate,
            host=host, iface=iface
        )

        lkp_aqsendp.run()

    def test_simple_ping(self):
        """
        @description: Simple ping test

        @steps:
        1. Put up a link between LKP and DUT
        2. Configure LKP linux macsec with key encryption.
        3. Configure DUT phy macsec with key encryption. 1 SC and 1 SA related to it. 128 bit key.
        4. Set IP addresses to DUT and LKP macsec interfaces
        5. Ping LKP from DUT and vice versa.
        7. Result - pings are pass
        """
        key = "73bd5434ca328f97b456568a67674134"

        self.setup_linux_macsec(self.MACSEC_IFACE, key)
        self.lkp_ifconfig.wait_link_up()

        macsec_yaml = MacsecTool.gen_config(self.dut_mac, self.lkp_mac, key, key)
        # Disable MAC_DA_MASK to reslove ARP requests
        macsec_yaml['INGRESS']['SC'][0]['PRECLASS'][0]['MAC_DA_MASK'] = 0
        macsec_yaml['EGRESS']['SC'][0]['PRECLASS'][0]['MAC_DA_MASK'] = 0
        self.dut_macsec.configure(macsec_yaml)
        self.dump_macsec_cfg()
        self.dump_macsec_yaml()

        try:
            self.dut_macsec.clear_counters()
            assert self.ping(from_host=self.lkp_hostname, to_host=self.DUT_IP_ADDRESS, number=10)
        finally:
            self.dut_macsec.get_stats(index='0.0.0')

    def test_encrypt_128_key(self):
        """
        @description: MacSec setup with encryption 128-bit key

        @steps:
        1. Put up a link between LKP and DUT
        2. Configure LKP linux macsec with key encryption.
        3. Configure DUT phy macsec with key encryption. 1 SC and 1 SA related to it. 128 bit key.
        4. Send traffic from LKP to DUT
        5. Check In_ok_pkts counter
        """

        key = "73bd5434ca328f97b456568a67674134"
        pkts_sent = 20000
        pkts_rate = 1000
        dlt = 30

        self.setup_linux_macsec(self.MACSEC_IFACE, key)
        self.lkp_ifconfig.wait_link_up()

        macsec_yaml = MacsecTool.gen_config(self.dut_mac, self.lkp_mac, key, key)
        self.dut_macsec.configure(macsec_yaml)
        self.dump_macsec_cfg()
        self.dump_macsec_yaml()

        self.dut_macsec.clear_counters()
        fcs_err_prev = self.dut_atltool.get_msm_counters()['fcserr']
        self.send_macsec_traffic(pkts_sent, pkts_rate, iface=self.MACSEC_IFACE, host=self.lkp_hostname)
        fcs_err_curr = self.dut_atltool.get_msm_counters()['fcserr']
        assert fcs_err_curr - fcs_err_prev == 0

        in_ok_packets = self.dut_macsec.get_stats()['In_ok_pkts']

        assert abs(in_ok_packets - pkts_sent) < dlt

    def test_encrypt_256_key(self):
        log.info("gcm-aes-256 support kernel patch required")
        pytest.skip()

    @idparametrize("mtype", ['da_only', 'sa_only', 'half_da_half_sa', 'ether_type_only',
                             'da_ethertype', 'sa_ethertype', 'da_range'])
    @idparametrize('direction', ['EGRESS', 'INGRESS'])
    def test_prectlf(self, direction, mtype):
        """
        @description: Egress PreCTLF.

        @steps:
        1. Put up a link between LKP and DUT
        2. Configure LKP linux macsec with key encryption.
        3. Configure DUT phy macsec with key encryption. (1 SC and 1 SA related to it. 128 bit key.)
        4. Set up Egress preCTLF table.
        5. For each match type send corresponding packet from DUT to LKP.
        6. Ensure the packet is not encrypted
            - Check Out_ctl_pkts for EGRESS
            - Check In_ctl_pkts for INGRESS
            - ????
        """

        key = "73bd5434ca328f97b456568a67674134"
        pkts_sent = 10000
        pkts_rate = 1000
        pkt_size = 100
        dlt = 30
        cfg_bypass_eth_type = 0x1234
        pkt_bypass_eth_type = 0x888E
        cfg_mac_addr = '00:17:b6:00:00:00'
        if direction == 'EGRESS':
            src_mac = self.dut_mac
            dst_mac = self.lkp_mac
        else:
            src_mac = self.lkp_mac
            dst_mac = self.dut_mac

        match_type_dict = {
            'da_only': 1,
            'sa_only': 2,
            'half_da_half_sa': 3,
            'ether_type_only': 4,
            'da_ethertype': 5,
            'sa_ethertype': 6,
            'da_range': 7
        }
        match_type = match_type_dict[mtype]
        if mtype == 'da_only':
            cfg_mac_addr = dst_mac
        elif mtype == 'sa_only':
            cfg_mac_addr = src_mac
        elif mtype == 'half_da_half_sa':
            cfg_mac_addr = ':'.join(dst_mac.split(':')[3:] + src_mac.split(':')[3:])
        elif mtype == 'ether_type_only':
            cfg_bypass_eth_type = 0x888E
            pkt_bypass_eth_type = 0x888E
        elif mtype == 'da_ethertype':
            cfg_mac_addr = dst_mac
            cfg_bypass_eth_type = 0x888E
            pkt_bypass_eth_type = 0x888E
        elif mtype == 'sa_ethertype':
            cfg_mac_addr = src_mac
            cfg_bypass_eth_type = 0x888E
            pkt_bypass_eth_type = 0x888E
        elif mtype == 'da_range':
            mac_int = int(dst_mac.replace(':', ''), 16) - 10
            mac_hex = "{:012x}".format(mac_int)
            mac_str = ":".join(mac_hex[i:i + 2] for i in range(0, len(mac_hex), 2))
            cfg_mac_addr = mac_str
            cfg_bypass_eth_type = 0x100

        self.setup_linux_macsec(self.MACSEC_IFACE, key)
        self.lkp_ifconfig.wait_link_up()

        macsec_yaml = MacsecTool.gen_config(self.dut_mac, self.lkp_mac, key, key)
        macsec_yaml[direction]['PRECTLF'][0]['MAC_ADDR'] = cfg_mac_addr
        macsec_yaml[direction]['PRECTLF'][0]['ETH_TYPE'] = cfg_bypass_eth_type
        macsec_yaml[direction]['PRECTLF'][0]['MATCH_TYPE'] = match_type
        self.dut_macsec.configure(macsec_yaml)
        self.dump_macsec_cfg()
        self.dump_macsec_yaml()

        l2 = Ether(src=src_mac, dst=dst_mac, type=pkt_bypass_eth_type)
        raw = Raw("\xff" * (pkt_size - len(l2)))
        pkt = l2 / raw

        dut_count_key = 'InPackets' if self.dut_ops.is_linux() else 'ReceivedUnicastPackets'
        lkp_count_key = 'InPackets' if self.lkp_ops.is_linux() else 'ReceivedUnicastPackets'

        if direction == 'EGRESS':
            counters_prev = self.lkp_statistics.get_drv_counters()

            self.dut_macsec.clear_counters()
            self.send_macsec_traffic(pkts_sent, pkts_rate, iface=self.dut_iface, host=None, pkt=pkt)
            fcs_err_prev = self.dut_atltool.get_msm_counters()['fcserr']
            self.send_macsec_traffic(pkts_sent, pkts_rate, iface=self.MACSEC_IFACE, host=self.lkp_hostname)
            fcs_err_curr = self.dut_atltool.get_msm_counters()['fcserr']
            assert fcs_err_curr - fcs_err_prev == 0

            out_ctl_pkts = self.dut_macsec.get_stats()["Out_ctl_pkts"]
            assert abs(out_ctl_pkts - pkts_sent) < dlt

            counters_curr = self.lkp_statistics.get_drv_counters()
            recive_cont = int(counters_curr[lkp_count_key]) - int(counters_prev[lkp_count_key])
            log.info('counters[{}]: {}'.format(lkp_count_key, recive_cont))

            assert abs(recive_cont - pkts_sent) < dlt

        if direction == 'INGRESS':
            counters_prev = self.dut_statistics.get_drv_counters()

            self.dut_macsec.clear_counters()
            fcs_err_prev = self.dut_atltool.get_msm_counters()['fcserr']
            self.send_macsec_traffic(pkts_sent, pkts_rate, iface=self.lkp_iface, host=self.lkp_hostname, pkt=pkt)
            fcs_err_curr = self.dut_atltool.get_msm_counters()['fcserr']
            assert fcs_err_curr - fcs_err_prev == 0

            in_ctl_pkts = self.dut_macsec.get_stats()['In_ctl_pkts']
            assert abs(in_ctl_pkts - pkts_sent) < dlt

            counters_curr = self.dut_statistics.get_drv_counters()
            recive_cont = int(counters_curr[dut_count_key]) - int(counters_prev[dut_count_key])
            log.info('counters[{}]: {}'.format(dut_count_key, recive_cont))

            assert abs(recive_cont - pkts_sent) < dlt

    @idparametrize("state", ['on', 'off'])
    def test_replay_protect(self, state):
        """
        @description: Replay protect

        @steps:
        1. Put up a link between LKP and DUT
        2. Configure LKP linux macsec with key encryption
        3. Configure DUT phy macsec with key encryption.
        4. Enable replay protect.
        5. Set RX packet number to pkts_delay.
        6. Set replay protect window to replay_window
        7. Send pkts_sent packets from LKP to DUT
            Check received traffic on DUT.
                In_ok_pkts = pkts_sent - (pkts_delay - replay_window)
                replay protect: on
                    In_late_pkts = pkts_delay - replay_window
                replay protect: off
                    In_delayed_pkts = pkts_delay - replay_window
        """

        raise Exception('TX stuck, test skipped')

        key = "73bd5434ca328f97b456568a67674134"
        en_protect = 1 if state == 'on' else 0
        pkts_sent = 20000
        pkts_rate = 1000
        pkts_delay = 1000
        replay_window = 500
        dlt = 35

        self.setup_linux_macsec(self.MACSEC_IFACE, key, tx_pn=1)
        self.lkp_ifconfig.wait_link_up()

        macsec_yaml = MacsecTool.gen_config(self.dut_mac, self.lkp_mac, key, key, rx_pn=pkts_delay)
        macsec_yaml['INGRESS']['SC'][0]['PARAMS']['REPLAY_PROTECT'] = en_protect
        macsec_yaml['INGRESS']['SC'][0]['PARAMS']['ANTI_REPLAY_WINDOW'] = replay_window
        self.dut_macsec.configure(macsec_yaml)
        self.dump_macsec_cfg()
        self.dump_macsec_yaml()

        self.dut_macsec.clear_counters()
        fcs_err_prev = self.dut_atltool.get_msm_counters()['fcserr']

        sniffer = Tcpdump(host=self.dut_hostname, port=self.dut_port, timeout=60)

        sniffer.run_async()
        time.sleep(30)

        self.send_macsec_traffic(pkts_sent, pkts_rate, iface=self.MACSEC_IFACE, host=self.lkp_hostname)

        dut_packets = sniffer.join(30)
        wrpcap("packets_dut.pcap", dut_packets)
        shutil.move("packets_dut.pcap", self.test_log_dir)

        sniff_pkt_count = 0
        for pkt in dut_packets:
            if pkt['Ether'].dst.lower() == self.dut_mac.lower():
                sniff_pkt_count += 1

        fcs_err_curr = self.dut_atltool.get_msm_counters()['fcserr']

        stats = self.dut_macsec.get_stats()
        in_ok_packets = stats['In_ok_pkts']
        in_late_pkts = stats['In_late_pkts']
        in_delayed_pkts = stats['In_delayed_pkts']

        log.info('========= TEST RESULT =========')
        log.info('In_ok_pkts: {}'.format(in_ok_packets))
        log.info('In_late_pkts: {}'.format(in_late_pkts))
        log.info('In_delayed_pkts: {}'.format(in_delayed_pkts))
        log.info('Sniffed packets: {}'.format(sniff_pkt_count))
        log.info('FCS errors: {}'.format(fcs_err_curr - fcs_err_prev))

        assert abs(int(in_ok_packets) - (pkts_sent - (pkts_delay - replay_window))) < dlt
        if en_protect:
            assert abs(int(in_late_pkts) - (pkts_delay - replay_window)) < dlt
            assert sniff_pkt_count == in_ok_packets
        else:
            assert abs(int(in_delayed_pkts) - (pkts_delay - replay_window)) < dlt
            assert sniff_pkt_count == in_ok_packets + in_delayed_pkts

        assert fcs_err_curr - fcs_err_prev == 0

    @idparametrize("num_sa", [2, 4])
    def test_multiple_sa_rx(self, num_sa):
        keys = [
            "73bd5434ca328f97b456568a67674000",
            "73bd5434ca328f97b456568a67674111",
            "73bd5434ca328f97b456568a67674222",
            "73bd5434ca328f97b456568a67674333"
        ]
        self.setup_linux_macsec(self.MACSEC_IFACE, keys[0])
        self.lkp_ifconfig.wait_link_up()

        for sa_n in range(1, num_sa):
            add_new_tx_sa = 'sudo ip macsec add {} tx sa {} pn 1 on key 0{} {}'.format(
                self.MACSEC_IFACE, sa_n, sa_n + 1, keys[sa_n])
            Command(cmd=add_new_tx_sa, host=self.lkp_hostname).run()

        macsec_yaml = MacsecTool.gen_config(self.dut_mac, self.lkp_mac, keys[0], keys[0])

        # Disable MAC_DA_MASK to reslove ARP requests
        macsec_yaml['INGRESS']['SC'][0]['PRECLASS'][0]['MAC_DA_MASK'] = 0
        macsec_yaml['EGRESS']['SC'][0]['PRECLASS'][0]['MAC_DA_MASK'] = 0

        for sa_n in range(1, num_sa):
            # add second rx sa on dut
            new_sa = dict(
                NEXT_PN=1,
                KEY=keys[sa_n],
            )
            macsec_yaml['INGRESS']['SC'][0]['SA'].append(new_sa)
        self.dut_macsec.configure(macsec_yaml)
        self.dump_macsec_cfg()
        self.dump_macsec_yaml()

        for sa_n in range(num_sa):
            # switch sa on lkp
            log.info('>>> Switch TX SA on LKP from {} to {}'.format(sa_n - 1, sa_n))
            switch_sa_cmd = 'sudo ip link set {} type macsec encodingsa {}'.format(self.MACSEC_IFACE, sa_n)
            Command(cmd=switch_sa_cmd, host=self.lkp_hostname).run()

            try:
                self.dut_macsec.clear_counters()
                assert self.ping(from_host=self.lkp_hostname, to_host=self.DUT_IP_ADDRESS, number=10)
            finally:
                self.dut_macsec.get_stats(index='{}.0.0'.format(num_sa))

    @idparametrize("num_sa", [2, 4])
    def test_multiple_sa_tx(self, num_sa):
        keys = [
            "73bd5434ca328f97b456568a67674000",
            "73bd5434ca328f97b456568a67674111",
            "73bd5434ca328f97b456568a67674222",
            "73bd5434ca328f97b456568a67674333"
        ]

        self.setup_linux_macsec(self.MACSEC_IFACE, keys[0])
        self.lkp_ifconfig.wait_link_up()

        for sa_n in range(1, num_sa):
            add_new_rx_sa = 'sudo ip macsec add {} rx address {} port 1 sa {} pn 1 on key 0{} {}'.format(
                self.MACSEC_IFACE, self.dut_mac, sa_n, sa_n,  keys[sa_n])
            Command(cmd=add_new_rx_sa, host=self.lkp_hostname).run()

        macsec_yaml = MacsecTool.gen_config(self.dut_mac, self.lkp_mac, keys[0], keys[0])

        # Disable MAC_DA_MASK to reslove ARP requests
        macsec_yaml['INGRESS']['SC'][0]['PRECLASS'][0]['MAC_DA_MASK'] = 0
        macsec_yaml['EGRESS']['SC'][0]['PRECLASS'][0]['MAC_DA_MASK'] = 0

        for sa_n in range(1, num_sa):
            # add second tx sa on dut
            new_sa = dict(
                NEXT_PN=1,
                KEY=keys[sa_n],
            )
            macsec_yaml['EGRESS']['SC'][0]['SA'].append(new_sa)
        self.dut_macsec.configure(macsec_yaml)
        self.dump_macsec_cfg()
        self.dump_macsec_yaml()

        for sa_n in range(num_sa):
            # switch sa on dut
            log.info('>>> Switch TX SA on DUT from {} to {}'.format(sa_n - 1, sa_n))
            self.dut_macsec.curr_sa(sa_n)

            try:
                self.dut_macsec.clear_counters()
                assert self.ping(from_host=self.lkp_hostname, to_host=self.DUT_IP_ADDRESS, number=10)
            finally:
                self.dut_macsec.get_stats(index='0.{}.0'.format(num_sa))

    def test_multiple_sc_tx(self):
        """
        @description: MacSec setup with 2 TX SC

        @steps:
        1. Put up a link between LKP and DUT
        2. Configure LKP linux macsec with key encryption.
        3. Configure DUT phy macsec with key encryption. 2 TX SC and 1 SA related to it. 128 bit key.
        4. Send traffic from DUT to LKP via 0 SC
        5. Check counters related to 0 SC
        6. Send traffic from DUT to LKP via 1 SC
        7. Check counters related to 1 SC
        """

        keys = [
            "73bd5434ca328f97b456568a67674000",
            "73bd5434ca328f97b456568a67674111",
            "73bd5434ca328f97b456568a67674222",
            "73bd5434ca328f97b456568a67674333"
        ]

        pkts_sent = 10000
        pkts_rate = 1000

        self.setup_linux_macsec(self.MACSEC_IFACE, keys[0])
        self.lkp_ifconfig.wait_link_up()

        dut_dummy_mac = "00:17:b6:01:02:03"
        lkp_dummy_mac = "00:17:b6:11:22:33"

        macsec_yaml = MacsecTool.gen_config(dut_dummy_mac, lkp_dummy_mac, keys[1], keys[1])
        macsec_yaml2 = MacsecTool.gen_config(self.dut_mac, self.lkp_mac, keys[0], keys[0])

        macsec_yaml['EGRESS']['SC'].append(macsec_yaml2['EGRESS']['SC'][0])

        self.dut_macsec.configure(macsec_yaml)
        self.dump_macsec_cfg()
        self.dump_macsec_yaml()

        # Send packets via SC 0
        size = 100
        l2 = Ether(src=dut_dummy_mac, dst=lkp_dummy_mac)
        raw = Raw("\xff" * (size - len(l2)))
        pkt = l2 / raw

        self.dut_macsec.clear_counters()
        self.send_macsec_traffic(pkts_sent, pkts_rate, iface=self.dut_iface, host=self.dut_hostname, pkt=pkt)
        sc_0_sa_0_stats = self.dut_macsec.get_stats(index='0.0.0')
        sc_1_sa_0_stats = self.dut_macsec.get_stats(index='0.1.1')

        assert sc_0_sa_0_stats['Out_sa_protected2_pkts'] == pkts_sent
        assert sc_0_sa_0_stats['Out_sa_encrypted_pkts'] == pkts_sent
        assert sc_0_sa_0_stats['Out_sc_encrypted_pkts'] == pkts_sent

        assert sc_1_sa_0_stats['Out_sa_protected2_pkts'] == 0
        assert sc_1_sa_0_stats['Out_sa_encrypted_pkts'] == 0
        assert sc_1_sa_0_stats['Out_sc_encrypted_pkts'] == 0

        # Send packets via SC 1
        size = 100
        l2 = Ether(src=self.dut_mac, dst=self.lkp_mac)
        raw = Raw("\xff" * (size - len(l2)))
        pkt = l2 / raw

        self.dut_macsec.clear_counters()
        self.send_macsec_traffic(pkts_sent, pkts_rate, iface=self.dut_iface, host=self.dut_hostname, pkt=pkt)

        sc_0_sa_0_stats = self.dut_macsec.get_stats(index='0.0.0')
        sc_1_sa_0_stats = self.dut_macsec.get_stats(index='0.1.1')

        assert sc_0_sa_0_stats['Out_sa_protected2_pkts'] == 0
        assert sc_0_sa_0_stats['Out_sa_encrypted_pkts'] == 0
        assert sc_0_sa_0_stats['Out_sc_encrypted_pkts'] == 0

        assert sc_1_sa_0_stats['Out_sa_protected2_pkts'] == pkts_sent
        assert sc_1_sa_0_stats['Out_sa_encrypted_pkts'] == pkts_sent
        assert sc_1_sa_0_stats['Out_sc_encrypted_pkts'] == pkts_sent

    @idparametrize('an_roll', ['on', 'off'])
    def test_sa_saturation(self, an_roll):
        """
        @description: SA saturation.

        @steps:
        1. Put up a link between LKP and DUT
        2. Configure LKP linux macsec with key encryption.
        3. Configure DUT phy macsec with key encryption. 1 SC and 2 SAs related to it on DUT and LKP. 128 bit key.
        4. Set current active SA 0 on DUT and LKP
        5. Set packet number to high limit - pkts_window to SA 0 and SA 1 on DUT.

        6. Clear macsec counters on DUT
        7. Send pkts_window + pkts_diff packets from DUT to LKP.
        8. Check counters SA 0 Out_sa_encrypted_pkts == pkts_window
        9. Check counters SA 1 Out_sa_encrypted_pkts == pkts_diff
        10. Check counters SC 1 Out_sc_encrypted_pkts == pkts_window + pkts_diff

        11. Switch activ SA on DUT from 0 to 1
        12. Clear macsec counters on DUT
        13. Send pkts_window packets from DUT to LKP.
        Association roll over is on.
            14. Check counters SA 0 Out_sa_encrypted_pkts == pkts_diff
            15. Check counters SA 1 Out_sa_encrypted_pkts == pkts_window - pkts_diff
            16. Check counters SC 1 Out_sc_encrypted_pkts == pkts_window
            (SA 0 key has roll over)
        Association roll over is off.
            14. Check counters SA 0 Out_sa_encrypted_pkts == 0
            15. Check counters SA 1 Out_sa_encrypted_pkts == pkts_window - pkts_diff
            16. Check counters SC 1 Out_sc_encrypted_pkts == pkts_window - pkts_diff
            (SA 0 key has not roll over)
        """

        keys = [
            "73bd5434ca328f97b456568a67674000",
            "73bd5434ca328f97b456568a67674111",
        ]
        pkts_window = 1000
        pkts_diff = 200
        dlt = 100
        next_pn = 0xFFFFFFFF - pkts_window
        pkts_sent_1 = pkts_window + pkts_diff
        pkts_sent_2 = pkts_window
        pkts_rate = 100
        pkt_size = 100

        self.setup_linux_macsec(self.MACSEC_IFACE, keys[0])
        self.lkp_ifconfig.wait_link_up()

        add_new_rx_sa = 'sudo ip macsec add {} rx address {} port 1 sa 1 pn 1 on key 02 {}'.format(
            self.MACSEC_IFACE, self.dut_mac, keys[1])
        Command(cmd=add_new_rx_sa, host=self.lkp_hostname).run()

        macsec_yaml = MacsecTool.gen_config(self.dut_mac, self.lkp_mac, keys[0], keys[0])

        # Disable MAC_DA_MASK to reslove ARP requests
        macsec_yaml['INGRESS']['SC'][0]['PRECLASS'][0]['MAC_DA_MASK'] = 0
        macsec_yaml['EGRESS']['SC'][0]['PRECLASS'][0]['MAC_DA_MASK'] = 0

        # Set Association roll over to 0 (disable).
        macsec_yaml['EGRESS']['SC'][0]['PARAMS']['AN_ROLL'] = 1 if an_roll == 'on' else 0
        macsec_yaml['EGRESS']['SC'][0]['SA'][0]['NEXT_PN'] = next_pn

        # add second tx sa on dut
        new_sa = dict(
            NEXT_PN=next_pn,
            KEY=keys[1],
        )
        macsec_yaml['EGRESS']['SC'][0]['SA'].append(new_sa)
        self.dut_macsec.configure(macsec_yaml)
        self.dump_macsec_cfg()
        self.dump_macsec_yaml()

        l2 = Ether(src=self.dut_mac, dst=self.lkp_mac)
        raw = Raw("\xff" * (pkt_size - len(l2)))
        pkt = l2 / raw

        self.dut_macsec.clear_counters()
        fcs_err_prev = self.dut_atltool.get_msm_counters()['fcserr']
        self.send_macsec_traffic(pkts_sent_1, pkts_rate, iface=self.dut_iface, host=None, pkt=pkt)
        fcs_err_curr = self.dut_atltool.get_msm_counters()['fcserr']
        assert fcs_err_curr - fcs_err_prev == 0

        log.info('>>> SA 0 stats')
        out_sa_encrypted_pkts_sa_0 = int(self.dut_macsec.get_stats(index='0.0.0')['Out_sa_encrypted_pkts'])
        log.info('>>> SA 1 stats')
        sc_0_sa_1_stats = self.dut_macsec.get_stats(index='0.1.0')
        out_sa_encrypted_pkts_sa_1 = int(sc_0_sa_1_stats['Out_sa_encrypted_pkts'])
        out_sc_encrypted_pkts_sc_0 = int(sc_0_sa_1_stats['Out_sc_encrypted_pkts'])

        assert abs(out_sa_encrypted_pkts_sa_0 - pkts_window) < dlt
        assert abs(out_sa_encrypted_pkts_sa_1 - (pkts_sent_1 - pkts_window)) < dlt
        assert abs(out_sc_encrypted_pkts_sc_0 - pkts_sent_1) < dlt

        # switch sa on dut
        self.dut_macsec.curr_sa(1)

        self.dut_macsec.clear_counters()
        fcs_err_prev = self.dut_atltool.get_msm_counters()['fcserr']
        self.send_macsec_traffic(pkts_sent_2, pkts_rate, iface=self.dut_iface, host=None, pkt=pkt)
        fcs_err_curr = self.dut_atltool.get_msm_counters()['fcserr']
        assert fcs_err_curr - fcs_err_prev == 0

        log.info('>>> SA 0 stats')
        out_sa_encrypted_pkts_sa_0 = int(self.dut_macsec.get_stats(index='0.0.0')['Out_sa_encrypted_pkts'])
        log.info('>>> SA 1 stats')
        sc_0_sa_1_stats = self.dut_macsec.get_stats(index='0.1.0')
        out_sa_encrypted_pkts_sa_1 = int(sc_0_sa_1_stats['Out_sa_encrypted_pkts'])
        out_sc_encrypted_pkts_sc_0 = int(sc_0_sa_1_stats['Out_sc_encrypted_pkts'])

        if an_roll == 'on':
            assert abs(out_sa_encrypted_pkts_sa_0 - pkts_diff) < dlt
            assert abs(out_sa_encrypted_pkts_sa_1 - (pkts_window - pkts_diff)) < dlt
            assert abs(out_sc_encrypted_pkts_sc_0 - pkts_sent_2) < dlt
        else:
            assert abs(out_sa_encrypted_pkts_sa_0) < dlt
            assert abs(out_sa_encrypted_pkts_sa_1 - (pkts_window - pkts_diff)) < dlt
            assert abs(out_sc_encrypted_pkts_sc_0 - (pkts_sent_2 - pkts_diff)) < dlt


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
