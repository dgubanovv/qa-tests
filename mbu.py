import os
import tempfile
import threading
import time
import Queue
import subprocess
import sys

import pytest

import tools.driver
from infra.test_base import TestBase
from tools.constants import CARD_BERMUDA_A0, CARD_BERMUDA_B0, CARD_NIKKI, FELICITY_CARDS
from tools.mbuper import download_mbu
from tools.utils import get_atf_logger
from tools.lom import LightsOutManagement

log = get_atf_logger()


def setup_module(module):
    pass
    # import tools._test_setup  # uncomment for manual test setup
    # os.environ["TEST"] = "offloads"


class TestMbu(TestBase):
    """
    @description: The MBU test perform low level testing of different components of Atlantic chip.

    @setup: Aquantia device with Atlantic chip onboard.
    """

    MBU_TIMEOUT = 10 * 60  # 10 minutes by default
    mbu_dir = None

    @classmethod
    def setup_class(cls):
        super(TestMbu, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            mbu_dir = download_mbu(cls.mbu_version, cls.working_dir)
            cls.mbu_dir = mbu_dir

            cls.log_local_dir = os.path.join(mbu_dir, "logs")
            cls.dut_driver = tools.driver.Driver(port=cls.dut_port,
                                                 drv_type="diag",
                                                 version="latest")
            cls.dut_driver.install()
            cls.mbu_timeout = int(os.environ.get("MBU_TIMEOUT", TestMbu.MBU_TIMEOUT))
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def setup_method(self, method):
        super(TestMbu, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)

        self.params = {}
        self.params["test_num"] = -1
        for k, v in os.environ.items():
            if k.startswith('MBU_') and k != 'MBU_VERSION':
                if k == "MBU_HW_OPTIONS":
                    # hw_options must be lowercase
                    self.params[k.lower()[4:]] = v
                else:
                    self.params[k[4:]] = v

    def teardown_method(self, method):
        super(TestMbu, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()

    def run_mbu_test(self, script):
        def enqueue_output(out, queue):
            for line in iter(out.readline, b''):
                queue.put(line)
            out.close()

        log.info("Test parameters:")
        for k, v in self.params.items():
            log.info("{} = {}".format(k, v))

        file_to_exec = os.path.join(self.mbu_dir, "file_to_exec.txt")
        log.info("Preparing file %s", file_to_exec)

        # Extract timeout before file creation
        tmo = self.params.pop("timeout", self.mbu_timeout)

        scripts_path = os.path.join(os.environ["ATF_HOME"],
                                    "qa-tests/tools/beton")
        script_full_path = os.path.join(scripts_path, script)

        with open(file_to_exec, "w") as f:
            for k, v in self.params.items():
                f.write("{}={}\n".format(k, v))
            # tmp_test_file.write("mac.reset\n")
            f.write("mac.init\n")
            f.write("mac.uninit\n")
            f.write("PWD={}\n".format(scripts_path))
            f.write("exec {}".format(script_full_path))

        log.info("Execution file content:")
        with open(file_to_exec, "r") as f:
            lines = f.readlines()
            for line in lines:
                log.info(line.rstrip("\r\n"))

        start_time = time.time()
        mbu_proc = subprocess.Popen(
            "python main.py -p {} -i -f {}".format(self.dut_port, file_to_exec),
            shell=True,
            stdout=subprocess.PIPE,
            bufsize=1,
            cwd=self.mbu_dir)

        q = Queue.Queue()
        t = threading.Thread(target=enqueue_output, args=(mbu_proc.stdout, q))
        t.daemon = True
        t.start()

        passed = False
        exceptions = False
        while mbu_proc.poll() is None:
            time.sleep(0.5)
            while not q.empty():
                log_line = q.get(block=False)
                log.info(log_line.rstrip("\r\n"))

                if 'exception' in log_line.lower():
                    exceptions = True
                if not exceptions and "[PASSED]" in log_line:
                    passed = True

                # TODO: hw error check in logs

            if time.time() - start_time > tmo:
                log.error("Timeout %s second is reached, terminating!", tmo)
                # TODO: make it killable on Linux
                out = subprocess.check_output('TASKKILL /T /F /PID {}'.
                                              format(mbu_proc.pid))
                log.info("Taskkill output:")
                sys.stdout.write(out)
                sys.stdout.flush()
                time.sleep(1)
                self.dut_driver.reset_pci_root_port()
                break

        assert passed is True

    # NOTE: all test names MUST begin with test_mbu, after that
    # test group should be specified, then short test purpose

    # OFFLOADS TEST GROUP

    def test_mbu_offloads_rx_checksum(self):
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Offloads/rxChecksumOffload.txt")

    def test_mbu_offloads_rx_header_split(self):
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Offloads/rxHeaderSplitTest.txt")

    def test_mbu_offloads_tx_zero_udp_checksum(self):
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Offloads/txZeroUDPChecksumOffload.txt")

    def test_mbu_offloads_tx_checksum(self):
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Offloads/txChecksumOffload.txt")

    def test_mbu_offloads_fragmented_udp_checksum(self):
        self.params["useVlan"] = True
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Offloads/rxFragmentedUdpChecksumOffload.txt")

    def test_mbu_offloads_rx_descriptor_field(self):
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.params["queue"] = 0
        self.run_mbu_test("Mngif2/rxDescFieldTest.txt")

    def test_mbu_offloads_rx_descriptor_rss_type(self):
        self.params["txRingNo"] = 0
        self.params["maxtc"] = 8
        self.run_mbu_test("Offloads/rxDescFieldRssType.txt")

    def test_mbu_offloads_packet_rss_check(self):
        self.params["txRingNo"] = 0
        self.params["maxtc"] = 8
        self.run_mbu_test("Packet/rssCheck.txt")

    def test_mbu_offloads_tx_ip_with_option(self):
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Offloads/txOffloadIPWithOption.txt")

    def test_mbu_offloads_rss_hash_ndis(self):
        self.run_mbu_test("Packet/rxRssHashNDISPacket.txt")

    def test_mbu_offloads_rss_hash_extended(self):
        self.run_mbu_test("Packet/rxRssHashExtended.txt")

    # def test_mbu_offloads_rx_rss_hash(self):
    #     self.run_mbu_test("Offloads/rxRssHash.txt")

    def test_mbu_offloads_double_vlan_rss(self):
        self.params["seed"] = 1
        self.params["itr"] = 15
        self.run_mbu_test("Packet/rxDoubleVlanRSS.txt")

    def test_mbu_offloads_vlan_tag_multiple_packet(self):
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Packet/vlanTagMultiplePacket.txt")

    def test_mbu_offloads_header_split_whql(self):
        self.run_mbu_test("Offloads/rxHeaderSplitWhql.txt")

    def test_mbu_offloads_tx_zero_tcp_checksum(self):
        self.run_mbu_test("Offloads/txZeroTCPChecksumOffload.txt")

    # RX FILTERS TEST GROUP

    def test_mbu_rx_filters_ext_overflow_unicast_filter(self):
        self.params["queue"] = 0
        self.params["filterUnicastMngQueue"] = 0
        self.params["filterUnicastIndex"] = 0
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rxExtOverflowUnicastFilterTest.txt")

    def test_mbu_rx_filters_estat_bit_set(self):
        self.params["queue"] = 0
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rxestatBitTest.txt")

    def test_mbu_rx_filters_vlan_untagged(self):
        self.params["queue"] = 0
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rxVlanFilterTestUntagged.txt")

    def test_mbu_rx_filters_vlan_broadcast(self):
        self.run_mbu_test("Mngif2/rxVlanFilterTestBroadcast.txt")

    def test_mbu_rx_filters_vlan_multicast(self):
        self.run_mbu_test("Mngif2/rxVlanFilterTestMulticast.txt")

    def test_mbu_rx_filters_vlan_all_multicast(self):
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rxFilterTestAllMulticast.txt")

    def test_mbu_rx_filters_multicast_filter_for_unicast(self):
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rxMulticastFilterFortUnicastTest.txt")

    def test_mbu_rx_filters_broadcast(self):
        self.params["queue"] = 0
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rxBroadcastFilterTest.txt")

    def test_mbu_rx_filters_ethertype(self):
        self.params["queue"] = 0
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rxEthertypeFilterTest.txt")

    # def test_mbu_rx_filters_l3l4(self):
    #     self.params["queue"] = 0
    #     self.params["txRingNo"] = 0
    #     self.params["rxRingNo"] = 0
    #     self.params["vlanMode"] = False
    #     self.run_mbu_test("Mngif2/rxL3L4FilterTest.txt")

    def test_mbu_rx_filters_l3l4_ipv6(self):
        self.params["queue"] = 0
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.params["vlanMode"] = True
        self.run_mbu_test("Mngif2/rxL3L4FilterTestIpv6.txt")

    def test_mbu_rx_filters_multicast(self):
        self.params["queue"] = 0
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.params["tests"] = [
            [17, 0, 0, 0, 0, 4095],
            [0, 34, 0, 0, 1, 2730],
            [0, 0, 68, 0, 2, 0],
            [0, 0, 0, 136, 3, 1365]
        ]
        self.run_mbu_test("Mngif2/rxMulticastFilterTest.txt")

    def test_mbu_rx_filters_unicast(self):
        self.params["queue"] = 0
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.params["tests"] = [
            [286331153, 0, 0, 0],
            [0, 572662306, 0, 0],
            [0, 0, 1145324612, 0],
            [0, 0, 0, 2290649224]
        ]
        self.run_mbu_test("Mngif2/rxUnicastFilterTest.txt")

    # def test_mbu_rx_filters_vlan(self):
    #     self.params["queue"] = 0
    #     self.params["txRingNo"] = 0
    #     self.params["rxRingNo"] = 0
    #     self.params["vlanMode"] = 0
    #     self.params["tests"] = [
    #         [4369, 0, 0, 0, 0, 33536],
    #         [0, 8738, 0, 0, 1, 33536],
    #         [0, 0, 17476, 0, 0, 33280],
    #         [0, 0, 0, 34952, 0, 33280]
    #     ]
    #     self.run_mbu_test("Mngif2/rxVlanFilterTest.txt")

    # def test_mbu_rx_filters_l3l4_fragmented(self):
    #     self.run_mbu_test("Mngif2/rxL3L4FilterTestfragmented.txt")

    def test_mbu_rx_filters_l3l4_opts(self):
        self.run_mbu_test("Mngif2/rxL3L4FilterTestopts.txt")

    def test_mbu_rx_filters_l3l4_ipv6_opts(self):
        self.run_mbu_test("Mngif2/rxL3L4FilterTestIpv6opts.txt")

    def test_mbu_rx_filters_l3l4_ipv6_fragmented(self):
        self.run_mbu_test("Mngif2/rxL3L4FilterTestIpv6fragmented.txt")

    # INJECTOR-EXTRACTOR TEST GROUP

    # def test_mbu_inj_ext_rx_tpo_checksum(self):
    #     self.params["queue"] = 0
    #     self.params["extType"] = "rx"
    #     self.params["txRingNo"] = 0
    #     self.run_mbu_test("Mngif2/tpoExtChecksumTest.txt")

    # def test_mbu_inj_ext_tx_tpo_checksum(self):
    #     self.params["queue"] = 0
    #     self.params["extType"] = "tx"
    #     self.params["txRingNo"] = 0
    #     self.run_mbu_test("Mngif2/tpoExtChecksumTest.txt")

    def test_mbu_inj_ext_rx_checksum(self):
        self.params["queue"] = 0
        self.params["injType"] = "rx"
        self.params["queueActive"] = [1, 0]
        self.params["extType"] = "rx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/tpoExtChecksumIpv6Test.txt")

    def test_mbu_inj_ext_tx_checksum(self):
        self.params["queue"] = 0
        self.params["injType"] = "rx"
        self.params["queueActive"] = [1, 0]
        self.params["extType"] = "tx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/tpoExtChecksumIpv6Test.txt")

    # def test_mbu_inj_ext_large_traffic(self):
    #     self.params["extType"] = "tx"
    #     self.run_mbu_test("Mngif2/extLargeTrafficTest.txt")

    def test_mbu_inj_ext_overflow_rro(self):
        self.params["queueActive"] = [1, 0]
        self.params["hw_options"] = "B0RRO"
        self.params["extType"] = "rx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/extOverflowTestRRO.txt")

    def test_mbu_inj_ext_rx_large_packet(self):
        self.params["queue"] = 0
        self.params["packetMaxSizeKB"] = 1
        self.params["injType"] = "rx"
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rpbInjLargePacketTest.txt")

    def test_mbu_inj_ext_tx_large_packet(self):
        self.params["queue"] = 0
        self.params["packetMaxSizeKB"] = 1
        self.params["injType"] = "tx"
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rpbInjLargePacketTest.txt")

    def test_mbu_inj_ext_rx_packet_more_2048_seg(self):
        self.params["segCount"] = 1
        self.params["queueActive"] = [1, 0]
        self.params["extType"] = "rx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/extLargePacketTestMoreThan2048.txt")

    def test_mbu_inj_ext_tx_packet_more_2048_seg(self):
        self.params["segCount"] = 1
        self.params["queueActive"] = [1, 0]
        self.params["extType"] = "tx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/extLargePacketTestMoreThan2048.txt")

    def test_mbu_inj_ext_rx_packet_more_2048(self):
        self.params["queueActive"] = [1, 0]
        self.params["injType"] = "rx"
        self.params["rxRingNo"] = 0
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/rpbInjLargePacketTestMoreThan2048.txt")

    def test_mbu_inj_ext_tx_packet_more_2048(self):
        self.params["queueActive"] = [1, 0]
        self.params["injType"] = "tx"
        self.params["rxRingNo"] = 0
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/rpbInjLargePacketTestMoreThan2048.txt")

    def test_mbu_inj_ext_extractor_rx_min_test(self):
        self.params["queue"] = 0
        self.params["extType"] = "rx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/extMinTest.txt")

    def test_mbu_inj_ext_extractor_tx_min_test(self):
        self.params["queue"] = 0
        self.params["rxRingNo"] = 0
        self.params["extType"] = "tx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/extMinTest.txt")

    def test_mbu_inj_ext_injector_rx_min_test(self):
        self.params["queue"] = 0
        self.params["injType"] = "rx"
        self.params["rxRingNo"] = 0
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/injMinTest.txt")

    def test_mbu_inj_ext_injector_tx_min_test(self):
        self.params["queue"] = 0
        self.params["injType"] = "tx"
        self.params["rxRingNo"] = 0
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/injMinTest.txt")

    def test_mbu_inj_ext_rx_parity(self):
        self.params["queueActive"] = [1, 0]
        self.params["queue"] = 0
        self.params["segCount"] = 1
        self.params["extType"] = "rx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/extParityTest.txt")

    # def test_mbu_inj_ext_tx_parity(self):
    #     self.params["queueActive"] = [1, 0]
    #     self.params["queue"] = 0
    #     self.params["segCount"] = 1
    #     self.params["extType"] = "tx"
    #     self.params["txRingNo"] = 0
    #     self.run_mbu_test("Mngif2/extParityTest.txt")

    def test_mbu_inj_ext_rx_overflow(self):
        self.params["queueActive"] = [1, 0]
        self.params["segCount"] = 1
        self.params["extType"] = "rx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/extOverflowTest.txt")

    def test_mbu_inj_ext_tx_overflow(self):
        self.params["queueActive"] = [1, 0]
        self.params["segCount"] = 1
        self.params["extType"] = "tx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/extOverflowTest.txt")

    def test_mbu_inj_ext_rx_large_2048(self):
        self.params["segCount"] = 1
        self.params["queueActive"] = [1, 0]
        self.params["extType"] = "rx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/extLargePacketTest2048.txt")

    def test_mbu_inj_ext_tx_large_2048(self):
        self.params["segCount"] = 1
        self.params["queueActive"] = [1, 0]
        self.params["extType"] = "tx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/extLargePacketTest2048.txt")

    def test_mbu_inj_ext_rx_rpb_parity(self):
        self.params["queue"] = 0
        self.params["injType"] = "rx"
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rpbInjParityTest.txt")

    def test_mbu_inj_ext_tx_rpb_parity(self):
        self.params["queue"] = 0
        self.params["injType"] = "tx"
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/rpbInjParityTest.txt")

    def test_mbu_inj_ext_host_and_mif(self):
        self.params["injType"] = "tx"
        self.run_mbu_test("Mngif2/injHostAndMIFPktTest.txt")

    def test_mbu_inj_ext_arp_filter(self):
        self.params["queue"] = 0
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/txExtArpFilterTest.txt")

    def test_mbu_inj_ext_ip_filter(self):
        self.params["queue"] = 0
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/txExtIpFilterTest.txt")

    def test_mbu_inj_ext_mac_and_ip_filters(self):
        self.params["queue"] = 0
        self.params["txRingNo"] = 0
        self.run_mbu_test("Mngif2/txExtMacAndIpFiltersTest.txt")

    def test_mbu_inj_ext_mac_filter(self):
        self.params["txRingNo"] = "0"
        self.run_mbu_test("Mngif2/txExtMacFilterTest.txt")

    def test_mbu_inj_ext_rx_rpb_var_len(self):
        self.params["queue"] = 0
        self.params["packetLenStep"] = 1
        self.params["endPacketLen"] = 520
        self.params["startPacketLen"] = 64
        self.params["injType"] = "rx"
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rpbInjVarLenTest.txt")

    def test_mbu_inj_ext_tx_rpb_var_len(self):
        self.params["queue"] = 0
        self.params["packetLenStep"] = 1
        self.params["endPacketLen"] = 520
        self.params["startPacketLen"] = 64
        self.params["injType"] = "tx"
        self.params["txRingNo"] = 0
        self.params["rxRingNo"] = 0
        self.run_mbu_test("Mngif2/rpbInjVarLenTest.txt")

    def test_mbu_inj_ext_wol_rro(self):
        self.run_mbu_test("Mngif2/extTestWoLRRO.txt")

    # MCP TEST GROUP

    def test_mbu_mcp_interrupt_exception(self):
        self.run_mbu_test("Mips/mcpInterruptException.txt")

    def test_mbu_mcp_memory(self):
        self.run_mbu_test("Mips/mipsMemory.txt")

    def test_mbu_mcp_firmware_q0_rx(self):
        self.params["queue"] = 0
        self.params["injType"] = "rx"
        self.params["loopbackType"] = 0
        self.params["extType"] = "tx"
        self.run_mbu_test("Mips/mipsFirmware.txt")

    def test_mbu_mcp_firmware_q1_rx(self):
        self.params["queue"] = 1
        self.params["injType"] = "rx"
        self.params["loopbackType"] = 0
        self.params["extType"] = "tx"
        self.run_mbu_test("Mips/mipsFirmware.txt")

    def test_mbu_mcp_firmware_q0_tx(self):
        self.params["queue"] = 0
        self.params["injType"] = "tx"
        self.params["loopbackType"] = 0
        self.params["extType"] = "rx"
        self.run_mbu_test("Mips/mipsFirmware.txt")

    def test_mbu_mcp_firmware_q1_tx(self):
        self.params["queue"] = 1
        self.params["injType"] = "tx"
        self.params["loopbackType"] = 0
        self.params["extType"] = "rx"
        self.run_mbu_test("Mips/mipsFirmware.txt")

    def test_mbu_mcp_ram_size(self):
        self.run_mbu_test("Mips/ramSizeTest.txt")

    # LSO-LRO TEST GROUP

    def test_mbu_lso_lro_tx_batch(self):
        self.run_mbu_test("Offloads/txLsoBatch.txt")

    def test_mbu_lso_lro_rx_short(self):
        self.params["givenTxHeaderLen"] = 54
        self.params["givenTxPacketLen"] = 294
        self.params["givenTxPacketCount"] = 6
        self.params["givenTxPayloadLen"] = 240
        self.run_mbu_test("Offloads/rxLroShort.txt")

    def test_mbu_lso_lro_rx_eviction(self):
        self.run_mbu_test("Offloads/rxLroEviction.txt")

    def test_mbu_lso_lro_rx_header_modifier(self):
        self.run_mbu_test("Offloads/rxLroHeaderModifier.txt")

    def test_mbu_lso_lro_rx_long(self):
        self.run_mbu_test("Offloads/rxLroLong.txt")

    def test_mbu_lso_lro_tx_segmentation(self):
        self.params["lsoMaxSize"] = 65535
        self.params["minMSS"] = 4
        self.params["maxPortNum"] = 65535
        self.params["maxMSS"] = 1994
        self.params["minPortNum"] = 1
        self.run_mbu_test("Offloads/txSegmentationOffload.txt")

    def test_mbu_lso_lro_tx_lso(self):
        self.params["packetLengthVariationsCount"] = 20
        self.run_mbu_test("Offloads/txLargeSegmentOffload.txt")

    def test_mbu_lso_lro_rx_lso(self):
        self.params["itr"] = 5
        self.run_mbu_test("Offloads/rxLargeSegmentOffload.txt")

    # def test_mbu_lso_lro_rx_tcp_syn(self):
    #     self.run_mbu_test("Packet/rxTCPsyn.txt")

    # def test_mbu_lso_lro_rx_payload_compare_ipv4_not_usual(self):
    #     self.params["maxPacketCountPerFlow"] = 10
    #     self.params["useIPv6"] = False
    #     self.params["useUsualPackets"] = False
    #     self.params["seed"] = 1
    #     self.params["flowCount"] = 8
    #     self.run_mbu_test("Offloads/rxLroPayloadCompare.txt")

    # def test_mbu_lso_lro_rx_payload_compare_ipv6_not_usual(self):
    #     self.params["maxPacketCountPerFlow"] = 2
    #     self.params["useIPv6"] = True
    #     self.params["useUsualPackets"] = False
    #     self.params["seed"] = 333
    #     self.params["flowCount"] = 8
    #     self.run_mbu_test("Offloads/rxLroPayloadCompare.txt")

    # def test_mbu_lso_lro_rx_payload_compare_ipv4_usual(self):
    #     self.params["maxPacketCountPerFlow"] = 2
    #     self.params["useIPv6"] = False
    #     self.params["useUsualPackets"] = True
    #     self.params["seed"] = 555
    #     self.params["flowCount"] = 8
    #     self.run_mbu_test("Offloads/rxLroPayloadCompare.txt")

    # def test_mbu_lso_lro_rx_payload_compare_ipv6_usual(self):
    #     self.params["maxPacketCountPerFlow"] = 2
    #     self.params["useIPv6"] = True
    #     self.params["useUsualPackets"] = True
    #     self.params["seed"] = 555
    #     self.params["flowCount"] = 8
    #     self.run_mbu_test("Offloads/rxLroPayloadCompare.txt")

    # FLASH TEST GROUP

    def test_mbu_flash_ncb_test(self):
        self.run_mbu_test("Flash/flashNCBTest.txt")

    def test_mbu_flash_jedec_id(self):
        self.run_mbu_test("Flash/flashJedecId.txt")

    def test_mbu_flash_erase_sector_page(self):
        self.params["blockSizeK"] = 4
        self.params["flashSizeBytes"] = "0x200000"
        self.run_mbu_test("Flash/flashEraseSectorPage.txt")

    def test_mbu_flash_random_data(self):
        self.run_mbu_test("Flash/flashRandomDataTest.txt")

    # BUGS TEST GROUP

    def test_mbu_bug_radar_1707__100M(self):
        """
        @description: This subtest verifies interrupt routine on 100M link speed.

        @steps:
        1. Set 100M link speed.
        2. Apply needed capabilities: external loopback, pause and asymmetric pause and transaction id.
        3. Wait for link up.
        4. Make sure that capabilities were applied correctly.
        5. Make sure that ISR counter is increased.
        6. Apply link drop capability.
        7. Make sure that link has ben dropped.
        8. Verify that ISR counter is increased.
        9. Remove link drop bit.
        10. Repeat 1-9 steps in the cycle 50 times.

        @result: All checks are passed.
        @duration: 10 minutes.
        """

        if self.dut_fw_card in FELICITY_CARDS:
            pytest.skip()

        self.params["timeout"] = 30000
        self.params["link_speed"] = '100M'
        self.run_mbu_test("Bugs/radar1707.txt")

    def test_mbu_bug_radar_1707__1G(self):
        """
        @description: This subtest verifies interrupt routine on 1G link speed.

        @steps:
        1. Set 1G link speed.
        2. Apply needed capabilities: external loopback, pause and asymmetric pause and transaction id.
        3. Wait for link up.
        4. Make sure that capabilities were applied correctly.
        5. Make sure that ISR counter is increased.
        6. Apply link drop capability.
        7. Make sure that link has ben dropped.
        8. Verify that ISR counter is increased.
        9. Remove link drop bit.
        10. Repeat 1-9 steps in the cycle 50 times.

        @result: All checks are passed.
        @duration: 10 minutes.
        """

        if self.dut_fw_card in [CARD_NIKKI, CARD_BERMUDA_A0, CARD_BERMUDA_B0]:
            pytest.skip()

        self.params["timeout"] = 30000
        self.params["link_speed"] = '1G'
        self.run_mbu_test("Bugs/radar1707_Felicity.txt")

    def test_mbu_bug_radar_1707__25G(self):
        """
        @description: This subtest verifies interrupt routine on 2.5G link speed.

        @steps:
        1. Set 2.5G link speed.
        2. Apply needed capabilities: external loopback, pause and asymmetric pause and transaction id.
        3. Wait for link up.
        4. Make sure that capabilities were applied correctly.
        5. Make sure that ISR counter is increased.
        6. Apply link drop capability.
        7. Make sure that link has ben dropped.
        8. Verify that ISR counter is increased.
        9. Remove link drop bit.
        10. Repeat 1-9 steps in the cycle 50 times.

        @result: All checks are passed.
        @duration: 10 minutes.
        """

        file = "radar1707.txt"
        if self.dut_fw_card in FELICITY_CARDS:
            file = "radar1707_Felicity.txt"

        self.params["timeout"] = 30000
        self.params["link_speed"] = '25G'
        self.run_mbu_test("Bugs/{}".format(file))

    def test_mbu_bug_radar_1707__5G(self):
        """
        @description: This subtest verifies interrupt routine on 5G link speed.

        @steps:
        1. Set 5G link speed.
        2. Apply needed capabilities: external loopback, pause and asymmetric pause and transaction id.
        3. Wait for link up.
        4. Make sure that capabilities were applied correctly.
        5. Make sure that ISR counter is increased.
        6. Apply link drop capability.
        7. Make sure that link has ben dropped.
        8. Verify that ISR counter is increased.
        9. Remove link drop bit.
        10. Repeat 1-9 steps in the cycle 50 times.

        @result: All checks are passed.
        @duration: 10 minutes.
        """

        file = "radar1707.txt"
        if self.dut_fw_card in FELICITY_CARDS:
            file = "radar1707_Felicity.txt"

        self.params["timeout"] = 30000
        self.params["link_speed"] = '5G'
        self.run_mbu_test("Bugs/{}".format(file))

    def test_mbu_bug_radar_1707__10G(self):
        """
        @description: This subtest verifies interrupt routine on 10G link speed.

        @steps:
        1. Set 10G link speed.
        2. Apply needed capabilities: external loopback, pause and asymmetric pause and transaction id.
        3. Wait for link up.
        4. Make sure that capabilities were applied correctly.
        5. Make sure that ISR counter is increased.
        6. Apply link drop capability.
        7. Make sure that link has ben dropped.
        8. Verify that ISR counter is increased.
        9. Remove link drop bit.
        10. Repeat 1-9 steps in the cycle 50 times.

        @result: All checks are passed.
        @duration: 10 minutes.
        """

        if self.dut_fw_card in [CARD_BERMUDA_A0, CARD_BERMUDA_B0]:
            pytest.skip()

        file = "radar1707.txt"
        if self.dut_fw_card in FELICITY_CARDS:
            file = "radar1707_Felicity.txt"

        self.params["timeout"] = 30000
        self.params["link_speed"] = '10G'
        self.run_mbu_test("Bugs/{}".format(file))

    def test_mbu_hw_jira_atl2_175__62_0x800(self):
        """
        @description: This subtest covers ATL2-175
        jira.aquantia.com:8080/browse/ATL2-175
        """

        self.params["packet_size"] = 62
        self.params["eth_type"] = 0x800
        self.run_mbu_test("Bugs/jira_atl2_175.txt")

    def test_mbu_hw_jira_atl2_175__62_0x801(self):
        """
        @description: This subtest covers ATL2-175
        jira.aquantia.com:8080/browse/ATL2-175
        """

        self.params["packet_size"] = 62
        self.params["eth_type"] = 0x801
        self.run_mbu_test("Bugs/jira_atl2_175.txt")

    def test_mbu_hw_jira_atl2_175__63_0x801(self):
        """
        @description: This subtest covers ATL2-175
        jira.aquantia.com:8080/browse/ATL2-175
        """

        self.params["packet_size"] = 63
        self.params["eth_type"] = 0x801
        self.run_mbu_test("Bugs/jira_atl2_175.txt")

    def test_mbu_hw_atlb0_402__130(self):
        """
        @description: This subtest covers ATLB0-402
        jira.aquantia.com:8080/browse/ATLB0-402
        """

        self.params["pktSize"] = 130
        self.run_mbu_test("Bugs/jira_atlb0_402.txt")

    def test_mbu_hw_atlb0_402__1500(self):
        """
        @description: This subtest covers ATLB0-402
        jira.aquantia.com:8080/browse/ATLB0-402
        """

        self.params["pktSize"] = 1500
        self.run_mbu_test("Bugs/jira_atlb0_402.txt")


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
