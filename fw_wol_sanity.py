import os
import re
import tempfile
import time
from shutil import copyfile

import pytest

import tools.constants
import tools.mbuper
from infra.test_base import TestBase
from tools.command import Command
from tools.constants import CARD_FELICITY_KR, CARD_FELICITY_EUROPA, CARD_FELICITY, LINK_SPEED_NO_LINK, \
    LINK_SPEED_100M, LINK_SPEED_10G, LINK_SPEED_AUTO
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.scapy_tools import ScapyTools
from tools.utils import get_atf_logger, remove_directory

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "fw_wol_sanity"


class TestFWWoL(TestBase):
    mbu_wrapper = None

    REMOTE_CMD_TIMEOUT = 30
    WOL_CONFIG_DELAY = 30
    MCP_LOG_DELAY = 15

    # Described in /sanity/wolFilterIPv4Syn.txt
    DUT_IP4 = "169.254.1.1"
    LKP_IP4 = "169.254.0.100"
    NETMASK = "255.255.0.0"

    # Described in /sanity/wolFilterIPv4Syn.txt
    WAKEPORT = 13370

    # Described in /sanity/wolLinkUp.txt
    WOL_LINKUP_DELAY = 10

    # Described in /sanity/wolFilterIPv6Syn.txt
    DUT_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2403"
    LKP_IP6 = "4000:0000:0000:0000:1601:bd17:0c02:2402"
    PREFIX_IP6 = "64"

    DEFAULT_LINK_SPEED = LINK_SPEED_100M

    RE_MAGIC_PKT = re.compile(r"([0-9]+).*Magic packet detected", re.DOTALL)
    RE_LINK_UP = re.compile(r"([0-9]+).*Link up timer", re.DOTALL)

    @classmethod
    def setup_class(cls):
        super(TestFWWoL, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            if cls.dut_fw_card in [CARD_FELICITY_KR, CARD_FELICITY_EUROPA, CARD_FELICITY]:
                cls.DEFAULT_LINK_SPEED = LINK_SPEED_AUTO
                cls.RE_WAKEUP_FRAME = re.compile(r"([0-9]+).*Filter packet detected.*", re.DOTALL)
            else:
                cls.RE_WAKEUP_FRAME = re.compile(r"([0-9]+).*Wake up frame detected", re.DOTALL)

            cls.dut_driver = Driver(port=cls.dut_port,
                                    drv_type=DRV_TYPE_DIAG,
                                    version=cls.dut_drv_version)
            cls.dut_driver.install()
            cls.lkp_driver = Driver(port=cls.lkp_port,
                                    version=cls.lkp_drv_version,
                                    host=cls.lkp_hostname)
            cls.lkp_driver.install()

            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP4, cls.NETMASK, None)
            cls.lkp_ifconfig.set_ipv6_address(cls.LKP_IP6, cls.PREFIX_IP6, None)

            cls.mbu_dir = tools.mbuper.download_mbu(cls.mbu_version, cls.working_dir)

            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
        except Exception as e:
            log.exception(e)
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestFWWoL, cls).teardown_class()
        remove_directory(cls.mbu_dir)
        # XXX: this is strictly necessary because
        # MBU doesn't let qa-tests Python process to be finished
        cls.state.test_cleanup_cold_restart = True

    def setup_method(self, method):
        super(TestFWWoL, self).setup_method(method)
        log.info("Initializing MBU wrapper")
        self.mbu_wrapper = tools.mbuper.MbuWrapper(
            mbu_dir=self.mbu_dir, port=self.dut_port)
        self.dut_mac = self.mbu_wrapper.get_mac_address()
        log.info("DUT mac is {}".format(self.dut_mac))

    def teardown_method(self, method):
        super(TestFWWoL, self).teardown_method(method)

        log.info("Disabling FW debug buffer")
        self.mbu_wrapper.debug_buffer_enable(False)
        time.sleep(5)
        log.info("FW debug buffer disabled")

        log.info("Destroying MBU wrapper")
        # self.mbu_wrapper.exit()
        # time.sleep(5)
        # self.mbu_wrapper.cli.destroy()
        # time.sleep(5)
        self.mbu_wrapper.destroy()
        time.sleep(5)
        self.mbu_wrapper.cleanup_logs()
        log.info("MBU wrapper destroyed")

    def copy_log_and_config(self, config):
        mbu_log_dir = os.path.join(self.mbu_dir, "Logs")
        mcp_log = os.path.join(mbu_log_dir, next(obj for obj in os.listdir(mbu_log_dir) if "mcp" in obj))
        copyfile(mcp_log, os.path.join(self.test_log_dir, "mcp_log.txt"))
        copyfile(os.path.join("tools/beton", config), os.path.join(self.test_log_dir, os.path.basename(config)))

    def enable_dbg_buffer(self):
        log.info("Enabling FW debug buffer")
        self.mbu_wrapper.debug_buffer_enable(True)
        time.sleep(5)
        self.mbu_wrapper.debug_buffer_reset()
        time.sleep(5)
        log.info("FW debug buffer enabled")

    def wake_up_frame_found(self):
        mcp_log = self.mbu_wrapper.readlog("mcp").splitlines()
        log.debug("Last 20 lines of MCP log:\n{}".format("\n".join(mcp_log[-20:])))
        wakeup_frame_found = False
        for line in mcp_log:
            m = self.RE_WAKEUP_FRAME.match(line)
            if m is not None:
                line_id = m.group(1)
                log.info("Wake up frame detected, MAC timer tick: {}".format(line_id))
                wakeup_frame_found = True
                break
        return wakeup_frame_found

    def test_magic_packet(self):
        # Described in /sanity/wolMagicPacket.txt
        dut_mac = "00:17:b6:00:07:82"

        beton_file = "testFW/wol/sanity/wolMagicPacket.txt"
        self.mbu_wrapper.set_link_params(LINK_SPEED_NO_LINK, tools.mbuper.LINK_STATE_DOWN, 0)
        time.sleep(5)  # Give FW some time to reset
        self.mbu_wrapper.exec_txt(beton_file)
        self.mbu_wrapper.set_link_params(self.DEFAULT_LINK_SPEED, tools.mbuper.LINK_STATE_UP, 0)
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.WOL_CONFIG_DELAY)

        self.enable_dbg_buffer()

        log.info("Sending magic packet from LKP")
        cmd = "cd ~/qa-tests/wakeonlan && python wol.py -m {} -a {}".format(
            dut_mac, "169.254.255.255")
        Command(cmd=cmd, host=self.lkp_hostname).run_join(self.REMOTE_CMD_TIMEOUT)
        time.sleep(self.MCP_LOG_DELAY)

        mcp_log = self.mbu_wrapper.readlog("mcp").splitlines()
        log.debug("Last 20 lines of MCP log:\n{}".format("\n".join(mcp_log[-20:])))
        wakeup_frame_found = False
        for line in mcp_log:
            m = self.RE_MAGIC_PKT.match(line)
            if m is not None:
                line_id = m.group(1)
                log.info("FW detected magic packet successfully, MAC timer tick: {}".format(line_id))
                wakeup_frame_found = True
                break
        self.copy_log_and_config(beton_file)
        assert wakeup_frame_found, "FW didn't detect magic packet"

    def test_ipv4_syn(self):
        beton_file = "testFW/wol/sanity/wolFilterIPv4Syn.txt"
        self.mbu_wrapper.set_link_params(LINK_SPEED_NO_LINK, tools.mbuper.LINK_STATE_DOWN, 0)
        time.sleep(5)  # Give FW some time to reset
        self.mbu_wrapper.exec_txt(beton_file)
        self.mbu_wrapper.set_link_params(self.DEFAULT_LINK_SPEED, tools.mbuper.LINK_STATE_UP, 0)
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.WOL_CONFIG_DELAY)

        self.enable_dbg_buffer()

        log.info("Sending TCP SYN packet from LKP")
        self.lkp_scapy_tools.wake_on_port(dstip=self.DUT_IP4, srcip=self.LKP_IP4, dstmac=self.dut_mac,
                                          dport=self.WAKEPORT, protocol="tcp")
        time.sleep(self.MCP_LOG_DELAY)

        self.copy_log_and_config(beton_file)
        assert self.wake_up_frame_found(), "FW didn't detect wake up frame"
        log.info("IPv4 TCP SYN packet detected")

    def test_ipv4_ping(self):
        beton_file = "testFW/wol/sanity/wolFilterIPv4Ping.txt"
        self.mbu_wrapper.set_link_params(LINK_SPEED_NO_LINK, tools.mbuper.LINK_STATE_DOWN, 0)
        time.sleep(5)  # Give FW some time to reset
        self.mbu_wrapper.exec_txt(beton_file)
        self.mbu_wrapper.set_link_params(self.DEFAULT_LINK_SPEED, tools.mbuper.LINK_STATE_SLEEP, 0)
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.WOL_CONFIG_DELAY)

        self.enable_dbg_buffer()

        log.info("Sending ICMP echo request from LKP")
        self.lkp_scapy_tools.ping(dstip=self.DUT_IP4, srcip=self.LKP_IP4, dstmac=self.dut_mac, number=1)
        time.sleep(self.MCP_LOG_DELAY)

        self.copy_log_and_config(beton_file)
        assert self.wake_up_frame_found(), "FW didn't detect wake up frame"
        log.info("IPv4 ICMP request packet detected")

    def test_ipv6_syn(self):
        beton_file = "testFW/wol/sanity/wolFilterIPv6Syn.txt"
        self.mbu_wrapper.set_link_params(LINK_SPEED_NO_LINK, tools.mbuper.LINK_STATE_DOWN, 0)
        time.sleep(5)  # Give FW some time to reset
        self.mbu_wrapper.exec_txt(beton_file)
        self.mbu_wrapper.set_link_params(self.DEFAULT_LINK_SPEED, tools.mbuper.LINK_STATE_UP, 0)
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.WOL_CONFIG_DELAY)

        self.enable_dbg_buffer()

        log.info("Sending TCP SYN packet from LKP")
        self.lkp_scapy_tools.wake_on_port(dstip=self.DUT_IP6, srcip=self.LKP_IP6, dstmac=self.dut_mac,
                                          dport=self.WAKEPORT, protocol="tcp")
        time.sleep(self.MCP_LOG_DELAY)

        self.copy_log_and_config(beton_file)
        assert self.wake_up_frame_found(), "FW didn't detect wake up frame"
        log.info("IPv6 TCP SYN packet detected")

    def test_ipv6_ping(self):
        beton_file = "testFW/wol/sanity/wolFilterIPv6Ping.txt"
        self.mbu_wrapper.set_link_params(LINK_SPEED_NO_LINK, tools.mbuper.LINK_STATE_DOWN, 0)
        time.sleep(5)  # Give FW some time to reset
        self.mbu_wrapper.exec_txt(beton_file)
        self.mbu_wrapper.set_link_params(self.DEFAULT_LINK_SPEED, tools.mbuper.LINK_STATE_UP, 0)
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.WOL_CONFIG_DELAY)

        self.enable_dbg_buffer()

        log.info("Sending ICMP echo request from LKP")
        self.lkp_scapy_tools.ping(dstip=self.DUT_IP6, srcip=self.LKP_IP6, dstmac=self.dut_mac, number=1)
        time.sleep(self.MCP_LOG_DELAY)

        self.copy_log_and_config(beton_file)
        assert self.wake_up_frame_found(), "FW didn't detect wake up frame"
        log.info("ICMPv6 request packet detected")

    def test_link_up(self):
        beton_file = "testFW/wol/sanity/wolLinkUp.txt"
        self.mbu_wrapper.set_link_params(LINK_SPEED_NO_LINK, tools.mbuper.LINK_STATE_DOWN, 0)
        time.sleep(5)  # Give FW some time to reset
        self.mbu_wrapper.exec_txt(beton_file)
        self.mbu_wrapper.set_link_params(self.DEFAULT_LINK_SPEED, tools.mbuper.LINK_STATE_UP, 0)
        self.lkp_ifconfig.wait_link_up()
        time.sleep(self.WOL_CONFIG_DELAY)

        self.enable_dbg_buffer()

        # WoL Link latch (FW takes too long to configure?)
        link_up_found = False
        for attempt in range(2):
            self.lkp_ifconfig.set_link_state(tools.constants.LINK_STATE_DOWN)
            time.sleep(20)
            self.lkp_ifconfig.set_link_state(tools.constants.LINK_STATE_UP)
            self.lkp_ifconfig.wait_link_up()
            time.sleep(self.WOL_LINKUP_DELAY + self.MCP_LOG_DELAY)

            mcp_log = self.mbu_wrapper.readlog("mcp").splitlines()
            log.debug("Last 20 lines of MCP log:\n{}".format("\n".join(mcp_log[-20:])))
            for line in mcp_log:
                m = self.RE_LINK_UP.match(line)
                if m is not None:
                    line_id = m.group(1)
                    log.info("FW woke up DUT on link up, MAC timer tick: {}".format(line_id))
                    link_up_found = True
                    break
            if attempt < 1 and any("Link latch" in line for line in mcp_log[-20:]):
                log.info("Link latch detected, trying to do link down/up again")
            else:
                break
        self.copy_log_and_config(beton_file)
        assert link_up_found, "FW didn't wake up DUT on link up"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
