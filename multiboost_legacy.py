import glob
import json
import os
import Queue
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

import pytest

from tools.command import Command
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, \
    ATF_REPO_DIR
from tools.mbuper import download_mbu
from tools.utils import get_atf_logger, download_file, remove_directory
from infra.test_base import TestBase
from tools.lom import LightsOutManagement

PARTNER_ROLE_SERVER = "server"
PARTNER_ROLE_CLIENT = "client"
JOIN_TIMEOUT = 360
JOIN_PORT = 10101
COMMAND_PORT = 10102
LOGS_PORT = 10103

log = get_atf_logger()


class MbuMultiboostPartner(object):
    def __init__(self, mbu_dir, role, **kwargs):
        self.mbu_dir = mbu_dir
        assert role in [PARTNER_ROLE_CLIENT, PARTNER_ROLE_SERVER]
        self.role = role
        if role == PARTNER_ROLE_CLIENT:
            # Delete argument "server", so kwargs could be passed to remote client object
            self.server = kwargs.pop("server")
        self.params = kwargs

    def join(self):
        if self.role == PARTNER_ROLE_SERVER:
            log.info("Waiting for a client")
            sock = socket.socket()
            sock.bind(('', JOIN_PORT))
            sock.listen(1)
            conn, addr = sock.accept()
            log.info("Client joined")
            while True:
                data = conn.recv(1024)
                if "join" in data:
                    conn.send("accept")
                    break
            conn.close()
        else:
            sock = socket.socket()
            sleep_time = 2
            nof_attempts = JOIN_TIMEOUT / sleep_time
            while True:
                log.info("Trying to connect to the server")
                try:
                    sock.connect((self.server, JOIN_PORT))
                    break
                except Exception:
                    nof_attempts -= 1
                    if nof_attempts == 0:
                        raise Exception("Failed to connect to the server")
                    time.sleep(sleep_time)
            log.info("Connected to the server")
            sock.send("join")
            while True:
                data = sock.recv(1024)
                if "accept" in data:
                    break
            sock.close()

    def start(self):
        res = None
        self.join()

        if self.role == PARTNER_ROLE_SERVER:
            sock = socket.socket()
            sock.bind(('', COMMAND_PORT))
            sock.listen(1)
            conn, addr = sock.accept()
            while True:
                log.info("Waiting for command from client")
                data = conn.recv(1024)
                command = json.loads(data)
                log.info("Command is '{}'".format(command))

                if command["cmd"] == "run":
                    kv = command["kv"]
                    res = self.run_mbu(kv)
                if command["cmd"] == "exit":
                    log.info("Stopping execution")
                    break
            conn.close()
        else:
            sock = socket.socket()
            sock.connect((self.server, COMMAND_PORT))

            test_file = os.path.join(self.mbu_dir, "scripts/multiboost.txt")

            kv = {
                "test_file": test_file,
                "start_delay": 1,
                "params": dict({"boost_iter": 10}, **self.params)
            }

            sock.send(json.dumps({"cmd": "run", "kv": kv}))
            kv.pop("start_delay")
            self.run_mbu(kv)

            sock.send(json.dumps({"cmd": "exit"}))
            sock.close()

        return res

    def sync_logs(self, logs):
        log_end_pattern = "---END---"

        if self.role == PARTNER_ROLE_SERVER:
            log.info("Waiting for logs from client")
            sock = socket.socket()
            sock.bind(('', LOGS_PORT))
            sock.listen(1)
            conn, addr = sock.accept()
            logs = []
            while True:
                data = conn.recv(1024)
                if log_end_pattern in data:
                    break
                logs.append(data)
                conn.send("accept")
            conn.close()
            log.info("Logs from client are collected")
            return logs
        else:
            sock = socket.socket()
            nof_attempts = 60
            while True:
                log.info("Trying to connect to the server")
                try:
                    sock.connect((self.server, LOGS_PORT))
                    break
                except Exception:
                    nof_attempts -= 1
                    if nof_attempts == 0:
                        raise Exception("Failed to connect to the server")
                    time.sleep(2)
            for line in logs:
                sock.send(line)
                data = sock.recv(1024)
                if "accept" in data:
                    continue
            sock.send(log_end_pattern)
            sock.close()
            return None

    def multiboost_get_results(self, logs):
        res = {"tx_dma": [], "rx_dma": [], "before": {}, "after": {}}

        re_dma_tx_rx = re.compile(".*DMA   Packet/Bytes: TX [0-9]+/[0-9]+, RX [0-9]+/[0-9]+, Mpps:Gbps TX/RX: "
                                  "[0-9\.]+/[0-9\.]+ : ([0-9\.]+)/([0-9\.]+)")

        re_tx_gpkt_lsw = re.compile(".*Register 0x00008800: ([a-fxA-F0-9]+) : [01 ]+")
        re_tx_gpkt_msw = re.compile(".*Register 0x00008804: ([a-fxA-F0-9]+) : [01 ]+")
        re_tx_goct_lsw = re.compile(".*Register 0x00008808: ([a-fxA-F0-9]+) : [01 ]+")
        re_tx_goct_msw = re.compile(".*Register 0x0000880C: ([a-fxA-F0-9]+) : [01 ]+")

        re_rx_gpkt_lsw = re.compile(".*Register 0x00006800: ([a-fxA-F0-9]+) : [01 ]+")
        re_rx_gpkt_msw = re.compile(".*Register 0x00006804: ([a-fxA-F0-9]+) : [01 ]+")
        re_rx_goct_lsw = re.compile(".*Register 0x00006808: ([a-fxA-F0-9]+) : [01 ]+")
        re_rx_goct_msw = re.compile(".*Register 0x0000680C: ([a-fxA-F0-9]+) : [01 ]+")

        re_tx_oct = re.compile(".*Prop 'txoct': ([a-fxA-F0-9]+)")
        re_tx_gfm = re.compile(".*Prop 'tx_gfm': ([a-fxA-F0-9]+)")
        re_rx_oct = re.compile(".*Prop 'rxoct': ([a-fxA-F0-9]+)")
        re_rx_gfm = re.compile(".*Prop 'rx_gfm': ([a-fxA-F0-9]+)")

        re_tx_pfm = re.compile(".*Prop 'tx_pfm': ([a-fxA-F0-9]+)")
        re_rx_pfm = re.compile(".*Prop 'rx_pfm': ([a-fxA-F0-9]+)")

        cnt_dict = {
            "tx_gpkt_lsw": re_tx_gpkt_lsw,
            "tx_gpkt_msw": re_tx_gpkt_msw,
            "tx_goct_lsw": re_tx_goct_lsw,
            "tx_goct_msw": re_tx_goct_msw,

            "rx_gpkt_lsw": re_rx_gpkt_lsw,
            "rx_gpkt_msw": re_rx_gpkt_msw,
            "rx_goct_lsw": re_rx_goct_lsw,
            "rx_goct_msw": re_rx_goct_msw,

            "tx_oct": re_tx_oct,
            "tx_gfm": re_tx_gfm,
            "rx_oct": re_rx_oct,
            "rx_gfm": re_rx_gfm,

            "tx_pfm": re_tx_pfm,
            "rx_pfm": re_rx_pfm
        }

        before = False
        after = False
        for line in logs:
            if "Start statistic before" in line:
                before = True
            elif "End statistic before" in line:
                before = False
            elif "Start statistic after" in line:
                after = True
            elif "End statistic after" in line:
                after = False

            m = re_dma_tx_rx.match(line)
            if m:
                res["tx_dma"].append(float(m.group(1)))
                res["rx_dma"].append(float(m.group(2)))
                continue

            for counter_name, counter_re in cnt_dict.items():
                m = counter_re.match(line)
                if m is not None:
                    if before:
                        res["before"][counter_name] = int(m.group(1), 16)
                    elif after:
                        res["after"][counter_name] = int(m.group(1), 16)
                    continue

        return res

    def run_mbu(self, kv):
        def enqueue_output(out, queue):
            for line in iter(out.readline, b''):
                queue.put(line)
            out.close()

        start_delay = kv.get("start_delay", None)
        test_file = "multiboost.txt" # os.path.join(os.environ["ATF_HOME"], "qa-tests/tools/beton/boost/multiboost.txt")
        tmp_file = os.path.join(self.mbu_dir, "tmp_test_file.txt")
        with open(tmp_file, "w") as f:
            if "params" in kv:
                for k, v in kv["params"].items():
                    f.write("{} = {}\n".format(k, v))
            f.write("exec {}\n".format(test_file))

        if start_delay:
            time.sleep(start_delay)
        proc = subprocess.Popen("python main.py -p pci0 -i -f %s" % (tmp_file),
                                shell=True,
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                bufsize=1,
                                cwd=self.mbu_dir)

        q = Queue.Queue()
        t = threading.Thread(target=enqueue_output, args=(proc.stdout, q))
        t.daemon = True
        t.start()

        logs = []
        while proc.poll() is None:
            time.sleep(0.5)
            while not q.empty():
                log_line = q.get(block=False)
                log.info(log_line.rstrip())
                logs.append(log_line)
                if "Start boost" in log_line:
                    try:
                        self.join()
                    except Exception:
                        log.error("Failed to synchronize boosting")
                        proc.kill()
                        break
                    proc.stdin.write("\r\n")
                    proc.stdin.flush()

        self.join()
        logs_from_client = self.sync_logs(logs)
        if logs_from_client:
            server_res = self.multiboost_get_results(logs)
            client_res = self.multiboost_get_results(logs_from_client)

            server_res["role"] = "server"
            client_res["role"] = "client"

            return server_res, client_res


def setup_module(module):
    # os.environ["LKP_HOSTNAME"] = "at053-970m"
    #
    # os.environ["DUT_PORT"] = "pci1.00.0"
    # os.environ["DUT_DRV_VERSION"] = "latest"
    # os.environ["DUT_FW_VERSION"] = "x2/latest"
    # os.environ["DUT_FW_CARD"] = "Nikki"
    # os.environ["DUT_FW_SPEED"] = "5G"
    # os.environ["DUT_FW_MDI"] = "MDINormal"
    # os.environ["DUT_FW_MII"] = "USX_SGMII"
    # os.environ["DUT_FW_PAUSE"] = "no"
    # os.environ["DUT_FW_PCIROM"] = "0.0.1"
    # os.environ["DUT_FW_DIRTYWAKE"] = "no"
    # os.environ["DUT_DEV_ID"] = "0xD108"
    # os.environ["DUT_SUBSYS_ID"] = "0x0001"
    # os.environ["DUT_SUBVEN_ID"] = "0x1D6A"
    #
    # os.environ["LKP_PORT"] = "pci1.00.0"
    # os.environ["LKP_DRV_VERSION"] = "stable"
    # os.environ["LKP_FW_VERSION"] = "x2/latest"
    # os.environ["LKP_FW_CARD"] = "Nikki"
    # os.environ["LKP_FW_SPEED"] = "5G"
    # os.environ["LKP_FW_MDI"] = "MDINormal"
    # os.environ["LKP_FW_MII"] = "USX_SGMII"
    # os.environ["LKP_FW_PAUSE"] = "no"
    # os.environ["LKP_FW_PCIROM"] = "0.0.1"
    # os.environ["LKP_FW_DIRTYWAKE"] = "no"
    # os.environ["LKP_DEV_ID"] = "0xD108"
    # os.environ["LKP_SUBSYS_ID"] = "0x0001"
    # os.environ["LKP_SUBVEN_ID"] = "0x1D6A"
    #
    # os.environ["MBU_VERSION"] = "latest"
    # os.environ["ATB_VERSION"] = "latest"
    # os.environ["SUBTEST_STATUS_API_URL"] = "http://nn-ap01.rdc-lab.marvell.com/flask/addsubtest-fake/0"
    # os.environ["TEST_TOOL_VERSION"] = "LATEST"
    # os.environ["LOG_SERVER"] = "nn-ap01.rdc-lab.marvell.com"
    # os.environ["LOG_PATH"] = "/storage/logs"
    # os.environ["JOB_ID"] = "0"
    # os.environ["PLATFORM"] = "multiboost_platform"
    # os.environ["WORKING_DIR"] = tempfile.gettempdir()

    # Hardcoded test name for log path
    os.environ["TEST"] = "multiboost"


class TestMultiboost(TestBase):
    """
    @description: The multiboost test is dedicated to send huge traffic via several rings and check RX/TX counters.
    Each test sends bidirectional traffic using several rings and checks following counters: DMA, MSM, TPO, TPB, PFM.
    Tx counter on one device should be equals to RX counter on opposite device.

    @setup: Two Aquantia devices connected back to back.
    """

    @classmethod
    def setup_class(cls):
        super(TestMultiboost, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            # Use latest DIAG drivers
            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version="latest")
            cls.lkp_driver = Driver(port=cls.lkp_port, drv_type=DRV_TYPE_DIAG, version="latest", host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.mbu_dir = download_mbu(cls.mbu_version, cls.atf_home)

            cls.dut_nof_pci_lines = cls.dut_ifconfig.get_nof_pci_lines()
            cls.lkp_nof_pci_lines = cls.lkp_ifconfig.get_nof_pci_lines()
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestMultiboost, cls).teardown_class()

        remove_directory(cls.mbu_dir)

    def setup_method(self, method):
        super(TestMultiboost, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl = LightsOutManagement(host=self.dut_hostname, port=self.dut_port)
            self.LOM_ctrl.set_lom_mac_address(self.LOM_ctrl.LOM_MAC_ADDRESS)
            self.LOM_ctrl.LoM_enable()
            self.LOM_ctrl.set_lom_ip_address(self.LOM_ctrl.LOM_IP_ADDRESS)

    def teardown_method(self, method):
        super(TestMultiboost, self).setup_method(method)
        if os.environ.get("LOM_TEST", None):
            self.LOM_ctrl.LoM_disable()

    def run_multiboost(self, link_speed, flow_control, eee, mcp_log):
        assert type(flow_control) is str

        if link_speed == LINK_SPEED_10G and (self.dut_nof_pci_lines != 4 or self.lkp_nof_pci_lines != 4):
            pytest.xfail()

        cmd = "cd {} && python multiboost.py {} {} {} {} {}".format(ATF_REPO_DIR, socket.gethostname(), link_speed,
                                                                    flow_control, mcp_log, eee)
        cmd_obj = Command(cmd=cmd, host=self.lkp_hostname)
        cmd_obj.run_async()
        server = MbuMultiboostPartner(self.mbu_dir, PARTNER_ROLE_SERVER)
        server_res, client_res = server.start()
        cmd_obj.join(180)

        log.info("Server results: {}".format(server_res))
        log.info("Client results: {}".format(client_res))

        counters = ["rx_gfm", "tx_gfm", "tx_oct", "rx_oct", "tx_pfm", "rx_pfm"]

        server_counters = {}
        client_counters = {}
        
        for counter in counters:
            server_counters[counter] = server_res["after"][counter] - server_res["before"][counter]
            client_counters[counter] = client_res["after"][counter] - client_res["before"][counter]
            
        if flow_control in ["link", "pfc"]:
            assert server_counters["tx_pfm"] > 0
            assert client_counters["tx_pfm"] > 0
        elif flow_control == "None":
            assert server_counters["tx_pfm"] == 0
            assert client_counters["tx_pfm"] == 0

        for counter in counters:
            if counter.startswith("tx_"):
                client_counter = counter.replace("tx_", "rx_")
                assert server_counters[counter] == client_counters[client_counter], \
                    "Server counter {}: {} != client counter {}: {}".format(counter, server_counters[counter],
                                                                            client_counter,
                                                                            client_counters[client_counter])
            elif counter.startswith("rx_"):
                client_counter = counter.replace("rx_", "tx_")
                assert server_counters[counter] == client_counters[client_counter], \
                    "Server counter {}: {} != client counter {}: {}".format(counter, server_counters[counter],
                                                                            client_counter,
                                                                            client_counters[client_counter])
            else:
                raise Exception("Invalid counter name: {}".format(counter))

        link_to_max_thr = {
            LINK_SPEED_100M: 0.1,
            LINK_SPEED_1G: 1,
            LINK_SPEED_2_5G: 2.5,
            LINK_SPEED_5G: 5,
            LINK_SPEED_10G: 10
        }

        if self.dut_nof_pci_lines == 4 and self.lkp_nof_pci_lines == 4:
            link_to_max_thr["Auto"] = 10
        else:
            link_to_max_thr["Auto"] = 5

        if mcp_log is True:
            res = Command(cmd="ls ~/mbu/Logs | grep mcp", host=self.lkp_hostname).run()
            if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
                raise Exception("MCP log was not found on LKP")
            mcp_log_file_name = res["output"][0].rstrip()
            remote_file = "~/mbu/Logs/" + mcp_log_file_name
            local_file = os.path.join(self.test_log_dir, "lkp_" + mcp_log_file_name)
            download_file(self.lkp_hostname, remote_file, local_file)

            files = glob.glob(os.path.normpath(os.path.join(self.mbu_dir, "Logs")) + "/mcp*.log")
            assert len(files) == 1, "Too many MCP log files"
            mcp_log_file_name = os.path.basename(files[0])
            dst_file_name = os.path.join(self.test_log_dir, "dut_" + mcp_log_file_name)
            shutil.copyfile(files[0], dst_file_name)

        # Commented because traffic speed is not main idea of the test
        # for tx_dma in server_res["tx_dma"]:
        #     assert tx_dma >= link_to_max_thr[link_speed] * 0.8
        # for tx_dma in client_res["tx_dma"]:
        #     assert tx_dma >= link_to_max_thr[link_speed] * 0.8
        # for rx_dma in server_res["rx_dma"]:
        #     assert rx_dma >= link_to_max_thr[link_speed] * 0.8
        # for rx_dma in client_res["rx_dma"]:
        #     assert rx_dma >= link_to_max_thr[link_speed] * 0.8

    def test_multiboost_10g_no_flowcontrol_no_eee(self):
        """
        @description: This subtest runs multiboost test on 10G link speed without flowcontrol and without EEE.

        @steps:
        1. Set link speed 10G on both DUT and LKP.
        2. Run multiboost script on both DUT and LKP.
        3. Let the script fill needed rings.
        4. Start traffic for 1 minute.
        5. Stop traffic.
        6. Verify that all TX counters on DUT are equal to RX counters on LKP.
        7. Verify that all RX counters on DUT are equal to TX counters on LKP.

        @result: Counters are OK, no packet loss.
        @duration: 2 minutes.
        """

        self.run_multiboost(link_speed=LINK_SPEED_10G, flow_control="None", eee=False, mcp_log=False)

    def test_multiboost_5g_no_flowcontrol_no_eee(self):
        """
        @description: This subtest runs multiboost test on 5G link speed without flowcontrol and without EEE.

        @steps:
        1. Set link speed 5G on both DUT and LKP.
        2. Run multiboost script on both DUT and LKP.
        3. Let the script fill needed rings.
        4. Start traffic for 1 minute.
        5. Stop traffic.
        6. Verify that all TX counters on DUT are equal to RX counters on LKP.
        7. Verify that all RX counters on DUT are equal to TX counters on LKP.

        @result: Counters are OK, no packet loss.
        @duration: 2 minutes.
        """

        self.run_multiboost(link_speed=LINK_SPEED_5G, flow_control="None", eee=False, mcp_log=False)

    def test_multiboost_2_5g_no_flowcontrol_no_eee(self):
        """
        @description: This subtest runs multiboost test on 2.5G link speed without flowcontrol and without EEE.

        @steps:
        1. Set link speed 2.5G on both DUT and LKP.
        2. Run multiboost script on both DUT and LKP.
        3. Let the script fill needed rings.
        4. Start traffic for 1 minute.
        5. Stop traffic.
        6. Verify that all TX counters on DUT are equal to RX counters on LKP.
        7. Verify that all RX counters on DUT are equal to TX counters on LKP.

        @result: Counters are OK, no packet loss.
        @duration: 2 minutes.
        """

        self.run_multiboost(link_speed=LINK_SPEED_2_5G, flow_control="None", eee=False, mcp_log=False)

    def test_multiboost_1g_no_flowcontrol_no_eee(self):
        """
        @description: This subtest runs multiboost test on 1G link speed without flowcontrol and without EEE.

        @steps:
        1. Set link speed 1G on both DUT and LKP.
        2. Run multiboost script on both DUT and LKP.
        3. Let the script fill needed rings.
        4. Start traffic for 1 minute.
        5. Stop traffic.
        6. Verify that all TX counters on DUT are equal to RX counters on LKP.
        7. Verify that all RX counters on DUT are equal to TX counters on LKP.

        @result: Counters are OK, no packet loss.
        @duration: 2 minutes.
        """

        self.run_multiboost(link_speed=LINK_SPEED_1G, flow_control="None", eee=False, mcp_log=False)

    def test_multiboost_100m_no_flowcontrol_no_eee(self):
        """
        @description: This subtest runs multiboost test on 100M link speed without flowcontrol and without EEE.

        @steps:
        1. Set link speed 100M on both DUT and LKP.
        2. Run multiboost script on both DUT and LKP.
        3. Let the script fill needed rings.
        4. Start traffic for 1 minute.
        5. Stop traffic.
        6. Verify that all TX counters on DUT are equal to RX counters on LKP.
        7. Verify that all RX counters on DUT are equal to TX counters on LKP.

        @result: Counters are OK, no packet loss.
        @duration: 2 minutes.
        """

        self.run_multiboost(link_speed=LINK_SPEED_100M, flow_control="None", eee=False, mcp_log=False)

    def test_multiboost_10g_flowcontrol_pfc_no_eee(self):
        """
        @description: This subtest runs multiboost test on 10G link speed with PFC and without EEE.

        @steps:
        1. Set link speed 10G on both DUT and LKP.
        2. Run multiboost script on both DUT and LKP.
        3. Let the script fill needed rings.
        4. Start traffic for 1 minute.
        5. Stop traffic.
        6. Verify that all TX counters on DUT are equal to RX counters on LKP.
        7. Verify that all RX counters on DUT are equal to TX counters on LKP.

        @result: Counters are OK, no packet loss.
        @duration: 2 minutes.
        """

        self.run_multiboost(link_speed=LINK_SPEED_10G, flow_control="pfc", eee=False, mcp_log=False)

    def test_multiboost_5g_flowcontrol_pfc_no_eee(self):
        """
        @description: This subtest runs multiboost test on 10G link speed with PFC and without EEE.

        @steps:
        1. Set link speed 5G on both DUT and LKP.
        2. Run multiboost script on both DUT and LKP.
        3. Let the script fill needed rings.
        4. Start traffic for 1 minute.
        5. Stop traffic.
        6. Verify that all TX counters on DUT are equal to RX counters on LKP.
        7. Verify that all RX counters on DUT are equal to TX counters on LKP.

        @result: Counters are OK, no packet loss.
        @duration: 2 minutes.
        """

        self.run_multiboost(link_speed=LINK_SPEED_5G, flow_control="pfc", eee=False, mcp_log=False)

    def test_multiboost_2_5g_flowcontrol_pfc_no_eee(self):
        """
        @description: This subtest runs multiboost test on 2.5G link speed with PFC and without EEE.

        @steps:
        1. Set link speed 2.5G on both DUT and LKP.
        2. Run multiboost script on both DUT and LKP.
        3. Let the script fill needed rings.
        4. Start traffic for 1 minute.
        5. Stop traffic.
        6. Verify that all TX counters on DUT are equal to RX counters on LKP.
        7. Verify that all RX counters on DUT are equal to TX counters on LKP.

        @result: Counters are OK, no packet loss.
        @duration: 2 minutes.
        """

        self.run_multiboost(link_speed=LINK_SPEED_2_5G, flow_control="pfc", eee=False, mcp_log=False)

    def test_multiboost_1g_flowcontrol_pfc_no_eee(self):
        """
        @description: This subtest runs multiboost test on 1G link speed with PFC and without EEE.

        @steps:
        1. Set link speed 1G on both DUT and LKP.
        2. Run multiboost script on both DUT and LKP.
        3. Let the script fill needed rings.
        4. Start traffic for 1 minute.
        5. Stop traffic.
        6. Verify that all TX counters on DUT are equal to RX counters on LKP.
        7. Verify that all RX counters on DUT are equal to TX counters on LKP.

        @result: Counters are OK, no packet loss.
        @duration: 2 minutes.
        """

        self.run_multiboost(link_speed=LINK_SPEED_1G, flow_control="pfc", eee=False, mcp_log=False)

    def test_multiboost_100m_flowcontrol_pfc_no_eee(self):
        """
        @description: This subtest runs multiboost test on 100M link speed with PFC and without EEE.

        @steps:
        1. Set link speed 100M on both DUT and LKP.
        2. Run multiboost script on both DUT and LKP.
        3. Let the script fill needed rings.
        4. Start traffic for 1 minute.
        5. Stop traffic.
        6. Verify that all TX counters on DUT are equal to RX counters on LKP.
        7. Verify that all RX counters on DUT are equal to TX counters on LKP.

        @result: Counters are OK, no packet loss.
        @duration: 2 minutes.
        """

        self.run_multiboost(link_speed=LINK_SPEED_100M, flow_control="pfc", eee=False, mcp_log=False)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        pytest.main([__file__, "-s", "-v"])
    else:
        """
            argv[1] -> partner server hostname
            argv[2] -> link speed
            argv[3] -> flow control
            argv[4] -> mcp log enable
        """
        mbu_dir = download_mbu(cls.mbu_version, os.environ["ATF_HOME"])
        MbuMultiboostPartner(mbu_dir, "client", server=sys.argv[1], link_speed=sys.argv[2],
                             flow_control=sys.argv[3], mcp_log=sys.argv[4], eee=sys.argv[5]).start()
