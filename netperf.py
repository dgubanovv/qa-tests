import os
import psutil
import re
import subprocess
import sys
import threading
import traceback
import time
import tools.driver
from Queue import Queue
from helpers import install_drv_on_host, install_fw_on_host, \
    get_os_name_on_host, install_fw_on_dut
from tools.utils import exec_remote_cmd, str_to_bool, \
    measure_cpu_load_on_partners, is_linux, get_atf_logger

DUT_IP = "192.168.0.101"
LKP_IP = "192.168.0.106"
NETPERF_EXEC_TIME = 10
assert NETPERF_EXEC_TIME > 9  # at least 9 seconds
PARALLEL_PROCS = [1, 4, 8]
DIRECTION_RX = "RX"
DIRECTION_TX = "TX"

log = get_atf_logger()


class Netperf(threading.Thread):
    def __init__(self, **kwargs):
        super(Netperf, self).__init__()
        self.src_hostname = kwargs["src_hostname"]
        self.dst_hostname = kwargs["dst_hostname"]
        self.port = kwargs.get("port", None)

    def parse_output_tcp(self, output):
        re_res = re.compile(
            " *([0-9\.]+) *([0-9\.]+) *([0-9\.]+) *([0-9\.]+) *([0-9\.]+)",
            re.DOTALL)
        for line in output:
            m = re_res.match(line)
            if m is not None:
                recv_rocket_size = m.group(1)
                send_socket_size = m.group(2)
                send_msg_size = m.group(3)
                elapsed_time = m.group(4)
                throughput = m.group(5)

    def run(self):
        cmd = "netperf -H {} -l {}".format(self.dst_hostname,
                                           NETPERF_EXEC_TIME)
        if self.port is not None:
            cmd += " -p {}".format(self.port)
        if self.src_hostname == "localhost":
            log.info("> {}".format(cmd))
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()
            self.parse_output_tcp(stdout.splitlines())
            # print stdout
            # print stderr
        else:
            qstdout = Queue()
            qstderr = Queue()
            exec_remote_cmd(self.src_hostname, cmd, qstdout, qstderr)
            output = []
            while not qstdout.empty():
                line = qstdout.get()
                output.append(line.rstrip("\r\n"))
            self.parse_output_tcp(output)
            # while not qstdout.empty():
            #     line = qstdout.get()
            #     sys.stdout.write(line)
            # while not qstderr.empty():
            #     line = qstderr.get()
            #     sys.stdout.write(line)


class Netserver(threading.Thread):
    BASE_PORT = 13444
    NOF_INSTANCES = 0

    def __init__(self, **kwargs):
        super(Netserver, self).__init__()
        self.hostname = kwargs["hostname"]
        Netserver.NOF_INSTANCES += 1
        self.port = Netserver.BASE_PORT + Netserver.NOF_INSTANCES
        self.proc = None
        self.pid = None

    def get_port(self):
        return self.port

    def run(self):
        port = self.port
        cmd = "netserver -D -1 -p {}".format(port)
        if self.hostname == "localhost":
            log.info("> {}".format(cmd))
            self.proc = subprocess.Popen(cmd, shell=True,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            self.pid = self.proc.pid
            stdout, stderr = self.proc.communicate()
            # print stdout
            # print stderr
        else:
            qstdout = Queue()
            qstderr = Queue()
            exec_remote_cmd(self.hostname, cmd, qstdout, qstderr)
            # while not qstdout.empty():
            #     line = qstdout.get()
            #     sys.stdout.write(line)
            # while not qstderr.empty():
            #     line = qstderr.get()
            #     sys.stdout.write(line)

    def stop(self):
        if self.hostname == "localhost" and self.proc is not None:
            log.info("Stopping local netserver process {} and it's childs".
                      format(self.pid))
            process = psutil.Process(self.pid)
            for proc in process.children(recursive=True):
                proc.kill()
            process.kill()
        if self.hostname != "localhost":
            log.info("Stopping remote netserver process")
            cmd = "kill -9 `ps -ef | grep -i netserver | awk '{print $2}'`"
            exec_remote_cmd(self.hostname, cmd, None, None)
            time.sleep(0.5)


def prepare_netperf(speed, procs, dut_port, lkp_hostname, lkp_port):
    pass


def run_netperf_onedirectional(speed, procs, dut_port, lkp_hostname, lkp_port,
                               direction, configure=True):
    assert direction in [DIRECTION_RX, DIRECTION_TX]
    try:
        log.info("Start onedirectional {} NetPerf test for link speed {} "
                  "and nof procs {}".format(direction, speed, procs))
        if configure:
            prepare_netperf(speed, procs, dut_port, lkp_hostname, lkp_port)

        netservers = []
        for i in range(procs):
            if direction == DIRECTION_RX:
                netserver = Netserver(hostname="localhost")
                netservers.append(netserver)
            else:
                netserver = Netserver(hostname=LKP_IP)
                netservers.append(netserver)
        netperfes = []
        for i in range(procs):
            if direction == DIRECTION_RX:
                netperf = Netperf(src_hostname=LKP_IP, dst_hostname=DUT_IP, port=netservers[i].get_port())
                netperfes.append(netperf)
            else:
                netperf = Netperf(src_hostname="localhost", dst_hostname=LKP_IP, port=netservers[i].get_port())
                netperfes.append(netperf)
        for i in range(procs):
            netservers[i].start()
        time.sleep(3)
        for i in range(procs):
            netperfes[i].start()

        for i in range(procs):
            netperfes[i].join(NETPERF_EXEC_TIME)

        for i in range(procs):
            netperfes[i].is_alive()
    except Exception:
        log.exception(traceback.format_exc())
        return None
    finally:
        log.info("End onedirectional {} NetPerf test for link speed {} and "
                  "nof procs {}".format(direction, speed, procs))


def run_netperf_bidirectional(speed, procs, dut_port, lkp_hostname, lkp_port,
                              configure=True):
    try:
        log.info("Start bidirectional NetPerf test for link speed {} "
                  "and nof procs {}".format(speed, procs))
        if configure:
            prepare_netperf(speed, procs, dut_port, lkp_hostname, lkp_port)

        local_netservers = []
        for i in range(procs):
            netserver = Netserver(hostname="localhost")
            local_netservers.append(netserver)
        remote_netservers = []
        for i in range(procs):
            netserver = Netserver(hostname=LKP_IP)
            remote_netservers.append(netserver)
        local_netperfes = []
        for i in range(procs):
            netperf = Netperf(src_hostname="localhost", dst_hostname=LKP_IP, port=remote_netservers[i].get_port())
            local_netperfes.append(netperf)
        remote_netperfes = []
        for i in range(procs):
            netperf = Netperf(src_hostname=LKP_IP, dst_hostname=DUT_IP, port=local_netservers[i].get_port())
            remote_netperfes.append(netperf)
        for i in range(procs):
            local_netservers[i].start()
            remote_netservers[i].start()
        time.sleep(3)
        for i in range(procs):
            local_netperfes[i].start()
            remote_netperfes[i].start()

        for i in range(procs):
            local_netperfes[i].join(NETPERF_EXEC_TIME)
            remote_netservers[i].join(NETPERF_EXEC_TIME)

        for i in range(procs):
            local_netperfes[i].is_alive()
            remote_netperfes[i].is_alive()
    except Exception:
        log.exception(traceback.format_exc())
        return None
    finally:
        log.info("End bidirectional NetPerf test for link speed {} and "
                  "nof procs {}".format(speed, procs))


#run_netperf_onedirectional("AUTO", 2, "pci1.00.0", "192.168.0.106", "pci1.00.0", DIRECTION_TX, False)
#run_netperf_bidirectional("AUTO", 2, "pci1.00.0", "192.168.0.106", "pci1.00.0", False)


def precondition():
    dut_port = os.environ["DUT_PORT"]

    # FW installation is not required
    dut_fw_version = os.environ.get("DUT_FW_VERSION", None)
    dut_os_name = tools.driver.get_os()
    if dut_os_name is None:
        raise Exception("Failed to determine OS name on DUT")
    if dut_fw_version is not None and "win" in dut_os_name.lower():
        dut_fw_card = os.environ["DUT_FW_CARD"]
        dut_fw_speed = os.environ["DUT_FW_SPEED"]
        dut_fw_mdi = os.environ["DUT_FW_MDI"]
        dut_fw_mii = os.environ["DUT_FW_MII"]
        dut_fw_pause = str_to_bool(os.environ["DUT_FW_PAUSE"])
        dut_fw_pcirom = str_to_bool(os.environ["DUT_FW_PCIROM"])
        install_fw_on_dut(dut_port, dut_fw_card, dut_fw_speed, dut_fw_version,
                          dut_fw_mdi, dut_fw_mii, dut_fw_pause, dut_fw_pcirom)

    lkp_port = os.environ["LKP_PORT"]
    lkp_hostname = os.environ["LKP_HOSTNAME"]

    # FW installation is not required
    lkp_fw_version = os.environ.get("LKP_FW_VERSION", None)
    lkp_os_name = get_os_name_on_host(lkp_hostname)
    if lkp_os_name is None:
        raise Exception("Failed to determine OS name on LKP")
    if lkp_fw_version is not None and "win" in lkp_os_name.lower():
        lkp_fw_card = os.environ["LKP_FW_CARD"]
        lkp_fw_speed = os.environ["LKP_FW_SPEED"]
        lkp_fw_mdi = os.environ["LKP_FW_MDI"]
        lkp_fw_mii = os.environ["LKP_FW_MII"]
        lkp_fw_pause = str_to_bool(os.environ["LKP_FW_PAUSE"])
        lkp_fw_pcirom = str_to_bool(os.environ["LKP_FW_PCIROM"])
        install_fw_on_host(lkp_hostname, lkp_port, lkp_fw_card, lkp_fw_speed,
                           lkp_fw_version, lkp_fw_mdi, lkp_fw_mii,
                           lkp_fw_pause, lkp_fw_pcirom)

    # DRV installation is required on DUT
    if is_linux(dut_os_name):
        tools.driver.install_ko_driver(dut_port, os.environ["DUT_DRV_VERSION"])
    else:
        tools.driver.install_ndis_driver(dut_port, os.environ["DUT_DRV_VERSION"])

    # DRV installation is required on LKP
    if is_linux(lkp_os_name):
        install_drv_on_host(lkp_hostname, lkp_port, os.environ["LKP_DRV_VERSION"], "ko")
    else:
        install_drv_on_host(lkp_hostname, lkp_port, os.environ["LKP_DRV_VERSION"], "ndis")
    time.sleep(10)


if __name__ == "__main__":
    os.environ["DUT_PORT"] = "pci1.00.0"
    os.environ["LKP_PORT"] = "pci1.00.0"
    os.environ["LKP_HOSTNAME"] = "at014-h170m"

    os.environ["DUT_DRV_VERSION"] = "1.04.1606"
    os.environ["LKP_DRV_VERSION"] = "1.04.1606"

    os.environ["DUT_FW_VERSION"] = "1.5.27"
    os.environ["DUT_FW_CARD"] = "Jamaica"
    os.environ["DUT_FW_SPEED"] = "10G"
    os.environ["DUT_FW_MDI"] = "MDINormal"
    os.environ["DUT_FW_MII"] = "XFI_SGMII"
    os.environ["DUT_FW_PAUSE"] = "no"
    os.environ["DUT_FW_PCIROM"] = "yes"

    os.environ["LKP_FW_VERSION"] = "1.5.27"
    os.environ["LKP_FW_CARD"] = "Jamaica"
    os.environ["LKP_FW_SPEED"] = "10G"
    os.environ["LKP_FW_MDI"] = "MDINormal"
    os.environ["LKP_FW_MII"] = "XFI_SGMII"
    os.environ["LKP_FW_PAUSE"] = "no"
    os.environ["LKP_FW_PCIROM"] = "yes"

    precondition()
    measure_cpu_load_on_partners(os.environ["LKP_HOSTNAME"], NETPERF_EXEC_TIME)
