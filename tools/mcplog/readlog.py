import argparse
import os
import platform
import requests
import shutil
import struct
import subprocess
import sys
import time
import timeit

if sys.platform == "win32":
    if platform.architecture()[0] == "64bit":
        WHERE_ATLTOOL = "X:/qa/windows/fwtools/64"
    else:
        WHERE_ATLTOOL = "X:/qa/windows/fwtools/32"
elif sys.platform == "darwin":
    WHERE_ATLTOOL = "/dos/qa/macos/fwtools"
elif "freebsd" in sys.platform:
    WHERE_ATLTOOL = "/x/qa/freebsd/fwtools"
else:
    WHERE_ATLTOOL = "/x/qa/linux/fwtools"
# Add path to python import search directories
sys.path.append(WHERE_ATLTOOL)

import atltool
import mdbgtrace


def download_phy_dbg_trace():
    chip_id = atltool.readreg(device_number, 0x10)
    fw_ver = atltool.readreg(device_number, 0x18)
    fw_ver_major = fw_ver >> 24
    fw_ver_minor = (fw_ver >> 16) & 0xff
    fw_ver_release = fw_ver & 0xffff
    fw_ver_str = "{}.{}.{}".format(fw_ver_major, fw_ver_minor, fw_ver_release)

    url = "http://qa-nfs01/builds/firmware/"
    if fw_ver_major == 2:
        url += "x2/"
    elif fw_ver_major == 3:
        url += "3x/"
    else:
        print "Unsupported firmware version {}".format(fw_ver_str)
        return None

    url += fw_ver_str + "/input/"

    if chip_id in [0xC107, 0xC108, 0xC109]:
        url += "Nikki/default/dbgtrace.py"
    elif chip_id in [0xC111, 0xC112, 0x111E, 0x112E]:
        url += "Bermuda/default/dbgtrace.py"
    else:
        print "Unsupported chip id {}, trying readstat".format(hex(chip_id))

        try:
            cmd = "readstat | grep VerStr"
            if sys.platform != "win32":
                cmd = "sudo " + cmd
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            if "Eur-" in output:
                print "Nikki board was detected using readstat"
                url += "Nikki/default/dbgtrace.py"
            elif "Cal-" in output:
                print "Bermuda board was detected using readstat"
                url += "Bermuda/default/dbgtrace.py"
            else:
                print "Cannot detect PHY type using readstat"
                return None
        except subprocess.CalledProcessError as e:
            print e.output
            return None

    try:
        if os.path.isfile("dbgtrace.py"):
            os.remove("dbgtrace.py")
    except Exception:
        print "Failed to remove file dbgtrace.py"
        return None

    print "Downloading PHY dbgtrace file from {}".format(url)
    response = requests.get(url)
    if response.status_code != 200:
        print "Failed to request URL status code {}".format(response.status_code)
        return None

    with open("dbgtrace.py", "w") as f:
        f.write(response.content)

    return "dbgtrace.py"


def enably_phy_logging(device_number, enable_status):
    PHY_LOG_MASK = 0x00002000

    r36C = atltool.readreg(device_number, 0x36C)
    if enable_status:
        r36C |= PHY_LOG_MASK
    else:
        r36C &= ~PHY_LOG_MASK
    atltool.writereg(device_number, 0x36C, r36C)


class MacCtrl(object):
    def __init__(self, device_number):
        self.device_number = device_number

    def macRegReadData(self, addr):
        return atltool.readreg(self.device_number, addr)

class PhyCtrl(object):
    def __init__(self, device_number):
        self.device_number = device_number

    def pifReadData(self, addr):
        mmd = (addr >> 16) & 0xFF
        reg = addr & 0xFFFF

        return atltool.readphyreg(self.device_number, mmd, reg)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", help="PCI port in lspci format", default="PCI")
    parser.add_argument("--phy", help="Enable PHY logs", action="store_true", default=False)
    parser.add_argument("-f", "--file", help="Save logs to file (binary + text)", action="store_true", default=False)
    parser.add_argument("-t", "--timeout", help="Execution timeout in seconds")
    args = parser.parse_args()

    device_number = atltool.open_device(args.port)

    dbgtrace = mdbgtrace.DebugTrace(maccontrol=MacCtrl(device_number), phycontrol=PhyCtrl(device_number))

    if args.phy:
        dbgtrace = download_phy_dbg_trace()
        if dbgtrace is not None:
            print "Replacing PHY dbgtrace"
            if os.path.isfile("phy_dbg_trace.py"):
                os.remove("phy_dbg_trace.py")
            shutil.copyfile(dbgtrace, "phy_dbg_trace.py")
            os.remove(dbgtrace)
        enably_phy_logging(device_number, True)

    data = []

    if args.file:
        bin_file_path = time.strftime("mcp-%Y-%m-%d__%H-%M-%S.bin")
        txt_file_path = os.path.splitext(bin_file_path)[0] + ".log"

        with open(bin_file_path, "wb") as bin_fp, open(txt_file_path, "w") as txt_fp:
            start_time = timeit.default_timer()
            while timeit.default_timer() - start_time <= int(args.timeout) if args.timeout else True:
                try:
                    new_data = atltool.readlog(device_number)
                    bin_fp.write("".join(map(lambda x: struct.pack("H", x), new_data)))
                    bin_fp.flush()
                    data.extend(new_data)
                    outString, data, status = dbgtrace.printTrace(data)
                    if outString:
                        txt_fp.writelines([outString, "\n"])
                        txt_fp.flush()
                except KeyboardInterrupt:
                    break
    else:
        start_time = timeit.default_timer()
        while timeit.default_timer() - start_time <= int(args.timeout) if args.timeout else True:
            try:
                data.extend(atltool.readlog(device_number))
                outString, data, status = dbgtrace.printTrace(data)
                if outString:
                    print(outString)
            except KeyboardInterrupt:
                break

    if args.phy:
        enably_phy_logging(device_number, False)

    atltool.close_device(device_number)
