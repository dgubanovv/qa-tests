# TEST PLAN: http://redmine.aquantia.com/projects/sdet/wiki/Driver_Installation_Test_Plan


import collections
import os
import re
import tools.driver
import tools.ifconfig
import tools.ping
import tools.utils
import traceback
import time
import urlparse
import requests
import subprocess

from os import listdir
from os.path import isfile, join, exists

from tools.utils import error_msg, start_end_trace, is_linux, print_msg, \
    provide_subtest_status, print_stdout_stderr, exec_remote_cmd, \
    get_wmi_device_pnp_driver
from tools.helpers import get_os_name_on_host, install_fw_on_dut, \
    install_drv_on_host
from tools.constants import RESULT_FAILED, RESULT_PASSED, ATF_TOOLS_DIR, VENDOR_AQUANTIA, \
    BUILDS_SERVER
from tools.driver import get_network_adapter_vendor, get_arch, devcon_rescan

DUT_IP = "192.168.0.3"
LKP_IP = "192.168.0.2"
NETMASK = "255.255.255.0"
GATEWAY = "192.168.0.1"

DRV_WIN_DIR = "C:\Program Files\AtlanticDriver"
            
def compare_driver_data(expected_ver):
    driver = get_wmi_device_pnp_driver(os.environ["DUT_PORT"])
    ver = driver.DriverVersion
    display_name = driver.FriendlyName
    vendor = driver.Manufacturer
    
    expected_ver = ".".join([str(int(v)) for v \
                    in expected_ver.split(".")])
    
    if vendor.lower() != VENDOR_AQUANTIA:
        return False
    elif ver != expected_ver:
        return False
    elif RE_NAME.match(display_name) is None:
        return False
    
    return True
    

def prepare_hosts():
    lkp_os_name = get_os_name_on_host(os.environ["LKP_HOSTNAME"])
    if is_linux(lkp_os_name):
        install_drv_on_host(os.environ["LKP_HOSTNAME"],
                            os.environ["LKP_PORT"],
                            os.environ["LKP_DRV_VERSION"],
                            "ko")
    else:
        install_drv_on_host(os.environ["LKP_HOSTNAME"],
                            os.environ["LKP_PORT"],
                            os.environ["LKP_DRV_VERSION"],
                            "ndis")
    time.sleep(15)    
    
    tools.ifconfig.set_ip_address(os.environ["DUT_PORT"],
                                  LKP_IP, NETMASK, GATEWAY)
    time.sleep(10)
    set_dut_lkp_address(DUT_IP, NETMASK, GATEWAY)
    time.sleep(10)
    
 
def set_dut_lkp_address(addr, mask, gateway):
    cmd = "cd {} && python ifconfig.py " \
        "-c {} -a {} -n {} -g {} -p {}".format(ATF_TOOLS_DIR, "setip", addr,
                                               mask, gateway,
                                               os.environ["LKP_PORT"])
    stdout, stderr = exec_remote_cmd(os.environ["LKP_HOSTNAME"], cmd)
    if len(stderr) != 0 or \
        not any(tools.ifconfig.SCRIPT_STATUS_SUCCESS in line
                for line in stdout):
        print_stdout_stderr(stdout, stderr)
        raise Exception("Failed to execute command on LKP") 
    
 
def check_drv_files():
    if not os.path.exists(DRV_WIN_DIR):
        return False
        
    dir_files = [f for f in listdir(DRV_WIN_DIR) if \
                isfile(join(DRV_WIN_DIR, f))]
    
    driver = get_wmi_device_pnp_driver(os.environ["DUT_PORT"])
    re_ndis = re.compile(".* \(NDIS ([0-9]\.[0-9]+) .*",re.DOTALL)
    ndis = re_ndis.match(driver.FriendlyName).group(1)
    ndis = ndis.replace(".", "")

    expected_files = [f.format(ndis) for f in \
                     ["atlantic{}.cat", "atlantic{}.inf", "atlantic{}.sys"]] 
    
    
    return set(dir_files) == set(expected_files)
    
    
def check_drv_error():
    drv = tools.utils.get_wmi_pnp_devices(os.environ["DUT_PORT"])
    if drv[0].Status != "OK":
        return True
    elif drv[0].ConfigManagerErrorCode != 0:
        return True
        
    return False
        
 
def get_wmi_pnp_device_name():
    return \
    tools.utils.get_wmi_pnp_devices(os.environ["DUT_PORT"])[0].Name


def download_msi():
    vendor = get_network_adapter_vendor(os.environ["DUT_PORT"])
    if vendor != VENDOR_AQUANTIA:
        raise NotImplementedError()
    
    arch = get_arch()
    file = "Aquantia_AQtion_x{}_Win_ver{}.msi".\
        format(arch.split("_")[1], os.environ["DUT_DRV_VERSION"])
    suburl = "driver/msi/aquantia/{}/{}".format(os.environ["DUT_DRV_VERSION"], file)

    url = urlparse.urljoin(BUILDS_SERVER, suburl)
    print_msg("Downloading MSI driver from {}".format(url))
    response = requests.get(url=url)
    if response.status_code != 200:
        raise Exception("Cannot download driver")
    with open(file, "wb") as f:
        f.write(response.content)
        
    return file
    
def msi_action(action):
    file = download_msi()
    
    if action == "repair":
        cmd = "msiexec /f {} /q".format(file)
    elif action == "remove":
        cmd = "msiexec /x {} /q".format(file)
    else:
        raise Exception("Wrong action")
    print_msg("Running command: {}".format(cmd))
    
    try:
        subprocess.check_output(cmd,
                                shell=True,
                                stderr=subprocess.STDOUT)
    except Exception as e:
        error_msg(e.output)
        raise e
    
    tools.utils.remove_file(file)
    devcon_rescan()
    print_msg("Driver has been repaired")
    
 
@provide_subtest_status
@start_end_trace
def driver_install_workflow_silent_mode(**kwargs):
    try:
        if not check_drv_error() or \
            get_wmi_pnp_device_name() != "Ethernet Controller":
                error_msg("DUT did not become enumerated as Unknown Ethernet Controller")
                return RESULT_FAILED

        tools.driver.install_msi_driver(os.environ["DUT_PORT"],
                                        os.environ["DUT_DRV_VERSION"])
        time.sleep(10)
        
        if check_drv_error():
            error_msg("Driver was installed with errors")
            return RESULT_FAILED
        
        if not compare_driver_data(os.environ["DUT_DRV_VERSION"]):
            error_msg("Compare driver data failed")
            return RESULT_FAILED
                
        if not tools.driver.is_msi_driver_present():
            error_msg("MSI driver does not present in list")
            return RESULT_FAILED
        
        if not check_drv_files():
            error_msg("Wrong files in driver dir")
            return RESULT_FAILED
        
        prepare_hosts()
        
        if not tools.ping.ping(3, LKP_IP):
            error_msg("LKP didn't answer on ping")
            return RESULT_FAILED
        
        return RESULT_PASSED
    except Exception:
        error_msg(traceback.format_exc())
        return RESULT_FAILED
    finally:
        test_postcondition()


@provide_subtest_status
@start_end_trace        
def driver_repair_workflow_silent_mode(**kwargs):
    try:
        tools.driver.install_msi_driver(os.environ["DUT_PORT"],
                                        os.environ["DUT_DRV_VERSION"])
        time.sleep(10)
        
        if check_drv_error() or \
            RE_NAME.match(get_wmi_pnp_device_name()) is None:
                error_msg("Driver was installed with errors")
                return RESULT_FAILED
            
             
        tools.driver.uninstall_ndis_diag_driver(os.environ["DUT_PORT"])
        time.sleep(5)
        
        if not check_drv_error() or \
                get_wmi_pnp_device_name() != "Ethernet Controller":
            error_msg("DUT did not become enumerated as Unknown Ethernet Controller")
            return RESULT_FAILED
        
        print_msg("Removing driver directory")
        tools.utils.remove_directory(DRV_WIN_DIR)
        
        print_msg("Repearing Atlantic driver")
        msi_action("repair")
        time.sleep(5)
        
        if check_drv_error():
            error_msg("Driver was installed with errors")
            return RESULT_FAILED
        
        if not compare_driver_data(os.environ["DUT_DRV_VERSION"]):
            error_msg("Compare driver data failed")
            return RESULT_FAILED
                
        if not tools.driver.is_msi_driver_present():
            error_msg("MSI driver does not present in list")
            return RESULT_FAILED
        
        if not check_drv_files():
            error_msg("Wrong files in driver dir")
            return RESULT_FAILED
        
        prepare_hosts()
        
        if not tools.ping.ping(3, LKP_IP):
            error_msg("LKP didn't answer on ping")
            return RESULT_FAILED
        
        return RESULT_PASSED
    except Exception:
        error_msg(traceback.format_exc())
        return RESULT_FAILED
    finally:
        test_postcondition()
        

@provide_subtest_status
@start_end_trace        
def driver_uninstall_workflow_silent_mode(**kwargs):
    try:
        tools.driver.install_msi_driver(os.environ["DUT_PORT"],
                                        os.environ["DUT_DRV_VERSION"])
        time.sleep(10)
                    
        if check_drv_error() or \
           RE_NAME.match(get_wmi_pnp_device_name()) is None:
            error_msg("Driver was installed with errors")
            return RESULT_FAILED
        
        print_msg("Removing driver")
        msi_action("remove")
        time.sleep(5)
        
        if not check_drv_error() or \
                get_wmi_pnp_device_name() != "Ethernet Controller":
            error_msg("DUT did not become enumerated as Unknown Ethernet Controller")
            return RESULT_FAILED
        
        if os.path.exists(DRV_WIN_DIR):
            error_msg("Driver directory was not deleted")
            return RESULT_FAILED
        
        return RESULT_PASSED
    except Exception:
        error_msg(traceback.format_exc())
        return RESULT_FAILED
    finally:
        test_postcondition()
        
        
def precondition():
    tools.driver.uninstall_msi_driver()
    time.sleep(5)
    
    global RE_NAME
    RE_NAME = re.compile\
        ("Aquantia \d+Gbit Network Adapter \(NDIS 6\.\d+ Miniport\)")

    
def postcondition():
    pass


def test_postcondition():
    # Restore win
    tools.driver.uninstall_msi_driver()
    time.sleep(5)
    
    
if __name__ == "__main__":
    # os.environ["DUT_PORT"] = "pci2.00.0"
    # os.environ["DUT_DRV_VERSION"] = "1.39.007.0"
    # os.environ["LKP_PORT"] = "pci1.00.0"
    # os.environ["LKP_HOSTNAME"] = "172.30.1.9"
    # os.environ["LKP_DRV_VERSION"] = "latest"

    # os.environ["SUBTEST_STATUS_API_URL"] = \
    #     "http://nn-ap01.rdc-lab.marvell.com/flask/addsubtest-fake/0"

    # os.environ["LOG_SERVER"] = "nn-ap01.rdc-lab.marvell.com"
    # os.environ["LOG_PATH"] = "/storage/logs"
    # os.environ["JOB_ID"] = "0"
    # os.environ["PLATFORM"] = "drv_link_test_platform"
    # os.environ["WORKING_DIR"] = "d:/"

    # Hardcoded test name for log path
    os.environ["TEST"] = "drv_link_test"

    precondition()

    res = collections.OrderedDict()
    
    name = "Driver install workflow in silent mode"
    res[name] = driver_install_workflow_silent_mode(name=name)
    
    name = "Driver repair workflow in silent mode"
    res[name] = driver_repair_workflow_silent_mode(name=name)
    
    name = "Driver uninstall workflow in silent mode"
    res[name] = driver_uninstall_workflow_silent_mode(name=name)
    

    print "\n\nOverall test result:"
    for k, v in res.items():
        print "{:55s} {}".format(k, v)

    print "\n\n"

    postcondition()
