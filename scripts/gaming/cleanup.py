import subprocess
import urllib

AQGAMING_SERVICE = "AQGaming"
AQGAMING_INSTALL_PATH = ["C:/Program Files/Aquantia",
                         "C:/Users/aqtest/AppData/Local/Aquantia",
                         "C:/ProgramData/AQGaming"]
AQGAMING_DRIVER_FILES = ["C:/Windows/System32/drivers/AQCallout.sys",
                         "C:/Windows/System32/drivers/AQNdisLwf.sys"]
AQGAMING_AQTION_APP = "AQtion*"
AQGAMING_WMI_PRODUCT_NAME = "AQtion%"
CLEANUP_TOOL_URL = "http://qa-nfs01.rdc-lab.marvell.com/qa/testing/aqgaming-cleanup.exe"
CLEANUP_TOOL_PATH = "aqgaming-cleanup.exe"


def run_cmd(cmd):
    print("Running cmd '{}' ...".format(cmd))
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    proc.wait()
    output = []
    for line in iter(proc.stdout.readline, ""):
        output.append(line.rstrip())
    print("Command '{}' has ended. Returncode = {}".format(cmd, proc.returncode))
    if output:
        print("-" * 84)
        print("    {}".format("\n    ".join(output)))
        print("-" * 84)
    return proc.returncode, output


if __name__ == "__main__":
    # Kill gaming application
    run_cmd("taskkill /F /T /IM {}".format(AQGAMING_AQTION_APP))

    # Kill AQGaming service
    pid_cmd = "sc queryex {} | grep -i PID | awk '{{print $3}}'".format(AQGAMING_SERVICE)
    ret, output = run_cmd(pid_cmd)
    if ret == 0 and output and output[0] and int(output[0]) != 0:
        run_cmd("taskkill /F /T /PID {}".format(output[0]))

    # Call uninstall for AQGaming product
    run_cmd("wmic.exe product where \"name like '{}'\" call uninstall".format(AQGAMING_WMI_PRODUCT_NAME))

    # Uninstall leftover drivers
    cmd = "powershell \"Get-WindowsDriver -Online | " \
          "where {$_.ProviderName -like 'Aquantia'} | " \
          "select Driver | ft -hidetableheaders\""
    ret, output = run_cmd(cmd)
    if ret == 0 and output:
        for line in output:
            if line.startswith("oem"):
                run_cmd("pnputil /delete-driver {} /force".format(line.strip()))

    # Delete driver files in case pnputil failed
    for path in AQGAMING_DRIVER_FILES:
        run_cmd("rm -rf \"{}\"".format(path))

    # Remove AQGaming local files
    for path in AQGAMING_INSTALL_PATH:
        run_cmd("rm -rf \"{}\"".format(path))

    # Call aqgaming_cleanup to cleanup registry
    urllib.urlretrieve(CLEANUP_TOOL_URL, CLEANUP_TOOL_PATH)
    run_cmd(CLEANUP_TOOL_PATH)
