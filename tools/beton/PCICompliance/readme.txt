pciLinkTest.sh
==================================
Made to run on linux, this script continuously cycles the PCIe network device through each gen and makes sure the link retrain was completed successfully.

Notes:
* dutvid, and dutid variables might need to be changed in the future
* rcaddr variable might need to be changed depending on which slot and which machine the PCIe device is connected to
* mmio test not currently implemented
* requires elevated privileges to run

pciPwrTest.sh
==================================
Based on pciLinkTest.sh, this script cycles through a list of gen speeds (3 1 2 3 2 1 3) of all possible combinations. It uses telnet to a netbooter machine to reboot the PC after this test has been completed (the system will need to be configured to run this script somehow on each Linux boot. One idea is listed below in "Notes"). Depending on the NUM_ITERATIONS variables, this test will run in a "loop" (test --> reboot --> test --> reboot --> etc) until the NUM_ITERATIONS variable has been reached. After each run, the test logs the results to a file.

Notes:
* USB_MOUNT, USB_MAIN_DIR, USB_FILES_DIR, NETBOOTER_ADDR are all machine-dependent and implementation-dependent, so they will have to be changed
* When Linux is rebooted using the netbooter, it doesn't always have time to flush the logs to the file. As a workaround, the logs are writtent to a file on a USB flash drive and this drive is unmounted before reboot, to force a file flush.
* Similar to pciLinkTest.sh, rcaddr, dutvid and dutid variables might need to be changed too
* mmio test not currently implemented
* requires elevated privileges to run
* to run pciPwrTest.sh on startup, I recommend adding a file in ~/.config/autostart/. An example would be "example.desktop":

[Desktop Entry]
Type=Application
Exec=gnome-terminal --exec /home/aquantia/run_pwr_test.sh
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name=Startup Script

And run_pwr_test.sh would only be needed if you need to automate the sudo password entry (otherwise you could just run pciPwrTest.sh directly in the "Exec" option above). The run_pwr_test.sh file would contain 1 line and would use a file ("password") to automate the password input for sudo:

sudo -S /home/aquantia/pciPwrTest.sh < password #use password file as standard input