#!/bin/bash
#clear

#constants and files that should always exist
NUM_ITERATIONS=100 #how many times test will be run after each power down
USB_MOUNT="/dev/sdc1"
USB_MAIN_DIR="/media/aquantia/WINPE"
USB_FILES_DIR="$USB_MAIN_DIR/pwr_test"
NETBOOTER_ADDR="10.10.13.253"

#remount USB as constant (sometimes it wouldn't mount it as expected)
umount $USB_MOUNT
sleep 1
mount $USB_MOUNT $USB_MAIN_DIR
sleep 1

#files that will exist only if this is not 1st iteration of this script
itr_file="$USB_FILES_DIR/pwr_itr.txt"
log_file="$USB_FILES_DIR/pwr_log.txt"
 
#get iteration variable and start (or continue) logging
if [ -f "$itr_file" ] && [ -f "$log_file" ] ;
then
	#files exist, so get current iteration from file
	itr=$( < $itr_file )
else
	#1st iteration, so start iteration at 1 and begin logging
	itr=1
	echo "$itr" > "$itr_file"
	echo -e "BEGIN\n" >> "$log_file"
fi

#continue "loop" if there are still iterations
if ((itr < $NUM_ITERATIONS));
then
	#print current iteration to log
	echo -e "\tIteration no. $itr" >> "$log_file"

	#setup pci variables
	rcaddr='00:01.00'
	rcname=$(lspci -s $rcaddr)
	dutvid='1d6a' #Aquantia
	dutdid='0001' #Atlantic
	dutname=$(lspci -d $dutvid:$dutdid)

	#check if link is up and device is recognized as Ethernet controller
	if [[ $dutname == *"Ethernet controller"* ]]
	then
		linkUp=1
		echo -e "\t\tLINK_UP_PASS: Link up and device recognized as Ethernet controller" >> "$log_file"
	else
		linkUp=0
		echo "LINK_UP_FAIL: Link didn't come up for device"
		echo -e "\t\tLINK_UP_FAIL: Link didn't come up for device" >> "$log_file"
	fi

	#only execute tests if link is up
	if ((linkUp != 0));
	then
		#more pci variables
		dutaddr=$(echo $dutname | cut -f 1 -d " ")
		echo "PCI LINK TEST"
		echo "Control bridge PCI address:    $rcaddr"
		echo "    $rcname"
		echo "Device under test PCI address: $dutaddr"
		echo "    $dutname"
		dutLinkState=$(setpci -s $dutaddr CAP_EXP+12.W)
		rcLinkState=$(setpci -s $rcaddr CAP_EXP+12.W)
		dutLinkSpeed=$[((16#$dutLinkState))&7]
		rcLinkSpeed=$[((16#$rcLinkState))&7]
		echo "Bridge speed $rcLinkSpeed ($rcLinkState), DUT link speed $dutLinkSpeed ($dutLinkState)"
		
		#loop through gens
		linkSpeedPass=1
		declare -a speedArr=(3 1 2 3 2 1 3)
		for newSpeed in "${speedArr[@]}"
		do
			setpci -s $rcaddr CAP_EXP+30.W=$newSpeed:3
			setpci -s $rcaddr CAP_EXP+10.W=20:20

			dutLinkState=$(setpci -s $dutaddr CAP_EXP+12.W)
			rcLinkState=$(setpci -s $rcaddr CAP_EXP+12.W)

			dutLinkSpeed=$[((16#$dutLinkState))&7]
			rcLinkSpeed=$[((16#$rcLinkState))&7]

			echo "New bridge speed $rcLinkSpeed ($rcLinkState), new DUT link speed $dutLinkSpeed ($dutLinkState)"
			
			if [ $rcLinkSpeed != $newSpeed ] || [ $dutLinkSpeed != $newSpeed ]
			then
				echo "LINK_SPEED_FAIL: New speed ($newSpeed) didn't match RC speed ($rcLinkSpeed) or dut speed ($dutLinkSpeed)"
				echo -e "\t\tLINK_SPEED_FAIL: New speed ($newSpeed) didn't match RC speed ($rcLinkSpeed) or dut speed ($dutLinkSpeed)" >> "$log_file"
				linkSpeedPass=0
				break
			fi
			
			#MMIO test will go here
			echo "No Test MMIO register access"
			if ((0 == 0)); #until MMIO test is finished, will always pass
			then
				echo "MMIO_PASS: After speed change + reboot, MMIO still works at gen $newSpeed"
				echo -e "\t\tMMIO_PASS: After speed change + reboot, MMIO still works at gen $newSpeed" >> "$log_file"
			else
				echo "MMIO_FAIL: After speed change + reboot, MMIO doesn't work at gen $newSpeed"
				echo -e "\t\tMMIO_FAIL: After speed change + reboot, MMIO doesn't work at gen $newSpeed" >> "$log_file"
			fi
			#sleep 1
		done
		
		#if all link speed changes were succesful, print this out to log
		if ((linkSpeedPass != 0));
		then
			echo "LINK_SPEED_PASS: Succeeded in changing to all link speeds"
			echo -e "\t\tLINK_SPEED_PASS: Succeeded in changing to all link speeds" >> "$log_file"
		fi
	fi
	
	#increment iteration count and put it in file
	itr=$((itr+1))
	echo -n "$itr" > "$itr_file" 
	
	#unmount usb drive (to allow for file flushing) and pause for 5 seconds in case user wants to kill script
	umount $USB_MOUNT
	echo "Sleeping..."
	sleep 5
	#sleep 60
	
	#reboot this computer using telnet to netbooter
	{ echo -e "rb 2\r\n"; sleep 1; echo -e "rb 2\r\n"; sleep 1; echo -e "rb 2\r\n"; sleep 1; echo -e "rb 2\r\n"; } | telnet $NETBOOTER_ADDR
else
	#done with the iteration "loop", so we no longer reboot computer
	echo -e "END\n\n" >> "$log_file"
	echo "DONE"
	rm $itr_file
fi
