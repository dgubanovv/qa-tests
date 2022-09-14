#!/bin/bash
clear
rcaddr='00:01.00'
rcname=$(lspci -s $rcaddr)

dutvid='1d6a' #Aquantia
dutdid='0001' #Atlantic
dutname=$(lspci -d $dutvid:$dutdid)
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
icount=0
while true; do
	newSpeed=$[($rcLinkSpeed == 3 ? 1 : $rcLinkSpeed + 1)]
	setpci -s $rcaddr CAP_EXP+30.W=$newSpeed:3
	setpci -s $rcaddr CAP_EXP+10.W=20:20

	dutLinkState=$(setpci -s $dutaddr CAP_EXP+12.W)
	rcLinkState=$(setpci -s $rcaddr CAP_EXP+12.W)

	dutLinkSpeed=$[((16#$dutLinkState))&7]
	rcLinkSpeed=$[((16#$rcLinkState))&7]

	echo "New bridge speed $rcLinkSpeed ($rcLinkState), new DUT link speed $dutLinkSpeed ($dutLinkState)"
	
	if [ $rcLinkSpeed != $newSpeed ]
		then
			break
	fi
	echo "No Test MMIO register access"
	#sleep 1
	if [ $[$icount%1000] == 0 ]
		then
			echo Iteration count $icount
	fi
	icount=$[$icount+1]
done
echo "Exit"

