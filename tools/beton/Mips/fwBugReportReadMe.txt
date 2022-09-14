1. Run fwBugReport1.txt, copy output to bug report
2. Delete all files from Logs subdirectory in MAC-Bringup (skip files that can't be deleted) - the files that could not be deleted are recent files
3. Run fwBugReport2.txt, copy output and files Logs/mcp*.txt to bug report
4. If you have WARNING messages in the output of fwBugReport2.txt, make commands "writereg 0x404 0x80e0" "writereg 0x404 0xe0" and re-run both scripts. Add output and logs after re-run to bug report
5. Add this information to bug report:
    - Issue description
    - Board ID
    - Is this board x1 or x4 (1 or 4 PCIe lanes)
    - What is Ethernet link partner?
    - Was the board under driver control when issue was identifyed? What is driver version?
    - If link partner is Aquantia board, is it under driver control or under MBU control? What is FW version and driver version on link partner?
    - If link partner is Aspen uner DSP GUI control, add screenshot of SIF/Top tab (should be updated) and GBE tab (press Update on "Connection" frame)
    - cable length/category
    - MB name/chipset
    - Full name of the image that was burned into the flash
    - Full name of the image that was loded to MAC or PHY RAM, if any