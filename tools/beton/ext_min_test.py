import os
import ctypes
import sys

script_path = os.path.dirname(os.path.abspath(__file__))
common_path = script_path + "../../common/"
sys.path.append(common_path)

import comparer
import maclib

ext_type = "tx"
assert ext_type == "rx" or ext_type == "tx"

if ext_type == "rx":
	# exec $(PWD)/helpers/rpoExtractorLlhNames.txt
	extractorLlhNames = {
		"extractionQueueLimitSet": "rpoRxExtractionQueueLimitSet",
		"extractionQueueModeSet": "rpoRxExtractionQueueModeSet",
		"extractionMacFilterEnableSet": "rpoRxExtractionMacFilterEnableSet",
		"extractionIpFilterEnableSet": "rpoRxExtractionIpFilterEnableSet",
		"extractionArpFilterEnableSet": "rpoRxExtractionArpFilterEnableSet",
		"extractionMacDestinationAddressLSW_Set": "rpoRxExtractionMacDestinationAddressLSW_Set",
		"extractionMacDestinationAddressMSW_Set": "rpoRxExtractionMacDestinationAddressMSW_Set",
		"extractionSelectSet": "rpoRxExtractionSelectSet",
		"extractionReadSet": "rpoRxExtractionReadSet",
		"extractionQueuePacketDataGet": "rpoRxExtractionQueuePacketDataGet",
		"extractionQueueEopGet": "rpoRxExtractionQueueEopGet",
		"extractionQueueByteValidGet": "rpoRxExtractionQueueDataValidGet",
		"extractionQueuePacketOffsetGet": "rpoRxExtractionQueuePacketOffsetGet",
		"extractionQueueChecksumErrorGet": "rpoRxExtractionQueueChecksumErrorGet",
		"extractionQueueInterruptGet": "rpoRxExtractionQueueInterruptGet",
		"extractionQueuePacketCountGet": "rpoRxExtractionQueuePacketCountGet",
		"extractionQueueLostErrorGet": "rpoRxExtractionQueueLostErrorGet",
		"extractionQueueOverflowErrorGet": "rpoRxExtractionQueueFullGet",
		"extractionQueueParityErrorGet": "rpoRxExtractionQueueParityErrorGet",
		"extractionQueueReadyGet": "rpoRxExtractionQueueReadyGet",
		"extractionQueueTruncationErrorGet": "rpoRxExtractionQueueTruncationErrorGet",
		"pathInvertParityCheckSenceSet": "rpfRpoRpbRdmRxPathParityCheckeSenseSet"
	}
else:
	# exec $(PWD)/helpers/tpoExtractorLlhNames.txt
	extractorLlhNames = {
		"extractionQueueLimitSet": "tpoTxExtractionQueueLimitSet",
		"extractionQueueModeSet": "tpoTxExtractionQueueModeSet",
		"extractionMacFilterEnableSet": "tpoTxExtractionMacFilterEnableSet",
		"extractionIpFilterEnableSet": "tpoTxExtractionIpFilterEnableSet",
		"extractionArpFilterEnableSet": "tpoTxExtractionArpFilterEnableSet",
		"extractionMacDestinationAddressLSW_Set": "tpoTxExtractionMacDestinationAddressLSW_Set",
		"extractionMacDestinationAddressMSW_Set": "tpoTxExtractionMacDestinationAddressMSW_Set",
		"extractionSelectSet": "tpoTxExtractionSelectSet",
		"extractionReadSet": "tpoTxExtractionReadSet",
		"extractionQueuePacketDataGet": "tpoTxExtractionQueuePacketDataGet",
		"extractionQueueEopGet": "tpoTxExtractionQueueEopGet",
		"extractionQueueByteValidGet": "tpoTxExtractionQueueByteValidGet",
		"extractionQueuePacketOffsetGet": "tpoTxExtractionQueuePacketOffsetGet",
		"extractionQueueChecksumErrorGet": "tpoTxExtractionQueueChecksumErrorGet",
		"extractionQueueInterruptGet": "tpoTxExtractionQueueInterruptGet",
		"extractionQueuePacketCountGet": "tpoTxExtractionQueuePacketCountGet",
		"extractionQueueLostErrorGet": "tpoTxExtractionQueueLostErrorGet",
		"extractionQueueOverflowErrorGet": "tpoTxExtractionQueueOverflowErrorGet",
		"extractionQueueParityErrorGet": "tpoTxExtractionQueueParityErrorGet",
		"extractionQueueReadyGet": "tpoTxExtractionQueueReadyGet",
		"extractionQueueTruncationErrorGet": "tpoTxExtractionQueueTruncationErrorGet",
		"pathInvertParityCheckSenceSet": "tpoTpbTdmTxPathInvertParityCheckSenseSet"
	}

def versionSpecificInit(mac_control, hw_options=0):
	expected_values = ('0', 'A0', 'B0RRO', 'B0RPO')
	if hw_options not in expected_values:
		raise Exception("Invalid HW options")

	addr = 0x5030
	read, write, checkaddr = mac_control.getAccfunc("main", funcNameList=['read', 'write', 'checkaddr'])
	checkaddr(addr)
	bit5030 = read(addr)

	if hw_options == "B0RPO":
		bit5030 |= 1
		write(addr, bit5030)
	elif hw_options == "B0RRO":
		bit5030 = (bit5030 >> 1) << 1
		write(addr, bit5030)

def enable_tpo_2(mac_control):
	write, checkaddr = mac_control.getAccfunc("main", funcNameList=['write', 'checkaddr'])
	write(0x7040, 0x10000)

def configure_rx_unicast_filter(mac_control,
								filterUnicastIndex,
								filterUnicastMngQueue,
								filterUnicastEnable,
								filterUnicastAction,
								filterUnicastMacAddr):
	hc = mac_control.getCachedHalContext()
	mac_control.llh_cache_invalidate() # mac.llhcache on

	(mac_control.getHalFunction("rpfL2UnicastFilterEnableSet"))(hc, filterUnicastEnable, filterUnicastIndex) # mac.llh -C rpfL2UnicastFilterEnableSet $filterUnicastEnable $filterUnicastIndex
	(mac_control.getHalFunction("rpfL2UnicastFilterActionSet"))(hc, filterUnicastAction, filterUnicastIndex) # mac.llh -C rpfL2UnicastFilterActionSet $filterUnicastAction $filterUnicastIndex

	(mac_control.getHalFunction("rpfL2UnicastManagementQueueSet"))(hc, filterUnicastMngQueue, filterUnicastIndex) # mac.llh -C rpfL2UnicastManagementQueueSet $filterUnicastMngQueue $filterUnicastIndex
	macAddressLSW = ((filterUnicastMacAddr[2] << 24) & 0xFF000000) | ((filterUnicastMacAddr[3] << 16) & 0xFF0000) | ((filterUnicastMacAddr[4] << 8) & 0xFF00) | (filterUnicastMacAddr[5] & 0xFF)
	macAddressMSW = ((filterUnicastMacAddr[0] << 8) & 0xFF00) | (filterUnicastMacAddr[1] & 0xFF)
	(mac_control.getHalFunction("rpfL2UnicastDestinationAddressMSW_Set"))(hc, macAddressMSW, filterUnicastIndex) # mac.llh -C rpfL2UnicastDestinationAddressMSW_Set $macAddressMSW $filterUnicastIndex
	(mac_control.getHalFunction("rpfL2UnicastDestinationAddressLSW_Set"))(hc, macAddressLSW, filterUnicastIndex) # mac.llh -C rpfL2UnicastDestinationAddressLSW_Set $macAddressLSW $filterUnicastIndex

	mac_control.llh_cache_flush() # mac.llhcache off

def configure_rx_ext_filters(mac_control):
	hc = mac_control.getCachedHalContext()
	macAddrFilters = [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05], [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]]

	for i in range(2):
		mac_control.llh_cache_invalidate() # mac.llhcache on
		(mac_control.getHalFunction("tpoTxExtractionMacFilterEnableSet"))(hc, 0, i) # mac.llh -C tpoTxExtractionMacFilterEnableSet 0 $queue
		(mac_control.getHalFunction("tpoTxExtractionIpFilterEnableSet"))(hc, 0, i) # mac.llh -C tpoTxExtractionIpFilterEnableSet 0 $queue
		(mac_control.getHalFunction("tpoTxExtractionArpFilterEnableSet"))(hc, 0, i) # mac.llh -C tpoTxExtractionArpFilterEnableSet 0 $queue
		mac_control.llh_cache_flush() # mac.llhcache off


	for i in range(2):
	    filterUnicastIndex = i
	    filterUnicastMngQueue = i
	    filterUnicastEnable = 1
	    filterUnicastAction = 2 #0=Discard, 1=Host, 2=Management, 3=Host & Management, 4=Wake-on-LAN, 5 to 7=Reserved
	    filterUnicastMacAddr = macAddrFilters[i]
	    # exec $(SCRIPT_PATH)/filtersConfigurators/rxUnicastFilter.txt
	    configure_rx_unicast_filter(mac_control,
									filterUnicastIndex,
									filterUnicastMngQueue,
									filterUnicastEnable,
									filterUnicastAction,
									filterUnicastMacAddr)

	return macAddrFilters

def configure_tx_ext_filters(mac_control):
	queueActive = [1,0]
	hc = mac_control.getCachedHalContext()
	macAddrFilters = [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05], [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]]

	for i in range(2):
		mac_control.llh_cache_invalidate() # mac.llhcache on
		(mac_control.getHalFunction(extractorLlhNames["extractionQueueLimitSet"]))(hc, 1, i) # mac.llh -C $extractionQueueLimitSet 1 $queue
		(mac_control.getHalFunction(extractorLlhNames["extractionQueueModeSet"]))(hc, 0, i) # mac.llh -C $extractionQueueModeSet 0 $queue
		queue_in_use = queueActive[i]
		(mac_control.getHalFunction(extractorLlhNames["extractionMacFilterEnableSet"]))(hc, queue_in_use, i) # mac.llh -C $extractionMacFilterEnableSet $queueInUse $queue
		(mac_control.getHalFunction(extractorLlhNames["extractionIpFilterEnableSet"]))(hc, 0, i) # mac.llh -C $extractionIpFilterEnableSet 0 $queue
		(mac_control.getHalFunction(extractorLlhNames["extractionArpFilterEnableSet"]))(hc, 0, i) # mac.llh -C $extractionArpFilterEnableSet 0 $queue
		mac_control.llh_cache_flush() # mac.llhcache off

	for i in range(2):
		ma_filter_lsw = ((macAddrFilters[i][2] << 24) & 0xff000000) | ((macAddrFilters[i][3] << 16) & 0xff0000) | ((macAddrFilters[i][4] << 8) & 0xff00) | (macAddrFilters[i][5] & 0xff)
		ma_filter_msw = ((macAddrFilters[i][0] << 8) & 0xff00) | (macAddrFilters[i][1] & 0xff)
		mac_control.llh_cache_invalidate() # mac.llhcache on
		(mac_control.getHalFunction(extractorLlhNames["extractionMacDestinationAddressLSW_Set"]))(hc, ma_filter_lsw, i) # mac.llh -C $extractionMacDestinationAddressLSW_Set $(macFilterLSW$(queue)) $queue
		(mac_control.getHalFunction(extractorLlhNames["extractionMacDestinationAddressMSW_Set"]))(hc, ma_filter_msw, i) # mac.llh -C $extractionMacDestinationAddressMSW_Set $(macFilterMSW$(queue)) $queue
		mac_control.llh_cache_flush() # mac.llhcache off

	return macAddrFilters

def get_desc_val(desc, field):
	val = None
	field = "DATA_BUF_ADDR"
	if field in desc.__dict__.keys():
		val = desc.__getattribute__(field)
	elif desc.hwdesc is not None:
		hwdesc = desc.hwdesc
		if field in [hwdesc.desc._fields_[i][0] for i in xrange(len(hwdesc.desc._fields_))]:
			val = hwdesc.desc.__getattribute__(field)
		elif field in [hwdesc.wb._fields_[i][0] for i in xrange(len(hwdesc.wb._fields_))]:
			val = hwdesc.wb.__getattribute__(field)
		elif field in [hwdesc.context._fields_[i][0] for i in xrange(len(hwdesc.context._fields_))]:
			val = hwdesc.context.__getattribute__(field)
	return val

def mem_put(mac_control, addr, values, size):
	start = lambda blk: blk.paddr
	block = maclib.getblock(mac_control.membuffers, addr, start)
	if block is None:
		offset = -1
		# wtf
	else:
		offset = addr - start(block)

	if block is not None:
		valType = ctypes.c_uint32 if size == 4 else ctypes.c_uint8  if size == 1 else ctypes.c_uint16 if size == 2 else ctypes.c_uint64
		vsize = ctypes.sizeof(valType)
		buf = ctypes.cast(block.vaddr, ctypes.POINTER(valType))
		for value in values:
			buf[offset / vsize] = value
			offset += size

def mem_dump(mac_control, addr, size):
	start = lambda blk: blk.paddr
	block = maclib.getblock(mac_control.membuffers, addr, start)
	if block is None:
		offset = -1
		# wtf
	else:
		offset = addr - start(block)

	if block is not None:
		print "Block %d. VAddr 0x%016X PAddr 0x%016X Size 0x%04X" % (mac_control.membuffers.index(block), block.vaddr, block.paddr, block.size)
		size = min(size, block.size - offset)
		maclib.dumphex(block.vaddr + offset, size)

def mem_cmp(mac_control, addr, value, size):
	start = lambda blk: blk.paddr
	block = maclib.getblock(mac_control.membuffers, addr, start)
	if block is None:
		offset = -1
		# wtf
	else:
		offset = addr - start(block)

	var_addr_a = block.vaddr + offset
	size = min(size, block.size - offset)
	var_addr_b = (ctypes.c_uint8 * size)()
	val_type = ctypes.c_uint8  if ctypes.sizeof(ctypes.c_uint8) * len(value) == size else\
				ctypes.c_uint16 if ctypes.sizeof(ctypes.c_uint16)* len(value) >= size else\
				ctypes.c_uint32 if ctypes.sizeof(ctypes.c_uint32)* len(value) >= size else ctypes.c_uint64
	val = ctypes.cast(var_addr_b, ctypes.POINTER(val_type))
	for i in xrange(size / ctypes.sizeof(val_type)):
		val[i] = value[i]
	if len(value) > size / ctypes.sizeof(val_type):
		in_offset = size / ctypes.sizeof(val_type)
		val_offset = in_offset * ctypes.sizeof(val_type)

		for i in xrange(size - val_offset):
			var_addr_b[val_offset + i] = ((value[in_offset] >> (i*8)) & 0xFF)

	return comparer.ctmemcmp(var_addr_a, var_addr_b, size)

def extract_and_compare(mac_control, addr):
	byte_cnt = 0
	data = []
	(mac_control.getHalFunction(extractorLlhNames["extractionSelectSet"]))(mac_control.hc, 0) # mac.llh $extractionSelectSet $queue
	while byte_cnt < 2048:
		(mac_control.getHalFunction(extractorLlhNames["extractionReadSet"]))(mac_control.hc, 0) # mac.llh $extractionReadSet 0
		(mac_control.getHalFunction(extractorLlhNames["extractionReadSet"]))(mac_control.hc, 1) # mac.llh $extractionReadSet 1
		dataExtracted = (mac_control.getHalFunction(extractorLlhNames["extractionQueuePacketDataGet"]))(mac_control.hc) # mac.llh -v dataExtracted $extractionQueuePacketDataGet
		if ext_type == "rx":
			dataExtracted = (dataExtracted & 0xFF) << 24 | (dataExtracted & 0xFF00) << 8 | (dataExtracted & 0xFF0000) >> 8 | (dataExtracted & 0xFF000000) >> 24
		data.append(dataExtracted)
		eop = (mac_control.getHalFunction(extractorLlhNames["extractionQueueEopGet"]))(mac_control.hc) # mac.llh -v eop $extractionQueueEopGet
		if eop != 0:
			byte_cnt += 4
			break
		byte_cnt += 4
	(mac_control.getHalFunction(extractorLlhNames["extractionReadSet"]))(mac_control.hc, 0) # mac.llh $extractionReadSet 0
	valid = (mac_control.getHalFunction(extractorLlhNames["extractionQueueByteValidGet"]))(mac_control.hc) # mac.llh -v dataExtracted $extractionQueuePacketDataGet
	if valid > 0:
		while (valid & 1) == 0:
			valid >>= 1
			byte_cnt -= 1
	else:
		byte_cnt -= 4

	res = mem_cmp(mac_control, addr, data, byte_cnt)
	print("Memory compare result is %s" % (res))

def atlantic_run(**kwargs):
	dl = kwargs.get('dllh')
	cl = kwargs.get('cllh')
	log = kwargs.get('log')
	mac_control = kwargs.get('maccontrol')

	if ext_type == "rx":
		mac_control.devprop["loopback"].value = "System Packet" # mac.set loopback System Packet
	else:
		mac_control.devprop["loopback"].value = None # mac.set loopback None $logTag

	mac_control.initializeBoard() # mac.init

	mac_control.interruptControl.disable() # mac.isr.disable

	if ext_type == "rx":
		mac_control.initializeRxDataPath() # mac.rxinit
		mac_control.rxRings[0].enable() # mac.rxring[0].enable
		mac_control.rxRings[0].fillRing(count=0xffff) # mac.rxring[0].fill
		#mac_control.rxRings[0].dumpBuf(mac_control.rxRings[0].descriptors[0], size=0x100, logtag="cli")

	mac_control.initializeTxDataPath() # mac.txinit
	mac_control.txRings[0].devprop["bufSize"].value = 4096 # mac.txring[0].set bufSize 4096
	mac_control.txRings[0].devprop["maxDmaSize"].value = 4096 # mac.txring[0].set maxDmaSize 4096
	mac_control.txRings[0].enable() # mac.txring[0].enable
	mac_control.txRings[0].devprop["PacketMark"].value = "uniq" # mac.txring[0].set PacketMark uniq

	# exec $(PWD)/helpers/versionSpecificInit.txt
	versionSpecificInit(mac_control, "B0RRO")

	# exec $(PWD)/helpers/workaroundBug3991.txt
	#dl.regRxDmaControl2Set(0x0202)
	#dl.regTxDmaControl2Set(0x0202)

	# exec $(PWD)/helpers/enableTPO2.txt
	#enable_tpo_2(mac_control)

	if ext_type == "rx":
		# exec $(PWD)/helpers/configureRxExtFilters.txt
		macAddrFilters = configure_rx_ext_filters(mac_control)
	else:
		macAddrFilters = configure_tx_ext_filters(mac_control)

	#packetLengths = [64, 1518]
	packetLengths = [64, 1518]
	i = 0
	for packetLen in packetLengths:
		isInterrupt = (mac_control.getHalFunction(extractorLlhNames["extractionQueueInterruptGet"]))(mac_control.hc, 0) # mac.llh -v isInterrupt $extractionQueueInterruptGet $queue
		fill_desc_args = {
			"buf_len": packetLen,
			"pay_len": packetLen,
			"pattern": "indexed_uniq_ramp",
			# next values are default
			"count": 1,
			"type": 1,
			"eop": 1,
			"cmd": 0,
			"vlan_insert": 0,
			"fcs_insert": 0,
			"ipv4_chksum": 0,
			"l4_chksum": 0,
			"lso": 0,
			"wb": 0,
			"tunneling": 0,
			"ct_idx": -1,
			"offset": 0,
			"packet_offset": 0
		}

		mac_control.txRings[0].fillDesc(**fill_desc_args) # mac.txring[$txRingNo].insert -b $packetLen -p $packetLen -f indexed_uniq_ramp
		# mac.txring[$txRingNo].getdescval -T 1 -f DATA_BUF_ADDR -n pAddr $logTag
		desc = mac_control.txRings[0].descriptors[i]
		addr = get_desc_val(desc, "DATA_BUF_ADDR")
		assert addr is not None
		mem_dump(mac_control, addr, packetLen)
		mem_put(mac_control, addr, macAddrFilters[0], 1)

		mac_control.txRings[0].dumpDesc(desc, logtag="cli") # mac.txring[$txRingNo].dumpdesc -T 1 -l dumptx  $logTag
		mac_control.txRings[0].dumpBuf(desc, logtag="dumptx") # mac.txring[$txRingNo].dumpbuf -T 1 -l dumptx  $logTag
		mac_control.txRings[0].bumpTail(amount=0xffff, batch=1) # mac.txring[$txRingNo].commit
		mac_control.txRings[0].clean() # mac.txring[$txRingNo].clean
		status = mac_control.txRings[0].getRingStatus()
		print status

		isInterrupt = (mac_control.getHalFunction(extractorLlhNames["extractionQueueInterruptGet"]))(mac_control.hc, 0) # mac.llh -v isInterrupt $extractionQueueInterruptGet $queue

		extract_and_compare(mac_control, addr)

		isInterrupt = (mac_control.getHalFunction(extractorLlhNames["extractionQueueInterruptGet"]))(mac_control.hc, 0) # mac.llh -v isInterrupt $extractionQueueInterruptGet $queue
		i += 1

	#read, = mac_control.getAccfunc("main", funcNameList=['read'])
	#val = read(0x7040)
	#print "0x7040 register = %s" % (val)
	#mac_control.uninitializeBoard() # mac.uninit