#!/usr/local/bin/python2.7
#
#                    Copyright 2008-2013 Aquantia Corporation
#                    Confidential and Proprietary
#
# This file was auto-generated by ./scripts/mdbggen.py using this command:
#      ./scripts/mdbggen.py -i ./include/dbgMsgs.h -o ./include/dbgMsgArgs.h -p ./scripts/mdbgconstants.py
#

# VERSION = 1.5.10


def DBG_ATL_PRINTF(args):
    numargs = 0
    return DBG_ID_PRINTF(args)
    # end of function DBG_ATL_PRINTF

def DBG_ATL_HELLO(args):
    numargs = 2
    format  = "%s SumOfArguments = %d\n"
    result = format % (formatMsgIndent(), sumArguments(args[0], args[1]))

    return result
    # end of function DBG_ATL_HELLO

def DBG_ATL_GLB_FAULT(args):
    numargs = 3
    format  = "%s\n%sGlobal Fault = %s\n"
    result = format % (formatTimeStamp(getTime(args[0],  args[1])), formatMsgIndent(), faults[args[2]])

    return result
    # end of function DBG_ATL_GLB_FAULT

def DBG_ATL_PIF_FAIL(args):
    numargs = 10
    format  = "[FAIL] Addr: 0x%08X, read: 0x%08X, mask: 0x%08X, expected: 0x%08X, pattern: 0x%08X, errors: %d\n"
    result = format % (args[0], makeDword(args[1], args[2]), makeDword(args[3], args[4]), makeDword(args[5], args[6]), makeDword(args[7], args[8]), args[9])

    return result
    # end of function DBG_ATL_PIF_FAIL

def DBG_ATL_DBGBUF_OVRFLW(args):
    numargs = 1
    format  = "Rpc resp failed counter = %d\n"
    result = format % (args[0])

    return result
    # end of function DBG_ATL_DBGBUF_OVRFLW

def DBG_ID_PCIE_PMA_SERDES_WR_TOUT(args):
    numargs = 2
    format  = "PCIe PMA Indirect write timeout: addr=0x%08X data=0x%08X\n"
    result = format % (args[0], args[1])

    return result
    # end of function DBG_ID_PCIE_PMA_SERDES_WR_TOUT

def DBG_ID_PCIE_PMA_SERDES_RD_TOUT(args):
    numargs = 1
    format  = "PCIe PMA Indirect read timeout: addr=0x%08X\n"
    result = format % (args[0])

    return result
    # end of function DBG_ID_PCIE_PMA_SERDES_RD_TOUT

def DBG_ID_PCIE_PCS_SERDES_WR_TOUT(args):
    numargs = 2
    format  = "PCIe PCS Indirect write timeout: addr=0x%08X data=0x%08X\n"
    result = format % (args[0], args[1])

    return result
    # end of function DBG_ID_PCIE_PCS_SERDES_WR_TOUT

def DBG_ID_PCIE_PCS_SERDES_RD_TOUT(args):
    numargs = 1
    format  = "PCIe PCS Indirect read timeout: addr=0x%08X\n"
    result = format % (args[0])

    return result
    # end of function DBG_ID_PCIE_PCS_SERDES_RD_TOUT

def DBG_ID_USX(args):
    numargs = 4
    format  = "%s\n"
    result = format % (formatUSXMsg(args[0], args[1], args[2], args[3]))

    return result
    # end of function DBG_ID_USX

def DBG_ID_SERDES_EYE_DIAG(args):
    numargs = 5
    format  = "Serdes Eye - %d:\n  0:0x%04X, 1:0x%04X, 2:0x%04X, 3:0x%04X\n"
    result = format % (args[0], args[1], args[2], args[3], args[4])

    return result
    # end of function DBG_ID_SERDES_EYE_DIAG

def DBG_ID_SERDES_INITIALIZATION(args):
    numargs = 3
    format  = "%s\n Serdes initialization for serdesMode=%s\n"
    result = format % (formatTimeStamp(getTime(args[0], args[1])), formatSerdesMode(args[2]))

    return result
    # end of function DBG_ID_SERDES_INITIALIZATION

def DBG_ID_SERDES_WR_TOUT(args):
    numargs = 2
    format  = "MPI Indirect write timeout: addr=0x%08X data=0x%08X\n"
    result = format % (args[0], args[1])

    return result
    # end of function DBG_ID_SERDES_WR_TOUT

def DBG_ID_SERDES_RD_TOUT(args):
    numargs = 1
    format  = "MPI Indirect read timeout: addr=0x%08X\n"
    result = format % (args[0])

    return result
    # end of function DBG_ID_SERDES_RD_TOUT

def DBG_ID_PROV_CHANGE(args):
    numargs = 2
    format  = "%s\n"
    result = format % (provVarLogger(args[0], args[1]))

    return result
    # end of function DBG_ID_PROV_CHANGE

def DBG_ID_PRINTF(arg):
    result = list2str(arg[0:])
    return result

def DBG_ID_PHY_DBG_BUF_PART(arg):
    print ">>> DBG_ID_PHY_DBG_BUF_PART: {}, {}".format(
        ["0x{:04x}".format(a) for a in arg],
        None,
        # phy_dbg_trace.printTrace(None, arg)
    )
    return ">>> DBG_ID_PHY_DBG_BUF_PART\n"

def DBG_ID_STRING(arg):
    if(arg[0] > 0):
        result = list2str(arg[1:]) + "\n"
    else:
        result = list2str(arg[1:])
    return result


msgIds = [
    (0, 'DBG_ATL_PRINTF', DBG_ID_PRINTF),
    (2, 'DBG_ATL_HELLO', "%s SumOfArguments = %d\n"),
    (3, 'DBG_ATL_GLB_FAULT', "%s\n%sGlobal Fault = %s\n"),
    (10, 'DBG_ATL_PIF_FAIL', "[FAIL] Addr: 0x%08X, read: 0x%08X, mask: 0x%08X, expected: 0x%08X, pattern: 0x%08X, errors: %d\n"),
    (1, 'DBG_ATL_DBGBUF_OVRFLW', "Rpc resp failed counter = %d\n"),
    (2, 'DBG_ID_PCIE_PMA_SERDES_WR_TOUT', "PCIe PMA Indirect write timeout: addr=0x%08X data=0x%08X\n"),
    (1, 'DBG_ID_PCIE_PMA_SERDES_RD_TOUT', "PCIe PMA Indirect read timeout: addr=0x%08X\n"),
    (2, 'DBG_ID_PCIE_PCS_SERDES_WR_TOUT', "PCIe PCS Indirect write timeout: addr=0x%08X data=0x%08X\n"),
    (1, 'DBG_ID_PCIE_PCS_SERDES_RD_TOUT', "PCIe PCS Indirect read timeout: addr=0x%08X\n"),
    (4, 'DBG_ID_USX', "%s\n"),
    (5, 'DBG_ID_SERDES_EYE_DIAG', "Serdes Eye - %d:\n  0:0x%04X, 1:0x%04X, 2:0x%04X, 3:0x%04X\n"),
    (3, 'DBG_ID_SERDES_INITIALIZATION', "%s\n Serdes initialization for serdesMode=%s\n"),
    (2, 'DBG_ID_SERDES_WR_TOUT', "MPI Indirect write timeout: addr=0x%08X data=0x%08X\n"),
    (1, 'DBG_ID_SERDES_RD_TOUT', "MPI Indirect read timeout: addr=0x%08X\n"),
    (2, 'DBG_ID_PROV_CHANGE', "%s\n"),
]
