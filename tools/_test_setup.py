import os
import tempfile

# os.environ["DUT_HOSTNAME"] = "at136-h170"  # uncomment if test is run on LKP
os.environ["LKP_HOSTNAME"] = "atXXX-xxx"  # uncomment if test is run on DUT

"""
DUT setup
"""
os.environ["DUT_PORT"] = "pci1.00.0"
os.environ["DUT_DRV_VERSION"] = "2x/latest"
os.environ["DUT_FW_VERSION"] = "3x/latest"
os.environ["DUT_FW_CARD"] = "Nikki"
os.environ["DUT_FW_SPEED"] = "10G"
os.environ["DUT_FW_MDI"] = "MDINormal"
os.environ["DUT_FW_MII"] = "USX_SGMII"
os.environ["DUT_FW_PAUSE"] = "no"
os.environ["DUT_FW_PCIROM"] = "0.0.1"
os.environ["DUT_FW_DIRTYWAKE"] = "no"
os.environ["DUT_DEV_ID"] = "0x07B1"
os.environ["DUT_SUBSYS_ID"] = "0x0001"
os.environ["DUT_SUBVEN_ID"] = "0x1D6A"
os.environ["DUT_USB_CONNECT"] = "direct"
os.environ["GAMING_BUILD"] = "1.1.113.0-whql.442"
os.environ["DUT_PORTS"] = "pci1.00.0;pci4.00.0"
os.environ["DUT_DEV_IDS"] = "0xd109;0x7b1"

"""
LKP setup
"""
os.environ["LKP_PORT"] = "pci1.00.0"
os.environ["LKP_DRV_VERSION"] = "2x/stable"
os.environ["LKP_FW_VERSION"] = "3x/stable"
os.environ["LKP_FW_CARD"] = "Nikki"
os.environ["LKP_FW_SPEED"] = "10G"
os.environ["LKP_FW_MDI"] = "MDINormal"
os.environ["LKP_FW_MII"] = "USX_SGMII"
os.environ["LKP_FW_PAUSE"] = "no"
os.environ["LKP_FW_PCIROM"] = "0.0.1"
os.environ["LKP_FW_DIRTYWAKE"] = "no"
os.environ["LKP_DEV_ID"] = "0x07B1"
os.environ["LKP_SUBSYS_ID"] = "0x0001"
os.environ["LKP_SUBVEN_ID"] = "0x1D6A"
os.environ["LKP_USB_CONNECT"] = "direct"

"""
Tools setup
"""
os.environ["MBU_VERSION"] = "latest"
os.environ["DIAG_VERSION"] = "latest"
os.environ["EFI_VERSION"] = "latest"

"""
Test setup
"""
os.environ["PERFORMANCE_SETUP"] = "FALSE"
os.environ["TEST_TOOL_VERSION"] = "LATEST"  # git repository branch
os.environ["WORKING_DIR"] = tempfile.gettempdir()  # test output and collected logs will be in system temp directory
os.environ["SUPPORTED_SPEEDS"] = "100M,1G,2.5G,5G,10G"
os.environ["SKIP_FW_INSTALL"] = "FALSE"
os.environ["MCP_LOG"] = "FALSE"
os.environ["SFP"] = "OPT-INTEL-FTLX8571D3BCVIT1"
os.environ["LOOPBACKS"] = "Shallow,Deep,Msm,Serdes,PHY NET,RJ45"
os.environ["MONOBOOST_TIMEOUTS"] = "1,30"
os.environ["PKT_SIZE"] = "64:9000"

"""
Uncomment if you want to upload logs to the server
Remote path will be: //LOG_SERVER/LOG_PATH/TEST/PLATFORM/JOB_ID/test_case
"""
# os.environ["SUBTEST_STATUS_API_URL"] = "http://nn-ap01.rdc-lab.marvell.com/flask/addsubtest-fake/0"
# os.environ["LOG_SERVER"] = "nn-ap01.rdc-lab.marvell.com"
# os.environ["LOG_PATH"] = "/storage/logs"
# os.environ["JOB_ID"] = "0"
# os.environ["PLATFORM"] = "MANUAL"

"""
Uncomment if you your setup has separate PHY configuration,
for example you have Felicity + Europa/Calypso/Rhea minipod or SLT board
"""
# os.environ["LKP_EEE_ENABLE"] = "TRUE"
# os.environ["DUT_PHY_BOARD_NAME"] = "M0CRRV0C0384-R1O24V0B006"
# os.environ["DUT_PHY_TYPE"] = "Rhea"
# os.environ["DUT_PHY_IDS"] = "0,1,2,3,4,5,6,7"
# os.environ["DUT_PHY_ID_TO_MDIO_MAP"] = "0,0,0,0,1,1,1,1"
# os.environ["DUT_PHY_FW_VERSION"] = "05.01.11"
# os.environ["DUT_PHY_FW_PACKAGE"] = "7x7"
# os.environ["DUT_PHY_FW_PART_NUMBER"] = "AQR113"
# os.environ["DUT_PHY_FW_SUFFIX"] = "XFI_SGMII_PPM_None_NoPtpSec_EEE"
