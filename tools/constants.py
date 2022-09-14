NFS_SERVER = "qa-nfs01"
DIST_SERVER = "http://qa-nfs01/dist/"
BUILDS_SERVER = "http://qa-nfs01/builds/"

ARCH_X86_64 = "x86_64"
ARCH_I386 = "i386"
ARCH_I686 = "i686"
ARCH_AARCH64 = "aarch64"
KNOWN_ARCHES = [ARCH_I386, ARCH_I686, ARCH_X86_64, ARCH_AARCH64]
KNOWN_X86_ARCHES = [ARCH_I386, ARCH_I686]

VENDOR_AQUANTIA = "aquantia"
VENDOR_APPLE = "apple"
VENDOR_DLINK = "dlink"
VENDOR_INTEL = "intel"
VENDOR_PACIFIC = "aquantia"
VENDOR_QNAP = "qnap"
VENDOR_REALTEK = "realtek"
VENDOR_TEHUTI = "tehuti"
VENDOR_TPLINK = "tplink"
VENDOR_MOTU = "motu"
VENDOR_UNKNOWN = "unknown"
KNOWN_VENDORS = [VENDOR_AQUANTIA, VENDOR_APPLE, VENDOR_DLINK, VENDOR_INTEL,
                 VENDOR_REALTEK, VENDOR_TEHUTI, VENDOR_TPLINK]

PHY_EUROPA = "Europa"
PHY_CALYPSO = "Calypso"
PHY_RHEA = "Rhea"
PHY_ANTIGUA = "Antigua"
KNOWN_PHYS = [PHY_EUROPA, PHY_CALYPSO, PHY_RHEA]

MAC_ATLANTIC1_A0 = "AtlanticA0"
MAC_ATLANTIC1_B0 = "AtlanticB0"
MAC_ATLANTIC1_B1 = "AtlanticB1"
MAC_ATLANTIC2_A0 = "Atlantic2"

CARD_NIKKI = "Nikki"
CARD_JAMAICA = "Jamaica"
CARD_BAMBI = "Bambi"
CARD_FELICITY = "Felicity"
CARD_FELICITY_KR = "felicity_kr"
CARD_FELICITY_EUROPA = "felicity_europa"
CARD_BERMUDA_A0 = "BermudaA0"
CARD_BERMUDA_B0 = "Bermuda"
CARD_FIJI = "Fiji"
CARD_ATLANTIC2 = "Atlantic2"
CARD_ANTIGUA = "Antigua"
CARD_ANTIGUA_LOM = "Antigua_LOM"
KNOWN_CARDS = [CARD_NIKKI, CARD_JAMAICA, CARD_BAMBI, CARD_FELICITY, CARD_FELICITY_KR, CARD_FELICITY_EUROPA,
               CARD_BERMUDA_A0, CARD_BERMUDA_B0, CARD_FIJI, CARD_ATLANTIC2, CARD_ANTIGUA, CARD_ANTIGUA_LOM]
FELICITY_CARDS = [CARD_FELICITY, CARD_FELICITY_KR, CARD_FELICITY_EUROPA]
BERMUDA_CARDS = [CARD_BERMUDA_A0, CARD_BERMUDA_B0]
CARDS_FELICITY_BERMUDA = BERMUDA_CARDS + FELICITY_CARDS
CHIP_REV_B0 = "B0"
CHIP_REV_B1 = "B1"

RATE_ADAPTATION_UNKNOW = 'Undefined Rate Adaptation'
RATE_ADAPTATION_NO = 'Not Rate Adaptation'
RATE_ADAPTATION_USX = 'USX Rate Adaptation'
RATE_ADAPTATION_PAUSE = 'Pause Rate Adaptation'

# media-independent interface (MII)
MII_MODE_AUTO = 'AUTO'
MII_MODE_2500BASE_X = '2500BASE-X'
MII_MODE_OCSGMII = 'OCSGMII'
MII_MODE_USX = 'USX'
MII_MODE_USX_DIV2 = 'USXDIV2'
MII_MODE_USX_SGMII = 'USX_SGMII'
MII_MODE_XFI = 'XFI'
MII_MODE_XFI_DIV2 = 'XFIDIV2'
MII_MODE_XFI_DIV2_OCSGMII_SGMII = 'XFIDIV2_OCSGMII_SGMII'
MII_MODE_XFI_SGMII = 'XFI_SGMII'
MII_MODE_XFI_XSGMII = 'XFI_XSGMII'
MII_MODE_SGMII = 'SGMII'

MII_MODES = [MII_MODE_SGMII, MII_MODE_XFI_SGMII, MII_MODE_XFI_DIV2_OCSGMII_SGMII, MII_MODE_XFI_DIV2, MII_MODE_XFI,
             MII_MODE_USX_SGMII, MII_MODE_USX_DIV2, MII_MODE_USX, MII_MODE_OCSGMII, MII_MODE_2500BASE_X,
             MII_MODE_XFI_XSGMII]


MII_RXAUI = "RXAUI"
MII_MAC = "MAC"
MII_OFF = "OFF"
MII_BACKPLANE_KR = "Backplane_KR"
MII_BACKPLANE_KX = "Backplane_KX"
MII_XAUI = "XAUI"
MII_XAUI_PAUSE_BASED = "XAUI_Pause_Based"


MDI_NORMAL = "MDINormal"
MDI_SWAP = "MDISwap"

LINK_STATE_UP = "LINK_UP"
LINK_STATE_DOWN = "LINK_DOWN"

LINK_SPEED_10M = "10M"
LINK_SPEED_100M = "100M"
LINK_SPEED_1G = "1G"
LINK_SPEED_2_5G = "2.5G"
LINK_SPEED_N2_5G = "N2.5G"
LINK_SPEED_5G = "5G"
LINK_SPEED_N5G = "N5G"
LINK_SPEED_10G = "10G"
LINK_SPEED_AUTO = "AUTO"
LINK_SPEED_NO_LINK = "NO_LINK"
KNOWN_LINK_SPEEDS = [LINK_SPEED_10M, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]
ALL_LINK_SPEEDS = [LINK_SPEED_10M, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G]

SPEED_TO_MBITS = {
    LINK_SPEED_10M: 10,
    LINK_SPEED_100M: 100,
    LINK_SPEED_1G: 1000,
    LINK_SPEED_2_5G: 2500,
    LINK_SPEED_5G: 5000,
    LINK_SPEED_10G: 10000
}

NO_LOOPBACK = 'No Loopback'
SYSTEM_INTERFACE_SYSTEM_LOOPBACK = 'System Interface - System Loopback'
SYSTEM_INTERFACE_NETWORK_LOOPBACK = 'System Interface - Network Loopback'
SYSTEM_SIDE_SHALLOW_LOOPBACK = 'System Side - Shallow Loopback'
LINE_SIDE_SHALLOW_LOOPBACK = 'Line Side - Shallow Loopback'
NETWORK_INTERFACE_SYSTEM_LOOPBACK = 'Network Interface - System Loopback'
NETWORK_INTERFACE_NETWORK_LOOPBACK = 'Network Interface - Network Loopback'

ENABLE = 'enable'
ENABLE_LINK = 'enable_link'
ENABLE_PRIORITY = 'enable_priority'
DISABLE = 'disable'


EGRESS = 'egress'
INGRESS = 'ingress'

SIF_SIDE = 'sif'
LINE_SIDE = 'line'

DIRECTION_RX = "rx"
DIRECTION_TX = "tx"
DIRECTION_RXTX = "rxtx"

DUPLEX_FULL = "full-duplex"
DUPLEX_HALF = "half-duplex"

OFFLOADS_STATE_ON = "on"
OFFLOADS_STATE_OFF = "off"
OFFLOADS_STATE_DSBL = "Disable"
OFFLOADS_STATE_ENBL = "Enable"
OFFLOADS_STATE_TX = "Tx"
OFFLOADS_STATE_RX = "Rx"
OFFLOADS_STATE_TX_RX = "Tx/Rx"

USB_CONNECT_DIRECT = "direct"
USB_CONNECT_HUB3P = "USBHub3p"
USB_CONNECT_CSWITCH = "USBCSwitch"

OS_CENTOS6_8_64 = "CentOS6.8-64"
OS_CENTOS7_2_64 = "CentOS7.2-64"
OS_CENTOS7_7_64 = "CentOS7.7-64"
OS_UBUNTU_16_04_64 = "Ubuntu16.04-64"
OS_UBUNTU_18_04_64 = "Ubuntu18.04-64"
OS_UBUNTU_19_04_64 = "Ubuntu19.04-64"
OS_RHEL7_3_64 = "RHEL7.3-64"
OS_RHEL7_4_64 = "RHEL7.4-64"
OS_RHEL7_5_64 = "RHEL7.5-64"
OS_RHEL8_0_64 = "RHEL8.0-64"
OS_FEDORA24_64 = "Fedora24-64"
OS_WIN7_32 = "Win7-32"
OS_WIN7_64 = "Win7-64"
OS_WIN8_32 = "Win8-32"
OS_WIN8_64 = "Win8-64"
OS_WIN8_1_32 = "Win8.1-32"
OS_WIN8_1_64 = "Win8.1-64"
OS_WIN10_32 = "Win10-32"
OS_WIN10_64 = "Win10-64"
OS_WIN10_1_32 = "Win10.1-32"
OS_WIN10_1_64 = "Win10.1-64"
OS_WIN10_2_32 = "Win10.2-32"
OS_WIN10_2_64 = "Win10.2-64"
OS_WIN10_3_32 = "Win10.3-32"
OS_WIN10_3_64 = "Win10.3-64"
OS_WIN10_4_32 = "Win10.4-32"
OS_WIN10_4_64 = "Win10.4-64"
OS_WIN10_5_32 = "Win10.5-32"
OS_WIN10_5_64 = "Win10.5-64"
OS_WIN10_6_32 = "Win10.6-32"
OS_WIN10_6_64 = "Win10.6-64"
OS_WIN10_7_32 = "Win10.7-32"
OS_WIN10_7_64 = "Win10.7-64"
OS_WINSRV_2019 = "Win2019-64"
OS_MAC_10_12 = "MacOS10.12-64"
OS_FREEBSD_11_2 = "FreeBSD11.2-64"
OS_FREEBSD_12_0 = "FreeBSD12.0-64"
OS_QNX = "QNX"
OS_UNKNOWN = "UNKNOWN"

WIN_OSES = [OS_WIN7_32, OS_WIN7_64, OS_WIN8_32, OS_WIN8_64,
            OS_WIN8_1_32, OS_WIN8_1_64, OS_WIN10_32, OS_WIN10_64,
            OS_WIN10_1_32, OS_WIN10_1_64, OS_WIN10_2_32, OS_WIN10_2_64,
            OS_WIN10_3_32, OS_WIN10_3_64, OS_WIN10_4_32, OS_WIN10_4_64,
            OS_WIN10_5_32, OS_WIN10_5_64, OS_WINSRV_2019, OS_WIN10_6_32,
            OS_WIN10_6_64, OS_WIN10_7_32, OS_WIN10_7_64]

CENTOS_OSES = [OS_CENTOS6_8_64, OS_CENTOS7_2_64, OS_CENTOS7_7_64]

UBUNTU_OSES = [OS_UBUNTU_16_04_64, OS_UBUNTU_18_04_64, OS_UBUNTU_19_04_64]

RHEL_OSES = [OS_RHEL7_3_64, OS_RHEL7_4_64, OS_RHEL7_5_64, OS_RHEL8_0_64]

LINUX_OSES = CENTOS_OSES + UBUNTU_OSES + RHEL_OSES

MAC_OSES = [OS_MAC_10_12]
QNX_OSES = [OS_QNX]
FREEBSD_OSES = [OS_FREEBSD_11_2, OS_FREEBSD_12_0]

KNOWN_OSES = WIN_OSES + LINUX_OSES + MAC_OSES + QNX_OSES + FREEBSD_OSES

WORKING_DIR_EVAR_NAME = "WORKING_DIR"
ATF_SCRIPTS_DIR = "$1 && cd qa-automation/aqtest/aqtest"

# if sys.platform == "darwin":
#     ATF_REPO_DIR = "/Users/aqtest/qa-tests"
# else:
#     ATF_REPO_DIR = "/home/aqtest/qa-tests"
ATF_REPO_DIR = "qa-tests"
ATF_TOOLS_DIR = ATF_REPO_DIR + "/tools"

BOOTP_SERVER = "http://nn-ap01.rdc-lab.marvell.com/bootp"
METRIC_SERVER = "http://statistic-01.rdc-lab.marvell.com/metric/add/"

HTTP_RETRY_COUNT = 3
HTTP_RETRY_INTERVAL = 15

INTERRUPT_TYPE_LEGACY = 0
INTERRUPT_TYPE_MSI = 0x1

MTU_1500 = 1500
MTU_2000 = 2000
MTU_4000 = 4000
MTU_9000 = 9000
MTU_16000 = 16000
MTU_DISABLED = 0
MTUS = [MTU_1500, MTU_2000, MTU_4000, MTU_9000, MTU_16000, MTU_DISABLED]

MTU_MAP_WIN = {MTU_1500: 1514, MTU_2000: 2040, MTU_4000: 4088, MTU_9000: 9014, MTU_16000: 16348, MTU_DISABLED: 1514}
MTU_MAP_LIN = {MTU_1500: 1500, MTU_2000: 2026, MTU_4000: 4074, MTU_9000: 9000, MTU_16000: 16348, MTU_DISABLED: 1500}

SETUP_PERFORMANCE_LOW = "Low"
SETUP_PERFORMANCE_MEDIUM = "Medium"
SETUP_PERFORMANCE_HIGH = "High"

LIN_PAUSE_SYMMETRIC = "symmetric"
LIN_PAUSE_SYMMETRIC_RECEIVE = "symmetric_receive_only"
LIN_PAUSE_NO = "no"
LIN_PAUSE_TRANSMIT = "transmit_only"