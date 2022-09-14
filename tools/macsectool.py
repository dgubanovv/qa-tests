import json
import yaml

from command import Command
from utils import get_atf_logger, get_domain_bus_dev_func, upload_file, download_file

# Hack to avoid references in PyYAML
yaml.Dumper.ignore_aliases = lambda *args: True

log = get_atf_logger()

SCRIPT_STATUS_SUCCESS = "[MACSEC-TOOL-SUCCESS]"
SCRIPT_STATUS_FAILED = "[MACSEC-TOOL-FAILED]"

"""
Usage: macsecTool -d DEVICE [-t TYPE] [--phy_type PHY_TYPE] [--phy_id PHY_ID]
                  [-y YAML] [--curr_sa [SC.]SA] [-c] [-s[IA.EA.EC]] [--json]
                  [--cc] [--ss]

Options:

    -h, --help   Display help message.

    -d DEVICE    Device name from listDevices tool.
                 You can use shortcuts to access the first device
                 in a family: PCI, T6, BB, TCP.
                 Default: PCI.
    -t TYPE      Device type. By default program tries to detect device
                 type by analyzing DEVICE name.
                 You can specify one of the following: PCI, T6, BB, TCP.
    --phy_type PHY_TYPE
                 PHY device type. One of the following:
                 APPIA, HHD, EUR, CAL, RHEA. Default=EUR
    --phy_id PHY_ID
                 PHY device ID. By default the program will try to detect
                 it automatically.
    -y           YAML config file.
    --curr_sa [SC.]SA
                 Change current SA. Default SC is 0.
    -c           Clear MACSEC configuration.
    -s[IA.EA.EC] Output MACSEC statistics.
                 IA.EA.EC - read request in next format:
                 <Ingress SA Index>.<Egress SA Index>.<Egress SC Index>
                 > 31 means get accumulated statistics for that type of record.
                 Default: accumulated statistics for all records.
    --json       Output statistics in json format.
    --cc         Clear MACSEC counters.
    --ss         Output current MACSEC configuration.
"""


class MacsecTool(object):
    def __init__(self, **kwargs):
        self.port = kwargs["port"]
        self.host = kwargs.get("host", None)
        self.device = kwargs.get("device", None)

        if self.device is None:
            _, bus, dev, func = get_domain_bus_dev_func(self.port)
            self.bus_address = '{:02x}:{:02x}.{:01x}'.format(bus, dev, func)
        else:
            self.bus_address = self.device

    @staticmethod
    def gen_config(src_mac, dst_mac, tx_key, rx_key, tx_pn=1, rx_pn=0):
        src_mac = src_mac.lower()
        dst_mac = dst_mac.lower()
        # Workaround for windows
        if type(src_mac) is unicode:
            src_mac = src_mac.encode('ascii', 'ignore')
        if type(dst_mac) is unicode:
            dst_mac = dst_mac.encode('ascii', 'ignore')

        rx_sci = '0x' + src_mac.replace(':', '') + '0001'
        tx_sci = '0x' + dst_mac.replace(':', '') + '0001'

        macsec_yaml = dict(
            # Filter out MAC control packets (bypass remaining modules)
            EGRESS=dict(
                PRECTLF=[
                    dict(
                        MAC_ADDR='00:17:b6:00:00:00',
                        ETH_TYPE=0x1234,
                        # Match mask (16 bits) is per-nibble (half of a byte)
                        # 0 means nibble will always match
                        MATCH_MASK=0xffff,
                        # 0: No compare, i.e. This entry is not used
                        # 1: compare DA only
                        # 2: compare SA only
                        # 3: compare half DA + half SA
                        # 4: compare ether type only
                        # 5: compare DA + ethertype
                        # 6: compare SA + ethertype
                        # 7: compare DA + range [DA:DA + ether type)
                        MATCH_TYPE=4,
                    )
                ],
                # Secure Channels configuration
                SC=[
                    dict(
                        # Define classifiers for that SC
                        PRECLASS=[
                            dict(
                                # SCI mask (8 bits) is per-byte (MAC_SA + PORT_IDENT)
                                SCI=rx_sci,
                                SCI_MASK=0x0,
                                # TCI mask (8 bits) is per-bit (including AN)
                                TCI=0xb,
                                TCI_MASK=0x0,
                                # Ethernet type mask (2 bits) is per-byte
                                ETH_TYPE=0x0,
                                ETH_TYPE_MASK=0x0,
                                # SNAP mask (5 bits) is per-byte
                                SNAP=0x0000000000,
                                SNAP_MASK=0,
                                # LLC mask (3 bits) is per-byte
                                LLC=0x000000,
                                LLC_MASK=0,
                                # SA MAC address mask (6 bits) is per-byte
                                MAC_SA=src_mac,
                                MAC_SA_MASK=0x3f,
                                # DA MAC address mask (6 bits) is per-byte
                                MAC_DA=dst_mac,
                                MAC_DA_MASK=0x3f,  # send and recive ARP
                                # Packet number mask (4 bits) is per-byte
                                PN=0x00000000,
                                PN_MASK=0,
                                # 0: Packets don't have explicit SecTAG
                                # 1: Packets already have explicit SecTAG
                                EXP_SECTAG_EN=0,
                                # 0: Use TCI V, ES, SCB, E, and C bits from explicit SecTAG
                                # 1: Use TCI V, ES, SCB, E, and C bits from table
                                TCI_87543=0,
                                # 0: Use TCI SC bit from explicit SecTAG
                                # 1: Use TCI SC bit from table
                                TCI_SC=0,
                                # 0: Process and forward to next two modules for 802.1AE encryption
                                # 1: Bypass the next two encryption modules. This is an uncontrolled-port packet
                                # 2: Drop this packet
                                ACTION=0,
                            )
                        ],
                        # SC-specific parameters
                        PARAMS=dict(
                            CURR_AN=0,
                            # 0: Expired SAs will be invalidated
                            # 1: Expired SAs will not be invalidated
                            AN_ROLL=1,
                            TCI=0xb,
                            ENCR_OFFSET=0,
                            # 0: Forward
                            # 1: Protect
                            PROTECT_FRAMES=1,
                        ),
                        # Secure Associations configuration (can be 1, 2 or 4)
                        SA=[
                            dict(
                                NEXT_PN=tx_pn,
                                # Key can be 128, 192 or 256 bits
                                KEY=tx_key,
                            )
                        ]
                    )
                ]
            ),
            INGRESS=dict(
                PRECTLF=[
                    dict(
                        MAC_ADDR='00:17:b6:00:00:00',
                        ETH_TYPE=0x1234,
                        MATCH_MASK=0x0,
                        MATCH_TYPE=0x0,
                    )
                ],
                SC=[
                    dict(
                        PRECLASS=[
                            dict(
                                ENCR_OFFSET=0,
                                SCI=tx_sci,
                                SCI_MASK=0x0,
                                # TCI mask (6 bits) is per-bit (6 upper bits of TCI field, excluding AN)
                                TCI=0xb,
                                TCI_MASK=0,
                                ETH_TYPE=0x88e5,
                                ETH_TYPE_MASK=0x3,
                                SNAP=0x0000000000,
                                SNAP_MASK=0,
                                LLC=0x000000,
                                LLC_MASK=0,
                                MAC_SA=dst_mac,
                                MAC_SA_MASK=0x3f,
                                MAC_DA=src_mac,
                                MAC_DA_MASK=0x3f,  # send and resive ARP
                                # Loopback packet mask is 1 bit (enable checking if this is loopback
                                # packet or not)
                                LPBK_PACKET=0,
                                LPBK_MASK=0,
                                # 0: Process and forward to next two modules for 802.1AE decryption
                                # 1: Process but keep SECTAG
                                # 2: Bypass the next two decryption modules but process by post-classification
                                # 3: Drop this packet
                                ACTION=0,
                                # 0: This is a controlled-port packet
                                # 1: This is an uncontrolled-port packet
                                CTRL_UNCTRL=0,
                                # Use the SCI value from the Table if SC bit of the input packet is not present
                                SCI_FROM_TABLE=0,
                            )
                        ],
                        PARAMS=dict(
                            # 0: Strict
                            # 1: Check
                            # 2: Disabled
                            VALIDATE_FRAMES=1,
                            REPLAY_PROTECT=0,
                            ANTI_REPLAY_WINDOW=0x00000000,
                        ),
                        SA=[
                            dict(
                                NEXT_PN=rx_pn,
                                KEY=rx_key,
                            ),
                        ]
                    )
                ]
            )
        )

        return macsec_yaml

    def _run_macsec_cmd(self, cmd):
        res = Command(cmd='sudo macsecTool -d {} {}'.format(self.bus_address, cmd), host=self.host).run()
        if res["returncode"] != 0:
            log.info(SCRIPT_STATUS_FAILED)
            raise Exception("Cannot setup MacSec on PHY")
        log.info(SCRIPT_STATUS_SUCCESS)

        return res

    def dump_conf(self, cfg_name):
        self._run_macsec_cmd('-ss > {}'.format(cfg_name))

        if self.host is not None:
            download_file(self.host, '~/{}'.format(cfg_name), cfg_name)

    def clear_conf(self):
        self._run_macsec_cmd('-c')

    def configure(self, macsec_yaml):
        with open('macsec.yaml', 'w') as outfile:
            yaml.dump(macsec_yaml, outfile, default_flow_style=False)

        if self.host is not None:
            upload_file(self.host, 'macsec.yaml', '~/qa-tests/macsec.yaml')

        self.clear_conf()
        self._run_macsec_cmd('-y macsec.yaml')

    def get_stats(self, index='', out_json=True):
        cmd = '-s{}'.format(index)
        if out_json:
            cmd += " --json"

        stats = self._run_macsec_cmd(cmd)

        if out_json:
            stat_dict = json.loads("".join(stats['output']))
        else:
            stat_dict = dict(tuple(i.split()) for i in stats['output'][2:])  # list to dict

        return stat_dict

    def clear_counters(self):
        self._run_macsec_cmd('-cc')

    def curr_sa(self, sa, sc=None):
        if sc is None:
            sc = 0
        self._run_macsec_cmd('--curr_sa {}.{}'.format(sc, sa))
