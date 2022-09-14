import os
import pytest

from infra.test_base import idparametrize
from infra.test_base_mbu import TestBaseMbu
from tools.utils import get_atf_logger

log = get_atf_logger()
multiboost_loopbacks = os.environ.get("LOOPBACKS", "Msm,PHY NET,RJ45").split(",")
multiboost_timeout = os.environ.get("MULTIBOOST_TIMEOUTS", '1').split(",")
pkt_size = os.environ.get("PKT_SIZE", "64:9000").split(",")
rings = os.environ.get("RINGS", "1,2,3;0,12;14,15").split(";")
no_mcp_link = os.environ.get("NO_MCP_LINK", "True").upper() == "TRUE"


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "mbu_multiboost"


class Test(TestBaseMbu):
    @classmethod
    def setup_class(cls):
        super(Test, cls).setup_class()
        try:
            import multiboost
            cls.multiboost = multiboost
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    if not no_mcp_link:
        if multiboost_loopbacks.count('Msm'):
            multiboost_loopbacks.remove('Msm')
        @idparametrize('pkts', pkt_size)
        @idparametrize('lpb', multiboost_loopbacks)
        @idparametrize('speed',  ['100M', '1G', '2.5G', '5G', '10G'])
        @idparametrize('fc', [None, 'link', 'pfc'])
        @idparametrize('t', multiboost_timeout)
        @idparametrize('rings', rings)
        def test_multi(self, pkts, lpb, speed, fc, t, rings):
            self.check_parameters(lpb, speed)
            kwargs = {
                'maccontrol': self.maccontrol,
                'interactive': True,
                'logtag': 'cli',
                'hw_cfg': {
                    'fc': fc,
                    'link': speed,
                    'no_mcp_link': no_mcp_link,
                    'loopback': lpb,
                }
            }
            self.set_seed()
            result = self.multiboost.atlantic_run('--sync_callback TRUE -t {} -p {} -r {} --final_counters ALL'.format(t,
                                                                                pkts, rings.replace(',', ' ')), **kwargs)
            assert not result['dma_error'], "Error, DMA TX != DMA RX"
            assert not result['msm_error'], "Error, MSM TX != MSM RX"
            assert not ('rx_wdpkt' in result), "Error, wrong packet count: {}".format(result['rx_wdpkt'])
            assert not ('rx_wdcnt' in result), "Error, wrong descriptor count: {}".format(result['rx_wdcnt'])
    else:
        @idparametrize('pkts', pkt_size)
        @idparametrize('lpb', multiboost_loopbacks)
        @idparametrize('speed,mode', [('100M', 'SGMII'),
                                      ('1G', 'SGMII'),
                                      ('2.5G', 'USXGMII'),
                                      ('5G', 'USXGMII'),
                                      ('10G', 'USXGMII')],
                       ids=['100M', '1G', '2.5G', '5G', '10G'])
        @idparametrize('fc', [None, 'link', 'pfc'])
        @idparametrize('t', multiboost_timeout)
        @idparametrize('rings', rings)
        def test_multi(self, pkts, lpb, speed, mode, fc, t, rings):
            self.check_parameters(lpb, speed)
            kwargs = {
                'maccontrol': self.maccontrol,
                'interactive': True,
                'logtag': 'cli',
                'hw_cfg': {
                    'fc': fc,
                    'link': speed,
                    'no_mcp_link': no_mcp_link,
                    'loopback': lpb,
                    'mpi': {
                        'mode': mode
                    },
                }
            }
            self.set_seed()
            result = self.multiboost.atlantic_run( '--sync_callback TRUE -t {} -p {} -r {} --final_counters ALL'.format(t,
                                                                              pkts, rings.replace(',', ' ')), **kwargs)
            assert not result['dma_error'], "Error, DMA TX != DMA RX"
            assert not result['msm_error'], "Error, MSM TX != MSM RX"
            assert not ('rx_wdpkt' in result), "Error, wrong packet count: {}".format(result['rx_wdpkt'])
            assert not ('rx_wdcnt' in result), "Error, wrong descriptor count: {}".format(result['rx_wdcnt'])


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
