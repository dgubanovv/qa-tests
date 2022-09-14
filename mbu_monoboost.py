import os
import pytest
import yaml
import urlparse

from infra.test_base import idparametrize
from infra.test_base_mbu import TestBaseMbu
from tools.utils import get_atf_logger
from tools.command import Command
from tools.constants import DIST_SERVER

log = get_atf_logger()
monoboost_loopbacks = os.environ.get("LOOPBACKS", "Msm,PHY NET").split(",")
monoboost_timeout = os.environ.get("MONOBOOST_TIMEOUTS", '1').split(",")
pkt_size = os.environ.get("PKT_SIZE", '64:9000').split(",")
no_mcp_link = os.environ.get("NO_MCP_LINK", "True").upper() == "TRUE"
x550_net_loopback = os.environ.get("X550_NET_LOOPBACK", "False").upper() == "TRUE"

if x550_net_loopback:
    monoboost_loopbacks.append(None)


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "mbu_monoboost"


def x550_net_loopback(lkp, script_dir, status):
    cmd = "sudo python {}/x550_net_loopback.py {}".format(script_dir, status)
    res = Command(cmd=cmd, host=lkp).run_join(15)
    if res['returncode'] != 0:
        raise ValueError(
            "Cannot {} net loopback. Script 'x550_net_loopback.py' returned with exit code '{}' and output: \n    {}".format(
                status, res['returncode'], '\n    '.join(res['output'])))


def x550_autoneg(lkp, script_dir, speed):
    cmd = "sudo python {}/x550_autoneg.py {}".format(script_dir, speed)
    res = Command(cmd=cmd, host=lkp).run_join(15)
    if res['returncode'] != 0:
        raise ValueError(
            "Cannot set speed '{}'. Script 'x550_autoneg.py' returned with exit code '{}' and output: \n    {}".format(
                speed, res['returncode'], '\n    '.join(res['output'])))


def x550_rx_status(lkp, script_dir):
    cmd = "sudo python {}/x550_rx_status.py".format(script_dir)
    res = Command(cmd=cmd, host=lkp).run_join(15)
    if res['returncode'] != 0:
        raise ValueError(
            "Cannot get status. Script 'x550_rx_status.py' returned with exit code '{}' and output: \n    {}".format(
                res['returncode'], '\n    '.join(res['output'])))


class Test(TestBaseMbu):
    @classmethod
    def setup_class(cls):
        super(Test, cls).setup_class()
        try:
            if x550_net_loopback:
                cls.lkp_dir = "/home/aqtest"
                script_dir = cls.lkp_dir + "/PlatfromDrivers"
                import commonArgParse
                cls.install_driver_to_lkp(cls.lkp_hostname)
                cls.download_and_unzip_to_lkp(cls.lkp_hostname, "intel_x550/PlatfromDrivers.tar.gz")

                def callback_before_link_up(*args, **kwargs):
                    mc = kwargs.get("maccontrol")
                    speed = mc.devprop['link'].value
                    x550_net_loopback(cls.lkp_hostname, script_dir, 'disable')
                    x550_autoneg(cls.lkp_hostname, script_dir, speed)
                    return True

                def callback_after_link_up(*args, **kwargs):
                    x550_net_loopback(cls.lkp_hostname, script_dir, 'enable')
                    x550_rx_status(cls.lkp_hostname, script_dir)
                    return True

                commonArgParse.available_callbacks['BEFORE_LINK_UP'] = callback_before_link_up
                commonArgParse.available_callbacks['AFTER_LINK_UP'] = callback_after_link_up
            import monoboost
            cls.monoboost = monoboost
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    if not no_mcp_link:
        if monoboost_loopbacks.count('Msm'):
            monoboost_loopbacks.remove('Msm')
        @idparametrize('pkts', pkt_size)
        @idparametrize('lpb', monoboost_loopbacks)
        @idparametrize('speed', ['100M', '1G', '2.5G', '5G', '10G'])
        @idparametrize('fc', [None, 'link', 'pfc'])
        @idparametrize('t', monoboost_timeout)
        def test_mono(self, pkts, lpb, speed, fc, t):
            self.check_parameters(lpb, speed)
            from globalVars import mblInfo
            logtag = 'cli'
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
            if x550_net_loopback and lpb is None:
                if speed in ["100M", "1G"]:
                    pytest.skip("This setup doesn't run on 100M and 1G.")
                mblInfo(logtag, 'Running monoboost.py --before_link_up_callback BEFORE_LINK_UP --sync_callback '
                                     'AFTER_LINK_UP -t {} -p {} -ic True --final_counters ALL'.format(t, pkts))
                self.set_seed()
                result = self.monoboost.atlantic_run(
                    '--before_link_up_callback BEFORE_LINK_UP --sync_callback AFTER_LINK_UP -t {} -p {} -fcc True --final_counters ALL'.format(
                        t, pkts), **kwargs)
            else:
                mblInfo(logtag, 'Running monoboost.py --sync_callback TRUE -t {} -p {}  --final_counters ALL'.format(t, pkts))
                self.set_seed()
                result = self.monoboost.atlantic_run('--sync_callback TRUE -t {} -p {}  --final_counters ALL'.format(t, pkts), **kwargs)

            tx_dma_pkt_cntr = result['counters']['Tx DMA']['TxDMAGoodPacketCounter']
            rx_dma_pkt_cntr = result['counters']['Rx DMA']['RxDmaGoodPacketCounter']
            tx_msm_pkt_cntr = result['counters']['MacPhy']['MSM']['TxGoodFrameCounterBits']
            rx_msm_pkt_cntr = result['counters']['MacPhy']['MSM']['RxGoodFrameCounterBits']

            dma_diff = float(rx_dma_pkt_cntr) / float(tx_dma_pkt_cntr)
            msm_diff = float(rx_msm_pkt_cntr) / float(tx_msm_pkt_cntr)

            mblInfo(logtag, "Tx DMA Good Packet Counter : {}".format(tx_dma_pkt_cntr))
            mblInfo(logtag, "Rx DMA Good Packet Counter : {}".format(rx_dma_pkt_cntr))
            mblInfo(logtag, "Proportion of DMA received good packets {}%".format(dma_diff * 100))

            mblInfo(logtag, "Tx MSM Good Frame Counter Bits : {}".format(tx_msm_pkt_cntr))
            mblInfo(logtag, "Rx MSM  Good Frame Counter Bits : {}".format(rx_msm_pkt_cntr))
            mblInfo(logtag, "Proportion of MSM received good packets : {}%".format(msm_diff * 100))

            if lpb is None and speed == '10G' and x550_net_loopback:
                assert result['counters']['PHY']["LDPCCRC8ErrorCounter"] < 5, \
                    'Error, LDPC CRC 8 Error Counter  : {}'.format(result['counters']['PHY']["LDPCCRC8ErrorCounter"])

                assert dma_diff > 0.999, "Error, difference between TX DMA and RX DMA have to be less " \
                                         "than 0.1%, founded {}%".format((1.0 - dma_diff) * 100)
                assert msm_diff > 0.999, "Error, difference between TX MSM and RX MSM have to be less " \
                                         "than 0.1%, founded {}%".format((1.0 - msm_diff) * 100)
            else:
                assert not result['dma_error'], "Error, DMA TX != DMA RX"
                assert not result['msm_error'], "Error, MSM TX != MSM RX"
                assert not ('rx_wdpkt' in result), "Error, wrong packet count: {}".format(result['rx_wdpkt'])
                assert not ('rx_wdcnt' in result), "Error, wrong descriptor count: {}".format(result['rx_wdcnt'])
    else:
        @idparametrize('pkts', pkt_size)
        @idparametrize('lpb', monoboost_loopbacks)
        @idparametrize('speed,mode', [('100M', 'USXGMII'),
                                      ('1G', 'USXGMII'),
                                      ('2.5G', 'USXGMII'),
                                      ('5G', 'USXGMII'),
                                      ('10G', 'USXGMII')],
                       ids=['100M', '1G', '2.5G', '5G', '10G'])
        @idparametrize('fc', [None, 'link', 'pfc'])
        @idparametrize('t', monoboost_timeout)
        def test_mono(self, pkts, lpb, speed, mode, fc, t):
            self.check_parameters(lpb, speed)
            from globalVars import mblInfo
            logtag = 'cli'
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
            if x550_net_loopback and lpb is None:
                if speed in ["100M", "1G"]:
                    pytest.skip("This setup doesn't run on 100M and 1G.")
                mblInfo(logtag, 'Running monoboost.py --before_link_up_callback BEFORE_LINK_UP --sync_callback '
                                'AFTER_LINK_UP -t {} -p {} -ic True --final_counters ALL'.format(t, pkts))
                self.set_seed()
                result = self.monoboost.atlantic_run(
                    '--before_link_up_callback BEFORE_LINK_UP --sync_callback AFTER_LINK_UP -t {} -p {} -fcc True --final_counters ALL'.format(
                        t, pkts), **kwargs)
            else:
                mblInfo(logtag,
                        'Running monoboost.py --sync_callback TRUE -t {} -p {}  --final_counters ALL'.format(t,
                                                                                                             pkts))
                self.set_seed()
                result = self.monoboost.atlantic_run(
                    '--sync_callback TRUE -t {} -p {}  --final_counters ALL'.format(t, pkts), **kwargs)

            tx_dma_pkt_cntr = result['counters']['Tx DMA']['TxDMAGoodPacketCounter']
            rx_dma_pkt_cntr = result['counters']['Rx DMA']['RxDmaGoodPacketCounter']
            tx_msm_pkt_cntr = result['counters']['MacPhy']['MSM']['TxGoodFrameCounterBits']
            rx_msm_pkt_cntr = result['counters']['MacPhy']['MSM']['RxGoodFrameCounterBits']

            dma_diff = float(rx_dma_pkt_cntr) / float(tx_dma_pkt_cntr)
            msm_diff = float(rx_msm_pkt_cntr) / float(tx_msm_pkt_cntr)

            mblInfo(logtag, "Tx DMA Good Packet Counter : {}".format(tx_dma_pkt_cntr))
            mblInfo(logtag, "Rx DMA Good Packet Counter : {}".format(rx_dma_pkt_cntr))
            mblInfo(logtag, "Proportion of DMA received good packets {}%".format(dma_diff * 100))

            mblInfo(logtag, "Tx MSM Good Frame Counter Bits : {}".format(tx_msm_pkt_cntr))
            mblInfo(logtag, "Rx MSM  Good Frame Counter Bits : {}".format(rx_msm_pkt_cntr))
            mblInfo(logtag, "Proportion of MSM received good packets : {}%".format(msm_diff * 100))

            if lpb is None and speed == '10G' and x550_net_loopback:
                assert result['counters']['PHY']["LDPCCRC8ErrorCounter"] < 5, \
                    'Error, LDPC CRC 8 Error Counter  : {}'.format(result['counters']['PHY']["LDPCCRC8ErrorCounter"])

                assert dma_diff > 0.999, "Error, difference between TX DMA and RX DMA have to be less " \
                                         "than 0.1%, founded {}%".format((1.0 - dma_diff) * 100)
                assert msm_diff > 0.999, "Error, difference between TX MSM and RX MSM have to be less " \
                                         "than 0.1%, founded {}%".format((1.0 - msm_diff) * 100)
            else:
                assert not result['dma_error'], "Error, DMA TX != DMA RX"
                assert not result['msm_error'], "Error, MSM TX != MSM RX"
                assert not ('rx_wdpkt' in result), "Error, wrong packet count: {}".format(result['rx_wdpkt'])
                assert not ('rx_wdcnt' in result), "Error, wrong descriptor count: {}".format(result['rx_wdcnt'])

    @classmethod
    def install_driver_to_lkp(cls, lkp):
        cls.download_and_unzip_to_lkp(lkp, "intel_x550/ixgbe-5.5.3.tar.gz")
        make_cmd = "ssh aqtest@{} 'cd  {}/ixgbe-5.5.3/src && make'".format(lkp, cls.lkp_dir)
        Command(cmd=make_cmd).run_join(10)
        rmmod_cmd = "ssh aqtest@{} 'sudo rmmod ixgbe'".format(lkp)
        Command(cmd=rmmod_cmd).run_join(10)
        drv_install_cmd = "ssh aqtest@{} 'sudo modprobe ixgbe'".format(lkp)
        Command(cmd=drv_install_cmd).run_join(10)

    @classmethod
    def download_and_unzip_to_lkp(cls, lkp, suburl):
        url = urlparse.urljoin(DIST_SERVER, suburl)
        log.info("Downloading {}".format(url))
        download_cmd = "ssh aqtest@{} 'wget {} {}'".format(lkp, url, cls.lkp_dir)
        Command(cmd=download_cmd).run_join(15)
        unzip_cmd = "ssh aqtest@{} 'tar -xvzf {}/{}'".format(lkp, cls.lkp_dir, suburl.split('/')[-1])
        Command(cmd=unzip_cmd).run_join(10)
        del_cmd = "ssh aqtest@{} 'rm {}/{}.*'".format(lkp, cls.lkp_dir, suburl.split('/')[-1])
        Command(cmd=del_cmd).run_join(5)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
