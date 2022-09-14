import os
import sys
import time

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.ops import OpSystem
from tools.command import Command
from tools.killer import Killer
from tools.receive_segment_coalescing import ReceiveSegmentCoalescing
from perf.iperf import Iperf
from infra.test_base import idparametrize
from infra.test_base_phy import TestBasePhy, print_statistics
from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_AUTO, LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, \
    LINK_SPEED_10G, DIRECTION_RXTX, OFFLOADS_STATE_DSBL, MTU_16000, MII_MODE_XFI, MII_MODE_XFI_SGMII, MII_MODE_USX, \
    MII_MODE_2500BASE_X, MII_MODE_OCSGMII, MII_MODE_XFI_XSGMII, MII_MODE_SGMII, MII_MODE_XFI_DIV2, MII_MODE_USX_DIV2, MII_MODE_XFI_DIV2_OCSGMII_SGMII
from tools.driver import Driver
from tools.statistics import Statistics
from perf.iperf_result import IperfResult
from tools.utils import get_atf_logger
from tools import firmware
from tools import ping

log = get_atf_logger()


MAP_MMI_LINK = {
    MII_MODE_2500BASE_X: {
        LINK_SPEED_10G: MII_MODE_XFI,
        LINK_SPEED_5G: MII_MODE_XFI,
        LINK_SPEED_2_5G: MII_MODE_OCSGMII,
        LINK_SPEED_1G: MII_MODE_SGMII,
        LINK_SPEED_100M: MII_MODE_SGMII
    },
    MII_MODE_OCSGMII: {
        LINK_SPEED_10G: MII_MODE_XFI,
        LINK_SPEED_5G: MII_MODE_XFI,
        LINK_SPEED_2_5G: MII_MODE_OCSGMII,
        LINK_SPEED_1G: MII_MODE_OCSGMII,
        LINK_SPEED_100M: MII_MODE_OCSGMII
    },
    MII_MODE_USX: {
        LINK_SPEED_10G: MII_MODE_USX,
        LINK_SPEED_5G: MII_MODE_USX,
        LINK_SPEED_2_5G: MII_MODE_USX,
        LINK_SPEED_1G: MII_MODE_USX,
        LINK_SPEED_100M: MII_MODE_USX
    },
    MII_MODE_USX_DIV2: {
        LINK_SPEED_5G: MII_MODE_XFI_DIV2,
        LINK_SPEED_2_5G: MII_MODE_XFI_DIV2,
        LINK_SPEED_1G: MII_MODE_XFI,
        LINK_SPEED_100M: MII_MODE_XFI
    },
    MII_MODE_XFI: {
        LINK_SPEED_10G: MII_MODE_XFI,
        LINK_SPEED_5G: MII_MODE_XFI,
        LINK_SPEED_2_5G: MII_MODE_XFI,
        LINK_SPEED_1G: MII_MODE_XFI,
        LINK_SPEED_100M: MII_MODE_XFI
    },
    MII_MODE_XFI_DIV2_OCSGMII_SGMII: {
        LINK_SPEED_5G: MII_MODE_XFI_DIV2,
        LINK_SPEED_2_5G: MII_MODE_OCSGMII,
        LINK_SPEED_1G: MII_MODE_SGMII,
        LINK_SPEED_100M: MII_MODE_SGMII
    },
    MII_MODE_XFI_SGMII: {
        LINK_SPEED_10G: MII_MODE_XFI,
        LINK_SPEED_5G: MII_MODE_XFI,
        LINK_SPEED_2_5G: MII_MODE_XFI,
        LINK_SPEED_1G: MII_MODE_SGMII,
        LINK_SPEED_100M: MII_MODE_SGMII
    },
    MII_MODE_XFI_XSGMII: {
         LINK_SPEED_10G: MII_MODE_XFI,
         LINK_SPEED_5G: MII_MODE_XFI,
         LINK_SPEED_2_5G: MII_MODE_XFI,
         LINK_SPEED_1G: MII_MODE_SGMII,
         LINK_SPEED_100M: MII_MODE_SGMII
    },
}

def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "phy_data_path"


class TestPhyDataPath(TestBasePhy):
    """
    @description: The test checks data path when phy is separate.

    @setup: Felicity <-> Dac cable <-> separate PHY <-> Eth cable <-> LKP
    """
    BEFORE_TRAFFIC_DELAY = 10
    IPERF_TIME = 57
    prev_mode = None

    @classmethod
    def setup_class(cls):
        super(TestPhyDataPath, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.dut_driver.install()
            cls.lkp_driver.install()

            cls.dut_ifconfig.set_ip_address(cls.DUT_IPV4_ADDR, cls.NETMASK_IPV4, None)
            cls.lkp_ifconfig.set_ip_address(cls.LKP_IPV4_ADDR, cls.NETMASK_IPV4, None)

            cls.dut_atltool = AtlTool(port=cls.dut_port)
            cls.lkp_atltool = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)

            ReceiveSegmentCoalescing(dut_hostname=cls.dut_hostname, lkp_hostname=cls.lkp_hostname).enable()

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def precondition(self, speed, mode):
        log.debug('MODE: [{}] -> [{}]'.format(TestPhyDataPath.prev_mode, mode))
        if TestPhyDataPath.prev_mode != mode:
            TestPhyDataPath.prev_mode = mode
            self.phy_firmware = firmware.PhyFirmware(phy_control=self.phy_controls[0],
                                                     version=self.dut_phy_fw_version,
                                                     package=self.dut_phy_fw_package,
                                                     part_number=self.dut_phy_fw_part_number,
                                                     suffix=self.dut_phy_fw_suffix,
                                                     mode=mode)
            self.phy_firmware.install()
            self.dut_ifconfig.mii = mode
            # burn new PHY FW
        time.sleep(5)
        self.lkp_ifconfig.set_flow_control(OFFLOADS_STATE_DSBL)
        self.dut_ifconfig.set_flow_control(OFFLOADS_STATE_DSBL)

        self.lkp_ifconfig.set_mtu(MTU_16000)
        self.dut_ifconfig.set_mtu(MTU_16000)

        self.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)

        mode = MAP_MMI_LINK[self.dut_ifconfig.mii][speed]
        self.dut_ifconfig.set_link_speed(speed, mac_sif_mode=mode)

        assert speed == self.lkp_ifconfig.wait_link_up()
        # self.lkp_ifconfig.wait_link_up()
        # self.dut_ifconfig.wait_link_up()

    def check_counters(self, is_need_to_check=False):
        phy_counters = self.read_phy_counters()
        stat = Statistics(port=self.dut_port)
        mac_counters = stat.get_mac_counters()

        print_statistics(phy_counters)
        print_statistics(mac_counters)
        Command(cmd='sudo readstat --dma_c --msm_c').run_join()
        Command(cmd='sudo readstat --dma_c --msm_c --phy_c', host=self.lkp_hostname).run_join()

        if is_need_to_check:
            for k in phy_counters.keys():
                if 'bad' in k:
                    assert phy_counters[k] == 0, 'Bad counters must be zero'

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    @idparametrize("mode", [MII_MODE_XFI_SGMII, MII_MODE_XFI, MII_MODE_OCSGMII, MII_MODE_XFI_XSGMII, MII_MODE_2500BASE_X, MII_MODE_USX])
    @idparametrize("pktlen", [80, 1500, 9000, 16000])
    def test_data_path(self, mode, speed, pktlen):
        """
        @description: This test checks that datapath works fine with special phy mode, speed and mtu.

        @steps:
        1. configure setup: burn phy firmware, set speed and mtu
        2. run traffic (iperf)
        3. check: bandwidth and phy counters

        @result:
        @duration: 120 seconds.
        """

        if speed not in self.supported_speeds:
            pytest.skip()

        if mode in [MII_MODE_XFI_XSGMII, MII_MODE_USX] and speed in [LINK_SPEED_1G, LINK_SPEED_100M]:
            pytest.skip()

        # workaround
        if mode == MII_MODE_OCSGMII and speed == LINK_SPEED_100M:
            pytest.skip()

        args = {
            'direction': DIRECTION_RXTX,
            'speed': speed,
            'num_process': 1,
            'num_threads': 1,
            'time': self.IPERF_TIME,
            'ipv': 4,
            'mss': 0,
            'bandwidth': 10000,
            'buffer_len': pktlen,
            'is_udp': True,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }

        self.precondition(speed=speed, mode=mode)
        self.check_counters()

        for i in range(3):
            log.info('iperf #{}'.format(i))

            Killer(host=self.dut_hostname).kill("iperf3")
            Killer(host=self.lkp_hostname).kill("iperf3")

            iperf = Iperf(**args)
            result = iperf.run()

            if result != Iperf.IPERF_OK:
                continue

            results = iperf.get_performance()

            # print statistics
            for res in results:
                log.info(res)

            # check results
            for res in results:
                res.check(criterion=args['criterion'])

            break
        else:
            assert ping.ping(4, self.LKP_IPV4_ADDR)
            raise Exception("Failed to run iperf 3 times")

        self.check_counters(is_need_to_check=True)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
