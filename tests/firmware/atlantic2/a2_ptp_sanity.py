import copy
import os
import pytest
import sys
import time
import timeit


sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))


from infra.test_base import idparametrize, TestBase
from tools.atltoolper import AtlTool
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G
from tools.driver import Driver, DRV_TYPE_DIAG
from tools.utils import get_atf_logger
from tools.mbuper import download_mbu, MbuWrapper


log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "a2_ptp_sanity"


class TestA2PTP(TestBase):
    """
    @description: The TestA2PTP test is dedicated to verify that FW doesn't impact pDelay variation.

    @setup: Aquantia device with RJ45 loopback.
    """
    PACKET_COUNT = 16
    DURATION = int(os.environ.get("DURATION", 60))
    PTP_FREQUENCY = 156250000
    PTM_FREQUENCY = 156250000
    NS_IN_SEC = 1000000000
    FRAC_NS_IN_NS = 0x1000000

    @classmethod
    def setup_class(cls):
        super(TestA2PTP, cls).setup_class()
        os.environ["AQ_DEVICEREV"] = "ANTA0"

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()

            cls.install_firmwares()

            # Set up DUT
            cls.dut_driver = Driver(port=cls.dut_port, version="latest", host=cls.dut_hostname,
                                    drv_type=DRV_TYPE_DIAG)
            cls.dut_driver.install()
            cls.atltool_wrapper = AtlTool(port=cls.dut_port)

            cls.mbu_dir = download_mbu(cls.mbu_version, cls.working_dir)
            cls.log_local_dir = os.path.join(cls.mbu_dir, "logs")

            log.info("Initializing MBU wrapper")
            cls.mbu_wrapper = MbuWrapper(mbu_dir=cls.mbu_dir, port=cls.dut_port)
            cls.mac_control = cls.mbu_wrapper.mac_control
            cls.ptp_avb_scripts_dir = os.path.join(cls.mbu_dir, "Scripts", "AvbPtpTsn")
            sys.path.append(os.path.join(cls.mbu_dir, 'Common'))
            sys.path.append(os.path.join(cls.mbu_dir, 'Os'))
            sys.path.append(cls.mbu_dir)
            sys.path.append(cls.ptp_avb_scripts_dir)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    @classmethod
    def teardown_class(cls):
        super(TestA2PTP, cls).teardown_class()

    def setup_method(self, method):
        super(TestA2PTP, self).setup_method(method)
        self.atltool_wrapper.kickstart2()

    def teardown_method(self, method):
        super(TestA2PTP, self).teardown_method(method)

    def calculate_per_clock_increment_conf(self, freq):
        nsi = self.NS_IN_SEC // freq
        nsi_frac = (self.NS_IN_SEC * self.FRAC_NS_IN_NS) // freq - nsi * self.FRAC_NS_IN_NS
        return (nsi << 24) + nsi_frac

    def read_tsg0_counter(self, mac_control):
        ptp_counter_lsb = mac_control.dllh.regTsgPtpReadCurrentNsecGet(0)
        ptp_counter_msb = mac_control.dllh.regTsgPtpReadCurrentNsecGet(1)
        return (ptp_counter_msb << 32) + ptp_counter_lsb

    def set_tsg0_counter(self, mac_control, ts):
        msb = ts >> 32
        lsb = ts - (msb << 32)
        mac_control.dllh.tsgModifyPtpNsecValue0OfTimerCountersSet(lsb)
        mac_control.dllh.tsgModifyPtpNsecValue1OfTimerCountersSet(msb)
        mac_control.dllh.tsgSetPtpTimerCountersSet(0x1)

    def read_tsg1_counter(self, mac_control):
        ptm_counter_lsb = mac_control.dllh.regTsgPtmReadCurrentNsecGet(0)
        ptm_counter_msb = mac_control.dllh.regTsgPtmReadCurrentNsecGet(1)
        return (ptm_counter_msb << 32) + ptm_counter_lsb

    def set_tsg1_counter(self, mac_control, ts):
        msb = ts >> 32
        lsb = ts - (msb << 32)
        mac_control.dllh.tsgModifyPtmNsecValue0OfTimerCountersSet(lsb)
        mac_control.dllh.tsgModifyPtmNsecValue1OfTimerCountersSet(msb)
        mac_control.dllh.tsgSetPtmTimerCountersSet(0x1)

    def check_ptp(self):
        caps_value = self.mac_control.macRegReadData(0x20)
        assert (caps_value & 0x00800000) == 0, "PTP is disabled by FW in 0x20 register. Most likely it's done " \
                                               "because it's 7x7 chip where PTP is disabled in eFuse"

    def _sync_callback(self, _, **kwargs):
        import send_ptp
        self.mac_control.macRegWriteData(0x8018, 0x0)

        egress_timestamps = kwargs.get("egress_timestamps", [])
        ingress_timestamps = kwargs.get("ingress_timestamps", [])
        counters = kwargs.get("counters", [])
        counter_name = kwargs.get("clock_source")

        # This test produces a lot of traces, reduce them
        args = copy.copy(kwargs)
        args["logtag"] = 'nul'
        from test_ptp_avb import script_settings
        script_settings["logtag"] = 'nul'

        time.sleep(2)
        start_time = timeit.default_timer()
        while (timeit.default_timer() - start_time) < self.DURATION:
            eg_ts, ing_ts = send_ptp.atlantic_run("", **args)
            egress_timestamps.extend(eg_ts)
            ingress_timestamps.extend(ing_ts)
            counter = self.read_tsg0_counter(self.mac_control) if counter_name == "tsg0" else self.read_tsg1_counter(
                self.mac_control
            )
            counters.append(counter)

    def check_pdelay_timestamps(self, **kwargs):
        self.set_tsg0_counter(self.mac_control, 0x0)
        self.set_tsg1_counter(self.mac_control, self.NS_IN_SEC * 3600)
        eg_ts = []
        ing_ts = []
        counters = []
        kwargs.update({
            "counters": counters,
            "egress_timestamps": eg_ts,
            "ingress_timestamps": ing_ts,
            "ptp_increment_config": self.calculate_per_clock_increment_conf(self.PTP_FREQUENCY),
            "ptm_increment_config": self.calculate_per_clock_increment_conf(self.PTM_FREQUENCY),
        })
        import test_ptp_avb
        test_ptp_avb.atlantic_run("", **kwargs)
        log.info("Egress timestamps: {}".format(eg_ts))
        log.info("Ingress timestamps: {}".format(ing_ts))
        counter_name = kwargs.get("clock_source")
        counter = counters[-1]
        log.info("{} counter value: {} s {} ns".format(
            counter_name, counter // self.NS_IN_SEC, counter % self.NS_IN_SEC
        ))
        pdelays = [ing - eg for ing, eg in zip(ing_ts, eg_ts)]
        log.info("pDelays: {}".format(pdelays))
        log.info("pDelays Max: {} Min: {} Avg: {} Var: {}".format(
            max(pdelays), min(pdelays), sum(pdelays)/len(pdelays), max(pdelays) - min(pdelays)
        ))

        assert len(eg_ts) == len(ing_ts), "Number of egress TS doesn't correspond to number of ingress TS>"
        assert all(item > 0 for item in ing_ts), "Expected that all the ingress timestamps are more than zero"
        assert all(ts - ing_ts[num - 1] > 0 for num, ts in enumerate(ing_ts[1:], start=1)), \
            "Ingress timestamps are not sequentially incremented"
        assert max(pdelays) - min(pdelays) < 50, "Round trip is more than 50 sometimes"
        assert counter - eg_ts[
            -1] < self.NS_IN_SEC * 40, "Last ingress TS doesn't correspond to {} counter value.".format(
            counter_name
        )

    def run_test(self, link_speed, source_clock, boost, pkt_size):
        hw_cfg = {
            "loopback": "Msm" if link_speed == "1G" else "RJ45",
            "link": link_speed,
            "no_mcp_link": False,
        }
        kwargs = {
            'hw_cfg': hw_cfg,
            'ptp_avb_sync_callback': self._sync_callback,
            "maccontrol": self.mac_control,
            "dllh": self.mac_control.dllh,
            "cllh": self.mac_control.cllh,
            "log": self.mac_control.log,
            'packet_count': self.PACKET_COUNT,
            'receive': True,
            'clock_source': source_clock,
            'boost': True,
            'enable_boost': 'all' if boost else 'None',
            'ptp_message_type': 'sync',
            "ring_flex_mapping": True,
            "new_filtering": True,
            "base_ring_index": [0, 4],
        }
        if pkt_size is not None:
            kwargs.update({"pkt_size": pkt_size})
        log.info("Parameters = {}".format(kwargs))
        self.check_ptp()
        self.check_pdelay_timestamps(**kwargs)

    @idparametrize("link_speed", (LINK_SPEED_100M, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G))
    @idparametrize("source_clock", ("tsg0", "tsg1"))
    @idparametrize("boost", (False, True))
    def test_ptp_pdelay(self, link_speed, source_clock, boost):
        """
        @description: Test sends PTP packets via RJ45 loopback, timestamps them on TX and RX and analyses difference
        between RX and TX timestamp. There should not be big variation. Usual variation values ~20ns.

        @steps:
        1. In loop for 10G/5G/2,5G/100M link speed, with tsg0 or tsg1 counter as source counter for timestamping,
        with or without background random-sized traffic:
            a. Set specified link speed on DUT.
            c. Setup TSG, TX and RX ptp rings.
            d. Send ptp packets (16 packets in iteration) for self.DURATION seconds.
            e. Catch TX and RX timestamps.

        @result: All checks are passed.
        @duration: Configurable (default 60 (Duration) + ~25 (for configuration) = 85s).
        """
        self.run_test(link_speed=link_speed, source_clock=source_clock, boost=boost, pkt_size=None)


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
