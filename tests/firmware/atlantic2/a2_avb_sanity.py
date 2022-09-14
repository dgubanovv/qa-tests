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
    os.environ["TEST"] = "a2_avb_sanity"


class TestA2AVB(TestBase):
    """
    @description: The TestA2AVB test is dedicated to verify that FW doesn't impact scheduled DMA.

    @setup: Aquantia device with RJ45 loopback.
    """
    PACKET_COUNT = 16
    DURATION = int(os.environ.get("DURATION", 30))
    PTP_FREQUENCY = 156250000
    PTM_FREQUENCY = 156250000
    NS_IN_SEC = 1000000000
    FRAC_NS_IN_NS = 0x1000000
    LAUNCH_TIME_INCREMENT = 125000
    LAUNCH_TIME_VAR_LIMIT_TX = 1000  # nanoseconds
    LAUNCH_TIME_VAR_LIMIT_RX = 2000  # nanoseconds
    LT_ADJUSTMENT = {
        LINK_SPEED_100M: 9,
        LINK_SPEED_1G: 5,
        LINK_SPEED_2_5G: 4,
        LINK_SPEED_5G: 4,
        LINK_SPEED_10G: 4,
    }

    @classmethod
    def setup_class(cls):
        super(TestA2AVB, cls).setup_class()
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
        super(TestA2AVB, cls).teardown_class()

    def setup_method(self, method):
        super(TestA2AVB, self).setup_method(method)
        self.atltool_wrapper.kickstart2()

    def teardown_method(self, method):
        super(TestA2AVB, self).teardown_method(method)

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

    def _sync_callback(self, mc, **kwargs):
        import send_avb

        link_speed = kwargs["hw_cfg"]["link"]
        self.mac_control.macRegWriteData(0x8018, 0x0)

        launch_times = kwargs.get("launch_times", [])
        egress_timestamps = kwargs.get("egress_timestamps", [])
        ingress_timestamps = kwargs.get("ingress_timestamps", [])
        counters = kwargs.get("counters", [])
        counter_name = kwargs.get("clock_source")
        args = copy.copy(kwargs)
        args.update({"logtag": "nul"})

        self.mac_control.dllh.tpbTxBufferLaunchTimeAdjustmentSet(self.LT_ADJUSTMENT[link_speed])

        if link_speed == LINK_SPEED_100M:
            self.mac_control.dllh.tpbTxBufferAvbBackgroundTrafficAdjustmentSet(0x60)
        start_time = timeit.default_timer()
        while (timeit.default_timer() - start_time) < self.DURATION:
            launch, eg_ts, ing_ts = send_avb.atlantic_run("", **args)
            launch_times.extend(launch)
            egress_timestamps.extend(eg_ts)
            ingress_timestamps.extend(ing_ts)
            counter = self.read_tsg0_counter(self.mac_control) if counter_name == "tsg0" else self.read_tsg1_counter(
                self.mac_control
            )
            counters.append(counter)

    def check_launch_time(self, **kwargs):
        import test_ptp_avb
        self.set_tsg0_counter(self.mac_control, 0x0)
        self.set_tsg1_counter(self.mac_control, self.NS_IN_SEC * 3600)
        launch_t = []
        eg_ts = []
        ing_ts = []
        counters = []
        kwargs.update({
            "counters": counters,
            "launch_times": launch_t,
            "egress_timestamps": eg_ts,
            "ingress_timestamps": ing_ts,
            "ptp_increment_config": self.calculate_per_clock_increment_conf(self.PTP_FREQUENCY),
            "ptm_increment_config": self.calculate_per_clock_increment_conf(self.PTM_FREQUENCY),
        })
        test_ptp_avb.atlantic_run("", **kwargs)
        log.info("Launch times: {}".format(launch_t))
        log.info("Egress timestamps: {}".format(eg_ts))
        log.info("Ingress timestamps: {}".format(ing_ts))
        counter_name = kwargs["clock_source"]
        counter = counters[-1]
        log.info("{} counter value: {} s {} ns".format(
            counter_name, counter // self.NS_IN_SEC, counter % self.NS_IN_SEC
        ))
        launch_time_diffs = [eg - la for eg, la in zip(eg_ts, launch_t)]
        max_error = max(launch_time_diffs)
        min_error = min(launch_time_diffs)
        avg_error = sum(launch_time_diffs) // len(launch_time_diffs)
        launch_time_variation = max_error - min_error

        log.info("Launch time diffs on TX: {}".format(launch_time_diffs))
        log.info("Launch time errors: Max: {}; Min: {}; Avg: {}; Variation: {}".format(
            max_error, min_error, avg_error, launch_time_variation,
        ))
        launch_time_diffs_rx = []
        for iteration in xrange(len(ing_ts) // self.PACKET_COUNT):
            temp = ing_ts[iteration * self.PACKET_COUNT: (iteration + 1) * self.PACKET_COUNT]
            launch_time_diffs_rx.extend([lt - temp[num - 1] for num, lt in enumerate(temp[1:], start=1)])

        max_lt_diff = max(launch_time_diffs_rx)
        min_lt_diff = min(launch_time_diffs_rx)
        avg_lt_diff = sum(launch_time_diffs_rx) / len(launch_time_diffs_rx)
        var_lt_diff = max_lt_diff - min_lt_diff
        log.info("Launch time diffs on RX: {}".format(launch_time_diffs_rx))
        log.info("Launch time diffs on RX: Max: {}; Min: {}; Avg: {}; Variation: {}".format(
            max_lt_diff, min_lt_diff, avg_lt_diff, var_lt_diff
        ))

        assert all(eg - eg_ts[num - 1] for num, eg in enumerate(eg_ts[1:], start=1)), \
            "Egress timestamps are not sequentially incremented"
        assert all(ing - ing_ts[num - 1] for num, ing in enumerate(ing_ts[1:], start=1)), \
            "Ingress timestamps are not sequentially incremented"
        link_speed = kwargs["hw_cfg"]["link"]
        # It's expected that for 100M bigger Prefetch delay must be used. (ANTIGUAA0-525)
        # At the same time it's expected for the first packet in the bunch ~2us TX delay error. (ANTIGUAA0-516)
        tx_limit = self.LAUNCH_TIME_VAR_LIMIT_TX * 3 if link_speed == LINK_SPEED_100M else self.LAUNCH_TIME_VAR_LIMIT_TX
        rx_limit = self.LAUNCH_TIME_VAR_LIMIT_RX * 3 if link_speed == LINK_SPEED_100M else self.LAUNCH_TIME_VAR_LIMIT_RX
        assert launch_time_variation < tx_limit, \
            "Launch time variation on TX {} exceeds the limit {}".format(
                launch_time_variation, tx_limit
            )
        assert var_lt_diff < rx_limit, \
            "Launch time variation on RX {} exceeds the limit {}".format(
                var_lt_diff, rx_limit
            )
        assert counter - eg_ts[-1] < self.NS_IN_SEC * 120, \
            "Last egress TS doesn't correspond to {} counter value.".format(counter_name)
        assert counter - ing_ts[-1] < self.NS_IN_SEC * 120, \
            "Last ingress TS doesn't correspond to {} counter value.".format(counter_name)

    def run_test(self, link_speed, source_clock, boost, pkt_size, avb_pkt_size):
        hw_cfg = {
            "loopback": "Msm" if link_speed == LINK_SPEED_1G else "RJ45",
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
            'launch_time_increment': self.LAUNCH_TIME_INCREMENT,
            'prefetch_delay': 250000 if link_speed == LINK_SPEED_100M else 125000,
            'avb_pkt_size': avb_pkt_size,
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
        self.check_launch_time(**kwargs)

    @idparametrize("link_speed", (LINK_SPEED_100M, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G))
    @idparametrize("source_clock", ("tsg0", "tsg1"))
    @idparametrize("boost", (False, True))
    @idparametrize("avb_pkt_size", (90, 282, 1024, 1480))
    def test_avb_launch_time(self, link_speed, source_clock, boost, avb_pkt_size):
        """
        @description: Test sends AVB packets via RJ45 loopback, timestamps them on TX and RX and analyses difference
        between RX and TX timestamp and Launch Time. There should not be big TX delay reported and interval between
        RX timestamps must correspond to launch time increment.

        @steps:
        1. In loop for 10G/5G/2,5G/100M link speed, with tsg0 or tsg1 counter as source counter for timestamping,
        with or without background random-sized traffic, in loop for 90, 282, 1024, 1480 AVB packet sizes:
            a. Set specified link speed on DUT.
            c. Setup TSG, TX and RX ptp rings.
            d. Send AVB packets (16 packets in iteration) for self.DURATION seconds.
            e. Catch TX and RX timestamps and compare with launch times.

        @result: All checks are passed.
        @duration: Configurable (default 30 (Duration) + ~25 (for configuration) = 55s).
        """
        self.run_test(
            link_speed=link_speed,
            source_clock=source_clock,
            boost=boost, pkt_size=None,
            avb_pkt_size=avb_pkt_size
        )


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
