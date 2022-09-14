import datetime
import decimal
import os
import re
import tempfile
import time
import timeit
import sys
import socket

import pytest

from tools.driver import Driver
from tools.utils import get_atf_logger
from tools import command
from tools import constants
from tools import motuper
from tools import power
from tools import virtual_audio
from tools import macos_ptp_avb_base


log = get_atf_logger()

MOTU_IP = "192.168.0.10"
MOTU_NETMASK = "255.255.255.0"

MAC_ROLE_SLAVE = "Slave"
MAC_ROLE_MASTER = "Master"

LOCK_TIME_MEASUREMENTS = 20
LOCK_TIMEOUT = 1800
AVB_LOCK_TIME_LIMIT = 120
PTP_LOCK_TIME_LIMIT = 40
MAC_DEVICE_TIMEOUT = 180
MOTU_APPLY_CHANGES_TIME = 30
STABILITY_TIME = 1200
AVB_LOCK_POLL_INTERVAL = 5


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["WORKING_DIR"] = tempfile.gettempdir()
    os.environ["TEST"] = "ptp_avb_motu"


class TestPtpAvbMotu(macos_ptp_avb_base.TestMacPtpAvbBase):
    SKIP_INSTALL = bool(os.environ.get("SKIP_INSTALL", False))
    @classmethod
    def setup_class(cls):
        super(TestPtpAvbMotu, cls).setup_class()
        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            if not cls.state.skip_class_setup:
                if not cls.SKIP_INSTALL:
                    cls.install_firmwares()
                    cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
                    cls.dut_driver.install()
                    cls.state.skip_class_setup = True
                    cls.state.update()
                    dut_power = power.Power()
                    dut_power.reboot()
                    time.sleep(30)
            new_ip = MOTU_IP.split(".")[:3]
            new_ip.append("1")
            cls.DUT_IPV4_ADDR = ".".join(new_ip)
            cls.dut_virtual_audio = virtual_audio.VirtualAudio(port=cls.dut_port)
            cls.dut_motuper = motuper.Motuper(motu_hostname=MOTU_IP)
        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def teardown_method(self, method):
        super(TestPtpAvbMotu, self).teardown_method(method)
        self.dut_ifconfig.set_link_state(constants.LINK_STATE_DOWN)

    def setup_method(self, method):
        super(TestPtpAvbMotu, self).setup_method(method)
        self.dut_ifconfig.set_link_state(constants.LINK_STATE_DOWN)

    def start_lock_log(self, log_file, interval=0.1):
        script = 'while true; do date "+%H:%M:%S   %d/%m/%Y"; /dos/qa/macos/timesyncutil --validate | grep -A100' \
                 ' +IOTimeSyncEthernetPort | grep "Port Role"; sleep {}; done > {}'.format(interval, log_file)
        cmd = "sudo -- sh -c '{}'".format(script)
        lock_cmd = command.Command(cmd=cmd)
        lock_cmd.run_async()
        self.to_kill.append(lock_cmd)
        return lock_cmd

    def get_ptp_lock_time(self, log_file):
        timestamps = self.get_timestamps_from_log_file(log_file)

        with open(log_file, "r") as fileo:
            roles = self.get_roles_from_log(fileo)
        log.debug("Roles: {}".format(roles))
        log.debug("Timestamps: {}".format(timestamps))
        role = "Slave" if "Slave" in roles else "Master"
        start = timestamps[0]
        end = timestamps[roles.index(role)]
        ptp_lock_time = (end - start).seconds
        return ptp_lock_time


    def lock_time_link_up(self, link_speed, stream_num):
        mac_role = MAC_ROLE_MASTER
        avb_lock_times = []
        ptp_lock_times = []
        self.dut_ifconfig.set_link_speed(link_speed)
        self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, MOTU_NETMASK, None)
        self.dut_ifconfig.set_link_state(constants.LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        self.dut_motuper.set_input_streams_number(stream_num)
        self.dut_motuper.set_output_streams_number(stream_num)

        # Wait a bit to let the MOTU to apply the changes
        time.sleep(MOTU_APPLY_CHANGES_TIME)

        start = timeit.default_timer()
        motu_device_id, mac_device_id = self.dut_motuper.get_entity_ids()
        while mac_device_id is None:
            motu_device_id, mac_device_id = self.dut_motuper.get_entity_ids()
            if (timeit.default_timer() - start) > MAC_DEVICE_TIMEOUT:
                raise Exception("Audio device on MAC was not detected by MOTU")

        motu_device_name = self.dut_motuper.get_value("avb/{}/entity_name".format(motu_device_id))["value"]
        if mac_role == MAC_ROLE_MASTER:
            mac_clock_source = "Mac System Clock"
            motu_clock_source = "AVB Input Stream 1"
        else:
            mac_clock_source = "{}:Internal:Output Stream 1".format(motu_device_name)
            motu_clock_source = "Internal"

        time.sleep(MOTU_APPLY_CHANGES_TIME)
        output_devices = self.dut_virtual_audio.get_output_devices()
        if all("{}:{}".format(motu_device_name, motu_device_name) not in item for item in output_devices):
            time.sleep(MOTU_APPLY_CHANGES_TIME)
            output_devices = self.dut_virtual_audio.get_output_devices()
            if all("{}:{}".format(motu_device_name, motu_device_name) not in item for item in output_devices):
                raise Exception("Audio device was not created on MAC")
        self.dut_motuper.set_clock_source(motu_clock_source)
        self.dut_virtual_audio.set_clock_source("{}:{}".format(motu_device_name, motu_device_name), mac_clock_source)
        start = timeit.default_timer()
        lock_state = motuper.LOCK_STATE_UNLOCKED
        while lock_state != motuper.LOCK_STATE_LOCKED:
            lock_state = self.dut_motuper.get_lock_state()
            log.debug('Current lock state: {}'.format(lock_state))
            assert (timeit.default_timer() - start) < LOCK_TIMEOUT, \
                "AVB state was not locked after timeout {} seconds".format(LOCK_TIMEOUT)
            time.sleep(0.5)
        lock_time = (timeit.default_timer() - start)
        log.info("Lock time: {}s".format(lock_time))
        assert lock_time
        self.dut_ifconfig.set_link_state(constants.LINK_STATE_DOWN)
        for num in xrange(LOCK_TIME_MEASUREMENTS):
            dut_lock_log_file = os.path.join(self.test_log_dir, "dut_lock_log_{}.txt".format(num))
            self.dut_ifconfig.set_link_state(constants.LINK_STATE_UP)
            self.dut_ifconfig.wait_link_up(retry_interval=0.1)
            start = timeit.default_timer()
            lock_cmd = self.start_lock_log(dut_lock_log_file, 0.1)
            lock_state = motuper.LOCK_STATE_UNLOCKED
            while lock_state != motuper.LOCK_STATE_LOCKED:
                lock_state = self.dut_motuper.get_lock_state()
                log.debug('Current lock state: {}'.format(lock_state))
                assert (timeit.default_timer() - start) < LOCK_TIMEOUT, \
                    "AVB state was not locked after timeout {} seconds".format(LOCK_TIMEOUT)
                time.sleep(0.5)
            lock_cmd.join(0)
            avb_lock_time = (timeit.default_timer() - start)
            avb_lock_times.append(int(avb_lock_time))
            ptp_lock_time = self.get_ptp_lock_time(dut_lock_log_file)
            ptp_lock_times.append(ptp_lock_time)

            log.info("PTP lock time: {}s".format(ptp_lock_time))
            log.info("AVB lock time: {}s".format(avb_lock_time))
            self.dut_ifconfig.set_link_state(constants.LINK_STATE_DOWN)

        log.info("PTP lock times: {}".format(ptp_lock_times))
        log.info("AVB lock times: {}".format(avb_lock_times))
        assert all(lock_time < PTP_LOCK_TIME_LIMIT for lock_time in ptp_lock_times), \
            "PTP lock time is longer than {}".format(PTP_LOCK_TIME_LIMIT)
        assert all(lock_time < AVB_LOCK_TIME_LIMIT for lock_time in avb_lock_times), \
            "Some of lock times are much than {}".format(AVB_LOCK_TIME_LIMIT)

    @pytest.mark.xfail
    def test_lock_time_link_up_100m_1_str(self):
        self.lock_time_link_up(constants.LINK_SPEED_100M, 1)

    def test_lock_time_link_up_1g_8_str(self):
        self.lock_time_link_up(constants.LINK_SPEED_1G, 8)

    def test_lock_time_link_up_1g_12_str(self):
        self.lock_time_link_up(constants.LINK_SPEED_1G, 12)

    # def test_lock_time_link_up_1g_13_str(self):
    #     self.lock_time_link_up(constants.LINK_SPEED_1G, 13)

    @pytest.mark.xfail
    def test_lock_time_link_up_1g_14_str(self):
        self.lock_time_link_up(constants.LINK_SPEED_1G, 14)
    #
    # def test_lock_time_link_up_1g_15_str(self):
    #     self.lock_time_link_up(constants.LINK_SPEED_1G, 15)

    @pytest.mark.xfail
    def test_lock_time_link_up_1g_16_str(self):
        self.lock_time_link_up(constants.LINK_SPEED_1G, 16)

    def check_stability(self, link_speed, stream_num):
        mac_role = MAC_ROLE_MASTER
        dut_delays_log_file = os.path.join(self.test_log_dir, "dut_delays_log.txt")
        dut_roles_log_file = os.path.join(self.test_log_dir, "dut_roles_log.txt")

        self.dut_ifconfig.set_link_speed(link_speed)
        self.dut_ifconfig.set_ip_address(self.DUT_IPV4_ADDR, MOTU_NETMASK, None)
        self.dut_ifconfig.set_link_state(constants.LINK_STATE_UP)
        self.dut_ifconfig.wait_link_up()
        self.dut_motuper.set_input_streams_number(stream_num)
        self.dut_motuper.set_output_streams_number(stream_num)

        # Wait a bit to let the MOTU to apply the changes
        time.sleep(MOTU_APPLY_CHANGES_TIME)

        start = timeit.default_timer()
        motu_device_id, mac_device_id = self.dut_motuper.get_entity_ids()
        while mac_device_id is None:
            motu_device_id, mac_device_id = self.dut_motuper.get_entity_ids()
            if (timeit.default_timer() - start) > MAC_DEVICE_TIMEOUT:
                raise Exception("Audio device on MAC was not detected by MOTU")

        motu_device_name = self.dut_motuper.get_value("avb/{}/entity_name".format(motu_device_id))["value"]
        if mac_role == MAC_ROLE_MASTER:
            mac_clock_source = "Mac System Clock"
            motu_clock_source = "AVB Input Stream 1"
        else:
            mac_clock_source = "{}:Internal:Output Stream 1".format(motu_device_name)
            motu_clock_source = "Internal"

        self.dut_motuper.set_clock_source(motu_clock_source)
        time.sleep(MOTU_APPLY_CHANGES_TIME)
        output_devices = self.dut_virtual_audio.get_output_devices()
        if all("{}:{}".format(motu_device_name, motu_device_name) not in item for item in output_devices):
            time.sleep(MOTU_APPLY_CHANGES_TIME)
            output_devices = self.dut_virtual_audio.get_output_devices()
            if all("{}:{}".format(motu_device_name, motu_device_name) not in item for item in output_devices):
                raise Exception("Audio device was not created on MAC")

        self.dut_virtual_audio.set_clock_source("{}:{}".format(motu_device_name, motu_device_name), mac_clock_source)
        time.sleep(MOTU_APPLY_CHANGES_TIME)
        lock_state = motuper.LOCK_STATE_UNLOCKED
        while lock_state != motuper.LOCK_STATE_LOCKED:
            lock_state = self.dut_motuper.get_lock_state()
            log.debug('Current lock state: {}'.format(lock_state))
            assert (timeit.default_timer() - start) < LOCK_TIMEOUT, \
                "AVB state was not locked after timeout {} seconds".format(LOCK_TIMEOUT)

        macos_ptp_avb_base.TestMacPtpAvbBase.start_time = datetime.datetime.now()

        log.debug("Start time = {}".format(macos_ptp_avb_base.TestMacPtpAvbBase.start_time))
        dut_roles_cmd = self.start_roles_log(self.dut_hostname, dut_roles_log_file, 1)
        dut_delays_cmd = self.start_delay_log(self.dut_hostname, dut_delays_log_file, 1)
        start = timeit.default_timer()
        lock_states = []
        log.info("Polling lock state during {}s".format(self.PRE_CHECK_TIME))
        while timeit.default_timer() - start < self.PRE_CHECK_TIME:
            lock_states.append(self.dut_motuper.get_lock_state())
            time.sleep(AVB_LOCK_POLL_INTERVAL)
        self.pre_check_roles(dut_roles_log_file)
        log.info("Polling lock state during {}s".format(self.STREAM_TIME - self.PRE_CHECK_TIME))
        while timeit.default_timer() - start < self.STREAM_TIME:
            lock_states.append(self.dut_motuper.get_lock_state())
            time.sleep(AVB_LOCK_POLL_INTERVAL)
        dut_delays_cmd.join(0)
        dut_roles_cmd.join(0)
        log.info("Lock states: {}".format(lock_states))
        was_not_unlocked = False
        rolles_not_changed = False
        round_trips_ok = False
        try:
            assert all(item == motuper.LOCK_STATE_LOCKED for item in lock_states), "AVB state was unlocked"
            was_not_unlocked = True
        except AssertionError as e:
            log.exception(e)
        try:
            self.check_roles(dut_roles_log_file, None, None, None)
            rolles_not_changed = True
        except AssertionError as e:
            log.exception(e)
        try:
            self.check_delays(None, None, dut_delays_log_file, None)
            round_trips_ok = True
        except AssertionError as e:
            log.exception(e)
        assert was_not_unlocked, "MOTU was unlocked"
        assert rolles_not_changed, "DUT role was changed"
        assert round_trips_ok, "Round trip delay is big sometimes"

    def test_stability_100m_1_str(self):
        self.check_stability(constants.LINK_SPEED_100M, 1)

    def test_stability_1g_8_str(self):
        self.check_stability(constants.LINK_SPEED_1G, 8)

    # def test_stability_1g_9_str(self):
    #     self.check_stability(constants.LINK_SPEED_1G, 9)
    #
    # def test_stability_1g_10_str(self):
    #     self.check_stability(constants.LINK_SPEED_1G, 10)
    #
    # def test_stability_1g_11_str(self):
    #     self.check_stability(constants.LINK_SPEED_1G, 11)

    def test_stability_1g_12_str(self):
        self.check_stability(constants.LINK_SPEED_1G, 12)

    # def test_stability_1g_13_str(self):
    #     self.check_stability(constants.LINK_SPEED_1G, 13)

    @pytest.mark.xfail
    def test_stability_1g_14_str(self):
        self.check_stability(constants.LINK_SPEED_1G, 14)

    # def test_stability_1g_15_str(self):
    #     self.check_stability(constants.LINK_SPEED_1G, 15)

    @pytest.mark.xfail
    def test_stability_1g_16_str(self):
        self.check_stability(constants.LINK_SPEED_1G, 16)


if __name__ == "__main__":
    exec_list = [__file__, "-s", "-v"]
    if len(sys.argv) > 1:
        exec_list.append("-k {}".format(sys.argv[1]))
    pytest.main(exec_list)
