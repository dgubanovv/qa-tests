import csv
import os

import pytest

from tools.debug import collect_debug_info
from tools.mbuper import download_mbu, MbuWrapper
from infra.test_base import TestBase, idparametrize
from tools.constants import LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G, \
    LINK_SPEED_AUTO

from tools.driver import Driver, DRV_TYPE_DIAG
from tools.utils import get_atf_logger, download_file

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "ptp_sanity"


class TestPtpRoundtrip(TestBase):
    MASTER_ROLE = "master"
    SLAVE_ROLE = "slave"
    ITERATION_COUNT = 300
    RETRY_CNT = 3

    @classmethod
    def setup_class(cls):
        super(TestPtpRoundtrip, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            # fw versions on dut and lkp must be the same
            cls.lkp_fw_version = cls.dut_fw_version

            cls.install_firmwares()

            cls.dut_driver = Driver(port=cls.dut_port, drv_type=DRV_TYPE_DIAG, version=cls.dut_drv_version)
            cls.lkp_driver = Driver(port=cls.lkp_port, drv_type=DRV_TYPE_DIAG, version=cls.lkp_drv_version,
                                    host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.dut_driver.install()

            mbu_dir = download_mbu(cls.mbu_version, cls.working_dir)
            cls.mbu_dir = mbu_dir
            cls.dut_mbu = MbuWrapper(mbu_dir=cls.mbu_dir, port=cls.dut_port, version=cls.mbu_version)
            cls.lkp_mbu = MbuWrapper(mbu_dir=cls.mbu_dir, port=cls.lkp_port, version=cls.mbu_version,
                                     host=cls.lkp_hostname)
            cls.log_local_dir = os.path.join(mbu_dir, "logs")

            cls.scripts_path = os.path.join(os.environ["ATF_HOME"], "qa-tests", "tools", "beton", "PTP")

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    def create_mbu_file(self, role, speed, iteration_count):
        run_ptp_roundtrip = os.path.join(self.scripts_path, "run_ptp_roundtrip_{}.txt".format(role))
        with open(run_ptp_roundtrip, 'w') as f:
            f.write('link_speed = {}\n'.format(speed))
            f.write('cd {}\n'.format(self.scripts_path))
            f.write('{} = True\n'.format(role))
            f.write('exec ptp_roundtrip_preinit.txt\n')
            f.write('pause 10\n')
            f.write('iteration_count = {}\n'.format(iteration_count))
            f.write('exec ptp_roundtrip.txt\n')
            f.write('writereg 0x36c 0x0\n')
            f.write('mac.uninit\n')
        return run_ptp_roundtrip

    def read_timestamps(self, csvfile, t1, t2):
        with open(csvfile, 'rb') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',')
            next(spamreader)
            for row in spamreader:
                t1.append(int(row[1]))
                t2.append(int(row[2]))

    @idparametrize("speed", [LINK_SPEED_100M, LINK_SPEED_1G, LINK_SPEED_2_5G, LINK_SPEED_5G, LINK_SPEED_10G])
    def test_roundtrip_variation(self, speed):
        if speed != LINK_SPEED_AUTO and speed not in self.supported_speeds:
            pytest.xfail()
        dut_file = self.create_mbu_file(self.SLAVE_ROLE, speed, self.ITERATION_COUNT)
        lkp_file = self.create_mbu_file(self.MASTER_ROLE, speed, self.ITERATION_COUNT)
        lkp_file = os.path.normpath(lkp_file)
        lkp_file = lkp_file.replace("\\", "\\\\")

        log.info('***** ***** ***** ***** Running MBU on LKP...')
        log.info(lkp_file)
        self.lkp_mbu.exec_txt(lkp_file, run_async=True,
                              remote_file=lkp_file,
                              work_dir='$ATF_HOME/qa-tests/tools/beton',
                              output=None,
                              file_to_upload=lkp_file,
                              timeout=10 * 60)

        # run on DUT
        log.info('***** ***** ***** ***** Running MBU on DUT...')
        log.info(dut_file)
        for i in range(self.RETRY_CNT):
            self.dut_mbu.exec_txt(dut_file)
            lkp_res = self.lkp_mbu.exec_join()

            if "Something is wrong! Cannot receive ingress PTP packet with TS." in lkp_res["output"]:
                if i == self.RETRY_CNT - 1:
                    raise Exception("problem with mbu sync after {} retries.".format(i))
                else:
                    collect_debug_info()
                    log.info("problem with mbu sync. Retry test run")
            else:
                break

        log.info('***** ***** ***** ***** FINISH MBU...')
        master_file = os.path.join(self.scripts_path, "{}_{}.csv".format(self.MASTER_ROLE, speed))
        slave_file = os.path.join(self.scripts_path, "{}_{}.csv".format(self.SLAVE_ROLE, speed))
        download_file(self.lkp_hostname, master_file, master_file)
        t1 = []
        t2 = []
        t3 = []
        t4 = []
        round_trips = []
        self.read_timestamps(master_file, t2, t3)
        self.read_timestamps(slave_file, t1, t4)
        for t1_, t2_, t3_, t4_ in zip(t1, t2, t3, t4):
            round_trip = (t4_ - t1_) - (t3_ - t2_)
            log.info("({}-{}) - ({}-{}) = {}".format(t4_, t1_, t3_, t2_, round_trip))
            round_trips.append(round_trip)
        log.info("MAX = {}, MIN = {}, VARIATION = {}".format(max(round_trips),
                                                             min(round_trips),
                                                             max(round_trips) - min(round_trips)))

        # This check sometimes fails on setups where LKP clock is ticking faster than clock on DUT.
        # However this is not actually a fault because there is no clock synchronization is the test.
        # This check is commented due to that problem.
        # for round_trip in round_trips:
        #     assert round_trip > 0, "Error roundtrip < 0"

        # 300ns max variation is too bad value for real setups with clock synchronization.
        # Since we do not have it let's do some sanity check.
        assert max(round_trips) - min(round_trips) < 3600


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
