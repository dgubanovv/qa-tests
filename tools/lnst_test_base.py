import socket

from infra.test_base import TestBase
from tools.atltoolper import AtlTool
from tools.command import Command

from tools.driver import Driver
from tools.lnst_pool import update_lnst_pool
from tools.prof import prof
from tools.utils import get_atf_logger

log = get_atf_logger()


class TestLNSTBase(TestBase):

    @classmethod
    def setup_class(cls):
        super(TestLNSTBase, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.log_local_dir = cls.working_dir

            cls.dut_atltool_wrapper = AtlTool(port=cls.dut_port)

            with prof('install_firmwares'):
                cls.install_firmwares()

            with prof('dut.driver.install'):
                cls.dut_driver = Driver(port=cls.dut_port, version=cls.dut_drv_version)
                cls.dut_driver.install()

            with prof('lkp.driver.install'):
                cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
                cls.lkp_driver.install()

            cls.prev_speed = None
            cls.machines = [cls.lkp_hostname, cls.dut_hostname]
            for i in range(len(cls.machines)):
                if cls.machines[i] is None:
                    cls.machines[i] = socket.gethostname()
            log.debug('cls.machines: {}'.format(cls.machines))

            # update pool machines
            cls.machines_names = update_lnst_pool(cls.machines)
            log.debug('cls.machines_names: {}'.format(cls.machines_names))

        except Exception as e:
            log.exception("Failed while setting up class")

    def teardown_method(self, method):
        for machine in self.machines:
            cmd = Command(cmd='sudo systemctl stop lnst-slave.service', host=machine)
            cmd.run_join()

    def setup_method(self, method):
        for machine in self.machines:
            cmd = Command(cmd='sudo systemctl start lnst-slave.service', host=machine)
            cmd.run_join()

    def run_test(self, path):
        cmd = 'cd /home/aqtest/lnst && sudo -u aqtest ./lnst-ctl run {}'.format(path)
        cmd = Command(cmd=cmd, host='lnst-master.rdc-lab.marvell.com')
        return cmd.run_join(timeout=2*60*60)

