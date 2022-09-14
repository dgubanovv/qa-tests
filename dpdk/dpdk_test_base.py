import os
import re
import shutil
import socket

from pytestpmd import ModuleTestPMD
from pytestpmd_patch import generate_pytestpmd

if __package__ is None:
    import sys
    from os import path

    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from tools.driver import Driver
from infra.test_base import TestBase
from tools.atltoolper import AtlTool
from tools.command import Command
from trafficgen.traffic_gen import TrafficGen
from tools.utils import get_atf_logger
from tools.constants import LINK_SPEED_AUTO, MTU_16000
from tools.scapy_tools import ScapyTools
from tools.ifconfig import Ifconfig
from tools import firmware

log = get_atf_logger()

PATH_TO_CONFIG_TXT = '/tmp/config.txt'


def run_commands(cmds, host=None, timeout=180, skip_fail=False):
    log.info('run commands: {}'.format('\n'.join(cmds)))
    for cmd in cmds:
        if cmd != '':
            command = Command(cmd=cmd, host=host)
            result = command.run_join(timeout)
            if skip_fail == False:
                assert result['returncode'] == 0, 'Fail to execute: {}'.format(cmd)


def init_dpdk(machine):
    # install dependency
    commands = [
        'sudo apt install -y software-properties-common',
        'sudo add-apt-repository ppa:jonathonf/meson',
        'sudo apt update',
        'sudo apt install -y meson ninja-build',
        'sudo apt install -y libnuma-dev libvirt-dev pkg-config libbsd-dev lsof libelf-dev',
    ]
    run_commands(commands, host=machine, skip_fail=True)

    # install source code
    dpdk_version = os.environ.get("DPDK_VER", 'v18.08')
    dpdk_drv = os.environ.get("DPDK_DRV", None)

    commands = [
        'sudo rm -rf /home/aqtest/dpdk',
        'sudo rm -rf /home/aqtest/dpdk_make',
        'sudo rm -rf /home/aqtest/dpdk_ninja',
        'sudo rm -rf /home/aqtest/dpdk-atlantic',
        'cd /home/aqtest/ && git clone git@gitlab.rdc-lab.marvell.com:qa/dpdk.git',
        'cd /home/aqtest/dpdk && git checkout {}'.format(dpdk_version)
    ]
    run_commands(commands, host=machine, skip_fail=True)  # FIX ME: delete skip_fail

    # apply patch for pytestpmd
    generate_pytestpmd('/home/aqtest/dpdk/app/test-pmd/testpmd.c')

    commands = [
        'cd /home/aqtest/ && git clone git@gitlab.rdc-lab.marvell.com:drv/DPDK.git dpdk-atlantic',
        '' if dpdk_drv is None else 'cd /home/aqtest/dpdk-atlantic && git checkout {}'.format(dpdk_drv),
        'cd /home/aqtest/ && cp -r dpdk-atlantic/* dpdk/',

        'cd /home/aqtest/ && cp -r dpdk dpdk_make',
        'cd /home/aqtest/ && cp -r dpdk dpdk_ninja',

        'cd /home/aqtest/dpdk_make && make defconfig',
        'cd /home/aqtest/dpdk_make && make -j 32 && make',
        'cd /home/aqtest/dpdk_make && export RTE_TARGET=build && export RTE_SDK=`pwd` && make -j8 -C examples',

        'cd /home/aqtest/dpdk_ninja && echo "build = true" > examples/ethtool/meson.build',
        'cd /home/aqtest/dpdk_ninja && echo "build = false" > examples/testpmd-scripts/meson.build',
        'cd /home/aqtest/dpdk_ninja && meson . build_meson -Dtests=true -Dexamples=all',
        'cd /home/aqtest/dpdk_ninja/build_meson && ninja -k 10',

        'echo 4 | sudo tee /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages',
        'echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages',
        'sudo umount /mnt/huge1g',
        'sudo umount /mnt/huge2m',
        'sudo mkdir /mnt/huge1g',
        'sudo mkdir /mnt/huge2m',
        'sudo mount -t hugetlbfs none /mnt/huge1g -o pagesize=1G',
        'sudo mount -t hugetlbfs none /mnt/huge2m -o pagesize=2M'
    ]
    run_commands(commands, host=machine, skip_fail=True)  # FIX ME: delete skip_fail

# def filter_match(pattern, text):
#     result = []
#     p = re.compile(pattern)
#     for line in text:
#         m = p.match(line)
#         if m is not None:
#             result.append(line)
#     return result


def filter_match_get(text, pattern):
    values = []
    for line in text:
        m = re.match(pattern, line)
        if not m is None:
            lst = list(m.groups())
            for v in lst:
                values.append(v)
    return values


class TestDPDKBase(TestBase):
    LKP_IP = '192.168.1.13'
    LKP_IP_1 = '192.168.1.12'
    PREFIX_IP6 = "64"
    PACKET_SIZE = [42, 53, 64, 96, 128, 160, 192, 224, 256, 320, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1408, 1500]

    @classmethod
    def setup_class(cls):
        super(TestDPDKBase, cls).setup_class()

        try:
            cls.log_server_dir = cls.create_logs_dir_on_log_server()
            cls.log_local_dir = cls.working_dir

            cls.dut_port1 = os.environ.get("DUT_PORT1", None)
            cls.lkp_port1 = os.environ.get("LKP_PORT1", None)

            cls.install_firmwares()

            cls.dut_firmware1 = firmware.Firmware(port=cls.dut_port1, card=cls.dut_fw_card, speed=cls.dut_fw_speed,
                                                  version=cls.dut_fw_version, mdi=cls.dut_fw_mdi, mii=cls.dut_fw_mii,
                                                  pause=cls.dut_fw_pause, pcirom=cls.dut_fw_pcirom,
                                                  dirtywake=cls.dut_fw_dirtywake, host=cls.dut_hostname,
                                                  bdp=cls.dut_bdp,
                                                  sign=cls.dut_sign, se_enable=cls.dut_se)
            postinstall_action = cls.dut_firmware1.install()
            if postinstall_action == firmware.Firmware.POSTINSTALL_RESTART:
                cls.restart(cls.dut_hostname)

            cls.lkp_firmware1 = firmware.Firmware(port=cls.lkp_port1, card=cls.lkp_fw_card, speed=cls.lkp_fw_speed,
                                                  version=cls.lkp_fw_version, mdi=cls.lkp_fw_mdi, mii=cls.lkp_fw_mii,
                                                  pause=cls.lkp_fw_pause, pcirom=cls.lkp_fw_pcirom,
                                                  dirtywake=cls.lkp_fw_dirtywake, host=cls.lkp_hostname,
                                                  bdp=cls.lkp_bdp,
                                                  sign=cls.lkp_sign, se_enable=cls.lkp_se)
            postinstall_action = cls.lkp_firmware1.install()
            if postinstall_action == firmware.Firmware.POSTINSTALL_RESTART:
                cls.restart(cls.lkp_hostname)

            cls.lkp_driver = Driver(port=cls.lkp_port, version=cls.lkp_drv_version, host=cls.lkp_hostname)
            cls.lkp_ifconfig1 = Ifconfig(port=cls.lkp_port1, host=cls.lkp_hostname)
            cls.lkp_driver.install()
            cls.lkp_ifconfig.set_link_speed(LINK_SPEED_AUTO)
            cls.lkp_ifconfig1.set_link_speed(LINK_SPEED_AUTO)

            cls.prev_speed = None

            cls.machines = {
                'dut':
                    {
                        'name': cls.dut_hostname,
                        'port0': '0' + cls.dut_port[3:4] + ':' + cls.dut_port[5:],
                        'port1': '0' + cls.dut_port1[3:4] + ':' + cls.dut_port1[5:]
                    },
                'lkp':
                    {
                        'name': cls.lkp_hostname,
                        'port0': '0' + cls.lkp_port[3:4] + ':' + cls.lkp_port[5:],
                        'port1': '0' + cls.lkp_port1[3:4] + ':' + cls.lkp_port1[5:]
                    }
            }
            cls.ports = [cls.machines['dut']['port0'], cls.machines['dut']['port1']]

            for m in ['dut', 'lkp']:
                if cls.machines[m]['name'] is None:
                    cls.machines[m]['name'] = socket.gethostname()

            log.debug('machines: {}'.format(cls.machines))

            cls.dut_atltool = AtlTool(port=cls.dut_port, host=cls.dut_hostname)
            cls.lkp_atltool = AtlTool(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.dut_atltool1 = AtlTool(port=cls.dut_port1, host=cls.dut_hostname)
            cls.lkp_atltool1 = AtlTool(port=cls.lkp_port1, host=cls.lkp_hostname)

            cls.machines['dut']['mac0'] = cls.dut_atltool.get_mac_address()
            cls.machines['dut']['mac1'] = cls.dut_atltool1.get_mac_address()

            cls.machines['lkp']['mac0'] = cls.lkp_atltool.get_mac_address()
            cls.machines['lkp']['mac1'] = cls.lkp_atltool1.get_mac_address()

            Command(cmd='sudo ifconfig -a', host=cls.lkp_hostname).run_join(timeout=180)
            Command(cmd='sudo ifconfig -a', host=cls.dut_hostname).run_join(timeout=180)

            cls.lkp_ifconfig.set_ip_address(cls.LKP_IP, cls.DEFAULT_NETMASK_IPV4, None)
            cls.lkp_ifconfig1.set_ip_address(cls.LKP_IP_1, cls.DEFAULT_NETMASK_IPV4, None)

            traffic_gen_name = os.environ.get("TRAFFIC_GEN", 'scapy')  # [pktgen, aukua, scapy]

            cls.lkp_scapy_tools = ScapyTools(port=cls.lkp_port, host=cls.lkp_hostname)
            cls.lkp_scapy_tools1 = ScapyTools(port=cls.lkp_port1, host=cls.lkp_hostname)

            cls.lkp_scapy_iface = cls.lkp_scapy_tools.get_scapy_iface()
            cls.lkp_scapy_iface1 = cls.lkp_scapy_tools1.get_scapy_iface()

            init_dpdk(cls.machines['dut']['name'])

            cls.pytestpmd = ModuleTestPMD(host=cls.dut_hostname, ports=cls.ports)

            log.info(cls.machines)

            args = {
                'host': cls.lkp_hostname,
                'port': cls.lkp_port,
                'iface': cls.lkp_scapy_iface
            }

            cls.traffic_generator = TrafficGen(name=traffic_gen_name, **args)
            cls.lkp_ifconfig.set_mtu(MTU_16000)

            commands = [
                'sudo modprobe uio_pci_generic',
                'cd /home/aqtest/dpdk_ninja && sudo ./usertools/dpdk-devbind.py --bind=uio_pci_generic {}'.
                    format(" ".join(cls.ports))
            ]
            run_commands(commands, host=cls.dut_hostname)

        except Exception as e:
            log.exception("Failed while setting up class")
            raise e

    # @classmethod
    # def setup_class(cls):
    #     # Make sure we are able to rmmod driver
    #     cls.uninit_ports()
    #     # Cleanup
    #     commands = [
    #         'cd /home/aqtest/dpdk_ninja && sudo ./usertools/dpdk-devbind.py -u {}'.format(" ".join(cls.ports)),
    #         'sudo rmmod uio_pci_generic',
    #     ]
    #     run_commands(commands)

    def setup_method(self, method):
        super(TestDPDKBase, self).setup_method(method)

        # # Cleanup
        # commands = [
        #     'cd /home/aqtest/dpdk_ninja && sudo ./usertools/dpdk-devbind.py -u {}'.format(" ".join(self.ports)),
        #     'sudo rmmod uio_pci_generic',
        # ]
        # run_commands(commands, skip_fail=True)

        # commands = [
        #     'sudo modprobe uio_pci_generic',
        #     'cd /home/aqtest/dpdk_ninja && sudo ./usertools/dpdk-devbind.py --bind=uio_pci_generic {}'.
        #         format(" ".join(self.ports))
        # ]
        # run_commands(commands, host=self.dut_hostname)
        #
        # # Initialize devices in testpmd
        # # TODO: add port_attach to pytestpmd (to be able to check error code)
        # for port_name in self.ports:
        #     self.pytestpmd.exec_cmd("port attach {}".format(port_name))

        if self.MCP_LOG:
            self.bin_log_file, self.txt_log_file = self.dut_atltool.debug_buffer_enable(True)
            log.info('DUT DEBUG LOG: {}'.format(self.txt_log_file))
            self.dut_atltool.enable_phy_logging(True)

            self.lkp_atltool.debug_buffer_enable(True)
            self.lkp_atltool.enable_phy_logging(True)

    def teardown_method(self, method):
        super(TestDPDKBase, self).teardown_method(method)

        if self.MCP_LOG:
            self.dut_atltool.enable_phy_logging(False)
            self.dut_atltool.debug_buffer_enable(False)
            shutil.copy(self.bin_log_file, self.test_log_dir)
            shutil.copy(self.txt_log_file, self.test_log_dir)

            self.lkp_atltool.enable_phy_logging(False)
            self.lkp_bin_log_file, self.lkp_txt_log_file = self.lkp_atltool.debug_buffer_enable(False)
            shutil.copy(self.lkp_bin_log_file, self.test_log_dir)
            shutil.copy(self.lkp_txt_log_file, self.test_log_dir)

        # # Close and detach ports (to able to rmmod driver)
        # self.uninit_ports()
        # # Unbind and unload driver
        # commands = [
        #     'cd /home/aqtest/dpdk_ninja && sudo ./usertools/dpdk-devbind.py -u {}'.format(" ".join(self.ports)),
        #     'sudo rmmod uio_pci_generic',
        # ]
        # run_commands(commands, host=self.dut_hostname)

    # @classmethod
    # def uninit_ports(cls):
    #     # TODO: add port_close and port_detach to pytestpmd (to be able to check error code)
    #     for port_id in cls.pytestpmd.get_valid_ports():
    #         cls.pytestpmd.exec_cmd("port stop {}".format(port_id))
    #         cls.pytestpmd.exec_cmd("port close {}".format(port_id))
    #         cls.pytestpmd.exec_cmd("port detach {}".format(port_id))

    def public_file(self, path_to_file):
        log.info('public: {} --> {}'.format(path_to_file, self.test_log_dir))
        shutil.move(path_to_file, self.test_log_dir)

    def run_app(self, command, params_pmd, params='', timeout=180):
        cmd = 'cd /home/aqtest/dpdk_ninja/build_meson/ && sudo {} {} -- {}'
        cmd = cmd.format(command, params_pmd, params)
        cmd_example = Command(cmd=cmd)
        return cmd_example.run_join(timeout=timeout)

    def run_app_async(self, command, params_pmd, params=''):
        cmd = 'cd /home/aqtest/dpdk_ninja/build_meson/ && sudo {} {} -- {}'
        cmd = cmd.format(command, params_pmd, params)
        self.cmd_example = Command(cmd=cmd)
        self.cmd_example.run_async()

    def run_app_join(self, timeout=180):
        return self.cmd_example.join(timeout=timeout)
