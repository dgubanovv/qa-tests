"""
Module to help manage core virtual networks
TODO: parse configuration files automatically to extract info about nodes
"""

import re

from command import Command
from utils import get_atf_logger

log = get_atf_logger()

NODE_TYPE_NONE = None
NODE_TYPE_HOST = "Host"
NODE_TYPE_SWITCH = "Switch"
NODE_TYPE_ROUTER = "Router"


class VirtualNode(object):
    node_type = None

    def __init__(self, name):
        self.name = name


class VirtualHost(VirtualNode):
    node_type = NODE_TYPE_HOST

    def __init__(self, name, ipv4, ipv6, mac=""):
        super(VirtualHost, self).__init__(name)
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.mac = mac.lower()


class VirtualSwitch(VirtualNode):
    node_type = NODE_TYPE_SWITCH


class VirtualRouter(VirtualNode):
    node_type = NODE_TYPE_ROUTER

    def __init__(self, name, eth0_ipv4, eth0_ipv6, eth1_ipv4, eth1_ipv6):
        super(VirtualRouter, self).__init__(name)
        self.eth0_ipv4 = eth0_ipv4
        self.eth0_ipv6 = eth0_ipv6
        self.eth1_ipv4 = eth1_ipv4
        self.eth1_ipv6 = eth1_ipv6


class VirtualNetwork(object):
    def __init__(self, conf_file, host=None):
        self.conf_file = conf_file
        self.host = host
        self.session_id = None

    def start_daemon(self):
        start_cmd = Command(cmd="sudo systemctl start core-daemon", host=self.host)
        start_res = start_cmd.run_join(30)
        if start_res["returncode"] != 0:
            raise Exception("Failed to start core-daemon")

    def stop_daemon(self):
        stop_cmd = Command(cmd="sudo systemctl stop core-daemon", host=self.host)
        stop_cmd.run_join(30)

    def list_sessions(self):
        list_cmd = Command(cmd="ls /tmp | grep pycore | awk -F'.' '{ print $2 }'", host=self.host)
        list_res = list_cmd.run_join()
        if list_res["returncode"] != 0:
            raise Exception("Failed to list current core sessions")
        return list_res["output"]

    def is_running(self):
        return self.session_id is not None

    def start_session(self):
        gui_cmd = Command(cmd="sudo core-gui -b {}".format(self.conf_file), host=self.host)
        gui_res = gui_cmd.run_join(30)
        re_session_id = re.compile(r"Session id is (\d+)")
        for line in gui_res["output"]:
            match = re_session_id.search(line)
            if match is not None:
                self.session_id = int(match.group(1))
                break
        if self.session_id is None:
            raise Exception("Failed to get session id for virtual network")

    def stop_session(self):
        gui_cmd = Command(cmd="sudo core-gui -c {}".format(self.session_id), host=self.host)
        gui_res = gui_cmd.run_join(10)
        if gui_res["returncode"] != 0:
            raise Exception("Failed to close core session {}".format(self.session_id))

    def kill_session_by_id(self, session_id):
        gui_cmd = Command(cmd="sudo core-gui -c {}".format(session_id), host=self.host)
        gui_cmd.run_join(10)

    def virtual_cmd(self, name, cmd, **kwargs):
        return Command(cmd="vcmd -c /tmp/pycore.{}/{} -- {}".format(self.session_id, name, cmd), host=self.host,
                       **kwargs)
