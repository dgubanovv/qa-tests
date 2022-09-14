import json
import os
import requests
import socket
import time
from collections import OrderedDict
from tools.constants import HTTP_RETRY_COUNT, HTTP_RETRY_INTERVAL
from tools.utils import get_atf_logger, get_url_response

log = get_atf_logger()


class TestState(object):
    def __init__(self):
        self.tests = OrderedDict()
        self.current_test = None
        self.current_test_norm = None
        self.fw_install_cold_restart = False
        self.test_cleanup_cold_restart = False
        self.skip_class_setup = False
        self.skip_reboot = False
        # Default scheduler value is temporary hardcoded for backward compatibility
        self.scheduler = os.environ.get("ATF_SCHEDULER", "http://nn-ap01.rdc-lab.marvell.com/sched")
        self.hostname = socket.gethostname()
        self.dut_dev_present_cold_restart = False
        self.lkp_dev_present_cold_restart = False

    def load_state_from_server(self):
        url = "{}/get_job_state?node={}".format(self.scheduler, self.hostname)
        content = get_url_response(url)
        return json.loads(content, object_pairs_hook=OrderedDict)

    def update_state_on_server(self, state):
        srv_state = self.load_state_from_server()
        srv_state["pytest"] = state

        url = "{}/update_job_state?node={}".format(self.scheduler, self.hostname)
        log.debug("Updating pytest state by URL {}".format(url))
        try:
            response = requests.post(url=url, data=json.dumps(srv_state))
        except Exception as exc:
            log.exception("Failed to update pytest state")
            raise exc
        else:
            if response.status_code != 200:
                log.error("Failed to update pytest state, status {}".format(response.status_code))
                log.error("JSON data for POST request: {}".format(json.dumps(srv_state)))
                log.error("Response content:\n{}".format(response.content))
                log.error("Failed to update test state on server!")
            return response.content

    def load(self):
        for i in range(HTTP_RETRY_COUNT):
            try:
                state = self.load_state_from_server()
            except Exception as e:
                log.error("Failed to load pytest state, retrying")
                log.error(e)
                time.sleep(HTTP_RETRY_INTERVAL)
            else:
                if "pytest" in state:
                    self.tests = state["pytest"].get("tests", OrderedDict())
                    self.fw_install_cold_restart = state["pytest"].get("fw_install_cold_restart", False)
                    self.test_cleanup_cold_restart = state["pytest"].get("test_cleanup_cold_restart", False)
                    self.skip_class_setup = state["pytest"].get("skip_class_setup", False)
                    self.skip_reboot = state["pytest"].get("skip_reboot", False)
                    self.dut_dev_present_cold_restart = state["pytest"].get("dut_dev_present_cold_restart", False)
                    self.lkp_dev_present_cold_restart = state["pytest"].get("lkp_dev_present_cold_restart", False)
                    return
                else:
                    log.info("Pytest state is empty on the server")
                    return
        raise Exception("Failed to load pytest state")

    def update(self):
        data = {
            "tests": self.tests,
            "fw_install_cold_restart": self.fw_install_cold_restart,
            "test_cleanup_cold_restart": self.test_cleanup_cold_restart,
            "skip_class_setup": self.skip_class_setup,
            "skip_reboot": self.skip_reboot,
            "dut_dev_present_cold_restart": self.dut_dev_present_cold_restart,
            "lkp_dev_present_cold_restart": self.lkp_dev_present_cold_restart
        }

        for i in range(HTTP_RETRY_COUNT):
            try:
                self.update_state_on_server(data)
                return
            except Exception:
                log.exception("Failed to update pytest state, retrying")
                time.sleep(HTTP_RETRY_INTERVAL)
        raise Exception("Failed to update pytest state")

    def erase(self):
        log.info("Erasing pytest state")
        self.tests = OrderedDict()
        self.fw_install_cold_restart = False
        self.test_cleanup_cold_restart = False
        self.skip_class_setup = False
        self.skip_reboot = False
        self.dut_dev_present_cold_restart = False
        self.lkp_dev_present_cold_restart = False
        self.update_state_on_server({})
