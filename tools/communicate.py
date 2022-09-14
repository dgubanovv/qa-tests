import time

import requests

from tools.constants import HTTP_RETRY_COUNT, HTTP_RETRY_INTERVAL
import json

from tools.utils import get_atf_logger

log = get_atf_logger()

SERVER_METRIC = 'http://nn-ap01.rdc-lab.marvell.com/flask/addmetrics/'


class PerfRecord(object):
    def __init__(self, units, min, max, avg, count, description='', params=''):
        self.units = units
        self.min = min
        self.max = max
        self.avg = avg
        self.count = count
        self.description = description
        self.params = params


def send_performance_results(results, _os, testid, name="", data=''):
    for r in results:
        url = SERVER_METRIC + '{}'.format(testid)
        send_metric_result(url, name, _os, r.units, r.min, r.max, r.avg, r.count, r.description, data, r.params)


def send_metric_result(url, name, _os, units, min, max, avg, count, description='', data='', params=''):
    if not all([url, name, _os, units, max, min, avg, count]):
        return
    data = {"name": name, "os": _os, "units": units, "min": min, "max": max, "avg": avg,
            "count": count, "description": description, "data": data, "params": params}
    send_result(url, data)


def send_test_result(url, name, result, _log, _test_log=''):
    if not all([url, name, result, _log]):
        return
    data = {"name": name, "result": result, "log": _log, "ticket_id": 0, "test_log": _test_log}
    send_result(url, data)


def send_result(url, data):
    log.info("Sending '{}' to url '{}'".format(str(data), url))
    for i in range(HTTP_RETRY_COUNT):
        try:
            response = requests.post(url, data=json.dumps(data))
            if response.status_code != 200:
                log.warning("Failed to send subtest result message")
                log.warning("Response content:\n{}".format(response.content))
                raise RuntimeError("Failed to report subtest result")
            break
        except Exception as exc:
            if i < HTTP_RETRY_COUNT - 1:
                log.exception("Attempt {} failed. Will retry after {} seconds.".format(i + 1, HTTP_RETRY_INTERVAL))
                time.sleep(HTTP_RETRY_INTERVAL)
                log.info('Retrying...')
                continue
            log.exception(exc)
            return
