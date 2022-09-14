import argparse
import json
import re
import sys
import time
import traceback

import requests

from utils import get_atf_logger


SCRIPT_STATUS_SUCCESS = "[MOTUPER-SUCCESS]"
SCRIPT_STATUS_FAILED = "[MOTUPER-FAILED]"
HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}

log = get_atf_logger()
SESSION = requests.Session()

LOCK_STATE_LOCKED = "LOCKED"
LOCK_STATE_UNLOCKED = "UNLOCKED"


def get_value(motu_hostname, path, session=SESSION, retries=3):
    if not isinstance(session, requests.Session):
        session = requests.Session()
    url = 'http://{}/datastore/{}'.format(motu_hostname, path)
    log.info("GET {}".format(url))
    for count in xrange(retries):
        try:
            req = session.get(url)
            if req.status_code == 200:
                content = json.loads(req.content)
                log.info(json.dumps(content, indent=4, sort_keys=True))
                return content
            else:
                log.warning("Failed to get URL: {}. Response code: {}. Retries remaining: {}".format(
                    url, req.status_code, retries - count - 1
                ))
        except Exception:
            log.warning("Failed to get URL: {}. Retries remaining: {}".format(url, retries - count - 1))
    raise Exception("Failed to get URL: {}.".format(url))


def set_value(motu_hostname, path, value, session=SESSION, timeout=2., retries=3):
    if not isinstance(session, requests.Session):
        session = requests.Session()
    value = str(value)
    url = 'http://{}/datastore/{}'.format(motu_hostname, path)
    log.info("SET {} {}".format(url, value))
    try:
        int(value)
        data_str = 'json={{"value": {}}}'.format(value)
    except ValueError:
        data_str = 'json={{"value": "{}"}}'.format(value)

    for count in xrange(retries):
        try:
            post = session.post(url, data=data_str, headers=HEADERS)
            if post.status_code == 204:
                break
            else:
                log.warning("Failed to set value {} to URL: {}. Response code: {}. Retries remaining: {}".format(
                    url, post.status_code, retries - count - 1
                ))
        except Exception:
            log.warning("Failed to get URL: {}. Retries remaining: {}".format(url, retries - count - 1))
    time.sleep(timeout)
    result = get_value(motu_hostname, path, session)
    if str(result["value"]) == str(value):
        log.info("Value {} successfully set to {}".format(value, url))
    else:
        raise Exception(
            "Failed to set value {} to URL: {}. Current value {} is not equal to the requested one {}".format(
                value, url, result["value"], value
            )
        )


def get_entity_ids(motu_hostname, session=SESSION):
    result = get_value(motu_hostname, "avb/devs", session)
    entities = result["value"].split(":")
    local_id = entities[0]
    if len(entities) == 1:
        remote_id = None
    else:
        remote_id = entities[-1]
    log.info("Entity IDs: Local: {}; Remote: {}".format(local_id, remote_id))
    return local_id, remote_id


def get_input_streams_number(motu_hostname, session=SESSION):
    local_entity, _ = get_entity_ids(motu_hostname, session)
    path = "avb/{}/cfg/0/input_streams/num".format(local_entity)
    result = int(get_value(motu_hostname, path, session)["value"])
    log.info("Number of input streams: {}".format(result))
    return result


def get_output_streams_number(motu_hostname, session=SESSION):
    local_entity, _ = get_entity_ids(motu_hostname, session)
    path = "avb/{}/cfg/0/output_streams/num".format(local_entity)
    result = int(get_value(motu_hostname, path, session)["value"])
    log.info("Number of output streams: {}".format(result))
    return result


def set_input_streams_number(motu_hostname, value, session=SESSION):
    value = int(value)
    local_entity, _ = get_entity_ids(motu_hostname, session)
    path = "avb/{}/cfg/0/input_streams/requested_num".format(local_entity)
    set_value(motu_hostname, path, value, session, timeout=5)
    path = "avb/{}/cfg/0/input_streams/num".format(local_entity)
    result = get_value(motu_hostname, path, session)
    if result["value"] == value:
        log.info("Value {} successfully applied.".format(value))
    else:
        raise Exception(
            "Value {} was not applied. Current value: {}".format(value, result["value"])
        )


def set_output_streams_number(motu_hostname, value, session=SESSION):
    value = int(value)
    local_entity, _ = get_entity_ids(motu_hostname, session)
    path = "avb/{}/cfg/0/output_streams/requested_num".format(local_entity)
    set_value(motu_hostname, path, value, session, timeout=5)
    path = "avb/{}/cfg/0/output_streams/num".format(local_entity)
    result = get_value(motu_hostname, path, session)
    if result["value"] == value:
        log.info("Value {} successfully applied.".format(value))
    else:
        raise Exception(
            "Value {} was not applied. Current value: {}".format(value, result["value"])
        )


def get_clock_sources(motu_hostname, session=SESSION):
    local_entity, _ = get_entity_ids(motu_hostname, session)
    path = "avb/{}/cfg/0/clock_sources".format(local_entity)
    result = get_value(motu_hostname, path, session)
    clock_sources = {}
    reg = re.compile("^(\d+)/(object_name|stream_id|type)$")
    for key, value in result.items():
        match = reg.match(key)
        if match:
            major_key, minor_key = int(match.group(1)), match.group(2)
            exist = clock_sources.get(major_key)
            if not exist:
                clock_sources[major_key] = {minor_key: value}
            else:
                clock_sources[major_key].update({minor_key: value})
    sources = [item["object_name"] for item in clock_sources.values()]
    log.info("Clock sources:\n{}".format("\n".join(sources)))
    return clock_sources


def set_clock_source(motu_hostname, value, session=SESSION):
    clock_sources = get_clock_sources(motu_hostname, session)
    for source_num, source in clock_sources.items():
        if source["object_name"] == value:
            local_entity, _ = get_entity_ids(motu_hostname, session)
            path = "avb/{}/cfg/0/clock_source_index".format(local_entity)
            set_value(motu_hostname, path, source_num, session)
            return
    raise Exception("Clock source {} is not available".format(value))


def get_clock_source(motu_hostname, session=SESSION):
    local_entity, _ = get_entity_ids(motu_hostname, session)
    path = "avb/{}/cfg/0/clock_source_index".format(local_entity)
    result = int(get_value(motu_hostname, path, session)["value"])
    clock_sources = get_clock_sources(motu_hostname, session)
    result = clock_sources[result]["object_name"]
    log.info("Current clock source: {}".format(result))
    return result

def get_lock_state(motu_hostname, session=SESSION):
    path = "ext/clockLocked"
    result = bool(get_value(motu_hostname, path, session)["value"])
    result= LOCK_STATE_LOCKED if result else LOCK_STATE_UNLOCKED
    log.info("MOTU lock state is: {}".format(result))
    return result

def get_avb_input_banks(motu_hostname, session=SESSION):
    avb_stream_reg = re.compile("^AVB Stream (\d+)$")
    path = "ext/ibank"
    avb_banks = {}
    result = get_value(motu_hostname, path, session)
    for key, value in result.items():
        if not isinstance(value, int):
            match = avb_stream_reg.match(value)
            if match:
                bank, _ = key.split("/")
                stream_num = match.group(1)
                avb_banks.update({int(stream_num): int(bank)})
    for key in sorted(avb_banks.keys()):
        log.info("AVB input banks:")
        log.info("AVB Stream {} in bank {}".format(key, avb_banks[key]))
    return avb_banks


def get_avb_output_banks(motu_hostname, session=SESSION):
    avb_stream_reg = re.compile("^AVB Stream (\d+)$")
    path = "ext/obank"
    avb_banks = {}
    result = get_value(motu_hostname, path, session)
    for key, value in result.items():
        if not isinstance(value, int):
            match = avb_stream_reg.match(value)
            if match:
                bank, _ = key.split("/")
                stream_num = match.group(1)
                avb_banks.update({int(stream_num): int(bank)})
    for key in sorted(avb_banks.keys()):
        log.info("AVB output banks:")
        log.info("AVB Stream {} in bank {}".format(key, avb_banks[key]))
    return avb_banks


def set_avb_input_to_output(motu_hostname, session=SESSION):
    input_stream_num = get_input_streams_number(motu_hostname, session)
    output_stream_num = get_output_streams_number(motu_hostname, session)
    streams_to_be_set = min(input_stream_num, output_stream_num)
    input_banks = get_avb_input_banks(motu_hostname, session)
    output_banks = get_avb_output_banks(motu_hostname, session)
    for stream in xrange(1, streams_to_be_set + 1):
        input_bank = input_banks[stream]
        output_bank = output_banks[stream]
        for channel in xrange(8):
            path = "ext/obank/{}/ch/{}/src".format(output_bank, channel)
            value = "{}:{}".format(input_bank, channel)
            set_value(motu_hostname, path, value, session, timeout=0.1)


class Motuper(object):
    def __init__(self, **kwargs):
        self.motu_hostname = kwargs["motu_hostname"]

    def get_value(self, path):
        return get_value(self.motu_hostname, path)

    def set_value(self, path, value, timeout=2.):
        set_value(self.motu_hostname, path, value, timeout=timeout)

    def get_entity_ids(self):
        return get_entity_ids(self.motu_hostname)

    def get_input_streams_number(self):
        return get_input_streams_number(self.motu_hostname)

    def get_output_streams_number(self):
        return get_output_streams_number(self.motu_hostname)

    def set_input_streams_number(self, value):
        set_input_streams_number(self.motu_hostname, value)

    def set_output_streams_number(self, value):
        set_output_streams_number(self.motu_hostname, value)

    def get_clock_sources(self):
        return get_clock_sources(self.motu_hostname)

    def set_clock_source(self, value):
        set_clock_source(self.motu_hostname, value)

    def get_clock_source(self):
        return get_clock_source(self.motu_hostname)

    def get_lock_state(self):
        return get_lock_state(self.motu_hostname)

    def get_avb_input_banks(self):
        return get_avb_input_banks(self.motu_hostname)

    def get_avb_output_banks(self):
        return get_avb_output_banks(self.motu_hostname)

    def set_avb_input_to_output(self):
        set_avb_input_to_output(self.motu_hostname)


class VirtualAudioArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error(SCRIPT_STATUS_FAILED)
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = VirtualAudioArgumentParser()
    parser.add_argument("-c", "--command", help="Command to be performed",
                        choices=["get_value",
                                 "set_value",
                                 "get_devs",
                                 "get_input_streams_number",
                                 "get_output_streams_number",
                                 "set_input_streams_number",
                                 "set_output_streams_number",
                                 "get_clock_sources",
                                 "set_clock_source",
                                 "get_clock_source",
                                 "get_lock_state",
                                 "get_avb_input_banks",
                                 "get_avb_output_banks",
                                 "set_avb_input_output",
                                 ], type=str, required=True)
    parser.add_argument("-host", "--motu_host", help="MOTU hostname, i.e. 'M8' or '192.168.0.10' or ...", type=str,
                        default=None)
    parser.add_argument("-p", "--path", help="path for item in MOTU storage", type=str, default="")
    parser.add_argument("-v", "--value", help="Stream config", type=str)
    args = parser.parse_args()

    try:
        if args.command == "get_value":
            get_value(args.motu_host, args.path)
        elif args.command == "set_value":
            set_value(args.motu_host, args.path, args.value)
        elif args.command == "get_devs":
            get_entity_ids(args.motu_host)
        elif args.command == "get_input_streams_number":
            get_input_streams_number(args.motu_host)
        elif args.command == "get_output_streams_number":
            get_output_streams_number(args.motu_host)
        elif args.command == "set_input_streams_number":
            set_input_streams_number(args.motu_host, args.value)
        elif args.command == "set_output_streams_number":
            set_output_streams_number(args.motu_host, args.value)
        elif args.command == "get_clock_sources":
            get_clock_sources(args.motu_host)
        elif args.command == "set_clock_source":
            set_clock_source(args.motu_host, args.value)
        elif args.command == "get_clock_source":
            get_clock_source(args.motu_host)
        elif args.command == "get_lock_state":
            get_lock_state(args.motu_host)
        elif args.command == "get_avb_input_banks":
            get_avb_input_banks(args.motu_host)
        elif args.command == "get_avb_output_banks":
            get_avb_output_banks(args.motu_host)
        elif args.command == "set_avb_input_output":
            set_avb_input_to_output(args.motu_host)

    except Exception as exc:
        traceback.print_exc(limit=10, file=sys.stderr)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
