import argparse
import re
import sys
import time
import traceback
import threading
import Queue
import numpy as np
import plistlib
import sounddevice as sd
import ops
import ifconfig
from command import Command
from abc import abstractmethod, ABCMeta
from constants import ATF_TOOLS_DIR
from utils import get_atf_logger

SCRIPT_STATUS_SUCCESS = "[VIRTUAL-AUDIO-SUCCESS]"
SCRIPT_STATUS_FAILED = "[VIRTUAL-AUDIO-FAILED]"
CONFIG_1_STREAM = 0
CONFIG_2_STREAMS = 1
CONFIG_4_STREAMS = 2
CONFIG_8_STREAMS = 3
CONFIG_16_STREAMS = 4

log = get_atf_logger()

op_system = ops.OpSystem()


def close_setup():
    tmp_file = "/tmp/script.txt"
    script = 'tell application "Audio MIDI Setup" to quit'
    with open(tmp_file, "w") as fileo:
        fileo.write(script)
    log.info("Executing applescript:")
    log.info(script)
    cmd = "sudo -u aqtest osascript '{}'".format(tmp_file)
    result = Command(host="localhost", cmd=cmd).run_join(120)
    if result["returncode"] != 0:
        log.warning("Failed to quit Audio MIDI Setup")
    time.sleep(2)


def gen_buffer(duration, block_size, sample_rate=48000, frequency=440, channels=1):
    """
    Sine generator

    Generate a peace of sine of lenght <block_size> samples in a given number of channels
    """
    start_angle = 0
    for buf_num in xrange(int(duration * sample_rate / block_size)):
        angle_list = np.arange(block_size) + start_angle
        start_angle = angle_list[-1]
        sine = np.array(np.sin(2 * np.pi * angle_list * frequency / sample_rate), dtype=np.float32)
        samples = []
        for frame in sine:
            samples.append(np.array([frame] * channels))
        samples = np.array(samples)
        yield samples


def play_sine_to_sound_device(sound_device, duration, frequency=440, sample_rate=48000, channels=1):
    """Plays sine wave to the given audio device in the given number of channels"""
    buffer_size = 20
    block_size = 2048
    buffer_queue = Queue.Queue(maxsize=buffer_size)
    event = threading.Event()
    gen = gen_buffer(duration, block_size, sample_rate=sample_rate, frequency=frequency, channels=channels)

    def callback(outdata, frames, time, status):
        if status.output_underflow:
            log.warning('Output underflow: increase blocksize')
            raise sd.CallbackAbort
        try:
            data = buffer_queue.get_nowait()
        except Queue.Empty:
            log.warning('Buffer is empty: increase buffersize')
            raise sd.CallbackAbort
        else:
            outdata[:] = data

    for _ in range(buffer_size):
        buffer_queue.put_nowait(gen.next())

    stream = sd.RawOutputStream(
        samplerate=sample_rate, blocksize=block_size,
        device=sound_device, channels=channels, dtype='float32',
        callback=callback, finished_callback=event.set)
    with stream:
        timeout = float(block_size * buffer_size) / sample_rate
        for data in gen:
            buffer_queue.put(data, timeout=timeout)
        event.wait()


def set_clock_source_macos(device, clock_source):
    tmp_file = "/tmp/script.txt"
    retry_count = 5
    script = """
tell application "Audio MIDI Setup" to launch
delay 2
tell application "System Events"
    tell application process "Audio MIDI Setup"
        repeat with theItem in every row of outline 1 of scroll area 1 of splitter group 1 of window "Audio Devices"
            if UI element "{}" of theItem exists then
               select theItem
               do shell script "echo 'Clock was set'"
               exit repeat
            end if
        end repeat
        click pop up button 1 of splitter group 1 of window "Audio Devices"
        click menu item "{}" of menu 1 of pop up button 1 of splitter group 1 of window "Audio Devices"
    end tell
end tell
tell application "Audio MIDI Setup" to quit
""".format(device, clock_source)
    cmd = "sudo DISPLAY=:0 -u aqtest osascript '{}'".format(tmp_file)
    for num in xrange(retry_count):
        with open(tmp_file, "w") as fileo:
            fileo.write(script)
        log.info("Executing applescript:")
        log.info(script)
        result = Command(host="localhost", cmd=cmd).run_join(120)
        if result["returncode"] != 0:
            log.warning("Failed to execute apple script remaining tries: {}".format(retry_count - num - 1))
            close_setup()
        else:
            return
    raise Exception("Failed to set source clock {} for device {}".format(clock_source, device))


def set_clock_source_windows(device, clock_source):
    raise NotImplementedError


def set_clock_source_linux(device, clock_source):
    raise NotImplementedError


def set_clock_source(device, clock_source):
    if op_system.is_mac():
        set_clock_source_macos(device, clock_source)
    elif op_system.is_linux():
        set_clock_source_linux(device, clock_source)
    elif op_system.is_windows():
        set_clock_source_windows(device, clock_source)
    else:
        raise ValueError("Unknown OS")


def set_avb_device_config_macos(config):
    config_file = "/Library/Preferences/Audio/com.apple.audio.SystemSettings.plist"
    device_name = get_avb_device_name()
    set_output_audio_device(device_name)
    config_file_content = plistlib.readPlist(config_file)
    current_output_entity = config_file_content["preferred devices"]["output"][0]["uid"]
    entity_id, config_id, _ = current_output_entity.split(":")
    log.debug("Current output entity_id: {}, config_id: {}".format(entity_id, config_id))
    entity_to_be_edit = None
    for entity in config_file_content["Plug-In.com.apple.audio.AppleAVBAudio"]["PersistentVirtualAudioEntities"].keys():
        if entity_id in entity:
            entity_to_be_edit = entity
            break

    config_file_content["Plug-In.com.apple.audio.AppleAVBAudio"]["PersistentVirtualAudioEntities"][
        entity_to_be_edit]["CurrentConfiguration"] = config
    Command(cmd="sudo chmod 777  {}".format(config_file)).run_join(3)
    plistlib.writePlist(config_file_content, config_file)
    Command(cmd="sudo kill `ps -ax | grep 'coreaudiod' | grep 'sbin' |awk '{print $1}'`").run_join(10)
    time.sleep(5)
    set_output_audio_device(device_name)


def set_avb_device_config_windows(config):
    raise NotImplementedError


def set_avb_device_config_linux(config):
    raise NotImplementedError


def set_avb_device_config(config):
    if op_system.is_mac():
        set_avb_device_config_macos(config)
    elif op_system.is_linux():
        set_avb_device_config_linux(config)
    elif op_system.is_windows():
        set_avb_device_config_windows(config)
    else:
        raise ValueError("Unknown OS")


def set_output_audio_device_macos(device):
    cmd = "SwitchAudioSource -s '{}' -t output".format(device)
    result = Command(cmd=cmd).run_join(10)["returncode"]
    if result != 0:
        raise Exception("Failed to set output audio device {}".format(device))


def set_output_audio_device_windows(device):
    raise NotImplementedError


def set_output_audio_device_linux(device):
    raise NotImplementedError


def set_output_audio_device(device):
    if op_system.is_mac():
        set_output_audio_device_macos(device)
    elif op_system.is_linux():
        set_output_audio_device_linux(device)
    elif op_system.is_windows():
        set_output_audio_device_windows(device)
    else:
        raise ValueError("Unknown OS")


def set_input_audio_device_macos(device):
    cmd = "SwitchAudioSource -s '{}' -t input".format(device)
    result = Command(cmd=cmd).run_join(10)["returncode"]
    if result != 0:
        raise Exception("Failed to set input audio device {}".format(device))


def set_input_audio_device_windows(device):
    raise NotImplementedError


def set_input_audio_device_linux(device):
    raise NotImplementedError


def set_input_audio_device(device):
    if op_system.is_mac():
        set_input_audio_device_macos(device)
    elif op_system.is_linux():
        set_input_audio_device_linux(device)
    elif op_system.is_windows():
        set_input_audio_device_windows(device)
    else:
        raise ValueError("Unknown OS")


def get_avb_device_name_macos():
    avb_device_reg = re.compile("^((.*macpro\d+|.*mm\d+|.*J137-\d+|.*imac\d+):.*) \(output\)$")
    output = Command(cmd="SwitchAudioSource -a -t output").run_join(10)["output"]
    avb_device = None
    for line in output:
        match = avb_device_reg.match(line)
        if match:
            avb_device = match.group(1)
            break
    if not avb_device:
        raise Exception("Failed to find AVB device")
    else:
        log.info("AVB device was found: '{}'".format(avb_device))
    return avb_device


def get_avb_device_name_windows():
    raise NotImplementedError


def get_avb_device_name_linux():
    raise NotImplementedError


def get_avb_device_name():
    if op_system.is_mac():
        avb_device = get_avb_device_name_macos()
    elif op_system.is_linux():
        avb_device = get_avb_device_name_linux()
    elif op_system.is_windows():
        avb_device = get_avb_device_name_windows()
    else:
        raise ValueError("Unknown OS")
    return avb_device


def get_output_devices_macos():
    output = Command(cmd="SwitchAudioSource -a -t output").run_join(10)["output"]
    log.info("Found output devices: {}".format(output))
    return output


def get_output_devices_windows():
    reg = re.compile("^[ ><] [ 1][0-9] ([\s\S]*) \(0 in, [0-9] out\)$")
    output = Command(cmd="python -m sounddevice").run_join(10)["output"]
    devices = []
    for line in output:
        match = reg.match(line)
        if match:
            devices.append(match.group(1))
    log.info("Found output devices: {}".format(devices))
    return devices


def get_output_devices_linux():
    raise NotImplementedError


def get_output_devices():
    if op_system.is_mac():
        output_devices = get_output_devices_macos()
    elif op_system.is_linux():
        output_devices = get_output_devices_linux()
    elif op_system.is_windows():
        output_devices = get_output_devices_windows()
    else:
        raise ValueError("Unknown OS")
    return output_devices


def get_input_devices_macos():
    output = Command(cmd="SwitchAudioSource -a -t input").run_join(10)["input"]
    log.info("Found input devices: {}".format(output))
    return output


def get_input_devices_windows():
    reg = re.compile("^[ ><] [ 1][0-9] ([\s\S]*) \([0-9] in, 0 out\)$")
    output = Command(cmd="python -m sounddevice").run_join(10)["output"]
    devices = []
    for line in output:
        match = reg.match(line)
        if match:
            devices.append(match.group(1))
    log.info("Found output devices: {}".format(devices))
    return devices


def get_input_devices_linux():
    raise NotImplementedError


def get_input_devices():
    if op_system.is_mac():
        input_devices = get_input_devices_macos()
    elif op_system.is_linux():
        input_devices = get_input_devices_linux()
    elif op_system.is_windows():
        input_devices = get_input_devices_windows()
    else:
        raise ValueError("Unknown OS")
    return input_devices


def _check_enabled(if_name):
    enabled = False
    output = Command(cmd="avbutil --virtual-audio list").run_join(10)["output"]
    for line in output:
        if if_name in line:
            enabled = True
            break
    return enabled


def enable_virtual_audio_macos(port):
    tries = 3

    if_name = ifconfig.get_conn_name(port)
    enabled = _check_enabled(if_name)
    if not enabled:
        for _ in xrange(tries):
            result = Command(cmd="avbutil --virtual-audio enable {}".format(if_name)).run_join(60)["returncode"]
            if result != 0:
                raise Exception("Failed to enable virtual-audion on interface {}".format(if_name))
            time.sleep(5)
            if _check_enabled(if_name):
                break


def enable_virtual_audio_windows(port):
    raise NotImplementedError


def enable_virtual_audio_linux(port):
    raise NotImplementedError


def enable_virtual_audio(port):
    if op_system.is_mac():
        enable_virtual_audio_macos(port)
    elif op_system.is_linux():
        enable_virtual_audio_linux(port)
    elif op_system.is_windows():
        enable_virtual_audio_windows(port)
    else:
        raise ValueError("Unknown OS")


def disable_virtual_audio_macos(port):
    enabled = False
    result = 0
    output = Command(cmd="avbutil --virtual-audio list").run_join(10)["output"]
    if_name = ifconfig.get_conn_name(port)
    for line in output:
        if if_name in line:
            enabled = True
            break
    if enabled:
        result = Command(cmd="avbutil --virtual-audio disable {}".format(if_name)).run_join(60)["returncode"]
    if result != 0:
        raise Exception("Failed to disable virtual-audion on interface {}".format(if_name))


def disable_virtual_audio_windows(port):
    raise NotImplementedError


def disable_virtual_audio_linux(port):
    raise NotImplementedError


def disable_virtual_audio(port):
    if op_system.is_mac():
        disable_virtual_audio_macos(port)
    elif op_system.is_linux():
        disable_virtual_audio_linux(port)
    elif op_system.is_windows():
        disable_virtual_audio_windows(port)
    else:
        raise ValueError("Unknown OS")


class VirtualAudio(object):
    __metaclass__ = ABCMeta

    def __new__(cls, **kwargs):
        host = kwargs.get("host", None)
        if host is None or host == "localhost":
            return object.__new__(VirtualAudioLocal)
        else:
            return object.__new__(VirtualAudioRemote)

    def __init__(self, **kwargs):
        self.port = kwargs["port"]

    @abstractmethod
    def enable_virtual_audio(self):
        pass

    @abstractmethod
    def disable_virtual_audio(self):
        pass

    @abstractmethod
    def get_avb_device_name(self):
        pass

    @abstractmethod
    def set_output_audio_device(self, device):
        pass

    @abstractmethod
    def set_input_audio_device(self, device):
        pass

    @abstractmethod
    def set_avb_device_config(self, config):
        pass

    @abstractmethod
    def set_clock_source(self, device, clock_cource):
        pass

    @abstractmethod
    def get_output_devices(self):
        pass

    @abstractmethod
    def get_input_devices(self):
        pass

    @abstractmethod
    def play_sine_to_sound_device(self, sound_device, duration, frequency=440, sample_rate=48000, channels=1):
        pass


class VirtualAudioLocal(VirtualAudio):
    def __init__(self, **kwargs):
        super(VirtualAudioLocal, self).__init__(**kwargs)

    def enable_virtual_audio(self):
        enable_virtual_audio(self.port)

    def disable_virtual_audio(self):
        disable_virtual_audio(self.port)

    def get_avb_device_name(self):
        return get_avb_device_name()

    def set_output_audio_device(self, device):
        set_output_audio_device(device)

    def set_input_audio_device(self, device):
        set_output_audio_device(device)

    def set_avb_device_config(self, config):
        set_avb_device_config(config)

    def set_clock_source(self, device, clock_cource):
        set_clock_source(device, clock_cource)

    def get_output_devices(self):
        return get_output_devices()

    def get_input_devices(self):
        return get_input_devices()

    def play_sine_to_sound_device(self, sound_device, duration, frequency=440, sample_rate=48000, channels=1):
        play_sine_to_sound_device(sound_device, duration, frequency, sample_rate, channels)


class VirtualAudioRemote(VirtualAudio):

    def __init__(self, **kwargs):
        super(VirtualAudioRemote, self).__init__(**kwargs)
        self.host = kwargs["host"]

    def remote_exec(self, cmd):
        res = Command(cmd=cmd, host=self.host).run()
        if res["returncode"] != 0 or res["reason"] != Command.REASON_OK:
            raise Exception("Failed to execute remote command")
        if not any(SCRIPT_STATUS_SUCCESS in line for line in res["output"]):
            log.error("Failed to execute command '{}' on host '{}'".format(cmd, self.host))
            raise Exception("Failed to perform remote virtual audio operation")
        return res["output"]

    def enable_virtual_audio(self):
        cmd = "cd {} && python virtual_audio.py -c enable -p {}".format(ATF_TOOLS_DIR, self.port)
        self.remote_exec(cmd)

    def disable_virtual_audio(self):
        cmd = "cd {} && python virtual_audio.py -c disable -p {}".format(ATF_TOOLS_DIR, self.port)
        self.remote_exec(cmd)

    def get_avb_device_name(self):
        avb_device_reg = re.compile("AVB device was found: '(.*)'")
        cmd = "cd {} && python virtual_audio.py -c get_device".format(ATF_TOOLS_DIR, self.port)
        stdout = self.remote_exec(cmd)
        for line in stdout:
            match = avb_device_reg.match(line)
            if match:
                return match.group(1)

    def set_output_audio_device(self, device):
        cmd = "cd {} && python virtual_audio.py -c set_output_device -d {}".format(ATF_TOOLS_DIR, device)
        self.remote_exec(cmd)

    def set_input_audio_device(self, device):
        cmd = "cd {} && python virtual_audio.py -c set_input_device -d {}".format(ATF_TOOLS_DIR, device)
        self.remote_exec(cmd)

    def set_avb_device_config(self, config):
        cmd = "cd {} && python virtual_audio.py -c set_config -conf {}".format(ATF_TOOLS_DIR, config)
        self.remote_exec(cmd)

    def set_clock_source(self, device, clock_cource):
        cmd = "cd {} && python virtual_audio.py -c set_clock_source -d {} -clock {}".format(
            ATF_TOOLS_DIR, device, clock_cource)
        self.remote_exec(cmd)

    def get_output_devices(self):
        cmd = "cd {} && python virtual_audio.py -c get_output_devices"
        stdout = self.remote_exec(cmd)
        for line in stdout:
            log.info(line)
            # not implemented

    def get_input_devices(self):
        cmd = "cd {} && python virtual_audio.py -c get_input_devices"
        stdout = self.remote_exec(cmd)
        for line in stdout:
            log.info(line)
            # not implemented

    def play_sine_to_sound_device(self, sound_device, duration, frequency=440, sample_rate=48000, channels=1):
        raise NotImplementedError


class VirtualAudioArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        log.error(SCRIPT_STATUS_FAILED)
        self.exit(2, "{}: error: {}\n".format(self.prog, message))


if __name__ == "__main__":
    parser = VirtualAudioArgumentParser()
    parser.add_argument("-c", "--command", help="Command to be performed",
                        choices=["enable",
                                 "disable",
                                 "get_device",
                                 "set_input_device",
                                 "set_output_device",
                                 "set_config",
                                 "set_clock_source",
                                 "get_input_devices",
                                 "get_output_devices",
                                 "play_sine"], type=str, required=True)
    parser.add_argument("-p", "--port", help="PCI port, i.e. pci0.00.0, ...", type=str, default=None)
    parser.add_argument("-d", "--device", help="Audio device", type=str, default=None)
    parser.add_argument("-conf", "--config", help="Stream config", type=int, default=1)
    parser.add_argument("-clock", "--clock_source", help="Clock source", type=str, default=1)
    parser.add_argument("-duration", "--duration", help="Sine signal duration", type=int)
    parser.add_argument("-fs", "--sample_rate", help="Sample rate", type=int, default=48000)
    parser.add_argument("-f", "--frequency", help="Sine frequency", type=int, default=440)
    parser.add_argument("-ch", "--channels", help="Number of channels", type=int, default=1)

    args = parser.parse_args()

    try:
        if args.command == "enable":
            enable_virtual_audio(args.port)
        elif args.command == "disable":
            disable_virtual_audio(args.port)
        elif args.command == "get_device":
            get_avb_device_name()
        elif args.command == "set_output_device":
            set_output_audio_device(args.device)
        elif args.command == "set_input_device":
            set_input_audio_device(args.device)
        elif args.command == "set_config":
            set_avb_device_config(args.config)
        elif args.command == "set_clock_source":
            set_clock_source(args.device, args.clock_source)
        elif args.command == "get_output_devices":
            get_output_devices()
        elif args.command == "get_input_devices":
            get_input_devices()
        elif args.command == "play_sine":
            play_sine_to_sound_device(
                args.device,
                args.duration,
                sample_rate=args.sample_rate,
                frequency=args.frequency,
                channels=args.channels
            )
    except Exception as exc:
        traceback.print_exc(limit=10, file=sys.stderr)
        log.exception(SCRIPT_STATUS_FAILED)
        exit(1)

    log.info(SCRIPT_STATUS_SUCCESS)
