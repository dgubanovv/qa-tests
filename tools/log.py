import logging
import logging.config
import os
import yaml


def get_log_level():
    level_log = os.environ.get('LOG_LEVEL', 'NONE')

    if level_log == 'DEBUG':
        return logging.DEBUG
    elif level_log == 'INFO':
        return logging.INFO
    elif level_log == 'WARNING':
        return logging.WARNING
    elif level_log == 'ERROR':
        return logging.ERROR
    elif level_log == 'NOTSET':
        return logging.NOTSET
    elif level_log == 'CRITICAL':
        return logging.CRITICAL
    return None


def get_atf_logger():
    log = logging.getLogger("atf")

    if len(log.handlers) == 0:
        fdir = os.path.dirname(os.path.abspath(__file__))
        log_cfg_file = os.path.join(fdir, "logging.conf")
        with open(log_cfg_file, "r") as f:
            log_cfg_data = yaml.load(f)
        logging.config.dictConfig(log_cfg_data)

    level = get_log_level()
    if level is not None:
        log.setLevel(level)

    return log
