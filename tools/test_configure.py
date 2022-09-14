import os
import pytest

from tools.constants import LINK_SPEED_AUTO
from tools.utils import get_atf_logger

log = get_atf_logger()


def auto_configure(func):
    def wrap(*args, **kwargs):
        speed = kwargs.get('speed', None)
        supported_speeds = os.environ.get("SUPPORTED_SPEEDS").split(',')

        if speed is not None:
            if speed not in supported_speeds:
                pytest.skip("unsupported speed")

        return func(*args, **kwargs)

    return wrap


def auto_configure_link_speed(func):
    def wrap(*args, **kwargs):
        log.info('    INPUT PARAMS: {}'.format(kwargs))

        speed = kwargs.get('speed', LINK_SPEED_AUTO)

        supported_speeds = os.environ.get("SUPPORTED_SPEEDS", "100M,1G").split(',')

        log.info('           SPEED: {}'.format(speed))
        log.info('SUPPORTED_SPEEDS: {}'.format(supported_speeds))

        is_continue = False if len(speed) <= 0 else True
        is_continue = is_continue and (True if speed in supported_speeds else False)
        if speed == LINK_SPEED_AUTO and len(supported_speeds) > 0:
            is_continue = True

        result = None
        if is_continue:
            result = func(*args, **kwargs)
        else:
            pytest.skip()
        return result

    return wrap
