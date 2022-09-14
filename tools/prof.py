import time

from tools.utils import get_atf_logger

log = get_atf_logger()


def timing(f):
    def wrap(*args, **kw):
        ts = time.clock()
        result = f(*args, **kw)
        te = time.clock()
        log.info('PROFILING: >>>>> func: {}     took: {:8.1f} ms'.format(f.__name__, (te - ts) * 1000.0))
        return result

    return wrap


class prof:
    def __init__(self, msg):
        self.msg = msg

    def __enter__(self):
        self.ts = time.clock()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        te = time.clock()
        log.info('PROFILING: {}  took: {:8.1f} ms'.format(self.msg, (te - self.ts) * 1000.0))
