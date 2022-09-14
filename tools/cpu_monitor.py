import threading
import time
import timeit
import psutil
import numpy

from tools.utils import get_atf_logger

log = get_atf_logger()


class CPUMonitor:

    def __init__(self, timeout=30, pid=None, interval=1.0):
        self.timeout = timeout
        self.pid = pid
        self.interval = interval

    def get_metric(self):
        max_u = numpy.amax(self.cpu_usages)
        min_u = numpy.amin(self.cpu_usages)
        avg_u = numpy.average(self.cpu_usages)
        return "CPU Load", "%", min_u, max_u, avg_u, len(self.cpu_usages)

    def report(self):
        if len(self.cpu_usages) > 0:
            max_u = numpy.amax(self.cpu_usages)
            min_u = numpy.amin(self.cpu_usages)
            mean_u = numpy.mean(self.cpu_usages)
            std_u = numpy.std(self.cpu_usages)

            p50 = numpy.quantile(self.cpu_usages, 0.50)
            p70 = numpy.quantile(self.cpu_usages, 0.70)
            p85 = numpy.quantile(self.cpu_usages, 0.85)
            p95 = numpy.quantile(self.cpu_usages, 0.95)

            msg = ''
            msg += "\n+ REPORT: ------------------------------------------------------------- +"
            msg += "\n|  interval: {:.3f} sec".format(self.interval)
            msg += "\n|   timeout: {} sec".format(self.timeout)
            msg += "\n|       pid: {}".format(self.pid)
            msg += "\n+ --------------------------------------------------------------------- +"
            msg += "\n| CPU: min = {:5.1f}%,    max = {:5.1f}%,    mean = {:5.1f}%,    std = {:5.1f}  |".format(min_u, max_u, mean_u, std_u)
            msg += "\n| CPU: p50 = {:5.1f}%,    p70 = {:5.1f}%,     p85 = {:5.1f}%,    p95 = {:5.1f}% |".format(p50, p70, p85, p95)
            msg += "\n+ --------------------------------------------------------------------- +"
            msg += "\n| CPU: {} %".format([int(p) for p in self.cpu_usages])
            msg += "\n+ --------------------------------------------------------------------- +\n"

            return msg

    def _worker(self):
        try:
            ps = psutil.Process(self.pid) if self.pid else psutil

            self.cpu_usages = []
            start_time = timeit.default_timer()

            exec_time = timeit.default_timer() - start_time
            while exec_time < self.timeout:
                tmp_usages = []
                for i in range(int(1.0 / self.interval)):
                    tmp_usages.append(ps.cpu_percent(interval=None))
                    time.sleep(self.interval)

                cpu_usage = sum(tmp_usages) / len(tmp_usages)
                self.cpu_usages.append(cpu_usage)

                exec_time = timeit.default_timer() - start_time

        except Exception as e:
            log.info('Exception: {}'.format(e))

    def run_async(self):
        self.thread = threading.Thread(target=self._worker)
        self.thread.daemon = True
        self.thread.start()

    def join(self, timeout=None):
        timeout = timeout if timeout > 0 else self.timeout
        self.thread.join(timeout)
        return self.cpu_usages

    def run_join(self, timeout):
        self.run_async()
        return self.join()
