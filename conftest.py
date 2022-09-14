import os
import re
import time

import logging
import logging.handlers

import pytest
from _pytest import runner
from _pytest.terminal import TerminalReporter
from py._io.terminalwriter import TerminalWriter

from infra.test_base import TestBase
from tools.communicate import send_test_result
from tools.utils import upload_directory, remove_directory, get_atf_logger, normalize_as_file_name


log = get_atf_logger()


# copied from MBU for now (TODO: can be re-used when MBU has become true pythonic library)
class tagFilter(logging.Filter):

    """This is a filter which pass or drop records according user settings"""

    def __init__(self, filterString, *args, **kwargs):
        super(tagFilter, self).__init__(*args, **kwargs)
        self.reject = []
        self.passed = []
        self.passAll = False

        for tag in filterString.split(','):
            if '-' in tag:
                self.reject.append(tag.strip('- '))
            elif '+' in tag:
                self.passed.append(tag.strip('+ '))
            elif tag.strip() == 'all':
                self.passAll = True
            else:
                #There is unrecognized filters
                pass

    def filter(self, record):
        allowed = self.passAll

        try:
            tags = record.tag
        except:
            tags = record.name
            # Prevent the default formatter from choking on messages emitted by child loggers and not containing the tag
            record.tag = tags

        if tags in self.passed:
            allowed = True
        elif tags in self.reject:
            allowed = False
        return allowed
# End class tagFilter


def get_test_name(item):
    test_name = item.getmodpath().replace("Test", "")
    if ".test_mbu_" in test_name:
        test_name = test_name.replace(".test_mbu_", ".")
    else:
        test_name = test_name.replace(".test_", ".")
    test_name = test_name.lstrip(".")
    if hasattr(item, "callspec"):
        base_name_re = re.compile("(.*)\[.*\]", re.DOTALL)
        test_name = base_name_re.match(test_name).group(1)
        test_name += "[" + ", ".join(["{}={}".format(k, v) for k, v in item.callspec.params.items()]) + "]"
    return test_name


def upload_test_logs(server, local_dir, remote_dir):
    if not all([server, local_dir, remote_dir]):
        return

    try:
        upload_directory(server, local_dir, remote_dir)
    except Exception as e:
        log.exception(e)


def pytest_addoption(parser):
    group = parser.getgroup("terminal reporting", "reporting", after="general")
    group._addoption("--noinstafail", action="store_true", dest="noinstafail", default=False,
                     help=("Do not show failures and errors instantly as they occur."))


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    if hasattr(config, 'slaveinput'):
        return  # xdist slave, we are already active on the master
    if not config.option.noinstafail:
        standard_reporter = config.pluginmanager.getplugin('terminalreporter')
        instafail_reporter = InstafailingTerminalReporter(standard_reporter)

        config.pluginmanager.unregister(standard_reporter)
        config.pluginmanager.register(instafail_reporter, 'terminalreporter')


class LoggingTerminalWriter(TerminalWriter):
    def line(self, s='', **kw):
        if s:
            log.info(s)


class InstafailingTerminalReporter(TerminalReporter):
    def __init__(self, reporter):
        TerminalReporter.__init__(self, reporter.config)
        self._tw = self.writer = LoggingTerminalWriter()

    def _locationline(self, nodeid, fspath, lineno, domain):
        if fspath:
            res = nodeid
        else:
            res = "[location]"
        return res + " - "

    def pytest_collectreport(self, report):
        TerminalReporter.pytest_collectreport(self, report)
        if report.failed:
            if self.isatty:
                self.rewrite('')  # erase the "collecting"/"collected" message
            self.print_failure(report)

    def pytest_runtest_logreport(self, report):
        TerminalReporter.pytest_runtest_logreport(self, report)
        if not hasattr(report, 'node'):
            self.writer.write("\n")

        if report.failed and not hasattr(report, "wasxfail"):
            if self.verbosity <= 0:
                self._tw.line()
            self.print_failure(report)

    def summary_failures(self):
        pass

    def summary_errors(self):
        pass

    def print_failure(self, report):
        if self.config.option.tbstyle != "no":
            if self.config.option.tbstyle == "line":
                line = self._getcrashline(report)
                self.write_line(line)
            else:
                msg = report.nodeid
                if not hasattr(report, 'when'):
                    msg = "ERROR collecting " + msg
                elif report.when == "setup":
                    msg = "ERROR at setup of " + msg
                elif report.when == "teardown":
                    msg = "ERROR at teardown of " + msg
                self.write_sep("_", msg)
                if not self.config.getvalue("usepdb"):
                    self._outrep_summary(report)


def pytest_runtest_protocol(item, nextitem):
    if "test_mbu" in item.name:
        mbu_test = os.environ.get("TEST", None)
        if mbu_test is not None:
            if mbu_test not in item.name:
                item.add_marker("skip")
        else:
            raise Exception("MBU test name was not provided")

    test_name = get_test_name(item)
    test_name_norm = normalize_as_file_name(test_name)

    TestBase.state.current_test = test_name
    TestBase.state.current_test_norm = test_name_norm
    reports = runner.runtestprotocol(item, nextitem=nextitem)

    for report in reports:
        if report.when == 'setup':
            setup_outcome = report.outcome
        if report.when == 'call':
            call_outcome = report.outcome
            xfail = getattr(report, 'wasxfail', None)
            if xfail is not None:
                if call_outcome == "skipped":
                    call_outcome = "xfailed"
                else:
                    call_outcome = "failed"

    if setup_outcome == "skipped":
        return True

    if setup_outcome == "failed":
        test_result = TestBase.RESULT_FAILED
    else:
        if call_outcome == "skipped":
            test_result = TestBase.RESULT_SKIPPED
        elif call_outcome == "passed":
            test_result = TestBase.RESULT_PASSED
        elif call_outcome == "xfailed":
            test_result = TestBase.RESULT_XFAIL
        else:
            test_result = TestBase.RESULT_FAILED

    # Upload test directory to the server
    test_class_obj = item.parent.obj
    remote_file_path = "no_logs"

    if all([test_class_obj.log_local_dir, test_class_obj.log_server]):
        if test_class_obj.log_local_dir and os.path.exists(test_class_obj.log_local_dir) \
                and test_class_obj.log_local_dir != TestBase.log_local_dir:
            # TODO: is this possible? test_class_obj.log_local_dir != TestBase.log_local_dir
            upload_test_logs(TestBase.log_server, test_class_obj.log_local_dir, test_class_obj.log_server_dir)

        local_path = os.path.join(TestBase.log_local_dir, test_name_norm)
        if os.path.exists(local_path):
            upload_test_logs(test_class_obj.log_server, local_path, test_class_obj.log_server_dir)
            local_dir_name = os.path.basename(local_path)
            if os.path.exists(os.path.join(local_path, 'output.log')):
                remote_file_path = os.path.join(test_class_obj.log_server_dir,
                                                local_dir_name, 'output.log').replace("\\", "/")
            remove_directory(local_path)  # Remove local directory immediatelly to keep empty space

    if remote_file_path == "no_logs":
        log.warning("Test '{}' has no logs".format(test_name))

    # Send test result to the server
    send_test_result(os.environ.get("SUBTEST_STATUS_API_URL", None), test_name, test_result, remote_file_path,
                     test_class_obj.log_server_dir)

    # Update test state
    TestBase.state.tests[test_name] = test_result
    TestBase.state.update()

    return True


def pytest_runtest_setup(item):
    print ""


def pytest_runtest_logreport(report):
    from tools.command import Command

    mbu_logger = logging.getLogger("Mac BringUP")
    if report.outcome != "skipped":
        print ""
    if report.when == "call":
        for handler in mbu_logger.handlers[:]:
            if type(handler) == logging.handlers.MemoryHandler:
                handler.flush()
                handler.close()
                mbu_logger.removeHandler(handler)

        log.info("{:#<80}".format(""))
        log.info("{:#<80}".format("ENDING TEST {} - {} ".format(report.nodeid, report.outcome.upper())))
        log.info("{:#<80}".format("DURATION = {} seconds ".format(report.duration)))
        log.info("{:#<80}\n".format(""))

        for handler in log.handlers[:]:
            if type(handler) == logging.handlers.MemoryHandler:
                handler.flush()
                handler.close()
                log.removeHandler(handler)

    elif report.when == "setup":
        if report.outcome != "skipped":
            # TODO: actually log_local_dir is needed not from TestBase, but from TestClass
            log_subtest_dir = os.path.join(TestBase.log_local_dir, normalize_as_file_name(report.nodeid))
            if not os.path.exists(log_subtest_dir):
                Command(cmd='mkdir "{}"'.format(log_subtest_dir)).run()

            fh = logging.FileHandler(os.path.join(log_subtest_dir, 'output.log'), mode="a")
            fh.setLevel(logging.DEBUG)
            frmt = logging.Formatter("%(asctime)s - %(levelname)7s - %(module)15s:%(lineno)-4d - %(message)s")
            fh.setFormatter(frmt)
            mh = logging.handlers.MemoryHandler(capacity=10, target=fh)  # capacity is the count of the log records
            mh.setLevel(logging.DEBUG)
            log.addHandler(mh)

            log.info("{:#<78}".format(""))
            log.info("{:#<78}".format("STARTING TEST {} ".format(report.nodeid)))
            log.info("{:#<78}\n".format(""))
            mh.flush()

            mbu_mem_handler = logging.handlers.MemoryHandler(capacity=1, target=fh)  # capacity is the count of the log records
            mbu_mem_handler.setLevel(logging.DEBUG)

            # add the same filter as "allow_console" from logging_with_mbu.conf
            mbu_mem_handler.addFilter(tagFilter('+cli,+base,+reg,+log,+tx,+rx,+upctrl'))
            mbu_logger.addHandler(mbu_mem_handler)


def pytest_runtest_makereport(item, call):
    # Replace test id in report with test name
    report = runner.pytest_runtest_makereport(item, call)
    report.nodeid = get_test_name(item)
    if len(report.nodeid) > 128:
        report.outcome = 'failed'
        log.exception('Too big len of name, should be less 128')
    return report


def pytest_collection_modifyitems(session, config, items):
    TestBase.state.load()
    already_executed_tests = TestBase.state.tests
    if len(already_executed_tests.keys()) > 0:
        log.info("Skipping already executed tests:")
    for item in items:
        test_name = get_test_name(item)
        if test_name in already_executed_tests.keys():
            log.info("{} - {}".format(test_name, already_executed_tests[test_name]))
            item.add_marker("skip")


def pytest_unconfigure(config):
    TestBase.state.erase()
    time.sleep(5)


def pytest_terminal_summary(terminalreporter, exitstatus):
    log.info("{:#<80}".format(""))
    log.info("{:#<80}".format("OVERALL TEST RESULT "))
    log.info("{:#<80}\n".format(""))

    if len(TestBase.state.tests.keys()) == 0:
        log.info("NO TEST RAN!!!")
        return

    max_len = max(len(name) for name in TestBase.state.tests.keys())
    max_len += 5
    for name, res in TestBase.state.tests.items():
        log.info("{test:{width}s} {res}".format(test=name, width=max_len, res=res.upper()))

    if TestBase.state.test_cleanup_cold_restart is True:
        log.info("Doing cold reboot for cleanup")
        log.info("Sleeping 10 seconds before cold reboot")
        time.sleep(10)  # sleep to let all logs be send to the server
        TestBase.state.test_cleanup_cold_restart = False
        TestBase.state.update()
        TestBase.cold_restart()
