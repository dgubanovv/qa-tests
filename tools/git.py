import command

from utils import get_atf_logger

log = get_atf_logger()

TEST_REPO_URL = "git@gitlab.rdc-lab.marvell.com:qa/qa-tests.git"


def clone(test_tool, host):
    log.info("Cloning branch {} of qa-tests repository on host {}".format(test_tool, host))
    cmd = "sudo rm -rf qa-tests && "
    cmd += "git clone --branch {} {}".format(test_tool, TEST_REPO_URL)
    res = command.Command(cmd=cmd, host=host).run()
    if res["returncode"] != 0:
        log.debug("GIT OUTPUT:")
        log.debug("".join(res["output"]))
        raise Exception("Couldn't clone branch {} of qa-tests repository on host".format(test_tool, host))
