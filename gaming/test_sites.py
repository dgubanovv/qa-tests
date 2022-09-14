import glob
import os
import sys
import time
import socket

import numpy
import pytest

from aq_gaming_base import AqGamingBase
from browsers import InternetExplorer, Chrome, Firefox, Opera, Edge
from msi_installer import MsiInstaller
from infra.test_base import idparametrize, TestBase
from tools.command import Command
from tools.killer import Killer
from tools.log import get_atf_logger

if __package__ is None:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

log = get_atf_logger()


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    # os.environ["SESSION_ID"] = "36923"  # Define if virtual network is already running on LKP
    os.environ["TEST"] = "gaming"


class TestSites(AqGamingBase):
    """
    @description: TestSites is dedicated to verify AQ Control Center gaming app operation on motherboard integrated NIC
    and to check it can detect and prioritize traffic for required sites (youtube, vimeo and etc).

    @setup: Any Windows machine with third-party NIC with installed driver connected to external network.
    """
    browsers = {"Chrome": Chrome,
                "Firefox": Firefox,
                "Opera": Opera,
                "Edge": Edge,
                "InternetExplorer": InternetExplorer}

    url = {"youtube": "https://www.youtube.com/watch?v=Bey4XXJAqS8&vq=hd1440",
           "twitch": "https://www.twitch.tv/videos/343874671?quality=source",
           "vimeo": "https://player.vimeo.com/video/47015825?muted=1&quality=1080p&autoplay=1#t=1m2s",
           "netflix": "https://www.netflix.com/ru/title/80115346",
           "primevideo": "https://www.primevideo.com/detail/Tom-Clancy-s-Jack-Ryan/0IMOE9I1H3BN74ON17M9XGZFPG",
           "download": "http://releases.ubuntu.com/18.04.1/ubuntu-18.04.1-desktop-amd64.iso"
                       "?_ga=2.204564691.256785567.1545118907-1084970793.1544694695"}

    @classmethod
    def setup_class(cls):
        cls.MANUAL_SESSION_ID = int(os.environ.get("SESSION_ID", 0))
        cls.log_server = os.environ.get("LOG_SERVER", None)
        cls.log_path = os.environ.get("LOG_PATH", None)
        cls.job_id = os.environ.get("JOB_ID", None)
        cls.platform = os.environ.get("PLATFORM", None)
        cls.test = os.environ.get("TEST", "")
        cls.log_server_dir = cls.create_logs_dir_on_log_server()

        cls.dut_hostname = os.environ.get("DUT_HOSTNAME", socket.gethostname())
        cls.dut_port = os.environ.get("DUT_PORT", None)
        cls.dut_drv_version = os.environ.get("DUT_DRV_VERSION", None)
        cls.dut_gaming_build = os.environ.get("GAMING_BUILD", None)

        if cls.dut_gaming_build is None:
            raise Exception("DUT gaming build must be specified to run this test")

        cls.working_dir = os.environ.get("WORKING_DIR", None)
        TestBase.log_server = os.environ.get("LOG_SERVER", None)
        TestBase.log_local_dir = cls.working_dir
        TestBase.log_server_dir = None

        cls.download_package()
        cls.aqgaming_remove()
        cls.dut_msi_installer = MsiInstaller(cls.MSI_PATH)
        cls.dut_msi_installer.install()
        cls.cleanup_windows()
        cls.import_aqgaming()

        cls.aqgaming_setup_adapter()

    @classmethod
    def aqgaming_setup_adapter(cls):
        """
        Get Network Adapter name and pass it to AQGaming service.
        """
        res = Command(
            cmd="powershell \"Get-NetAdapter -Name \"Ethernet\" | Format-List -Property InterfaceDescription\"").run()
        adapter = filter(None, res["output"])[0].split(":")[1].strip()

        res = Command(cmd="sc config {} binPath=\"{} --adapter=\\\"{}\\\"\""
                      .format(cls.AQGAMING_SERVICE, cls.AQGAMING_SERVICE_BIN_PATH, adapter)).run()
        assert res["returncode"] == 0

    def teardown_method(self, method):
        super(AqGamingBase, self).teardown_method(method)
        log.info("#" * 80)
        log.info("Current latest service log file: {}".format(max(glob.glob(self.AQGAMING_SERVICE_LOGS_PATH))))
        log.info("#" * 80)

        for browser in ["chrome", "firefox", "opera", "browser", "MicrosoftEdge", "iexplore"]:
            Killer().kill(browser)

        Command(cmd="powershell \"del C:\\Users\\aqtest\\Downloads\\* -include *.crdownload\"").run()

    def startup_browser(self, browser, site_url):
        browser.kill()

        self.aqgaming_clientRegister()
        self.aqgaming_activate()
        self.aqgaming_set_shaper_settings(dn_mbit=10, up_mbit=50)

        browser.run(url=site_url)

        try:
            self.aqgaming_idle(10)
        except Exception as e:
            browser.kill()
            raise e

    def measure_dn_rate(self, get_func, name, seconds=15):
        self.aqgaming.setVerbose(0)
        dn_rate = []
        for i in range(seconds):
            self.aqgaming.kickLib()
            dn_rate.append(get_func(name)["dnRate"])
            time.sleep(1)

        result = numpy.average(dn_rate)
        log.info("{} dn rate is {}".format(name, result))
        self.aqgaming.setVerbose(1)
        return result

    def parallel_measure(self, object_list, seconds=60):
        self.aqgaming.setVerbose(0)
        dn_rate = {}
        for _ in range(seconds):
            self.aqgaming.kickLib()
            for app, get_dn_rate in object_list:
                value = get_dn_rate(app)["dnRate"]
                if app in dn_rate.keys():
                    dn_rate[app].append(get_dn_rate(app)["dnRate"])
                else:
                    dn_rate[app] = [value]
            time.sleep(1)

        for app in dn_rate:
            dn_rate[app] = numpy.average(dn_rate[app])
            log.info("{} dn rate is {}".format(app, dn_rate[app]))
        self.aqgaming.setVerbose(1)
        return dn_rate

    @idparametrize("site_name", ["youtube", "twitch", "vimeo", "netflix", "primevideo"])
    @idparametrize("browser_name", ["InternetExplorer", "Chrome", "Edge", "Firefox", "Opera"])
    def test_sites_detected(self, site_name, browser_name):
        """
        @description: Verify that AQGaming detects required sites in supported browsers.

        @steps:
        1. Open AQGaming client.
        2. Turn on AQGaming client.
        3. Set shaper settings to DN 10 / UP 50 Mbit/s.
        4. Run <browser> with <site>.
        5. Make sure AQGaming detects site.
        6. Close browser.
        7. Make sure AQGaming client does not report any sites.

        @result: AQGaming should correctly detect all supported sites.
        @duration: 1 minute (for each set of parameters).
        """
        browser = self.browsers[browser_name]()
        self.startup_browser(browser, self.url[site_name])

        # we can already kill it - aqcc will still report sites until you do kickLib()
        browser.kill()

        ids = self.aqgaming.getSiteIds()
        assert len(ids) == 1, "Found {} sites instead of 1".format(len(ids))

        site = self.aqgaming.getSiteById(ids[0])
        log.info(site)
        assert site["siteName"] == site_name, "Browser reported site with not expected name"

        self.aqgaming_idle(5)
        assert len(self.aqgaming.getSiteIds()) == 0, "Browser is closed, but AQCC still sees {}".format(site_name)

    @idparametrize("site_name", ["youtube"])
    @idparametrize("browser_name", ["Chrome"])
    def test_change_priority(self, site_name, browser_name):
        """
        @description: Verify that AQGaming keeps selected priority for site.

        @steps:
        1. Open AQGaming client.
        2. Turn on AQGaming client.
        3. Set shaper settings to DN 10 / UP 50 Mbit/s.
        4. Run <browser> with <site>.
        5. Change site priority to Critical.
        6. Sleep for 5 seconds.
        7. Make sure AQGaming client keeps Critical priority for site.
        8. Change site priority to Low.
        9. Wait for 5 seconds and make sure site has Low priority.

        @result: AQGaming should keep site priority.
        @duration: 1 minute (for each set of parameters).
        """
        def assert_priority_changes(site_name, required_priority, sleep=5):
            self.aqgaming_set_site_priority_by_name(site_name, required_priority)
            self.aqgaming_idle(sleep)
            actual_priority = self.aqgaming_get_site_priority_by_name(site_name)
            assert actual_priority == required_priority, \
                "Actual priority: {} != Expected priority: {}".format(actual_priority, required_priority)

        browser = self.browsers[browser_name]()
        self.startup_browser(browser, self.url[site_name])

        assert_priority_changes(site_name, self.aqgaming.PRIORITY_CRITICAL)
        assert_priority_changes(site_name, self.aqgaming.PRIORITY_LOW)

    @idparametrize("attempt", [1, 2, 3, 4, 5])
    def test_site_catches_highest_priority(self, attempt):
        """
        @description: Verify that AQGaming chooses site priority as highest from site and browser priorities.

        @steps:
        1. Open AQGaming client.
        2. Turn on AQGaming client.
        3. Set shaper settings to DN 10 / UP 50 Mbit/s.
        4. Run <site_browser> with <site> and <download_browser> with download.
        5. Set site_browser and site priorities to Low.
        6. Set download_browser priority to High.
        8. Make sure download_browser consumes more bandwidth that site_browser.
        9. Change SITE priority to Critical.
        10. Make sure site_browser consumes more bandwidth that download_browser.
        11. Change SITE priority to Low.
        12. Make sure download_browser consumes more bandwidth that site_browser.
        13. Change SITE_BROWSER priority to Critical.
        14. Make sure site_browser consumes more bandwidth that download_browser.

        @result: AQGaming should select highest priority for site from site and browser priorities.
        @duration: 4 minutes (for each set of parameters).
        """
        site = "vimeo"
        site_browser = InternetExplorer()
        self.startup_browser(site_browser, self.url[site])

        download_browser = Chrome()
        download_browser.run(self.url["download"])

        idle_time = 20

        self.aqgaming_set_shaper_settings(dn_mbit=10, up_mbit=50)
        self.aqgaming_idle(idle_time)

        self.aqgaming_set_site_priority_by_name(site, self.aqgaming.PRIORITY_LOW)
        self.aqgaming_set_app_priority_by_name(site_browser.name, self.aqgaming.PRIORITY_LOW)
        self.aqgaming_set_app_priority_by_name(download_browser.name, self.aqgaming.PRIORITY_HIGH)
        self.aqgaming_idle(idle_time)

        apps_to_measure = [(site_browser.name, self.aqgaming_get_app_by_name),
                           (download_browser.name, self.aqgaming_get_app_by_name)]

        dn_rate = self.parallel_measure(apps_to_measure)
        assert dn_rate[download_browser.name] > dn_rate[site_browser.name] * self.BANDWIDTH_PRIORITY_RATIO, \
            "Download browser has higher priority, but its DN Rate is too low"

        self.aqgaming_set_site_priority_by_name(site, self.aqgaming.PRIORITY_CRITICAL)
        self.aqgaming_idle(idle_time)
        dn_rate = self.parallel_measure(apps_to_measure)
        assert dn_rate[site_browser.name] > dn_rate[download_browser.name] * self.BANDWIDTH_PRIORITY_RATIO, \
            "Site was moved to critical priority, but its DN Rate is too low"

        self.aqgaming_set_site_priority_by_name(site, self.aqgaming.PRIORITY_LOW)
        self.aqgaming_idle(idle_time)
        dn_rate = self.parallel_measure(apps_to_measure)
        assert dn_rate[download_browser.name] > dn_rate[site_browser.name] * self.BANDWIDTH_PRIORITY_RATIO, \
            "Site was moved to Low priority, but its DN Rate is still to high"

        self.aqgaming_set_app_priority_by_name(site_browser.name, self.aqgaming.PRIORITY_CRITICAL)
        self.aqgaming_idle(idle_time)
        dn_rate = self.parallel_measure(apps_to_measure)
        assert dn_rate[site_browser.name] > dn_rate[download_browser.name] * self.BANDWIDTH_PRIORITY_RATIO, \
            "Site Browser was moved to Critical priority, but its DN Rate is too low"

    def test_site_vs_download(self):
        """
        @description: Verify that AQGaming can prioritize download and site running in the same browser.

        @steps:
        1. Open AQGaming client.
        2. Turn on AQGaming client.
        3. Set shaper settings to DN 10 / UP 50 Mbit/s.
        4. Run <browser> with <site> and with <download>.
        5. Change Site priority to Low.
        6. Change Browser priority to High.
        7. This means that site and download are both in High priority.
        8. Make sure site DN Rate is ~50% of browser DN Rate.
        9. Change site priority to High and browser priority to Low.
        10. Make sure Site consumes almost full bandwidth.

        @result: AQGaming should correctly prioritize traffic in the same browser.
        @duration: 1 minute (for each set of parameters).
        """
        site = "vimeo"
        browser = Chrome()
        self.startup_browser(browser, '{}" "{}'.format(self.url[site], self.url["download"]))

        dn_shaper = 5
        self.aqgaming_set_shaper_settings(dn_mbit=dn_shaper, up_mbit=50)
        self.aqgaming_idle(10)

        self.aqgaming_set_site_priority_by_name(site, self.aqgaming.PRIORITY_LOW)
        self.aqgaming_set_app_priority_by_name(browser.name, self.aqgaming.PRIORITY_HIGH)
        self.aqgaming_idle(10)
        site_dn_rate = self.measure_dn_rate(self.aqgaming_get_site_by_name, site)
        browser_dn_rate = self.measure_dn_rate(self.aqgaming_get_app_by_name, browser.name)
        assert site_dn_rate < browser_dn_rate * 0.7, "Site and Download DN Rates should be almost equal"
        assert site_dn_rate > 0, "Site DN Rate should not drop to zero"

        self.aqgaming_set_site_priority_by_name(site, self.aqgaming.PRIORITY_HIGH)
        self.aqgaming_set_app_priority_by_name(browser.name, self.aqgaming.PRIORITY_LOW)
        self.aqgaming_idle(10)
        site_dn_rate = self.measure_dn_rate(self.aqgaming_get_site_by_name, site)
        browser_dn_rate = self.measure_dn_rate(self.aqgaming_get_app_by_name, browser.name)
        assert site_dn_rate > browser_dn_rate * 0.7, \
            "Site should consume almost full bandwidth, because it has Higher priority"

        assert browser_dn_rate < dn_shaper * 1000, "Browser DN rate exceeded shaper values"

    @idparametrize("site_name", ["vimeo", "youtube"])
    def test_site_duplication(self, site_name):
        """
        @description: Verify that AQGaming can handle the same site running in different browsers in parallel.

        @steps:
        1. Open AQGaming client.
        2. Turn on AQGaming client.
        3. Set shaper settings to DN 10 / UP 50 Mbit/s.
        4. Run <browser_1> with <site> and <browser_2> with the same site.
        5. Make sure AQGaming client reports only one site.
        6. Measure DN Rates for Site and both Browsers.
        7. Make sure Site DN Rate is the sum of browsers DN Rates.
        8. Make sure site DN Rate does not exceed shaper values.

        @result: AQGaming should correctly report traffic for site running in two browsers in parallel.
        @duration: 1 minute (for each set of parameters).
        """
        first_browser = Chrome()
        second_browser = InternetExplorer()
        self.startup_browser(first_browser, self.url[site_name])
        second_browser.run(self.url[site_name])

        dn_shaper = 5
        self.aqgaming_set_shaper_settings(dn_mbit=dn_shaper, up_mbit=50)
        self.aqgaming_idle(10)

        count = 0
        ids = self.aqgaming.getSiteIds()
        for id in ids:
            site = self.aqgaming.getSiteById(id)
            if site_name.lower() in site["siteName"].lower():
                count += 1
        assert count == 1, "Found {} sites instead of 1".format(count)

        site_dn_rate = self.measure_dn_rate(self.aqgaming_get_site_by_name, site_name)
        first_browser_dn_rate = self.measure_dn_rate(self.aqgaming_get_app_by_name, first_browser.name)
        second_browser_dn_rate = self.measure_dn_rate(self.aqgaming_get_app_by_name, second_browser.name)

        assert site_dn_rate > (first_browser_dn_rate + second_browser_dn_rate) * 0.8, \
            "Site DN Rate should be equal to sum of browsers DN Rates"
        assert site_dn_rate < dn_shaper * 1000, "Site DN Rate should not exceed shaper values"


if __name__ == "__main__":
    pytest.main([__file__, "-s", "-v"])
