import os

from infra.test_base import TestBase


def setup_module(module):
    # import tools._test_setup  # uncomment for manual test setup
    os.environ["TEST"] = "multinic"


class TestMultinic(TestBase):

    """@description: The multinic test is dedicated to verify functionality of several network cards (or other devices
    like USB) connected to the same DUT.

    At this moment maximum 2 network devices can be tested. These devices can be manufactured by different vendors,
    but usually they are Aquantia devices (Lil Nikki, Felicity, Bermuda or Fiji). The test suite performs different
    kind of high-level tests: power management, sleep-wake, offloads, iperf and so on.

    @setup: 2 Aquantia devices on DUT connected back-to-back to 2 Aquantia devices on LKP
    """

    def test_one_driver_different_firmwares(self):
        """
        @description: This subtest burns different versions of firmware to devices, then installs one driver.
        After that it verifies that ping works well on both devices.

        @steps:
        1. Install different firmwares on DUT.
        2. Install driver on DUT.
        3. Configure IPv4 addresses on DUT and LKP.
        4. Send ping from DUT to LKP via both devices.

        @result: No ping loss.
        @duration: 8 minutes.
        """
        pass

    def test_one_firmware_different_drivers(self):
        """
        @description: This subtest burns the same version of firmware to both devices on DUT, then installs different
        driver versions to devices. After that it verifies that ping works well on both devices.

        @steps:
        1. Install the same firmware to both devices on DUT.
        2. Install different drivers to devices on DUT.
        3. Configure IPv4 addresses on DUT and LKP.
        4. Send ping from DUT to LKP via both devices.

        @result: No ping loss.
        @duration: 8 minutes.
        """
        pass

    def test_iperf_in_stack_tcp(self):
        """
        @description: The In-Stack iperf subtest runs iPerf server and client on the same machine to send TCP traffic
        over OS stack.

        @steps:
        1. Install the same firmwares on both devices on DUT.
        2. Install the same driver on both devices on DUT.
        3. Set IPv4 addresses on both devices in the same subnetwork.
        4. Create iPerf server and client.
        5. Run TCP traffic for 1 minute.
        6. Check iPerf statistics.

        @result: No traffic loss.
        @duration: 10 minutes.
        """
        pass

    def test_iperf_bridge_tcp(self):
        """
        @description: The test incapsulates both devices on DUT into bridge and sends traffic over it.

        @steps:
        1. Install firmware on both devices on DUT.
        2. Install driver on both devices on DUT.
        3. Bridge interfaces on DUT
        4. Create iPerf server on LKP and bind it to the first device.
        5. Create iPerf client on LKP and bind it to the second device.
        6. Start traffic that goes through the bridge on DUT.
        5. Wait 2 minutes.
        6. Check iPerf statistics.

        @result: No traffic loss.
        @duration: 10 minutes.
        """
        pass

    def test_offloads(self):
        """
        @description: The test incapsulates both devices on DUT into bridge and sends traffic over it.

        @steps:
        1. Install firmware on both devices on DUT.
        2. Install driver on both devices on DUT.
        3. Set IPv4 and IPv6 addresses on DUT and LKP
        4. Hibernate DUT.
        5. Send ARP, NS and ICMP requests from LKP using both devices.

        @result: All requests are answered.
        @duration: 8 minutes.
        """

    def test_wol(self):
        """
        @description: The test incapsulates both devices on DUT into bridge and sends traffic over it.

        @steps:
        1. Install firmware on both devices on DUT.
        2. Install driver on both devices on DUT.
        3. Set IPv4 and IPv6 addresses on DUT and LKP.
        4. Verify wake on link:
            a. Hibernate DUT
            b. Link down/up on first device on LKP.
            c. Check DUT woke up.
            d. Check datapass (send ping).
            e. Repeat the same for second device on LKP.
        5. Verify wake by magic packet:
            a. Hibernate DUT.
            b. Send IPv4 magic packet from first device on LKP
            c. Check DUT woke up.
            d. Check datapass (send ping).
            e. Hibernate DUT.
            f. Send IPv6 magic packet from first device on LKP
            g. Check DUT woke up.
            h. Check datapass (send ping).
            i. Repeat the same for second device on LKP.
        6. Verify wake on pattern:
            a. Hibernate DUT.
            b. Send IPv4 TCP SYN packet to port 22.
            c. Check DUT woke up.
            d. Check datapass (send ping).
            e. Hibernate DUT.
            f. Send IPv6 magic packet from first device on LKP
            g. Check DUT woke up.
            h. Check datapass (send ping).
            i. Repeat the same for second device on LKP.

        @result: Dut wakes up on each wakeup pattern.
        @duration: 20 minutes.
        """

    def test_hibernate(self):
        """
        @description: The test performs hibernation and datapass check in the loop.

        @steps:
        1. Install firmware on both devices on DUT.
        2. Install driver on both devices on DUT.
        3. Set IPv4 and IPv6 addresses on DUT and LKP
        4. Hibernate DUT.
        5. Wakeup DUT.
        6. Check datapass (ping) on all devices.
        7. Repeat 4-6 steps in the loop 19 times.

        @result: Datapass is OK after wake up.
        @duration: 30 minutes.
        """
