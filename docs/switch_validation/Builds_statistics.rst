=======================
Builds and related bugs
=======================

* 8th of June

    #. DEADCODE problem

* 15th of June

    #. DEADCODE problem fixed
    #. Traffic loses if any switch port is not connected. Workaround is provided. Waiting for fix
    #. MAC table doesn't learn addresses for forwarded packets
    #. Support for multicast and broadcast source MAC addresses to be added in next release
    #. Bug related to impossibility of adding VLAN info
    #. Support for port based hardware learn limiting (from 1 to 255 addresses per port) in next release
    #. Support for 12 ports in next release

* 28th of June

    #. No new features implemented
    #. VLAN addition bug is fixed
    #. New bug related to pings and traffic loses (regression failed)
    #. Unable to write egress shaping register. Wrong default values in shaping registers
    #. Register map overlap. Waiting for new build

* 10th of July

    #. Issue with port 3. Traffic loses when port 3 enabled
    #. Egress shaping. Rate_y is not writable (cannot set float mantissa)

* 17th of July

    #. Egress shaping bug is fixed.
    #. Traffic loses bug is fixed.
    #. 5 ports supported

* 27th of July

    #. Build with 10 port supporting is released
    #. IPERF traffic loses between ports 0 and 1
