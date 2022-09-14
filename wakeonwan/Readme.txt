Command line options:
    -6 - use IPv6 (must be first parameter in command line)
    -c - client mode, server IP:PORT
    -k - keepalive binary pattern filename
    -w - wakeup binary pattern filename
    -m - keepalive timeout in seconds (default: off)
    -t - wakeup timeout in seconds (default: off)
    -p - listen on port (default: 1234)


Server mode:
$ ./wakeonwan.exe -6 -k keepalive.txt -w wakeup.txt -m 6 -t 20 -p 2233


Client mode:
$ ./wakeonwan.exe -6 -c ::1:2233 -k keepalive.txt -w wakeup.txt -m 3 -t 60 -p 4455
