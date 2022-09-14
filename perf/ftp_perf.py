import argparse
import json
import time

from ftplib import FTP

try:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler, DTPHandler
    from pyftpdlib.servers import FTPServer, ThreadedFTPServer
except ImportError:
    print("pyftpdlib module is required to run FTP server")
    print("Run 'pip install pyftpdlib'")
    exit(-1)

__version__ = "0.0.2"

SERVER = None


class MyFTPHandler(FTPHandler):
    def on_disconnect(self):
        if self.one_client:
            global SERVER
            SERVER.close_all()


if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument("-v", "--version", action="version", version="%(prog)s {}".format(__version__))
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-s", "--server", dest="server_ip", nargs="?", const="0.0.0.0", help="FTP server")
        group.add_argument("-c", "--client", dest="client_ip", help="FTP client")
        parser.add_argument("-p", "--port", dest="port", type=int, default=10260,
                            help="Port to open a connection with. Default = 10260")
        parser.add_argument("-1" "--one-off", dest="one_client", action="store_true",
                            help="Handle one client connection then exit")
        parser.add_argument("-t", "--time", dest="timeout", type=int, default=10,
                            help="Timeout for measurement. Default = 10")
        parser.add_argument("-i" "--interval", dest="interval", type=float, default=1.0,
                            help="Seconds between periodic bandwidth reports. Default = 1.0")
        parser.add_argument("-J", "--json", dest="json_output", action="store_true",
                            help="Output in JSON format")
        args = parser.parse_args()

        if args.server_ip:
            try:
                authorizer = DummyAuthorizer()
                try:
                    authorizer.add_anonymous("/dev")
                except ValueError as exc:
                    if "no such directory" in exc.message:
                        print ("Server has to be started on Linux system with /dev/zero file available")
                        print ("Exception: {}".format(exc))
                        exit(-1)
                    else:
                        raise exc

                ftp_handler = MyFTPHandler
                ftp_handler.authorizer = authorizer
                ftp_handler.one_client = args.one_client

                SERVER = FTPServer((args.server_ip, args.port), ftp_handler)
                # SERVER = ThreadedFTPServer((args.server_ip, args.port), ftp_handler)
                # SERVER = MultiprocessFTPServer((args.server_ip, args.port), ftp_handler)
                SERVER.serve_forever()
            except Exception as e:
                print ('\n\n\n\n\n>>>> SERVER:\n' + str(e) + '\n\n\n\n\n')
        else:
            try:
                output_dict = {
                    "start": {
                        "version": "{} {}".format(parser.prog, __version__),
                        "timestamp": {
                            "time": "",
                            "timesecs": 0.0}
                    },
                    "intervals": [],
                    "end": {
                        "sum_sent": {
                            "seconds": 0.0,
                            "bytes": 0
                        },
                        "sum_received": {
                            "seconds": 0.0,
                            "bytes": 0
                        }
                    }
                }

                client = FTP("")
                client.connect(args.client_ip, args.port)
                client.login()

                output_dict["start"]["timestamp"]["time"] = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

                # Global variables
                local_size = 0
                total_size = 0

                local_time = time.time()
                total_time = time.time()

                output_dict["start"]["timestamp"]["timesecs"] = total_time

                def callback(buff):
                    """Callback function for receiver"""
                    global local_size, total_size, local_time, total_time, args
                    try:

                        current_time = time.time()
                        local_duration = current_time - local_time
                        if local_duration >= args.interval:
                            output_dict["intervals"].append({"sum": {"seconds": local_duration, "bytes": local_size}})
                            if not args.json_output:
                                print ("Current speed = {:.3f} Mbps".format((local_size / 125000.0) / local_duration))

                            local_size = 0
                            local_time = time.time()

                        size = len(buff)

                        total_size += size
                        local_size += size

                        if current_time - total_time >= args.timeout + 0.5:  # Make sure last second goes into output
                            raise KeyboardInterrupt()

                    except Exception as e:
                        print e

                try:
                    client.retrbinary('RETR zero', callback)
                except KeyboardInterrupt:
                    # Exit client (timeout or user input)
                    pass
                except Exception as e:
                    print('Exception in client: {}'.format(e))

                total_duration = time.time() - total_time

                try:
                    client.quit()
                except Exception as exc:
                    if not args.json_output:
                        print ("Warning: Exception ignored while closing connection: {}".format(exc.message))

                output_dict["end"]["sum_received"]["seconds"] = total_duration
                output_dict["end"]["sum_received"]["bytes"] = total_size
                if not args.json_output:
                    print ("=" * 80)
                    print ("Total bytes transmitted = {}".format(total_size))
                    print ("Total time = {:.3f} seconds".format(total_duration))
                    print ("Average speed = {:.3f} Mbps".format((total_size / 125000.0) / total_duration))
                else:
                    print (json.dumps(output_dict, indent=4))
            except Exception as e:
                print ('\n\n\n\n\n>>>> CLIENT:\n' + str(e) + '\n\n\n\n\n')