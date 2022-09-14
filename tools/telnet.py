import telnetlib


class Telnet:
    def __init__(self, user, password, host, port=0, timeout=1):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.user = user
        self.password = password
        self.connection = telnetlib.Telnet(host, timeout=1)
        self.config_mode = False

    @staticmethod
    def send(cmd, host, user, password, config_mode=False):
        tn = Telnet(user, password, host)
        tn._login()
        tn._send("terminal length 0\n")
        if config_mode:
            tn._enable_config_mode()
        tn._send(cmd + "\n")
        if config_mode:
            tn._send("exit\n")
        tn._send("exit\n")

        return tn.connection.read_all()

    def _enable_config_mode(self):
        self.connection.write("enable\n")
        prompt = self.connection.expect(["assword"], timeout=self.timeout)
        if prompt[1]:
            self.connection.write(self.password + "\n")
            m = self.connection.expect(["#"], timeout=self.timeout)
            if not m[1]:
                raise Exception("Couldn't establish enabled mode")
        self._send("config term")

    def _send(self, cmd):
        self.connection.write(cmd + "\n")

    def _login(self):
        prompt = self.connection.read_some()

        if "ogin:" in prompt:
            self.connection.write(self.user + "\n")
            prompt = self.connection.read_some()

        if "assword:" in prompt:
            self.connection.write(self.password + "\n")
            m = self.connection.expect([">"], timeout=self.timeout)
            if not m[1]:
                raise Exception("Couldn't connect to switch. Wrong password")
