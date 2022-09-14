import pcapy
import sys
import time
from utils import get_wmi_network_adapter


def get_pcapy_device(port):
    if sys.platform == "win32":
        adapter = get_wmi_network_adapter(port)
        devices = pcapy.findalldevs()
        for dev in devices:
            if adapter.GUID in dev:
                return dev
        return None


dev = get_pcapy_device("pci1.00.0")
print "!!!", dev
cap = pcapy.open_live(dev, 65536, 1, 5)
while(1):
    (header, packet) = cap.next()
    print header
    if header is None:
        time.sleep(0.1)

