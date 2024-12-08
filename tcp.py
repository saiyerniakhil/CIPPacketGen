from scapy.layers.inet import Ether, IP, TCP

from scapy.sendrecv import sr1, sendp
from scapy_cip_enip import plc


def connect_to_plc(dst_ip, dport):
    client = plc.PLCClient(dst_ip, dport)
    if not client.connected:
        raise Exception("Unable to establish session")

    print("Established session {}".format(client.session_id))
    return client