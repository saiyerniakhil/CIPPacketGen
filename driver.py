from scapy.fields import LEIntField
from scapy.layers.inet import Ether, IP, TCP
from scapy.packet import Packet
from scapy.sendrecv import sendp
from scapy_cip_enip.cip import CIP

class CIPIO(Packet):
    name = "CIP IO"
    fields_desc = [
        LEIntField("CIP Sequence Count", 0),
        LEIntField("sequence", 0),
    ]

cipiopkt = CIP()

"""
192.168.1.14

192.168.0.1
"""