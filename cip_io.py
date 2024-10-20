from scapy.all import *
from scapy.contrib.enipTCP import ENIPTCP, ENIPListInterfacesItem, ENIPListInterfaces, ENIPSendRRData, ItemData
from scapy.contrib.etherip import EtherIP
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv46
from scapy.layers.l2 import Ether

from cip_fields import CIPSegment, LogicalSegment, EPATHField


class CIPMessageRouterRequest(Packet):
    name = 'CIP'
    fields_desc = [
        ByteField("Service", 0x00),  # Service code
        ByteField("RequestPathSize", None),  # Will be calculated
        EPATHField("RequestPath", []),  # List of CIPSegments
        # Add Request Data fields if needed
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.RequestPathSize is None:
            request_path_bytes = b"".join(raw(s) for s in self.RequestPath)
            self.RequestPathSize = len(request_path_bytes) // 2  # Size in words (16 bits)



# bind_layers(ENIPTCP, ENIPSendRRData, commandId=0x006f)
# bind_layers(ENIPSendRRData, CIPMessageRouterRequest)

cipmrr = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=60493,dport=44818) / ENIPTCP() / ENIPSendRRData(items=[ItemData(typeId=0x0000), ItemData(typeId=0x00B2)])

cipmrr  /=   CIPMessageRouterRequest(
    Service=0x24,
    RequestPath=[
        LogicalSegment(logical_type='class_id', logical_format=1, value=0x01),
        LogicalSegment(logical_type='instance_id', logical_format=1, value=0x01),
    ]
)

send(cipmrr, iface="en0")
send(cipmrr, iface="en0")
send(cipmrr, iface="en0")
send(cipmrr, iface="en0")
send(cipmrr, iface="en0")
send(cipmrr, iface="en0")
send(cipmrr, iface="en0")
send(cipmrr, iface="en0")
cipmrr.show()

print(conf.ifaces)