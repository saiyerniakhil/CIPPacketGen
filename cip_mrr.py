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

bind_layers(ENIPSendRRData, CIPMessageRouterRequest)


src_ip = "192.168.1.10"
dst_ip = "192.168.1.20"
src_port = RandShort()  # Random source port
dst_port = 44818        # ENIP standard port

cip_request = CIPMessageRouterRequest(
    Service=0x24,
    RequestPath=[
        LogicalSegment(logical_type='class_id', logical_format=1, value=0x01),
        LogicalSegment(logical_type='instance_id', logical_format=1, value=0x01),
    ]
)

items = [
    ItemData(typeId=0x0000, data=b''), ItemData(typeId=0x00B2, data=b'')
]
enip_send_rrr_data = ENIPSendRRData(items=items, itemCount=len(items))
enip_tcp = ENIPTCP(
    commandId=0x006F,  # SendRRData command
    # Do not set length; let Scapy calculate it
    session=0x00000000,  # For dummy packet
    status=0x00000000,
    senderContext=RawVal(b'\x00' * 8),
    options=0x00000000
) / enip_send_rrr_data




data_pkt = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=src_port, dport=dst_port,flags='PA', seq=1, ack=1) / enip_tcp / cip_request

send(data_pkt)
data_pkt.show()