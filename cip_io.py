from scapy.all import *
from scapy.packet import bind_layers, bind_bottom_up, Packet
from scapy.contrib.etherip import EtherIP
import cip_fields

CIP_OPTIONS = {

}
"""
TODO: Gather the Fields 
"""
# class EtherNetIP(Packet):
#     pass



"""
A CIP MessageRouter Request has the following fields 
    1. Service - Service Code - is in the range of `0 - 31 (hex)` 
    2. Request Path Size -
    3. Request Path - Sequence of CIP Path Segments 
    4. Request Data
"""
class CIPMessageRouterRequest(Packet):
    Name = 'CIPMessageRouterRequest'
    fields_desc = [
        cip_fields.USINT("Service", 00), # Ranges from 00 - 31 (hex) hence the default value of 00
        # [cip_fields.LogicalSegment("RequestPath")]
        # Create a new field for epath
    ]
    # EtherNetIP()


cipmrr = CIPMessageRouterRequest(Service=0x24)
cipmrr.show()