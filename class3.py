from scapy.layers.inet import Ether, IP, TCP
from scapy.sendrecv import send, sendp
import random

from scapy_cip_enip.cip import CIP, CIP_Path
from scapy_cip_enip.enip_tcp import ENIP_TCP, ENIP_SendUnitData, ENIP_SendUnitData_Item, ENIP_ConnectionAddress, \
    ENIP_ConnectionPacket


services = {
    0x01: "Get_Attribute_All",
    0x03: "Get_Attribute_List",
    0x0e: "Get_Attribute_Single",
    0x4c: "Read_Tag_Service",
    0x52: "Read_Tag_Fragmented_Service",
}

def gen_class_3_cip_packet(src_ip, dst_ip, sport, dport, service, path):
    enippkt = Ether(type=0x0800) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='S') / ENIP_TCP(
        session=0x00)
    cippkt = CIP(service=service, path=path)
    enippkt /= ENIP_SendUnitData(items=[
        ENIP_SendUnitData_Item() / ENIP_ConnectionAddress(connection_id=0),
        ENIP_SendUnitData_Item() / ENIP_ConnectionPacket(sequence=0) / cippkt
    ])
    sendp(enippkt)
    enippkt.show()
    return enippkt

def randomize_service():
    return random.choice(list(services.keys()))
