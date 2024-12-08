"""
class 0
Modeless Format
    0-n bytes of application data

Zero-length Data Format
Two parts
    0  bytes of application data
    1-n bytes of application data

Heartbeat Format
    0 bytes of application data

32 Bit Header Format
    32-bit real time header | 0-n bytes of application data

"""
from random import random

from scapy.fields import StrLenField, PacketField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import UDP, IP
from scapy.sendrecv import send

from utils import ENIP_UDP_Item, ENIP_UDP, RealTimeHeader, random_application_data

PORT = 2222 #doesnt change

def craft_class0_modeless_packet(src_ip: str, dst_ip: str, data=b'\x01\x02\x03\x04'):
    # Create the CIP packet
    cip_pkt = CIP_Class0_Modeless(
        application_data=data  # Example application data
    )

    # Create ENIP UDP Item
    enip_udp_item = ENIP_UDP_Item(
        type_id=0x00b1,
        length=None  # Will be set automatically
    ) / cip_pkt

    # Create ENIP UDP Packet
    enip_udp_pkt = ENIP_UDP(
        count=1,
        items=[enip_udp_item]
    )

    # Create UDP and IP layers
    udp_pkt = UDP(sport=PORT, dport=PORT) / enip_udp_pkt
    ip_pkt = IP(src=src_ip, dst=dst_ip) / udp_pkt

    return ip_pkt

def craft_class0_32_bit_header_packet(src_ip: str, dst_ip: str, data=b'\x01\x02\x03\x04'):
    cip_pkt = CIP_Class0_32BitHeader(
        application_data=data  # Example application data
    )
    # Create ENIP UDP Item
    enip_udp_item = ENIP_UDP_Item(
        type_id=0x00b1,
        length=None  # Will be set automatically
    ) / cip_pkt

    # Create ENIP UDP Packet
    enip_udp_pkt = ENIP_UDP(
        count=1,
        items=[enip_udp_item]
    )

    # Create UDP and IP layers
    udp_pkt = UDP(sport=2222, dport=2222) / enip_udp_pkt
    ip_pkt = IP(src=src_ip, dst=dst_ip) / udp_pkt

    return ip_pkt

# Class 0 Packet Formats
class CIP_Class0_Modeless(Packet):
    name = "CIP_Class0_Modeless"
    fields_desc = [
        StrLenField("application_data", b"", length_from=lambda pkt: len(pkt.application_data)),
    ]

class CIP_Class0_ZeroLength(Packet):
    name = "CIP_Class0_ZeroLength"
    fields_desc = [
        StrLenField("application_data", b"", length_from=lambda pkt: len(pkt.application_data)),
    ]

class CIP_Class0_Heartbeat(Packet):
    name = "CIP_Class0_Heartbeat"
    fields_desc = [
        # No fields for heartbeat format
    ]

class CIP_Class0_32BitHeader(Packet):
    name = "CIP_Class0_32BitHeader"
    fields_desc = [
        PacketField("real_time_header", RealTimeHeader(), RealTimeHeader),
        StrLenField("application_data", b"", length_from=lambda pkt: len(pkt.application_data)),
    ]

bind_layers(ENIP_UDP_Item, CIP_Class0_32BitHeader, type_id=0x00b1)
bind_layers(ENIP_UDP_Item, CIP_Class0_Modeless, type_id=0x00b1)
bind_layers(ENIP_UDP_Item, CIP_Class0_ZeroLength, type_id=0x00b1)
bind_layers(ENIP_UDP_Item, CIP_Class0_Heartbeat, type_id=0x00b1)

if __name__ == "__main__":
    # Example of crafting a Class 0 packet with modeless format
    # Craft and send a Class 0 packet
    src_ip = '192.168.0.114'
    dst_ip = '192.168.0.114'

    class0_pkt = craft_class0_32_bit_header_packet(src_ip, dst_ip, random_application_data(8))
    send(class0_pkt, verbose=0)
    class0_pkt.summary()
    class0_pkt = craft_class0_32_bit_header_packet(src_ip, dst_ip, random_application_data(8))
    send(class0_pkt, verbose=0)
    class0_pkt = craft_class0_32_bit_header_packet(src_ip, dst_ip, random_application_data(8))
    send(class0_pkt, verbose=0)