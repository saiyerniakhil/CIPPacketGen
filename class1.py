from scapy.all import *
from scapy.layers.inet import UDP, IP
from utils import RealTimeHeader, ENIP_UDP, ENIP_UDP_Item, random_application_data

PORT = 2222 #Doesn't change

# Class 1 Packet Formats
class CIP_Class1_Modeless(Packet):
    name = "CIP_Class1_Modeless"
    fields_desc = [
        ShortField("sequence_count", 0),
        StrLenField("application_data", b"", length_from=lambda pkt: len(pkt.application_data)),
    ]

class CIP_Class1_ZeroLength(Packet):
    name = "CIP_Class1_ZeroLength"
    fields_desc = [
        ShortField("sequence_count", 0),
        StrLenField("application_data", b"", length_from=lambda pkt: len(pkt.application_data)),
    ]

class CIP_Class1_Heartbeat(Packet):
    name = "CIP_Class1_Heartbeat"
    fields_desc = [
        ShortField("sequence_count", 0),
    ]

class CIP_Class1_32BitHeader(Packet):
    name = "CIP_Class1_32BitHeader"
    fields_desc = [
        ShortField("sequence_count", 0),
        PacketField("real_time_header", RealTimeHeader(), RealTimeHeader),
        StrLenField("application_data", b"", length_from=lambda pkt: len(pkt.application_data)),
    ]


# ENIP UDP Item and Packet definitions

# Bindings
bind_layers(UDP, ENIP_UDP, sport=2222, dport=PORT)
bind_layers(ENIP_UDP_Item, CIP_Class1_32BitHeader, type_id=0x00b1)
bind_layers(ENIP_UDP_Item, CIP_Class1_Modeless, type_id=0x00b1)
bind_layers(ENIP_UDP_Item, CIP_Class1_ZeroLength, type_id=0x00b1)
bind_layers(ENIP_UDP_Item, CIP_Class1_Heartbeat, type_id=0x00b1)


# Example of crafting a Class 1 packet with 32-bit header format
def craft_class1_32bitheader_packet(src_ip, dst_ip, data):
    """

    :param src_ip: Source IP Address
    :param dst_ip: Destination IP Address
    :param data: Data to be sent
    :return: UDP packet from :param src_ip to :param dst_ip
    """
    # Create the CIP packet
    cip_pkt = CIP_Class1_32BitHeader(
        sequence_count=1234,
        real_time_header=RealTimeHeader(
            reserved=0,
            roo=0,
            coo=0,
            run_idle=1  # Run mode
        ),
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


# Send the crafted packets
if __name__ == "__main__":
    # Craft and send a Class 1 packet
    src_ip = '192.168.0.114'
    dst_ip = '192.168.0.1'
    class1_pkt = craft_class1_32bitheader_packet(src_ip, dst_ip, random_application_data(8))
    send(class1_pkt)
    class1_pkt.show()


