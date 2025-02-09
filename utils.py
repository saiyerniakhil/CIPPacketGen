# RealTimeHeader class definition
import os
import struct
import random

from scapy.fields import BitField, LEShortEnumField, LEShortField, PacketListField
from scapy.packet import Packet


class RealTimeHeader(Packet):
    name = "RealTimeHeader"
    fields_desc = [
        BitField("reserved", 0, 28),  # bits 4-31
        BitField("roo", 0, 2),        # bits 2-3
        BitField("coo", 0, 1),        # bit 1
        BitField("run_idle", 0, 1),   # bit 0
    ]

# ENIP UDP Item and Packet definitions
class ENIP_UDP_Item(Packet):
    name = "ENIP_UDP_Item"
    fields_desc = [
        LEShortEnumField("type_id", 0x00b1, {
            0x00b1: "Connected_Data_Item",
            0x8002: "Sequenced_Address",
        }),
        LEShortField("length", None),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]

    def post_build(self, p, pay):
        if self.length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay

class ENIP_UDP(Packet):
    name = "ENIP_UDP"
    fields_desc = [
        LEShortField("count", None),
        PacketListField("items", [], ENIP_UDP_Item,
                        count_from=lambda pkt: pkt.count),
    ]

    def post_build(self, p, pay):
        if self.count is None:
            self.count = len(self.items)
            p = struct.pack("<H", self.count) + p[2:]
        return p + pay


def random_interval_between(low, high):
    """

    :param low: lower bound
    :param high: upper bound
    :return: a random number between (low,high) range
    """
    return round(random.randint(low * 1000, high * 1000) / 1000, 2)

def random_application_data(minlength=8, maxlength=25):
    """
    :param length: length of application data
    :return: generates random binary application data
    """
    return os.urandom(random.randint(minlength, maxlength))