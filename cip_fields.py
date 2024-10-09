from scapy.fields import *
from scapy.packet import Packet
from typing import Union, Sequence


class CIPSegment(Packet):
    name = "CIPSegment"
    fields_desc = [
        # To be overridden by subclasses
    ]


class LogicalSegment(CIPSegment):
    name = "LogicalSegment"

    logical_types = {
        "class_id": 0b000,
        "instance_id": 0b001,
        "member_id": 0b010,
        "connection_point": 0b011,
        "attribute_id": 0b100,
        "special": 0b101,
        "service_id": 0b110,
    }

    logical_formats = {
        1: 0b00,  # 8-bit
        2: 0b01,  # 16-bit
        4: 0b11,  # 32-bit
    }

    fields_desc = [
        # Segment type (3 bits), logical type (3 bits), logical format (2 bits)
        BitField("segment_type", 0b001, 3),  # Logical Segment Type
        BitField("logical_type", 0b000, 3),
        BitField("logical_format", 0b00, 2),
        # Value field, size depends on logical_format
        ConditionalField(ByteField("value8", 0), lambda pkt: pkt.logical_format == 0b00),
        ConditionalField(ShortField("value16", 0), lambda pkt: pkt.logical_format == 0b01),
        ConditionalField(IntField("value32", 0), lambda pkt: pkt.logical_format == 0b11),
    ]

    def __init__(self, logical_type="class_id", logical_format=1, value=0, *args, **kwargs):
        kwargs['logical_type'] = self.logical_types.get(logical_type, 0b000)
        kwargs['logical_format'] = self.logical_formats.get(logical_format, 0b00)
        if kwargs['logical_format'] == 0b00:
            kwargs['value8'] = value
        elif kwargs['logical_format'] == 0b01:
            kwargs['value16'] = value
        elif kwargs['logical_format'] == 0b11:
            kwargs['value32'] = value
        else:
            raise ValueError("Invalid logical_format")
        super().__init__(*args, **kwargs)


class EPATHField(PacketListField):
    def __init__(self, name, default):
        super().__init__(name, default, CIPSegment, count_from=self._count_segments)

    def _count_segments(self, pkt):
        # Length in words (16 bits)
        length = sum(len(raw(s)) for s in pkt.RequestPath) // 2
        return length
