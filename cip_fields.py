from typing import Any
from scapy.fields import Field, ByteField
from typing import Literal, Sequence, Union


class ElementaryDataType(ByteField):
    data_type_code = 0x00
    size = 0  # size of type in bytes

    def __init__(self, name: str, default) -> None:
        super().__init__(name, default)


class USINT(ElementaryDataType):
    """
    Unsigned 8-bit integer value
    """
    data_type_code = 0xC6
    size = 1  # 1 byte = 8 bits

    def __init__(self, name: str, default) -> None:
        super().__init__(name, default)


class CIPSegment(ByteField):
    """
    A segment is an 8 bit.

    _ _ _           SEGMENT TYPE
          _ _ _ _ _ SEGMENT FORMAT

    There are 4 types of segment types
    1. Port Segment
    2. Logical Segment
    3. Network Segment
    4. Symbolic Segment
    5. Data Segment
    """
    segment_type = 0b_000_00000  # default type of port segment

    """
    `default` here is an 8-bit value which contains both segment_type and segment_format
    """
    def __init__(self, name, default):
        super().__init__(name, default)


class LogicalSegment(CIPSegment):
    segment_type = 0b_001_000_00

    logical_types = {
        "class_id": 0b_000_000_00,
        "instance_id": 0b_000_001_00,
        "member_id": 0b_000_010_00,
        "connection_point": 0b_000_011_00,
        "attribute_id": 0b_000_100_00,
        "special": 0b_000_101_00,
        "service_id": 0b_000_110_00,
    }

    logical_formats = {
        1: 0b_000_000_00,  # 8-bit
        2: 0b_000_000_01,  # 16-bit
        4: 0b_000_000_11,  # 32-bit
    }
    """
    default logical segment packet is a logical segment with **class_id** as logical type with **8 bit** format
    """
    def __init__(self, name):
        super().__init__(name, self.segment_type + self.logical_types.get("class_id") + self.logical_formats.get(1))

    # users could also choose have their own logical segment with custom logical type and custom logical_format
    def __init__(self, name, logical_type = "class_id", logical_format = 1):
        super().__init__(name, self.segment_type + self.logical_types.get(logical_type) + self.logical_formats.get(logical_format))


    # def __init__(self, name: str, logical_type: Literal[
    #     'class_id', 'instance_id', 'member_id', 'connection_point', 'attribute_id', 'special', 'service_id'],
    #              logical_format_len: Literal[1, 2, 4]) -> None:
    #     # combined value will be segment_type, logical_type and logical_value added
    #     super().__init__(name,
    #                      default=self.segment_type + self.logical_types.get(logical_type) + self.logical_format.get(
    #                          logical_format_len))
    #
    # def __init__(self, name: str) -> None:
    #     super().__init__(name,
    #                      default=self.segment_type + self.logical_types.get("class_id") + self.logical_format.get(1))


# class NetworkSegment(CIPSegment):
#     segment_type = 0b_010_000_00


# class SymbolicSegment(CIPSegment):
#     segment_type = 0b_011_000_00

# class DataSegment(CIPSegment):
#     segment_type = 0b_100_000_00


class EPATH(ElementaryDataType):
    """
    CIP Path Segments
    """
    data_type_code = 0xDC
    path = b""

    def __init__(self, name: str, default) -> None:
        super().__init__(name, default)

    def __init__(self, name: str, segments=Sequence[Union[CIPSegment, int]]) -> None:
        # convert the sequence of segments to a large binary string?
        path = b"".join([format(segment & 0xFF, '08b') for segment in segments])
        self.size = len(segments)

