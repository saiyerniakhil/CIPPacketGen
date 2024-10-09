from scapy.all import *
from cip_fields import CIPSegment, LogicalSegment, EPATHField


class CIPMessageRouterRequest(Packet):
    name = 'CIPMessageRouterRequest'
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


# Example usage:
cipmrr = CIPMessageRouterRequest(
    Service=0x24,
    RequestPath=[
        LogicalSegment(logical_type='class_id', logical_format=1, value=0x01),
        LogicalSegment(logical_type='instance_id', logical_format=1, value=0x01),
    ]
)
raw(cipmrr)
cipmrr.show()
