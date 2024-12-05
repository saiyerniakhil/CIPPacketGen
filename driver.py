import sys

from scapy.fields import LEIntField
from scapy.layers.inet import Ether, IP, TCP
from scapy.packet import Packet
from scapy.sendrecv import sendp
from scapy_cip_enip.cip import CIP, CIP_Path
from scapy_cip_enip.plc import PLCClient

# testing connection to a plc client

client = PLCClient('192.168.0.114', plc_port=12345)
if not client.connected:
    sys.exit(1)

print(f"Established connection {client.session_id}")

if not client.forward_open():
    print("Failed to open connection")
    sys.exit(1)

# Send a CIP ReadTag request
cippkt = CIP(service=0x4c, path=CIP_Path.make_str("HMI_LIT101"))
client.send_unit_cip(cippkt)

# Receive the response and show it
resppkt = client.recv_enippkt()
resppkt[CIP].show()

# Close the connection
client.forward_close()

