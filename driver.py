from sys import flags

from scapy.layers.inet import Ether, IP, TCP

from scapy.sendrecv import sr1, sendp, send

from scapy_cip_enip import plc
from scapy_cip_enip.cip import CIP, CIP_Path
from scapy_cip_enip.enip_tcp import ENIP_TCP, ENIP_SendUnitData, ENIP_SendUnitData_Item, ENIP_ConnectionAddress, \
    ENIP_ConnectionPacket

import logging
import sys

from class0 import craft_class0_32_bit_header_packet, craft_class0_keep_alive_packet
from utils import random_application_data

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

"""# Connect to PLC
client = plc.PLCClient('127.0.0.1', 12345)
if not client.connected:
    sys.exit(1)
print("Established session {}".format(client.session_id))

if not client.forward_open():
    sys.exit(1)

# Send a CIP ReadTag request
cippkt = CIP(service=0x4c, path=CIP_Path.make(class_id=0x93, instance_id=3, member_id=None, attribute_id=10))
client.send_unit_cip(cippkt)




# Close the connection
# client.forward_close()"""

src_ip = '192.168.0.1'
dst_ip = '192.168.0.114'
dport = 12345

# client = plc.PLCClient('192.168.0.114', 12345)
# if not client.connected:
#     sys.exit(1)
# print("Established session {}".format(client.session_id))
sendp(craft_class0_keep_alive_packet(src_ip, dst_ip))
sendp(craft_class0_keep_alive_packet(src_ip, dst_ip))
sendp(craft_class0_keep_alive_packet(src_ip, dst_ip))
sendp(craft_class0_keep_alive_packet(src_ip, dst_ip))
sendp(craft_class0_keep_alive_packet(src_ip, dst_ip))


