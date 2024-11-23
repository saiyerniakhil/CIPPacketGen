from scapy.layers.inet import Ether, IP, TCP
from scapy.sendrecv import send
from scapy_cip_enip.cip import CIP, CIP_Path
from scapy_cip_enip.enip_tcp import ENIP_TCP

pkt = Ether() / IP(src='192.168.1.1', dst='192.168.0.1') / TCP(sport=5000, dport=80, flags='S')

pkt /= ENIP_TCP() / CIP(service=0x4c,)
# print(CIP_Path.make_str('HMI_LIT101').fields)
pkt.show()
# send(pkt, verbose=0)