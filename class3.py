from scapy_cip_enip.cip import CIP, CIP_Path
from scapy_cip_enip.plc import PLCClient
import sys

def read_tag_operation(dst_ip, src_ip):
    pass

class Class3Driver:
    client = None
    def __init__(self, src_ip = b'192.168.1.2', dst_ip=b'192.168.0.1', sport=5000, dport=80):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        # Create a connection to the PLC
        self.client = PLCClient(self.dst_ip, dport)
        if not self.client.connected:
            print(f"Unable to connect to client at {self.dst_ip}")
            sys.exit(1)
        print(f"Established session {self.client.session_id}")

    def craft_packet(self):
        """

        TODO: Randomize the packet creation, read more about this. Everytime this is called a new kind of packet is created with different values
        :return:
        """
        cippkt = CIP(service=0x4c, path=CIP_Path.make_str("HMI_LIT101"))
        return cippkt


    def generate_traffic(self):
        # create a CIP packet
        self.client.send_unit_cip(self.craft_packet())

        resppkt = self.client.recv_enippkt()
        resppkt.show()


    def destroy_connection(self):
        self.client.forward_close()



