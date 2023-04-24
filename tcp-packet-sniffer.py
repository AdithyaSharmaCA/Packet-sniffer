from scapy.all import *
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP 

TCP_list = []
# Sniff packets from network interface
def packet_handler(packet):
    if packet.haslayer(TCP):
        tcp_packet = packet[TCP]
        if TCP in tcp_packet
            print("Sniffed TCP packet: ", tcp_packet.summary())
            tcp_packet.show()   
            TCP_list.append(tcp_packet)
# Sniff packets with the custom packet handler
sniff(filter = "tcp",prn=packet_handler)
print(len(TCP_list))
