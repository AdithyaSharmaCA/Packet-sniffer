# Import Scapy library for packet sniffing and manipulation
from scapy.all import *
from scapy.layers.inet import TCP
from scapy.layers.inet import IP
# Initialize counter to zero
handshake_counter = 0

# Define the callback function to process sniffed packets
def process_packet(packet):
    global handshake_counter

    # Check for SYN packet
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        # Check for SYN-ACK packet
        syn_ack_packet = sniff(filter=f"tcp and host {packet[IP].dst} and port {packet[TCP].dport}", count=1)
        if syn_ack_packet and syn_ack_packet[0][TCP].flags == 'SA':
            # Check for ACK packet
            ack_packet = sniff(filter=f"tcp and host {packet[IP].src} and port {packet[TCP].sport}", count=1)
            if ack_packet and ack_packet[0][TCP].flags == 'A':
                # Increment handshake counter
                handshake_counter += 1
                # Print current number of handshakes
                print(f"Number of handshakes: {handshake_counter}")
    print(packet.summary())
# Start sniffing packets on the network interface
sniff(filter="tcp", prn=process_packet)
