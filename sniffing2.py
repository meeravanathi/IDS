from scapy.all import *

def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        try:
            src_name = socket.gethostbyaddr(src_ip)[0]
        except socket.herror:
            src_name = "Unknown"
        try:
            dst_name = socket.gethostbyaddr(dst_ip)[0]
        except socket.herror:
            dst_name = "Unknown"
        print(f"Source: {src_ip} ({src_name}) -> Destination: {dst_ip} ({dst_name})")


sniff(filter="ip", prn=packet_handler, store=False)