from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")

            data = packet[TCP].payload
            if data:
                print(f"Data: {data}")

sniff(prn=packet_callback, store=0)
