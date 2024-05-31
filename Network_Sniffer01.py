from scapy.all import sniff, Ether, IP, TCP, UDP

# Define a function to process each packet sniffed
def packet_sniffer(packet):
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        print(f"Source MAC: {src_mac} | Destination MAC: {dst_mac}")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip}")

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"Source Port: {src_port} | Destination Port: {dst_port}")

    if UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print(f"Source Port: {src_port} | Destination Port: {dst_port}")

    # Save the output to a text file
    with open("packet_output.txt", "a") as output_file:
        output_file.write(f"Packet Info: {packet.summary()}\n")

# Placeholder function to get the current MAC address of the interface
def get_current_mac(interface):
    # Implementation to get the MAC address of the interface
    pass

# Placeholder function to get the current IP address of the interface
def get_current_ip(interface):
    # Implementation to get the IP address of the interface
    pass

# Prompt the user for the interface name
iface = input("Enter the interface name (e.g., eth0, wlan0): ")
print(f"Current MAC address: {get_current_mac(iface)}")
print(f"Current IP address: {get_current_ip(iface)}")
choice = input("Print raw packets? (Y/N): ")
# Sniff packets on the specified interface with provided packet processing function and filter
sniff(iface=iface, prn=packet_sniffer, filter="ip")
