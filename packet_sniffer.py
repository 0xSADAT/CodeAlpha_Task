import time
import subprocess
import re
from scapy.all import *

# Get the current MAC address of an interface
def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface])
        return re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(output)).group(0)
    except:
        pass

# Get the current IP address of an interface
def get_current_ip(interface):
    output = subprocess.check_output(["ifconfig", interface])
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    output1 = output.decode()
    ip = pattern.search(output1)[0]
    return ip

# Sniff packets
def packet_sniffer(interface):
    try:
        sniffed_packets = sniff(iface=interface, count=10)  # Capture 10 packets
        with open("packet_output.txt", "w") as output_file:
            for packet in sniffed_packets:
                output_file.write(str(packet) + "\n")
        print(f"Captured {len(sniffed_packets)} packets. Output saved to packet_output.txt")
    except KeyboardInterrupt:
        print("\nSniffing stopped by user.")

if __name__ == "__main__":
    interface_name = input("Enter the interface name (e.g., eth0, wlan0): ")
    print(f"Current MAC address: {get_current_mac(interface_name)}")
    print(f"Current IP address: {get_current_ip(interface_name)}")
    packet_sniffer(interface_name)
