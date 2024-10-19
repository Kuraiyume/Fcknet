# FckNet: Network Attack Toolkit

FckNet is a versatile network manipulation tool that utilizes **Scapy** for all its features, enabling users to perform various network-related tasks. It supports several functionalities, including ARP spoofing, DHCP starvation, network scanning, SYN flooding, DDoS POST Req.

## Features

- **ARP Spoofing**: Intercept and redirect network traffic by sending fake ARP packets.
- **DHCP Starvation**: Flood the DHCP server with requests to exhaust its available IP addresses.
- **Network Scanning**: Discover active devices on a network and retrieve their IP and MAC addresses.
- **SYN Flooding**: Launch a SYN flood attack to overwhelm a target system.
- **ICMP Flooding**: Launch an ICMP flood attack to overwhelm a target system.
- **DDoS POST**: Launch a large number of POST requests to overwhelm a target system.
- **DDoS GET**: Launch a large number of GET requests to overwhelm a target system.

## Usage

1. Run Fcknet with Root Privilege:
   ```
   sudo python3 fcknet.py
   ```

2. Available Commands:
- **arp_spoof:** Execute ARP Spoofing.
- **dhcp_starv:** Conduct DHCP Starvation.
- **net_scan:** Perform a Network Scan.
- **syn_flood:** Initiate a SYN Flood Attack.
- **icmp_flood:** Initiate an ICMP Flood Attack.
- **ddos_post:** Perform DDoS POST Request.
- **ddos_get:** Perform DDoS GET Request.
- **help or h:** Display the list of commands.
- **exit or quit:** Terminate the program.

## Requirements
- Root Access: FckNet requires root privileges to perform its functions.
- Python 3: Ensure that Python 3 is installed on your system.
- Scapy: Ensure you have Scapy library installed because Scapy is the root core of this tool. (pip3 install scapy)

## Disclaimer
- Use this tool responsibly and only on networks you have permission to test. Unauthorized use of this tool can lead to legal consequences.

## License
- This project is licensed under the GNU General Public License.

## Author
- Kuraiyume (A1SBERG)

