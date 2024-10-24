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

2. Available Actions:
- **arp_spoof:** Execute ARP Spoofing.
- **dhcp_starv:** Conduct DHCP Starvation.
- **net_scan:** Perform a Network Scan.
- **syn_flood:** Initiate a SYN Flood Attack.
- **icmp_flood:** Initiate an ICMP Flood Attack.
- **ddos_post:** Perform DDoS POST Request.
- **ddos_get:** Perform DDoS GET Request.
- **help or h:** Display the list of commands.
- **exit or quit:** Terminate the program.

## Commands && Parameters

1. ARP Spoofing
   ```bash
   sudo python3 fcknet.py -a arp_spoof -ip <target_ip> -sip <router_ip>
   ```

2. DHCP Starvation
   ```bash
   sudo python3 fcknet.py -a dhcp_starv -i <interface>
   ```

3. Network Scanner
   ```bash
   sudo python3 fcknet.py -a net_scan -r <ip_range>
   ```

4. SYN Flooding
   ```bash
   sudo python3 fcknet.py -a syn_flood -ip <target_ip> -p <port> -pr <packet_rate> -t <threads> -d <duration>
   ```

5. ICMP Flooding
   ```bash
   sudo python3 fcknet.py -a icmp_flood -ip <target_ip> -pr <packet_rate> - t <threads> -d <duration>
   ```

6. DDoS POST
   ```bash
   sudo python3 fcknet.py -a ddos_post -u <URL>  -pr <packet_rate> -t <threads> -d <duration> -psize <packet_size>
   ```

7. DDoS GET
   ```bash
   sudo python3 fcknet.py -a ddos_get -u <URL>  -pr <packet_rate> -t <threads> -d <duration> -psize <packet_size>
   ```

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

