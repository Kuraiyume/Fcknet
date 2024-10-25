![GIF](https://github.com/Kuraiyume/FckNet/blob/main/fckpeople.gif)

# FckNet: Network Manipulation Toolkit

FckNet is a relentless toolkit for network manipulation, designed to seize control, exploit weaknesses, and push the limits of network security. It equips you with the means to infiltrate, disrupt, and test the resilience of any network environment.

## [+] Features

- **ARP Spoofing**: Intercept and redirect network traffic by sending fake ARP packets.
- **DHCP Starvation**: Flood the DHCP server with requests to exhaust its available IP addresses.
- **Network Scanning**: Discover active devices on a network and retrieve their IP and MAC addresses.
- **SYN Flooding**: Launch a SYN flood attack to overwhelm a target system.
- **ICMP Flooding**: Launch an ICMP flood attack to overwhelm a target system.
- **DDoS POST**: Launch a large number of POST requests to overwhelm a target system.
- **DDoS GET**: Launch a large number of GET requests to overwhelm a target system.

## [+] Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Kuraiyume/FckNet
   ```

2. Install the essential libraries:
   ```bash
   pip3 install -r requirements.txt
   ```
   
3. Run Fcknet with Root Privilege:
   ```
   sudo python3 fcknet.py
   ```

## [+] Commands and Parameters

   | Actions       | Description                               |
   |---------------|-------------------------------------------|
   | **arp_spoof** | Execute ARP Spoofing                      |
   | **dhcp_starv**| Conduct DHCP Starvation                   |
   | **net_scan**  | Perform a Network Scan                    |
   | **syn_flood** | Initiate a SYN Flood Attack               |
   | **icmp_flood**| Initiate an ICMP Flood Attack             |
   | **ddos_post** | Perform a DDoS POST Request               |
   | **ddos_get**  | Perform a DDoS GET Request                |

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
   sudo python3 fcknet.py -a ddos_get -u <URL>  -pr <packet_rate> -t <threads> -d <duration>
   ```

## [+] Disclaimer
- This toolkit is intended strictly for educational purposes or authorized testing on networks you have explicit permission to assess. Misuse of FckNet can lead to severe legal consequences. Always obtain proper authorization before conducting any network manipulation or attack simulations.

## [+] License
- This project is licensed under the GNU General Public License (GPL).

## [+] Author
- Kuraiyume (A1SBERG)

