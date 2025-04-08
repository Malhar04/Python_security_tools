#!/usr/bin/env python
from operator import truediv

import scapy.all as scapy

 #echo 1 > /proc/sys/net/ipv4/ip_forward
def get_mac(ip):
    arp_request =scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #broadcast mac address
    arp_request_broadcast = broadcast/arp_request #forward slash allows to combine 2 packets into new one using scapy
    answered_list = scapy.srp(arp_request_broadcast, timeout =1, verbose=False)[0] # send packets wih custom mac, .sr function for  packets without custom mac. Response in form of 2 list answered, unanswered response and also add timeout.

    return answered_list[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface, store =False,prn = precess_sniffed_packet)

def precess_sniffed_packet(packet):
    try:
        real_mac =get_mac(packet[scapy.ARP].psrc)
        response_mac = packet[scapy.ARP].hwsrc

        if real_mac!= response_mac:
            print("[+] you are under attack")
    except IndexError:
        pass


sniff("eth0")