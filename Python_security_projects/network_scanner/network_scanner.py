#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request =scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #broadcast mac address
    arp_request_broadcast = broadcast/arp_request #forward slash allows to combine 2 packets into new one using scapy
    #arp_request_broadcast.show() #show details about the package
    answered_list = scapy.srp(arp_request_broadcast, timeout =1, verbose=False)[0] # send packets wih custom mac, .sr function for  packets without custom mac. Response in form of 2 list answered, unanswered response and also add timeout.

    client_list =[]
    for element in answered_list:
        client_disc = {"ip": element[1].psrc ,"mac":element[1].hwsrc} #
        client_list.append(client_disc) #store dictationary in list

    return  client_list


def print_result(result_list):
    print("IP\t\t\tMAC\n---------------------------------------")
    for client in result_list:
        print(client["ip"]+ "\t\t" + client["mac"])  # print ip and mac of response device







scan_results = scan("192.168.102.1/24")
print_result(scan_results)