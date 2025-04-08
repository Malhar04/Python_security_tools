#!/usr/bin/env python

import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface", help="Interface to change its mac address")
    parser.add_option("-m","--mac",dest="mac", help="New MAC address")
    (options,arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not options.mac:
        parser.error("[-] Please specify a new mac, use --help for more info.")
    return options

def change_mac(interface,mac):
    print("[+] changing MAC address for"+interface+ "to "+mac)
    subprocess.call(["ifconfig",interface,"down"])
    subprocess.call(["ifconfig",interface,"hw","ether",mac])
    subprocess.call(["ifconfig",interface,"up"])

def get_current_mac(interface):
    ifconfig_results = subprocess.check_output(["ifconfig", options.interface])
    mac_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_results))

    if mac_search_result:
       return (mac_search_result.group(0))
    else:
        print("[-] Could not find mac address")


options=get_arguments()

current_mac = get_current_mac(options.interface)
print("Current mac = "+ str(current_mac))
change_mac(options.interface,options.mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.mac:
    print("[+] MAC was sucessfully changed to " +current_mac)
else:
    print("[-] Something went wrong, please try again")




