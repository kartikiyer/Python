# NETWORKING FRAMEWORK

# Importing Libraries/Modules
import socket
import os
import subprocess
import string
import random
from cryptography.fernet import Fernet
import struct
import binascii
from pyfiglet import Figlet
from termcolor import colored

os.system('cls') # For clearing out screen

# result = pyfiglet.figlet_format("Networking Framework",font = "banner3-D")
# print(result)
f = Figlet(font = 'banner3-D',width = 200)
print(colored(f.renderText('NetFramework'),'red'))
print("                                                                                                         Coded by : Kartik Iyer")

# g = Figlet()
# print(colored(g.renderText('By - Kartik Iyer'),'red'))
print("-------------------------------------------------------------------------------------------------------------------------------")

def Banner(ip,port):
    s = socket.socket()
    try:
        socket.setdefaulttimeout(5)
        s.connect((ip,port))
        recieve = s.recv(1024)
        print("=>",recieve)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except:
        print("=> Connection to this port closed or refused.")
        print("-------------------------------------------------------------------------------------------------------------------------------")

def PortScan(ip,port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        socket.setdefaulttimeout(5)
        if s.connect_ex((ip,port)):
            print("=> Port is closed")
            print("-------------------------------------------------------------------------------------------------------------------------------")
        else:
            print("=> Port is open")
            print("-------------------------------------------------------------------------------------------------------------------------------")
    except:
        print("=> Connection to this port is refused.")
        print("-------------------------------------------------------------------------------------------------------------------------------")

def Ping(hostname):
    ping = subprocess.check_output(['ping',hostname])
    try:
        print("=>",ping.decode('ascii'))
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print("=>",e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def Listener(ip,port):
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.bind((ip,port))
        print(f'=> Binded to port {port} with ip {ip}')
        s.listen(5)
        print(f'=> Server is listening on port {port}...')
        while True:
            c,addr = s.accept()
            print(f'=> Got a connection from {addr}')
            message = "=> Thank you for connecting with us.."
            c.send(message.encode())
            c.close()
            print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print("=>",e)
        print("-------------------------------------------------------------------------------------------------------------------------------")
   
def Wifi(interface):
    try:
        command = subprocess.check_output(['netsh',interface,'show','network'])
        decoded = command.decode('ascii')
        print("=>",decoded)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except:
        print(f"No interface found with name {interface}.Check your adaptor name again")
        print("-------------------------------------------------------------------------------------------------------------------------------")

def Caesar(plain_text,shift):
    try:
        alphabet = string.ascii_lowercase
        shifted = alphabet[shift:] + alphabet[:shift]
        table = str.maketrans(alphabet,shifted)
        encrypted = plain_text.translate(table)
        print(" => The encrypted string is:",encrypted)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print("=>",e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def PasswordGen(length):
    try:
        lower = "abcdefghijklmnopqrstuvwxyz"
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        numbers = "123456789"
        symbols = "[]{}()*;/,-_+%@$^!&"

        all = lower + upper + numbers + symbols
        Password = "".join(random.sample(all,length))
        print("=> Your generated password is:",Password)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print("=>",e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def Domain(domain):
    try:
        result = subprocess.check_output(['tracert',domain])
        decoded = result.decode('ascii')
        print("=>",decoded)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except:
        print("=> Cannot trace the route")
        print("-------------------------------------------------------------------------------------------------------------------------------")

def DNSlookup(domain):
    try:
        result = subprocess.check_output(['nslookup',domain])
        decode = result.decode('ascii')
        print("=>",decode)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print("=>",e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def IP_req():
    try:
        print("Here's your system's IP configurations")
        result = os.system(('ipconfig'))
        print("=>",result)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print("=>",e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def ARP():
    try:
        ip = input("Enter ip address to change: ")
        mac_addr = input("Enter MAC address: ")
        if mac_addr == "":
            print("=> MAC addr cannot be empty")
            mac_addr = input("=> Enter MAC address: ")
            result = subprocess.check_output(['arp','-s',ip,mac_addr])
            print("=>",result.decode('ascii'))
            view = input("=> Do you wish to view the current ARP cache? (yes/no): ")
            if view == "yes":
                view_cache = subprocess.check_output(['arp','-a'])
                print("=>",view_cache.decode('ascii'))
                ("-------------------------------------------------------------------------------------------------------------------------------")
            elif view == "no":
                print("Quitting")
                print("-------------------------------------------------------------------------------------------------------------------------------")
            else:
                print("=> Enter either yes or no")
        else:
            result = subprocess.check_output(['arp','-s',ip,mac_addr])
            print(result.decode('ascii'))
            view = input("Do you wish to view the current ARP cache? (yes/no): ")
            if view == "yes":
                view_cache = subprocess.check_output(['arp','-a'])
                print("=>",view_cache.decode('ascii'))
                ("-------------------------------------------------------------------------------------------------------------------------------")
            elif view == "no":
                print("Quitting")
                print("-------------------------------------------------------------------------------------------------------------------------------")
            else:
                print("Enter either yes or no")   
    except Exception as e:
        print("=>",e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def PasswordEncrypt():
        user_encrypt = input("[+] Enter your password you want to be encrypted: ").encode()
        print("")
        try:
            key = Fernet.generate_key()
            crypto = Fernet(key)
            pw = crypto.encrypt(user_encrypt)
            print("=> Your encrypted password is:",pw)
            print("-------------------------------------------------------------------------------------------------------------------------------")
        except Exception as e:
            print("=>",e)
            print("-------------------------------------------------------------------------------------------------------------------------------")   
    
def main():
    # print()
    print("[+] LIST: ")
    print("-------------------------------------------------------------------------------------------------------------------------------")
    print("[+] Press '1' for Banner Grabbing (Requires Net Connectivity)")
    print("[+] Press '2' for Port Scanning (Requires Net Connectivity)")
    print("[+] Press '3' for Pinging a Domain (Requires Net Connectivity)")
    print("[+] Press '4' for Listening on a Specific Port (Requires Net Connectivity)")
    print("[+] Press '5' for Checking Wifi Networks")
    print("[+] Press '6' for Caesar Encryption")
    print("[+] Press '7' for Password Generation")
    print("[+] Press '8' for Tracerouting (Requires Net Connectivity)")
    print("[+] Press '9' for DNS lookup (Requires Net Connectivity)")
    print("[+] Press '10' for Viewing your System's IP ")
    print("[+] Press '11' for Changing IP and MAC addr (Administrator)")
    print("[+] Press '12' for Encrypting(AES SYMMETRIC ALGORITHM) your password")
    print("[+] Press '13' for Quitting the Framework")
    print("-------------------------------------------------------------------------------------------------------------------------------")

    while True:
        choice = int(str((input("[+] Enter your choice: "))))
        print("-------------------------------------------------------------------------------------------------------------------------------")
        if choice == 1:
            ip = input("[+] Enter ip address: ")
            port = int(input("[+] Specify port: "))
            print("-------------------------------------------------------------------------------------------------------------------------------")
            Banner(ip,port)
        elif choice == 2:
            ip = input("[+] Enter ip address: ")
            port = int(input("[+] Specify port: "))
            print("-------------------------------------------------------------------------------------------------------------------------------")
            PortScan(ip,port)
        elif choice == 3:
            hostname = input("[+] Enter ip address/domain: ")
            print("-------------------------------------------------------------------------------------------------------------------------------")
            Ping(hostname)
        elif choice == 4:
            ip = input("[+] Enter ip: ")
            port = int(input("[+] Specify a port to listen: "))
            print("-------------------------------------------------------------------------------------------------------------------------------")
            Listener(ip,port)
        elif choice == 5:
            interface = input("[+] Enter your interface name: ")
            print("-------------------------------------------------------------------------------------------------------------------------------")
            Wifi(interface)
        elif choice == 6:
            plain_text = input("[+] Enter word/string to encrypt: ")
            shift = int(input("[+] Enter the shift value: "))
            print("-------------------------------------------------------------------------------------------------------------------------------")
            Caesar(plain_text,shift)
        elif choice == 7:
            length = int(input("Enter the length of the password to be generated: "))
            print("-------------------------------------------------------------------------------------------------------------------------------")
            PasswordGen(length)
        elif choice == 8:
            domain = input("Enter the domain/ip address: ")
            print("-------------------------------------------------------------------------------------------------------------------------------")
            Domain(domain)
        elif choice == 9:
            domain = input("Enter the domain/ip address: ")
            print("-------------------------------------------------------------------------------------------------------------------------------")
            DNSlookup(domain)
        elif choice == 10:
            IP_req()
        elif choice == 11:
            ARP()
        elif choice == 12: 
            PasswordEncrypt()
        elif choice == 13:
            print("Bye! Hope to see you soon...")
            print("-------------------------------------------------------------------------------------------------------------------------------")
            print("")
            break
        else:
            print("Enter valid number")
main()

   

