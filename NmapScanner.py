#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("Welcome to the nmap automation tool")
print("===========================================================")

ip_addr = input("Enter the target IP address: ")
print("IP entered is: ", ip_addr)
type(ip_addr)

response = input("""\nPlease enter the type of scan to run
                    1)SYN ACK Scan
                    2)UDP Scan
                    3)Comprehensive Scan""")
print("you have selected option: ", response)

if response == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports are: ", scanner[ip_addr]['tcp'].keys())
elif response == '2':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports are: ", scanner[ip_addr]['udp'].keys())
elif response == '3':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports are: ", scanner[ip_addr]['tcp'].keys())
elif response >= '4':
    print("Enter only valid options.")