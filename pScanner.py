#################################################
# Mike Solie                                    #
# Version 1.2 (Works and prints as expected)    #
# Network Mapper/Port Scanner                   #
#                                               #
# Description:                                  #
# Takes a host and subnet, using ARP to see     #
# which hosts are up. If a host responds it     #
# perfonms a port scan on whichever ports are   #
# indicated                                     #
#                                               #
#################################################

#####
# Library imports
# Argparse to pass argumnets through the command line
# Socket to use TCP connections to check for Open Ports
# Scapy to use ARP to perform a subnet scan w/o needing ping
#####
import argparse
import socket
from scapy.all import *

# Host variable holds the ipaddress/subnet - will be replaced in future versions
host = '192.168.50.0/24'
# open ports empty list - Not sure this will be staying either
open_ports = []
# Hosts that are up or "answered" the APR request
answered = []

#####
# function: Subnet Scan
# purpose: To use ARP requests to check which hosts are up for the requested subnet
# inputs: IP address/subnet
# returns: A dictionary of ip addresses and mac addresses
#####
def subnet_scan(ip_range):
    # ARP frame variable - where the frame is going
    arp_request_frame = ARP(pdst=ip_range)
    # Broadcast frame variable - broadcast address
    broadcast_frame = Ether(dst='ff:ff:ff:ff:ff:ff')
    # New frame variable/creation - scapy uses the / to combine
    broadcast_request_frame = broadcast_frame/arp_request_frame
    # responses to the request frame
    who_answered = srp(broadcast_request_frame, timeout=0.5, verbose=False)[0]
    # loop that adds each client that responded to a dictionary and appends it to an empty list
    for a in range(0,len(who_answered)):
        clients = {'ip' : who_answered[a][1].psrc, 'mac' : who_answered[a][1].hwsrc}
        answered.append(clients)
    return answered


#####
# function: create connection
# purpose: To check for open ports on devices that were found "up"
# inputs: ip addresses and port range
# returns: information on which ports are open/closed/timed out
#####
def create_connection(lower, upper):
    # port range variable to iterate through
    ports = range(lower, upper + 1)
    # outside for loop to iterate through nothing
    for ip in answered:
        # variable that pulls the ip address from the answered list
        ips = ip['ip']

        # tells the user that the host is up
        print(f'{ips} is up')
        # for loop to iterate through hosts and scan for open ports
        for port in ports:
            print(f'Scannning port {port}...')
            # TCP connection variable
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # timeout length to reduce hanging time
            sock.settimeout(1)
            # try block - tries to connect and/or identifies reasons a connection couldn't be made
            try:
                sock.connect((ips, port))
                print(f'Port {port} open')
                # add open ports to the open_ports list
                is_open = {'ip_a' : ips, 'ports' : port}
                open_ports.append(is_open)
    
            except socket.timeout:
                print(f'Port {port} timeout')
            except ConnectionRefusedError:  
                pass  
            # Close TCP connection
            sock.close()

        print(f'Finished scanning {ips}')
    print(f'Finished scanning')
    return open_ports

#####
# function: main
# purpose: to run the program
# inputs: CL arguments
# returns: nothing
#####
def main():
    # scan variable holds the subnet_scan function
    scan = subnet_scan(host)
    # connect variable holds the create_connection variable with the port range
    connect = create_connection(1, 1024)

    # organizes information and prints to terminal
    print('------------------------------------------------\nIP Address\t   MAC Address\t     Open Ports\n------------------------------------------------')
    for answers in answered:
        ip_address = answers['ip']
        mac_address = answers['mac']
        print(f'{ip_address}\t{mac_address}')
        for port in open_ports:
            open_port_s = port['ports']
            if answers['ip'] == port['ip_a']:
                print(f'{ip_address}\t{mac_address}\t{open_port_s}')



# call to start program
##----->
main()
##<-----
# program end
