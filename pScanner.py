#################################################
# Mike Solie                                    #
# CYBR-260-40                                   #
# 01/29/2023                                    #                                 #
# Version 1 (first working version)             #
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
host = 'INPUT HOST/SUBNET'
# open ports empty list - Not sure this will be staying either
open_ports = []
# Hosts that are up or "answered" the APR request
answered = []

#     Add in Argparse for CL arguments                  #
#     remove debug print statements                     #
#     getting this to iterate through felt amaxzing     #
#     time to start documnenting and commenting code    #
#     need to fix the error so it runs on linux         #
#     +++PRIORITY+++ Write the file_write function      # 

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
        print(ips)  # debug line
        # tells the user that the host is up
        print(f'{ips} is up')
        # for loop to iterate through hosts and scan for open ports
        open_ports.append(ips)
        for port in ports:
            #print(f'Scannning port {port}...')  # debug line
            # TCP connection variable
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # timeout length to reduce hanging time
            sock.settimeout(1)
            # try block - tries to connect and/or identifies reasons a connection couldn't be made
            try:
                sock.connect((ips, port))
                print(f'Port {port} open')
                # add open ports to the open_ports list
                open_ports.append(port)
            except socket.timeout:
                print(f'Port {port} timeout')
            except:  # need to change this except and move the if statement up and == 0
                result = sock.connect_ex((host, port))
                if result != 0:
                    print(f'Port {port} is closed')
            # Close TCP connection
            sock.close()
    return open_ports
        #print(f'Finished scanning {ips}')  # debug line
    #print(f'Finished scanning')  #  debug line


#####
# function: write file
# purpose: To write which hosts are up and their open ports into a document
# inputs: answered and open ports
# returns: nothing, it writes a file 
#####
def write_file():
    pass

#####
# function: main
# purpose: to run the program
# inputs: CL arguments
# returns: nothing
#####
def main():
    # unused variable 
    scan = subnet_scan(host)
    print(scan)
    # puts the create_connection function inside the connect variable and defines the port range
    connect = create_connection(PORT, PORT) # INPUT PORT RANGE
    # prints to terminal
    print(connect)
    
# call to start program
##----->
main()
##<-----
# program end
