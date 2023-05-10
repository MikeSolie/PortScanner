#################################################
# Mike Solie                                    #
# Version 1.3 (Write File works correctly)      #
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
from datetime import datetime

# Host variable holds the ipaddress/subnet - will be replaced in future versions
host = 'CHANGE THIS'
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
        print(f'[+] {ips} is up')  # Verbose Output?
        # for loop to iterate through hosts and scan for open ports
        for port in ports:
            print(f'Scanning port {port}...')  
            # TCP connection variable
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # timeout length to reduce hanging time
            sock.settimeout(0.5)
            # try block - tries to connect and/or identifies reasons a connection couldn't be made
            try:
                sock.connect((ips, port))
                print(f'[+] Port {port} open')  
                is_open = {'ip_a' : ips, 'ports' : port}
                open_ports.append(is_open)
            except socket.timeout:
                pass ?
            except ConnectionRefusedError: 
                pass 
            except socket.gaierror:
                pass
            except socket.error:
                pass
            
            # Close TCP connection
            finally:
                sock.close()
        print(f'Finished scanning {ips}')  
    print(f'Finished scanning')  
    return open_ports


#####
# function: terminal_output
# purpose: organize information and print to terminal 
# inputs: answered and open_ports
# returns: prints, no returns
#####
def terminal_output():
    # prints column headers
    print(f'------------------------------------------------\nIP Address\t   MAC Address\t     Open Ports\n------------------------------------------------')
    # for loop that pulls the dictionary out of the list and grabs the output of the ip and mac values
    for answers in answered:
            ip_address = answers['ip']
            mac_address = answers['mac']
            # prints the values
            print(f'{ip_address}\t{mac_address}')
            # loop that pulls the dictionary out of the list and grabs the output from the ports value
            for port in open_ports:
                open_port_s = port['ports']
                # if statment that checks if ip addresses in both dictionaries are the same
                if answers['ip'] == port['ip_a']:
                    # prints the the mac and open port of a given ip address
                    print(f'{ip_address}\t{mac_address}\t{open_port_s}')
    
    
#####
# function: write file
# purpose: To write which hosts are up and their open ports into a document
# inputs: answered and open ports
# returns: nothing, it writes a file
#####
def write_file(filepath):
    # opens the file to write, uses filepath to be called in main()
    with open(filepath, 'w') as f:
        # this code is essentially the same as the ouput function, except it uses the f.write function to write the information to a txt file
        # there are no timestamps in this function
        f.write('------------------------------------------------\nIP Address\t   MAC Address\t     Open Ports\n------------------------------------------------\n')
        for answers in answered:
            ip_address = answers['ip']
            mac_address = answers['mac']
            f.write(f'{ip_address}\t{mac_address}')
            # starts a new line 
            f.write('\n')
            for port in open_ports:
                open_port_s = port['ports']
                if answers['ip'] == port['ip_a']:
                    f.write(f'{ip_address}\t{mac_address}\t{open_port_s}')
                    f.write('\n')


#####
# function: main
# purpose: to run the program
# inputs: CL arguments
# returns: nothing
#####
def main():
    # variable that stores the date at time of script start
    start_time = datetime.now()
    # prints the start time variable
    print(f'------------------------------------------------\nScanning started at {start_time}\n------------------------------------------------')
    # scan variable holds the subnet_scan function
    subnet_scan(host)
    # connect variable holds the create_connection variable with the port range
    create_connection(1, 100) # CHANGE THIS <-- Port Range
    # write a file
    write_file('.\Scan_Results.txt')
    # terminal print
    terminal_output()
    # end time variable - time at completion
    end_time = datetime.now()
    # variable that stores the result of the endtime minus the start time, providing elapsed time
    finished = end_time - start_time
    # print statement that outputs the time at completion and the elapsed time
    print(f'------------------------------------------------\nScanning Completed at {end_time} in {finished}\n------------------------------------------------')
    

# call to start program
##----->
main()
##<-----

