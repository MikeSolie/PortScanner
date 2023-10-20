#################################################
# Mike Solie                                    #
# Version 1.4 (Argparse Added and Works)        #
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
# datetime to stamp the scan and show elapsed time
#####
import argparse
import socket
from scapy.all import *
from datetime import datetime

# open ports empty list 
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
def create_connection(port_range, verbose=False):
    # port range variable to iterate through
    ports = range(port_range[0], port_range[1] + 1)
    
    # outside for loop to iterate through nothing
    for ip in answered:
        # variable that pulls the ip address from the answered list
        ips = ip['ip']
        # tells the user that the host is up
        print(f'[+] {ips} is up')  
        
        # for loop to iterate through hosts and scan for open ports
        for port in ports:
            # adds output to terminal if verbose is used
            if verbose:
                print(f'Scanning port {port}...')  # verbose print statement
            # TCP connection variable
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # timeout length to reduce hanging time
            sock.settimeout(0.5)
            # try block - tries to connect and/or identifies reasons a connection couldn't be made
            try:
                # socket connection
                sock.connect((ips, port))
                # Verbose Output
                if verbose:
                    print(f'[+] Port {port} open')
                
                # creates a dictionary with keys ip and ports, values are the actual ip addresses and ports
                is_open = {'ip_a' : ips, 'ports' : port}
                # adds the dictionary to the open_ports list
                open_ports.append(is_open)
            # exceptions that pass to keep the code moving
            except socket.timeout:
                pass
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
def terminal_output(verbose=False):
    if verbose:
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
    try:
        with open(filepath, 'w') as f:
            # this code is essentially the same as the ouput function, except it uses the f.write function to write the information to a txt file
            # there is no timestamp in this function
            f.write('------------------------------------------------\nIP Address\t        MAC Address\tOpen Ports\n------------------------------------------------\n')
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
    finally:
        f.close()


#####
# function: main
# purpose: to run the program
# inputs: CL arguments
# returns: nothing
#####
def main(ip_range, port_range, filepath, verbose):
    # variable that stores the date at time of script start
    start_time = datetime.now().strftime('%m-%d-%Y %H:%M')
    s_time = datetime.now()
    # prints the start time variable
    print(f'------------------------------------------------\nScanning started at {start_time}\n------------------------------------------------')
    
    # scan variable holds the subnet_scan function
    subnet_scan(ip_range)
    # connect variable holds the create_connection variable with the port range
    create_connection(port_range, verbose)
    # write a file
    write_file(filepath)
    # terminal print
    terminal_output(verbose)
    # end time variable - time at completion
    end_time = datetime.now().strftime('%m-%d-%Y %H:%M')
    e_time = datetime.now()
    # variable that stores the result of the endtime minus the start time, providing elapsed time
    finished = e_time - s_time
    
    # print statement that outputs the time at completion and the elapsed time
    
    print(f'------------------------------------------------\nCompleted at {end_time} in {finished}\n------------------------------------------------')

###
# The if block below checks to see if the program is being run as the main program or not
# if this code is imported this section will be skipped
###
if __name__ == '__main__':

    # argument parser variable and description
    parser = argparse.ArgumentParser(description='Python Network Scanner')
    # arguments that will be parsed by the parser
    parser.add_argument('-H', '--host', help='IP Range or Single Jost to Scan - Ex 192.168.1.1/24 or 192.168.1.100', required=True) # -h needs to be uppercase because of -h/help
    parser.add_argument('-p', '--port', help='Port Range to Scan - Ex 1 1024', required=False, type=int, nargs=2)
    parser.add_argument('-wf', '--write-file', help='Write Text File - Ex file.txt', required=False)
    parser.add_argument('-v', '--verbose', help='Increase Output Verbosity', action='store_true')

    # parses the CL arguments and stores them in an object
    args = parser.parse_args()
    
    # call to start program
    ##----->>
    main(args.host, args.port, args.write_file, args.verbose) # adds the arguments to the "main" parameters by order/location
    ##<<-----

