# Subnet/Port Scanner

This Network Mapper/Port Scanner is a Python script that performs a subnet scan using ARP requests to identify hosts that are up. For each live host, it conducts a port scan to determine which ports are open.

## Getting Started

### Prerequisites

This project requires the following software to be installed on your machine:

1. Python 3.6 or higher
2. Scapy
3. Socket

### Installing

1. Clone the repository

2. Install Scapy
`pip install scapy` or `apt install scapy`

More information here:
`https://scapy.readthedocs.io/en/latest/installation.html`

3. To run the program open the terminal and navigate to the project directory

### Features

Subnet scan using ARP requests
Port scanning on live hosts
Command-line arguments using argparse
Optional file output
Verbosity control

## Usage

`python3 pScanner.py -H [host] -p [first_port] [last_port] -wf /path/to/scan.txt -v`

-H, --host: Specify the IP range or single host to scan (e.g., 192.168.1.1/24 or 192.168.1.100)
-p, --port: Define the port range to scan (e.g., 1 1024)
-wf, --write-file: Provide a file name for text output
-v, --verbose: Increase output verbosity

```
------------------------------------------------
IP Address	MAC Address	     Open Ports
------------------------------------------------
192.168.1.1	00:11:22:33:44:55
192.168.1.1     00:11:22:33:44:55	22
192.168.1.1     00:11:22:33:44:55	80
192.168.1.2     11:22:33:44:55:66       
192.168.1.2     11:22:33:44:55:66	443
------------------------------------------------
```

This means that the hosts `192.168.1.1` and `192.168.1.2` are both up and `192.168.1.1` has both ports 22,80 open while `192.168.1.2` has only 443 open. 

## License

This project is licensed under teh MIT License. See the LICENSE file for details
