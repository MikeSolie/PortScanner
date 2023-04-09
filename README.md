# Subnet/Port Scanner

This is a Python script designed to check which hosts are up on a specified subnet along with which ports are open on the available hosts. It works by sending out ARP requests to the specified subnet and creating TCP connections to hosts that respond to those requests. Results are then printed to the terminal.

## Getting Started

### Prerequisites

This project requires the following software to be installed on your machine:

1. Python 3.6 or higher
2. Scapy
3. Socket

### Installing

1. Clone the repository

2. Install Scapy
`pip install scapy`

More information here:
`https://scapy.readthedocs.io/en/latest/installation.html`

3. To run the program open the terminal and navigate to the project directory

4. Run by using this command:
`python3 pScanner.py` or `sudo python3 pScanner.py`

## Usage

The script has two main functions: 

`subnet_scan(ip_range)`: This function takes an IP address or subnet as input and returns a list of hosts that are up with the respective MAC addresses.

`create_connection`: This function takes a range of ports to scan and checks which ports are open on the hosts found by the `subnet_scan` function. 

## Example

`python3 pScanner.py`

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
