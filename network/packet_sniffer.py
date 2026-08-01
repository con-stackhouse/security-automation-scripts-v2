'''
Network Packet Sniffer & Analyzer
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona
Date: October 2024

Purpose:
    Captures and analyzes network packets using raw sockets.
    Identifies protocols (TCP/UDP/ICMP) and tracks communication patterns.

Security Application:
    - Network forensics
    - Traffic analysis
    - Intrusion detection
    - Protocol identification
    - Network monitoring

Usage:
    sudo python3 packet_sniffer.py
    (Requires administrator/root privileges)

Requirements:
    - Python 3.x
    - prettytable: pip install prettytable
    - Administrator/root privileges
    - Windows OS (uses Windows-specific socket options)

Output:
    Real-time packet capture showing:
    - Source and destination IP addresses
    - Protocol identification
    - Frequency analysis of communications

Security Note:
    Only use on networks you own or have explicit permission to monitor.
'''

'''
BLACK HAT PYTHON
SNIFFER EXPERIMENT WITH MODIFICATIONS

STRUCT UNPACK FORMATTING NOTES
Format  C Type              Python type      Standard size
x       pad byte            no value
c       char                bytes of length  1
b       signed char         integer          1
B       unsigned char       integer          1
?       _Bool               bool             1
h       short               integer          2
H       unsigned short      integer          2
i       int                 integer          4
I       unsigned int        integer          4
l       long                integer          4
L       unsigned long       integer          4
q       long long           integer          8
Q       unsigned long long  integer          8
n       ssize_t             integer
N       size_t              integer
e       (6)                 float            2
f       float               float            4
d       double              float            8
s       char[]              bytes
p       char[]              bytes
P       void*               integer

ENCODING
Character  Byte order              Size        Alignment
<          little-endian           standard    none
>          big-endian              standard    none
!          network (= big-endian)  standard    none
'''

import socket
import ipaddress
import struct

from prettytable import PrettyTable

# Get the HOST to Sniff From
hostname = socket.gethostname()
HOST = socket.gethostbyname(hostname)

# Number of packets to capture before reporting
PACKET_LIMIT = 10000


class IP:
    def __init__(self, buff=None):

        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # human readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}


def main():

    socket_protocol = socket.IPPROTO_IP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))

    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    captureDict = {}

    try:
        for i in range(PACKET_LIMIT):

            packet = sniffer.recvfrom(65565)   # Wait for Packet
            basePacket = packet[0]             # Extract Packet Data from tuple
            pckHeader = basePacket[0:20]       # Extract the packet header

            ipOBJ = IP(pckHeader)              # Create the IP Object

            # Lookup the protocol name
            protocolName = ipOBJ.protocol_map.get(ipOBJ.protocol_num, "Unknown")

            print("SRC-IP  :", ipOBJ.src_address)
            print("DST-IP  :", ipOBJ.dst_address)
            print("Protocol:", protocolName)

            key = (ipOBJ.src_address, ipOBJ.dst_address, protocolName)
            captureDict[key] = captureDict.get(key, 0) + 1
    finally:
        # Always disable promiscuous capture, even if interrupted or an
        # exception is raised mid-capture
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    tbl = PrettyTable(["Occurs", "SRC", "DST", "Protocol"])
    for (src, dst, proto), count in captureDict.items():
        tbl.add_row([count, src, dst, proto])

    print(tbl.get_string(sortby="Occurs", reversesort=True))


if __name__ == '__main__':
    main()
