#!/usr/bin/env python3

"""
Generate a test PCAP file for testing the packet analyzer
"""

from scapy.all import IP, TCP, UDP, ICMP, Ether, DNS, DNSQR, Raw, wrpcap
import random

# Create a list to store packets
packets = []

# Generate some TCP packets with retransmissions and out-of-order packets
for i in range(10):
    # Create a TCP packet
    tcp_packet = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=1234, dport=80, seq=i)
    packets.append(tcp_packet)
    
    # Add a retransmission for some packets
    if i % 3 == 0:
        retrans_packet = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=1234, dport=80, seq=i)
        packets.append(retrans_packet)

# Generate some out-of-order packets
for i in range(5):
    seq_num = 20 - i  # Reverse order
    ooo_packet = Ether()/IP(src="192.168.1.3", dst="192.168.1.4")/TCP(sport=2345, dport=443, seq=seq_num)
    packets.append(ooo_packet)

# Generate some UDP packets
for i in range(5):
    udp_packet = Ether()/IP(src="192.168.1.5", dst="192.168.1.6")/UDP(sport=5678, dport=53)
    packets.append(udp_packet)

# Generate some ICMP packets
for i in range(3):
    icmp_packet = Ether()/IP(src="192.168.1.7", dst="192.168.1.8")/ICMP()
    packets.append(icmp_packet)

# Generate some DNS packets
for i in range(3):
    dns_packet = Ether()/IP(src="192.168.1.9", dst="8.8.8.8")/UDP(sport=random.randint(1024, 65535), dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
    packets.append(dns_packet)

# Generate some HTTP-like packets
for i in range(3):
    http_req = Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/TCP(sport=random.randint(1024, 65535), dport=80)/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    packets.append(http_req)
    http_resp = Ether()/IP(src="93.184.216.34", dst="192.168.1.10")/TCP(sport=80, dport=http_req[TCP].sport)/Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    packets.append(http_resp)

# Write packets to a PCAP file
output_file = "sample.pcap"
print(f"Writing {len(packets)} packets to {output_file}")
wrpcap(output_file, packets)
print(f"PCAP file created successfully: {output_file}")