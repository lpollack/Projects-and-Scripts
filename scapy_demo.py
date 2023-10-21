from scapy.all import *

#create icmp packet to chosen destination. Change this
ip_layer = IP(dst="examplehere.com")
icmp_layer = ICMP()
packet = ip_layer / icmp_layer
r = send(packet)

#print(packet.show())
#can call wireshark
#wireshark(packet)

#ARP scan
#arp target protocol address. local subnet our machine is on
#ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.10.0.24"), timeout=3, verbose=False)
#for i in ans:
#	print(i)
	#identify hosts
#	print(i[1].psrc)

#tcp flags
SYN = 0x02
RST = 0x04
ACK = 0x10
"""
#common ports to scan
for port in [22, 80, 139, 443, 445, 8080]:
	#send packet and only return first packet that answers
	tcp_connect = sr1(IP(dst="127.0.0.1")/TCP(sport=RandShort(), dport=port, flags="S"), timeout=1, verbose=False)
	if tcp_connect and tcp_connect.haslayer(TCP):
		response_flags = tcp_connect.getlayer(TCP).flags
		if response_flags == (SYN + ACK):
			send_rst = send(IP(dst="127.0.0.1")/TCP(sport=RandShort(), dport=port, flags="AR"), verbose=False)
			print("{} is open!".format(port))
		elif response_flags == (RST + ACK):
			print("{} is closed!".format(port))
		else:
			print("{} is closed!".format(port))
"""
from scapy.layers.http import HTTPRequest

#sniffer
def process(packet):
	if packet.haslayer(HTTPRequest):
		print(packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode())

#sniff(filter="port 80", prn=process, store=False)

#read pcap
scapy_cap = rdpcap("filename.pcap")
for packet in scapy_cap:
	if packet.getlayer(ICMP):
		print(packet.load)
		


