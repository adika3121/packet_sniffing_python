# Importing the necessary modules
import logging
from datetime import datetime
import subprocess
import sys
# import wxPython
# from wx import xrc

# This will suppress all messages that have a lower level of seriousness than error messages, while running or loading Scapy
from pip._vendor import ipaddress
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

########################


#############################
try:
    from scapy.all import *

except ImportError:
    print("Scapy package for Python is not installed on your system.")
    sys.exit()

# Printing a message to the user; always use "sudo scapy" in Linux!
print("\n! Make sure to run this program as ROOT !\n")

# Asking the user for some parameters: interface on which to sniff, the number of packets to sniff, the time interval to sniff, the protocol
# list_iface = get_windows_if_list()
# print(list_iface)
# Asking the user for input - the interface on which to run the sniffer
net_iface = input("* Enter the interface on which to run the sniffer (e.g. 'enp0s8'): ")

# Setting network interface in promiscuous mode
'''
Wikipedia: In computer networking, promiscuous mode or "promisc mode"[1] is a mode for a wired network interface controller (NIC) or wireless network interface controller (WNIC) that causes the controller to pass all traffic it receives to the central processing unit (CPU) rather than passing only the frames that the controller is intended to receive.
This mode is normally used for packet sniffing that takes place on a router or on a computer connected to a hub.
'''

try:
    subprocess.call(["ifconfig", net_iface, "promisc"], stdout=None, stderr=None, shell=False)

except:
    print("\nFailed to configure interface as promiscuous.\n")

else:
    # Executed if the try clause does not raise an exception
    print("\nInterface %s was set to PROMISC mode.\n" % net_iface)

#### ini arp-nya
# pkts = sniff(filter="arp", count=10)
# print(pkts.summary())
##### Kalo mau dnsnya cari di udp port 53

# Asking the user for the number of packets to sniff (the "count" parameter)
pkt_to_sniff = input("* Enter the number of packets to capture (0 is infinity): ")

# Considering the case when the user enters 0 (infinity)
if int(pkt_to_sniff) != 0:
    print("\nThe program will capture %d packets.\n" % int(pkt_to_sniff))

elif int(pkt_to_sniff) == 0:
    print("\nThe program will capture packets until the timeout expires.\n")

# Asking the user for the time interval to sniff (the "timeout" parameter)
time_to_sniff = input("* Enter the number of seconds to run the capture: ")

# Handling the value entered by the user
if int(time_to_sniff) != 0:
    print("\nThe program will capture packets for %d seconds.\n" % int(time_to_sniff))

# Asking the user for any protocol filter he might want to apply to the sniffing process
# For this example I chose three protocols: ARP, BOOTP, ICMP
# You can customize this to add your own desired protocols
proto_sniff = input("* Enter the protocol to filter by (arp|bootp|icmp|0 is all): ")

# Considering the case when the user enters 0 (meaning all protocols)
if (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    print("\nThe program will capture only %s packets.\n" % proto_sniff.upper())

elif (proto_sniff) == "0":
    print("\nThe program will capture all protocols.\n")

# Asking the user to enter the name and path of the log file to be created
file_name = input("* Please give a name to the log file: ")

# Creating the text file (if it doesn't exist) for packet logging and/or opening it for appending
sniffer_log = open(file_name, "a")


# def protocol_name(num):
#     if num

def protocol_name(proto):
    if proto == "1":
        return "ICMP"
    elif proto == "6":
        return "TCP"
    elif proto == "17":
        return "UDP"
    else:
        return "Id " + proto


# This is the function that will be called for each captured packet
# The function will extract parameters from the packet and then log each packet to the log file
def packet_log(packet):
    # Getting the current timestamp
    waktu = datetime.now()
    now = waktu.strftime("%m/%d/%Y, %H:%M:%S")

    # Writing the packet information to the log file, also considering the protocol or 0 for all protocols
    if proto_sniff == "0":
        protokol = protocol_name(str(packet[0].proto))
        # Writing the data to the log file
        print("Time: " + str(now) + " Protocol: " + protokol + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst,
              file=sniffer_log)

    elif proto_sniff == "port 53":
        # if packet.haslayer(IPv6) and packet.haslayer(DNS) and packet.getlayer(DNS).qr ==0:
        #     ip_src = packet[IPv6].src
        #     ip_dst = packet[IPv6].dst
        #     encoding = "utf-8"
        #     print(ip_src + " -> " + ip_dst + " : ( " + packet.getlayer(DNS).qd.qname + " )")
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                print(str(ip_src) + " -> " + str(ip_dst) + " : ( " + str(packet.getlayer(DNS).qd.qname) + " )",file=sniffer_log)

    elif proto_sniff == "arp":
        if packet[ARP].op == 1:
            print("Waktu: " + str(now) + " IP " + str(
                packet[ARP].psrc) + " bertanya siapa pemilik perangkat dengan IP " + str(packet[ARP].pdst),
                  file=sniffer_log)
        elif packet[ARP].op == 2:
            print("Waktu: " + str(now) + " IP " + str(packet[ARP].psrc) + " merupakan pemilik dari perangkat " + str(
                packet[ARP].hwsrc), file=sniffer_log)

    elif proto_sniff=="icmp":
        if packet[ICMP].type == 8:
            print("Waktu: "+ str(now)+ "IP: "+ str(packet[IP].src)+" melakukan request ke IP: "+ str(packet[IP].dst),file=sniffer_log)
        elif packet[ICMP].type == 0:
            print("Waktu: "+ str(now)+ "IP: "+ str(packet[IP].src)+" melakukan reply ke IP: "+ str(packet[IP].dst),file=sniffer_log)

    elif proto_sniff == "bootp":
        # Writing the data to the log file
        protokol = str(packet[0].proto)
        print(
            "Time: " + str(now) + " Protocol: " + str(packet[0].proto) + " SMAC: " + packet[0].src + " DMAC: " + packet[
                0].dst, file=sniffer_log)


# Printing an informational message to the screen
print("\n* Starting the capture...")

# Running the sniffing process (with or without a filter)
if proto_sniff == "0":
    sniff(iface=net_iface, count=int(pkt_to_sniff), timeout=int(time_to_sniff), prn=packet_log)

# elif proto_sniff == "arp":
#     sniff(iface=net_iface, filter=proto_sniff, count=int(pkt_to_sniff), timeout=int(time_to_sniff), prn=packet_log)

elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp") or (proto_sniff == "port 53"):
    sniff(iface=net_iface, filter=proto_sniff, count=int(pkt_to_sniff), timeout=int(time_to_sniff), prn=packet_log)

else:
    print("\nCould not identify the protocol.\n")
    sys.exit()

# Printing the closing message
print("\n* Please check the %s file to see the captured packets.\n" % file_name)

# Closing the log file
sniffer_log.close()
