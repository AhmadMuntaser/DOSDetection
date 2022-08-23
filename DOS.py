# !/usr/bin/python
from __future__ import print_function
from scapy.all import *

ssid=input("enter your AP name... \n")
deauth_packet_counter = 0
mac = ""

def ahmad(packet):
	global ssid
	global mac
	global deauth_packet_counter

	if packet.type==0x00 and packet.subtype==0x0C:
		deauth_packet_counter = deauth_packet_counter + 1
		print("\r DOS attack detected : " + str(deauth_packet_counter) + "againest ssid : " +  ssid+ "  ", end=" ")	
			
	if packet.haslayer(Dot11Beacon):
		if packet.info == ssid:
			mac = packet.addr2


sniff(iface="wlan0mon",prn=ahmad,count=0)