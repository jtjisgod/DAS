from CommandModule import *

class ArpSpoofing(CommandModule) :
    command = "arp"
    outline = "This command can arp poisoning"
    manual = \
"""=== <TITLE> ===
It command can arp spoof and get some data
==============="""

    def run(self) :
        print("THIS IS ARP-SPOOFING")
        pass
