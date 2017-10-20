from CommandModule import *
from scapy.all import *
from time import sleep
import subprocess

class SSLStrip(CommandModule) :
    command = "ssl"
    outline = "This is a command which is stripping 'https://' and turning them into 'http://'"
    manual = "This command can sniff the data which someone communicates on ssl"

    def run(self) :
        if False == NetSetup.checkIpForward() :
            NetSetup.ipForward()

        if False == NetSetup.checkIpTables() :
            NetSetup.ipTables()

        # ssl-strip & arp
        pass


    def sslStrip(self) :
        pass




class NetSetup() :

    # IP Forwarding : be router.
    # If IP Forward is set, all packet allowed.
    @staticmethod
    def ipForward() :
        print("# Set IP Forwarding...")
        ipForwardCommand = "echo 1 > /proc/sys/net/ipv4/ip_forward"
        try :
            subprocess.run(ipForwardCommand, shell=True)
            sleep(1)
        except Exception as e:
            pass


    # Check if IP Forward is set.
    @staticmethod
    def checkIpForward() :
        print("# Check IP Forawrding...")
        checkIpForwardCommand = "cat /proc/sys/net/ipv4/ip_forward"
        try :
            res = (1 == int(subprocess.check_output(checkIpForwardCommand, shell=True)))
        except Exception as e:
            return False
        return res


    # IP Table : packet filtering tool(= firewall).
    # It doesn't filter the packet, it is just the rule of filtering packet.
    @staticmethod
    def ipTables(listenPort=10000) :
        print("# Add a rule to IP Table...")
        ipTableCommand  = "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port " + str(listenPort)
        try :
            subprocess.run(ipTableCommand, shell=True)
            sleep(1)
        except Exception as e:
            pass


    # Check if IP Table is added our redirection(port 80 to 10000) rules.
    @staticmethod
    def checkIpTables(listenPort=10000) :
        print("# Check IP Tables...")
        checkIpTableCommand = "iptables -t nat -L -v -n | grep \"dpt:80 redir ports " + str(listenPort)+"\""
        try :
            res = (None != subprocess.check_output(checkIpTableCommand, shell=True))
        except Exception as e:
            return False
        return res



sslStrip = SSLStrip()
sslStrip.run()
