from CommandModule import *
from scapy.all import *
from time import sleep
import subprocess

class SSLStrip(CommandModule) :
    command = "ssl"
    outline = "This is a command which is stripping 'https://' and turning them into 'http://'"
    manual = "This command can sniff the data which someone communicates on ssl"

    def run(self) :
        if False == NetSetup.getInstance().checkIpForward() :
            NetSetup.getInstance().ipForward(1)


        checkOpt = "\"tcp dpt:80 redir ports 10000\""
        iptablesOpt = "-t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 10000"
        if False == NetSetup.getInstance().checkIpTables(checkOpt) :
            NetSetup.getInstance().ipTables(iptablesOpt)


        # ssl-strip & arp
        pass


    def sslStrip(self) :
        pass



class ClientConnection:
    pass


class ServerConnection:
    pass


class NetSetup() :

    instance = None

    @staticmethod
    def getInstance() :
        if None == NetSetup.instance :
            NetSetup.instance = NetSetup()
        return NetSetup.instance


    # IP Forwarding : be router.
    # If IP Forward is set, all packet allowed.
    # @staticmethod
    def ipForward(self, isForward) :
        print("# Set IP Forwarding...")
        ipForwardCommand = "echo " + str(isForward) +  " > /proc/sys/net/ipv4/ip_forward"
        try :
            subprocess.run(ipForwardCommand, shell=True)
            sleep(1)
        except Exception as e:
            pass


    # Check if IP Forward is set.
    # @staticmethod
    def checkIpForward(self) :
        print("# Check IP Forawrding...")
        checkIpForwardCommand = "cat /proc/sys/net/ipv4/ip_forward"
        try :
            res = (1 == int(subprocess.check_output(checkIpForwardCommand, shell=True)))
        except Exception as e:
            return False
        return res


    # IP Table : packet filtering tool(= firewall).
    # It doesn't filter the packet, it is just the rule of filtering packet.
    # @staticmethod
    def ipTables(self, opt) :
        print("# Set a rule to IP Table...")
        ipTableCommand  = "iptables " + str(opt)
        try :
            subprocess.run(ipTableCommand, shell=True)
            sleep(1)
        except Exception as e:
            pass


    # Check if IP Table is added our redirection(port 80 to 10000) rules.
    # @staticmethod
    def checkIpTables(self, opt) :
        print("# Check IP Tables...")
        checkIpTableCommand = "iptables -t nat -L -n | grep " + str(opt)
        try :
            res = (None != subprocess.check_output(checkIpTableCommand, shell=True))
        except Exception as e:
            return False
        return res



if __name__ == '__main__':
    sslStrip = SSLStrip()
    sslStrip.run()
