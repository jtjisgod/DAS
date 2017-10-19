from CommandModule import *
# from scapy.all import *
import subprocess

class SSLStrip(CommandModule) :
    command = "ssl"
    outline = "This is a command which is stripping 'https://' and turning them into 'http://'"
    manual = "This command can sniff the data which someone communicates on ssl"
    kIpForwardPathString = "/proc/sys/net/ipv4/ip_forward"


    def run(self) :
        print("## SSL-STRIP Start...")
        self.ipForward()
        if False == self.checkIpForward() :
            pass

        self.ipTables()
        if False == self.checkIpTables() :
            pass

        # ssl-strip & arp
        pass


    def sslStrip(self) :
        pass


    # IP Forwarding : be router.
    # If IP Forward is set, all packet allowed.
    def ipForward(self) :
        print("# IP Forawrding...")
        ipForwardCommand = "echo 1 > " + self.kIpForwardPathString
        try :
            subprocess.run(ipForwardCommand, shell=True)
            sleep(1)
        except Exception as e:
            pass


    # Check if IP Forward is set.
    def checkIpForward(self) :
        print("# Check IP Forawrding...")
        checkIpForwardCommand = "cat " + self.kIpForwardPathString
        try :
            res = (1 == int(subprocess.check_output(checkIpForwardCommand, shell=True)))
        except Exception as e:
            return False
        return res


    # IP Table : packet filtering tool(= firewall).
    # It doesn't filter the packet, it is just the rule of filtering packet.
    def ipTables(self) :
        print("# Add a rule to IP Table...")
        ipTableCommand  = "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 10000"
        try :
            subprocess.run(ipTableCommand, shell=True)
            sleep(1)
        except Exception as e:
            pass

    # Check if IP Table is added our redirection(port 80 to 10000) rules.
    def checkIpTables(self) :
        print("# Check IP Tables...")
        checkIpTableCommand = "iptables -t nat -L -v -n | grep \"dpt:80 redir ports 10000\""
        try :
            res = (None != subprocess.check_output(checkIpTableCommand, shell=True))
        except Exception as e:
            return False
        return res


    def arpSpoofing(self) :
        pass

sslStrip = SSLStrip()
sslStrip.run()
