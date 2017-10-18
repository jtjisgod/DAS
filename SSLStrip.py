from CommandModule import *
from scapy.all import *
import subprocess

class SSLStrip(CommandModule) :
    command = "ssl"
    outline = "This is a command which is stripping 'https://' and turning them into 'http://'"
    manual = "This command can sniff the data which communicate on ssl"

    def run(self) :
        print("THIS IS SSL-STRIP")
        res = self.ipForward()
        print(res)
        pass

    def sslStrip(self) :
        pass

    # IP Forwarding : be router.
    def ipForward(self) :
        ipForwardPath = "/proc/sys/net/ipv4/ip_forward"
        ipForwardCommand = "echo 1 > " + ipForwardPath
        checkIpForwardCommand = "cat " + ipForwardPath

        subprocess.run(ipForwardCommand, shell=True)
        res = int(subprocess.check_output(checkIpForwardCommand, shell=True))
        return (0 == res)

    def ipTable(self) :
        pass

    def arpSpoofing(self) :
        pass

sslStrip = SSLStrip()
sslStrip.run()
