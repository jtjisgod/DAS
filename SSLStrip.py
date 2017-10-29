from CommandModule import *
from scapy.all import *
from time import sleep
from NetEnvManager import *
import subprocess

class SSLStrip(CommandModule) :
    command = "ssl"
    outline = "This is a command which is stripping 'https://' and turning them into 'http://'"
    manual = "This command can sniff the data which someone communicates on ssl"

    def run(self) :
        if False == NetEnvManager.getInstance().checkIpForward() :
            NetEnvManager.getInstance().ipForward(1)


        table = "-t nat"
        checkOpt = "\"tcp dpt:80 redir ports 10000\""
        iptablesOpt = table + " -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 10000"
        if False == NetEnvManager.getInstance().checkIpTables(table, checkOpt) :
            NetEnvManager.getInstance().ipTables(table, iptablesOpt)


        # ssl-strip & arp
        pass


    def sslStrip(self) :
        pass



class ClientConnection:
    pass


class ServerConnection:
    pass


if __name__ == '__main__':
    sslStrip = SSLStrip()
    sslStrip.run()
