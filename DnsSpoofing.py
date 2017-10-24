from CommandModule import *
from scapy.all import *
from SSLStrip import NetSetup
from netfilterqueue import NetfilterQueue
import _thread

class DnsSpoofing(CommandModule) :
    command = "dns"
    outline = "--"
    manual = "--"
    nfqueue = {}


    def getNFQueue(self, num) :
        if None == self.nfqueue.get(num) :
            self.nfqueue[num] = NetfilterQueue()
        return self.nfqueue[num]
	

    def run(self) :
        if False == NetSetup.getInstance().checkIpForward() :
            NetSetup.getInstance().ipForward()


        # This rule of iptables can make a packet which is modifiable.
        queryID = 1
        checkOpt = "\"udp dpt:53 NFQUEUE num " + str(queryID) + "\""
        iptablesOpt = "-t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num " + str(queryID)
        if False == NetSetup.getInstance().checkIpTables(checkOpt) :
            NetSetup.getInstance().ipTables(iptablesOpt)

        responseID = 2
        checkOpt = "\"udp spt:53 NFQUEUE num " + str(responseID) + "\""
        iptablesOpt = "-t nat -A PREROUTING -p udp --sport 53 -j NFQUEUE --queue-num " + str(responseID)
        if False == NetSetup.getInstance().checkIpTables(checkOpt) :
            NetSetup.getInstance().ipTables(iptablesOpt)


        # DNS-Spoofing
        # _thread.start_new_thread(self.dnsCachePoisoning, (queryID, responseID))
        self.dnsCachePoisoning(queryID, responseID)


    def dnsCachePoisoning(self, queryID, responseID) :
        print("# DNS cache poisoning...")
        # sniff(lfilter=lambda x: x.haslayer(DNS), prn=processDns)
        try :
            self.getNFQueue(queryID).bind(queryID, self.dnsQueryCallback)
            self.getNFQueue(responseID).bind(responseID, self.dnsResponseCallback)
            self.getNFQueue(queryID).run()
            self.getNFQueue(responseID).run()
        except KeyboardInterrupt :
            self.getNFQueue(queryID).unbind()
            self.getNFQueue(responseID).unbind()
	

    def dnsQueryCallback(self, packet) :
        # pkt = IP(packet.get_payload)
        # packet.set_payload(str(pkt))
        print("# DNS Query")
        print(packet)
        packet.accept()
        pass


    def dnsResponseCallback(self, packet) :
        # pkt = IP(packet.get_payload)
        # packet.set_payload(str(pkt))
        print("# DNS Response")
        print(packet)
        packet.accept()
        pass


"""
# scapy.layers.dns
# scapy.packet.Packet = packet
def processDns(packet) :
    # DNSQR : DNS Question Record
    if DNSQR in packet and packet.dport == 53 :
	    print("# queries...")
    # DNSRR : DNS Resource Record
    elif DNSRR in packet and packet.sport == 53 :
        print("# response...")
        # payload = IP(packet.get_payload())
    else :
        print("It is not a DNS packet")
        pass

    if IP in packet :
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 :
            print(str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + str(packet.getlayer(DNS).qd.qname) + ")")
        elif packet.haslayer(DNS) and packet.getlayer(DNS).rr == 0 :
            print(str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + str(packet.getlayer(DNS).qd.qname) + ")")
"""



if __name__ == '__main__' :
    a = DnsSpoofing()
    a.run();
