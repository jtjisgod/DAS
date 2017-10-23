from CommandModule import *
from scapy.all import *
from SSLStrip import NetSetup
from netfilterqueue import NetfilterQueue

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
        # iptablesOpt = "-I INPUT -d 192.168.0.8/24 -j NFQUEUE --queue-num " + str(responseID)
        # NetSetup.getInstance().ipTables(iptablesOpt)


        # DNS-Spoofing
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
        print(packet)
        packet.accept()
        pass


    def dnsResponseCallback(self, packet) :
        # pkt = IP(packet.get_payload)
        # packet.set_payload(str(pkt))
        packet.accept()
        print(packet)
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
        payload = IP(packet.get_payload())
    else :
        print("It is not a DNS packet")
        pass

    if IP in pkt :
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 :
            print(str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + str(pkt.getlayer(DNS).qd.qname) + ")")
        elif pkt.haslayer(DNS) and pkt.getlayer(DNS).rr == 0 :
            print(str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + str(pkt.getlayer(DNS).qd.qname) + ")")

"""


if __name__ == '__main__' :
    a = DnsSpoofing()
    a.run();
