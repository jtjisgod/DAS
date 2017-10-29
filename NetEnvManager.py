from time import sleep
import subprocess


class NetEnvManager() :

    instance = None

    @staticmethod
    def getInstance() :
        if None == NetEnvManager.instance :
            NetEnvManager.instance = NetEnvManager()
        return NetEnvManager.instance


    # IP Forwarding : be router.
    # If IP Forward is set, all packet allowed.
    def ipForward(self, isForward) :
        print("# Set IP Forwarding...")
        ipForwardCommand = "echo " + str(isForward) +  " > /proc/sys/net/ipv4/ip_forward"
        try :
            subprocess.run(ipForwardCommand, shell=True)
            sleep(1)
        except Exception as e:
            pass


    # Check if IP Forward is set.
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
    def ipTables(self, opt) :
        print("# Set a rule to IP Table...")
        ipTableCommand  = "iptables " + str(opt)
        try :
            subprocess.run(ipTableCommand, shell=True)
            sleep(1)
        except Exception as e:
            pass


    # Check if IP Table is added our redirection(port 80 to 10000) rules.
    def checkIpTables(self, table, target) :
        print("# Check IP Tables...")
        checkIpTableCommand = "iptables " + str(table) + " -L -n | grep " + str(target)
        try :
            res = (None != subprocess.check_output(checkIpTableCommand, shell=True))
        except Exception as e:
            return False
        return res
