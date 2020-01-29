import csv #importing library to read csv

def cIP(ip, fwallIP): # function to check IP range/input
    IPrange = fwallIP.find("-")
    if IPrange == -1:
        return ip == fwallIP
    else:
        mini = fwallIP[:IPrange]
        mini = int(mini.replace(".", ""))
        max = fwallIP[IPrange + 1:]
        max = int(max.replace(".", ""))
        ip = int(ip.replace(".", ""))
        return (mini <= ip) and (ip <= max)
        
def cport(port, fwallport): #function to check port range/input
    portrange = fwallport.find("-")
    if portrange != -1:
        mini = int(fwallport[:portrange])
        max = int(fwallport[portrange + 1:])
        return (mini <= port) and (port <= max)
    else:
        fwallport = int(fwallport)
        return port == fwallport

class fwall(object):
    input = {}
    def __init__(self, file):
        # creating ruleset dictionaries
        self.input["inbound"] = {}
        self.input["outbound"] = {}
        self.input["inbound"]["tcp"] = {}
        self.input["inbound"]["udp"] = {}
        self.input["outbound"]["tcp"] = {}
        self.input["outbound"]["udp"] = {}
        inputtextfile = open('test.csv', 'r')
        filehandle = csv.reader(inputtextfile)

        for row in filehandle:
            direction, protocol, port, ip = row
            #print(direction, protocol, port, ip)
            port_dict = self.input[direction][protocol]
            if port in port_dict:
              self.input[direction][protocol][port] += [ip]
            else:
              self.input[direction][protocol][port] = [ip]

    def accept_packet(self, direction, protocol, port, ip_address):
        try:
            ports = self.input[direction][protocol]
        except KeyError:
            return False
        for port_val, ips in ports.items():
            if cport(port, port_val):
                for ip in ips:
                    if cIP(ip_address, ip):
                        return True
        return False

fw = fwall("test.csv")
print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
