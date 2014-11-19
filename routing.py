from scapy.all import *
import socket
import sys
import subprocess

class RoutingTable:
    class RoutingTableEntry:
        def __init__(self, dest, netmask=0xFFFFFFFF, gateway, gatewayMAC, interface, localMAC, metric=1):
            self.dest = dest
            self.netmask = netmask
            self.gateway = gateway
            self.gatewayMAC = gatewayMAC
            self.interface = interface
            self.localMAC = localMAC
            self.metric = metric
        def __init__(self, param_list, metric=1):
            self.dest = param_list[0]
            self.netmask = param_list[1]
            self.gateway = param_list[2]
            self.gatewayMAC = param_list[3]
            self.interface = param_list[4]
            self.localMAC = param_list[5]
            self.metric = metric
        def __repr__(self):
            return "dest: " + str(self.dest) 
                + "\tnetmask: " + str(self.netmask) 
                + "\tgateway: " + str(self.gateway)
                + "\tgatewayMAC: " + str(self.gatewayMAC)
                + "\tinterface: " + str(self.interface)
                + "\localMAC: " + str(self.localMAC)
                + "\tmetric: " + str(self.metric)
                + "]"

    def __init__(self):
        self.table = []
    def __repr__(self):
        out_str = "Routing Table\n"
        for entry in self.table:
            out_str += entry + "\n"
        return out_str
    def add_entry(entry):
        self.table.append(entry)
    def find_entry(ip):
        """ Finds most specific routing table entry, breaking ties on metric """
        # Dummmy variable
        bestEntry = RoutingTableEntry(dest, 0xFFFFFFFF, 0x0, "eth0", sys.maxint)

        for dest,netmask,gateway,interface,metric in self.table:
            # Check the subnet
            if dest&netmask == ip&netmask:
                # Always take more specific match
                if netmask < bestEntry.netmask:
                    bestEntry = RoutingTableEntry(dest,netmask,gateway,interface,metric)
                # If equally specific, take entry with lower metric
                elif netmask == bestEntry.netmask:
                     if metric < bestEntry.metric:
                        bestEntry = RoutingTableEntry(dest,netmask,gateway,interface,metric)
        return bestEntry

routing_table = RoutingTable()

#Your per-packet router code goes here
def pkt_callback(pkt):
    print "Received an Ethernet packet. MAC src:", pkt.src, "MAC dst:",pkt.dst
    print pkt.summary()

    #Determine if it is an IP packet. If not then return
    if IP not in pkt:
        return

    dest_ip = pkt[IP].dest

    # Determine if the destination IP is local to this computer. If yes, then return
    # TODO: check all interfaces and drop if to local subnet, not just local host
    local_ip = socket.gethostbyname(socket.gethostname())
    if dest_ip == local_ip:
        return

    # Is the destination *network* in your routing table, if not, send ICMP "Destination host unreachable", then return
    if not any((dest_ip & entry.netmask) == (entry.dest & entry.netmask) for entry in routing_table):
        send(IP(dst=pkt[IP].src)/ICMP(type=3, code=1))
        return

    # Decrement the TTL. If TTL=0, send ICMP for TTL expired and return.
    pkt[IP].ttl -= 1
    if pkt[IP].ttl < 1:
        send(IP(dst=pkt[IP].src)/ICMP(type=11, code=0))
        return

    # Find the next hop (gateway) for the destination *network*
    routing_entry = routing_table.find_entry(dest_ip)
    gateway = routing_entry.gateway

    # Determine the outgoing interface and MAC address needed to reach the next-hop router
    out_iface=routing_entry.interface

    # Modify the SRC and DST MAC addresses to match the outgoing interface and the DST MAC found above
    pkt.src = pkt.dst
    # TODO: WHAT to DO
    pkt.dst = arping(gateway)

    # Update the IP header checksum
    pkt.show2()

    #Send the packet out the proper interface as required to reach the next hop router. Use:
    sendp(pkt, iface=out_iface)

def setup():
    # Disable ICMP echos
    subprocess.Popen('sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1')
    subprocess.Popen('sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1')

    # Ping everything w/ TTL 1 --> ARP created 
    # TODO make sure this works
    arping()

    # Construct Routing Table
    # Hardcoded IP mappings
    lan1 = ["10.1.0.0", 0xFFFFFF00, "10.99.0.1"]
    lan2 = ["10.1.2.0", 0xFFFFFF00, "10.99.0.2"]
    # Look at ARP table for corresponding info
    process = subprocess.Popen("arp -a".split(), stdout=subprocess.PIPE)
    output = process.communicate()[0]
    output_list = output.split('\n')
    output_split_list = [a.split() for a in output_list]
    arp_info = [[a[1].translate(None, '()'),a[3],a[5]] for a in output_split_list if len(a) > 5]

    lan1 += [a[1:] for a in arp_info if a[0] == lan1[2]][0]
    lan2 += [a[1:] for a in arp_info if a[0] == lan2[2]][0]

    unique_interface = list(set([a[2] for a in arp_info]))
    interface_destmac_dict = {}
    for interface in unique_interface:
        process = subprocess.Popen(["ifconfig", str(interface)], stdout=subprocess.PIPE)
        output = process.communicate()[0]
        output_list = output.replace('\n', ' ').split()
        local_mac = output_list[output_list.index('ether') + 1]
        interface_destmac_dict[interface] = local_mac

    lan1.append(interface_destmac_dict[lan1[-1]])
    lan2.append(interface_destmac_dict[lan2[-1]])

    lan1Entry = RoutingTable.RoutingTableEntry(lan1)
    lan2Entry = RoutingTable.RoutingTableEntry(lan2)
    routing_table.add(lan1Entry)
    routing_table.add(lan2Entry)
    

#Main code here...
if __name__ == "__main__":
    #First setup your routing table either as global variables or as objects passed to pkt_callback
    #And any other init code
    setup()

    #Start the packet sniffer
    #sniff(prn=pkt_callback, store=0)
