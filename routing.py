from scapy.all import *
import socket
import sys
import subprocess

class RoutingTable:
    class RoutingTableEntry:
        def __init__(self, param_list, metric=1):
            self.dest = param_list[0]
            self.netmask = param_list[1]
            self.gateway = param_list[2]
            self.gateway_mac = param_list[3]
            self.interface = param_list[4]
            self.local_mac = param_list[5]
            self.metric = metric
        def __repr__(self):
            return "dest: " + str(self.dest) \
                + "\tnetmask: " + str(self.netmask) \
                + "\tgateway: " + str(self.gateway) \
                + "\tgateway_mac: " + str(self.gateway_mac) \
                + "\tinterface: " + str(self.interface) \
                + "\tlocal_mac: " + str(self.local_mac) \
                + "\tmetric: " + str(self.metric) \
                + "]"

    def __init__(self):
        self.table = []
    def __repr__(self):
        out_str = "Routing Table\n"
        for entry in self.table:
            out_str += str(entry) + "\n"
        return out_str
    def __iter__(self):
        return iter(self.table)
    def add_entry(self, entry):
        self.table.append(entry)
    def find_entry(self, ip):
        """ Finds most specific routing table entry, breaking ties on metric """
        # Dummmy variable
        dummy_param_list = ["0.0.0.0", 0xFFFFFFFF, "0.0.0.0", "00:00:00:00:00:00", "eth0", "00:00:00:00:00:00"]
        bestEntry = RoutingTable.RoutingTableEntry(dummy_param_list,sys.maxint)

        for entry in self.table:
            # Check the subnet
            if ipstr_to_hex(entry.dest)&entry.netmask == ipstr_to_hex(ip)&entry.netmask:
                # Always take more specific match
                if entry.netmask < bestEntry.netmask:
                    bestEntry = entry
                # If equally specific, take entry with lower metric
                elif entry.netmask == bestEntry.netmask:
                     if entry.metric < bestEntry.metric:
                        bestEntry = entry
        return bestEntry

# Global Variables
routing_table = RoutingTable()
arp_table = []

def ipstr_to_hex(ip_str):
    """
    input: an ip address as a scapy_table_string
    output: the same ip as an int
    """
    str_byte_list = ip_str.split('.')
    byte_list = [int(a) for a in str_byte_list]
    ip_hex = 0
    for i in range(len(byte_list)):
        ip_hex += byte_list[i] << (8 * (len(byte_list) - i - 1))
    return ip_hex

def send_icmp(pkt, icmp_type, icmp_code):
    """
    input: bad packet, with type and code of desired ICMP message
    output: none
    """
    # Craft ICMP response
    icmp_pkt = Ether()/IP()/ICMP()

    # Switch src and dest
    icmp_pkt[IP].src = pkt[IP].dst
    icmp_pkt[IP].dst = pkt[IP].src
    
    # Set type and code
    icmp_pkt[ICMP].type = icmp_type
    icmp_pkt[ICMP].code = icmp_code

    # Get IP header and 8 bytes, allows ICMP dest to demux
    ip_hdr_len = pkt[IP].ihl
    data = str(pkt[IP])[0:ip_hdr_len*4 + 8]

    out_pkt = icmp_pkt/data
    print "======= ICMP Packet ========"
    out_pkt.show()

    send(out_pkt, verbose=0)

#Your per-packet router code goes here
def pkt_callback(pkt):
    #print "Received an Ethernet packet. MAC src:", pkt.src, "MAC dst:",pkt.dst
    #print pkt.summary()

    #Determine if it is an IP packet. If not then return
    if IP not in pkt:
        return

    dest_ip = pkt[IP].dst

    # If the dest IP is local to this computer or LAN, kernel handles packet
    # Change to starts with
    if "10.99.0" in dest_ip or "10.10.0" in dest_ip or "192.168" in dest_ip:
        return

    # Is the destination *network* in your routing table, if not, send ICMP "Destination host unreachable", then return
    has_route = False
    for entry in routing_table:
        # Make sure these comparisons are valid
        if ((ipstr_to_hex(dest_ip) & entry.netmask) == (ipstr_to_hex(entry.dest) & entry.netmask)):
            print dest_ip + " is reachable"
            has_route = True

    if not has_route:
        print dest_ip + " is unreachable"
        send_icmp(pkt, icmp_type=3, icmp_code=11)
        return

    # Decrement the TTL. If TTL=0, send ICMP for TTL expired and return.
    pkt[IP].ttl -= 1
    if pkt[IP].ttl < 1:
        send_icmp(pkt, icmp_type=11, icmp_code=0)
        return

    # Find the next hop (gateway) for the destination *network*
    routing_entry = routing_table.find_entry(dest_ip)
    gateway = routing_entry.gateway

    # Determine the outgoing interface and MAC address needed to reach the next-hop router
    out_iface = routing_entry.interface

    # Modify the SRC and DST MAC addresses to match the outgoing interface and the DST MAC found above
    # Drop packet if src is equal to local_mac, as this means pkt is duplicate
    if pkt.src == routing_entry.local_mac:
        return
    pkt.src = routing_entry.local_mac
    pkt.dst = routing_entry.gateway_mac

    # Update the IP header checksum
    del pkt[IP].chksum
    pkt = pkt.__class__(str(pkt))

    #Send the packet out the proper interface as required to reach the next hop router. Use:
    sendp(pkt, iface=out_iface, verbose=0)

def setup():
    # Disable ICMP echos
    subprocess.Popen('sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1'.split())
    subprocess.Popen('sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1'.split())
    #subprocess.Popen('sudo iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP'.split())

    # Ping the routers and node0 w/ TTL 1 --> ARP created 
    subprocess.Popen('ping 10.99.0.1 -c 1'.split())
    subprocess.Popen('ping 10.99.0.2 -c 1'.split())
    subprocess.Popen('ping 10.10.0.1 -c 1'.split())

    # Construct Routing Table
    # Hardcoded IP mappings
    subnet1 = ["10.1.0.0", 0xFFFFFF00, "10.99.0.1"]
    subnet2 = ["10.1.2.0", 0xFFFFFF00, "10.99.0.2"]

    # Look at ARP table for corresponding info
    process = subprocess.Popen("arp -a".split(), stdout=subprocess.PIPE)
    output = process.communicate()[0]

    # Split twice so we can get individual words per line
    output_list = output.split('\n')
    output_split_list = [a.split() for a in output_list]

    # Parse the output of arp -a into a table (a list of lists of 3 string fields)
    # The gateway IP should be the second word on the line, but is surrounded
    #   by parentheses
    arp_table = [[a[1].translate(None, '()'),a[3],a[6]] for a in output_split_list if len(a) > 6]
    print "arp table:\n\n" + str(arp_table)

    # Add the dest MAC info into the subnet info
    for entry in arp_table:
        if entry[0] == subnet1[2]:
            subnet1 += entry[1:]
        elif entry[0] == subnet2[2]:
            subnet2 += entry[1:]

    # For each unique interface found above, we want to find the local mac
    #  that corresponds to it using ifconfig
    unique_interface = list(set([a[2] for a in arp_table]))
    interface_destmac_dict = {}
    for interface in unique_interface:
        process = subprocess.Popen(["ifconfig", str(interface)], stdout=subprocess.PIPE)
        output = process.communicate()[0]
        output_list = output.replace('\n', ' ').split()

        # This is hardcoded based on the output of ifconfig on the nodes,
        # as the local mac address is the word after HWaddr
        local_mac = output_list[output_list.index('HWaddr')+1]
        interface_destmac_dict[interface] = local_mac

    # Combine the parameters we have gathered for each subnet and add them
    #  to the routing table
    subnet1.append(interface_destmac_dict[subnet1[-1]])
    subnet2.append(interface_destmac_dict[subnet2[-1]])

    subnet1Entry = RoutingTable.RoutingTableEntry(subnet1)
    subnet2Entry = RoutingTable.RoutingTableEntry(subnet2)
    routing_table.add_entry(subnet1Entry)
    routing_table.add_entry(subnet2Entry)
    

#Main code here...
if __name__ == "__main__":
    #First setup your routing table either as global variables or as objects passed to pkt_callback
    #And any other init code
    setup()
    print "routing_table: ", routing_table

    #Start the packet sniffer
    sniff(prn=pkt_callback, store=0)
