import scapy.all as scapy
import optparse

parser = optparse.OptionParser()

parser.add_option('-i', '--interface', dest='interface', help="Network interface to sniff on")
parser.add_option('-o', '--output', dest='filename', help="The pcap file to write the output in")
parser.add_option('-n', '--port-number', dest='port_sniff', help="Specific port to sniff on")
parser.add_option('-p', '--protocol', dest='protocol', help="Protocol to sniff (tcp / udp / icmp...)")

(options, armnts) = parser.parse_args()

interface = options.interface
filename = options.filename
port_sniff = options.port_sniff
filters = options.port_sniff
protocol = options.protocol

def tcpdump_filtered(interface, filename, filters):
    try:
        caps = scapy.sniff(iface=interface, filter="port 80")
        scapy.wrpcap(filename, caps)
    except:
        print('[X] Could not sniff on target machine, check for permissions.')


def tcpdump_no_filtered(interface, filename):
    try:
        caps = scapy.sniff(iface=interface)
        scapy.wrpcap(filename, caps)
    except:
        print('[X] Could not sniff on target machine, check for permissions.')

if not interface:
    print('[X] No interface for sniffing was specified')
else:
    if not filename:
        print('[X] No filename specified for the output')
    else:
        if not filters and not protocol:
            print('[!] No filters were specified for sniffing')
            print("[+] Starting to sniff...")
            tcpdump_no_filtered(interface, filename)
        elif filters and protocol:
            print('[!] You must use only one of the options - protocol or port')
        else:
            if protocol:
                filters = protocol
                print("[+] Sniffing on ", interface, " on protocol: ", filters)
                tcpdump_filtered(interface, filename, filters)
            if filters:
                port = "port " + filters
                print("[+] Sniffing on ", interface, " on port: ", port)
                tcpdump_filtered(interface, filename, port)
