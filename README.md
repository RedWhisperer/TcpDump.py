# TcpDump.py
A python utility for Linux machines that missing the native tcpdump utility.
Many times in my engagements I encounter Linux targets (usually old version servers) that does not contain tcpdump, but contain updated Python.

To use the script, just specify a network interface to sniff and a file name for the output (optional - protocol or port number). For example: sudo python3 tcpdump.py -i enp0s3 -o capture.pcap -n 443
