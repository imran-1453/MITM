import scapy.all as scapy
from scapy_http import http
def packet_listen():
    scapy.sniff(iface="eth0",store=False,prn=packet_analyze)

def packet_analyze(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

packet_listen()
