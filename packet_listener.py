import scapy.all as scapy
from scapy.all import sniff
from scapy.layers import http
from scapy.packet import Raw

def listen_packets(interface):
    sniff(iface=interface, store=False, prn=analyze_packets)

def analyze_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        http_layer = packet.getlayer(http.HTTPRequest)
        if packet.haslayer(scapy.Raw):
            print("HTTP Request Detected:")
            print(f"Host: {http_layer.Host.decode('utf-8')}")
            print(f"Path: {http_layer.Path.decode('utf-8')}")
            print(f"Method: {http_layer.Method.decode('utf-8')}")
            print(f"Data: {packet[scapy.Raw].load.decode('utf-8', errors='ignore')}")


listen_packets("eth0")


