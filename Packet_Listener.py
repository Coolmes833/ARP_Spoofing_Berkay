import scapy.all as scapy
from scapy_http import http

def listen_packets(interface=None):
    scapy.sniff(iface=interface, store=False, prn=analyze_packets)

def analyze_packets(packet):
    if packet.haslayer(http.HTTPRequest):  # HTTP İsteklerini Yakala
        if packet.haslayer(scapy.Raw):  # Raw katmanı varsa al
            try:
                print(packet[scapy.Raw].load.decode(errors="ignore"))  # Encoding hatalarını önle
            except Exception as e:
                print(f"Hata: {e}")

# Arayüzü elle gir veya None ile tüm arayüzleri dinle
listen_packets("eth0")  # veya listen_packets(None)
