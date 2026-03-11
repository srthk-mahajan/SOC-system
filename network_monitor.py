from scapy.all import sniff, TCP, IP
from detection_engine import process_packet


def packet_callback(packet):

    if packet.haslayer(IP) and packet.haslayer(TCP):

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        print(src_ip, "->", dst_port)
        process_packet(src_ip, dst_port, flags)


def start_network_monitor():

    print("[+] Packet monitoring started")

    sniff(
        iface=["lo", "wlp2s0"],
        filter="tcp",
        prn=packet_callback,
        store=False
    )