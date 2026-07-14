import json
from scapy.all import IP, TCP, UDP, sniff

capture_packets = []

def process_packet(packet):
    if IP not in packet:
        return
    
    protocol = "OTHER"
    src_port = 0
    dst_port = 0

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    capture_packets.append(
        {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "size": len(packet)
        }
    )


def main():
    print("Capturing packets for 20 seconds")

    sniff(prn=process_packet, timeout=20, store=False)

    with open("data/baseline_packets.json", "w") as file:
        json.dump(capture_packets, file, indent=4)
    
    print(f"Captured {len(capture_packets)} packets and saved to data/baseline_packets.json")


if __name__ == "__main__":\
    main()