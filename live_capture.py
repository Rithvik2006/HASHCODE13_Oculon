from scapy.all import sniff, Ether, IP, TCP, UDP
from datetime import datetime

def detailed_packet_info(packet):
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    info = {
        "timestamp": timestamp,
        "src_mac": packet[Ether].src if Ether in packet else "N/A",
        "dst_mac": packet[Ether].dst if Ether in packet else "N/A",
        "src_ip": packet[IP].src if IP in packet else "N/A",
        "dst_ip": packet[IP].dst if IP in packet else "N/A",
        "ttl": packet[IP].ttl if IP in packet else "N/A",
        "proto": packet[IP].proto if IP in packet else "N/A",
        "src_port": "N/A",
        "dst_port": "N/A",
        "flags": "N/A",
        "seq": "N/A",
        "ack": "N/A",
        "win": "N/A",
        "len": len(packet)
    }

    if TCP in packet:
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
        info["flags"] = packet[TCP].flags
        info["seq"] = packet[TCP].seq
        info["ack"] = packet[TCP].ack
        info["win"] = packet[TCP].window
    elif UDP in packet:
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport

    print(
        f"[{info['timestamp']}] {info['proto']} | {info['src_ip']}:{info['src_port']} "
        f"-> {info['dst_ip']}:{info['dst_port']} | TTL={info['ttl']} | Flags={info['flags']} "
        f"| Seq={info['seq']} | Ack={info['ack']} | Win={info['win']} | Len={info['len']}"
    )

print("📡 Capturing detailed packet metadata... Press Ctrl+C to stop.")
sniff(iface="Wi-Fi", prn=detailed_packet_info, store=False)
