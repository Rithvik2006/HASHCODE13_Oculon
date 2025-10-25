# live_capture.py
import pyshark

# Function to convert a packet to a dictionary
def pkt_to_dict(pkt):
    try:
        length = int(pkt.length)
        proto = pkt.transport_layer or pkt.highest_layer
        s_port = int(pkt[pkt.transport_layer].srcport) if hasattr(pkt, 'transport_layer') else 0
        d_port = int(pkt[pkt.transport_layer].dstport) if hasattr(pkt, 'transport_layer') else 0

        return {
            'length': length,
            'src_port': s_port,
            'dst_port': d_port,
            'proto': proto
        }
    except Exception as e:
        # Skip packets that cannot be parsed
        return None

# Live capture generator
def capture_live(iface="eth0"):
    cap = pyshark.LiveCapture(interface=iface)
    print(f"Starting live capture on {iface}...")
    for pkt in cap.sniff_continuously():
        data = pkt_to_dict(pkt)
        if data:
            yield data  # yield one packet at a time

# Example usage
if __name__ == "__main__":
    for packet in capture_live(iface="eth0"):
        print(packet)
        # Here you can feed 'packet' into Pandas/Numpy for processing
