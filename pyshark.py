# services/pcap_agent/capture.py
import pyshark
import socket
import time
import json
from geoip2.database import Reader as GeoReader
from elasticsearch import Elasticsearch, helpers
from prometheus_client import start_http_server, Counter, Gauge, Histogram
import asyncio
import websockets

ES_INDEX = "net-events"
es = Elasticsearch("http://elasticsearch:9200")

geo = GeoReader("/data/GeoLite2-City.mmdb")

PKTS = Counter('pkts_total', 'Total packets', ['iface'])
BYTES = Counter('bytes_total', 'Total bytes', ['iface'])
FLOWS = Gauge('flows_active', 'Active 5m flows')
LATENCY = Histogram('tcp_latency_ms', 'TCP handshake latency (ms)')

WS_URL = "ws://api-gateway:8080/ingest"

def ip_geo(ip):
    try:
        r = geo.city(ip)
        return dict(country=r.country.iso_code, city=r.city.name, lat=r.location.latitude, lon=r.location.longitude)
    except:
        return {}

def to_doc(pkt):
    ts = float(pkt.sniff_timestamp)
    length = int(pkt.length)
    layer = pkt.highest_layer
    src, dst = pkt.ip.src if 'IP' in pkt else None, pkt.ip.dst if 'IP' in pkt else None
    s_port = int(pkt[pkt.transport_layer].srcport) if hasattr(pkt, 'transport_layer') else None
    d_port = int(pkt[pkt.transport_layer].dstport) if hasattr(pkt, 'transport_layer') else None
    proto = pkt.transport_layer or pkt.highest_layer

    s_geo = ip_geo(src) if src and '.' in src else {}
    d_geo = ip_geo(dst) if dst and '.' in dst else {}

    tls_sni = getattr(getattr(pkt, 'tls', None), 'handshake_extensions_server_name', None)
    dns_q = getattr(getattr(pkt, 'dns', None), 'qry_name', None)
    tcp_flags = getattr(getattr(pkt, 'tcp', None), 'flags', None)

    return {
        "@timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time.gmtime(ts)),
        "src_ip": src, "dst_ip": dst,
        "src_port": s_port, "dst_port": d_port,
        "proto": proto, "layer": layer, "length": length,
        "dns_qname": dns_q, "tls_sni": tls_sni, "tcp_flags": tcp_flags,
        "src_geo": s_geo, "dst_geo": d_geo
    }

async def ws_send(doc):
    async with websockets.connect(WS_URL) as ws:
        await ws.send(json.dumps(doc))

def bulk_index(buffer):
    actions = [{"_index": ES_INDEX, "_source": d} for d in buffer]
    if actions:
        helpers.bulk(es, actions)

def run_capture(iface="eth0", display_filter=None):
    start_http_server(9102)  # prometheus exporter
    cap = pyshark.LiveCapture(interface=iface, display_filter=display_filter)  # e.g. "tcp or dns or tls"
    buffer, last_flush = [], time.time()
    for pkt in cap.sniff_continuously():
        doc = to_doc(pkt)
        PKTS.labels(iface).inc()
        BYTES.labels(iface).inc(doc["length"])
        buffer.append(doc)

        # fire-and-forget websocket (optional)
        try:
            asyncio.get_event_loop().run_until_complete(ws_send(doc))
        except:
            pass

        # flush to ES every ~1s
        if time.time() - last_flush > 1.0:
            bulk_index(buffer); buffer.clear(); last_flush = time.time()

if __name__ == "__main__":
    run_capture(iface="eth0", display_filter="tcp or dns or tls")
