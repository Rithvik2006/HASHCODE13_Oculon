import os
import json
import time
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw, DNS, get_if_list
from scapy.layers.tls.all import TLS
from collections import defaultdict
from influxdb_client import InfluxDBClient, Point, WritePrecision
import math

baseline = defaultdict(float)
variance = defaultdict(float)  
count_samples = defaultdict(int)

INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "nhT2RMCFjwHCC4jhJ4kJa4GWoZB0x3R1-CZFGb4v1acz5A4BIC2YrviF_jMUhv7isopnNfbeLpv7niAvo0KYFQ=="
INFLUX_ORG = "Oculon"
INFLUX_BUCKET = "network_metrics"

client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
from influxdb_client.client.write_api import WriteOptions

write_api = client.write_api(write_options=WriteOptions(batch_size=1000, flush_interval=10_000))

AGG_INTERVAL = 5       
ALPHA = 0.3            
OUTPUT_DIR = "output"  

os.makedirs(OUTPUT_DIR, exist_ok=True)

interfaces = get_if_list()
iface = None
for i in interfaces:
    if "Loopback" not in i:
        iface = i
        break
if not iface:
    raise RuntimeError("No non-loopback interface found")
print(f"Using interface: {iface}")


agg = {
    "device_mac": defaultdict(int),
    "endpoint_ip": defaultdict(int),
    "tcp_flags": defaultdict(int),
    "icmp": defaultdict(int),
    "http_methods": defaultdict(int),
    "dns_queries": defaultdict(int),
    "tls_versions": defaultdict(int),
    "traffic": {"count": 0, "bytes": 0, "iat": []}
}

ewma = {
    "device_mac": defaultdict(float),
    "endpoint_ip": defaultdict(float),
    "tcp_flags": defaultdict(float),
    "icmp": defaultdict(float),
    "http_methods": defaultdict(float),
    "dns_queries": defaultdict(float),
    "tls_versions": defaultdict(float),
    "traffic_bytes": 0.0,
    "traffic_count": 0.0
}

last_ts = None
current_interval = int(time.time())


def safe_decode(val):
    if isinstance(val, bytes):
        try:
            return val.decode(errors="ignore")
        except:
            return repr(val)
    return val


def update_aggregation(pkt, ts):
    global last_ts
    # Inter-arrival time
    if last_ts is not None:
        iat = ts - last_ts
        agg["traffic"]["iat"].append(iat)
    last_ts = ts

    agg["traffic"]["count"] += 1
    agg["traffic"]["bytes"] += len(pkt)

 
    if Ether in pkt:
        eth = pkt[Ether]
        agg["device_mac"][safe_decode(eth.src)] += 1

   
    ip_layer = None
    if IP in pkt:
        ip_layer = pkt[IP]
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]

    if ip_layer:
        agg["endpoint_ip"][safe_decode(ip_layer.src)] += 1

    
    if TCP in pkt:
        tcp = pkt[TCP]
        agg["tcp_flags"][str(tcp.flags)] += 1
    elif UDP in pkt:
        pass
    elif ICMP in pkt:
        ic = pkt[ICMP]
        key = f"{ic.type}:{ic.code}"
        agg["icmp"][key] += 1

   
    if Raw in pkt:
        raw = bytes(pkt[Raw])[:1024]
        try:
            s = raw.decode(errors="ignore")
            if s.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                method, uri, *_ = s.split()
                agg["http_methods"][method] += 1
        except:
            pass

   
    if DNS in pkt:
        dns = pkt[DNS]
        if dns.qd:
            qname = safe_decode(getattr(dns.qd, "qname", ""))
            qtype = getattr(dns.qd, "qtype", "")
            key = f"{qname}:{qtype}"
            agg["dns_queries"][key] += 1

    
    if TLS in pkt:
        tls = pkt[TLS]
        ew_version = getattr(tls, "version", "unknown")
        agg["tls_versions"][ew_version] += 1


def update_ewma():
    for k, v in agg["device_mac"].items():
        ewma["device_mac"][k] = ALPHA*v + (1-ALPHA)*ewma["device_mac"].get(k,0)
    for k, v in agg["endpoint_ip"].items():
        ewma["endpoint_ip"][k] = ALPHA*v + (1-ALPHA)*ewma["endpoint_ip"].get(k,0)
    for k, v in agg["tcp_flags"].items():
        ewma["tcp_flags"][k] = ALPHA*v + (1-ALPHA)*ewma["tcp_flags"].get(k,0)
    for k, v in agg["icmp"].items():
        ewma["icmp"][k] = ALPHA*v + (1-ALPHA)*ewma["icmp"].get(k,0)
    for k, v in agg["http_methods"].items():
        ewma["http_methods"][k] = ALPHA*v + (1-ALPHA)*ewma["http_methods"].get(k,0)
    for k, v in agg["dns_queries"].items():
        ewma["dns_queries"][k] = ALPHA*v + (1-ALPHA)*ewma["dns_queries"].get(k,0)
    for k, v in agg["tls_versions"].items():
        ewma["tls_versions"][k] = ALPHA*v + (1-ALPHA)*ewma["tls_versions"].get(k,0)
    ewma["traffic_bytes"] = ALPHA*agg["traffic"]["bytes"] + (1-ALPHA)*ewma["traffic_bytes"]
    ewma["traffic_count"] = ALPHA*agg["traffic"]["count"] + (1-ALPHA)*ewma["traffic_count"]


def flush_aggregation():
    update_ewma()
    push_ewma_to_influx(ewma)
    ts_str = time.strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(OUTPUT_DIR, f"aggregated_{ts_str}.json")
    data = {
        "raw": {k: dict(v) if isinstance(v, defaultdict) else v for k,v in agg.items()},
        "ewma": {k: dict(v) if isinstance(v, defaultdict) else v for k,v in ewma.items()}
    }
    with open(out_file, "w") as f:
        json.dump(data, f, indent=2)

    for k in agg:
        if isinstance(agg[k], defaultdict):
            agg[k].clear()
        elif isinstance(agg[k], dict):
            for subk in agg[k]:
                if isinstance(agg[k][subk], int):
                    agg[k][subk] = 0
                elif isinstance(agg[k][subk], list):
                    agg[k][subk].clear()
        elif isinstance(agg[k], list):
            agg[k].clear()


def packet_handler(pkt):
    ts = time.time()
    update_aggregation(pkt, ts)
    global current_interval
    if ts - current_interval >= AGG_INTERVAL:
        flush_aggregation()
        current_interval = int(ts)
        
        
def push_ewma_to_influx(ewma_data):
    ts = int(time.time() * 1_000_000_000) 


    for mac, ewma_value in ewma_data.get("device_mac", {}).items():
        count_value = agg["device_mac"].get(mac, 0)
        point = Point("device_mac") \
            .tag("mac", mac) \
            .field("count", count_value) \
            .field("ewma", float(ewma_value)) \
            .time(ts, WritePrecision.NS)
        write_api.write(bucket=INFLUX_BUCKET, record=point)

  
    for ip, ewma_value in ewma_data.get("endpoint_ip", {}).items():
        count_value = agg["endpoint_ip"].get(ip, 0)
        point = Point("endpoint_ip") \
            .tag("ip", ip) \
            .field("count", count_value) \
            .field("ewma", float(ewma_value)) \
            .time(ts, WritePrecision.NS)
        write_api.write(bucket=INFLUX_BUCKET, record=point)


    for flag, ewma_value in ewma_data.get("tcp_flags", {}).items():
        count_value = agg["tcp_flags"].get(flag, 0)
        point = Point("tcp_flags") \
            .tag("flag", flag) \
            .field("count", count_value) \
            .field("ewma", float(ewma_value)) \
            .time(ts, WritePrecision.NS)
        write_api.write(bucket=INFLUX_BUCKET, record=point)


    for icmp_key, ewma_value in ewma_data.get("icmp", {}).items():
        count_value = agg["icmp"].get(icmp_key, 0)
        point = Point("icmp") \
            .tag("type_code", icmp_key) \
            .field("count", count_value) \
            .field("ewma", float(ewma_value)) \
            .time(ts, WritePrecision.NS)
        write_api.write(bucket=INFLUX_BUCKET, record=point)


    for method, ewma_value in ewma_data.get("http_methods", {}).items():
        count_value = agg["http_methods"].get(method, 0)
        point = Point("http_methods") \
            .tag("method", method) \
            .field("count", count_value) \
            .field("ewma", float(ewma_value)) \
            .time(ts, WritePrecision.NS)
        write_api.write(bucket=INFLUX_BUCKET, record=point)


    for query, ewma_value in ewma_data.get("dns_queries", {}).items():
        count_value = agg["dns_queries"].get(query, 0)
        point = Point("dns_queries") \
            .tag("query", query) \
            .field("count", count_value) \
            .field("ewma", float(ewma_value)) \
            .time(ts, WritePrecision.NS)
        write_api.write(bucket=INFLUX_BUCKET, record=point)


    for tls_version, ewma_value in ewma_data.get("tls_versions", {}).items():
        count_value = agg["tls_versions"].get(tls_version, 0)
        point = Point("tls_versions") \
            .tag("version", str(tls_version)) \
            .field("count", count_value) \
            .field("ewma", float(ewma_value)) \
            .time(ts, WritePrecision.NS)
        write_api.write(bucket=INFLUX_BUCKET, record=point)
        
    for mac, ewma_val in ewma["device_mac"].items():
        update_baseline_std(mac, ewma_val)
        check_anomaly(mac, ewma_val, "MAC")
        
    for ip, ewma_val in ewma["endpoint_ip"].items():
        update_baseline_std(ip, ewma_val)
        check_anomaly(ip, ewma_val, "IP") 


    point = Point("traffic") \
        .field("bytes", float(agg["traffic"]["bytes"])) \
        .field("count", float(agg["traffic"]["count"])) \
        .field("ewma_bytes", float(ewma_data.get("traffic_bytes", 0))) \
        .field("ewma_count", float(ewma_data.get("traffic_count", 0))) \
        .time(ts, WritePrecision.NS)
    write_api.write(bucket=INFLUX_BUCKET, record=point)

def update_baseline_std(key, ewma_value):
    count_samples[key] += 1
    delta = ewma_value - baseline.get(key, 0)
    baseline[key] = baseline.get(key, 0) + delta / count_samples[key]
    
    # Welford’s method for variance
    variance[key] = variance.get(key, 0) + delta * (ewma_value - baseline[key])

def get_std_dev(key):
    n = count_samples.get(key, 1)
    return math.sqrt(variance.get(key, 0) / n)

def check_anomaly(key, ewma_value, metric_type):
    std_dev = get_std_dev(key)
    thresh = baseline[key] + 3 * std_dev  # k = 3 for critical
    if ewma_value > thresh:
        print(f"🚨 Anomaly detected on {metric_type} {key}: EWMA={ewma_value:.2f}, Threshold={thresh:.2f}")


print(f"Starting capture on {iface}...")
sniff(iface=None, prn=packet_handler, store=False)
