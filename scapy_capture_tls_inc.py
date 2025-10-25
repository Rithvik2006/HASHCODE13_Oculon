import json
import time
from scapy.all import (
    sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw,
    DNS
)
from scapy.layers.tls.all import TLS


LOGFILE = "packet_log1.jsonl"

def safe_decode(val):
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="ignore")
        except Exception:
            return repr(val)
    return val

def safe_json(obj):
    """Recursively make any object JSON-serializable."""
    if isinstance(obj, dict):
        return {k: safe_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [safe_json(v) for v in obj]
    elif isinstance(obj, bytes):
        return safe_decode(obj)
    elif hasattr(obj, "__dict__"):
        return safe_json(vars(obj))
    else:
        # fallback to string if it's not a basic JSON type
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        return safe_decode(str(obj))

def packet_to_record(pkt):
    rec = {"ts": time.time()}
    
    if Ether in pkt:
        eth = pkt[Ether]
        rec.update({
            "src_mac": safe_decode(eth.src),
            "dst_mac": safe_decode(eth.dst),
            "eth_type": safe_decode(hex(eth.type))
        })
    
    if IP in pkt:
        ip = pkt[IP]
        rec.update({
            "version": 4,
            "src_ip": safe_decode(ip.src),
            "dst_ip": safe_decode(ip.dst),
            "ttl": ip.ttl,
            "ip_len": ip.len
        })
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        rec.update({
            "version": 6,
            "src_ip": safe_decode(ip6.src),
            "dst_ip": safe_decode(ip6.dst),
            "ttl": ip6.hlim,
            "ip_len": len(ip6)
        })
    
    if TCP in pkt:
        tcp = pkt[TCP]
        rec.update({
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "tcp_flags": safe_decode(str(tcp.flags)),
            "seq": tcp.seq,
            "ack": getattr(tcp, "ack", None),
            "payload_len": len(tcp.payload)
        })
    elif UDP in pkt:
        udp = pkt[UDP]
        rec.update({
            "protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "payload_len": len(udp.payload)
        })
    elif ICMP in pkt:
        ic = pkt[ICMP]
        rec.update({
            "protocol": "ICMP",
            "icmp_type": ic.type,
            "icmp_code": ic.code,
            "payload_len": len(ic.payload)
        })

    # DNS layer parsing
    if DNS in pkt:
        dns = pkt[DNS]
        rec.update({
            "dns_id": dns.id,
            "dns_qr": dns.qr,
            "dns_opcode": dns.opcode,
            "dns_qdcount": dns.qdcount,
            "dns_ancount": dns.ancount,
            "dns_nscount": dns.nscount,
            "dns_arcount": dns.arcount,
            "dns_rcode": dns.rcode
        })
        if dns.qd:
            rec["dns_qname"] = safe_decode(getattr(dns.qd, "qname", None))
            rec["dns_qtype"] = dns.qd.qtype if hasattr(dns.qd, "qtype") else None
        answers = []
        for i in range(dns.ancount):
            ans = dns.an[i]
            answers.append({
                "rrname": safe_decode(getattr(ans, "rrname", None)),
                "type": getattr(ans, "type", None),
                "rdata": safe_decode(getattr(ans, "rdata", None))
            })
        rec["dns_answers"] = answers
    
    # HTTP parsing from raw data
    if Raw in pkt:
        raw = bytes(pkt[Raw])[:1024]
        try:
            s = raw.decode(errors="ignore")
            if s.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                lines = s.split("\r\n")
                method, uri, *_ = lines[0].split()
                rec["http_method"] = method
                rec["http_uri"] = uri
                for line in lines[1:]:
                    if line.lower().startswith("host:"):
                        rec["http_host"] = safe_decode(line.split(":", 1)[1].strip())
                    if line.lower().startswith("user-agent:"):
                        rec["http_user_agent"] = safe_decode(line.split(":", 1)[1].strip())
            rec["http_raw"] = safe_decode(raw)
        except Exception:
            pass
    
    # TLS/SSL parsing
    try:
        if TLS in pkt:
            tls = pkt[TLS]
            rec["tls_version"] = getattr(tls, "version", None)
            if hasattr(tls, "msg") and tls.msg:
                for m in tls.msg:
                    if hasattr(m, "servernames") and m.servernames:
                        rec["tls_sni"] = safe_decode(m.servernames[0].data)
                    if hasattr(m, "cipher_suites") and m.cipher_suites:
                        rec["tls_ciphers"] = [safe_decode(c) for c in m.cipher_suites]
    except Exception:
        pass
    
    return rec

def main():
    print("Starting Scapy capture...")

    def handle(pkt):
        rec = packet_to_record(pkt)
        rec_safe = safe_json(rec)
        with open(LOGFILE, "a", encoding="utf-8") as f:
            json.dump(rec_safe, f, ensure_ascii=False)
            f.write("\n")

    sniff(prn=handle, store=False)

if __name__ == "__main__":
    main()
