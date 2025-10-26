# FastAPI backend for AI Explainer (uses env vars for configuration)
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os, json
from dotenv import load_dotenv
import influxdb_client
from influxdb_client.client.query_api import QueryApi
import openai
import httpx

load_dotenv()

INFLUX_URL = os.getenv("INFLUX_URL", "")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "")
INFLUX_ORG = os.getenv("INFLUX_ORG", "")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
LLM_API_URL = os.getenv("LLM_API_URL", "")

if OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY

app = FastAPI(title="AI Explainer Service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ExplainRequest(BaseModel):
    graph_type: str
    measurement: str = None
    field: str = None
    tags: dict = None
    time_range_minutes: int = 15
    extra_context: dict = None

GRAPH_TEMPLATES = {
    "per_mac_ewma": {"title": "Per MAC EWMA", "desc": "EWMA per MAC to detect rogue/new MACs and misconfigurations."},
    "per_ip_ewma": {"title": "Per IP EWMA", "desc": "EWMA per IP for exfiltration, scanning, unusual host activity."},
    "tcp_flags": {"title": "TCP Flags", "desc": "Counts/spikes in TCP flags indicating resets, SYN floods, scanning."},
    "icmp_types": {"title": "ICMP Types", "desc": "ICMP type/code counts for recon or path/host issues."},
    "http_methods": {"title": "HTTP Methods", "desc": "HTTP method volumes to highlight uploads, destructive APIs, crawling."},
    "dns_queries": {"title": "DNS Queries", "desc": "Domain/qtype analysis for tunneling or suspicious domains."},
    "tls_version": {"title": "TLS Version", "desc": "TLS version distribution to spot downgrades or insecure traffic."},
    "traffic_bytes": {"title": "Traffic Bytes", "desc": "Bytes/packets to reveal throughput anomalies or data exfiltration."},
}

def build_prompt(graph_type: str, recent_summary: str) -> str:
    template = GRAPH_TEMPLATES.get(graph_type, {})
    base = (
        "You are a helpful network-security-aware assistant. Provide a concise, actionable explanation "
        "of the focused graph: what it shows, likely causes for patterns, steps to investigate, a confidence level, and one quick mitigation.\n"
    )
    if template:
        base += f"Graph: {template.get('title')}. {template.get('desc')}\n"
    base += f"\nRecent summary:\n{recent_summary}\n\nRespond in JSON with keys: explanation, causes (list), steps (list), confidence, mitigation.\n"
    return base

def query_influx_for_summary(measurement: str, field: str, tags: dict, minutes: int) -> str:
    if not (INFLUX_URL and INFLUX_TOKEN and INFLUX_ORG and INFLUX_BUCKET):
        return "InfluxDB not configured; no automatic summary available."
    client = influxdb_client.InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    query_api: QueryApi = client.query_api()
    measurement = measurement or ""
    field_filter = f'and r._field == "{field}"' if field else ""
    tag_filters = ""
    if tags:
        for k, v in tags.items():
            tag_filters += f' and r["{k}"] == "{v}"'
    flux = (
        f'from(bucket:"{INFLUX_BUCKET}") |> range(start: -{minutes}m) '
        f'|> filter(fn: (r) => r["_measurement"] == "{measurement}" {field_filter} {tag_filters}) '
        f'|> keep(columns: ["_time","_value","_field"]) |> limit(n:500)'
    )
    try:
        tables = query_api.query(flux)
        vals = []
        count = 0
        for table in tables:
            for rec in table.records:
                count += 1
                try:
                    vals.append(float(rec.get_value()))
                except Exception:
                    pass
        if not vals:
            return f"Found {count} points but no numeric values in last {minutes}m."
        mx, mn = max(vals), min(vals)
        avg = sum(vals) / len(vals)
        return f"Points: {count}, min={{mn:.3f}}, max={{mx:.3f}}, mean={{avg:.3f}} over last {minutes} minutes."
    except Exception as e:
        return f"Influx query error: {e}"

async def call_llm(prompt: str) -> str:
    if OPENAI_API_KEY:
        try:
            resp = openai.ChatCompletion.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                messages=[{"role":"user","content":prompt}],
                max_tokens=700, temperature=0.2
            )
            return resp.choices[0].message.content.strip()
        except Exception:
            pass
    if LLM_API_URL:
        async with httpx.AsyncClient() as client:
            r = await client.post(LLM_API_URL, json={"prompt": prompt, "max_tokens": 700})
            r.raise_for_status()
            return r.json().get("text") or r.json().get("output") or json.dumps(r.json())
    raise RuntimeError("No LLM configured.")

@app.post("/api/explain")
async def explain(req: ExplainRequest):
    recent = query_influx_for_summary(req.measurement, req.field, req.tags, req.time_range_minutes or 15)
    prompt = build_prompt(req.graph_type, recent)
    if req.extra_context:
        prompt += "\nExtra context:\n" + json.dumps(req.extra_context)
    try:
        llm_text = await call_llm(prompt)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM call failed: {e}")
    explanation = {"raw": llm_text}
    try:
        start = llm_text.find("{")
        if start != -1:
            explanation = json.loads(llm_text[start:])
        else:
            explanation["explanation"] = llm_text
    except Exception:
        explanation["explanation"] = llm_text
    return {"graph_type": req.graph_type, "influx_summary": recent, "explanation": explanation}