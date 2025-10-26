# AI Explainer Widget (for HASHCODE13_Oculon)

This folder provides a lightweight AI explainer service and frontend widget that can be used alongside your Influx Cloud dashboard. When a chart is focused/hovered an "AI Explainer" button appears; clicking it fetches a short Influx summary (if configured) and asks the configured LLM for a concise explanation.

Quick start:
1. Add the python dependencies: pip install -r ai_explainer/requirements.txt
2. Configure environment variables (.env):
   - INFLUX_URL, INFLUX_TOKEN, INFLUX_ORG, INFLUX_BUCKET (optional, for automatic summaries)
   - OPENAI_API_KEY (preferred) or LLM_API_URL (generic)
   - OPENAI_MODEL (optional)
3. Run the service:
   uvicorn ai_explainer.main:app --host 0.0.0.0 --port 8080
4. Host the static files (static/js and static/css) with your frontend (or serve them from the FastAPI static mount).
5. Use an overlay page to embed your Influx Cloud dashboard (iframe) and include the JS widget. Panels: add data attributes or map CSS selectors from the hosted dashboard.

Security:
- Keep keys server-side, protect the explain endpoint.
- Revoke tokens after verification if needed.

Notes:
- The backend will try to query Influx for a short numeric summary if INFLUX_* env vars are set.
- LLM keys must never be exposed client-side. The frontend only calls your backend explain endpoint.
