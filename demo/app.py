import json
import os
import time

import redis
import requests
import streamlit as st

from shared import (
    API_URL,
    SEVERITY_STYLE,
    render_contexts,
    render_provider_sidebar,
    render_result,
    severity_badge,
)

st.set_page_config(
    page_title="Cyber Threat Analyzer",
    page_icon="🛡️",
    layout="wide",
)

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    provider, model_name = render_provider_sidebar()
    st.divider()
    auto_refresh = st.toggle("Auto-refresh (3s)", value=True)

redis_host = os.getenv("REDIS_HOST", "localhost")
redis_port = int(os.getenv("REDIS_PORT", "6379"))
RESULT_QUEUE = "alerts:results"

# ── Header ───────────────────────────────────────────────────────────────────
st.title("🛡️ Cyber Threat Analyzer")
st.caption("Real-time alert monitoring")

try:
    h = requests.get(f"{API_URL}/health", timeout=5)
    health = h.json()
    api_label = "API online"
    api_color = "green"
    qdrant_ok = health.get("qdrant") == "ok"
    qdrant_label = "Qdrant ok" if qdrant_ok else "Qdrant unreachable"
    qdrant_color = "green" if qdrant_ok else "red"
    vllm_ok = health.get("vllm") == "ok"
    vllm_label = "vLLM ok" if vllm_ok else "vLLM offline"
    vllm_color = "green" if vllm_ok else "gray"
except Exception as e:
    api_label = f"API unreachable — {e}"
    api_color = "red"
    qdrant_label = "Qdrant ?"
    qdrant_color = "gray"
    vllm_label = "vLLM ?"
    vllm_color = "gray"

try:
    r = redis.Redis(host=redis_host, port=redis_port, db=0)
    r.ping()
    redis_label = "Redis online"
    redis_color = "green"
    # Persist provider/model selection so consumer picks it up without restart
    r.set("config:consumer:provider", provider)
    r.set("config:consumer:model", model_name or "")
except Exception:
    r = None
    redis_label = "Redis unreachable"
    redis_color = "red"

st.markdown(
    f'<span style="color:{api_color};font-size:0.85rem">● {api_label}</span>'
    f'&emsp;<span style="color:{qdrant_color};font-size:0.85rem">● {qdrant_label}</span>'
    f'&emsp;<span style="color:{vllm_color};font-size:0.85rem">● {vllm_label}</span>'
    f'&emsp;<span style="color:{redis_color};font-size:0.85rem">● {redis_label}</span>'
    f'&emsp;<span style="color:#2563eb;font-size:0.85rem">🤖 {provider} / {model_name}</span>',
    unsafe_allow_html=True,
)

st.divider()

# ── Dashboard metrics ────────────────────────────────────────────────────────
if r is None:
    st.warning("Cannot connect to Redis. Check connection settings in sidebar.")
    st.stop()

results_raw = r.lrange(RESULT_QUEUE, 0, -1)
alerts = [json.loads(x) for x in reversed(results_raw)]

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Alerts", len(alerts))
critical = sum(1 for a in alerts if a.get("severity") == "Critical")
high = sum(1 for a in alerts if a.get("severity") == "High")
col2.metric("🔴 Critical", critical)
col3.metric("🟠 High", high)
col4.metric("🟡🟢 Medium/Low", len(alerts) - critical - high)

st.divider()

# ── Alert list ───────────────────────────────────────────────────────────────
if not alerts:
    st.info("No alerts yet. Waiting for real-time data…")
else:
    for i, alert in enumerate(alerts[:50]):
        severity = alert.get("severity", "Unknown")
        icon = SEVERITY_STYLE.get(severity.capitalize(), SEVERITY_STYLE["Unknown"])[1]
        meta = alert.get("_meta", {})
        src = meta.get("src_ip", "?")
        dst = meta.get("dest_ip", "?")
        port = meta.get("dest_port", "?")
        proto = meta.get("proto", "")

        header = f"{icon} {src} → {dst}:{port}/{proto} | {severity.upper()}"

        with st.expander(header, expanded=(i == 0)):
            col_l, col_r = st.columns([3, 2])
            render_result(alert, col_l)
            render_contexts(alert.get("contexts", []), col_r)

# ── Auto-refresh ─────────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(3)
    st.rerun()
