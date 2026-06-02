import json
import streamlit as st
import requests

API_URL = "http://localhost:8000"

st.set_page_config(
    page_title="Cyber Threat Analyzer",
    page_icon="🛡️",
    layout="wide",
)

SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    "Critical": ("#dc2626", "🔴"),
    "High":     ("#ea580c", "🟠"),
    "Medium":   ("#d97706", "🟡"),
    "Low":      ("#16a34a", "🟢"),
    "Unknown":  ("#6b7280", "⚪"),
}

SOURCE_LABEL: dict[str, str] = {
    "cve":   "CVE",
    "mitre": "MITRE ATT&CK",
    "sigma": "Sigma Rule",
}

SOURCE_COLOR: dict[str, str] = {
    "cve":   "#dc2626",
    "mitre": "#7c3aed",
    "sigma": "#d97706",
}


def _severity_badge(severity: str) -> str:
    key = severity.capitalize()
    bg, icon = SEVERITY_STYLE.get(key, SEVERITY_STYLE["Unknown"])
    return (
        f'<div style="display:inline-block;background:{bg};color:white;'
        f'padding:8px 22px;border-radius:24px;font-weight:700;font-size:1.1rem;'
        f'letter-spacing:0.05em;margin-bottom:12px">'
        f'{icon}&nbsp; {severity.upper()} SEVERITY</div>'
    )


def _source_badge(source: str) -> str:
    bg = SOURCE_COLOR.get(source, "#6b7280")
    label = SOURCE_LABEL.get(source, source.upper())
    return (
        f'<span style="background:{bg};color:white;padding:2px 10px;'
        f'border-radius:12px;font-size:0.78rem;font-weight:600">{label}</span>'
    )


def _render_contexts(contexts: list, container):
    with container:
        st.subheader("Retrieved Knowledge Sources")
        if not contexts:
            st.info("No knowledge sources retrieved.")
            return
        for chunk in contexts:
            src = chunk.get("source", "unknown")
            score = chunk.get("score", 0.0)
            text = chunk.get("text", "")
            cid = chunk.get("chunk_id", "")

            score_str = f"  ·  score {score:.3f}" if score != 0.0 else ""
            label = f"{SOURCE_LABEL.get(src, src.upper())}{score_str}"

            with st.expander(label):
                st.markdown(_source_badge(src), unsafe_allow_html=True)
                st.write("")
                st.write(text[:700] + ("…" if len(text) > 700 else ""))
                if cid:
                    st.caption(f"chunk_id: {cid}")
                meta = chunk.get("metadata", {})
                extra = {
                    mk: mv for mk, mv in meta.items()
                    if mk not in ("chunk_id", "source")
                    and mv
                    and not isinstance(mv, (dict, list))
                }
                for mk, mv in list(extra.items())[:4]:
                    st.caption(f"{mk}: {mv}")


def _render_result(res: dict, container):
    with container:
        st.markdown(_severity_badge(res.get("severity", "Unknown")), unsafe_allow_html=True)
        st.subheader("Threat Description")
        st.write(res.get("threat_description") or "—")
        st.subheader("Explanation")
        st.write(res.get("rationale") or "—")
        steps = res.get("mitigation_steps", [])
        if steps:
            st.subheader("Mitigation Steps")
            for idx, step in enumerate(steps, 1):
                st.markdown(f"**{idx}.** {step}")


# ── Header ───────────────────────────────────────────────────────────────────
st.title("🛡️ Cyber Threat Analyzer")
st.caption("RAG-based cybersecurity threat analysis system")

try:
    h = requests.get(f"{API_URL}/health", timeout=2)
    health = h.json()
    api_ok = health.get("status") == "ok"
    label = "API online" if api_ok else f"API degraded — {health}"
    color = "green" if api_ok else "orange"
except Exception:
    label = "API unreachable"
    color = "red"

st.markdown(
    f'<span style="color:{color};font-size:0.85rem">● {label}</span>',
    unsafe_allow_html=True,
)

st.divider()

# ── Input ────────────────────────────────────────────────────────────────────
st.subheader("Alert Input")

paste_tab, upload_tab = st.tabs(["📋 Paste Text", "📁 Upload File"])

alert_text = ""
with paste_tab:
    pasted = st.text_area(
        "alert",
        height=200,
        placeholder=(
            "Paste a security alert, Snort/Suricata rule match, "
            "syslog entry, or incident description…"
        ),
        label_visibility="collapsed",
    )
    alert_text = pasted

with upload_tab:
    uploaded = st.file_uploader(
        "file", type=["txt", "log", "json"], label_visibility="collapsed"
    )
    if uploaded:
        file_content = uploaded.read().decode("utf-8", errors="replace")
        st.text_area(
            "preview",
            value=file_content[:600] + ("…" if len(file_content) > 600 else ""),
            height=150,
            disabled=True,
            label_visibility="collapsed",
        )
        alert_text = file_content

c1, c2, c3 = st.columns([2, 2, 3])
with c1:
    source_choice = st.selectbox("Knowledge source", ["All", "CVE", "MITRE", "Sigma"])
with c2:
    k = st.slider("Top-k sources", min_value=1, max_value=10, value=5)
with c3:
    analyze_btn = st.button(
        "🔍 Analyze Threat",
        type="primary",
        use_container_width=True,
        disabled=not bool(alert_text.strip()),
    )

source_map = {"All": None, "CVE": "cve", "MITRE": "mitre", "Sigma": "sigma"}

# ── State ────────────────────────────────────────────────────────────────────
if "result" not in st.session_state:
    st.session_state.result = None
    st.session_state.err = None

# ── Streaming analyze ─────────────────────────────────────────────────────────
if analyze_btn and alert_text.strip():
    st.session_state.result = None
    st.session_state.err = None
    st.divider()

    left, right = st.columns([3, 2])
    result_box   = left.empty()
    contexts_box = right.empty()

    payload = {
        "alert_text": alert_text,
        "k": k,
        "source": source_map[source_choice],
    }

    try:
        streamed_text = ""
        contexts = []

        with requests.post(
            f"{API_URL}/analyze/stream",
            json=payload,
            stream=True,
            timeout=300,
        ) as resp:
            resp.raise_for_status()

            for raw_line in resp.iter_lines():
                if not raw_line or not raw_line.startswith(b"data: "):
                    continue
                event = json.loads(raw_line[6:])

                if event["type"] == "contexts":
                    contexts = event["contexts"]
                    _render_contexts(contexts, contexts_box.container())

                elif event["type"] == "token":
                    streamed_text += event["token"]
                    result_box.markdown(
                        f"*Generating analysis…*\n\n```\n{streamed_text}\n```"
                    )

                elif event["type"] == "done":
                    st.session_state.result = {**event, "contexts": contexts}
                    st.session_state.err = None

        st.rerun()

    except Exception as exc:
        st.session_state.err = str(exc)
        st.session_state.result = None

if st.session_state.err:
    st.error(f"API error: {st.session_state.err}")

# ── Results (sau khi stream xong) ────────────────────────────────────────────
if st.session_state.result:
    res = st.session_state.result
    st.divider()

    left, right = st.columns([3, 2])
    _render_result(res, left)
    _render_contexts(res.get("contexts", []), right)
