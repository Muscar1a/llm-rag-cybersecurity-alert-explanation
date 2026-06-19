import json
import requests
import streamlit as st

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


RISK_COLOR = {"low": "#16a34a", "medium": "#d97706", "high": "#dc2626"}


def _render_remediation(res: dict, container):
    commands = res.get("remediation_commands", [])
    if not commands:
        return
    with container:
        if res.get("auto_response_triggered"):
            st.markdown(
                '<div style="background:#dc2626;color:white;padding:10px 16px;'
                'border-radius:8px;font-weight:700;margin-bottom:12px">'
                '⚡ AUTO-RESPONSE TRIGGERED</div>',
                unsafe_allow_html=True,
            )
            for log_line in res.get("auto_response_log", []):
                st.caption(log_line)

        st.subheader("Remediation Commands")
        for cmd in commands:
            risk_bg = RISK_COLOR.get(cmd.get("risk", "low"), "#6b7280")
            auto_badge = (
                ' <span style="background:#2563eb;color:white;padding:1px 8px;'
                'border-radius:8px;font-size:0.72rem">Auto-executable</span>'
                if cmd.get("auto_executable") else ""
            )
            status = cmd.get("execution_status")
            status_badge = ""
            if status:
                s_color = {"success": "#16a34a", "dry_run": "#2563eb", "failed": "#dc2626"}
                status_badge = (
                    f' <span style="background:{s_color.get(status, "#6b7280")};color:white;'
                    f'padding:1px 8px;border-radius:8px;font-size:0.72rem">{status}</span>'
                )

            header = (
                f'<span style="background:{risk_bg};color:white;padding:1px 8px;'
                f'border-radius:8px;font-size:0.72rem">risk: {cmd.get("risk","low")}</span>'
                f'{auto_badge}{status_badge}'
            )

            with st.expander(cmd.get("description", "Command")):
                st.markdown(header, unsafe_allow_html=True)
                st.code(cmd.get("command", ""), language="bash")
                if cmd.get("undo_command"):
                    st.caption("Undo:")
                    st.code(cmd["undo_command"], language="bash")


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
        _render_remediation(res, container)


def _parse_upload(content: str, filename: str) -> list[str]:
    """Parse uploaded file into a list of alert texts.

    Supports:
    - JSON array of objects with 'alert_text' or 'user_input' key
    - JSON array of strings
    - Plain text (single alert)
    """
    if filename.lower().endswith(".json"):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                alerts = []
                for item in data:
                    if isinstance(item, str):
                        alerts.append(item)
                    elif isinstance(item, dict):
                        text = item.get("alert_text") or item.get("user_input") or item.get("text")
                        if text:
                            alerts.append(str(text))
                return alerts if alerts else [content]
            elif isinstance(data, dict):
                text = data.get("alert_text") or data.get("user_input") or data.get("text")
                return [str(text)] if text else [content]
        except Exception:
            pass
    return [content]


def _render_batch_entry(i: int, entry: dict):
    if entry["ok"]:
        result = entry["result"]
        severity = result.get("severity", "Unknown")
        icon = SEVERITY_STYLE.get(severity.capitalize(), SEVERITY_STYLE["Unknown"])[1]
        with st.expander(f"Alert #{i + 1} — {icon} {severity.upper()}", expanded=False):
            col_l, col_r = st.columns([3, 2])
            _render_result(result, col_l)
            _render_contexts(result.get("contexts", []), col_r)
    else:
        with st.expander(f"Alert #{i + 1} — ⚠️ Error", expanded=False):
            st.error(entry["error"])


# ── Sidebar — metadata & auto-response ────────────────────────────────────────
with st.sidebar:
    st.header("Alert Metadata")
    meta_src_ip = st.text_input("Source IP", placeholder="e.g. 192.168.1.100")
    meta_dest_ip = st.text_input("Destination IP", placeholder="e.g. 10.0.0.5")
    meta_dest_port = st.number_input("Destination Port", min_value=0, max_value=65535, value=0, step=1)
    st.divider()
    st.header("Auto-Response")
    auto_response_on = st.toggle("Enable auto-response", value=False)

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
batch_alerts: list[str] = []

with paste_tab:
    pasted = st.text_area(
        "alert",
        height=200,
        placeholder=(
            "Paste a security alert, Snort/Suricata rule match, "
            "syslog entry, or incident description…"
        ),
        label_visibility="collapsed",
        key="paste_input",
    )
    alert_text = pasted

with upload_tab:
    st.markdown(
        "<small style='color:#6b7280'>"
        "📦 <b>.json</b> — array of objects with <code>alert_text</code> or <code>user_input</code> key, "
        "or array of strings — supports multiple alerts (batch)<br>"
        "📄 <b>.txt / .log</b> — entire file treated as a single alert"
        "</small>",
        unsafe_allow_html=True,
    )
    uploaded = st.file_uploader(
        "file", type=["txt", "log", "json"], label_visibility="collapsed",
        key="upload_input",
    )
    if uploaded:
        file_content = uploaded.read().decode("utf-8", errors="replace")
        alerts = _parse_upload(file_content, uploaded.name)
        if len(alerts) == 1:
            alert_text = alerts[0]
            st.caption("1 alert found")
        elif len(alerts) > 1:
            batch_alerts = alerts
            st.caption(f"{len(alerts)} alerts found — batch mode")
        else:
            st.warning("No alerts found in file")

is_single = bool(alert_text.strip())
is_batch = bool(batch_alerts)

# ── State ────────────────────────────────────────────────────────────────────
if "result" not in st.session_state:
    st.session_state.result = None
    st.session_state.err = None
if "batch_results" not in st.session_state:
    st.session_state.batch_results = []
if "running" not in st.session_state:
    st.session_state.running = False

is_running = st.session_state.running

# ── Controls ─────────────────────────────────────────────────────────────────
c1, c2, c3 = st.columns([2, 3, 1])
with c1:
    k = st.slider("Top-k sources", min_value=1, max_value=10, value=5)
with c2:
    if is_running:
        st.button("⏳ Analyzing…", disabled=True, type="primary", use_container_width=True)
        analyze_btn = False
    else:
        analyze_btn = st.button(
            "🔍 Analyze Threat",
            type="primary",
            use_container_width=True,
            disabled=not (is_single or is_batch),
        )
with c3:
    clear_btn = st.button("🗑️ Clear", use_container_width=True, disabled=is_running)

if clear_btn:
    st.session_state.result = None
    st.session_state.err = None
    st.session_state.batch_results = []
    st.session_state.running = False
    st.rerun()

# Button click → snapshot input, clear widgets, rerun to show disabled button
if analyze_btn and (is_single or is_batch):
    st.session_state.running = True
    st.session_state._pending_alert = alert_text
    st.session_state._pending_batch = list(batch_alerts)
    st.session_state._pending_k = k
    st.session_state["paste_input"] = ""
    st.session_state.pop("upload_input", None)
    st.rerun()

# ── Single alert: streaming ───────────────────────────────────────────────────
_pending_alert = st.session_state.get("_pending_alert", "")
_pending_batch = st.session_state.get("_pending_batch", [])
_pending_k     = st.session_state.get("_pending_k", k)

if is_running and _pending_alert.strip():
    st.session_state.result = None
    st.session_state.err = None
    st.session_state.batch_results = []
    st.divider()

    left, right = st.columns([3, 2])
    result_box   = left.empty()
    contexts_box = right.empty()

    _meta = {}
    if meta_src_ip.strip():
        _meta["src_ip"] = meta_src_ip.strip()
    if meta_dest_ip.strip():
        _meta["dest_ip"] = meta_dest_ip.strip()
    if meta_dest_port > 0:
        _meta["dest_port"] = meta_dest_port
    payload = {
        "alert_text": _pending_alert,
        "k": _pending_k,
        "metadata": _meta or None,
        "auto_response": auto_response_on,
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

        st.session_state.running = False
        st.rerun()

    except Exception as exc:
        st.session_state.err = str(exc)
        st.session_state.result = None
        st.session_state.running = False

# ── Batch: sequential analyze ─────────────────────────────────────────────────
if is_running and _pending_batch:
    st.session_state.result = None
    st.session_state.err = None
    st.session_state.batch_results = []
    st.divider()

    n = len(_pending_batch)
    progress = st.progress(0, text=f"Analyzing 0 / {n}…")

    _bmeta = {}
    if meta_src_ip.strip():
        _bmeta["src_ip"] = meta_src_ip.strip()
    if meta_dest_ip.strip():
        _bmeta["dest_ip"] = meta_dest_ip.strip()
    if meta_dest_port > 0:
        _bmeta["dest_port"] = meta_dest_port

    for i, alert in enumerate(_pending_batch):
        try:
            resp = requests.post(
                f"{API_URL}/analyze",
                json={
                    "alert_text": alert,
                    "k": _pending_k,
                    "metadata": _bmeta or None,
                    "auto_response": auto_response_on,
                },
                timeout=300,
            )
            resp.raise_for_status()
            entry = {"ok": True, "result": resp.json()}
        except Exception as exc:
            entry = {"ok": False, "error": str(exc)}

        st.session_state.batch_results.append(entry)
        _render_batch_entry(i, entry)
        progress.progress((i + 1) / n, text=f"Analyzing {i + 1} / {n}…")

    progress.progress(1.0, text=f"Done — {n} alerts analyzed")
    st.session_state.running = False
    st.rerun()

# ── Single result re-render ───────────────────────────────────────────────────
if st.session_state.err:
    st.error(f"API error: {st.session_state.err}")

if st.session_state.result:
    res = st.session_state.result
    st.divider()
    left, right = st.columns([3, 2])
    _render_result(res, left)
    _render_contexts(res.get("contexts", []), right)

# ── Batch results re-render ───────────────────────────────────────────────────
if not is_running and st.session_state.batch_results:
    st.divider()
    st.caption(f"{len(st.session_state.batch_results)} alerts analyzed")
    for i, entry in enumerate(st.session_state.batch_results):
        _render_batch_entry(i, entry)
