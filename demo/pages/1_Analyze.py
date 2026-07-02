import json

import requests
import streamlit as st

from shared import (
    API_URL,
    parse_upload,
    render_batch_entry,
    render_contexts,
    render_provider_sidebar,
    render_result,
)

st.set_page_config(page_title="Analyze", page_icon="🔍", layout="wide")

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    provider, model_name = render_provider_sidebar()
    st.divider()
    st.header("Alert Metadata")
    meta_src_ip = st.text_input("Source IP", placeholder="e.g. 192.168.1.100")
    meta_dest_ip = st.text_input("Destination IP", placeholder="e.g. 10.0.0.5")
    meta_dest_port = st.number_input(
        "Destination Port", min_value=0, max_value=65535, value=0, step=1,
    )
    st.divider()
    st.header("Options")
    k = st.slider("Top-k sources", min_value=1, max_value=10, value=5)
    auto_response_on = st.toggle("Enable auto-response", value=False)


def _build_metadata():
    meta = {}
    if meta_src_ip.strip():
        meta["src_ip"] = meta_src_ip.strip()
    if meta_dest_ip.strip():
        meta["dest_ip"] = meta_dest_ip.strip()
    if meta_dest_port > 0:
        meta["dest_port"] = meta_dest_port
    return meta or None


# ── Header ───────────────────────────────────────────────────────────────────
st.title("🔍 Analyze")

tab_single, tab_batch = st.tabs(["Single Alert", "Batch Upload"])

# ── Single Alert Tab ─────────────────────────────────────────────────────────
with tab_single:
    alert_text = st.text_area(
        "alert",
        height=200,
        placeholder=(
            "Paste a security alert, Snort/Suricata rule match, "
            "syslog entry, or incident description…"
        ),
        label_visibility="collapsed",
        key="paste_input",
    )

    for _k in ("single_result", "single_err"):
        if _k not in st.session_state:
            st.session_state[_k] = None
    if "single_running" not in st.session_state:
        st.session_state.single_running = False

    is_running = st.session_state.single_running
    has_input = bool(alert_text.strip())

    c1, c2 = st.columns([5, 1])
    with c1:
        analyze_btn = st.button(
            "⏳ Analyzing…" if is_running else "🔍 Analyze Threat",
            type="primary",
            use_container_width=True,
            disabled=is_running or not has_input,
            key="single_analyze",
        )
    with c2:
        clear_btn = st.button(
            "🗑️ Clear", use_container_width=True,
            disabled=is_running, key="single_clear",
        )

    if clear_btn:
        st.session_state.single_result = None
        st.session_state.single_err = None
        st.session_state.single_running = False
        st.rerun()

    if analyze_btn and has_input:
        st.session_state.single_running = True
        st.session_state._single_pending = alert_text
        st.session_state._single_k = k
        st.rerun()

    _pending = st.session_state.get("_single_pending", "")
    _pk = st.session_state.get("_single_k", k)

    if is_running and _pending.strip():
        st.session_state.single_result = None
        st.session_state.single_err = None
        st.divider()

        left, right = st.columns([3, 2])
        result_box = left.empty()
        contexts_box = right.empty()

        payload = {
            "alert_text": _pending,
            "k": _pk,
            "metadata": _build_metadata(),
            "auto_response": auto_response_on,
            "provider": provider,
            "model": model_name,
        }

        try:
            streamed_text = ""
            contexts = []

            with requests.post(
                f"{API_URL}/analyze/stream",
                json=payload, stream=True, timeout=300,
            ) as resp:
                resp.raise_for_status()
                for raw_line in resp.iter_lines():
                    if not raw_line or not raw_line.startswith(b"data: "):
                        continue
                    event = json.loads(raw_line[6:])
                    if event["type"] == "contexts":
                        contexts = event["contexts"]
                        render_contexts(contexts, contexts_box.container())
                    elif event["type"] == "token":
                        streamed_text += event["token"]
                        result_box.markdown(
                            f"*Generating analysis… (raw model output — severity below "
                            f"is provisional and will be recalculated deterministically "
                            f"once generation finishes)*\n\n```\n{streamed_text}\n```"
                        )
                    elif event["type"] == "done":
                        st.session_state.single_result = {
                            **event, "contexts": contexts,
                        }
                        st.session_state.single_err = None

            st.session_state.single_running = False
            st.rerun()

        except Exception as exc:
            st.session_state.single_err = str(exc)
            st.session_state.single_result = None
            st.session_state.single_running = False

    if st.session_state.single_err:
        st.error(f"API error: {st.session_state.single_err}")

    if st.session_state.single_result:
        res = st.session_state.single_result
        st.divider()
        left, right = st.columns([3, 2])
        render_result(res, left)
        render_contexts(res.get("contexts", []), right)

# ── Batch Upload Tab ─────────────────────────────────────────────────────────
with tab_batch:
    st.markdown(
        "<small style='color:#6b7280'>"
        "📦 <b>.json</b> — array of objects with <code>alert_text</code> or "
        "<code>user_input</code> key, or array of strings<br>"
        "📄 <b>.txt / .log</b> — entire file treated as a single alert"
        "</small>",
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader(
        "file", type=["txt", "log", "json"],
        label_visibility="collapsed", key="upload_input",
    )

    alerts: list[str] = []
    if uploaded:
        file_content = uploaded.read().decode("utf-8", errors="replace")
        alerts = parse_upload(file_content, uploaded.name)
        st.caption(f"{len(alerts)} alert(s) found")

    if "batch_results" not in st.session_state:
        st.session_state.batch_results = []
    if "batch_running" not in st.session_state:
        st.session_state.batch_running = False

    is_batch_running = st.session_state.batch_running

    c1, c2 = st.columns([5, 1])
    with c1:
        batch_btn = st.button(
            "⏳ Analyzing…" if is_batch_running else "🔍 Analyze All",
            type="primary",
            use_container_width=True,
            disabled=is_batch_running or not alerts,
            key="batch_analyze",
        )
    with c2:
        batch_clear = st.button(
            "🗑️ Clear", use_container_width=True,
            disabled=is_batch_running, key="batch_clear",
        )

    if batch_clear:
        st.session_state.batch_results = []
        st.session_state.batch_running = False
        st.rerun()

    if batch_btn and alerts:
        st.session_state.batch_running = True
        st.session_state._batch_pending = list(alerts)
        st.session_state._batch_k = k
        st.rerun()

    _batch_pending = st.session_state.get("_batch_pending", [])
    _batch_k = st.session_state.get("_batch_k", k)

    if is_batch_running and _batch_pending:
        st.session_state.batch_results = []
        st.divider()

        n = len(_batch_pending)
        progress = st.progress(0, text=f"Analyzing 0 / {n}…")

        for i, alert in enumerate(_batch_pending):
            try:
                resp = requests.post(
                    f"{API_URL}/analyze",
                    json={
                        "alert_text": alert,
                        "k": _batch_k,
                        "metadata": _build_metadata(),
                        "auto_response": auto_response_on,
                        "provider": provider,
                                    "model": model_name,
                    },
                    timeout=300,
                )
                resp.raise_for_status()
                entry = {"ok": True, "result": resp.json()}
            except Exception as exc:
                entry = {"ok": False, "error": str(exc)}

            st.session_state.batch_results.append(entry)
            render_batch_entry(i, entry)
            progress.progress((i + 1) / n, text=f"Analyzing {i + 1} / {n}…")

        progress.progress(1.0, text=f"Done — {n} alerts analyzed")
        st.session_state.batch_running = False
        st.rerun()

    if not is_batch_running and st.session_state.batch_results:
        st.divider()
        st.caption(f"{len(st.session_state.batch_results)} alerts analyzed")
        for i, entry in enumerate(st.session_state.batch_results):
            render_batch_entry(i, entry)
