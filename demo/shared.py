import json

import requests
import streamlit as st

API_URL = "http://127.0.0.1:8000"

FALLBACK_PROVIDERS = [
    {"id": "vllm", "label": "vLLM (Local)", "default_model": "Qwen/Qwen2.5-14B-Instruct", "models": ["Qwen/Qwen2.5-14B-Instruct"], "requires_api_key": False},
    {"id": "openai", "label": "OpenAI", "default_model": "gpt-4o-mini", "models": ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "gpt-4.1-nano"], "requires_api_key": True},
    {"id": "deepseek", "label": "DeepSeek", "default_model": "deepseek-v4-flash", "models": ["deepseek-v4-flash", "deepseek-v4-pro"], "requires_api_key": True},
    {"id": "gemini", "label": "Google Gemini", "default_model": "gemini-2.0-flash", "models": ["gemini-2.0-flash", "gemini-2.5-flash", "gemini-2.5-pro"], "requires_api_key": True},
    {"id": "glm", "label": "GLM (Zhipu)", "default_model": "glm-4-flash", "models": ["glm-4-flash", "glm-4-plus"], "requires_api_key": True},
    {"id": "kimi", "label": "Kimi (Moonshot)", "default_model": "moonshot-v1-8k", "models": ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"], "requires_api_key": True},
    {"id": "grok", "label": "Grok (xAI)", "default_model": "grok-3-mini", "models": ["grok-3-mini", "grok-3"], "requires_api_key": True},
]


def fetch_providers() -> list[dict]:
    try:
        resp = requests.get(f"{API_URL}/providers", timeout=3)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return FALLBACK_PROVIDERS


def render_provider_sidebar():
    providers = fetch_providers()
    labels = [p["label"] for p in providers]

    st.header("Model")
    idx = st.selectbox("Provider", range(len(labels)), format_func=lambda i: labels[i])
    selected = providers[idx]

    model_name = selected["default_model"]

    if selected["requires_api_key"]:
        models = selected.get("models", [selected["default_model"]])
        model_idx = st.selectbox(
            "Model", range(len(models)),
            format_func=lambda i: models[i],
        )
        model_name = models[model_idx]
    else:
        st.caption(f"Model: **{model_name}**")

    return selected["id"], model_name

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

RISK_COLOR = {"low": "#16a34a", "medium": "#d97706", "high": "#dc2626"}


def severity_badge(severity: str) -> str:
    key = severity.capitalize()
    bg, icon = SEVERITY_STYLE.get(key, SEVERITY_STYLE["Unknown"])
    return (
        f'<div style="display:inline-block;background:{bg};color:white;'
        f'padding:8px 22px;border-radius:24px;font-weight:700;font-size:1.1rem;'
        f'letter-spacing:0.05em;margin-bottom:12px">'
        f'{icon}&nbsp; {severity.upper()} SEVERITY</div>'
    )


def source_badge(source: str) -> str:
    bg = SOURCE_COLOR.get(source, "#6b7280")
    label = SOURCE_LABEL.get(source, source.upper())
    return (
        f'<span style="background:{bg};color:white;padding:2px 10px;'
        f'border-radius:12px;font-size:0.78rem;font-weight:600">{label}</span>'
    )


def render_contexts(contexts: list, container):
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
                st.markdown(source_badge(src), unsafe_allow_html=True)
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


def render_remediation(res: dict, container):
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


def render_result(res: dict, container):
    with container:
        st.markdown(severity_badge(res.get("severity", "Unknown")), unsafe_allow_html=True)
        st.subheader("Threat Description")
        st.write(res.get("threat_description") or "—")
        st.subheader("Explanation")
        st.write(res.get("rationale") or "—")
        steps = res.get("mitigation_steps", [])
        if steps:
            st.subheader("Mitigation Steps")
            for idx, step in enumerate(steps, 1):
                st.markdown(f"**{idx}.** {step}")
        render_remediation(res, container)


def render_batch_entry(i: int, entry: dict):
    if entry["ok"]:
        result = entry["result"]
        severity = result.get("severity", "Unknown")
        icon = SEVERITY_STYLE.get(severity.capitalize(), SEVERITY_STYLE["Unknown"])[1]
        with st.expander(f"Alert #{i + 1} — {icon} {severity.upper()}", expanded=False):
            col_l, col_r = st.columns([3, 2])
            render_result(result, col_l)
            render_contexts(result.get("contexts", []), col_r)
    else:
        with st.expander(f"Alert #{i + 1} — ⚠️ Error", expanded=False):
            st.error(entry["error"])


def parse_upload(content: str, filename: str) -> list[str]:
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
