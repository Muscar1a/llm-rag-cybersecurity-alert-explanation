import json
import os
import time
import redis
import streamlit as st

st.set_page_config(page_title="Real-time Alerts", layout="wide")

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
RESULT_QUEUE = "alerts:results"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)

SEVERITY_COLOR = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
}

st.title("Real-time Alert Monitor")

placeholder = st.empty()

while True:
    results_raw = r.lrange(RESULT_QUEUE, 0, -1)
    alerts = [json.loads(x) for x in reversed(results_raw)]

    with placeholder.container():
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Alerts", len(alerts))
        critical = sum(1 for a in alerts if a.get("severity") == "Critical")
        high = sum(1 for a in alerts if a.get("severity") == "High")
        col2.metric("🔴 Critical", critical)
        col3.metric("🟠 High", high)
        col4.metric("🟡🟢 Medium/Low", len(alerts) - critical - high)

        st.divider()

        for i, alert in enumerate(alerts[:20]):
            severity = alert.get("severity", "Unknown")
            icon = SEVERITY_COLOR.get(severity, "⚪")
            meta = alert.get("_meta", {})
            src = meta.get("src_ip", "?")
            dst = meta.get("dest_ip", "?")
            port = meta.get("dest_port", "?")
            proto = meta.get("proto", "")

            header = f"{icon} {src} → {dst}:{port}/{proto} | {severity}"

            with st.expander(header, expanded=(i == 0)):
                st.markdown(f"**Threat:** {alert.get('threat_description', '')}")
                st.markdown(f"**Rationale:** {alert.get('rationale', '')}")

                steps = alert.get("mitigation_steps", [])
                if steps:
                    st.markdown("**Mitigation:**")
                    for s in steps:
                        st.markdown(f"- {s}")

                contexts = alert.get("contexts", [])
                if contexts:
                    with st.popover("Retrieved KB Sources"):
                        for ctx in contexts:
                            st.caption(
                                f"{ctx.get('source', '')} | "
                                f"score: {ctx.get('score', 'N/A')}"
                            )
                            st.text(ctx.get("text", "")[:200])

    time.sleep(3)
