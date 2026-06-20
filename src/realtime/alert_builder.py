
from pathlib import Path
import sys


project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
from src.data_process.zeek_alert_builder import build_alert_text


def build_combined_alert(suricata_event: dict, zeek_flow: dict | None) -> str:
    """Build combined alert text: Suricata signature + Zeek telemetry.

    Output preserves "port {N}" and "Connection state {X}:" patterns
    for KBRetriever regex matching.
    """
    parts: list[str] = []

    alert = suricata_event.get("alert", {})
    sig = alert.get("signature", "Unknown alert")
    sev = alert.get("severity", "?")
    cat = alert.get("category", "")

    header = f"Suricata alert: {sig} (severity {sev}"
    if cat:
        header += f", {cat}"
    header += ")."
    parts.append(header)

    if zeek_flow:
        mapped = {
            "src_ip_zeek":    zeek_flow.get("id.orig_h", ""),
            "dest_ip_zeek":   zeek_flow.get("id.resp_h", ""),
            "dest_port_zeek": zeek_flow.get("id.resp_p", 0),
            "proto":          zeek_flow.get("proto", ""),
            "conn_state":     zeek_flow.get("conn_state", ""),
            "history":        zeek_flow.get("history", ""),
            "duration":       zeek_flow.get("duration", 0),
            "orig_bytes":     zeek_flow.get("orig_bytes", 0),
            "resp_bytes":     zeek_flow.get("resp_bytes", 0),
            "orig_pkts":      zeek_flow.get("orig_pkts", 0),
            "resp_pkts":      zeek_flow.get("resp_pkts", 0),
            "service":        zeek_flow.get("service", ""),
        }
        zeek_text = build_alert_text(mapped)
        if zeek_text:
            parts.append(zeek_text)
    else:
        proto = suricata_event.get("proto", "TCP").upper()
        dp = suricata_event.get("dest_port", 0)
        parts.append(f"{proto} connection to port {dp}.")

    return " ".join(parts)
