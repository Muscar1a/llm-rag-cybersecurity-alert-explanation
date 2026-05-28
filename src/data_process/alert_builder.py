import argparse
import csv
import json
import sys
from datetime import datetime

PROTO = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "Unknown"}

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
}

# Ports commonly abused as C2 channels or proxy bypass
_C2_PROXY_PORTS = {8080, 8443, 3128, 1080, 9090, 4444, 6667, 6666}

# Known standard OS TCP initial window sizes (exact match)
# 8192 intentionally excluded — original WIN_OS already labeled it non-standard
_STANDARD_WINDOWS = {
    65535: "Windows (legacy)",
    64240: "Windows 10/11",
    65392: "Windows",
    29200: "Linux",
    5840:  "Linux (older kernel)",
    14600: "Linux",
    43690: "Linux",
    32768: "macOS / Linux",
}


def _classify_window(win: int) -> str:
    """Map TCP window size to OS fingerprint or anomaly label."""
    if win in _STANDARD_WINDOWS:
        return _STANDARD_WINDOWS[win]
    if win <= 0:
        return "unknown"
    if win < 1024:
        return "embedded/stripped-down stack (malware candidate)"
    if win < 4096:
        return "non-standard small window (embedded device or malware stack)"
    return "non-standard/custom stack"


def _get_flag_signature(row: dict) -> str:
    """Summarize TCP flag combination as a named signature."""
    syn = get_int(row, "SYN Flag Cnt")
    ack = get_int(row, "ACK Flag Cnt")
    rst = get_int(row, "RST Flag Cnt")
    fin = get_int(row, "FIN Flag Cnt")
    psh = get_int(row, "PSH Flag Cnt")
    if syn > 0 and ack == 0 and rst == 0 and fin == 0:
        return "SYN-only"
    if syn == 0 and ack > 0 and rst == 0 and fin == 0 and psh == 0:
        return "ACK-only"
    if psh > 0 and rst > 0:
        return "PSH+RST"
    if syn > 0 and fin > 0:
        return "SYN+FIN"
    if fin > 0 and syn == 0:
        return "FIN-no-SYN"
    if syn > 0 and ack > 0 and fin > 0:
        return "SYN-ACK-FIN-normal"
    return "other"


def get_float(row, col, default=0.0):
    try:
        v = float(row.get(col, default))
        return v if v == v else default  # NaN check
    except (ValueError, TypeError):
        return default

def get_int(row, col, default=0):
    return int(get_float(row, col, default))


def build_alert_text(row: dict, baseline=None) -> str:
    parts = []

    dst_port = get_int(row, "Dst Port")
    proto_num = int(get_float(row, "Protocol"))
    proto = PROTO.get(proto_num, f"proto-{proto_num}")
    service = SERVICES.get(dst_port)
    port_str = f"port {dst_port}/{service}" if service else f"port {dst_port}"
    parts.append(f"{proto} flow on {port_str}")

    fwd_pkts = get_int(row, "Tot Fwd Pkts")
    bwd_pkts = get_int(row, "Tot Bwd Pkts")
    fwd_bytes = get_float(row, "TotLen Fwd Pkts")
    bwd_bytes = get_float(row, "TotLen Bwd Pkts")
    total_pkts = fwd_pkts + bwd_pkts
    ratio = round(bwd_bytes / fwd_bytes, 2) if fwd_bytes > 0 else None

    parts.append(
        f"Volume: {total_pkts} packets total "
        f"({fwd_pkts} forward / {bwd_pkts} backward), "
        f"{int(fwd_bytes + bwd_bytes)} bytes total "
        f"({int(fwd_bytes)} B sent, {int(bwd_bytes)} B received)."
    )

    # Semantic anchor: byte ratio with behavioral interpretation
    if ratio is not None:
        if ratio > 5:
            direction = "heavily server-dominant — large download or potential data exfiltration"
        elif ratio > 2:
            direction = "server-dominant"
        elif ratio > 0.5:
            direction = "balanced"
        else:
            direction = "client-dominant — client sent significantly more than received; upload, POST, or C2 beacon"
        parts.append(f"Byte ratio received/sent: {ratio}x ({direction}).")

    dur_us = get_float(row, "Flow Duration")
    dur_s = dur_us / 1e6
    dur_str = (
        f"{round(dur_s * 1000, 1)} ms" if dur_s < 1
        else f"{round(dur_s, 2)} s" if dur_s < 60
        else f"{round(dur_s / 60, 1)} min"
    )
    parts.append(f"Duration: {dur_str}.")

    iat_mean_us = get_float(row, "Flow IAT Mean")
    iat_std_us  = get_float(row, "Flow IAT Std")
    iat_max_us  = get_float(row, "Flow IAT Max")
    fwd_iat_max_us  = get_float(row, "Fwd IAT Max")
    fwd_iat_mean_us = get_float(row, "Fwd IAT Mean")

    if iat_mean_us > 0:
        iat_parts = [
            f"mean {round(iat_mean_us / 1000, 1)} ms",
            f"std {round(iat_std_us / 1000, 1)} ms",
            f"max {round(iat_max_us / 1000, 1)} ms",
        ]
        # Semantic anchor: highly regular IAT = scripted/automated sender
        regularity = ""
        if iat_std_us < iat_mean_us * 0.1:
            regularity = " (highly regular — consistent with automated/scripted sender or keepalive beacon)"
        parts.append(f"Inter-arrival time (IAT): {', '.join(iat_parts)}{regularity}.")

    if fwd_iat_max_us > 0:
        parts.append(
            f"Forward IAT: mean {round(fwd_iat_mean_us / 1000, 1)} ms, "
            f"max {round(fwd_iat_max_us / 1000, 1)} ms."
        )

    fwd_max = get_float(row, "Fwd Pkt Len Max")
    fwd_min = get_float(row, "Fwd Pkt Len Min")
    fwd_std = get_float(row, "Fwd Pkt Len Std")
    bwd_max = get_float(row, "Bwd Pkt Len Max")
    bwd_min = get_float(row, "Bwd Pkt Len Min")
    bwd_std = get_float(row, "Bwd Pkt Len Std")

    # Semantic anchors: annotate what zero / uniform sizes mean behaviorally
    fwd_note = ""
    if fwd_max == 0:
        fwd_note = " (no payload in forward direction)"
    elif fwd_std == 0.0:
        fwd_note = " (perfectly uniform — automated/scripted sender, not human interaction)"

    bwd_note = ""
    if bwd_pkts == 0 or (bwd_max == 0 and bwd_min == 0):
        bwd_note = " (no server response)"
    elif bwd_std == 0.0:
        bwd_note = " (perfectly uniform server responses)"

    parts.append(
        f"Forward packet sizes: min {int(fwd_min)} B, max {int(fwd_max)} B, "
        f"std {round(fwd_std, 1)} B{fwd_note}. "
        f"Backward packet sizes: min {int(bwd_min)} B, max {int(bwd_max)} B, "
        f"std {round(bwd_std, 1)} B{bwd_note}."
    )

    flag_map = [
        ("SYN Flag Cnt", "SYN"), ("ACK Flag Cnt", "ACK"),
        ("PSH Flag Cnt", "PSH"), ("FIN Flag Cnt", "FIN"),
        ("RST Flag Cnt", "RST"), ("URG Flag Cnt", "URG"),
        ("ECE Flag Cnt", "ECE"), ("CWE Flag Count", "CWE"),
    ]
    flags_set = [
        f"{name}x{get_int(row, col)}"
        for col, name in flag_map
        if get_int(row, col) > 0
    ]
    parts.append(f"TCP flags: {', '.join(flags_set)}." if flags_set else "TCP flags: none set.")

    init_fwd_win = get_int(row, "Init Fwd Win Byts")
    init_bwd_win = get_int(row, "Init Bwd Win Byts")
    seg_min = get_int(row, "Fwd Seg Size Min")

    win_parts = []
    if init_fwd_win > 0:
        win_parts.append(f"client init window {init_fwd_win} B ({_classify_window(init_fwd_win)})")
    if init_bwd_win == -1:
        win_parts.append("server init window: none (server did not respond)")
    elif init_bwd_win > 0:
        win_parts.append(f"server init window {init_bwd_win} B")
    if win_parts:
        parts.append(f"TCP window: {'; '.join(win_parts)}.")

    if seg_min > 0:
        parts.append(f"Minimum forward segment size: {seg_min} B.")

    # --- Behavioral hints ---
    hints = []
    syn_cnt = get_int(row, "SYN Flag Cnt")
    ack_cnt = get_int(row, "ACK Flag Cnt")
    rst_cnt = get_int(row, "RST Flag Cnt")
    fin_cnt = get_int(row, "FIN Flag Cnt")
    psh_cnt = get_int(row, "PSH Flag Cnt")

    # 1. SYN flood impossible
    if syn_cnt == 0:
        hints.append("SYN flood: NOT possible (SYN count = 0)")

    # 2. Zero-byte flow
    if fwd_bytes == 0 and bwd_bytes == 0:
        hints.append("Zero-byte flow: no data transferred")

    # 3. ACK-only probe: no SYN, ACK present, zero payload, server silent
    #    → botnet C2 reachability check or port liveness probe
    if syn_cnt == 0 and ack_cnt > 0 and fwd_bytes == 0 and bwd_pkts == 0:
        hints.append(
            "ACK-only probe (no SYN, zero payload, server silent): "
            "matches botnet C2 reachability check or port liveness probe"
        )

    # 4. Non-standard TCP stack fingerprint (window size not matching any known OS)
    if init_fwd_win > 0 and init_fwd_win not in _STANDARD_WINDOWS:
        if init_fwd_win < 4096:
            hints.append(
                f"Malware-range TCP window {init_fwd_win} B "
                f"(< 4096 B, not matching any standard OS): "
                "embedded or stripped-down malware TCP stack"
            )
        else:
            hints.append(
                f"Non-OS TCP window {init_fwd_win} B "
                "(does not match Windows/Linux/macOS fingerprint): "
                "custom or malware TCP stack"
            )

    # 5. PSH+RST micro-burst: data sent then connection abruptly torn down
    #    → C2 check-in or evasion of flow-duration-based detection
    if psh_cnt > 0 and rst_cnt > 0 and dur_s < 0.05:
        hints.append(
            "PSH+RST micro-burst (< 50 ms): data pushed then connection abruptly reset — "
            "consistent with C2 check-in or evasion of flow-duration detection"
        )

    # 6. RST termination without FIN (abnormal teardown, not a micro-burst)
    if rst_cnt > 0 and fin_cnt == 0 and total_pkts > 2 and not (psh_cnt > 0 and dur_s < 0.05):
        hints.append(
            "RST termination without FIN: connection abruptly reset — "
            "abnormal teardown seen in port scanning, C2 beaconing, and exploit attempts"
        )

    # 7. Proxy/C2 candidate port combined with non-browser stack
    #    → strong signal for malware C2 channel
    win_label = _classify_window(init_fwd_win) if init_fwd_win > 0 else ""
    if dst_port in _C2_PROXY_PORTS and ("non-standard" in win_label or "malware" in win_label or "embedded" in win_label):
        hints.append(
            f"Non-browser TCP stack on proxy/C2-candidate port {dst_port}: "
            "strongly consistent with malware using proxy port as C2 channel"
        )

    # 8. SYN-only (no ACK, no data) → half-open port scan
    if syn_cnt > 0 and ack_cnt == 0 and fwd_bytes == 0:
        hints.append(
            "SYN-only flow (no ACK, no data): half-open connection — "
            "consistent with SYN port scan"
        )

    # 9. FIN without SYN → abnormal TCP state
    if fin_cnt > 0 and syn_cnt == 0:
        hints.append(
            "FIN without prior SYN: abnormal TCP state — "
            "possible FIN scan (OS fingerprinting) or mid-session injection"
        )

    # 10. One-directional flow with payload (server never responded to data)
    if bwd_pkts == 0 and fwd_bytes > 0:
        hints.append(
            "One-directional flow with payload: client sent data but server never responded — "
            "possible filtered/closed port, firewall drop, or exploit attempt"
        )

    # 11. Baseline anomaly annotations (if baseline provided)
    if baseline is not None:
        for feature in ["Flow Pkts/s", "Flow Byts/s", "Flow Duration", "Flow IAT Mean"]:
            ann = baseline.annotate(proto_num, dst_port, feature, get_float(row, feature))
            if ann:
                hints.append(f"{feature}: {ann}")

    if hints:
        parts.append(f"Analysis hints: {'; '.join(hints)}.")
    return " ".join(parts)


def build_metadata(row: dict) -> dict:
    dst_port  = get_int(row, "Dst Port")
    proto_num = int(get_float(row, "Protocol"))
    fwd_pkts  = get_int(row, "Tot Fwd Pkts")
    bwd_pkts  = get_int(row, "Tot Bwd Pkts")
    fwd_bytes = get_float(row, "TotLen Fwd Pkts")
    bwd_bytes = get_float(row, "TotLen Bwd Pkts")
    dur_s     = get_float(row, "Flow Duration") / 1e6
    total_pkts  = fwd_pkts + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes

    return {
        # Original fields
        "dst_port":     dst_port,
        "service":      SERVICES.get(dst_port),
        "protocol":     PROTO.get(proto_num, f"proto-{proto_num}"),
        "duration_s":   round(dur_s, 6),
        "total_pkts":   total_pkts,
        "total_bytes":  int(total_bytes),
        "init_fwd_win": get_int(row, "Init Fwd Win Byts"),
        # Derived fields for hybrid search / filtering
        "pkts_per_s":        round(total_pkts / dur_s, 2) if dur_s > 0 else 0,
        "bytes_per_pkt":     round(total_bytes / total_pkts, 1) if total_pkts > 0 else 0,
        "fwd_bwd_pkt_ratio": round(fwd_pkts / bwd_pkts, 2) if bwd_pkts > 0 else None,
        "is_c2_proxy_port":  dst_port in _C2_PROXY_PORTS,
        "flag_signature":    _get_flag_signature(row),
    }


def process_row(row: dict) -> dict:
    return {
        "text":     build_alert_text(row),
        "metadata": build_metadata(row),
    }


if __name__ == "__main__":
    try:
        import pandas as _pd, os as _os, sys as _sys

        _csv_path = _os.path.join("E:/Uni/BigProject/data/raw/cse-cic-ids2018", "combined_shorten.csv")
        if not _os.path.exists(_csv_path):
            print("Test CSV not found:", _csv_path)
            _sys.exit(1)

        _df = _pd.read_csv(_csv_path, low_memory=False)

        print("Running quick alert tests on first 3 rows of combined_shorten.csv using process_row()")
        for idx, _r in _df.head(3).iterrows():
            result = process_row(_r.to_dict())
            print(f"\n--- Record {idx} ---")
            print(result["text"])

    except Exception as _e:
        print("Error during test run:", _e)
