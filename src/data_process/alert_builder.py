def infer_attack_family(label: str) -> str:
    label = str(label).strip().lower()
    # Bỏ: if label == "benign": return "benign"
    if any(x in label for x in ["ddos", "dos"]):
        return "denial-of-service"
    if "portscan" in label:
        return "reconnaissance"
    if "patator" in label or "brute force" in label:
        return "credential-attack"
    if "web attack" in label or "xss" in label:
        return "web-application-attack"
    if "bot" in label:
        return "botnet"
    return "unknown"


def infer_severity(label: str) -> str:
    label = str(label).strip().lower()
    if "portscan" in label:
        return "Medium"
    if any(x in label for x in ["ddos", "dos", "patator", "brute force", "bot", "web attack", "xss"]):
        return "High"
    return "Unknown"


def _describe_rate(value, unit: str = "packets") -> str:
    if value is None:
        return "unknown"
    v = float(value)
    if unit == "packets":
        low, high = 1_000, 100_000
    else:
        low, high = 10_000, 1_000_000
    if v < low:
        label = "low"
    elif v < high:
        label = "moderate"
    else:
        label = "high"
    return f"{label} ({v:.0f})"


def _describe_duration(duration_us) -> str:
    if duration_us is None:
        return "unknown duration"
    sec = float(duration_us) / 1_000_000
    desc = f"{sec:.3f}s"
    if sec < 0.1:
        desc += " (very short flow)"
    elif sec > 60:
        desc += " (long-lived flow)"
    return desc


def _describe_asymmetry(fwd_pkts, bwd_pkts) -> str:
    fwd = int(fwd_pkts or 0)
    bwd = int(bwd_pkts or 0)
    total = fwd + bwd
    if total == 0:
        return "no packets observed"
    ratio = fwd / total
    base = f"{fwd} forward, {bwd} backward"
    if ratio > 0.9:
        return base + " (heavily forward-dominant, possible scan or flood)"
    if ratio < 0.1:
        return base + " (heavily backward-dominant)"
    return base + " (bidirectional)"


def _describe_flags(syn, rst, psh, ack) -> str:
    syn, rst, psh, ack = (int(x or 0) for x in (syn, rst, psh, ack))
    findings = []
    
    if syn > 10 and ack == 0:
        findings.append(f"SYN-only ({syn} SYN, no ACK) — incomplete handshake, possible flood or stealth scan")
    if rst > max(syn, ack, 1):
        findings.append(f"RST-dominant ({rst} RST) — port rejection or scan response")
    if psh > 0 and syn == 0 and ack == 0:
        findings.append(f"PSH ({psh}) with no handshake flags — anomalous data push")

    if not findings:
        if syn > 100:
            findings.append(f"elevated SYN ({syn})")
        if rst > 50:
            findings.append(f"elevated RST ({rst})")
    
    return "; ".join(findings) if findings else f"normal distribution (SYN={syn}, RST={rst}, PSH={psh}, ACK={ack})"


def build_alert_text(row: dict) -> str:
    dst_port = row.get("destination_port", "unknown")
    label = row.get("label", "unknown")
    
    family = infer_attack_family(label)
    severity = infer_severity(label)
    
    parts = [
        f"[Severity: {severity}] Network flow to destination port {dst_port}.",
        f"Duration: {_describe_duration(row.get('flow_duration'))}.",
        f"Packets: {_describe_asymmetry(row.get('total_fwd_packets'), row.get('total_backward_packets'))}.",
        f"Traffic rate: {_describe_rate(row.get('flow_bytes_s'), 'bytes')} bytes/s,"
        f" {_describe_rate(row.get('flow_packets_s'), 'packets')} packets/s.",
        f"TCP flags: {_describe_flags(row.get('syn_flag_count'), row.get('rst_flag_count'), row.get('psh_flag_count'), row.get('ack_flag_count'))}.",
    ]
    
    if family != "benign" and family != "BENIGN":
        parts.append(f"Pattern resembles {family}.")
    
    return " ".join(parts)