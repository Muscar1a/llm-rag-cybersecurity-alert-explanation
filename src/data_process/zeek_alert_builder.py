# ── Lookup tables (neutral facts only) ────────────────────────────────────────

# Port → registered service name. This is a naming convention (IANA-style),
# not an interpretation of intent, so it stays in the alert text.
KNOWN_PORTS: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB/CIFS",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    4848: "GlassFish admin",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Zeek service tag → human-readable protocol name. Neutral naming only.
SERVICE_DESC: dict[str, str] = {
    "ssl":     "TLS/SSL",
    "http":    "HTTP",
    "smb":     "SMB",
    "gssapi":  "GSSAPI",
    "ntlm":    "NTLM",
    "dce_rpc": "DCE/RPC",
    "ssh":     "SSH",
    "dns":     "DNS",
    "ftp":     "FTP",
    "rdp":     "RDP",
    "kerberos": "Kerberos",
}

# Connection state → factual description of the TCP outcome.
# This describes what happened on the wire (which packets were/weren't seen),
# NOT what it might indicate. Compare to the old version which appended
# "host discovery or port scanning", "stealth scan technique", etc.
CONN_STATE_INFO: dict[str, str] = {
    "SF":     "handshake completed, connection closed normally",
    "S0":     "SYN sent, no SYN-ACK received",
    "S1":     "connection established, not terminated during capture",
    "S2":     "originator sent FIN, no reply observed",
    "S3":     "responder sent FIN, no reply observed",
    "REJ":    "SYN sent, RST received in reply",
    "RSTO":   "originator sent RST after partial connection",
    "RSTR":   "responder sent RST",
    "RSTOS0": "originator sent SYN then RST before any SYN-ACK",
    "RSTRH":  "responder sent SYN-ACK then RST",
    "SH":     "originator sent SYN then FIN, no SYN-ACK observed",
    "SHR":    "responder sent SYN-ACK then originator sent RST",
    "OTH":    "mid-stream traffic, no SYN observed in capture",
}

# Uppercase = originator (client), lowercase = responder (server)
HISTORY_CHAR: dict[str, str] = {
    "S": "SYN(client)",    "h": "SYN-ACK(server)",
    "A": "ACK(client)",    "a": "ACK(server)",
    "D": "data(client)",   "d": "data(server)",
    "F": "FIN(client)",    "f": "FIN(server)",
    "R": "RST(client)",    "r": "RST(server)",
    "T": "retrans(client)", "t": "retrans(server)",
    "G": "content-gap",    "W": "zero-window",
    "C": "capture-gap",    "I": "inconsistent-pkt",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get(row: dict, key: str, default=None):
    v = row.get(key, default)
    if v is None or (isinstance(v, float) and v != v):  # NaN check
        return default
    return v


def _float(row: dict, key: str) -> float:
    try:
        return float(_get(row, key, 0) or 0)
    except (ValueError, TypeError):
        return 0.0


def _int(row: dict, key: str) -> int:
    return int(_float(row, key))


def _parse_services(service_raw) -> list[str]:
    if not service_raw or (isinstance(service_raw, float) and service_raw != service_raw):
        return []
    return [s.strip() for s in str(service_raw).split(",") if s.strip()]


def _interpret_history(history: str) -> str:
    if not history:
        return ""
    return " → ".join(HISTORY_CHAR.get(ch, f"flag({ch})") for ch in history)


def _port_label(port: int) -> str:
    return f"port {port}"


def _direction_label(orig_bytes: int, resp_bytes: int) -> str:
    if orig_bytes == 0 and resp_bytes == 0:
        return "no application payload"
    if orig_bytes == 0:
        return "all bytes from responder"
    if resp_bytes == 0:
        return "all bytes from originator"
    if resp_bytes >= orig_bytes:
        return "more bytes received than sent"
    return "more bytes sent than received"


# ── Main builder ──────────────────────────────────────────────────────────────

def build_alert_text(row: dict) -> str:
    parts: list[str] = []

    proto      = str(_get(row, "proto", "tcp")).upper()
    dest_port  = _int(row, "dest_port_zeek")
    conn_state = str(_get(row, "conn_state", "")).strip()
    history    = str(_get(row, "history", "") or "")
    duration   = _float(row, "duration")
    orig_bytes = _int(row, "orig_bytes")
    resp_bytes = _int(row, "resp_bytes")
    orig_pkts  = _int(row, "orig_pkts")
    resp_pkts  = _int(row, "resp_pkts")
    services   = _parse_services(_get(row, "service"))

    # 1. Connection header
    parts.append(f"{proto} connection to {_port_label(dest_port)}.")

    # 2. Connection state (factual outcome only)
    state_desc = CONN_STATE_INFO.get(conn_state)
    if state_desc:
        parts.append(f"Connection state {conn_state}: {state_desc}.")
    elif conn_state:
        parts.append(f"Connection state: {conn_state}.")

    # 3. Traffic volume
    if orig_pkts or resp_pkts:
        total_bytes = orig_bytes + resp_bytes
        parts.append(
            f"Traffic volume: {orig_pkts} packets sent / {resp_pkts} packets received, "
            f"{orig_bytes} bytes sent / {resp_bytes} bytes received "
            f"({total_bytes} bytes total)."
        )

        # 4. Byte ratio: report the number and the neutral direction only.
        if orig_bytes > 0 and resp_bytes > 0:
            ratio = resp_bytes / orig_bytes
            parts.append(
                f"Byte ratio (received/sent): {ratio:.2f}x — {_direction_label(orig_bytes, resp_bytes)}."
            )
        elif orig_bytes or resp_bytes:
            parts.append(f"Byte distribution: {_direction_label(orig_bytes, resp_bytes)}.")

    # 5. Duration
    if duration > 0:
        if duration < 1:
            dur_str = f"{duration * 1000:.1f} ms"
        elif duration < 60:
            dur_str = f"{duration:.2f} s"
        else:
            dur_str = f"{duration / 60:.1f} min"
        parts.append(f"Duration: {dur_str}.")

    # 6. TCP history sequence
    if history:
        parts.append(f"TCP sequence: {_interpret_history(history)}.")

    # 7. Detected services (protocol names only)
    if services:
        descs = [SERVICE_DESC.get(s, s) for s in services]
        parts.append(f"Services detected: {', '.join(descs)}.")

    return " ".join(parts)


def build_metadata(row: dict) -> dict:
    return {
        "src_ip":          _get(row, "src_ip_zeek", ""),
        "dest_ip":         _get(row, "dest_ip_zeek", ""),
        "dest_port":       _int(row, "dest_port_zeek"),
        "proto":           _get(row, "proto", ""),
        "service":         _get(row, "service", ""),
        "conn_state":      _get(row, "conn_state", ""),
        "duration_s":      round(_float(row, "duration"), 6),
        "orig_bytes":      _int(row, "orig_bytes"),
        "resp_bytes":      _int(row, "resp_bytes"),
        "orig_pkts":       _int(row, "orig_pkts"),
        "resp_pkts":       _int(row, "resp_pkts"),
        "history":         _get(row, "history", ""),
        "label_tactic":    _get(row, "label_tactic", ""),
        "label_technique": _get(row, "label_technique", ""),
        "label_binary":    _get(row, "label_binary", ""),
        "label_cve":       _get(row, "label_cve", ""),
        "datetime":        _get(row, "datetime", ""),
    }


def process_row(row: dict) -> dict:
    return {
        "text":     build_alert_text(row),
        "metadata": build_metadata(row),
    }


# ── Quick self-check ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    sample = {
        "proto": "tcp",
        "dest_port_zeek": 4848,
        "conn_state": "SF",
        "history": "ShADTadtttFAfF",
        "duration": 0.0315,
        "orig_bytes": 686,
        "resp_bytes": 11329,
        "orig_pkts": 44,
        "resp_pkts": 48,
        "service": "ssl",
        "src_ip_zeek": "10.0.0.5",
        "dest_ip_zeek": "10.0.0.20",
        "label_tactic": "Credential Access",
        "label_technique": "T1110",
    }
    out = process_row(sample)
    print("ALERT TEXT:\n", out["text"], "\n")
    print("METADATA:\n", out["metadata"])