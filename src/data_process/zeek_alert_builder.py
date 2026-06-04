"""
Zeek conn.log row → natural language alert text for RAG ingestion / evaluation.

Input columns (UWF-ZeekData24 schema):
    community_id, conn_state, duration, history,
    src_ip_zeek, src_port_zeek, dest_ip_zeek, dest_port_zeek,
    local_orig, local_resp, missed_bytes,
    orig_bytes, orig_ip_bytes, orig_pkts,
    proto, resp_bytes, resp_ip_bytes, resp_pkts,
    service, ts, uid, datetime,
    label_tactic, label_technique, label_binary, label_cve
"""

# ── Lookup tables ─────────────────────────────────────────────────────────────

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
    4848: "GlassFish Admin",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

SERVICE_DESC: dict[str, str] = {
    "ssl":     "TLS/SSL encrypted channel",
    "http":    "HTTP web traffic",
    "smb":     "SMB file sharing (Windows)",
    "gssapi":  "Kerberos/GSSAPI Windows authentication",
    "ntlm":    "NTLM Windows authentication",
    "dce_rpc": "Windows DCE/RPC remote procedure call",
    "ssh":     "SSH secure shell",
    "dns":     "DNS name resolution",
    "ftp":     "FTP file transfer",
    "rdp":     "RDP remote desktop",
    "kerberos":"Kerberos authentication",
}

# (short description, behavioral interpretation)
CONN_STATE_INFO: dict[str, tuple[str, str]] = {
    "SF":     ("Connection completed normally",
               "full handshake and graceful termination — normal bidirectional flow"),
    "S0":     ("Connection attempt, no reply",
               "SYN sent but no SYN-ACK received — host discovery or port scanning, or filtered by firewall"),
    "S1":     ("Connection established, not terminated",
               "connection left open without FIN or RST"),
    "S2":     ("Originator sent FIN, awaiting reply",
               "half-closed connection"),
    "S3":     ("Responder sent FIN, awaiting reply",
               "half-closed connection"),
    "REJ":    ("Connection rejected",
               "RST received in response to SYN — port closed or firewall ACL drop"),
    "RSTO":   ("Connection reset by originator",
               "client sent RST after partial connection — abrupt teardown, possible scan or evasion"),
    "RSTR":   ("Connection reset by responder",
               "server sent RST — server-side abnormal termination or active blocking"),
    "RSTOS0": ("Originator sent SYN then RST before SYN-ACK",
               "aborted connection attempt before handshake completed"),
    "RSTRH":  ("Responder sent SYN-ACK then RST",
               "server acknowledged then immediately rejected"),
    "SH":     ("Originator sent SYN then FIN without completing handshake",
               "half-open connection — stealth FIN scan technique"),
    "SHR":    ("SYN then FIN rejected by RST from responder",
               "rejected half-open/stealth scan"),
    "OTH":    ("Mid-stream traffic observed, no SYN seen",
               "ACK probe or partial capture — possible firewall mapping or evasion of SYN-based detection"),
}

# Uppercase = originator (client), lowercase = responder (server)
HISTORY_CHAR: dict[str, str] = {
    "S": "SYN(client)",   "h": "SYN-ACK(server)",
    "A": "ACK(client)",   "a": "ACK(server)",
    "D": "data(client)",  "d": "data(server)",
    "F": "FIN(client)",   "f": "FIN(server)",
    "R": "RST(client)",   "r": "RST(server)",
    "T": "retrans(client)","t": "retrans(server)",
    "G": "content-gap",   "W": "zero-window",
    "C": "capture-gap",   "I": "inconsistent-pkt",
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
    tokens = []
    for ch in history:
        tokens.append(HISTORY_CHAR.get(ch, f"flag({ch})"))
    return " → ".join(tokens)


def _port_label(port: int) -> str:
    name = KNOWN_PORTS.get(port)
    return f"port {port} ({name})" if name else f"port {port}"


# ── Main builder ──────────────────────────────────────────────────────────────

def build_alert_text(row: dict) -> str:
    parts: list[str] = []

    proto       = str(_get(row, "proto", "tcp")).upper()
    dest_port   = _int(row, "dest_port_zeek")
    src_ip      = _get(row, "src_ip_zeek", "")
    dest_ip     = _get(row, "dest_ip_zeek", "")
    conn_state  = str(_get(row, "conn_state", "")).strip()
    history     = str(_get(row, "history", "") or "")
    duration    = _float(row, "duration")
    orig_bytes  = _int(row, "orig_bytes")
    resp_bytes  = _int(row, "resp_bytes")
    orig_pkts   = _int(row, "orig_pkts")
    resp_pkts   = _int(row, "resp_pkts")
    services    = _parse_services(_get(row, "service"))

    # 1. Connection header
    port_str = _port_label(dest_port)
    parts.append(f"{proto} connection to {port_str}.")

    # 2. Connection state
    state_info = CONN_STATE_INFO.get(conn_state)
    if state_info:
        short, behavior = state_info
        parts.append(f"Connection state: {short} ({conn_state}). Behavioral meaning: {behavior}.")
    elif conn_state:
        parts.append(f"Connection state: {conn_state}.")

    # 3. Traffic volume
    if orig_pkts or resp_pkts:
        total_bytes = orig_bytes + resp_bytes
        vol = (
            f"{orig_pkts} packets sent / {resp_pkts} packets received, "
            f"{orig_bytes} bytes sent / {resp_bytes} bytes received "
            f"({total_bytes} bytes total)."
        )
        parts.append(f"Traffic volume: {vol}")

        # Byte ratio hint
        if orig_bytes > 0 and resp_bytes > 0:
            ratio = resp_bytes / orig_bytes
            if ratio > 5:
                direction = "heavily server-dominant (large download or inbound data)"
            elif ratio > 2:
                direction = "server-dominant"
            elif ratio > 0.5:
                direction = "balanced"
            else:
                direction = "client-dominant (client sent significantly more — upload, exfiltration, or C2 beacon)"
            parts.append(f"Byte ratio (received/sent): {ratio:.2f}x — {direction}.")

    # 4. Duration
    if duration > 0:
        if duration < 1:
            dur_str = f"{duration * 1000:.1f} ms"
        elif duration < 60:
            dur_str = f"{duration:.2f} s"
        else:
            dur_str = f"{duration / 60:.1f} min"
        parts.append(f"Duration: {dur_str}.")

    # 5. TCP history sequence
    if history:
        interpreted = _interpret_history(history)
        parts.append(f"TCP sequence: {interpreted}.")

    # 6. Detected services
    if services:
        descs = [SERVICE_DESC.get(s, s) for s in services]
        parts.append(f"Services detected: {', '.join(descs)}.")

    # 7. Behavioral hints
    hints: list[str] = []

    # S0 = unanswered SYN → scanning
    if conn_state == "S0":
        hints.append(
            "Unanswered SYN — consistent with port scanning, host discovery, or firewall probing."
        )

    # OTH + ACK-only history → ACK scan
    if conn_state == "OTH" and set(history) <= {"A", "a"}:
        hints.append(
            "ACK-only probe with no SYN — consistent with TCP ACK scan used for firewall rule mapping "
            "or host liveness detection."
        )

    # RSTO/RSTR with data → data then reset (exfiltration / C2 pattern)
    if conn_state in ("RSTO", "RSTR") and orig_bytes > 0:
        hints.append(
            f"Data exchanged ({orig_bytes} B sent, {resp_bytes} B received) then connection reset — "
            "consistent with command-and-control check-in, data staging, or exfiltration followed by cleanup."
        )

    # SMB + Windows auth services
    windows_auth = {"gssapi", "ntlm", "kerberos"}
    detected_set = set(services)
    if "smb" in detected_set or detected_set & windows_auth:
        auth_list = ", ".join(SERVICE_DESC[s] for s in (detected_set & (windows_auth | {"smb", "dce_rpc"})) if s in SERVICE_DESC)
        hints.append(
            f"Windows authentication and file-sharing protocols detected ({auth_list}) — "
            "typical of lateral movement, credential-based access, or SMB-based persistence/exfiltration."
        )

    # GlassFish admin panel (port 4848)
    if dest_port == 4848:
        hints.append(
            "Destination port 4848 is the GlassFish Java EE application server admin panel — "
            "a high-value target for credential brute-forcing or unauthorized admin access."
        )

    # Zero payload on established connection
    if conn_state == "SF" and orig_bytes == 0 and resp_bytes == 0:
        hints.append(
            "Fully established connection with zero application payload — "
            "consistent with TLS handshake probing, credential testing, or keepalive-only connection."
        )

    # Large client-side upload or exfiltration
    if orig_bytes > 10000 and (resp_bytes == 0 or orig_bytes / max(resp_bytes, 1) > 5):
        hints.append(
            f"Large outbound data ({orig_bytes} bytes) with minimal server response — "
            "possible data exfiltration or large POST/upload."
        )

    if hints:
        parts.append("Behavioral hints: " + " ".join(hints))

    return " ".join(parts)


def build_metadata(row: dict) -> dict:
    return {
        "src_ip":        _get(row, "src_ip_zeek", ""),
        "dest_ip":       _get(row, "dest_ip_zeek", ""),
        "dest_port":     _int(row, "dest_port_zeek"),
        "proto":         _get(row, "proto", ""),
        "service":       _get(row, "service", ""),
        "conn_state":    _get(row, "conn_state", ""),
        "duration_s":    round(_float(row, "duration"), 6),
        "orig_bytes":    _int(row, "orig_bytes"),
        "resp_bytes":    _int(row, "resp_bytes"),
        "orig_pkts":     _int(row, "orig_pkts"),
        "resp_pkts":     _int(row, "resp_pkts"),
        "history":       _get(row, "history", ""),
        "label_tactic":  _get(row, "label_tactic", ""),
        "label_technique": _get(row, "label_technique", ""),
        "datetime":      _get(row, "datetime", ""),
    }


def process_row(row: dict) -> dict:
    return {
        "text":     build_alert_text(row),
        "metadata": build_metadata(row),
    }
