"""
Parse Emerging Threats Suricata/Snort rules into human-readable text chunks
for embedding in the RAG knowledge base.

Input:  data/raw/emerging_threats/*.rules
Output: data/processed/emerging_threats/et_rules_cleaned.parquet

Each row = one rule, with a pre-rendered `rule_text` field ready for embedding.
"""

import os
import re
import pandas as pd
from pathlib import Path

# ---------------------------------------------------------------------------
# Rule files to process
# ---------------------------------------------------------------------------
RULE_FILES = [
    "emerging-dos.rules",
    "emerging-sql.rules",
    "emerging-scan.rules",
    "emerging-web_specific_apps.rules",
    "emerging-policy.rules",
]

# Keywords to keep rules from large files (web_specific_apps, policy).
# Applied as case-insensitive substring match on the `msg` field.
KEEP_KEYWORDS = [
    "brute", "xss", "cross-site", "sql", "injection",
    "botnet", "c2", "beacon", "c&c", "command and control",
    "ssh", "ftp", "telnet", "rdp",
    "dos", "flood", "slowloris", "slow http",
    "scan", "sweep", "cleartext", "non-standard port",
    "infiltrat", "exfiltrat", "tunnel",
]

# Files that should be fully imported (no keyword filtering)
IMPORT_ALL_FILES = {
    "emerging-dos.rules",
    "emerging-sql.rules",
    "emerging-scan.rules",
}

# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _extract_quoted(field: str, text: str) -> str | None:
    """Extract value of a named field like: field:"value" """
    m = re.search(rf'{field}:"([^"]*)"', text)
    return m.group(1).strip() if m else None


def _extract_metadata_field(key: str, metadata_str: str) -> str | None:
    """Extract a key from metadata:key value, key value, ... """
    m = re.search(rf'\b{key}\s+([^,\)]+)', metadata_str)
    return m.group(1).strip() if m else None


def _parse_rule(line: str) -> dict | None:
    """Parse a single Suricata/Snort rule line into a structured dict."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Must start with an action keyword
    if not re.match(r'^(alert|drop|pass|reject|log)\s', line):
        return None

    # Extract header: action proto src_ip src_port direction dst_ip dst_port
    header_m = re.match(
        r'^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)',
        line
    )
    if not header_m:
        return None

    action, proto, src_ip, src_port, direction, dst_ip, dst_port = header_m.groups()

    # Extract options block (everything inside the outermost parentheses)
    opts_m = re.search(r'\((.+)\)\s*$', line, re.DOTALL)
    if not opts_m:
        return None
    opts = opts_m.group(1)

    msg       = _extract_quoted("msg", opts)
    classtype = _extract_quoted("classtype", opts)
    sid_m     = re.search(r'\bsid:(\d+)', opts)
    sid       = sid_m.group(1) if sid_m else None

    # Content patterns (payload signatures)
    contents  = re.findall(r'content:"([^"]*)"', opts)

    # References
    refs      = re.findall(r'reference:([^;]+)', opts)

    # Severity from metadata
    meta_m    = re.search(r'metadata:([^;]+)', opts)
    severity  = None
    if meta_m:
        severity = _extract_metadata_field("signature_severity", meta_m.group(1))

    if not msg:
        return None

    return {
        "sid":       sid or "",
        "msg":       msg,
        "proto":     proto,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "classtype": classtype or "",
        "severity":  severity or "",
        "contents":  contents,
        "refs":      refs,
    }


def _render_rule_text(r: dict) -> str:
    """Render a parsed rule dict into human-readable text for embedding."""
    lines = [f"Rule: {r['msg']}"]

    proto_str = r["proto"].upper()
    port_info = []
    if r["src_port"] not in ("any", "$EXTERNAL_NET", ""):
        port_info.append(f"src_port:{r['src_port']}")
    if r["dst_port"] not in ("any", "$HTTP_SERVERS", "$HTTP_PORTS", ""):
        port_info.append(f"dst_port:{r['dst_port']}")
    port_str = " ".join(port_info)
    lines.append(f"Protocol: {proto_str}" + (f" | Ports: {port_str}" if port_str else ""))

    if r["contents"]:
        # Show up to 3 content patterns (avoid overly long text)
        content_str = "; ".join(repr(c) for c in r["contents"][:3])
        lines.append(f"Detection: {content_str}")

    if r["classtype"]:
        lines.append(f"Classtype: {r['classtype']}")

    if r["severity"]:
        lines.append(f"Severity: {r['severity']}")

    if r["refs"]:
        lines.append(f"Reference: {'; '.join(r['refs'][:2])}")

    return "\n".join(lines)


def _should_keep(msg: str, filename: str) -> bool:
    if filename in IMPORT_ALL_FILES:
        return True
    msg_lower = msg.lower()
    return any(kw in msg_lower for kw in KEEP_KEYWORDS)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_all(raw_dir: Path, out_path: Path) -> None:
    records = []

    for filename in RULE_FILES:
        filepath = raw_dir / filename
        if not filepath.is_file():
            print(f"[SKIP] Not found: {filepath}")
            continue

        kept = 0
        skipped = 0
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = _parse_rule(line)
                if parsed is None:
                    continue
                if not _should_keep(parsed["msg"], filename):
                    skipped += 1
                    continue

                rule_text = _render_rule_text(parsed)
                records.append({
                    "sid":       parsed["sid"],
                    "msg":       parsed["msg"],
                    "classtype": parsed["classtype"],
                    "severity":  parsed["severity"],
                    "source_file": filename,
                    "rule_text": rule_text,
                })
                kept += 1

        print(f"[{filename}] kept={kept}, filtered={skipped}")

    df = pd.DataFrame(records)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)
    print(f"\n[+] Saved {len(df)} rules → {out_path}")

    # Quick preview
    if len(df) > 0:
        print("\n--- Sample rule_text ---")
        print(df.iloc[0]["rule_text"])


if __name__ == "__main__":
    raw_dir  = Path("data/raw/emerging_threats")
    out_path = Path("data/processed/emerging_threats/et_rules_cleaned.parquet")
    parse_all(raw_dir, out_path)
