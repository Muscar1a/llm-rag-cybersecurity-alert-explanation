import argparse
import json
import os
import glob
import re
import sys
import pandas as pd
import yaml

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
os.chdir(PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parse_attck import load_attack_techniques

SIGMA_CATEGORIES = ["network"]

ET_RULE_FILES = [
    "emerging-scan.rules",
    "emerging-dos.rules",
    "emerging-sql.rules",
    "emerging-web_specific_apps.rules",
    "emerging-policy.rules",
]

ET_IMPORT_ALL = {"emerging-scan.rules", "emerging-dos.rules", "emerging-sql.rules"}

ET_KEEP_KEYWORDS = [
    "brute", "xss", "cross-site", "sql", "injection",
    "botnet", "c2", "beacon", "c&c", "command and control",
    "ssh", "ftp", "telnet", "rdp",
    "dos", "flood", "slowloris", "slow http",
    "scan", "sweep", "cleartext", "non-standard port",
    "infiltrat", "exfiltrat", "tunnel",
]


# ---------------------------------------------------------------------------
# Sigma
# ---------------------------------------------------------------------------

def _parse_sigma_rules(sigma_base_dir: str) -> list[dict]:
    rules = []
    for category in SIGMA_CATEGORIES:
        pattern = os.path.join(sigma_base_dir, category, "**", "*.yml")
        for filepath in glob.glob(pattern, recursive=True):
            try:
                with open(filepath, encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                if not rule or not isinstance(rule, dict) or not rule.get("title"):
                    continue
                rules.append({
                    "title":          rule.get("title", ""),
                    "description":    rule.get("description", ""),
                    "status":         rule.get("status", ""),
                    "level":          rule.get("level", ""),
                    "tags":           json.dumps(rule.get("tags", [])),
                    "logsource":      str(rule.get("logsource", {})),
                    "falsepositives": json.dumps(rule.get("falsepositives", [])),
                    "detection":      str(rule.get("detection", {})),
                    "source":         "sigma",
                })
            except Exception:
                continue
    return rules


# ---------------------------------------------------------------------------
# Emerging Threats
# ---------------------------------------------------------------------------

def _et_extract_quoted(field: str, text: str) -> str | None:
    m = re.search(rf'{field}:"([^"]*)"', text)
    return m.group(1).strip() if m else None


def _et_parse_rule(line: str) -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if not re.match(r'^(alert|drop|pass|reject|log)\s', line):
        return None

    header = re.match(
        r'^(\w+)\s+(\w+)\s+\S+\s+(\S+)\s+(?:->|<>)\s+\S+\s+(\S+)',
        line,
    )
    if not header:
        return None
    _, proto, src_port, dst_port = header.groups()

    opts_m = re.search(r'\((.+)\)\s*$', line, re.DOTALL)
    if not opts_m:
        return None
    opts = opts_m.group(1)

    msg       = _et_extract_quoted("msg", opts)
    classtype = _et_extract_quoted("classtype", opts)
    sid_m     = re.search(r'\bsid:(\d+)', opts)
    sid       = sid_m.group(1) if sid_m else ""
    contents  = re.findall(r'content:"([^"]*)"', opts)
    refs      = re.findall(r'reference:([^;]+)', opts)

    severity = ""
    meta_m = re.search(r'metadata:([^;]+)', opts)
    if meta_m:
        sev_m = re.search(r'signature_severity\s+(\S+)', meta_m.group(1))
        if sev_m:
            severity = sev_m.group(1).strip(" ,)")

    if not msg:
        return None

    return {
        "sid": sid, "msg": msg,
        "proto": proto.upper(), "src_port": src_port, "dst_port": dst_port,
        "classtype": classtype or "", "severity": severity,
        "contents": contents, "refs": refs,
    }


def _et_render_text(r: dict) -> str:
    lines = [f"Rule: {r['msg']}"]

    port_parts = []
    for label, val in [("src_port", r["src_port"]), ("dst_port", r["dst_port"])]:
        if val not in ("any", "$EXTERNAL_NET", "$HTTP_SERVERS", "$HTTP_PORTS", ""):
            port_parts.append(f"{label}:{val}")
    port_str = " | ".join(port_parts)
    lines.append(f"Protocol: {r['proto']}" + (f" | Ports: {port_str}" if port_str else ""))

    if r["contents"]:
        lines.append(f"Detection: {'; '.join(repr(c) for c in r['contents'][:3])}")
    if r["classtype"]:
        lines.append(f"Classtype: {r['classtype']}")
    if r["severity"]:
        lines.append(f"Severity: {r['severity']}")
    if r["refs"]:
        lines.append(f"Reference: {'; '.join(r['refs'][:2])}")

    return "\n".join(lines)


def _et_should_keep(msg: str, filename: str) -> bool:
    if filename in ET_IMPORT_ALL:
        return True
    return any(kw in msg.lower() for kw in ET_KEEP_KEYWORDS)


def _parse_et_rules(raw_dir: str) -> list[dict]:
    records = []
    for filename in ET_RULE_FILES:
        filepath = os.path.join(raw_dir, filename)
        if not os.path.isfile(filepath):
            print(f"  [SKIP] Not found: {filepath}")
            continue

        kept = 0
        filtered = 0
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = _et_parse_rule(line)
                if parsed is None:
                    continue
                if not _et_should_keep(parsed["msg"], filename):
                    filtered += 1
                    continue
                rule_text = _et_render_text(parsed)
                records.append({
                    "sid":         parsed["sid"],
                    "msg":         parsed["msg"],
                    "classtype":   parsed["classtype"],
                    "severity":    parsed["severity"],
                    "source_file": filename,
                    "rule_text":   rule_text,
                })
                kept += 1

        print(f"  [{filename}] kept={kept}, filtered={filtered}")

    return records


# ---------------------------------------------------------------------------
# Individual source runners
# ---------------------------------------------------------------------------

def run_mitre():
    print("=== MITRE ===")
    techniques = load_attack_techniques()
    df = pd.DataFrame(techniques)
    df["tactics"]   = df["tactics"].apply(json.dumps)
    df["platforms"] = df["platforms"].apply(json.dumps)
    df = df.rename(columns={"id": "mitre_id"})

    out_dir = os.path.join("data", "processed", "MITRE")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "mitre_cleaned.parquet")
    df.to_parquet(out, index=False)
    print(f"  Saved {len(df)} MITRE techniques → {out}")


def run_sigma():
    print("=== Sigma ===")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sigma_raw_dir = os.path.join(project_root, "data", "raw", "sigma")
    if not os.path.isdir(sigma_raw_dir):
        print(f"  No Sigma data at {sigma_raw_dir} — skipping.")
        return

    rules = _parse_sigma_rules(sigma_raw_dir)
    if not rules:
        print("  No valid Sigma rules found — skipping.")
        return

    df = pd.DataFrame(rules)
    out_dir = os.path.join("data", "processed", "sigma")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "sigma_cleaned.parquet")
    df.to_parquet(out, index=False)
    print(f"  Saved {len(df)} Sigma rules → {out}")


def run_et_rules():
    print("=== Emerging Threats ===")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    raw_dir = os.path.join(project_root, "data", "raw", "emerging_threats")
    if not os.path.isdir(raw_dir):
        print(f"  No ET rules data at {raw_dir} — skipping.")
        return

    records = _parse_et_rules(raw_dir)
    if not records:
        print("  No valid ET rules found — skipping.")
        return

    df = pd.DataFrame(records)
    out_dir = os.path.join("data", "processed", "emerging_threats")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "et_rules_cleaned.parquet")
    df.to_parquet(out, index=False)
    print(f"  Saved {len(df)} ET rules → {out}")

    print("\n--- Sample rule_text ---")
    print(df.iloc[0]["rule_text"])

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

SOURCE_MAP = {
    "mitre":    run_mitre,
    "sigma":    run_sigma,
    "et_rules": run_et_rules,
}


def run_pipeline(sources: list[str]):
    for src in sources:
        SOURCE_MAP[src]()
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clean raw data sources into parquet files.")
    parser.add_argument(
        "--source", nargs="+",
        choices=list(SOURCE_MAP),
        default=["mitre", "sigma", "et_rules"],
        help="Sources to process (default: mitre sigma et_rules). Use 'cve' to also re-download CVEs.",
    )
    args = parser.parse_args()
    run_pipeline(args.source)
