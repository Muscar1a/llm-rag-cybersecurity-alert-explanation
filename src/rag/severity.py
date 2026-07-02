"""Deterministic severity computation.

Mirrors the severity ladder in lc_prompt.py (and the ground-truth logic in
scripts/verify_gt.py): base level from the Suricata severity number, adjusted
by the confirmed tactic tier, escalated on anomalous traffic behavior, with a
benign override. The LLM only supplies the tactic; the arithmetic runs here.
"""

import re

HIGH_RISK = {"exfiltration", "command and control", "impact", "lateral movement"}
MED_RISK = {"credential access", "discovery", "initial access", "execution", "persistence",
            "privilege escalation", "defense evasion", "reconnaissance", "resource development", "collection"}
LADDER = ["low", "medium", "high", "critical"]
BASE_SEVERITY = {1: "critical", 2: "high", 3: "medium"}

# "Suricata alert: <signature> (severity N, <category>)."
_SURICATA_RE = re.compile(r"\(severity (\d+), ([^)]+)\)")
_BYTES_RE = re.compile(r"(\d+) bytes sent / (\d+) bytes received")
_STATE_RE = re.compile(r"Connection state (\w+)")
_SEQ_RE = re.compile(r"TCP sequence: ([^.]+)\.")


def _has_behavioral_pattern(alert_text: str) -> bool:
    """True if the alert shows one of the behavioral traffic patterns that
    trigger escalation: dominant byte ratio (>=5x either direction), reset
    after data exchange, or retransmission-heavy history."""
    m = _BYTES_RE.search(alert_text)
    o, r = (int(m.group(1)), int(m.group(2))) if m else (0, 0)

    if o > 0 and r > 0 and (r / o >= 5 or o / r >= 5):
        return True

    state_m = _STATE_RE.search(alert_text)
    state = state_m.group(1) if state_m else ""
    if (o > 0 or r > 0) and state in ("RSTO", "RSTR"):
        return True

    seq_m = _SEQ_RE.search(alert_text)
    if seq_m:
        # zeek_alert_builder renders each history char as one item joined
        # by " → "; retransmissions render as retrans(client)/retrans(server)
        items = [s.strip() for s in seq_m.group(1).split("→")]
        retrans = sum(1 for s in items if s.startswith("retrans"))
        if items and retrans >= len(items) / 3:
            return True

    return False


def compute_severity(alert_text: str, tactic: str | None) -> str | None:
    """Compute severity from the alert text and the confirmed tactic.

    Returns "Low" | "Medium" | "High" | "Critical", or None when the alert
    has no Suricata severity header to anchor on (caller keeps its fallback).
    """
    suricata_m = _SURICATA_RE.search(alert_text)
    if not suricata_m:
        return None
    base = BASE_SEVERITY.get(int(suricata_m.group(1)))
    if base is None:
        return None
    category = suricata_m.group(2)

    tactic_norm = (tactic or "").replace("_", " ").strip().lower()
    confirmed = tactic_norm in HIGH_RISK or tactic_norm in MED_RISK

    idx = LADDER.index(base)
    if tactic_norm in HIGH_RISK:
        idx = min(idx + 1, 3)
    elif not confirmed:
        idx = max(idx - 1, 0)

    if LADDER[idx] in ("high", "critical") and _has_behavioral_pattern(alert_text):
        idx = min(idx + 1, 3)

    if not confirmed and category == "Not Suspicious Traffic":
        idx = 0

    return LADDER[idx].capitalize()
