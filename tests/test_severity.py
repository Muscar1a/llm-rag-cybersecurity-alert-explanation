"""Pins the alert_text ↔ regex contract that src/rag/severity.py relies on."""

from src.rag.severity import compute_severity

_FULL_ALERT = (
    "Suricata alert: ET WEB_SERVER Application Server Admin Interface Access "
    "(severity 1, Attempted Administrator Privilege Gain). "
    "TCP connection to port 4848. "
    "Connection state SF: handshake completed, connection closed normally. "
    "Traffic volume: 44 packets sent / 48 packets received, "
    "686 bytes sent / 11329 bytes received."
)


def test_high_risk_tactic_raises_one_level():
    # base High (severity 2) + HIGH_RISK tactic -> Critical
    alert = "Suricata alert: x (severity 2, Some Category)."
    assert compute_severity(alert, "Exfiltration") == "Critical"


def test_unconfirmed_tactic_lowers_one_level():
    alert = "Suricata alert: x (severity 2, Some Category)."
    assert compute_severity(alert, "none") == "Medium"
    assert compute_severity(alert, "") == "Medium"


def test_behavioral_pattern_escalates_high_to_critical():
    # base Critical (severity 1), MED_RISK tactic keeps Critical (already clamped)
    # use severity 2 base High + MED_RISK keep High, then behavioral bumps to Critical
    alert = (
        "Suricata alert: x (severity 2, Some Category). "
        "Traffic volume: 5 packets sent / 5 packets received, "
        "10 bytes sent / 100 bytes received."
    )
    assert compute_severity(alert, "Credential Access") == "Critical"


def test_benign_override_forces_low():
    alert = "Suricata alert: x (severity 2, Not Suspicious Traffic)."
    assert compute_severity(alert, "none") == "Low"


def test_full_realtime_style_alert_matches_header_regex():
    assert compute_severity(_FULL_ALERT, "Credential Access") == "Critical"


def test_missing_suricata_header_returns_none():
    assert compute_severity("TCP connection to port 443. Connection state REJ.", "none") is None


def test_category_omitted_header_is_not_matched():
    # src/realtime/alert_builder.py drops ", <category>" entirely when the
    # Suricata event has no category, producing "(severity 2)." with no comma.
    # _SURICATA_RE requires the comma+category group, so this is a known
    # fallback path: compute_severity returns None and the caller keeps the
    # LLM's own severity instead of crashing.
    alert = "Suricata alert: x (severity 2)."
    assert compute_severity(alert, "Exfiltration") is None
