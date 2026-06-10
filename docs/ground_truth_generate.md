You are a senior SOC analyst.
Your task is to generate a ground_truth.json containing reference explanations for 131 network security alerts. Each reference must be grounded STRICTLY in the provided knowledge base files. This is a RAG evaluation dataset; correctness and grounding matter more than fluency.

## INPUT FILES
- alerts.json — 131 alerts. Each has: alert_text, label_tactic, label_technique, and metadata (dest_port, conn_state, orig_bytes, resp_bytes, orig_pkts, resp_pkts, duration_s, history, ...).
- port_profiles.jsonl — entries with a "document" field and metadata.port (int).
- conn_state_profiles.jsonl — entries with a "document" field and metadata.state_code (string).
- tactic_profiles.jsonl — entries with a "document" field and an "id" field.
- traffic_pattern_profiles.jsonl — entries with a "document" field, an "id", and metadata.scope ("single_flow" or "multi_flow").

## STEP 1 — DETERMINISTIC KB LOOKUPS (per alert)
1a. PORT_KB = the "document" of the port_profiles.jsonl entry where metadata.port == alert.metadata.dest_port. If none, PORT_KB = null.
1b. CONN_KB = the "document" of the conn_state_profiles.jsonl entry where metadata.state_code == alert.metadata.conn_state. If none, CONN_KB = null.
1c. TACTIC_KB = the "document" of the tactic_profiles.jsonl entry whose id == "tactic_" + lowercase(label_tactic with spaces and underscores normalized to underscore).
    Examples: "Credential_Access" → "tactic_credential_access"; "Initial_Access" → "tactic_initial_access"; "Defense_Evasion" → "tactic_defense_evasion"; "Reconnaissance" → "tactic_reconnaissance"; "Exfiltration" → "tactic_exfiltration".
    If none, TACTIC_KB = null.

## STEP 2 — TRAFFIC PATTERN SELECTION (per alert, rule-based, NOT free choice)
Compute from alert.metadata only. Let o=orig_bytes, r=resp_bytes, cs=conn_state, h=history string, d=duration_s.
ONLY single_flow patterns are eligible. Multi-flow patterns (horizontal_scan, vertical_scan, brute_force, beaconing_c2, fan_out, fan_in) are FORBIDDEN — a single alert cannot establish them.
Evaluate each rule; a pattern qualifies if its condition is true:
- traffic_pattern_zero_payload_established:  cs == "SF" AND o == 0 AND r == 0
- traffic_pattern_server_dominant_bulk:      o > 0 AND r > 0 AND (r / o) >= 5
- traffic_pattern_client_dominant_bulk:      o > 0 AND r > 0 AND (o / r) >= 5
- traffic_pattern_reset_after_data:          (o > 0 OR r > 0) AND cs in ("RSTO", "RSTR")
- traffic_pattern_retransmission_heavy:      count of 'T' and 't' chars in h  >=  (length of h) / 3
- traffic_pattern_long_duration_low_volume:  d >= 60 AND (o + r) <= 1000
Collect all qualifying patterns. If more than 2 qualify, keep at most 2 using this priority order:
  server_dominant_bulk / client_dominant_bulk  >  reset_after_data  >  retransmission_heavy  >  zero_payload_established  >  long_duration_low_volume
If zero qualify, there is no traffic-pattern sentence.
For each kept pattern, PATTERN_KB[i] = the "document" of that entry in traffic_pattern_profiles.jsonl.

## STEP 3 — WRITE THE REFERENCE
Write one sentence per KB source that is non-null, in this exact order:
1. [from PORT_KB] What service runs on this port and its security role. If PORT_KB is null: "Port {dest_port} is not covered by the knowledge base, so service context is unavailable."
2. [from CONN_KB] What this connection state indicates behaviorally. If CONN_KB is null: "Connection state {conn_state} is not covered by the knowledge base."
3. [from each PATTERN_KB, one sentence each] What the observed numbers (byte ratio, retransmissions, payload, or duration — cite the actual figures from alert_text) indicate, per the pattern document. Skip if no pattern qualified.
4. [from TACTIC_KB + alert facts] How these observations are consistent with {label_tactic}, using only the tactic document. If TACTIC_KB is null: omit.
5. [from PORT_KB or TACTIC_KB] One concrete mitigation explicitly stated or directly implied by those documents.

## HARD CONSTRAINTS
- Use ONLY: alert_text, PORT_KB, CONN_KB, TACTIC_KB, and the kept PATTERN_KB documents. Nothing else.
- FORBIDDEN: CVE identifiers not present in PORT_KB; technique names not in TACTIC_KB; tool names; attacker infrastructure; any multi-flow pattern; any claim that requires observing flows other than this one.
- Do NOT assert the attack succeeded unless the alert facts and KB support it; hedge as the KB documents hedge ("may indicate", "consistent with").
- Keep numbers consistent with alert_text. Do not invent figures.

## OUTPUT
A single valid JSON array, saved as ground_truth.json. No prose before or after. No markdown.
[
  {
    "user_input": "<exact alert_text from alerts.json, unchanged>",
    "reference": "<the sentences from STEP 3, plain text, joined with spaces>",
    "label_tactic": "<exact label_tactic string from alerts.json>"
  }
]
Process all 131 alerts, in file order. Do not skip any. Do not summarize — emit the full array.