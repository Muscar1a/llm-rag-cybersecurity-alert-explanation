You are a senior SOC analyst producing a ground truth benchmark dataset for RAG retrieval evaluation (RAGAS) and automation remediation demos.
For each alert in `alerts.json`, perform KB lookups, record evidence, compute severity, derive a recommended action, and write a KB-grounded reference explanation.

## INPUT FILES

- **alerts.json** — Each entry has `id`, `alert_text` (combined Suricata header + Zeek telemetry), `network`, and `_ground_truth` (label_tactic, label_technique).
- **port_profiles.jsonl** — entries with "id", "document" and metadata.port (int).
- **conn_state_profiles.jsonl** — entries with "id", "document" and metadata.state_code (string).
- **tactic_profiles.jsonl** — entries with "id", "document" and metadata.tactic (string).
- **traffic_pattern_profiles.jsonl** — entries with "id", "document", and metadata.scope ("single_flow" or "multi_flow").
- **suricata_category_profiles.jsonl** — entries with "id", "document" and metadata.category (string), metadata.classtype (string).

---

## PART 1 — KB LOOKUPS (per row, deterministic)

### 1a. PORT_KB
Find the entry in port_profiles.jsonl where `metadata.port == network.dest_port`. Extract its "id" and "document". If no match: PORT_KB = null.

### 1b. CONN_KB
Find the entry in conn_state_profiles.jsonl where `metadata.state_code == network.conn_state`. Extract its "id" and "document". If no match: CONN_KB = null.

### 1c. TACTIC_KB
Normalize `_ground_truth.label_tactic`: replace underscores with spaces, lowercase → match against `metadata.tactic` in tactic_profiles.jsonl (case-insensitive comparison).
Examples: "Credential_Access" → match tactic containing "credential access"; "Defense_Evasion" → "defense evasion"; "Benign" → no match (TACTIC_KB = null).
If no match: TACTIC_KB = null.

### 1d. TRAFFIC PATTERN selection (rule-based, per alert)
Let o = network.orig_bytes, r = network.resp_bytes, cs = network.conn_state, h = network.history, d = network.duration_s.
ONLY single_flow scope patterns are eligible. Multi_flow patterns are FORBIDDEN.

Evaluate each condition:
- **zero_payload_established**: cs == "SF" AND o == 0 AND r == 0
- **server_dominant_bulk**: o > 0 AND r > 0 AND (r / o) >= 5
- **client_dominant_bulk**: o > 0 AND r > 0 AND (o / r) >= 5
- **reset_after_data**: (o > 0 OR r > 0) AND cs in ("RSTO", "RSTR")
- **retransmission_heavy**: count of 'T' and 't' in h >= len(h) / 3
- **long_duration_low_volume**: d >= 60 AND (o + r) <= 1000

Collect qualifying patterns. Keep at most 2, using priority order:
server_dominant_bulk / client_dominant_bulk > reset_after_data > retransmission_heavy > zero_payload_established > long_duration_low_volume

For each kept pattern, look up its "id" and "document" in traffic_pattern_profiles.jsonl by matching the pattern name against the entry's "id" field.

### 1e. CATEGORY_KB
Extract the Suricata alert category from `alert_text` using the pattern: `"Suricata alert: ... (severity N, {category})."`.
Find the entry in suricata_category_profiles.jsonl where `metadata.category == {category}` (exact string match). Extract its "id" and "document".
If no category found in alert_text or no match in KB: CATEGORY_KB = null.

---

## PART 2 — SEVERITY (hybrid, deterministic, drives remediation)

Severity is the ground truth for both RAGAS metadata and the automation remediation demo. Compute in **five ordered steps**. Do not skip steps.

### Step 1 — Base from Suricata signature
Extract numeric severity N from `alert_text` pattern `"(severity N, ...)"`. Map:
- 1 → **critical**
- 2 → **high**
- 3 → **medium**

### Step 2 — Tactic risk tier
Normalize `_ground_truth.label_tactic` as in 1c. Classify:

- **HIGH_RISK_TACTICS** = {"exfiltration", "command and control", "impact", "lateral movement"}
- **MED_RISK_TACTICS** = {"credential access", "discovery", "initial access", "execution", "persistence", "privilege escalation", "defense evasion", "reconnaissance", "resource development", "collection"}
- **NO_TACTIC** = label_tactic is "Benign" or null or does not match any of the above

### Step 3 — Tactic-driven adjustment
Apply to the base severity from Step 1:
- If tactic ∈ HIGH_RISK_TACTICS: **bump UP one level** (medium→high, high→critical, critical stays critical)
- If tactic ∈ MED_RISK_TACTICS: **keep base**
- If tactic ∈ NO_TACTIC: **bump DOWN one level** (critical→high, high→medium, medium→low)

Severity ladder: low < medium < high < critical (bumps clamp at the ends).

### Step 4 — Behavioral confirmation bump
If current severity is **high** or **critical** AND any of the following traffic patterns qualified in 1d:
`reset_after_data`, `server_dominant_bulk`, `client_dominant_bulk`, `retransmission_heavy`
→ **bump UP one more level** (high→critical; critical stays critical).

Rationale: behavioral evidence corroborates IDS + tactic, justifying aggressive automation.

### Step 5 — Benign override (final)
If `_ground_truth.label_tactic == "Benign"`: **set severity = low**, overriding all previous steps.

### Severity reasoning (record this)
Produce a one-sentence `severity_reasoning` that explains the final level in terms of the steps above. Do NOT name the tactic label directly; describe it in evidence terms.
- Good: "Suricata base 'high' raised to 'critical' because tactic falls in the high-risk tier and a server-dominant bulk transfer pattern corroborates the IDS finding."
- Bad: "Severity is critical because the label_tactic is Exfiltration."

---

## PART 3 — RECOMMENDED ACTION (drives automation demo)

Map final severity to a deterministic action profile. This is the ground truth for the remediation playbook selector.

| Severity | action_id | description |
|----------|-----------|-------------|
| critical | `auto_isolate_host` | Isolate source host from network, page on-call SOC, open P1 incident |
| high | `auto_block_and_ticket` | Block source IP at perimeter, open P2 ticket, enrich with threat intel |
| medium | `enrich_and_queue` | Enrich alert with context, queue for analyst review (no auto-block) |
| low | `log_and_suppress` | Log to SIEM, suppress from analyst queue unless pattern repeats |

Record both `action_id` and `description` verbatim from the table.

---

## PART 4 — EVIDENCE (per row)

Record the `id` field of each KB entry used in Part 1. This enables retrieval precision/recall evaluation for RAGAS `context_precision` and `context_recall`.

```json
"evidence": {
  "port_kb": "<id from port_profiles.jsonl>" or null,
  "conn_state_kb": "<id from conn_state_profiles.jsonl>" or null,
  "category_kb": "<id from suricata_category_profiles.jsonl>" or null,
  "tactic_kb": "<id from tactic_profiles.jsonl>" or null,
  "traffic_pattern_kb": ["<id1>", "<id2>"] or []
}
```

---

## PART 5 — WRITE THE REFERENCE (per row)

Write one sentence per non-null KB source. The reference must read as **forward reasoning from evidence to conclusion** — as if the analyst discovered the security context by reading the KB documents, NOT by knowing the label in advance. This text is the ground truth for RAGAS `faithfulness` and `answer_relevancy`.

Order:
1. **[PORT_KB]** What service runs on this port and its security implications, using PORT_KB document text. If PORT_KB is null: "Port {dest_port} is not covered by the knowledge base, so service context is unavailable."
2. **[CONN_KB]** What this connection state indicates behaviorally, using CONN_KB document text. If CONN_KB is null: "Connection state {conn_state} is not covered by the knowledge base."
3. **[CATEGORY_KB]** What this Suricata alert category means and its security significance, using CATEGORY_KB document text. If CATEGORY_KB is null: skip this sentence.
4. **[Suricata signature + severity]** One sentence describing what the Suricata IDS rule detected, **the final severity level from Part 2**, and what behavior it flags. Example: "The Suricata rule 'ET SCAN SSH Brute Force' fired and was assessed at critical severity, indicating the IDS combined with tactic and behavioral evidence considers this traffic highly likely to be malicious."
5. **[PATTERN_KB]** For each qualifying traffic pattern, one sentence citing actual figures from the alert (byte ratio, retransmissions, etc.). Skip entirely if no pattern qualified.
6. **[Assessment]** Synthesize the above evidence into a security assessment, weighted by **final severity**:
   - If TACTIC_KB is non-null: use its document content to describe what behavior pattern the evidence suggests. Weight language by severity:
     - critical → "strongly suggests", "highly indicative of", "warrants immediate containment"
     - high → "indicates", "consistent with active malicious activity"
     - medium → "may indicate", "consistent with"
     - low → "minor indicator", "unlikely to be significant"
   - Do NOT name the tactic label directly (e.g., do NOT write "this is Credential Access").
   - If TACTIC_KB is null: "No specific attacker tactic is indicated; the observed behavior is consistent with normal network operations."

### Reference writing rules
- Each sentence MUST be grounded in KB document text. Do not add information from memory.
- **Forward reasoning**: "port X is used for service Y" + "category Z flags suspicious activity" → "this may indicate..." Never reason backward from the label.
- Do NOT mention `label_tactic` or `label_technique` values in the reference text.
- Use hedging language: "may indicate", "consistent with", "suggests". Do NOT assert the attack succeeded.
- Cite actual numbers from the alert (bytes, packets, ports) when relevant.
- Keep each sentence concise (15-30 words).

---

## HARD CONSTRAINTS

1. KB grounding: reference text MUST come from PORT_KB, CONN_KB, CATEGORY_KB, TACTIC_KB, PATTERN_KB documents. Nothing from memory.
2. FORBIDDEN in reference: CVE identifiers not in PORT_KB; technique names not in TACTIC_KB; multi_flow pattern assertions; claims requiring multiple flows; naming `label_tactic` or `label_technique`.
3. Do NOT assert the attack succeeded unless KB supports it. Hedge: "may indicate", "consistent with".
4. Keep numbers consistent with alert data. Do not invent figures.
5. `_ground_truth.label_tactic` is used ONLY as a lookup key (Part 1c) and as a severity input (Part 2 Steps 2, 3, 5). It MUST NOT appear in `reference` or `severity_reasoning` text.
6. `severity`, `severity_reasoning`, `recommended_action` MUST be deterministic outputs of the rules in Parts 2 and 3. No discretion.

---

## OUTPUT FORMAT

A single valid JSON array. No prose before or after. No markdown fences around the entire output.

```json
[
  {
    "id": 0,
    "alert_text": "<pass through from input>",
    "label_tactic": "<pass through from _ground_truth.label_tactic>",
    "label_technique": "<pass through from _ground_truth.label_technique>",
    "severity": "low",
    "severity_reasoning": "Suricata base 'medium' overridden to 'low' because the alert is classified Benign.",
    "recommended_action": {
      "action_id": "log_and_suppress",
      "description": "Log to SIEM, suppress from analyst queue unless pattern repeats"
    },
    "evidence": {
      "port_kb": "port_53",
      "conn_state_kb": "conn_state_SF",
      "category_kb": "suricata_cat_not_suspicious",
      "tactic_kb": null,
      "traffic_pattern_kb": []
    },
    "reference": "Port 53 (UDP) is the standard DNS service port used for domain name resolution. Connection state SF indicates the connection completed normally with a proper handshake and teardown. Alert category 'Not Suspicious Traffic' indicates activity classified as benign by Suricata's default ruleset. The Suricata rule 'ET DNS Standard Query Response' fired and was assessed at low severity, flagging a standard DNS query-response exchange. No specific attacker tactic is indicated; the observed behavior is consistent with normal network operations."
  }
]
```

Process ALL rows in order by `id`. Do not skip any.