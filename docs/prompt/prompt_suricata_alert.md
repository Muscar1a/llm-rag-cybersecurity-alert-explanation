# Synthetic Suricata Alert Generation from Zeek Connection Records

You are a senior SOC analyst and Suricata expert.

Your task is to convert each Zeek connection record into a deterministic synthetic Suricata alert event.

The objective is **NOT** to infer attacker intent and **NOT** to classify ATT&CK tactics.

The objective is **ONLY** to generate a realistic IDS-style alert based on observable network metadata.

---

# INPUT

Input file:

`zeek_rows.json`

Each element contains:

```json
{
  "id": 0,
  "network": {
    ...
  },
  "_ground_truth": {
    ...
  }
}
```

The file contains 173 records.

---

# CRITICAL RULES

## Rule 1 — Use Only Network Telemetry

You may use ONLY the following fields from `network`:

* proto
* src_ip
* src_port
* dest_ip
* dest_port
* conn_state
* duration_s
* orig_bytes
* resp_bytes
* orig_pkts
* resp_pkts
* service
* history

Do NOT use:

* label_tactic
* label_technique
* label_binary
* label_cve
* any other ground-truth field

Ground truth exists only for pass-through.

---

## Rule 2 — Deterministic Signature Selection

Alert selection MUST be performed exclusively using:

```text
(dest_port, conn_state, service)
```

No additional reasoning is allowed.

Select the FIRST matching rule from the lookup table below.

Once a rule matches:

* Stop evaluation immediately.
* Do not evaluate later rules.
* Do not combine multiple rules.
* Do not invent new signatures.

---

## Rule 3 — Service Normalization

Before matching:

Treat the following values as EMPTY:

* null
* ""
* "-"
* "unknown"
* strings containing only whitespace

Convert the service value to lowercase before comparison.

---

# SIGNATURE LOOKUP TABLE

| Priority | dest_port | conn_state | service condition               | signature                                                             | severity | category                      |
| -------- | --------- | ---------- | ------------------------------- | --------------------------------------------------------------------- | -------- | ----------------------------- |
| 1        | 53        | SF         | contains dns                    | ET DNS Standard Query Response                                        | 3        | Not Suspicious Traffic        |
| 2        | 53        | S0         | any                             | ET DNS Query Timeout — No Server Response                             | 3        | Potentially Bad Traffic       |
| 3        | 123       | SF         | contains ntp                    | ET POLICY NTP Sync                                                    | 3        | Not Suspicious Traffic        |
| 4        | 4848      | SF         | contains ssl OR contains http   | ET WEB_SERVER Application Server Admin Interface Access               | 1        | Potentially Bad Traffic       |
| 5        | 445       | S0         | service is empty                | ET SCAN Possible SMB Connection Probe                                 | 2        | Attempted Information Leak    |
| 6        | 445       | RSTO       | contains smb OR ntlm OR dce_rpc | ET NETBIOS SMB Session Established Then Reset — Possible Exploitation | 1        | A Network Trojan was detected |
| 7        | 445       | RSTO       | service exactly equals gssapi   | ET NETBIOS SMB Authentication Exchange Then Reset                     | 2        | Potentially Bad Traffic       |
| 8        | 445       | RSTO       | service is empty                | ET NETBIOS SMB Connection Reset After Handshake                       | 2        | Potentially Bad Traffic       |
| 9        | 445       | RSTR       | any                             | ET NETBIOS SMB Server Forced Connection Reset                         | 2        | Potentially Bad Traffic       |
| 10       | 445       | REJ        | any                             | ET SCAN SMB Connection Rejected by Target                             | 2        | Attempted Information Leak    |
| 11       | 80        | SF         | contains http                   | ET WEB_SERVER Inbound HTTP Connection to Server                       | 2        | Potentially Bad Traffic       |
| 12       | 80        | RSTO       | any                             | ET WEB_SERVER HTTP Connection Reset by Client                         | 2        | Potentially Bad Traffic       |
| 13       | 80        | OTH        | any                             | ET WEB_SERVER Incomplete HTTP Session — Mid-Stream Capture            | 2        | Potentially Bad Traffic       |
| 14       | 443       | S0         | any                             | ET SCAN HTTPS Port Probe — No Handshake Completed                     | 2        | Attempted Information Leak    |
| 15       | 443       | REJ        | any                             | ET SCAN HTTPS Connection Rejected                                     | 2        | Attempted Information Leak    |
| 16       | 20        | S0         | any                             | ET SCAN FTP-Data Port Probe                                           | 2        | Attempted Information Leak    |
| 17       | 21        | REJ        | any                             | ET SCAN FTP Connection Rejected by Server                             | 2        | Attempted Information Leak    |
| 18       | 21        | RSTO       | any                             | ET SCAN FTP Connection Reset After Partial Exchange                   | 2        | Attempted Information Leak    |
| 19       | 22        | S0         | any                             | ET SCAN Potential SSH Scan — No Handshake                             | 2        | Attempted Information Leak    |
| 20       | 25        | REJ        | any                             | ET SCAN SMTP Connection Rejected                                      | 2        | Attempted Information Leak    |
| 21       | 110       | S0         | any                             | ET SCAN POP3 Port Probe — No Reply                                    | 2        | Attempted Information Leak    |
| 22       | 111       | S0         | any                             | ET SCAN SunRPC Port Probe                                             | 2        | Attempted Information Leak    |
| 23       | 139       | S0         | any                             | ET SCAN NetBIOS Session Port Probe                                    | 2        | Attempted Information Leak    |
| 24       | 143       | REJ        | any                             | ET SCAN IMAP Connection Rejected                                      | 2        | Attempted Information Leak    |

---

# FALLBACK RULE

If no rule matches:

Signature:

```text
ET POLICY Unusual {PROTO} Traffic to Port {dest_port}
```

Severity:

```text
2
```

Category:

```text
Misc activity
```

Replace:

* `{PROTO}` with the uppercase protocol value
* `{dest_port}` with the actual destination port

Examples:

```text
proto=tcp, dest_port=8080
→ ET POLICY Unusual TCP Traffic to Port 8080
```

```text
proto=udp, dest_port=5353
→ ET POLICY Unusual UDP Traffic to Port 5353
```

---

# OUTPUT REQUIREMENTS

For every input record produce exactly one output object.

Preserve the following fields unchanged:

* id
* network
* _ground_truth

Generate a new field:

```json
"suricata_event": {
  "src_ip": "...",
  "src_port": 12345,
  "dest_ip": "...",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "signature": "...",
    "severity": 2,
    "category": "..."
  }
}
```

Requirements:

* `proto` must be uppercase.
* `severity` must be an integer.
* `src_port` must remain numeric.
* `dest_port` must remain numeric.
* Do not modify values from `network`.
* Do not modify values from `_ground_truth`.
* Do not add extra fields.

Forbidden fields include:

* flow_id
* timestamp
* metadata
* explanation
* classification
* references
* notes
* tags

---

# OUTPUT FORMAT

Return exactly one JSON array.

Each element must have the following structure:

```json
{
  "id": 0,
  "suricata_event": {
    "src_ip": "143.88.4.11",
    "src_port": 35663,
    "dest_ip": "143.88.5.12",
    "dest_port": 445,
    "proto": "TCP",
    "alert": {
      "signature": "ET SCAN Possible SMB Connection Probe",
      "severity": 2,
      "category": "Attempted Information Leak"
    }
  },
  "network": {
    "...copied exactly from input..."
  },
  "_ground_truth": {
    "...copied exactly from input..."
  }
}
```

Final response format:

```json
[
  {
    ...
  },
  {
    ...
  }
]
```

---

# VALIDATION

Before producing the final answer:

1. Verify output count equals input count.
2. Verify every input `id` appears exactly once.
3. Verify every output object contains:

   * id
   * suricata_event
   * network
   * _ground_truth
4. Verify no signature exists outside the lookup table or fallback template.
5. Verify `proto` is uppercase.
6. Verify output is valid JSON.
7. Verify no records were skipped.

---

# FINAL OUTPUT

Return ONLY a single valid JSON array.

Do NOT use Markdown code fences around the final output.

Do NOT include:

* explanations
* comments
* notes
* reasoning
* validation messages
* summaries

Output JSON only.
