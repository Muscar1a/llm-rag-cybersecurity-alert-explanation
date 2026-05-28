# alert_builder.py — Enhancement Summary

## Motivation

Evaluation results (3-sample comparison across `basic`, `cot`, `few_shot` prompt templates) revealed:

| Problem | Metric |
|---|---|
| Hallucination rate | 0.93–1.0 across all templates |
| Attack semantic hit | 0/3 — no template identified botnet C2 pattern |
| Context precision | 0.0–0.17 — retrieved KB rules were irrelevant |

**Root cause**: the original alert text was purely statistical (raw numbers, no behavioral interpretation).  
The model had to infer all meaning from values like `std 0.0 B` or `init window 2052 B`, with no semantic guidance.  
KB retrieval pulled unrelated IDS rules (FireFlood, Oracle SQL, SMB DoS) because the alert text lacked behavioral anchors.

---

## Changes

### 1. Window classification — `_classify_window()`

Replaced the 7-entry `WIN_OS` dict with a tiered helper function.  
`8192 B` is no longer treated as a known OS window (it was mislabeled before).

| Window size | Label |
|---|---|
| In `_STANDARD_WINDOWS` | OS name (Windows 10/11, Linux, macOS, …) |
| < 1024 B | `embedded/stripped-down stack (malware candidate)` |
| 1024–4095 B | `non-standard small window (embedded device or malware stack)` |
| ≥ 4096 B, not in standard list | `non-standard/custom stack` |

**Standard windows recognised**: 65535, 64240, 65392, 29200, 5840, 14600, 43690, 32768.

---

### 2. Semantic anchors

Four places in the alert text now carry behavioral interpretation inline:

**Byte ratio**

```
Before: 0.4x (client-dominant)
After:  0.4x (client-dominant — client sent significantly more than received; upload, POST, or C2 beacon)
```

```
Before: 8.2x (heavily server-dominant)
After:  8.2x (heavily server-dominant — large download or potential data exfiltration)
```

**Inter-arrival time (IAT)** — regularity annotation added when `std < 10% of mean`:

```
After: mean 0.6 ms, std 0.0 ms, max 0.6 ms
       (highly regular — consistent with automated/scripted sender or keepalive beacon)
```

**Forward / backward packet sizes**

| Condition | Annotation added |
|---|---|
| `fwd_max == 0` | `(no payload in forward direction)` |
| `fwd_std == 0.0` and data present | `(perfectly uniform — automated/scripted sender, not human interaction)` |
| `bwd_pkts == 0` or both bwd sizes are 0 | `(no server response)` |
| `bwd_std == 0.0` and data present | `(perfectly uniform server responses)` |

**TCP window** — `_classify_window()` replaces `WIN_OS.get(x, "unknown OS")`, so unknown windows now get a meaningful label instead of `"unknown OS"`.

---

### 3. Behavioral hints — expanded from 2 to 11

| # | Hint | Trigger condition | Attack pattern |
|---|---|---|---|
| 1 | SYN flood NOT possible | `SYN == 0` | (existing) |
| 2 | Zero-byte flow | `fwd_bytes == 0 and bwd_bytes == 0` | (existing) |
| 3 | **ACK-only probe** | `SYN=0, ACK>0, fwd_bytes=0, bwd_pkts=0` | Botnet C2 reachability check |
| 4 | **Non-OS TCP window (≥ 4096)** | `init_fwd_win not in _STANDARD_WINDOWS` | Custom / malware TCP stack |
| 4b | **Malware-range window (< 4096)** | `init_fwd_win < 4096, not standard` | Embedded / malware stack |
| 5 | **PSH+RST micro-burst** | `PSH>0, RST>0, dur < 50 ms` | C2 check-in, flow-duration evasion |
| 6 | **RST without FIN** | `RST>0, FIN=0, pkts>2` (not micro-burst) | Port scan, C2 beaconing, exploit |
| 7 | **C2 proxy port + non-browser stack** | `port ∈ _C2_PROXY_PORTS, window non-standard` | Malware C2 via proxy port |
| 8 | **SYN-only scan** | `SYN>0, ACK=0, fwd_bytes=0` | Half-open port scan |
| 9 | **FIN without SYN** | `FIN>0, SYN=0` | FIN scan, mid-session injection |
| 10 | **One-directional with payload** | `bwd_pkts=0, fwd_bytes>0` | Exploit attempt, filtered port |
| 11 | Baseline anomaly | via `baseline.annotate()` | (existing) |

`_C2_PROXY_PORTS = {8080, 8443, 3128, 1080, 9090, 4444, 6667, 6666}`

---

### 4. `build_metadata()` — 5 derived fields added

| Field | Formula | Purpose |
|---|---|---|
| `pkts_per_s` | `total_pkts / dur_s` | Rate anomaly detection |
| `bytes_per_pkt` | `total_bytes / total_pkts` | Avg payload size |
| `fwd_bwd_pkt_ratio` | `fwd_pkts / bwd_pkts` | Traffic asymmetry |
| `is_c2_proxy_port` | `dst_port in _C2_PROXY_PORTS` | Boolean filter for hybrid search |
| `flag_signature` | named enum via `_get_flag_signature()` | Fast flag-pattern lookup |

`flag_signature` values: `SYN-only`, `ACK-only`, `PSH+RST`, `SYN+FIN`, `FIN-no-SYN`, `SYN-ACK-FIN-normal`, `other`.

---

## Verification — 3 eval samples

| Sample | Traffic | New hints triggered |
|---|---|---|
| Bot S1 | C2 beaconing, PSH+RST, window 8192, port 8080 | Non-OS window · PSH+RST micro-burst · C2 proxy port |
| Bot S2 | ACK probe, window 2052, 0 bytes, no response | ACK-only probe · Malware-range window · C2 proxy port |
| Bot S3 | ACK probe, window 256, 0 bytes, no response | ACK-only probe · Malware-range window · C2 proxy port |

All 3 samples that previously received only 2 generic hints now receive 4–5 behaviorally specific hints pointing toward botnet C2 activity.

---

## Known limitations / next steps

- **KB mismatch not fixed here**: the KB still contains payload-based IDS rules (FireFlood, Oracle SQL, SMB DoS) which cannot match flow-level statistics. Retrieval quality will not improve until behavioral rules are added to the KB.
- **Behavioral classification labels** (Tier 1a from Opus proposal) deliberately left out — hard labels risk encoding wrong conclusions into embeddings. Hedged semantic anchors (implemented here) are safer.
- **Short-view for retrieval** (Tier 2d) requires changes in `lc_vectorstore.py`, not in this file.
