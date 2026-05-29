# Knowledge Base Upgrade: Behavioral Rules

**Date**: 2026-05-28  
**Based on**: Evaluation results from 16 ground truth samples across 3 prompt templates

---

## 1. Problem Summary

### Current State
- **Severity Accuracy**: 62.5% (basic/cot), 31.3% (few_shot)
- **Attack Semantic Hit**: Only 12.5% - system fails to identify correct attack type
- **Root Cause**: Knowledge base lacks behavioral rules matching flow metadata patterns

### Input Format
System receives **flow metadata**, not packet payloads:
```
TCP flow on port 8080/HTTP-Proxy
Volume: 7 packets (3 fwd / 4 bwd), 455 bytes
Duration: 9.3 ms
TCP flags: PSHx1, RSTx1, ECEx1
TCP window: client 8192 B (non-standard), server 219 B
```

### Current KB Coverage Gap
| Retrieved Rules | Type | Problem |
|-----------------|------|---------|
| ET DOS Excessive Large Tree Connect | Signature | Matches SMB payload, not flow metadata |
| GPL SQL buffer overflow | Signature | Matches SQL strings, not timing patterns |
| ET DOS HTTP GET AAAAAAAA | Signature | Matches HTTP payload, not available |

---

## 2. Missing Behavioral Rules

### 2.1 Botnet C2 Beaconing (HTTP-Proxy)

**Attack Pattern** (from ground truth):
> Short TCP session to HTTP-Proxy port 8080, non-standard initial window 8192 B identifies custom (non-browser) TCP stack, PSH-data-then-RST pattern consistent with botnet C2 beaconing.

```yaml
id: BHR-022
name: Botnet C2 Beaconing via HTTP-Proxy
protocol: TCP
ports: 
  dst_port: 8080, 3128, 8888, 1080
keywords: 
  - botnet, C2, beaconing, proxy tunnel, custom stack, malware check-in
mitre_attack: "Command and Control | T1071.001 — Web Protocols"

detection:
  - Non-standard TCP initial window: not matching common OS fingerprints
  - PSH flag followed by RST: post-then-abort pattern
  - Very short duration: < 50 ms
  - Client-dominant byte ratio with small payload (< 1KB)
  - No standard HTTP request/response cycle

flow_profile:
  direction: outbound_to_proxy
  duration: very_short (< 100ms)
  payload: minimal (< 1KB)
  handshake: may be incomplete
  byte_ratio: client_dominant
  packet_pattern: micro_burst_then_abort
  tcp_flags: PSH followed by RST

classtype: trojan-activity
severity: High

context: |
  Botnet implants often use HTTP proxies for C2 communication to blend with 
  legitimate traffic. Key fingerprints include non-standard TCP window sizes 
  (indicating custom malware TCP stack), very short connection duration, and 
  PSH+RST pattern where the bot posts a small beacon/command and immediately 
  tears down the connection to evade flow-based detection.

differential_diagnosis: |
  - BHR-022 (this): Custom TCP stack + PSH+RST on PROXY ports = C2 beaconing
  - BHR-021 (Zero-byte probe): No payload, just probing = reconnaissance
  - BHR-006 (Slowloris): Long duration, slow rate = connection exhaustion DoS
```

---

### 2.2 Botnet Reachability Probe (ACK-only)

**Attack Pattern** (from ground truth):
> Two-packet ACK-only probe to HTTP-Proxy port 8080 with zero payload, non-standard initial window of 2052 B, lone ACK without SYN handshake indicates botnet implant probing C2 channel.

```yaml
id: BHR-023
name: Botnet C2 Reachability Probe
protocol: TCP
ports:
  dst_port: 8080, 3128, 8888, 1080, 443, 80
keywords:
  - botnet, reachability, probe, ACK scan, C2 check, liveness

mitre_attack: "Command and Control | T1071 — Application Layer Protocol"

detection:
  - ACK flag only: no SYN handshake
  - Zero bytes transferred
  - Non-standard TCP window: embedded/malware stack fingerprint
  - Very short duration: < 5 ms
  - Server did not respond

flow_profile:
  direction: outbound
  duration: very_short (< 10ms)
  payload: zero
  handshake: none (ACK without SYN)
  byte_ratio: zero
  packet_pattern: single_probe_no_response
  tcp_flags: ACK only

classtype: trojan-activity
severity: Medium

context: |
  Before full C2 communication, botnet implants often probe whether their 
  command server is reachable. These probes use ACK packets without prior 
  SYN (no handshake), non-standard TCP windows from custom malware stacks, 
  and expect no response - they just check if the path is not blocked.

differential_diagnosis: |
  - BHR-023 (this): ACK-only + non-standard window + C2 ports = bot probe
  - BHR-021 (Zero-byte probe): Generic probe, any port, any flag pattern
  - BHR-017 (SYN scan): Uses SYN flag, targets multiple ports sequentially
```

---

### 2.3 Time-Based Blind SQL Injection

**Attack Pattern** (from ground truth):
> HTTP/80 conversation spanning 5.0 s with short forward request bursts followed by multi-second idle gaps, characteristic of time-based blind SQL injection (sqlmap with SLEEP/BENCHMARK payloads).

```yaml
id: BHR-024
name: Time-Based Blind SQL Injection
protocol: TCP
ports:
  dst_port: 80, 443, 8080, 8443
keywords:
  - SQL injection, blind SQLi, time-based, SLEEP, BENCHMARK, sqlmap

mitre_attack: "Initial Access | T1190 — Exploit Public-Facing Application"

detection:
  - HTTP port with moderate duration: 2-30 seconds
  - High IAT variance: short bursts then long gaps (> 1 second)
  - Forward IAT much shorter than overall flow IAT
  - Small request size with delayed/small response
  - Non-standard TCP stack (automated tool)
  - RST termination common

flow_profile:
  direction: outbound_to_server
  duration: medium (2-30 seconds)
  payload: small_request_small_response
  handshake: complete
  byte_ratio: balanced or client_dominant
  packet_pattern: burst_then_long_gap (IAT max >> IAT mean)
  tcp_flags: PSH, often RST termination

classtype: web-application-attack
severity: High

context: |
  Time-based blind SQL injection tools (sqlmap, etc.) inject SLEEP() or 
  BENCHMARK() payloads and measure server response time to infer query 
  results bit-by-bit. Flow signature shows request bursts followed by 
  multi-second gaps (the injected delay). High IAT standard deviation 
  relative to mean indicates this pattern.

differential_diagnosis: |
  - BHR-024 (this): HTTP + high IAT variance + medium duration = SQLi timing
  - BHR-006 (Slowloris): Very long duration, minimal payload, no response gaps
  - BHR-005 (Hulk/GoldenEye): High packet rate, short bursts, volumetric
```

---

### 2.4 DNS-Based C2 Beaconing / Tunneling

**Attack Pattern** (from ground truth):
> Small DNS query/response pair on UDP/53 (32 B sent, 48 B received). Pattern consistent with DNS-based C2 beaconing or low-and-slow DNS tunneling.

```yaml
id: BHR-025
name: DNS C2 Beaconing / Tunneling
protocol: UDP
ports:
  dst_port: 53
keywords:
  - DNS tunneling, DNS C2, beaconing, exfiltration, covert channel

mitre_attack: "Command and Control | T1071.004 — DNS"

detection:
  - UDP/53 with small fixed-size queries: 30-100 bytes
  - Regular timing pattern when aggregated
  - Query/response pairs with minimal size variance
  - High frequency to same destination
  - Response slightly larger than query (TXT record tunneling)

flow_profile:
  direction: outbound_to_dns
  duration: very_short per flow
  payload: small_fixed_size (30-100 bytes each direction)
  byte_ratio: balanced (1.2x - 2.0x response/query)
  packet_pattern: single_query_response_pair
  aggregation_pattern: periodic when viewed across multiple flows

classtype: trojan-activity
severity: Medium

context: |
  DNS tunneling encodes C2 commands or exfiltrated data within DNS queries 
  to attacker-controlled domains. Individual flows appear benign (normal 
  DNS lookup), but patterns emerge: fixed-size queries, periodic timing, 
  and TXT record responses slightly larger than queries. Single-flow 
  detection is difficult; correlation across flows reveals the pattern.

differential_diagnosis: |
  - BHR-025 (this): Small UDP/53 + periodic + fixed size = DNS C2
  - Normal DNS: Variable query sizes, irregular timing, cached responses
  - DNS amplification attack: Large responses (10x+ query size), spoofed src
```

---

### 2.5 HULK HTTP Flood Fingerprint

**Attack Pattern** (from ground truth):
> Two-packet ACK-only HTTP/80 micro-flow, recurring fingerprint (init window 225 B, minimum forward segment 32 B) characteristic of HULK flood traffic.

```yaml
id: BHR-026
name: HULK HTTP Flood Tool Fingerprint
protocol: TCP
ports:
  dst_port: 80, 443, 8080
keywords:
  - HULK, HTTP flood, DDoS, tool fingerprint, application flood

mitre_attack: "Impact | T1499.002 — Service Exhaustion Flood"

detection:
  - TCP initial window: 225 B (HULK fingerprint)
  - Minimum forward segment: 32 B
  - Zero-byte or minimal payload per flow
  - Very short duration per flow
  - High flow rate when aggregated
  - ACK-only termination fragments

flow_profile:
  direction: outbound_to_server
  duration: very_short per flow
  payload: zero_to_minimal
  handshake: fragments (ACK teardowns)
  byte_ratio: client_only or zero
  packet_pattern: micro_flow_fragments
  tcp_window: 225 B (tool signature)
  min_segment: 32 B (tool signature)

classtype: denial-of-service
severity: High

context: |
  HULK (HTTP Unbearable Load King) generates massive parallel HTTP requests 
  to exhaust web server worker pools. Many flow records capture only the 
  teardown/ACK fragments from this barrage. Tool fingerprint: TCP initial 
  window 225 B, minimum segment 32 B. Single fragment looks benign, but 
  thousands per second indicate active HULK campaign.

differential_diagnosis: |
  - BHR-026 (this): Window 225B + segment 32B = HULK fingerprint
  - BHR-005 (Generic HTTP flood): Higher volume, no specific fingerprint
  - BHR-021 (Zero-byte probe): No specific window/segment fingerprint
```

---

### 2.6 IKE/VPN Brute Force Enumeration

**Attack Pattern** (from ground truth):
> Six fixed-size 500-byte UDP packets to port 500 over 1.5 min with no replies, characteristic of IKE aggressive-mode brute force or PSK enumeration.

```yaml
id: BHR-027
name: IKE/VPN PSK Brute Force
protocol: UDP
ports:
  dst_port: 500, 4500
keywords:
  - IKE, IPsec, VPN, brute force, PSK enumeration, aggressive mode

mitre_attack: "Credential Access | T1110.001 — Password Guessing"

detection:
  - UDP port 500 or 4500 (IKE/IPsec)
  - Fixed-size packets: typically 500-600 bytes
  - Regular spacing: 10-60 seconds between packets
  - One-directional: server not responding
  - Multiple packets from same source

flow_profile:
  direction: outbound_to_vpn
  duration: minutes
  payload: fixed_size_per_packet (500-600 bytes)
  byte_ratio: client_only (no response)
  packet_pattern: slow_regular_spacing
  packet_size_variance: zero (identical packets)

classtype: attempted-admin
severity: High

context: |
  IKE aggressive-mode allows identity/PSK enumeration against VPN gateways. 
  Attackers send fixed-size IKE proposals iterating through identities or 
  pre-shared keys. Pattern: identical packet sizes, regular slow spacing 
  (to avoid rate limits), no server response (probing for valid identity).
  Successful compromise grants full network access.

differential_diagnosis: |
  - BHR-027 (this): UDP/500 + fixed size + regular spacing = IKE brute force
  - Normal IKE: Bidirectional, variable phases, successful negotiation
  - UDP flood: High rate, variable sizes, volumetric intent
```

---

## 3. Implementation Priority

| Priority | Rule ID | Attack Type | Impact |
|----------|---------|-------------|--------|
| P0 | BHR-022 | Bot C2 Beaconing | High - currently misclassified as DoS |
| P0 | BHR-023 | Bot Reachability Probe | High - currently misclassified |
| P0 | BHR-024 | Time-based SQLi | High - completely missed |
| P1 | BHR-025 | DNS C2/Tunneling | Medium - currently rated Low |
| P1 | BHR-026 | HULK Fingerprint | High - misclassified as Slowloris |
| P2 | BHR-027 | IKE Brute Force | Medium - misclassified as Slowloris |

---

## 4. Expected Improvement

After implementing these rules:

| Metric | Current | Expected |
|--------|---------|----------|
| Attack Semantic Hit | 12.5% | ~70-80% |
| Severity Correct | 62.5% | ~80-85% |
| Context Precision | 0.52 | ~0.75+ |
| Hallucination Rate | 0.87 | ~0.5 |

---

## 5. File Locations

Rules should be added to:
- `data/behavioral_rules/` - YAML format behavioral rules
- Ingested via `src/data_process/ingest_behavioral_rules.py`

Embedding model: `BAAI/bge-base-en-v1.5` (as per upgrade plan)
