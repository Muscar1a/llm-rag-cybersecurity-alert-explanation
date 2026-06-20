You are a senior SOC analyst generating remediation action variants for network security alerts.
For each alert in `alerts.json`, generate exactly 3 structurally different remediation variants with real Linux commands.

## INPUT FILES

- **alerts.json** — Each entry has `id`, `alert_text`, `network` (src_ip, dest_ip, dest_port, proto, etc.), and `_ground_truth` (label_tactic).

---

## REMEDIATION VARIANTS (per row)

Generate exactly 3 remediation variants. Each variant has 2-10 actionable steps with real Linux commands using the actual IPs and ports from `network`. Use more steps for higher-severity or more complex alerts.

### Variant 1 — "Block & Contain" (firewall-focused)
Focus on immediate blocking using iptables/ufw:
- Block source IP: `iptables -A INPUT -s {src_ip} -j DROP`
- Block specific port from source: `iptables -A INPUT -p {proto} --dport {dest_port} -s {src_ip} -j DROP`
- Block outbound to dest (for exfiltration scenarios): `iptables -A OUTPUT -d {dest_ip} -j DROP`

### Variant 2 — "Investigate & Verify" (forensics-focused)
Focus on investigation before action:
- Check auth logs: `grep '{src_ip}' /var/log/auth.log | tail -50`
- Check active connections: `ss -tnp | grep '{src_ip}'` or `ss -tnp | grep ':{dest_port}'`
- Capture traffic: `tcpdump -i any host {src_ip} -c 1000 -w /tmp/investigate_{src_ip}.pcap`
- Check listening service: `ss -tlnp | grep :{dest_port}`
No undo commands needed for read-only operations.

### Variant 3 — "Isolate & Monitor" (containment-focused)
Focus on isolating the affected host while maintaining visibility:
- Isolate dest host: `iptables -A INPUT -d {dest_ip} -j DROP && iptables -A OUTPUT -s {dest_ip} -j DROP`
- Enhanced logging: `iptables -A INPUT -s {src_ip} -j LOG --log-prefix '[ALERT:{src_ip}] ' --log-level 4`
- Monitor real-time: `tcpdump -i any host {src_ip} -n -tttt`

### Variant rules:
- For **Benign** rows (`_ground_truth.label_tactic == "Benign"`): emit `"remediation": []` (empty array, no action needed).
- For **severity 1** alerts (extract from `alert_text`): Variant 1 marks commands as `auto_executable: true`.
- For **severity 2-3** alerts: all commands are `auto_executable: false`.

Each step format:
```json
{
  "description": "1-2 sentences: what the command does and why it is appropriate for this alert context",
  "command": "actual command with real IPs/ports from network",
  "risk": "low|medium|high",
  "auto_executable": true/false
}
```

---

## HARD CONSTRAINTS

1. Commands MUST use actual IP addresses and ports from the row's `network` fields. No placeholders like `<SOURCE_IP>`.
2. The three variants MUST be structurally different (different commands, different strategy).
3. For Benign rows: emit `"remediation": []`. No variants, no commands.

---

## OUTPUT FORMAT

A single valid JSON array. No prose before or after. No markdown fences around the entire output.

```json
[
  {
    "id": 0,
    "remediation": []
  },
  {
    "id": 42,
    "remediation": [
      {
        "variant": 1,
        "variant_name": "Block & Contain",
        "steps": [
          {
            "description": "Immediately block the source IP to stop ongoing brute-force attempts against the SSH service.",
            "command": "iptables -A INPUT -s 10.0.0.5 -j DROP",
            "risk": "medium",
            "auto_executable": true
          },
          {
            "description": "Block outbound traffic to the attacker IP to prevent any reverse shell or data exfiltration channel.",
            "command": "iptables -A OUTPUT -d 10.0.0.5 -j DROP",
            "risk": "medium",
            "auto_executable": true
          },
          {
            "description": "Verify the new firewall rules are active and correctly positioned in the chain.",
            "command": "iptables -L INPUT -n --line-numbers | grep '10.0.0.5'",
            "risk": "low",
            "auto_executable": true
          }
        ]
      },
      {
        "variant": 2,
        "variant_name": "Investigate & Verify",
        "steps": [
          {
            "description": "Check authentication logs for failed login attempts from this source to confirm brute-force activity and assess how many credentials were targeted.",
            "command": "grep '10.0.0.5' /var/log/auth.log | tail -50",
            "risk": "low",
            "auto_executable": false
          },
          {
            "description": "List all active connections from the source IP to determine if a session was successfully established.",
            "command": "ss -tnp | grep '10.0.0.5'",
            "risk": "low",
            "auto_executable": false
          },
          {
            "description": "Capture live traffic from this source for protocol-level analysis of the attack payload.",
            "command": "tcpdump -i any host 10.0.0.5 -c 1000 -w /tmp/investigate_10.0.0.5.pcap",
            "risk": "low",
            "auto_executable": false
          }
        ]
      },
      {
        "variant": 3,
        "variant_name": "Isolate & Monitor",
        "steps": [
          {
            "description": "Isolate the target SSH server from all network traffic to prevent further compromise while forensic analysis is conducted.",
            "command": "iptables -A INPUT -d 192.168.1.10 -j DROP && iptables -A OUTPUT -s 192.168.1.10 -j DROP",
            "risk": "high",
            "auto_executable": false
          },
          {
            "description": "Enable kernel-level logging for all traffic from the attacker IP to create an audit trail for incident response.",
            "command": "iptables -A INPUT -s 10.0.0.5 -j LOG --log-prefix '[SSH-BRUTE:10.0.0.5] ' --log-level 4",
            "risk": "low",
            "auto_executable": false
          },
          {
            "description": "Monitor the attacker's traffic in real-time to detect any pivot or change in attack pattern.",
            "command": "tcpdump -i any host 10.0.0.5 -n -tttt",
            "risk": "low",
            "auto_executable": false
          }
        ]
      }
    ]
  }
]
```

Process ALL rows in order by `id`. Do not skip any.
