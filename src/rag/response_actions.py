import re
import subprocess
import logging

logger = logging.getLogger(__name__)

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def _safe_ip(val: str | None) -> str | None:
    if val and _IP_RE.match(val):
        return val
    return None


def _safe_port(val: int | None) -> int | None:
    if val is not None and 1 <= val <= 65535:
        return val
    return None


TACTIC_TEMPLATES = {
    "Reconnaissance": [
        {
            "description": "Block source IP at firewall",
            "command_template": "iptables -A INPUT -s {src_ip} -j DROP",
            "severity_threshold": "High",
            "risk": "low",
        },
        {
            "description": "Log all connections from source IP",
            "command_template": "iptables -A INPUT -s {src_ip} -j LOG --log-prefix '[THREAT:{src_ip}] '",
            "severity_threshold": "Medium",
            "risk": "low",
        },
    ],
    "Credential_Access": [
        {
            "description": "Block source IP at firewall",
            "command_template": "iptables -A INPUT -s {src_ip} -j DROP",
            "severity_threshold": "High",
            "risk": "low",
        },
        {
            "description": "Block source IP on target port",
            "command_template": "iptables -A INPUT -p tcp --dport {dest_port} -s {src_ip} -j DROP",
            "severity_threshold": "High",
            "risk": "low",
        },
        {
            "description": "Check authentication logs from source IP",
            "command_template": "grep '{src_ip}' /var/log/auth.log | tail -50",
            "severity_threshold": "Critical",
            "risk": "low",
        },
    ],
    "Exfiltration": [
        {
            "description": "Block outbound traffic to destination IP",
            "command_template": "iptables -A OUTPUT -d {dest_ip} -j DROP",
            "severity_threshold": "High",
            "risk": "medium",
        },
        {
            "description": "Capture traffic to destination for forensics",
            "command_template": "tcpdump -i any host {dest_ip} -w /tmp/exfil_{dest_ip}.pcap &",
            "severity_threshold": "Medium",
            "risk": "low",
        },
        {
            "description": "Kill active connections to destination IP",
            "command_template": "ss -K dst {dest_ip}",
            "severity_threshold": "Critical",
            "risk": "high",
        },
    ],
    "Initial_Access": [
        {
            "description": "Block source IP at firewall",
            "command_template": "iptables -A INPUT -s {src_ip} -j DROP",
            "severity_threshold": "High",
            "risk": "low",
        },
        {
            "description": "Isolate compromised host",
            "command_template": "iptables -A INPUT -d {dest_ip} -j DROP && iptables -A OUTPUT -s {dest_ip} -j DROP",
            "severity_threshold": "Critical",
            "risk": "high",
        },
        {
            "description": "Check running services on target port",
            "command_template": "ss -tlnp | grep :{dest_port}",
            "severity_threshold": "Medium",
            "risk": "low",
        },
    ],
    "Defense_Evasion": [
        {
            "description": "Enable enhanced logging for source IP",
            "command_template": "iptables -A INPUT -s {src_ip} -j LOG --log-prefix '[EVASION:{src_ip}] ' --log-level 4",
            "severity_threshold": "Medium",
            "risk": "low",
        },
        {
            "description": "Isolate suspect host",
            "command_template": "iptables -A INPUT -d {dest_ip} -j DROP && iptables -A OUTPUT -s {dest_ip} -j DROP",
            "severity_threshold": "Critical",
            "risk": "high",
        },
    ],
}

PORT_TEMPLATES = {
    22: [
        {
            "description": "Block SSH from source IP",
            "command_template": "iptables -A INPUT -p tcp --dport 22 -s {src_ip} -j DROP",
            "severity_threshold": "High",
            "risk": "low",
        },
    ],
    445: [
        {
            "description": "Block external SMB access from source",
            "command_template": "iptables -A INPUT -p tcp --dport 445 -s {src_ip} -j DROP",
            "severity_threshold": "High",
            "risk": "low",
        },
    ],
    4848: [
        {
            "description": "Restrict GlassFish admin to localhost only",
            "command_template": "iptables -A INPUT -p tcp --dport 4848 ! -s 127.0.0.1 -j DROP",
            "severity_threshold": "Medium",
            "risk": "low",
        },
    ],
}

_KNOWN_TACTICS = list(TACTIC_TEMPLATES.keys())


def detect_tactic(
    label_tactic: str | None,
    raw_docs: list,
    llm_output: dict,
) -> str | None:
    if label_tactic and label_tactic in TACTIC_TEMPLATES:
        return label_tactic

    for doc in raw_docs:
        meta = doc.metadata if hasattr(doc, "metadata") else {}
        if meta.get("kb_type") == "tactic" and meta.get("tactic"):
            tactic = meta["tactic"]
            if tactic in TACTIC_TEMPLATES:
                return tactic

    desc = llm_output.get("threat_description", "")
    for tactic in _KNOWN_TACTICS:
        if re.search(tactic.replace("_", r"[_ ]"), desc, re.IGNORECASE):
            return tactic

    return None


class ResponseActionEngine:
    def generate(
        self,
        severity: str,
        tactic: str | None,
        metadata: dict | None = None,
    ) -> list[dict]:
        metadata = metadata or {}
        src_ip = _safe_ip(metadata.get("src_ip"))
        dest_ip = _safe_ip(metadata.get("dest_ip"))
        dest_port = _safe_port(metadata.get("dest_port"))

        params = {
            "src_ip": src_ip or "<SOURCE_IP>",
            "dest_ip": dest_ip or "<DEST_IP>",
            "dest_port": str(dest_port) if dest_port else "<DEST_PORT>",
        }

        templates = []
        if tactic and tactic in TACTIC_TEMPLATES:
            templates.extend(TACTIC_TEMPLATES[tactic])
        if dest_port and dest_port in PORT_TEMPLATES:
            templates.extend(PORT_TEMPLATES[dest_port])

        if not templates:
            templates = TACTIC_TEMPLATES["Reconnaissance"][:1]

        sev_rank = SEVERITY_RANK.get(severity, 0)
        commands = []
        for t in templates:
            threshold_rank = SEVERITY_RANK.get(t["severity_threshold"], 0)
            try:
                cmd = t["command_template"].format(**params)
            except KeyError:
                continue

            commands.append({
                "description": t["description"],
                "command": cmd,
                "platform": "linux",
                "risk": t["risk"],
                "auto_executable": sev_rank >= threshold_rank,
                "executed": False,
                "execution_status": None,
            })

        return commands

    def execute(self, commands: list[dict], mode: str = "dry_run") -> list[str]:
        logs = []
        for cmd in commands:
            if not cmd.get("auto_executable"):
                continue
            if mode == "dry_run":
                logs.append(f"[DRY-RUN] Would execute: {cmd['command']}")
                cmd["executed"] = True
                cmd["execution_status"] = "dry_run"
            elif mode == "live":
                try:
                    result = subprocess.run(
                        cmd["command"],
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    cmd["executed"] = True
                    cmd["execution_status"] = "success" if result.returncode == 0 else "failed"
                    logs.append(f"[EXEC] {cmd['command']} -> {cmd['execution_status']}")
                except Exception as e:
                    cmd["executed"] = True
                    cmd["execution_status"] = "failed"
                    logs.append(f"[EXEC-ERROR] {cmd['command']} -> {e}")
        return logs
