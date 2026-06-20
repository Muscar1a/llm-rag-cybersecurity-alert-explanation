# Plan: Remediation Commands & Auto-Response

## Context

Thầy yêu cầu hệ thống phải:
1. Đưa ra **biện pháp khắc phục cụ thể** bao gồm các lệnh (iptables, firewall...)
2. Với mức độ **đặc biệt nghiêm trọng** (Critical/High), có thể **trực tiếp can thiệp** bảo vệ hệ thống

Hiện tại `mitigation_steps` chỉ chứa hướng dẫn chung ("Correlate source IP...", "Escalate and block...") — không có lệnh cụ thể, không có khả năng tự động thực thi.

---

## Thiết kế: Two-layer Remediation

```
Alert + metadata ──► RAG Pipeline ──► LLM Response
                                          │
                          ┌───────────────┴───────────────┐
                          │                               │
                   mitigation_steps              ResponseActionEngine
                   (LLM, ngôn ngữ tự nhiên,     (rule-based, deterministic)
                    grounded in KB)                        │
                                              ┌───────────┴───────────────┐
                                              │                           │
                                    remediation_commands          auto-execution
                                    (iptables, ufw, ss...)       (nếu Critical + toggle ON)
                                    parameterized với             log + thực thi
                                    src_ip, dest_ip, port
```

**Tại sao tách 2 lớp:**
- **LLM layer**: giải thích CHO ANALYST hiểu cần làm gì và tại sao (đã có, giữ nguyên)
- **Engine layer**: sinh lệnh CHÍNH XÁC, deterministic, không hallucination — an toàn để auto-execute

---

## Thay đổi cụ thể

### 1. NEW: `src/rag/response_actions.py`

Module chính — ResponseActionEngine + command templates.

```python
# Templates per tactic, mỗi template có:
TACTIC_TEMPLATES = {
    "Reconnaissance": [
        {
            "description": "Block source IP tại firewall",
            "command_template": "iptables -A INPUT -s {src_ip} -j DROP",
            "undo_template": "iptables -D INPUT -s {src_ip} -j DROP",
            "severity_threshold": "High",  # auto-exec nếu severity >= threshold
            "risk": "low",
        },
        {
            "description": "Log tất cả kết nối từ source IP để giám sát",
            "command_template": "iptables -A INPUT -s {src_ip} -j LOG --log-prefix '[THREAT:{src_ip}] '",
            "undo_template": "iptables -D INPUT -s {src_ip} -j LOG --log-prefix '[THREAT:{src_ip}] '",
            "severity_threshold": "Medium",
            "risk": "low",
        },
    ],
    "Credential_Access": [
        # block src_ip,
        # block src_ip → dest_port cụ thể,
        # kiểm tra auth log,
    ],
    "Exfiltration": [
        # block outbound tới dest_ip,
        # capture traffic để forensics,
        # kill active connections,
    ],
    "Initial_Access": [
        # block src_ip,
        # isolate dest_ip (cách ly host bị tấn công),
        # kiểm tra dịch vụ trên dest_port,
    ],
    "Defense_Evasion": [
        # enhanced logging,
        # isolate host,
    ],
}

# Port-specific overrides (bổ sung cho tactic)
PORT_TEMPLATES = {
    22:   [  # ssh-specific: disable password auth, check authorized_keys
    ],
    445:  [  # smb-specific: disable SMBv1, block external SMB
    ],
    4848: [  # glassfish-specific: restrict admin access
    ],
}
```

**ResponseActionEngine class:**
- `generate(severity, tactic, metadata) → list[RemediationCommand]`
  - Chọn templates theo tactic + port
  - Fill parameters từ metadata (src_ip, dest_ip, dest_port)
  - Nếu không có metadata → dùng placeholder `<SOURCE_IP>`, `<DEST_IP>`
  - Mark `auto_executable=True` nếu severity >= template.severity_threshold
- `execute(commands, mode) → list[ExecutionLog]`
  - `mode="dry_run"`: chỉ log, không chạy
  - `mode="live"`: subprocess.run() + log kết quả

### 2. MODIFY: `src/rag/schemas.py` — Response models

```python
class RemediationCommand(BaseModel):
    description: str            # "Block source IP tại firewall"
    command: str                # "iptables -A INPUT -s 10.0.0.5 -j DROP"
    undo_command: str | None    # "iptables -D INPUT -s 10.0.0.5 -j DROP"
    platform: str = "linux"
    risk: str = "low"           # low | medium | high
    auto_executable: bool       # True nếu severity đủ ngưỡng
    executed: bool = False      # True nếu đã thực thi
    execution_status: str | None = None  # "success" | "failed" | "dry_run"

class AnalyzeResponse(BaseModel):
    # --- giữ nguyên 6 field hiện tại ---
    threat_description: str
    severity: str
    rationale: str
    mitigation_steps: list[str]
    retrieved_context_ids: list[str]
    contexts: list[RetrievedChunk] = Field(default_factory=list)
    # --- MỚI ---
    remediation_commands: list[RemediationCommand] = Field(default_factory=list)
    auto_response_triggered: bool = False
    auto_response_log: list[str] = Field(default_factory=list)
```

### 3. MODIFY: `src/rag/schemas.py` — Request models

Thêm optional metadata fields:

```python
class AlertMetadata(BaseModel):
    src_ip: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    conn_state: str | None = None
    label_tactic: str | None = None  # có thể dùng cho demo, không leak vào LLM

class AnalyzeRequest(BaseModel):
    alert_text: str = Field(min_length=5)
    source: Literal["cve", "mitre", "sigma"] | None = None
    k: int = Field(default=5, ge=1, le=20)
    metadata: AlertMetadata | None = None   # MỚI
    auto_response: bool | None = None       # MỚI — override setting per-request
```

### 4. MODIFY: `src/rag/settings.py`

```python
# Auto-response settings
auto_response_enabled: bool = False           # default tắt
auto_response_mode: str = "dry_run"           # "dry_run" | "live"
auto_response_severity_threshold: str = "Critical"  # severity tối thiểu để auto-exec
```

### 5. MODIFY: `src/rag/service.py`

Trong `analyze()` và `stream_analyze()`:
1. Sau khi LLM trả kết quả → lấy severity
2. Xác định tactic (từ request metadata hoặc parse từ LLM response)
3. Gọi `ResponseActionEngine.generate()` → remediation_commands
4. Nếu auto_response enabled + severity đủ → gọi `execute()`
5. Merge vào response

### 6. MODIFY: `src/api/main.py`

- `POST /analyze` nhận `metadata` và `auto_response` từ request
- Truyền xuống RagService
- Response bao gồm `remediation_commands` + `auto_response_log`

### 7. MODIFY: `demo/app.py`

Thêm section mới trong UI:
- **"Remediation Commands"** section: hiển thị từng command với:
  - Description + command trong code block (copy-paste ready)
  - Undo command
  - Badge: "Auto-executable" nếu đủ ngưỡng
  - Status: "Executed" / "Dry-run" / "Pending"
- **Sidebar/toggle**: Auto-response ON/OFF
- **Optional metadata input**: src_ip, dest_ip fields cho demo
- Nếu auto_response triggered → hiển thị banner cảnh báo đỏ "AUTO-RESPONSE TRIGGERED"

### 8. OPTIONAL: `src/rag/lc_prompt.py`

Thay đổi nhỏ trong prompt — thêm instruction cho `mitigation_steps`:
```
- "mitigation_steps" must contain 2-5 actionable steps. Each step should be
  specific and mention concrete actions (e.g., "block source IP at perimeter
  firewall", "check authentication logs for unauthorized access").
  Avoid generic steps like "monitor the network".
```

Thay đổi này nhẹ, không ảnh hưởng RAGAS metrics đáng kể.

---

## Tactic detection tại inference

LLM response không trả về tactic name trực tiếp. Cần xác định tactic để chọn đúng templates. Ba cách (ưu tiên từ trên xuống):

1. **request.metadata.label_tactic** — nếu client gửi (demo/benchmark biết label)
2. **Parse từ LLM response** — threat_description thường mention tactic name ("consistent with Reconnaissance"), regex match
3. **Retrieved tactic context** — KBRetriever đã semantic search tactic, lấy tactic từ top hit

Cách 2+3 kết hợp đủ cho production. Cách 1 cho demo/test.

---

## Ví dụ output

```json
{
  "threat_description": "A single SYN probe to TCP/4848 ...",
  "severity": "High",
  "rationale": "...",
  "mitigation_steps": [
    "Block the source IP at the perimeter firewall to prevent further brute-force attempts.",
    "Review authentication logs on the GlassFish server for unauthorized access.",
    "Restrict access to port 4848 to trusted management networks only."
  ],
  "remediation_commands": [
    {
      "description": "Block source IP tại firewall",
      "command": "iptables -A INPUT -s 192.168.1.100 -j DROP",
      "undo_command": "iptables -D INPUT -s 192.168.1.100 -j DROP",
      "platform": "linux",
      "risk": "low",
      "auto_executable": true,
      "executed": true,
      "execution_status": "dry_run"
    },
    {
      "description": "Block brute-force target port from source",
      "command": "iptables -A INPUT -p tcp --dport 4848 -s 192.168.1.100 -j DROP",
      "undo_command": "iptables -D INPUT -p tcp --dport 4848 -s 192.168.1.100 -j DROP",
      "platform": "linux",
      "risk": "low",
      "auto_executable": true,
      "executed": true,
      "execution_status": "dry_run"
    },
    {
      "description": "Kiểm tra auth log trên target",
      "command": "grep '192.168.1.100' /var/log/auth.log | tail -50",
      "undo_command": null,
      "platform": "linux",
      "risk": "low",
      "auto_executable": false,
      "executed": false,
      "execution_status": null
    }
  ],
  "auto_response_triggered": true,
  "auto_response_log": [
    "[DRY-RUN] Would execute: iptables -A INPUT -s 192.168.1.100 -j DROP",
    "[DRY-RUN] Would execute: iptables -A INPUT -p tcp --dport 4848 -s 192.168.1.100 -j DROP"
  ]
}
```

---

## Verification

1. **Unit**: Chạy `ResponseActionEngine.generate()` với mock metadata → verify commands đúng syntax
2. **Integration**: `POST /analyze` với metadata → verify response có `remediation_commands`
3. **Demo**: Streamlit UI hiển thị commands, toggle auto-response, verify UI
4. **Regression**: Chạy lại benchmark basic 135 samples → verify RAGAS metrics không bị ảnh hưởng (engine là post-processing, không đụng LLM/retrieval)
