# Thiết kế luồng Real-time — Suricata + Zeek → RAG

> Suricata phát hiện (signature-based) → Zeek cung cấp telemetry → RAG giải thích cảnh báo.
> Mục tiêu: thesis-grade, ổn định cho demo trước hội đồng.

---

## 1. Tổng quan kiến trúc

### 1.1 Nguyên tắc phân vai

| Component | Vai trò | Output |
|-----------|---------|--------|
| **Suricata** | Detection — IDS signature-based | Alert: signature, severity, category |
| **Zeek** | Telemetry — flow metadata | Context: conn_state, bytes, packets, duration, TCP history |
| **Alert Builder** | Ghép alert + telemetry | Enriched alert text cho RAG |
| **RAG** | Giải thích cảnh báo bằng KB | Threat analysis grounded vào knowledge base |

**Tại sao tách Suricata + Zeek thay vì chỉ Zeek?**

Thiết kế cũ: Zeek vừa phát hiện (qua heuristic `should_alert` rule-based) vừa cung cấp context — Zeek không phải signature-based IDS nên heuristic thô, bỏ sót nhiều attack pattern.

Thiết kế mới: Suricata chuyên phát hiện (hàng nghìn signature từ ET Open rules), Zeek chuyên telemetry. Mỗi component làm đúng thế mạnh.

### 1.2 Data Flow

```
┌──────────────┐                    ┌─────────────────┐
│   Attacker   │ ── network ──────► │ Network Traffic  │
│  (pcap/live) │    traffic         │ (shared capture) │
└──────────────┘                    └────────┬────────┘
                                        sniff │ cùng traffic
                                    ┌────────┴────────┐
                                    │                 │
                            ┌───────▼───────┐ ┌──────▼────────┐
                            │   Suricata    │ │     Zeek      │
                            │ (detection)   │ │  (telemetry)  │
                            │  eve.json     │ │   conn.log    │
                            └───────┬───────┘ └──────┬────────┘
                                    │                │
                            ┌───────▼───────┐ ┌──────▼────────┐
                            │   Watcher     │ │   Watcher     │
                            │  (Suricata)   │ │   (Zeek)      │
                            │ filter alerts │ │ index flows   │
                            │  → RPUSH      │ │  → SET w/ TTL │
                            └───────┬───────┘ └──────┬────────┘
                                    │                │
                            ┌───────▼────────────────▼────────┐
                            │             Redis               │
                            │  suricata:alerts:raw   (queue)  │
                            │  zeek:flow:{5-tuple}   (cache)  │
                            │  alerts:results        (output) │
                            └────────────────┬────────────────┘
                                             │
                            ┌────────────────▼────────────────┐
                            │           Consumer              │
                            │  1. BLPOP suricata alert        │
                            │  2. Lookup Zeek flow (5-tuple)  │
                            │  3. Build combined alert text   │
                            │  4. POST /analyze               │
                            │  5. RPUSH result                │
                            └────────────────┬────────────────┘
                                             │
                            ┌────────────────▼────────────────┐
                            │        FastAPI RAG API          │
                            │    Qdrant + Ollama (existing)   │
                            └────────────────┬────────────────┘
                                             │
                            ┌────────────────▼────────────────┐
                            │      Streamlit Dashboard        │
                            │     poll Redis results          │
                            └─────────────────────────────────┘
```

**Tại sao Redis queue:** RAG inference mất ~5-6s/alert, Suricata có thể sinh nhiều alert/giây trên mạng bận. Redis buffer giữ lại, consumer xử lý tuần tự FIFO, không mất alert.

---

## 2. Redis — 3 keys

| Key | Kiểu | Producer | Consumer | Nội dung | TTL |
|-----|------|----------|----------|----------|-----|
| `suricata:alerts:raw` | List (RPUSH/BLPOP) | Suricata Watcher | Consumer | Suricata alert event (JSON) | — |
| `zeek:flow:{5-tuple}` | String (SET EX) | Zeek Watcher | Consumer | Zeek conn.log row (JSON) | 300s |
| `alerts:results` | List (RPUSH/LRANGE) | Consumer | Streamlit | Kết quả RAG analysis | LTRIM 200 |

**5-tuple key format:** `zeek:flow:{proto}:{src_ip}:{src_port}:{dst_ip}:{dst_port}`

Ví dụ: `zeek:flow:tcp:192.168.1.10:49832:192.168.1.20:22`

---

## 3. Components chi tiết

### 3.1 Suricata Container

Image: `jasonish/suricata:latest`

Rules: **ET Open** (Emerging Threats community rules) — cài qua `suricata-update`, bao gồm hàng nghìn signature cho scanning, exploit, malware, policy violation, v.v.

**eve.json** — unified JSON log. Mỗi dòng một event. Watcher chỉ quan tâm `event_type == "alert"`:

```json
{
  "timestamp": "2026-06-17T10:00:01.123456+0000",
  "flow_id": 1234567890,
  "event_type": "alert",
  "src_ip": "192.168.1.10",
  "src_port": 49832,
  "dest_ip": "192.168.1.20",
  "dest_port": 22,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2001219,
    "rev": 19,
    "signature": "ET SCAN Potential SSH Scan",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "flow": {
    "pkts_toserver": 1,
    "pkts_toclient": 0,
    "bytes_toserver": 66,
    "bytes_toclient": 0,
    "start": "2026-06-17T10:00:01.123456+0000"
  }
}
```

### 3.2 Zeek Container

Giữ nguyên. Image: `zeekurity/zeek:latest`.

Config `zeek/local.zeek` — bật JSON output:

```zeek
@load base/protocols/conn
@load base/protocols/dns
@load policy/tuning/json-logs
redef LogAscii::use_json = T;
```

Output: `conn.log` — mỗi dòng một JSON flow record gồm `conn_state`, `history`, `duration`, byte/packet counts, service detection.

### 3.3 Suricata Watcher — `src/realtime/watcher_suricata.py`

Tail `eve.json`, lọc chỉ `event_type == "alert"`, push vào Redis queue.

```python
import json, time, os, logging, redis

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [suricata-watcher] %(levelname)s %(message)s",
)
log = logging.getLogger("suricata-watcher")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
LOG_PATH = os.getenv("SURICATA_EVE_LOG", "/var/log/suricata/eve.json")
QUEUE = "suricata:alerts:raw"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


def wait_for_file(path: str, poll: float = 1.0):
    log.info(f"Waiting for {path}...")
    while not os.path.exists(path):
        time.sleep(poll)
    log.info(f"Found {path}, starting tail.")


def tail(path: str, poll: float = 0.3):
    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                try:
                    if f.tell() > os.fstat(f.fileno()).st_size:
                        log.warning("Log rotation detected, seeking to start.")
                        f.seek(0)
                except OSError:
                    pass
                time.sleep(poll)
                continue

            try:
                event = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            r.rpush(QUEUE, json.dumps(event))
            sig = event.get("alert", {}).get("signature", "?")
            log.info(f"Alert: {event.get('dest_ip')}:{event.get('dest_port')} | {sig}")


if __name__ == "__main__":
    wait_for_file(LOG_PATH)
    tail(LOG_PATH)
```

### 3.4 Zeek Watcher (Flow Indexer) — `src/realtime/watcher_zeek.py`

Tail `conn.log`, index mỗi flow vào Redis với TTL 300s để consumer có thể lookup.

```python
import json, time, os, logging, redis

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [zeek-watcher] %(levelname)s %(message)s",
)
log = logging.getLogger("zeek-watcher")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
LOG_PATH = os.getenv("ZEEK_CONN_LOG", "/opt/zeek/logs/current/conn.log")
FLOW_TTL = int(os.getenv("FLOW_TTL", 300))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


def flow_key(row: dict) -> str:
    proto = str(row.get("proto", "tcp")).lower()
    src = row.get("id.orig_h", "")
    sp = row.get("id.orig_p", 0)
    dst = row.get("id.resp_h", "")
    dp = row.get("id.resp_p", 0)
    return f"zeek:flow:{proto}:{src}:{sp}:{dst}:{dp}"


def wait_for_file(path: str, poll: float = 1.0):
    log.info(f"Waiting for {path}...")
    while not os.path.exists(path):
        time.sleep(poll)
    log.info(f"Found {path}, starting tail.")


def tail(path: str, poll: float = 0.3):
    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                try:
                    if f.tell() > os.fstat(f.fileno()).st_size:
                        log.warning("Log rotation detected, seeking to start.")
                        f.seek(0)
                except OSError:
                    pass
                time.sleep(poll)
                continue

            if line.startswith("#"):
                continue

            try:
                row = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            key = flow_key(row)
            r.set(key, json.dumps(row), ex=FLOW_TTL)


if __name__ == "__main__":
    wait_for_file(LOG_PATH)
    tail(LOG_PATH)
```

### 3.5 Consumer — `src/realtime/consumer.py`

BLPOP Suricata alert → lookup Zeek flow → build combined text → POST RAG API → push result.

Suricata `signature` and `severity` are sent via `AlertMetadata` so the RAG service can use them for tactic detection and severity assessment.

```python
import json, os, logging, redis, requests
from src.realtime.alert_builder import build_combined_alert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [consumer] %(levelname)s %(message)s",
)
log = logging.getLogger("consumer")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
API_URL = os.getenv("API_URL", "http://host.docker.internal:8000/analyze")
API_TIMEOUT = int(os.getenv("API_TIMEOUT", 60))

SURICATA_QUEUE = "suricata:alerts:raw"
RESULT_QUEUE = "alerts:results"
MAX_RESULTS = 200

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


def _flow_key(event: dict) -> str:
    proto = str(event.get("proto", "TCP")).lower()
    src = event.get("src_ip", "")
    sp = event.get("src_port", 0)
    dst = event.get("dest_ip", "")
    dp = event.get("dest_port", 0)
    return f"zeek:flow:{proto}:{src}:{sp}:{dst}:{dp}"


def consume():
    log.info("Consumer started, waiting for Suricata alerts...")

    while True:
        _, raw = r.blpop(SURICATA_QUEUE)
        event = json.loads(raw)

        sig = event.get("alert", {}).get("signature", "?")
        dst = f"{event.get('dest_ip', '?')}:{event.get('dest_port', '?')}"
        log.info(f"Processing: {dst} | {sig}")

        key = _flow_key(event)
        flow_raw = r.get(key)
        zeek_flow = json.loads(flow_raw) if flow_raw else None

        if zeek_flow:
            log.info(f"  Zeek flow found: {key}")
        else:
            log.info(f"  No Zeek flow, using Suricata-only info.")

        alert_text = build_combined_alert(event, zeek_flow)

        payload = {
            "alert_text": alert_text,
            "k": 5,
            "metadata": {
                "src_ip":    event.get("src_ip", ""),
                "dest_ip":   event.get("dest_ip", ""),
                "dest_port": event.get("dest_port", 0),
                "proto":     event.get("proto", ""),
                "signature": sig,
                "severity":  event.get("alert", {}).get("severity", 0),
            },
        }

        try:
            resp = requests.post(API_URL, json=payload, timeout=API_TIMEOUT)
            resp.raise_for_status()
            result = resp.json()
            result["_meta"] = payload["metadata"]
            result["_alert_text"] = alert_text

            r.rpush(RESULT_QUEUE, json.dumps(result))
            r.ltrim(RESULT_QUEUE, -MAX_RESULTS, -1)

            severity = result.get("severity", "?")
            desc = result.get("threat_description", "")[:80]
            log.info(f"  → {severity} | {desc}")

        except requests.exceptions.Timeout:
            log.warning(f"API timeout for {dst}, skipping.")
        except Exception as e:
            log.error(f"API error: {e}")


if __name__ == "__main__":
    consume()
```

### 3.6 Alert Builder (Combined) — `src/realtime/alert_builder.py`

Ghép Suricata signature + Zeek telemetry thành alert text cho RAG.

**Thiết kế:** Reuse `zeek_alert_builder.build_alert_text()` cho phần Zeek telemetry, đảm bảo output vẫn chứa `"port {N}"` và `"Connection state {X}:"` để KBRetriever regex match.

```python
from src.data_process.zeek_alert_builder import build_alert_text


def build_combined_alert(suricata_event: dict, zeek_flow: dict | None) -> str:
    """Build combined alert text: Suricata signature + Zeek telemetry.

    Output format ensures KBRetriever regex compatibility:
    - "port {N}" pattern for port_profile exact lookup
    - "Connection state {X}:" pattern for conn_state exact lookup
    """
    parts: list[str] = []

    # ── Suricata alert info ─────────────────────────────────
    alert = suricata_event.get("alert", {})
    sig = alert.get("signature", "Unknown alert")
    sev = alert.get("severity", "?")
    cat = alert.get("category", "")

    header = f"Suricata alert: {sig} (severity {sev}"
    if cat:
        header += f", {cat}"
    header += ")."
    parts.append(header)

    # ── Zeek telemetry (nếu có) ─────────────────────────────
    if zeek_flow:
        mapped = {
            "src_ip_zeek":    zeek_flow.get("id.orig_h", ""),
            "dest_ip_zeek":   zeek_flow.get("id.resp_h", ""),
            "dest_port_zeek": zeek_flow.get("id.resp_p", 0),
            "proto":          zeek_flow.get("proto", ""),
            "conn_state":     zeek_flow.get("conn_state", ""),
            "history":        zeek_flow.get("history", ""),
            "duration":       zeek_flow.get("duration", 0),
            "orig_bytes":     zeek_flow.get("orig_bytes", 0),
            "resp_bytes":     zeek_flow.get("resp_bytes", 0),
            "orig_pkts":      zeek_flow.get("orig_pkts", 0),
            "resp_pkts":      zeek_flow.get("resp_pkts", 0),
            "service":        zeek_flow.get("service", ""),
        }
        zeek_text = build_alert_text(mapped)
        if zeek_text:
            parts.append(zeek_text)
    else:
        # Fallback: basic info từ Suricata event (vẫn có "port {N}" cho retriever)
        proto = suricata_event.get("proto", "TCP").upper()
        dp = suricata_event.get("dest_port", 0)
        parts.append(f"{proto} connection to port {dp}.")

    return " ".join(parts)
```

**Ví dụ output CÓ Zeek telemetry:**

```
Suricata alert: ET SCAN Potential SSH Scan (severity 2, Attempted Information Leak).
TCP connection to port 22. Connection state S0: SYN sent, no SYN-ACK received.
Traffic volume: 1 packets sent / 0 packets received, 0 bytes sent / 0 bytes
received (0 bytes total). TCP sequence: SYN(client).
```

→ Retriever match: `port 22` → port_profile SSH, `Connection state S0` → conn_state S0, semantic search → tactic Reconnaissance.

**Ví dụ output KHÔNG CÓ Zeek telemetry (fallback):**

```
Suricata alert: ET SCAN Potential SSH Scan (severity 2, Attempted Information Leak).
TCP connection to port 22.
```

→ Retriever match: `port 22` → port_profile SSH, semantic search → tactic. Ít context hơn nhưng vẫn hoạt động.

### 3.7 Streamlit Real-time Page — `demo/pages/realtime.py`

Poll Redis `alerts:results` every 3s, hiển thị alert mới nhất lên đầu. Shows summary metrics (total/critical/high/medium+low) and latest 20 alerts with expandable details (threat description, rationale, mitigation steps, retrieved KB sources). Suricata metadata available via `result["_meta"]["signature"]`.

---

## 4. Correlation — Suricata ↔ Zeek

### 4.1 Correlation key

**5-tuple:** `(proto, src_ip, src_port, dst_ip, dst_port)`

Suricata và Zeek cùng sniff một traffic → cùng 5-tuple cho cùng connection:
- Suricata: `proto`, `src_ip`, `src_port`, `dest_ip`, `dest_port`
- Zeek: `proto`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`

Consumer build key từ Suricata fields, lookup Zeek flow bằng key tương ứng.

### 4.2 Timing

**Vấn đề:** Suricata fire alert ngay khi signature match (giữa connection). Zeek ghi conn.log khi flow kết thúc (FIN/RST/timeout). Vậy Suricata alert đến trước, Zeek flow có thể chưa có.

**Xử lý:**
- **Pcap replay (demo):** Không ảnh hưởng — cả Suricata và Zeek xử lý xong toàn bộ pcap trước khi watcher đọc, nên Zeek flow luôn có sẵn.
- **Live traffic:** Consumer lookup Zeek flow, nếu chưa có → dùng fallback (Suricata-only info). RAG vẫn hoạt động, chỉ ít context hơn.

Đây là graceful degradation — không block pipeline, chấp nhận output quality thấp hơn khi thiếu Zeek data.

---

## 5. Docker Compose

```yaml
services:
  # ─── Existing (giữ nguyên) ────────────────────────────────
  qdrant:
    image: qdrant/qdrant:v1-gpu-nvidia
    ports: ["6333:6333", "6334:6334"]
    volumes: [qdrant_storage:/qdrant/storage]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:6333/"]
      interval: 30s
      retries: 3

  mlflow:
    image: ghcr.io/mlflow/mlflow:v2.16.2
    ports: ["5000:5000"]
    volumes: [./mlruns:/mlruns]
    command: >
      mlflow server --backend-store-uri sqlite:///mlruns/mlflow.db
      --artifacts-destination /mlruns/artifacts --host 0.0.0.0

  prometheus:
    image: prom/prometheus:latest
    ports: ["9090:9090"]
    volumes:
      - ./infra/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus

  grafana:
    image: grafana/grafana:latest
    ports: ["3000:3000"]
    depends_on: [prometheus]
    volumes:
      - grafana_data:/var/lib/grafana
      - ./infra/grafana/provisioning:/etc/grafana/provisioning
      - ./infra/grafana/dashboards:/var/lib/grafana/dashboards

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      retries: 3

  # ─── IDS: Suricata + Zeek ─────────────────────────────────
  suricata:
    image: jasonish/suricata:latest
    network_mode: host
    volumes:
      - suricata_logs:/var/log/suricata
      - ./suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
    # Live:  suricata -i eth0
    # Demo:  suricata -r /data/attack.pcap -l /var/log/suricata
    command: suricata -i eth0

  zeek:
    image: zeekurity/zeek:latest
    network_mode: host
    volumes:
      - zeek_logs:/opt/zeek/logs
      - ./zeek/local.zeek:/opt/zeek/share/zeek/site/local.zeek:ro
    # Live:  zeek -i eth0 local.zeek
    # Demo:  zeek -r /data/attack.pcap local.zeek
    command: zeek -i eth0 local.zeek

  # ─── Watchers ─────────────────────────────────────────────
  watcher-suricata:
    build:
      context: .
      dockerfile: Dockerfile.watcher-suricata
    restart: unless-stopped
    volumes:
      - suricata_logs:/var/log/suricata:ro
    environment:
      REDIS_HOST: redis
      SURICATA_EVE_LOG: /var/log/suricata/eve.json
    depends_on:
      redis: { condition: service_healthy }

  watcher-zeek:
    build:
      context: .
      dockerfile: Dockerfile.watcher-zeek
    restart: unless-stopped
    volumes:
      - zeek_logs:/opt/zeek/logs:ro
    environment:
      REDIS_HOST: redis
      ZEEK_CONN_LOG: /opt/zeek/logs/current/conn.log
      FLOW_TTL: "300"
    depends_on:
      redis: { condition: service_healthy }

  # ─── Consumer ─────────────────────────────────────────────
  consumer:
    build:
      context: .
      dockerfile: Dockerfile.consumer
    restart: unless-stopped
    environment:
      REDIS_HOST: redis
      API_URL: http://host.docker.internal:8000/analyze
      API_TIMEOUT: "60"
    depends_on:
      redis: { condition: service_healthy }

volumes:
  qdrant_storage:
  grafana_data:
  prometheus_data:
  suricata_logs:
  zeek_logs:
```

### Dockerfiles

**`Dockerfile.watcher-suricata`:**

```dockerfile
FROM python:3.11-slim
RUN pip install redis --no-cache-dir
COPY src/realtime/watcher_suricata.py /app/watcher_suricata.py
WORKDIR /app
CMD ["python", "watcher_suricata.py"]
```

**`Dockerfile.watcher-zeek`:**

```dockerfile
FROM python:3.11-slim
RUN pip install redis --no-cache-dir
COPY src/realtime/watcher_zeek.py /app/watcher_zeek.py
WORKDIR /app
CMD ["python", "watcher_zeek.py"]
```

**`Dockerfile.consumer`:**

```dockerfile
FROM python:3.11-slim
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt --no-cache-dir
COPY src/ /app/src/
ENV PYTHONPATH=/app
WORKDIR /app
CMD ["python", "src/realtime/consumer.py"]
```

---

## 6. Sequence Diagram — xử lý 1 alert

```
Suricata     Zeek     Watcher-S   Watcher-Z    Redis        Consumer      API/RAG     Streamlit
  │            │          │           │           │              │             │            │
  │─eve.json─►│          │           │           │              │             │            │
  │ (alert)   │─conn.log►│           │           │              │             │            │
  │           │          │           │           │              │             │            │
  │           │  readline│  readline │           │              │             │            │
  │           │          │           │           │              │             │            │
  │           │          │──RPUSH───►│           │              │             │            │
  │           │          │  suricata:│           │              │             │            │
  │           │          │  alerts:  │           │              │             │            │
  │           │          │  raw      │──SET EX──►│              │             │            │
  │           │          │           │  zeek:flow│              │             │            │
  │           │          │           │  :{5tuple}│              │             │            │
  │           │          │           │           │◄──BLPOP──    │             │            │
  │           │          │           │           │              │             │            │
  │           │          │           │           │◄──GET─────   │             │            │
  │           │          │           │           │  zeek:flow   │             │            │
  │           │          │           │           │              │             │            │
  │           │          │           │           │         build_combined_alert()          │
  │           │          │           │           │              │             │            │
  │           │          │           │           │              │─POST /analyze►           │
  │           │          │           │           │              │          retrieve KB     │
  │           │          │           │           │              │          LLM generate    │
  │           │          │           │           │              │◄──JSON result─│          │
  │           │          │           │           │              │             │            │
  │           │          │           │           │◄──RPUSH──    │             │            │
  │           │          │           │           │ alerts:results             │            │
  │           │          │           │           │              │             │◄──LRANGE── │
  │           │          │           │           │              │             │     render │
```

---

## 7. Tương thích với RAG Pipeline hiện tại

### 7.1 Retriever — không cần sửa

`KBRetriever` (`lc_vectorstore.py`) dùng regex extract từ alert text:
- `\bport (\d+)\b` → port_profile exact lookup
- `\bConnection state (\w+)[:\s]` → conn_state exact lookup
- Semantic search → traffic_pattern, tactic

Alert builder output giữ nguyên format (reuse `build_alert_text()`), nên cả hai regex vẫn match.

### 7.2 Prompt — đã adapt

System prompt (`lc_prompt.py`) đã cập nhật: "A Suricata IDS has fired an alert, enriched with Zeek conn.log telemetry when available."

Grounding rules: thêm bullet "Suricata signature and severity are additional signals." Severity criteria: thêm "Suricata severity 1 reinforces High when both conditions are met" (High) và "Suricata severity 1-2 alone stays Medium" (Medium).

### 7.3 KB — giữ nguyên

Cả 4 nhóm KB đều vẫn relevant:
- `port_profile`: match qua dest_port trong Zeek telemetry
- `conn_state`: match qua conn_state trong Zeek telemetry
- `traffic_pattern`: semantic match qua flow characteristics
- `tactic_profile`: semantic match qua Suricata signature + flow pattern

---

## 8. Error Handling

| Tình huống | Xử lý |
|------------|--------|
| Suricata chưa tạo eve.json | Watcher-S chờ (poll 1s) |
| Zeek chưa tạo conn.log | Watcher-Z chờ (poll 1s) |
| Log rotation | Watcher detect `tell() > file_size`, seek lại đầu |
| Redis down | Watchers/Consumer crash → Docker restart tự khởi lại |
| Zeek flow chưa có khi consumer lookup | Graceful degradation: dùng Suricata-only info |
| API timeout (RAG chậm >60s) | Consumer log warning, skip alert, tiếp tục |
| Queue backlog | Redis buffer giữ lại, consumer xử lý tuần tự FIFO |
| Streamlit disconnect | Không ảnh hưởng — results vẫn trong Redis |

---

## 9. Kịch bản demo

### Pcap replay (recommend — deterministic, lặp lại được)

```bash
# Suricata xử lý pcap
docker-compose exec suricata suricata -r /data/attack.pcap -l /var/log/suricata

# Zeek xử lý cùng pcap
docker-compose exec zeek zeek -r /data/attack.pcap local.zeek

# Cả hai sinh log → watchers đọc → consumer correlate → RAG giải thích → dashboard hiển thị
```

Hoặc set command trong docker-compose cho replay mode.

### Flow demo trước hội đồng

```
Bước 1: Mở Streamlit dashboard → trang Real-time → trống, 0 alerts
Bước 2: Replay pcap chứa attack traffic
Bước 3: Suricata fire alerts → Zeek ghi telemetry
         → Watchers đọc → Redis → Consumer correlate
         → RAG giải thích → Dashboard cập nhật real-time
Bước 4: Alert xuất hiện với:
         - Suricata signature (cái gì bị phát hiện)
         - RAG explanation grounded vào KB (giải thích chi tiết)
         - Mitigation steps (hành động khuyến nghị)
```

---

## 10. Monitoring & Debug

```bash
# Queue depth — bao nhiêu alert chưa xử lý
docker exec redis redis-cli LLEN suricata:alerts:raw

# Bao nhiêu Zeek flows đang cached
docker exec redis redis-cli DBSIZE

# Bao nhiêu kết quả RAG
docker exec redis redis-cli LLEN alerts:results

# Xem kết quả gần nhất
docker exec redis redis-cli LINDEX alerts:results -1 | python -m json.tool

# Logs
docker logs -f watcher-suricata
docker logs -f watcher-zeek
docker logs -f consumer
```

---

## 11. Cấu trúc file

```
project/
├── suricata/
│   └── suricata.yaml                  # Suricata config
├── zeek/
│   └── local.zeek                     # Zeek config: JSON output
├── src/
│   └── realtime/
│       ├── __init__.py
│       ├── watcher_suricata.py        # Tail eve.json → Redis queue
│       ├── watcher_zeek.py            # Tail conn.log → Redis flow cache
│       ├── consumer.py                # Correlate → alert_builder → RAG
│       └── alert_builder.py           # Suricata + Zeek → combined text
├── demo/
│   └── pages/
│       └── realtime.py                # Streamlit real-time page
├── Dockerfile.watcher-suricata
├── Dockerfile.watcher-zeek
├── Dockerfile.consumer
└── docker-compose.yml
```

---

## 12. Checklist triển khai

- [x] Tạo `suricata/suricata.yaml` (config + ET Open rules)
- [x] Viết `src/realtime/watcher_suricata.py`
- [x] Viết `src/realtime/watcher_zeek.py`
- [x] Viết `src/realtime/alert_builder.py`
- [x] Cập nhật `src/realtime/consumer.py`
- [x] Tạo `Dockerfile.watcher-suricata`
- [x] Tạo `Dockerfile.watcher-zeek`
- [x] Cập nhật `Dockerfile.consumer`
- [x] Cập nhật `docker-compose.yml` (+suricata, watcher-suricata, watcher-zeek)
- [x] Adapt prompt (`lc_prompt.py`) cho Suricata + Zeek input
- [x] Xóa dead code: `Dockerfile.watcher`, `suppressor.py`, `parse_et_rules.py`
- [x] Fix `realtime.py` queue name (`alerts:results`)
- [x] Fix `AlertMetadata` thêm `signature`, `severity`
- [x] Bỏ unused `source` param khỏi chain/service/API
- [ ] Chuẩn bị pcap demo (attack traffic triggers ET Open rules)
- [ ] Test end-to-end: replay pcap → alert xuất hiện trên dashboard
- [ ] Dry run demo flow

---

**Document Version**: 3.1
**Last Updated**: 2026-06-18
**Architecture**: Suricata (detection) + Zeek (telemetry) → Redis → RAG
