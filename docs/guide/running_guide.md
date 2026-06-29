# Hướng dẫn chạy hệ thống — End-to-End

> **Mục tiêu:** Chạy đầy đủ pipeline từ Suricata + Zeek → RAG phân tích → Remediation execution.
> Tài liệu này phản ánh trạng thái code thực tế, không phải thiết kế lý thuyết.

---

## Mục lục

- [A. Setup một lần](#a-setup-một-lần)
- [B. Khởi động mỗi phiên](#b-khởi-động-mỗi-phiên)
- [C. Demo Mode 1 — Docker Suricata + Zeek (pcap replay)](#c-demo-mode-1--docker-suricata--zeek-pcap-replay)
- [D. Demo Mode 2 — Redis injection (không cần Docker IDS)](#d-demo-mode-2--redis-injection-không-cần-docker-ids)
- [E. Demo Mode 3 — Offline Batch Upload](#e-demo-mode-3--offline-batch-upload)
- [F. Remediation Execution](#f-remediation-execution)
- [G. Reset và chạy lại](#g-reset-và-chạy-lại)
- [H. Troubleshoot](#h-troubleshoot)

---

## A. Setup một lần

> Chỉ cần làm lần đầu hoặc sau khi `docker compose down -v`.

### A.1 Điều kiện tiên quyết

| Công cụ | Kiểm tra | Ghi chú |
|---|---|---|
| Docker Desktop | `docker info` | Phải đang chạy |
| Python 3.11+ venv | `python --version` | Activate: `.\.venv\Scripts\Activate.ps1` |
| scapy | `python -c "import scapy"` | `pip install scapy` |
| vLLM *(tuỳ chọn)* | `curl http://localhost:8001/v1/models` | Cần GPU + WSL2; có thể dùng DeepSeek thay thế |

### A.2 Khởi động infrastructure

```powershell
docker compose up -d qdrant redis mlflow
```

Chờ ~30 giây, kiểm tra:
```powershell
curl http://localhost:6333        # Qdrant  → {"result":"ok"}
curl http://localhost:5000/health # MLflow  → 200 OK
```

### A.3 Build data pipeline và ingest KB

```powershell
# DVC pipeline: clean data + ingest KB v2 vào Qdrant
dvc repro
```

Kiểm tra KB đã vào Qdrant:
```powershell
curl http://localhost:6333/collections/cyber_chunks
# "points_count" > 0 là thành công
```

### A.4 Sinh demo pcap từ CSV

```powershell
pip install scapy
python tests/generate_pcap.py
# Output: data/demo.pcap (~6 KB, ~97 packets từ CSV uwf-zeekdata24)
```

### A.5 Build Docker images cho realtime pipeline

```powershell
# Build watcher và consumer images (cần rebuild khi đổi code src/realtime/)
docker compose build watcher-suricata watcher-zeek consumer
```

---

## B. Khởi động mỗi phiên

Mỗi lần ngồi demo, chạy theo thứ tự sau (4 terminal riêng biệt):

### Terminal 1 — vLLM (nếu có GPU)

```powershell
vllm serve Qwen/Qwen2.5-14B-Instruct --port 8001 --max-model-len 8192 --quantization bitsandbytes --load-format bitsandbytes
```

> Không có GPU: bỏ qua bước này, chọn provider `DeepSeek` hoặc `Gemini` trong Streamlit sidebar.

### Terminal 2 — FastAPI

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Kiểm tra:
```powershell
curl http://localhost:8000/health
# {"status":"ok","qdrant":"ok","vllm":"ok"}
# vllm có thể "unreachable" nếu không dùng vLLM — vẫn OK nếu dùng provider khác
```

### Terminal 3 — Streamlit

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run demo/app.py
```

Mở **http://localhost:8501**.
- Trang chính (`app.py`): **Realtime Monitor** — hiện kết quả từ Redis `alerts:results`, auto-refresh 3 giây.
- Trang Analyze (`pages/1_Analyze.py`): phân tích thủ công 1 alert hoặc batch upload.

---

## C. Demo Mode 1 — Docker Suricata + Zeek (pcap replay)

Pipeline đầy đủ qua Docker containers:

```
data/demo.pcap
    ├─► [suricata container]  → eve.json  → watcher-suricata → Redis: suricata:alerts:raw
    └─► [zeek container]      → conn.log  → watcher-zeek     → Redis: zeek:flow:{5-tuple}
                                                                          │
                                                                    [consumer]
                                                              BLPOP + Zeek flow lookup
                                                              → build_combined_alert()
                                                              → POST /analyze (port 8000)
                                                              → RPUSH alerts:results
                                                                          │
                                                                 Streamlit dashboard
```

> **Yêu cầu:** Đã làm A.4 (có `data/demo.pcap`) và A.5 (images đã build).

### C.1 Dọn Redis (nếu chạy lại)

```powershell
docker exec redis redis-cli DEL suricata:alerts:raw alerts:results
```

### C.2 Khởi động watchers + consumer với TAIL_FROM_START

```powershell
# Dùng docker-compose.demo.yml để set TAIL_FROM_START=1
# (watchers đọc từ đầu file thay vì từ cuối — cần thiết cho pcap replay)
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d watcher-suricata watcher-zeek consumer
```

Kiểm tra đang chờ:
```powershell
docker logs watcher-zeek     # → "Waiting for /opt/zeek/logs/current/conn.log..."
docker logs watcher-suricata # → "Waiting for /var/log/suricata/eve.json..."
```

### C.3 Replay Zeek trước (tạo flow cache trong Redis)

```powershell
docker compose -f docker-compose.yml -f docker-compose.demo.yml run --rm zeek
```

Chờ container kết thúc (~5–10 giây). Kiểm tra flow cache:
```powershell
docker exec redis redis-cli KEYS "zeek:flow:*"
# Phải thấy nhiều keys — nếu trống, xem mục H.Troubleshoot
```

### C.4 Replay Suricata

```powershell
docker compose -f docker-compose.yml -f docker-compose.demo.yml run --rm suricata
```

Suricata đọc `data/demo.pcap`, match với `suricata/suricata.rules` (custom rules không cần `suricata-update`), ghi `eve.json`.

### C.5 Theo dõi kết quả

```powershell
# Xem consumer đang xử lý
docker logs -f consumer

# Đếm kết quả đã phân tích
docker exec redis redis-cli LLEN alerts:results

# Xem kết quả mới nhất (JSON)
docker exec redis redis-cli LRANGE alerts:results -1 -1
```

Streamlit dashboard tại **http://localhost:8501** tự cập nhật mỗi 3 giây.

### C.6 Chạy lại demo (reset nhanh)

```powershell
docker exec redis redis-cli DEL suricata:alerts:raw alerts:results
docker compose -f docker-compose.yml -f docker-compose.demo.yml restart watcher-suricata watcher-zeek
docker compose -f docker-compose.yml -f docker-compose.demo.yml run --rm zeek
docker compose -f docker-compose.yml -f docker-compose.demo.yml run --rm suricata
```

---

## D. Demo Mode 2 — Redis injection (không cần Docker IDS)

Bypass Suricata/Zeek hoàn toàn — inject thẳng vào Redis từ `tests/suricata_alerts.json` (173 alerts đã build sẵn từ CSV).

> Phù hợp khi muốn demo luồng consumer → API → dashboard mà không cần pcap hay Docker IDS containers.

### D.1 Khởi động consumer trực tiếp trên host

```powershell
.\.venv\Scripts\Activate.ps1
$env:REDIS_HOST = "localhost"
$env:API_URL    = "http://localhost:8000/analyze"
python -m src.realtime.consumer
# → "Consumer started, waiting for Suricata alerts..."
```

### D.2 Inject alerts vào Redis

```powershell
# Tất cả 173 alerts, delay 1 giây/alert (realtime demo)
python tests/simulate_pipeline.py --delay 1.0

# Chỉ 1 tactic cụ thể
python tests/simulate_pipeline.py --tactic Initial_Access --delay 0.5

# 10 alerts đầu để test nhanh
python tests/simulate_pipeline.py --limit 10 --delay 0.3
```

Script sẽ hiện:
```
[  1/173] Benign            | 143.88.5.1:53     | ET DNS Standard Query...
[  2/173] Reconnaissance    | 143.88.10.12:22   | ET SCAN SSH Brute Force...
```

Streamlit dashboard nhận kết quả khi consumer xử lý xong từng alert.

### D.3 Debug

```powershell
docker exec redis redis-cli LLEN suricata:alerts:raw   # còn bao nhiêu chờ
docker exec redis redis-cli LLEN alerts:results        # đã xử lý xong bao nhiêu
docker exec redis redis-cli DEL suricata:alerts:raw alerts:results  # reset
```

---

## E. Demo Mode 3 — Offline Batch Upload

Phân tích trực tiếp qua Streamlit, không cần Redis hay consumer.

> Chỉ cần: API đang chạy + KB đã ingest.

1. Mở **http://localhost:8501** → trang **Analyze** (sidebar trái)
2. Sidebar → chọn **Provider** (DeepSeek nếu không có vLLM)
3. Sidebar → bật **Enable auto-response**
4. Tab **Batch Upload** → upload `tests/alerts.json` (173 alerts, 6 tactic)
5. Bấm **Analyze All**

Lọc 1 tactic để demo nhanh:
```powershell
python -c "
import json
d = json.load(open('tests/alerts.json', encoding='utf-8'))
out = [r for r in d if r['_ground_truth']['label_tactic'] == 'Initial_Access']
json.dump(out, open('tests/alerts_initial_access.json', 'w'))
print(len(out), 'alerts')
"
```

---

## F. Remediation Execution

### F.1 Cơ chế

Mỗi `/analyze` response trả về `remediation_commands[]` — lệnh `iptables`/`ss`/`tcpdump` đã điền IP/port thật.

`auto_response_triggered = true` khi **cả hai** đúng:
1. `auto_response = true` (trong request hoặc `AUTO_RESPONSE_ENABLED=true` trong `.env`)
2. Severity LLM chấm ≥ `AUTO_RESPONSE_SEVERITY_THRESHOLD`

### F.2 Cấu hình `.env`

```env
AUTO_RESPONSE_ENABLED=false
AUTO_RESPONSE_MODE=dry_run
AUTO_RESPONSE_SEVERITY_THRESHOLD=High
```

> Restart uvicorn sau khi sửa `.env`.

**Để chắc chắn trigger trong demo:**
```env
AUTO_RESPONSE_SEVERITY_THRESHOLD=Medium
AUTO_RESPONSE_MODE=dry_run
```

`dry_run` chỉ log lệnh vào `auto_response_log[]`, không thực thi — an toàn trên Windows.

### F.3 Test nhanh qua curl

```powershell
curl -X POST http://localhost:8000/analyze `
  -H "Content-Type: application/json" `
  -d '{
    "alert_text": "Suricata alert: ET EXPLOIT Microsoft SMB MS17-010 EternalBlue Attempt (severity 1, Attempted User Privilege Gain). TCP connection to port 445. Connection state SF: normal established TCP.",
    "metadata": {"src_ip": "203.0.113.10", "dest_ip": "10.0.0.5", "dest_port": 445, "proto": "tcp"},
    "auto_response": true,
    "provider": "deepseek"
  }'
```

Kiểm tra trong response:
- `remediation_commands[].command` — lệnh đã điền `203.0.113.10`
- `auto_response_triggered` — `true` nếu severity đủ ngưỡng
- `auto_response_log` — `["DRY RUN: iptables -A INPUT -s 203.0.113.10 -j DROP"]`

### F.4 Live mode (Linux only)

```env
AUTO_RESPONSE_MODE=live
```

Chạy lệnh thật qua `subprocess.run(shell=True)`. **Yêu cầu:** API chạy trên Linux (WSL2/VM) với quyền root. Không hoạt động khi API chạy trên Windows host.

---

## G. Reset và chạy lại

### Reset nhẹ (giữ data, chỉ xóa kết quả demo)

```powershell
docker exec redis redis-cli DEL suricata:alerts:raw alerts:results
docker exec redis redis-cli DEL $(docker exec redis redis-cli KEYS "zeek:flow:*")
```

### Reset hoàn toàn (xóa cả Qdrant data + volumes)

```powershell
docker compose down -v
Remove-Item -Recurse -Force data\processed, data\embeddings -ErrorAction SilentlyContinue
# Sau đó làm lại từ A.2
```

---

## H. Troubleshoot

| Triệu chứng | Nguyên nhân | Fix |
|---|---|---|
| `LLEN alerts:results = 0` sau Suricata replay | Watcher dùng `seek(0,2)`, bỏ lỡ file đã ghi | Chạy bằng `docker-compose.demo.yml` để set `TAIL_FROM_START=1` |
| `KEYS zeek:flow:* = (empty)` sau Zeek replay | Zeek không ghi vào `/opt/zeek/logs/current/` | Kiểm tra `docker logs` của zeek run — phải thấy "conn.log" trong output |
| Zeek image pull lỗi | `zeekurity/zeek` không còn tồn tại | Dùng `zeek/zeek:latest` (đã sửa trong `docker-compose.yml`) |
| `/health` → `qdrant: unreachable` | Qdrant chưa start | `docker compose up -d qdrant` |
| `/health` → `vllm: unreachable` | vLLM không chạy | Bỏ qua nếu dùng DeepSeek/Gemini |
| Consumer không xử lý alert | API chưa start hoặc `API_URL` sai | Kiểm tra `docker logs consumer` → thấy connection error? |
| Suricata không fire alert | Rules không match pcap | `docker compose ... run --rm suricata` → xem output có "Alert:" không |
| `auto_response_triggered = false` | Severity LLM thấp hơn threshold | Hạ `AUTO_RESPONSE_SEVERITY_THRESHOLD=Medium` trong `.env` |
| Streamlit trắng / không update | Redis trống hoặc API chưa chạy | `docker exec redis redis-cli LLEN alerts:results` |
| `dvc repro` báo "no changes" | `dvc.lock` đã up-to-date | `dvc repro --force` |

---

## Tham khảo nhanh — Tất cả lệnh theo nhóm

### Kiểm tra trạng thái

```powershell
docker compose ps                                      # services đang chạy
curl http://localhost:8000/health                      # API health
docker exec redis redis-cli LLEN alerts:results        # kết quả trong Redis
docker exec redis redis-cli KEYS "zeek:flow:*"         # flow cache
docker logs consumer --tail 20                         # log consumer
```

### Lệnh demo Mode 1 (Docker IDS)

```powershell
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d watcher-suricata watcher-zeek consumer
docker compose -f docker-compose.yml -f docker-compose.demo.yml run --rm zeek
docker compose -f docker-compose.yml -f docker-compose.demo.yml run --rm suricata
```

### Lệnh demo Mode 2 (inject)

```powershell
$env:REDIS_HOST="localhost"; $env:API_URL="http://localhost:8000/analyze"; python -m src.realtime.consumer
python tests/simulate_pipeline.py --delay 1.0
```

### Lệnh demo Mode 3 (batch)

```
Streamlit → Analyze → Batch Upload → tests/alerts.json
```
