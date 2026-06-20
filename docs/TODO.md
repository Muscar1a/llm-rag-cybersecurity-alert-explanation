## Realtime Pipeline — Suricata + Zeek → RAG

### 1. Code pipeline mới (`src/realtime/`)
- [x] Tạo `watcher_suricata.py` — tail eve.json, filter `event_type=="alert"`, RPUSH to Redis
- [x] Tạo `watcher_zeek.py` — tail conn.log, SET flow vào Redis với TTL 300s
- [x] Tạo `alert_builder.py` — ghép Suricata signature + Zeek telemetry (reuse `build_alert_text()`)
- [x] Cập nhật `consumer.py` — BLPOP suricata alert → lookup Zeek flow → build combined text → POST /analyze
- [x] Xóa `watcher.py` cũ (replaced bởi watcher_suricata + watcher_zeek)

### 2. Prompt adaptation (`src/rag/lc_prompt.py`)
- [x] System prompt: đổi "alert built from a single Zeek conn.log flow" → mô tả chung cho Suricata + Zeek input
- [x] Grounding rules: thêm Suricata severity/signature như signal bổ sung
- [x] Severity criteria: cân nhắc Suricata severity trong rubric

### 3. Docker
- [x] Tạo `Dockerfile.watcher-suricata`
- [x] Tạo `Dockerfile.watcher-zeek`
- [x] Tạo `suricata/suricata.yaml` (config + ET Open rules)
- [x] Cập nhật `docker-compose.yml` (+suricata, watcher-suricata, watcher-zeek)

### 4. Demo & Testing
- [ ] Chuẩn bị pcap demo (attack traffic triggers ET Open rules)
- [ ] Test end-to-end: replay pcap → Suricata alerts + Zeek flows → consumer correlate → RAG → dashboard
- [ ] Dry run demo flow trước hội đồng
