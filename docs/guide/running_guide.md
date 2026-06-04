# Running Guide — Fresh Start

Hướng dẫn khởi động hệ thống từ đầu, bao gồm reset hoàn toàn và rebuild toàn bộ pipeline.

## Điều kiện tiên quyết

| Công cụ | Kiểm tra | Ghi chú |
|---|---|---|
| Docker Desktop | `docker info` | Phải đang chạy |
| Python 3.11+ | `python --version` | Virtual env tại `.venv/` |
| Ollama | `ollama list` | Cài tại https://ollama.com |
| LLM model | `ollama list` → thấy `qwen2.5:7b-instruct-q4_K_M` | Pull nếu thiếu |
| Embedding model | Tự download khi chạy `dvc repro` | `BAAI/bge-base-en-v1.5` (~440 MB) |

Pull model nếu chưa có:
```powershell
ollama pull qwen2.5:7b-instruct-q4_K_M
```

---

## Phần 1 — Reset hoàn toàn

> Bỏ qua phần này nếu lần đầu setup (chưa có gì).

### 1.1 Dừng và xóa Docker volumes

```powershell
docker compose down -v
```

Lệnh này xóa các **named volumes**: `qdrant_storage`, `grafana_data`, `prometheus_data`.

### 1.2 Xóa dữ liệu đã xử lý

```powershell
Remove-Item -Recurse -Force data\processed  -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force data\embeddings -ErrorAction SilentlyContinue
```

### 1.3 Xóa MLflow history và DVC cache

```powershell
Remove-Item -Recurse -Force mlruns          -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .dvc\cache      -ErrorAction SilentlyContinue
Remove-Item -Force dvc.lock                 -ErrorAction SilentlyContinue
```

> Không xóa `.dvc/config` — file này chỉ chứa `autostage = true`, không cần reset.

---

## Phần 2 — Khởi động Infrastructure

### 2.1 Khởi động các service Docker

```powershell
docker compose up -d qdrant mlflow
```

Chờ ~30 giây, kiểm tra trạng thái:
```powershell
docker compose ps
```

Tất cả phải ở `running` hoặc `healthy`. Kiểm tra từng service:
```powershell
curl http://localhost:6333        # Qdrant  → {"result":"ok"}
curl http://localhost:5000/health # MLflow  → 200 OK
```

| Service | URL |
|---|---|
| MLflow UI | http://localhost:5000 |
| Qdrant Dashboard | http://localhost:6333/dashboard |

### 2.2 Khởi động Ollama

Mở terminal riêng và giữ chạy:
```powershell
ollama serve
```

> Nếu Ollama đã chạy như background service, bỏ qua. Kiểm tra: `curl http://localhost:11434/api/tags`

---

## Phần 3 — Build Data Pipeline

Pipeline DVC gồm 3 stage chạy tuần tự:

```
raw data → [clean_data] → [chunk_data] → [embed_chunks] → Qdrant
```

### 3.1 Chạy pipeline

```powershell
dvc repro
```

| Stage | Script | Thời gian ước tính |
|---|---|---|
| `clean_data` | `src/data_process/clean_data.py` | 2–5 phút |
| `chunk_data` | `src/data_process/chunk_data.py` | 5–10 phút |
| `embed_chunks` | `src/data_process/embed_chunks.py --recreate` | 20–40 phút |

Pipeline hoàn thành khi xuất hiện file `data/embeddings/completed.txt`.

Kiểm tra data đã load vào Qdrant:
```powershell
curl http://localhost:6333/collections/cyber_chunks
```

Khi `"points_count" > 0` là thành công.

### 3.2 Commit dvc.lock

```powershell
git add dvc.lock
git commit -m "chore: update dvc.lock after repro"
```

`dvc.lock` là snapshot version của data — commit này là bằng chứng data versioning.

---

## Phần 4 — Khởi động API

Mở terminal mới, giữ chạy:

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Kiểm tra:
```powershell
curl http://localhost:8000/health
```

Kết quả mong đợi:
```json
{"status": "ok", "qdrant": "ok", "ollama": "ok"}
```

---

## Phần 5 — Monitoring

```powershell
docker compose up -d prometheus grafana
```

| Dashboard | URL | Tài khoản |
|---|---|---|
| Grafana | http://localhost:3000 | admin / admin |
| Prometheus | http://localhost:9090 | — |

Trong Grafana: vào **Dashboards → RAG** để xem request latency, error rate theo thời gian thực.

---

## Phần 6 — Demo Dashboard

Mở terminal mới:

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run demo/app.py
```

Browser tự mở tại **http://localhost:8501**.

---

## Phần 7 — Chạy Benchmark (tuỳ chọn)

```powershell
.\.venv\Scripts\Activate.ps1
python scripts/run_benchmark.py --samples 20 --version v1 --reset
```

Tham số:
- `--samples N` : số lượng mẫu per template (default 135)
- `--version v1` : tag version, dùng trong tên output file
- `--reset` : xóa checkpoint cũ, chạy lại từ đầu
- `--templates basic,cot` : chỉ chạy các template được chỉ định

Kết quả tự log vào MLflow tại http://localhost:5000.

---

## Tóm tắt lệnh (chạy một lần)

```powershell
# 1. RESET
docker compose down -v
Remove-Item -Recurse -Force data\processed, data\embeddings, mlruns -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .dvc\cache -ErrorAction SilentlyContinue
Remove-Item -Force dvc.lock -ErrorAction SilentlyContinue

# 2. INFRA
docker compose up -d qdrant mlflow
# [Terminal riêng]: ollama serve

# 3. DATA PIPELINE
dvc repro
git add dvc.lock && git commit -m "chore: update dvc.lock after repro"

# 4. API  [Terminal riêng]
.\.venv\Scripts\Activate.ps1
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# 5. MONITORING
docker compose up -d prometheus grafana

# 6. DEMO  [Terminal riêng]
streamlit run demo/app.py
```

---

## Thứ tự terminal

| Terminal | Lệnh | Giữ chạy? |
|---|---|---|
| Terminal 1 | `ollama serve` | Có |
| Terminal 2 | `uvicorn src.api.main:app --port 8000 --reload` | Có |
| Terminal 3 | `streamlit run demo/app.py` | Có |
| Terminal 4 | Lệnh một lần (`dvc repro`, `git commit`, v.v.) | Không |

---

## Troubleshoot

| Triệu chứng | Nguyên nhân | Fix |
|---|---|---|
| `/health` trả `qdrant: unreachable` | Qdrant chưa start hoặc chưa có data | `docker compose up -d qdrant` → chờ healthy |
| `/health` trả `ollama: unreachable` | Ollama không chạy | `ollama serve` |
| `points_count: 0` sau `dvc repro` | Stage `embed_chunks` chưa hoàn thành | Chờ thêm, kiểm tra log terminal |
| MLflow không thấy experiment | Chưa chạy benchmark | Chạy Phần 7 |
| Streamlit lỗi kết nối API | API chưa start | Kiểm tra Terminal 2 |
| `dvc repro` báo "no changes" | `dvc.lock` đã up-to-date | Thêm `--force` nếu muốn chạy lại |
