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
Không xóa bind mounts (`./data_minio`, `./mlruns`) — cần xóa thủ công ở bước sau.

### 1.2 Xóa dữ liệu đã xử lý

```powershell
Remove-Item -Recurse -Force data\processed  -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force data\embeddings -ErrorAction SilentlyContinue
```

### 1.3 Xóa MinIO data và MLflow history

```powershell
Remove-Item -Recurse -Force data_minio -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force mlruns      -ErrorAction SilentlyContinue
```

### 1.4 Xóa và init lại DVC

```powershell
Remove-Item -Recurse -Force .dvc      -ErrorAction SilentlyContinue
Remove-Item -Force dvc.lock           -ErrorAction SilentlyContinue

dvc init
```

### 1.5 Cấu hình DVC remote (MinIO)

```powershell
dvc remote add -d minio_remote s3://minio-processed
dvc remote modify minio_remote endpointurl    http://localhost:9000
dvc remote modify minio_remote access_key_id  minioadmin
dvc remote modify minio_remote secret_access_key minioadmin123
dvc remote modify minio_remote use_ssl        false
```

Kiểm tra `.dvc/config` phải có nội dung:
```ini
[core]
    remote = minio_remote
['remote "minio_remote"']
    url = s3://minio-processed
    endpointurl = http://localhost:9000
    access_key_id = minioadmin
    secret_access_key = minioadmin123
    use_ssl = false
```

---

## Phần 2 — Khởi động Infrastructure

### 2.1 Khởi động các service Docker

```powershell
docker compose up -d minio qdrant mlflow
```

Service `minio-setup` tự chạy kèm và tạo bucket `mlflow-artifacts` cho MLflow.

Chờ ~30 giây, kiểm tra trạng thái:
```powershell
docker compose ps
```

Tất cả phải ở `running` hoặc `healthy`. Kiểm tra từng service:
```powershell
curl http://localhost:9000/minio/health/live   # MinIO   → 200 OK
curl http://localhost:6333                     # Qdrant  → {"result":"ok"}
curl http://localhost:5000/health              # MLflow  → 200 OK
```

| Service | URL | Tài khoản |
|---|---|---|
| MinIO Console | http://localhost:9001 | minioadmin / minioadmin123 |
| MLflow UI | http://localhost:5000 | — |
| Qdrant Dashboard | http://localhost:6333/dashboard | — |

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

Theo dõi tiến trình load vào Qdrant (terminal khác):
```powershell
curl http://localhost:6333/collections/cyber_chunks
```

Khi `"points_count" > 0` là dữ liệu đang được load. Pipeline hoàn thành khi xuất hiện file `data/embeddings/completed.txt`.

### 3.2 Push data lên MinIO (DVC remote)

Tạo bucket riêng cho DVC (khác với `mlflow-artifacts`):
```powershell
docker exec minio mc alias set local http://localhost:9000 minioadmin minioadmin123
docker exec minio mc mb --ignore-existing local/minio-processed
```

Push DVC cache:
```powershell
dvc push
```

Xác nhận:
```powershell
docker exec minio mc ls local/minio-processed/
```

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

Nếu `qdrant` hoặc `ollama` báo lỗi, kiểm tra lại Bước 2.1 và 2.2.

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

Tính năng:
- Paste text hoặc upload file alert (`.txt`, `.log`, `.json`)
- Chọn nguồn tri thức: All / CVE / MITRE / Sigma
- Chọn số lượng sources retrieve (top-k)
- Hiển thị severity badge, threat description, rationale, mitigation steps
- Hiển thị các knowledge chunks được retrieve kèm rerank score

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

Kết quả tự log vào MLflow. Xem tại http://localhost:5000 → experiment **rag-cybersec-benchmark** → tab **Models** để xem `RAGPipeline` đã đăng ký.

---

## Tóm tắt lệnh (chạy một lần)

```powershell
# 1. RESET
docker compose down -v
Remove-Item -Recurse -Force data\processed, data\embeddings, data_minio, mlruns -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .dvc -ErrorAction SilentlyContinue
Remove-Item -Force dvc.lock -ErrorAction SilentlyContinue

# 2. DVC INIT
dvc init
dvc remote add -d minio_remote s3://minio-processed
dvc remote modify minio_remote endpointurl    http://localhost:9000
dvc remote modify minio_remote access_key_id  minioadmin
dvc remote modify minio_remote secret_access_key minioadmin123
dvc remote modify minio_remote use_ssl        false

# 3. INFRA
docker compose up -d minio qdrant mlflow
# [Terminal riêng]: ollama serve

# 4. DATA PIPELINE
dvc repro
docker exec minio mc alias set local http://localhost:9000 minioadmin minioadmin123
docker exec minio mc mb --ignore-existing local/minio-processed
dvc push

# 5. API  [Terminal riêng]
.\.venv\Scripts\Activate.ps1
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# 6. MONITORING
docker compose up -d prometheus grafana

# 7. DEMO  [Terminal riêng]
streamlit run demo/app.py
```

---

## Thứ tự terminal

| Terminal | Lệnh | Giữ chạy? |
|---|---|---|
| Terminal 1 | `ollama serve` | Có |
| Terminal 2 | `uvicorn src.api.main:app --port 8000 --reload` | Có |
| Terminal 3 | `streamlit run demo/app.py` | Có |
| Terminal 4 | Chạy lệnh một lần (`dvc repro`, `dvc push`, v.v.) | Không |

---

## Troubleshoot

| Triệu chứng | Nguyên nhân | Fix |
|---|---|---|
| `/health` trả `qdrant: unreachable` | Qdrant chưa start hoặc chưa có data | `docker compose up -d qdrant` → chờ healthy |
| `/health` trả `ollama: unreachable` | Ollama không chạy | `ollama serve` |
| Qdrant `points_count: 0` sau `dvc repro` | Stage `embed_chunks` chưa hoàn thành | Chờ thêm, xem log uvicorn |
| `dvc push` lỗi `NoSuchBucket` | Bucket chưa tạo | Chạy lại lệnh `mc mb` |
| `dvc push` lỗi `AccessDenied` | Sai credentials | Kiểm tra `.dvc/config` |
| MLflow không thấy experiment | Chưa chạy benchmark | Chạy Phần 7 |
| Streamlit lỗi kết nối API | API chưa start | Kiểm tra Terminal 2 |
