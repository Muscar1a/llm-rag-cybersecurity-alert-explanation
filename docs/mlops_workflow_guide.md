# MLOps Workflow — Cyber-RAG System

Tài liệu này mô tả luồng hoạt động của hệ thống theo diagram `mlops_workflow_diagram.png`.

---

## Tổng quan

Hệ thống gồm 5 lớp MLOps chạy độc lập nhưng liên kết với nhau:

```
① Data Versioning  →  ② Experiment Tracking  →  ③ Model Evaluation
                                                         ↓
⑤ Monitoring       ←  ④ Model Deployment      ←────────┘
```

---

## ① Data Versioning

**Mục tiêu:** Đảm bảo mọi thay đổi về dữ liệu hoặc tham số đều được ghi lại và tái tạo được.

**Luồng:**

```
Raw Data ──────────────────────────────→ DVC Pipeline ──→ dvc.lock (commit git)
(MITRE / Sigma / ET)                    clean→chunk→      (snapshot hash)
                                         embed
params.yaml ───────────────────────────→ (trigger re-run nếu thay đổi)
(chunk_size, embedding model, ...)
```

**Giải thích từng bước:**

1. **Raw Data** — nguồn tri thức của hệ thống: MITRE ATT&CK techniques, Sigma network rules, Emerging Threats rules, Behavioral rules tự viết.

2. **params.yaml** — chứa toàn bộ hyperparameter (chunk size, overlap, embedding model name, vector dim). DVC theo dõi file này — nếu thay đổi params, DVC tự biết phải re-run stage liên quan.

3. **DVC Pipeline** (`dvc.yaml`) — định nghĩa 3 stages nối tiếp:
   - `clean_data`: parse raw files → parquet
   - `chunk_data`: chia nhỏ text theo `chunk_size` / `chunk_overlap`
   - `embed_chunks`: encode bằng embedding model → upsert vào Qdrant

4. **dvc.lock** — DVC ghi lại MD5 hash của mọi input/output sau mỗi lần `dvc repro`. File này được commit vào git → git history chính là lịch sử version của data.

> Không dùng MinIO/S3. Với data tổng ~1MB, không cần object storage. `dvc repro` từ source là đủ để tái tạo.

---

## ② Experiment Tracking

**Mục tiêu:** Mỗi lần thay đổi (embedding model, params, prompt) đều được log lại để so sánh.

**Luồng:**

```
Qdrant ──→ run_benchmark.py ──→ MLflow ──→ MLflow Registry
                │                               (model versions)
                └──────────────────────→ Benchmark Results (JSON)
```

**Giải thích:**

1. **Qdrant** — vector store chứa toàn bộ knowledge base đã embed. `run_benchmark.py` query Qdrant để lấy context cho mỗi alert.

2. **run_benchmark.py** — chạy RAG trên tập test alerts, tính metrics (Ragas scores, latency), rồi log kết quả lên MLflow.

3. **MLflow** (`localhost:5000`) — lưu mỗi lần chạy benchmark thành 1 "run" với đầy đủ params + metrics + artifact. Artifacts lưu tại `./mlruns/artifacts` (local filesystem).

4. **MLflow Registry** — đăng ký phiên bản model/config tốt nhất để deployment trỏ vào.

---

## ③ Model Evaluation Automation

**Mục tiêu:** Đánh giá chất lượng RAG một cách có hệ thống, không chỉ nhìn output thủ công.

**Luồng:**

```
Test Alerts ──→ Ragas Metrics ──→ Latency p50/p95 ──→ MLflow Run
(ground_truth)  (faithfulness,    (đo thời gian        (auto-log)
                 answer_relevancy) /analyze)
```

**Giải thích:**

1. **Test Alerts** — tập `baselines/ground_truth.json` gồm alerts từ UWF-ZeekData24 kèm expected output (threat_description, severity, mitigation). Đây là "ground truth" để so sánh.

2. **Ragas Metrics** — đánh giá chất lượng câu trả lời của RAG:
   - `faithfulness`: câu trả lời có bám vào context retrieved không
   - `answer_relevancy`: câu trả lời có relevant với câu hỏi không

3. **Latency p50/p95** — đo thời gian phản hồi của `/analyze` endpoint ở percentile 50 và 95.

4. **MLflow Run** — tất cả metrics trên được auto-log vào 1 MLflow run để so sánh với các run trước.

---

## ④ Model Deployment

**Mục tiêu:** Đóng gói hệ thống RAG thành service có thể chạy bằng một lệnh.

**Luồng:**

```
Dockerfile.api ──→ docker-compose ──→ FastAPI ──→ LangChain RAG ──→ Ollama LLM
                   (full stack)       /analyze     (retrieve +        qwen2.5:7b
                                      /health       generate)
                                      /version
                   ↑
                Qdrant (vector store, kết nối từ ②)
```

**Giải thích:**

1. **Dockerfile.api** — build image cho FastAPI service.

2. **docker-compose** — khởi động toàn bộ stack: Qdrant + MLflow + Prometheus + Grafana + rag-api.

3. **FastAPI** — API chính của hệ thống:
   - `POST /analyze` — nhận alert text, trả về threat analysis
   - `GET /health` — kiểm tra Qdrant + Ollama reachable
   - `GET /version` — trả về git sha, model version, embedding model

4. **LangChain RAG** — pipeline retrieve + generate: query Qdrant lấy top-k chunks → đưa vào prompt → Ollama sinh câu trả lời.

5. **Ollama LLM** — chạy `qwen2.5:7b` trên host machine (không trong container), FastAPI gọi qua `host.docker.internal:11434`.

---

## ⑤ Monitoring

**Mục tiêu:** Quan sát hệ thống đang chạy thực tế — phát hiện chậm, lỗi, tắc nghẽn.

**Luồng:**

```
FastAPI ──→ Prometheus Middleware ──→ Prometheus ──→ Grafana
            (/metrics endpoint)       (scrape 15s)   (dashboard)
            
Metrics tracked: latency p50/p95 · error rate · QPS · tokens/s
```

**Giải thích:**

1. **Prometheus Middleware** — tích hợp trong FastAPI, tự động đo mỗi request và expose tại `/metrics`.

2. **Prometheus** (`localhost:9090`) — scrape `/metrics` mỗi 15 giây, lưu time-series data.

3. **Grafana** (`localhost:3000`) — hiển thị dashboard từ Prometheus data:
   - Latency p50/p95 theo endpoint
   - Error rate (% non-200)
   - QPS (queries per second)
   - Tokens per second từ Ollama

---

## Cách các lớp kết nối với nhau

| Từ | Đến | Kết nối như thế nào |
|---|---|---|
| ① DVC Pipeline | ② Qdrant | `embed_chunks.py` upsert vectors vào Qdrant sau khi pipeline chạy |
| ② Qdrant | ④ LangChain RAG | FastAPI query Qdrant real-time mỗi request |
| ③ Benchmark | ② MLflow | `run_benchmark.py` log metrics vào MLflow sau mỗi lần đánh giá |
| ④ FastAPI | ⑤ Prometheus | Middleware expose `/metrics` sau mỗi request |

---

## Chạy hệ thống

```bash
# 1. Khởi động infrastructure
docker compose up -d

# 2. Tái tạo knowledge base (nếu data thay đổi)
dvc repro

# 3. Chạy benchmark
python scripts/run_benchmark.py

# 4. Xem kết quả
# MLflow UI:  http://localhost:5000
# Grafana:    http://localhost:3000
# API docs:   http://localhost:8000/docs
```
