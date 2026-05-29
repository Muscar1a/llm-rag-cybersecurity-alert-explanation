# MLOps Pipeline Proposal

Đề xuất pipeline MLOps cho dự án Cyber-RAG. Bản đề xuất này **mở rộng từ những gì đã có**, không thay thế. Stack hiện tại: DVC + MinIO, Qdrant, FastAPI, LangChain + Ollama, HuggingFace embeddings.

---

## 0. Stack đề xuất (tổng quan)

| Layer | Component | Trạng thái |
|-------|-----------|-----------|
| Data versioning | **DVC** + **MinIO (S3)** | Đã có — cần mở rộng |
| Experiment tracking | **MLflow** (self-host, backend MinIO) | Mới |
| Evaluation automation | **Pytest + Ragas** + Makefile (local) | Mới (ragas đã có trong requirements) |
| Model deployment | **FastAPI + Docker** + MLflow Model Registry (tùy chọn) | Service đã có — cần đóng gói |
| Monitoring | **Prometheus + Grafana** + FastAPI middleware | Mới |

Lý do chọn open-source self-host: dự án đã chạy MinIO + Qdrant trong `docker-compose.yml`. Thêm MLflow + Prometheus + Grafana vào cùng compose stack giữ mọi thứ chạy local, không tốn credit cloud.

---

## 1. Data Versioning

### Hiện trạng
- `dvc.yaml` đã định nghĩa 4 stages: `clean_data`, `chunk_data`, `embed_cve`, `embed_mitre`.
- Remote MinIO `minio-processed` đã cấu hình.
- `dvc.lock` track hash của outputs.

### Gap
- Sigma / ET-rules / behavioral-rules đã có ingest script nhưng **chưa nằm trong dvc.yaml** → không version được.
- Không có `params.yaml` → thay đổi hyperparameter (chunk size, embedding model) không trigger re-run stage tương ứng.
- Không có `dvc metrics` để track chất lượng dataset (số chunk, độ dài trung bình, v.v.).

### Đề xuất

**a. Tách `params.yaml`** ở project root, chứa toàn bộ tham số:
```yaml
embedding:
  model_name: "BAAI/bge-base-en-v1.5"
  dim: 768
  batch_size: 64
chunking:
  tokenizer_model: "BAAI/bge-base-en-v1.5"
  chunk_size: 400
  chunk_overlap: 100
retrieval:
  k: 5
  lambda_mult: 0.5
  score_threshold: 0.60
llm:
  model: "wen2.5:7b-instruct-q4_K_M
  temperature: 0.1
```

**b. Bổ sung stages còn thiếu** vào `dvc.yaml`:
- `ingest_sigma`, `ingest_et_rules`, `ingest_behavioral_rules` → outputs có `cleaned.parquet` tương ứng.
- `embed_sigma`, `embed_et_rules`, `embed_behavioral_rules`.
- Tham chiếu `params:` để DVC tự detect thay đổi.

**c. Thêm `dvc metrics`** cho mỗi stage `chunk_data` (ghi `metrics/chunk_stats.json`: số chunk/source, độ dài tb, …) → `dvc metrics diff` so giữa các commit.

**d. Commit `dvc.lock` + `params.yaml`** vào git; data thật vẫn ở MinIO. Mỗi PR cần kèm `dvc repro` để tái sinh.

---

## 2. Experiment Tracking

### Mục tiêu
Mỗi lần chạy benchmark / re-embed / đổi prompt phải log lại đủ để **reproduce** và **so sánh**.

### Đề xuất: MLflow self-host

**a. Thêm service vào `docker-compose.yml`:**
```yaml
mlflow:
  image: ghcr.io/mlflow/mlflow:v2.16.2
  command: >
    mlflow server
    --backend-store-uri sqlite:///mlruns/mlflow.db
    --artifacts-destination s3://mlflow-artifacts/
    --host 0.0.0.0
  ports: ["5000:5000"]
  environment:
    MLFLOW_S3_ENDPOINT_URL: http://minio:9000
    AWS_ACCESS_KEY_ID: ${MINIO_ROOT_USER}
    AWS_SECRET_ACCESS_KEY: ${MINIO_ROOT_PASSWORD}
```
→ Backend SQLite (đủ cho 1 dev), artifact ở MinIO bucket `mlflow-artifacts`.

**b. Wrapper `src/mlops/tracking.py`** chuẩn hoá việc log:
```python
def log_rag_experiment(run_name, *, params, metrics, artifacts, tags):
    with mlflow.start_run(run_name=run_name):
        mlflow.log_params(params)        # embedding model, llm, k, lambda_mult, prompt_version, dvc_data_rev
        mlflow.log_metrics(metrics)      # ragas scores, latency_p50/p95
        for path in artifacts:           # rag_output_results.json, prompts dump
            mlflow.log_artifact(path)
        mlflow.set_tags(tags)            # git_sha, branch, author
```

**c. Tham số bắt buộc log mỗi run:**
- `embedding.model_name`, `embedding.dim`
- `llm.model`, `llm.temperature`
- `retrieval.k`, `retrieval.lambda_mult`, `retrieval.score_threshold`
- `prompt.template_name`, `prompt.version` (hash của file `lc_prompt.py`)
- `data.dvc_rev` (giá trị `dvc.lock` hash)
- `git.sha`

**d. (Tùy chọn) Model Registry** cho prompt template + retriever config — đăng ký `cyber-rag@v2` để API trỏ thẳng đến phiên bản đang chạy production.

---

## 3. Model Evaluation Automation

### Hiện trạng
`tests/` đã có script chạy RAG trên alerts, output JSON. Chưa có numeric metric, chưa auto-run.

### Đề xuất

**a. Benchmark suite ở `tests/eval/`:**
- `eval_retrieval.py` — Recall@k, MRR, source diversity trên ground-truth set (đã có `ground_truth_generate.md`).
- `eval_generation.py` — Ragas (`faithfulness`, `answer_relevancy`, `context_precision`) trên 20-50 alerts mẫu.
- `eval_latency.py` — đo p50/p95/p99 latency cho `/analyze` & `/chat`.

**b. CLI driver `scripts/run_benchmark.py`** load `params.yaml`, chạy 3 suite trên, ghi `results/benchmark_<ts>.json`, push lên MLflow qua wrapper `log_rag_experiment`.

**c. Makefile target** `make benchmark` chạy local:
- `dvc pull` (nếu data chưa có) → start Qdrant + Ollama (qua `docker compose up -d`) → `python scripts/run_benchmark.py`.
- Mỗi lần chạy ghi 1 MLflow run mới → so sánh các phiên bản qua UI MLflow.
- Đây là "automation" đủ để kể trong báo cáo: 1 lệnh tái chạy toàn bộ benchmark, kết quả version hoá.

> Không setup CI/CD cloud (GitHub Actions). Đồ án tốt nghiệp được chấm trên kiến trúc + demo + báo cáo, không vận hành 24/7. Nếu hội đồng hỏi mở rộng: Makefile target có thể wrap thành workflow YAML trong vài dòng.

---

## 4. Model Deployment

### Hiện trạng
`src/api/main.py` có FastAPI với 4 endpoints. Chưa Dockerize, chưa có version/health-check chi tiết.

### Đề xuất

**a. `Dockerfile.api`** multi-stage:
```dockerfile
FROM python:3.11-slim AS builder
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.11-slim
COPY --from=builder /root/.local /root/.local
COPY src/ /app/src/
ENV PATH=/root/.local/bin:$PATH
EXPOSE 8000
HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**b. Bổ sung vào `docker-compose.yml`:**
```yaml
rag-api:
  build: { context: ., dockerfile: Dockerfile.api }
  depends_on: [qdrant, ollama, mlflow]
  ports: ["8000:8000"]
  environment:
    QDRANT_URL: http://qdrant:6333
    OLLAMA_URL: http://ollama:11434
    MLFLOW_TRACKING_URI: http://mlflow:5000
```
Thêm service `ollama` cùng compose nếu muốn full-stack một lệnh `docker compose up`.

**c. Endpoint mở rộng:**
- `GET /health` → đã có; bổ sung check Qdrant + Ollama reachable.
- `GET /version` → trả `{git_sha, model, embedding, prompt_version, dvc_rev}` (đọc từ env build-time).
- `GET /metrics` → Prometheus exposition (mục 5).

**d. Versioning**: tag image `rag-api:<git_sha>` mỗi build, latest trỏ tới production. Rollback = đổi tag trong compose.

---

## 5. Monitoring

### Đề xuất

**a. FastAPI middleware** `src/api/middleware.py` dùng `prometheus-client`:
- `rag_request_duration_seconds{endpoint, status}` — Histogram (latency).
- `rag_request_total{endpoint, status}` — Counter (request rate, error rate).
- `rag_retrieval_latency_seconds`, `rag_llm_latency_seconds` — phân tách bottleneck.
- `rag_retrieved_docs_count{source}` — phân phối source theo query.
- Expose tại `/metrics`.

**b. Prometheus + Grafana vào docker-compose:**
```yaml
prometheus:
  image: prom/prometheus:latest
  volumes: [./infra/prometheus.yml:/etc/prometheus/prometheus.yml]
  ports: ["9090:9090"]
grafana:
  image: grafana/grafana:latest
  ports: ["3000:3000"]
  depends_on: [prometheus]
```
`infra/prometheus.yml` scrape `rag-api:8000/metrics` mỗi 15s.

**c. Grafana dashboard** (commit JSON ở `infra/grafana/dashboards/rag.json`):
- Latency p50/p95/p99 by endpoint
- Error rate (% non-200) trượt 5 phút
- QPS
- Retrieval vs LLM latency stacked
- Top sources retrieved

**d. Alerting** (tùy chọn, Prometheus AlertManager):
- `error_rate_5m > 5%` → cảnh báo.
- `latency_p95 > 8s` trong 10 phút → cảnh báo.
- `ollama_unreachable` → cảnh báo.

**e. Log structured** (loguru hoặc structlog): mỗi request log JSON `{ts, endpoint, latency_ms, status, alert_text_hash, sources_used}` → dễ ship sang Loki sau này nếu cần.

---

## 6. Roadmap đề xuất (4 sprint, mỗi sprint ~1 tuần)

```
Sprint 1 — Data + Tracking
  - params.yaml + bổ sung DVC stages thiếu       [§1b, §1c]
  - MLflow service + wrapper log_rag_experiment   [§2a, §2b]
  - Migrate manual run hiện tại sang dùng wrapper

Sprint 2 — Evaluation
  - Ground-truth set 30-50 alerts                 [§3a]
  - 3 benchmark scripts + run_benchmark.py        [§3a, §3b]
  - Makefile target + chạy local end-to-end

Sprint 3 — Deployment
  - Dockerfile.api + compose service              [§4a, §4b]
  - /version, /health mở rộng                     [§4c]

Sprint 4 — Monitoring
  - Prometheus middleware + /metrics              [§5a]
  - Prometheus + Grafana service                  [§5b]
  - Dashboard JSON + structured logging           [§5c, §5e]
```

---

## 7. File / thay đổi cần tạo

```
params.yaml                              # mới
dvc.yaml                                 # mở rộng
Dockerfile.api                           # mới
docker-compose.yml                       # thêm mlflow, prometheus, grafana, rag-api
Makefile                                 # mới (targets: repro, benchmark, up, down)
infra/prometheus.yml                     # mới
infra/grafana/dashboards/rag.json        # mới
src/mlops/__init__.py                    # mới
src/mlops/tracking.py                    # mới — MLflow wrapper
src/api/middleware.py                    # mới — Prometheus metrics
src/api/main.py                          # sửa: add middleware, /version, /metrics
scripts/run_benchmark.py                 # mới
tests/eval/eval_retrieval.py             # mới
tests/eval/eval_generation.py            # mới
tests/eval/eval_latency.py               # mới
requirements.txt                         # thêm: mlflow, prometheus-client, structlog
```

---

## 8. Quyết định cần user chốt trước khi triển khai

1. **Experiment tracking host**: MLflow self-host (đề xuất) vs Weights & Biases cloud (free tier có giới hạn).
2. **Ollama trong compose**: chạy chung container (giới hạn GPU passthrough trên Windows) hay giữ Ollama chạy host và API gọi qua `host.docker.internal`.

Sau khi chốt 2 điểm trên, có thể bắt đầu Sprint 1.
