# Session Summary — Các thay đổi đã thực hiện

## 1. Loại bỏ MinIO khỏi toàn bộ hệ thống

**Lý do:** MinIO là S3-compatible object storage dùng để lưu DVC remote và MLflow artifacts. Với dự án thesis, lượng data ~65MB, không cần object storage phức tạp.

**Các file đã thay đổi:**

- **`docker-compose.yml`**: Xóa service `minio` và `minio-setup`. Cập nhật service `mlflow`: bỏ `depends_on: minio-setup`, bỏ boto3, đổi `--artifacts-destination` từ `s3://mlflow-artifacts/` sang `/mlruns/artifacts`.
- **`.dvc/config`**: Xóa remote MinIO, chỉ giữ `autostage = true`.
- **`.env`** / **`.env.example`**: Xóa `MINIO_*` và `NVD_API_KEY`.

**Kết quả:** Data versioning vẫn hoạt động qua `dvc.lock` + git. MLflow lưu artifacts local.

---

## 2. Cập nhật MLOps diagram

**File:** `scripts/draw_mlops_diagram.py`

- Row 1: Xóa box MinIO, reposition 4 box còn lại.
- Sublabel Raw Data: `CVE / MITRE / Sigma` → `MITRE / Sigma / ET`.
- Legend: `Data Versioning (DVC + MinIO)` → `Data Versioning (DVC + git)`.

---

## 3. Tạo tài liệu MLOps workflow

**File mới:** `docs/mlops_workflow_guide.md`

Mô tả 5 tầng MLOps của hệ thống, flow diagram từng tầng, bảng liên kết giữa các tầng, và quick-start commands.

---

## 4. Fix label format cho UWF-ZeekData24

**Lý do:** `ground_truth.json` đã được cập nhật sang format UWF-ZeekData24 (dùng `label_tactic` / `label_technique` thay vì `label` của CIC-IDS2018 cũ).

**Các file đã thay đổi:**

- **`scripts/run_benchmark.py`**:
  - `sample_balanced()`: `r["label"]` → `r["label_tactic"]`
  - Print line trong eval phase: `s['label']` → `s['label_tactic']` (bug fix)
  - `samples_data` dict: thêm `label_tactic` và `label_technique`

- **`tests/eval/eval_generation.py`**:
  - `get_severity_verdict(entry["severity"], entry["label"])` → `entry["label_tactic"]`

- **`tests/eval/utils.py`**:
  - `SEVERITY_MIN`: thay CIC-IDS2018 labels bằng UWF MITRE tactic labels (`Credential_Access`, `Exfiltration`, `Initial_Access`, `Privilege_Escalation`, `Defense_Evasion`, `Persistence`, `Reconnaissance`).
  - `get_context_diversity()`: bỏ `has_cve`, thêm `has_et`.

---

## 5. Cập nhật running_guide.md

**File:** `docs/guide/running_guide.md`

- Xóa toàn bộ bước liên quan MinIO (step 1.5 DVC remote config, step 3.2 dvc push).
- Section 2.1: `docker compose up -d qdrant mlflow` (không còn minio).
- Thêm step 3.2: `git add dvc.lock && git commit -m "chore: update dvc.lock after repro"`.
- Cập nhật troubleshoot table.

---

## 6. Chuyển Evaluation Judge từ Groq sang DeepSeek

**Lý do:** Groq free tier có rate limit nghiêm ngặt (30 req/min, 6000 req/day), gây chậm và cần sleep(3) giữa các sample. DeepSeek API trả phí không có giới hạn này.

**Model đang dùng:** `deepseek-v4-flash` (xác nhận từ API — account chỉ có `deepseek-v4-flash` và `deepseek-v4-pro`).

**Các file đã thay đổi:**

- **`requirements.txt`**: Thêm `langchain-openai`.
- **`src/rag/settings.py`**: Bỏ `groq_api_key` và `groq_judge_model`, thêm `deepseek_api_key` và `deepseek_model`.
- **`tests/eval/utils.py`**: Bỏ `ChatGroq`, dùng `ChatOpenAI` với `base_url="https://api.deepseek.com"`.
- **`tests/eval/eval_generation.py`**: Bỏ `answer_relevancy.strictness = 1` (workaround cho Groq), bỏ `time.sleep(3)`, bỏ `import time`.
- **`.env`**: Thêm `DEEPSEEK_API_KEY` và `DEEPSEEK_MODEL="deepseek-v4-flash"`.
- **`.env.example`**: Thay GROQ variables bằng DEEPSEEK variables.

---

## 7. Thông tin benchmark

**Test set:** `tests/alerts.json` — 143 samples, phân bố:

| Label | Count |
|---|---|
| Credential_Access | 30 |
| Defense_Evasion | 30 |
| Initial_Access | 30 |
| Reconnaissance | 30 |
| Exfiltration | 23 |

**Ước tính chi phí DeepSeek (full benchmark — 3 templates × 143 samples):**
- ~4,000–4,500 Ragas LLM calls
- Chi phí ước tính: ~$0.80–1.20 với `deepseek-v4-flash`

**Lệnh chạy benchmark:**
```powershell
python scripts/run_benchmark.py --samples 143 --version v1 --reset
```
