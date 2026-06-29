# Cyber-RAG — Hướng dẫn vận hành

## Yêu cầu trước khi bắt đầu

- Docker Desktop đang chạy
- vLLM đang chạy trên máy host (port 8001) với model đã được load sẵn
- Python virtual environment đã được cài đặt tại `.venv`

---

## 1. Khởi động hạ tầng

Khởi động Qdrant (vector database) và MLflow (tracking server):

```bash
make up
```

Để dừng toàn bộ:

```bash
make down
```

---

## 2. Khởi tạo DVC (chỉ lần đầu)

```bash
.venv\Scripts\dvc init
```

---

## 3. Chạy data pipeline

Đọc `dvc.yaml` và thông số từ `params.yaml`, thực thi tuần tự: `clean_data` → `chunk_data` → `embed_chunks`:

```bash
.venv\Scripts\dvc repro
```

Sau khi pipeline chạy xong, commit thay đổi vào git:

```bash
git add dvc.yaml dvc.lock params.yaml .dvc/config
git commit -m "chore: repro pipeline"
```

---

## 4. Chạy benchmark đánh giá

Đảm bảo hạ tầng đang chạy (`make up`), sau đó:

```bash
.venv\Scripts\python scripts/run_benchmark.py
```

Kết quả JSON được lưu tại `results/benchmark_<timestamp>.json`. Các metrics (latency, faithfulness, context recall, ...) được tự động log lên MLflow tại [http://localhost:5000](http://localhost:5000).

Để chạy nhanh với số lượng mẫu ít hơn (ví dụ 15 mẫu):

```bash
.venv\Scripts\python scripts/run_benchmark.py --samples 15
```

---

## 5. Chạy API service (Production / Demo)

Build Docker image và khởi động toàn bộ stack bao gồm API:

```bash
make build-api
make up-api
```

Kiểm tra API:

```bash
# Kiểm tra trạng thái Qdrant và vLLM
curl http://localhost:8000/health

# Xem phiên bản model và cấu hình đang chạy
curl http://localhost:8000/version
```

---

## Tổng quan các lệnh `make`

| Lệnh | Mô tả |
|---|---|
| `make up` | Khởi động qdrant, mlflow |
| `make up-api` | Khởi động toàn bộ stack (bao gồm rag-api) |
| `make build-api` | Build Docker image cho rag-api |
| `make down` | Dừng toàn bộ containers |
| `make ps` | Xem trạng thái các containers |
| `make logs` | Xem log của MLflow |

---

## Cấu trúc tham số

Toàn bộ tham số (embedding model, chunk size, LLM, retrieval) được quản lý tập trung tại [`params.yaml`](params.yaml). Thay đổi bất kỳ tham số nào tại đây rồi chạy `dvc repro` để DVC tự động phát hiện và re-run các stage bị ảnh hưởng.