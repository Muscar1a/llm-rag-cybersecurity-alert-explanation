# Cyber-RAG — Cybersecurity Alert Analysis System Based on RAG

A Retrieval-Augmented Generation (RAG) system for cybersecurity alert analysis, designed to support Security Operations Center (SOC) analysts in interpreting, assessing severity, and recommending response actions for network intrusion events. The system ingests Suricata IDS alerts combined with Zeek network flow telemetry, retrieves context from a five-tier anti-leakage cybersecurity knowledge base, and uses a Large Language Model (LLM) to generate structured analysis reports with autonomous remediation commands.

---

## Project Structure

```
src/
├── api/            # FastAPI backend (REST endpoints, Prometheus metrics)
├── rag/            # RAG core (LLM factory, retrieval, prompt, response actions)
├── realtime/       # Realtime pipeline (Suricata/Zeek watchers, consumer)
├── data_process/   # Data pipeline (clean → ingest KB)
├── mlops/          # MLflow experiment tracking
├── monitoring/     # Port baseline & data drift detection
demo/               # Streamlit dashboard (realtime monitor + batch analysis)
tests/eval/         # RAGAS evaluation (retrieval, generation, latency, remediation)
scripts/            # Benchmark runner, ground truth verification
data/
├── kb/             # Knowledge Base v2 (5 silos JSONL)
├── test_data/      # UWF-ZeekData24 dataset (135 samples, 8 tactics)
baselines/          # Ground truth & remediation reference
suricata/           # Suricata rules + config
zeek/               # Zeek config
infra/              # Prometheus + Grafana provisioning
```

---

## System Requirements

| Component | Requirement |
|---|---|
| OS | Windows 10/11 (WSL2 for Docker) |
| Python | 3.11+ |
| Docker Desktop | Running |
| RAM | >= 16 GB |
| GPU (optional) | NVIDIA GPU with CUDA (for vLLM local inference) |

---

## Installation

### 1. Create virtual environment and install dependencies

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure environment

```powershell
Copy-Item .env.example .env
```

Open `.env` and fill in the required API keys. At minimum, **one** of the following providers is needed:
- `VLLM_BASE_URL`       - for local LLM via vLLM
- `DEEPSEEK_API_KEY`    - for DeepSeek API
- `GEMINI_API_KEY`      - for Google Gemini
- `OPENAI_API_KEY`      - for OpenAI
- `GLM_API_KEY`         - for GLM
- `KIMI_API_KEY`        - for Kimi
- `GROK_API_KEY`        - for Grok

### 3. Start infrastructure

```powershell
docker compose up -d qdrant redis mlflow
```

Verify:
```powershell
curl http://localhost:6333         # Qdrant → {"title":"qdrant"...}
curl http://localhost:5000/health  # MLflow → 200 OK
```

### 4. Initialize DVC (first time only)

```powershell
dvc init
git add .dvc .dvcignore
git commit -m "init dvc"
```

### 5. Run data pipeline (ingest Knowledge Base)

```powershell
dvc repro
```

The pipeline executes `ingest_kb`, loading KB v2 JSONL into Qdrant. Verify:
```powershell
curl http://localhost:6333/collections/cyber_chunks
# "points_count" > 0 means success
```

---

## Running the System

### Start API server

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Verify: `curl http://localhost:8000/health`

### Start Streamlit dashboard

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run demo/app.py
```

Open http://localhost:8501. Select LLM provider in the sidebar (DeepSeek, Gemini, vLLM, etc....).

---

## Live Deployment (Suricata + Zeek)

To connect the system with live network traffic, Suricata and Zeek must monitor a real network interface. The full pipeline runs as Docker containers sharing log volumes.

### 1. Identify the network interface

```bash
# Linux
ip link show        # e.g., eth0, ens33, enp0s3

# Windows (WSL2)
ip link show        # Inside WSL2 — typically eth0
```

### 2. Configure and start IDS containers

Edit `docker-compose.yml` — replace `eth0` with your actual interface name in both the `suricata` and `zeek` service commands:

```yaml
suricata:
  command: suricata -c /etc/suricata/suricata.yaml -i <your-interface>

zeek:
  command: zeek -i <your-interface> local.zeek
```

Then start the full realtime stack:

```powershell
# Build watcher/consumer images (first time only)
docker compose build watcher-suricata watcher-zeek consumer

# Start all realtime services
docker compose up -d suricata zeek watcher-suricata watcher-zeek consumer
```

### 3. Verify the pipeline

```powershell
# Check Suricata is sniffing
docker logs suricata --tail 5

# Check Zeek flow cache in Redis
docker exec redis redis-cli KEYS "zeek:flow:*"

# Check alert queue
docker exec redis redis-cli LLEN suricata:alerts:raw

# Check processed results
docker exec redis redis-cli LLEN alerts:results

# Follow consumer logs
docker logs -f consumer
```

The Streamlit dashboard at http://localhost:8501 will display analyzed alerts in real-time.

> **Note:** Suricata and Zeek both require `network_mode: host` and `CAP_NET_ADMIN` to capture packets. On Windows, this only works inside WSL2. Suricata uses rules from `suricata/suricata.yaml`; run `suricata-update` inside the container to fetch the latest ET Open rules.

---

## Demo Modes

### Demo 1 — Docker Suricata + Zeek (pcap replay)

Full pipeline: pcap → Suricata/Zeek containers → Redis → Consumer → RAG API → Dashboard.

```powershell
# Generate demo pcap (first time only)
python tests/generate_pcap.py

# Build images
docker compose build watcher-suricata watcher-zeek consumer

# Start watchers + consumer
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d watcher-suricata watcher-zeek consumer

# Replay Zeek first (populate flow cache)
docker compose -f docker-compose.yml -f docker-compose.demo.yml run --rm zeek

# Replay Suricata (trigger alerts)
docker compose -f docker-compose.yml -f docker-compose.demo.yml run --rm suricata
```

Results appear automatically on the Streamlit dashboard (auto-refresh every 3 seconds).

### Demo 2 — Batch upload via Streamlit

No Redis or consumer needed. Open http://localhost:8501 → **Analyze** page → **Batch Upload** tab → upload `tests/alerts.json` → **Analyze All**.

---

## Benchmark Evaluation

```powershell
python scripts/run_benchmark.py               # Full 135 samples
python scripts/run_benchmark.py --samples 15   # Quick test with 15 samples
```

Results are saved in `results/`. Metrics are automatically logged to MLflow: http://localhost:5000.

### Individual evaluations

```powershell
python tests/eval/eval_retrieval.py     # Context Recall + Context Precision
python tests/eval/eval_generation.py    # Faithfulness + Answer Relevancy
python tests/eval/eval_latency.py       # p50/avg latency
python tests/eval/eval_remediation.py   # Description Recall/Precision
```

---

## Remediation Engine

The system automatically generates defense commands (`iptables`, `tcpdump`, `ss`) from analysis results. Configuration in `.env`:

```env
AUTO_RESPONSE_ENABLED=false              # Enable/disable auto-response
AUTO_RESPONSE_MODE=dry_run               # dry_run | live (live requires Linux)
AUTO_RESPONSE_SEVERITY_THRESHOLD=High    # Minimum severity threshold
```

`dry_run` mode only logs commands without executing — safe for demo.

---

## Make Commands

| Command | Description |
|---|---|
| `make up` | Start Qdrant + MLflow |
| `make up-api` | Start Qdrant + MLflow + RAG API |
| `make monitoring` | Start full stack + Prometheus + Grafana |
| `make build-api` | Build Docker image for RAG API |
| `make down` | Stop all containers |
| `make ps` | View container status |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/health` → `qdrant: unreachable` | Qdrant not started | `docker compose up -d qdrant` |
| `/health` → `vllm: unreachable` | vLLM not running | Ignore if using DeepSeek/Gemini |
| `dvc repro` says "no changes" | Pipeline already up-to-date | `dvc repro --force` |
| `LLEN alerts:results = 0` | Watcher missed already-written file | Use `docker-compose.demo.yml` (sets `TAIL_FROM_START=1`) |
| `KEYS zeek:flow:* = empty` | Zeek did not write conn.log | Check `docker logs` of zeek container |
| Consumer not processing | API not started or wrong URL | Check `docker logs consumer` |
| Streamlit not updating | Redis empty or API not running | Check `docker exec redis redis-cli LLEN alerts:results` |
