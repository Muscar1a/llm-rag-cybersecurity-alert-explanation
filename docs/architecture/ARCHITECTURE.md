# Cyber Security RAG System — Architecture

**Project**: Đồ án tốt nghiệp (Capstone Project)
**Purpose**: Giải thích cảnh báo mạng bằng RAG — Retrieval-Augmented Generation system for explaining network security alerts using cybersecurity knowledge bases

---

## 1. Project Overview

A **RAG** system that explains network security alerts by:

1. **Detecting** threats via Suricata IDS (signature-based)
2. **Enriching** alerts with Zeek network telemetry (flow metadata)
3. **Retrieving** relevant cybersecurity knowledge from Qdrant vector DB
4. **Generating** threat analysis and mitigation via local LLM (Ollama)
5. **Executing** auto-response actions based on severity and tactic
6. **Evaluating** RAG quality using RAGAS metrics

**Key Features**:
- Real-time alert pipeline: Suricata (detection) + Zeek (telemetry) → Redis → Consumer → RAG
- Multi-mode analysis: sync, streaming (SSE), and batch
- Tactic-aware auto-response with dry-run and execution modes
- Multiple prompt templates (basic, CoT, few-shot)
- RAGAS evaluation (context_recall, answer_relevancy, hallucination_rate, latency)
- MLflow experiment tracking, Prometheus/Grafana monitoring
- Streamlit UI for interactive and real-time alert analysis

---

## 2. System Architecture

### 2.1 High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      REALTIME NETWORK MONITORING                        │
│  Traffic → Suricata (detection, eve.json) + Zeek (telemetry, conn.log) │
│  → Watchers → Redis → Consumer (correlate + build) → RAG API          │
└──────────────────────────────┬──────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                         ALERT INPUT SOURCES                             │
│  • Realtime pipeline (primary)   • Demo UI (Streamlit)                 │
│  • API direct call               • Batch processing (JSON upload)      │
└──────────────────────────────┬──────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  FastAPI REST API (8000) — src/api/main.py                             │
│  GET /health · GET /version · POST /analyze · POST /analyze/stream     │
└──────────────────────────────┬──────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  RAG Service — src/rag/service.py                                       │
│  analyze() / stream_analyze()                                           │
│    ├─ Retrieve top-k KB chunks (Qdrant)                                │
│    ├─ Generate threat analysis JSON (Ollama LLM)                       │
│    └─ Build remediation commands (tactic-based)                        │
└────────┬──────────────────────┬──────────────────────┬──────────────────┘
         ↓                      ↓                      ↓
  ┌──────────────┐  ┌───────────────────┐  ┌──────────────────────┐
  │  Retriever   │  │  LLM (Ollama)     │  │  Response Actions    │
  │  KBRetriever │  │  qwen2.5:7b       │  │  Tactic detection    │
  │  Qdrant      │  │  temp=0.1         │  │  Command generation  │
  │  768-dim BGE │  │  ctx=5120 tokens  │  │  Auto-execution      │
  └──────────────┘  └───────────────────┘  └──────────────────────┘
         ↑
  ┌──────────────────────────────────────┐
  │  KB Ingestion — data/kb/*.jsonl     │
  │  4 groups: port_profile, conn_state, │
  │  traffic_pattern, tactic_profile     │
  └──────────────────────────────────────┘
```

### 2.2 Component Table

| Component | Location | Purpose |
|-----------|----------|---------|
| **API** | `src/api/main.py` | FastAPI endpoints, health checks, SSE streaming |
| **RAG Service** | `src/rag/service.py` | Orchestrates retrieval, generation, remediation |
| **Chain Builder** | `src/rag/lc_chain.py` | LangChain retrieval + generation chain |
| **Retriever** | `src/rag/lc_vectorstore.py` | KBRetriever: exact filter + semantic search + reranking |
| **Embeddings** | `src/rag/embeddings.py` | BAAI/bge-base-en-v1.5, 768-dim, normalized |
| **Prompts** | `src/rag/lc_prompt.py` | basic, CoT, few-shot templates |
| **Schemas** | `src/rag/schemas.py` | AnalyzeRequest (with AlertMetadata: signature, severity), AnalyzeResponse, RemediationCommand |
| **Settings** | `src/rag/settings.py` | Env-based config (Qdrant, Ollama, embedding, auto-response) |
| **Response Actions** | `src/rag/response_actions.py` | Tactic detection, command gen & execution |
| **Data Cleaning** | `src/data_process/clean_data.py` | MITRE, Sigma, ET rules → cleaned parquet |
| **KB Ingestion** | `src/data_process/ingest_kb.py` | Load KB v2 JSONL → embed → upsert Qdrant |
| **Alert Builder** | `src/data_process/zeek_alert_builder.py` | Zeek conn.log row → neutral fact-only text |
| **Combined Builder** | `src/realtime/alert_builder.py` | Suricata signature + Zeek telemetry → combined text |
| **Suricata Watcher** | `src/realtime/watcher_suricata.py` | Tail eve.json → filter alerts → Redis queue |
| **Zeek Watcher** | `src/realtime/watcher_zeek.py` | Tail conn.log → Redis flow cache (TTL) |
| **Consumer** | `src/realtime/consumer.py` | Correlate Suricata+Zeek → build alert → call RAG API |
| **Demo UI** | `demo/app.py` | Streamlit: paste/upload/batch + streaming display |
| **Realtime UI** | `demo/pages/realtime.py` | Streamlit: poll Redis, live alert monitor |
| **Evaluation** | `tests/eval/`, `scripts/run_benchmark.py` | RAGAS metrics, two-pass benchmark |

---

## 3. Realtime Pipeline — Suricata + Zeek

### 3.1 Design Principle

| Component | Role | Output |
|-----------|------|--------|
| **Suricata** | Detection (signature-based IDS) | Alert: signature name, severity, category |
| **Zeek** | Telemetry (flow metadata) | Context: conn_state, bytes, packets, duration, TCP history |
| **Alert Builder** | Combine alert + telemetry | Enriched text for RAG |
| **RAG** | Explain the alert using KB | Threat analysis grounded in knowledge base |

Suricata replaces the old `should_alert()` heuristic — signature-based detection is more accurate and covers more attack patterns via ET Open rules.

### 3.2 Pipeline Flow

```
Traffic ──► Suricata (eve.json alerts) ──► Watcher-S ──► Redis queue
       └──► Zeek (conn.log flows)     ──► Watcher-Z ──► Redis flow cache
                                                              │
Consumer: BLPOP alert → lookup Zeek flow (5-tuple) → build combined text → POST /analyze
```

**Redis keys:**

| Key | Type | Content | TTL |
|-----|------|---------|-----|
| `suricata:alerts:raw` | List | Suricata alert events | — |
| `zeek:flow:{proto}:{src}:{sp}:{dst}:{dp}` | String | Zeek conn.log row | 300s |
| `alerts:results` | List | RAG analysis results (LTRIM 200) | — |

**Correlation:** 5-tuple `(proto, src_ip, src_port, dst_ip, dst_port)`. When Zeek flow not yet available (Suricata fires mid-connection, Zeek logs on close), consumer falls back to Suricata-only info — graceful degradation.

### 3.3 Combined Alert Text Format

```
Suricata alert: ET SCAN Potential SSH Scan (severity 2, Attempted Information Leak).
TCP connection to port 22. Connection state S0: SYN sent, no SYN-ACK received.
Traffic volume: 1 packets sent / 0 packets received, 0 bytes / 0 bytes (0 total).
TCP sequence: SYN(client).
```

Line 1 = Suricata signature. Rest = reuses `zeek_alert_builder.build_alert_text()`. Format preserves `"port {N}"` and `"Connection state {X}:"` patterns for KBRetriever regex matching.

> See `docs/architecture/zeek_realtime_design.md` for full pipeline design with code examples, Docker setup, and sequence diagrams.

---

## 4. RAG Pipeline

### 4.1 Retrieval (lc_vectorstore.py)

**KBRetriever** — hybrid exact + semantic retrieval:

| KB Group | Method | Match |
|----------|--------|-------|
| `port_profile` | Exact filter | `\bport (\d+)\b` regex → metadata.port |
| `conn_state` | Exact filter | `\bConnection state (\w+)[:\s]` regex → metadata.state_code |
| `traffic_pattern` | Semantic search | Top-k similarity in Qdrant |
| `tactic` | Semantic search | Top-k similarity in Qdrant |

After retrieval: optional CrossEncoder reranking (`cross-encoder/ms-marco-MiniLM-L-6-v2`).

**Embedding**: BAAI/bge-base-en-v1.5 (768-dim, HuggingFace, normalized L2, cosine similarity). Configured in `params.yaml` → `embedding.model_name`. GPU if available, else CPU.

### 4.2 Generation (lc_chain.py)

LangChain `create_retrieval_chain` with `create_stuff_documents_chain`. `build_analyze_chain(k, template_name)` — no source filter needed since KBRetriever always queries `kb_v2`. LLM: `ChatOllama(model=qwen2.5:7b-instruct-q4_K_M, temperature=0.1, num_ctx=5120)`.

**Prompt templates** (`lc_prompt.py`):
- **basic**: Context + question → JSON answer. Optimal for cybersecurity domain.
- **cot**: Chain-of-thought in `<scratchpad>`, JSON output after.
- **few_shot**: 2 in-context examples (Reconnaissance + Credential Access).

**Output extraction** (`service.py`): Try JSON parse → `<answer>{}</answer>` → ` ```json``` ` → regex `{...}` → raw text fallback.

### 4.3 KB v2 (data_process/ingest_kb.py)

No chunking — each JSONL entry is self-contained. Input: `data/kb/{port_profile,conn_state,traffic_pattern,tactic_profile}/*.jsonl`. Batch embed (batch_size=64) → upsert to Qdrant with metadata.

---

## 5. Response Actions & Auto-Response

**Tactic detection** (`response_actions.py`): Priority: explicit `label_tactic` from metadata → extract from KB docs → parse from LLM output → fallback "Reconnaissance".

**Command generation**: Per-tactic templates with `{src_ip}`, `{dest_ip}`, `{dest_port}` substitution. Each command has: description, command, undo_command, severity_threshold, risk level, auto_executable flag.

**Execution modes**: `dry_run` (default, log only) or `execute` (subprocess.run, Linux only). Triggered when: auto_response enabled AND severity >= threshold (default: Critical).

---

## 6. API & Streaming

**POST /analyze**: `AnalyzeRequest { alert_text, k, metadata?: AlertMetadata, auto_response? }` → JSON response with threat_description, severity, rationale, mitigation_steps, contexts, remediation_commands. `AlertMetadata` includes: src_ip, dest_ip, dest_port, proto, conn_state, label_tactic, signature, severity.

**POST /analyze/stream**: Same request → SSE events: `contexts` (retrieved KB chunks) → `token` (incremental generation) → `done` (final parsed result with remediation).

**GET /health**: Check Qdrant + Ollama reachability. **GET /version**: Git SHA, model info, params.

---

## 7. Demo UI (Streamlit)

**Main page** (`demo/app.py`): Paste/upload alert text → streaming analysis display. Sidebar: metadata (src_ip, dest_ip, dest_port), auto-response toggle, top-k slider. Output: severity badge, threat description, mitigation steps, remediation commands, retrieved KB sources with scores. Supports batch mode (JSON array upload).

**Realtime page** (`demo/pages/realtime.py`): Polls Redis `alerts:results` every 3s. Shows summary metrics (total/critical/high/medium+low) and latest 20 alerts with expandable details.

---

## 8. Evaluation & Benchmarking

**Two-pass evaluation** (`scripts/run_benchmark.py`):
- Pass 1 (inference): Run `rag.analyze()` on sampled ground truth, collect output + contexts + latency. Checkpointed.
- Pass 2 (judge): RAGAS metrics via judge LLM (default: DeepSeek). Checkpointed.

**Metrics:**

| Metric | Range | What it measures |
|--------|-------|------------------|
| context_recall | [0,1] ↑ | Fraction of ground-truth info in retrieved chunks |
| answer_relevancy | [0,1] ↑ | How well answer addresses the question |
| hallucination_rate | [0,1] ↓ | 1 - faithfulness; factual inconsistencies |
| latency (p50/avg) | seconds | Retrieval + generation wall-clock time |

**Usage**: `python scripts/run_benchmark.py --samples 135 --templates "basic,cot,few_shot" --version v4`

**Latest results** (qwen2.5:7b, BGE-base, basic template, 135 samples): context_recall=0.674, answer_relevancy=0.505, hallucination=0.425, p50=4.9s.

---

## 9. Configuration

**Environment** (`src/rag/settings.py`, loaded via pydantic_settings from `.env`):

| Group | Key settings |
|-------|-------------|
| Qdrant | `qdrant_host=localhost`, `qdrant_port=6333`, `qdrant_collection=cyber_chunks`, `qdrant_timeout=60` |
| Embedding | `embedding_model=BAAI/bge-base-en-v1.5` |
| Ollama | `ollama_host=http://localhost:11434`, `ollama_num_ctx=5120` |
| Auto-response | `auto_response_enabled=False`, `auto_response_mode=dry_run`, `severity_threshold=Critical` |
| Judge LLM | `deepseek_api_key`, `deepseek_model=deepseek-chat` |

**Pipeline** (`params.yaml`): `embedding.model_name`, `embedding.dim=768`, `retrieval.k=5`, `llm.model=qwen2.5:7b-instruct-q4_K_M`, `llm.temperature=0.1`, `llm.num_ctx=5120`.

**Precedence**: `.env` → environment variables → Settings class defaults.

---

## 10. Docker Stack

| Service | Image | Purpose | Port |
|---------|-------|---------|------|
| **qdrant** | qdrant/qdrant:v1-gpu-nvidia | Vector database | 6333 |
| **mlflow** | ghcr.io/mlflow/mlflow:v2.16.2 | Experiment tracking | 5000 |
| **prometheus** | prom/prometheus:latest | Metrics scraping | 9090 |
| **grafana** | grafana/grafana:latest | Monitoring dashboard | 3000 |
| **redis** | redis:7-alpine | Queue broker + flow cache | 6379 |
| **suricata** | jasonish/suricata:latest | Signature-based IDS | — |
| **zeek** | zeekurity/zeek:latest | Network telemetry | — |
| **watcher-suricata** | custom | Tail eve.json → Redis queue | — |
| **watcher-zeek** | custom | Tail conn.log → Redis flow cache | — |
| **consumer** | custom | Correlate → alert builder → RAG API | — |

**Volumes**: `qdrant_storage`, `prometheus_data`, `grafana_data`, `suricata_logs`, `zeek_logs`.

**Networking**: Windows/Mac: `http://host.docker.internal:8000/analyze`. Linux: `--network host` or `http://172.17.0.1:8000`.

---

## 11. Project Structure

```
project/
├── src/
│   ├── api/
│   │   ├── main.py                    # FastAPI app
│   │   └── middleware.py              # Prometheus metrics
│   ├── rag/
│   │   ├── service.py                 # RAG orchestration
│   │   ├── lc_chain.py                # LangChain chain builder
│   │   ├── lc_vectorstore.py          # KBRetriever (hybrid exact+semantic)
│   │   ├── lc_prompt.py               # Prompt templates (basic, CoT, few-shot)
│   │   ├── embeddings.py              # SentenceTransformer (BGE-base)
│   │   ├── qdrant_store.py            # Qdrant client + ensure_collection
│   │   ├── schemas.py                 # Pydantic models (AlertMetadata, AnalyzeRequest/Response)
│   │   ├── settings.py                # Environment config (pydantic_settings)
│   │   └── response_actions.py        # Tactic-based auto-response engine
│   ├── data_process/
│   │   ├── clean_data.py              # MITRE + Sigma + ET rules → cleaned parquet
│   │   ├── chunk_data.py              # Tokenizer-based chunking
│   │   ├── embed_chunks.py            # Embed chunks → upsert Qdrant
│   │   ├── ingest_kb.py              # KB v2 JSONL → embed → upsert Qdrant
│   │   ├── parse_attck.py            # MITRE ATT&CK STIX → techniques
│   │   └── zeek_alert_builder.py      # Zeek flow → neutral fact-only text
│   ├── realtime/
│   │   ├── watcher_suricata.py        # Tail eve.json → Redis queue
│   │   ├── watcher_zeek.py            # Tail conn.log → Redis flow cache
│   │   ├── consumer.py                # Correlate → build → POST /analyze
│   │   └── alert_builder.py           # Suricata + Zeek → combined text
│   ├── mlops/
│   │   └── tracking.py                # MLflow experiment logging
│   └── monitoring/
│       ├── baseline.py                # PortBaseline (MAD-based anomaly stats)
│       └── build_baseline.py          # Build baseline from CIC-IDS CSV
├── scripts/
│   ├── run_benchmark.py               # Two-pass RAGAS evaluation
│   └── measure_recall_k.py            # Recall@K measurement
├── tests/
│   ├── eval/                          # RAGAS evaluation modules
│   ├── export_zeek_for_suricata.py    # UWF-ZeekData24 → zeek_rows.json
│   ├── build_combined_alerts.py       # suricata_alerts.json + Zeek → alerts.json
│   └── inspect_kb.py                  # Qdrant KB inspection tool
├── demo/
│   ├── app.py                         # Streamlit main UI (paste/upload/batch/stream)
│   └── pages/realtime.py              # Realtime alert monitor (poll Redis)
├── suricata/suricata.yaml             # Suricata config (ET Open rules)
├── zeek/local.zeek                    # Zeek JSON output config
├── data/kb/                           # KB v2 JSONL (4 groups)
├── baselines/                         # Ground truth for evaluation
├── results/                           # Benchmark outputs + checkpoints
├── infra/                             # Prometheus + Grafana config
├── Dockerfile.watcher-suricata
├── Dockerfile.watcher-zeek
├── Dockerfile.consumer
├── docker-compose.yml
├── params.yaml
└── requirements.txt
```

---

## 12. Technology Stack

| Layer | Technology |
|-------|-----------|
| **IDS** | Suricata (detection, ET Open rules), Zeek (telemetry) |
| **API** | FastAPI, Uvicorn, SSE |
| **LLM** | LangChain + Ollama (qwen2.5:7b-instruct-q4_K_M) |
| **Vector DB** | Qdrant |
| **Embeddings** | SentenceTransformer (BAAI/bge-base-en-v1.5, 768-dim) |
| **Evaluation** | RAGAS (judge-based) |
| **Monitoring** | Prometheus, Grafana, MLflow |
| **Queue** | Redis |
| **UI** | Streamlit |
| **Infra** | Docker, docker-compose |

---

## 13. Quick Start

**Local development:**
```bash
pip install -r requirements.txt
# Start Qdrant: docker run -p 6333:6333 qdrant/qdrant
# Start Ollama: ollama pull qwen2.5:7b-instruct-q4_K_M
python src/data_process/ingest_kb.py        # Ingest KB
uvicorn src.api.main:app --reload --port 8000
streamlit run demo/app.py                   # Optional UI
```

**Docker stack:** `docker-compose up -d`. Endpoints: API `:8000`, Docs `:8000/docs`, Prometheus `:9090`, Grafana `:3000`, MLflow `:5000`.

---

## 14. Status & Benchmark

**Completed**: Core RAG pipeline, KB v2 (4 groups), streaming API, RAGAS evaluation, MLflow tracking, Prometheus metrics, auto-response engine, Streamlit UI, realtime Suricata+Zeek pipeline (code, prompts, Docker).

**In Progress**: Demo & testing (pcap dataset, end-to-end test, dry-run before thesis defense).

**Benchmark** (basic template, 135 samples, qwen2.5:7b + BGE-base):

| Metric | Value |
|--------|-------|
| Context Recall | 0.674 |
| Answer Relevancy | 0.505 |
| Hallucination Rate | 0.425 |
| p50 Latency | 4.9s |

---

**Version**: 3.1 | **Updated**: 2026-06-18 | **Maintainer**: Muscar1a
