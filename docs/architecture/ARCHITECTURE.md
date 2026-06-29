# Cyber-RAG System — Architecture

## 1. Overview

A Retrieval-Augmented Generation (RAG) system for cybersecurity alert analysis in SOC environments. The system:

1. **Detects** threats via Suricata IDS (signature-based)
2. **Enriches** alerts with Zeek network telemetry (flow metadata)
3. **Retrieves** relevant context from a five-tier anti-leakage Knowledge Base (Qdrant)
4. **Generates** structured threat analysis via LLM (local vLLM or cloud API)
5. **Executes** autonomous remediation commands based on severity and tactic
6. **Evaluates** output quality using the RAGAS framework

---

## 2. Layered Architecture

The system follows a four-layer architecture with strict top-down dependency:

| Layer | Packages | Responsibility |
|-------|----------|----------------|
| **Presentation** | `demo/` | Streamlit dashboard (realtime monitor + batch analysis) |
| **Application** | `src/api/` | FastAPI REST endpoints, Prometheus metrics middleware |
| **Core Domain** | `src/rag/`, `src/realtime/` | RAG pipeline, LLM orchestration, realtime event correlation |
| **Infrastructure** | `src/data_process/`, `src/mlops/`, `src/monitoring/` | KB ingestion, MLflow tracking, port baselines |

---

## 3. Data Flow

```
Network Traffic
    ├── Suricata (signature detection) → eve.json → Watcher → Redis queue
    └── Zeek (flow telemetry)          → conn.log → Watcher → Redis flow cache (TTL 300s)
                                                                    │
                                                               Consumer
                                                          BLPOP + 5-tuple lookup
                                                          → build combined alert
                                                          → POST /analyze
                                                                    │
                                                              FastAPI (8000)
                                                          ┌─────────┼──────────┐
                                                     KBRetriever   LLM    Response Engine
                                                     (Qdrant)   (vLLM/   (iptables cmds)
                                                                 Cloud)
                                                                    │
                                                              Streamlit (8501)
                                                          poll Redis → dashboard
```

---

## 4. Core Components

### 4.1 RAG Pipeline (`src/rag/`)

| Component | File | Purpose |
|-----------|------|---------|
| RAG Service | `service.py` | Facade orchestrating retrieval → generation → remediation |
| Chain Builder | `lc_chain.py` | LangChain LCEL retrieval + generation chain |
| KBRetriever | `lc_vectorstore.py` | Hybrid exact-filter + semantic search + dual-ranker tactic union |
| LLM Factory | `llm_factory.py` | 7-provider factory (vLLM, OpenAI, DeepSeek, Gemini, GLM, Kimi, Grok) |
| Prompt Templates | `lc_prompt.py` | basic, CoT, few-shot templates with grounding rules |
| Response Engine | `response_actions.py` | Tactic/port-based command generation with risk-gated execution |
| Embeddings | `embeddings.py` | BAAI/bge-base-en-v1.5 (768-dim), CUDA-aware |
| Qdrant Store | `qdrant_store.py` | Vector DB client + collection management |
| Schemas | `schemas.py` | Pydantic models (AnalyzeRequest/Response, AlertMetadata) |
| Settings | `settings.py` | Env-based configuration via pydantic-settings |

### 4.2 Realtime Pipeline (`src/realtime/`)

| Component | File | Purpose |
|-----------|------|---------|
| Suricata Watcher | `watcher_suricata.py` | Tail eve.json → filter alerts → Redis RPUSH |
| Zeek Watcher | `watcher_zeek.py` | Tail conn.log → Redis SET with 300s TTL |
| Consumer | `consumer.py` | BLPOP alert → 5-tuple Zeek lookup → build text → POST /analyze |
| Alert Builder | `alert_builder.py` | Suricata signature + Zeek telemetry → combined fact-only text |

### 4.3 Data Pipeline (`src/data_process/`)

| Component | File | Purpose |
|-----------|------|---------|
| KB Ingestion | `ingest_kb.py` | KB v2 JSONL → embed (batch 64) → upsert Qdrant |
| Alert Builder | `zeek_alert_builder.py` | Zeek conn.log row → neutral fact-only text (no interpretation) |

---

## 5. Knowledge Base (KB v2)

Five taxonomic silos, each stored as JSONL in `data/kb/`:

| Silo | Source | Retrieval Method |
|------|--------|------------------|
| `port_profile` | Manual curation | Exact filter on destination port |
| `conn_state` | Zeek documentation | Exact filter on connection state code |
| `traffic_pattern` | Manual curation | Semantic similarity search |
| `tactic` | MITRE ATT&CK (network-adapted) | Dual-ranker union (bi-encoder ∪ cross-encoder) |
| `suricata_category` | Suricata classification rules | Exact filter on alert category |

All silos are indexed in a single Qdrant collection (`cyber_chunks`) with `kb_type` metadata for pre-filtering.

---

## 6. Retrieval Strategy

KBRetriever applies per-silo retrieval:

1. **Exact match silos** — regex extracts structured facts from alert text:
   - `\bport (\d+)\b` → `port_profile` filter
   - `\bConnection state (\w+)[:\s]` → `conn_state` filter
   - `Suricata alert: .+?\(severity \d+, (.+?)\)` → `suricata_category` filter

2. **Semantic search silos** — `traffic_pattern` via standard cosine similarity

3. **Dual-ranker tactic union** — bi-encoder top-k ∪ cross-encoder top-k to bridge the semantic gap between raw network observables and abstract MITRE tactic descriptions

4. **Final reranking** — all collected documents merged, deduplicated, cross-encoder reranked

---

## 7. API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Qdrant + vLLM reachability check |
| `GET` | `/version` | Git SHA, model info, parameters |
| `GET` | `/providers` | List available LLM providers |
| `POST` | `/analyze` | Synchronous RAG analysis → JSON response |
| `POST` | `/analyze/stream` | SSE streaming (contexts → tokens → done) |

---

## 8. Response Action Engine

Two template registries generate remediation commands:

- **Tactic templates** — mapped to MITRE ATT&CK tactics (e.g., Exfiltration → block outbound, capture traffic)
- **Port templates** — mapped to well-known services (e.g., port 22 → SSH hardening)

Each command carries a `severity_threshold`; execution is risk-gated:
- `dry_run` mode (default): log only
- `live` mode: `subprocess.run` execution (Linux only, requires root)

---

## 9. Evaluation Framework

Two-pass benchmark (`scripts/run_benchmark.py`):
- **Pass 1**: RAG inference on 135 stratified samples → collect outputs + contexts + latency
- **Pass 2**: RAGAS judge evaluation (DeepSeek as independent judge LLM)

| Metric | Target | Best Achieved |
|--------|--------|---------------|
| Context Recall | ≥ 0.75 | 0.674 (14B) |
| Faithfulness | ≥ 0.80 | 0.575 (14B) |
| Answer Relevancy | ≥ 0.75 | 0.705 (14B) |

Additional evaluations: retrieval (`eval_retrieval.py`), generation (`eval_generation.py`), latency (`eval_latency.py`), remediation quality (`eval_remediation.py`).

---

## 10. Infrastructure

| Service | Port | Purpose |
|---------|------|---------|
| Qdrant | 6333 | Vector database |
| Redis | 6379 | Event queue + flow cache |
| MLflow | 5000 | Experiment tracking |
| Prometheus | 9090 | Metrics scraping |
| Grafana | 3000 | Monitoring dashboard |
| FastAPI | 8000 | RAG API |
| Streamlit | 8501 | SOC dashboard |

All services containerized via Docker Compose. DVC manages the reproducible data pipeline (`clean_data` → `ingest_kb`).

---

## 11. Realtime Pipeline — Suricata + Zeek Correlation

### 11.1 Pipeline Flow

```
Network Traffic
    ├── Suricata (eve.json alerts) → Watcher-S → RPUSH → Redis queue
    └── Zeek (conn.log flows)      → Watcher-Z → SET EX → Redis flow cache
                                                                │
                Consumer: BLPOP alert → lookup Zeek flow (5-tuple) →
                build combined text → POST /analyze → RPUSH result
                                                                │
                                                        Streamlit dashboard
                                                        (poll every 3s)
```

### 11.2 Redis Keys

| Key | Type | Producer | Consumer | TTL |
|-----|------|----------|----------|-----|
| `suricata:alerts:raw` | List (RPUSH/BLPOP) | Suricata Watcher | Consumer | — |
| `zeek:flow:{proto}:{src}:{sp}:{dst}:{dp}` | String (SET EX) | Zeek Watcher | Consumer | 300s |
| `alerts:results` | List (RPUSH/LRANGE) | Consumer | Streamlit | LTRIM 200 |

### 11.3 Temporal Race Condition

Suricata fires alerts mid-connection (instant signature match). Zeek emits conn.log after flow termination (FIN/RST/timeout). This creates a timing gap.

**Resolution:**
- Zeek flows are cached in Redis with 300s TTL (sliding window)
- Consumer looks up Zeek flow for each Suricata alert
- If Zeek flow not yet available → graceful degradation (Suricata-only info)
- Pipeline never blocks waiting for telemetry

### 11.4 Combined Alert Text Format

**With Zeek telemetry:**
```
Suricata alert: ET SCAN Potential SSH Scan (severity 2, Attempted Information Leak).
TCP connection to port 22. Connection state S0: SYN sent, no SYN-ACK received.
Traffic volume: 1 packets sent / 0 packets received, 0 bytes / 0 bytes (0 total).
TCP sequence: SYN(client).
```

**Without Zeek telemetry (fallback):**
```
Suricata alert: ET SCAN Potential SSH Scan (severity 2, Attempted Information Leak).
TCP connection to port 22.
```

Both formats preserve `"port {N}"`, `"Connection state {X}:"`, and `"Suricata alert: ... (severity N, {category})"` patterns for KBRetriever regex matching.

### 11.5 Error Handling

| Scenario | Behavior |
|----------|----------|
| Suricata/Zeek log not yet created | Watcher polls every 1s until file appears |
| Log rotation | Watcher detects `tell() > file_size`, seeks to beginning |
| Redis down | Watchers/Consumer crash → Docker auto-restart |
| Zeek flow not yet cached | Graceful degradation: Suricata-only alert text |
| RAG API timeout (>60s) | Consumer logs warning, skips alert, continues |
| Queue backlog | Redis buffers alerts, consumer processes FIFO sequentially |

### 11.6 Docker Services

| Service | Image | Volumes |
|---------|-------|---------|
| `suricata` | `jasonish/suricata:latest` | `suricata_logs:/var/log/suricata` |
| `zeek` | `zeek/zeek:latest` | `zeek_logs:/opt/zeek/logs` |
| `watcher-suricata` | Custom (Dockerfile.watcher-suricata) | `suricata_logs` (read-only) |
| `watcher-zeek` | Custom (Dockerfile.watcher-zeek) | `zeek_logs` (read-only) |
| `consumer` | Custom (Dockerfile.consumer) | — |

For pcap replay demo, use `docker-compose.demo.yml` overlay which sets `TAIL_FROM_START=1` so watchers read from the beginning of log files.
