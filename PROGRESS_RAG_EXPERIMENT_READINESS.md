# Progress Tracker: RAG Experiment Readiness

Updated: 2026-04-30  
Based on: `rag_security_plan_v2.md` and `GUIDE_NEXT_STEPS.md`

## Goal
Stabilise the local no-rerank RAG pipeline first, then add reranking and benchmark support.

## Current Status
- Qdrant collection `cyber_chunks` exists.
- Retrieval step 13 is complete on the current machine.
- All main RAG modules read shared settings from `src/rag/settings.py`.
- `service.py` is locked to `template_name="basic"` for debugging stability.
- `llm_ollama.py` parser supports:
  - plain JSON
  - `<answer>{...}</answer>`
  - fenced JSON
- `scripts/test_e2e.py` now uses `src/data_process/alert_builder.py` to build CICIDS2017-based alerts.
- FastAPI `/health` and `/analyze` endpoints are wired.
- Reranker is not implemented yet.

## Current State Change
- Step 14 is no longer blocked.
- `scripts/test_e2e.py` has produced a valid end-to-end response.
- This should be recorded as a technical pass for the no-rerank pipeline.
- However, the first output also showed quality issues in retrieval focus, rationale fit, and mitigation specificity.

## Recommended Ollama Setup
Recommended model for current hardware:
- `qwen2.5:3b-instruct`

Suggested `.env`:
```env
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5:3b-instruct
```

Command:
```powershell
ollama pull qwen2.5:3b-instruct
```

## Phase Checklist

### 1) Infrastructure
- [ ] Confirm `cyber_chunks` point count matches the intended ingest result.
- [ ] Re-run ingest and verify idempotency if needed.
- [ ] Record retrieval latency on a small sample.

### 2) Retrieval Quality
- [x] Retrieval smoke test completed.
- [ ] Build manual query set.
- [ ] Produce `eval_retrieval_manual.csv`.

### 3) End-to-End Without Reranker
- [x] Run `scripts/test_e2e.py` successfully.
  Result: technical pass with valid JSON output.
- [ ] Start FastAPI and test `POST /analyze`.
- [ ] Validate output quality across multiple alerts.
- [ ] Run 5 realistic alerts.
- [ ] Score the first 5 alerts with a manual rubric.
- [ ] Compare `basic`, `few_shot`, and `cot` on a smaller subset.

### 4) Reranker
- [ ] Create `src/rag/reranker.py`.
- [ ] Change retrieval flow from retrieve-top-k to retrieve-then-rerank.
- [ ] Validate latency and JSON stability after reranking.

### 5) Experiment Preparation
- [ ] Build labelled evaluation set.
- [ ] Write benchmark script for the 4 target configs.
- [ ] Add structured logging for alert ID, model, template, retrieved IDs, output JSON, and latency.

## Immediate Next 3 Actions
1. Run `/analyze` through FastAPI and confirm the API path is stable.
2. Collect 5 realistic alerts and record retrieved chunks, rationale quality, mitigation quality, and latency.
3. Build a manual scoring table before changing prompts or adding reranking.

## Notes and Risks
- The main blocker has shifted from runtime setup to output quality validation.
- `alert_builder.py` is now part of the practical test path and should be kept stable before step 16.
- Do not start reranking until step 14 and API smoke tests are both green.
