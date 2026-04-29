# Guide: From Stable Retrieval to RAG with Reranking and Experiment Readiness

> **Updated:** 2026-04-29  
> **Current state:** Qdrant retrieval is working, prompt/parser are stabilised, `service.py` is locked to the `basic` template, and step 14 is currently blocked by a missing local Ollama model.  
> **Next step:** install a local Ollama model, finish the no-rerank E2E smoke test, then compare prompt templates.

---

## Goal
Move from "retrieval works" to a stable local RAG pipeline that can support later reranking and experiment runs.

## Code Reality Check
- Qdrant collection `cyber_chunks` exists and retrieval step 13 is considered complete on the current machine.
- `src/rag/settings.py` is the shared config source for retriever, embeddings, service, and Ollama.
- `src/rag/service.py` is intentionally locked to `template_name="basic"` so later errors are easier to isolate.
- `src/rag/llm_ollama.py` can parse plain JSON, `<answer>{...}</answer>`, and fenced JSON.
- `src/data_process/alert_builder.py` is now used by `scripts/test_e2e.py` to generate realistic CICIDS2017-based alert text.
- `/health` and `/analyze` are already wired in FastAPI.
- `src/rag/reranker.py` does not exist yet and should stay deferred until the no-rerank pipeline is stable.

## Current Blocker
- Step 14 fails because Ollama has no local model installed.
- On 2026-04-29, `ollama list` returned no models.
- The earlier `gemma4:e4b` failure was therefore an environment/runtime issue, not a parser or prompt-builder issue.

## Recommended Local Model
For the current hardware:
- RAM: `40 GB`
- GPU: `RTX 3060 6 GB`

Recommended starting model:
- `qwen2.5:3b-instruct`

Suggested `.env` entries:
```env
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5:3b-instruct
```

Pull command:
```powershell
ollama pull qwen2.5:3b-instruct
```

## Pipeline Order
1. Keep `service.py` fixed on `basic`.
2. Verify prompt builder output.
3. Verify Ollama JSON parser.
4. Verify retriever.
5. Run `RagService.analyze()` without FastAPI.
6. Run `/analyze` through FastAPI.
7. Run 5 realistic alerts for the no-rerank baseline.
8. Only then compare `basic`, `few_shot`, and `cot`.
9. Only after that add reranking.

## Step 14 Note
`scripts/test_e2e.py` now uses `alert_builder.py` instead of a hand-written alert string.

Current flow:
1. Load one non-benign row from `data/processed/CICIDS2017/cicids_rag_evaluation.csv`
2. Prefer labels such as `SSH-Patator`, `FTP-Patator`, `PortScan`, `DoS Hulk`, `DDoS`, or `Bot`
3. Convert that row into natural-language alert text with `build_alert_text()`
4. Send the alert into `RagService.analyze()`

This makes step 14 a better rehearsal for step 16.

## Priority Checklist
1. [x] Qdrant health and ingest verification.
2. [x] Retrieval step 13 completed on the current machine.
3. [ ] Step 14 E2E without reranker.
   Blocker: no local Ollama model installed.
4. [ ] `/analyze` API smoke test.
5. [ ] Run 5 realistic alerts and record outputs.
6. [ ] Compare prompt templates.
7. [ ] Add reranker.

## Common Pitfalls
- Pulling reranker work forward before the no-rerank pipeline is green.
- Debugging prompt logic when the real failure is missing local runtime dependencies.
- Testing only with hand-written alerts and not with CICIDS-derived alert text.
- Expanding context too early before the JSON output path is stable.
