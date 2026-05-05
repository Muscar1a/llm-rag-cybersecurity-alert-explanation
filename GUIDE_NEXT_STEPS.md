# Guide: From Stable Retrieval to RAG with Reranking and Experiment Readiness

> **Updated:** 2026-04-30  
> **Current state:** Qdrant retrieval is working, prompt/parser are stabilised, `service.py` is locked to the `basic` template, and step 14 has now passed as a technical E2E run with no reranker.  
> **Next step:** treat step 14 as a technical pass, then run API smoke tests and collect a 5-alert no-rerank quality baseline.

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

## Step 14 Status Update
- The earlier blocker was a missing local Ollama model.
- That environment issue has now been resolved enough for `scripts/test_e2e.py` to run end-to-end.
- Step 14 should now be treated as a technical pass, not a quality pass.
- The current problem is no longer "cannot run"; it is "how good is the analysis output?"

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

## Quality Note From First E2E Output
The first successful `test_e2e` run showed:
- valid JSON output
- at least one relevant retrieved chunk for SSH / credential-related reasoning
- some retrieval noise
- rationale drift toward command-and-control
- mitigation steps that are still too generic

This means the pipeline is operational, but the no-rerank baseline still needs structured quality evaluation.

## Priority Checklist
1. [x] Qdrant health and ingest verification.
2. [x] Retrieval step 13 completed on the current machine.
3. [x] Step 14 E2E without reranker.
   Note: technical pass only; output quality still needs evaluation.
4. [ ] `/analyze` API smoke test.
5. [ ] Run 5 realistic alerts and record outputs.
6. [ ] Create a manual scoring table for retrieval relevance, rationale fit, and mitigation fit.
7. [ ] Compare prompt templates.
8. [ ] Add reranker.

## Common Pitfalls
- Treating a technical pass as if quality validation is already complete.
- Pulling reranker work forward before the no-rerank pipeline is green.
- Testing only with hand-written alerts and not with CICIDS-derived alert text.
- Expanding context too early before the JSON output path is stable.
