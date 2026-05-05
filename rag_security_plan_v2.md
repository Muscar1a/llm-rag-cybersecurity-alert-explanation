# Graduation Project: RAG for Cybersecurity Alert Analysis

> Project direction: build a local RAG system that uses CVE and MITRE knowledge to support alert analysis, then compare no-RAG, no-rerank RAG, and reranked RAG settings.

---

## 0. Current State

| Item | Status | Notes |
|---|---|---|
| Data cleaning, chunking, embeddings for CVE and MITRE | Done | Core knowledge preparation is complete |
| `scripts/ingest_qdrant.py` | Done | Batch upsert pipeline exists |
| FastAPI skeleton (`/health`, `/analyze`) | Done | API route layer exists |
| Retriever -> prompt builder -> Ollama path in `service.py` | Done | Locked to `basic` template for now |
| Shared settings cleanup | Done | Main RAG modules use `src/rag/settings.py` |
| Retrieval step 13 | Done | Verified on the current machine |
| Step 14 end-to-end without FastAPI | Technical pass | `scripts/test_e2e.py` returned valid JSON, but quality evaluation is still pending |
| Reranker | Not started | Must stay blocked until no-rerank path is stable |

Immediate action:
- Treat step 14 as a technical pass
- Run `/analyze` API smoke test
- Build a 5-alert no-rerank quality baseline

## 1. Research Direction

Main question:
- Does RAG with a cybersecurity knowledge base improve alert-analysis quality compared with a local LLM used alone?

Supporting questions:
- Does RAG improve severity classification quality?
- Does RAG reduce hallucination?
- How much does prompt style affect output stability?
- Does reranking improve context quality enough to justify added complexity?

## 2. System Architecture

### Knowledge Sources
- CVE / NVD
- MITRE ATT&CK
- CICIDS2017 for realistic alert-style evaluation inputs

### Base RAG Flow
```text
Alert text
-> query embedding
-> Qdrant retrieval
-> prompt builder
-> Ollama LLM
-> JSON output
```

### Future Rerank Flow
```text
Alert text
-> query embedding
-> Qdrant top-50
-> reranker
-> top-5 context
-> prompt builder
-> Ollama LLM
-> JSON output
```

## 3. Practical Notes From Current Implementation

### Prompt Layer
- `service.py` is intentionally fixed to `template_name="basic"` for debugging.
- `few_shot` and `cot` should only be compared after the base path is stable.

### Parser Layer
- `llm_ollama.py` handles:
  - plain JSON
  - `<answer>{...}</answer>`
  - fenced JSON

### Alert Builder
- `src/data_process/alert_builder.py` is now part of the evaluation path.
- It converts CICIDS2017 rows into richer alert text using:
  - inferred severity
  - inferred attack family
  - duration and traffic rate descriptions
  - packet asymmetry
  - TCP flag summaries
- `scripts/test_e2e.py` now uses this builder instead of a manual alert string.

This is useful because it makes step 14 and later step 16 closer to the real evaluation scenario.

## 4. Step 14 Outcome and Current Focus

Step 14 outcome:
- `scripts/test_e2e.py` has run end-to-end successfully
- the output is valid JSON
- the pipeline can retrieve context, build prompts, call Ollama, and parse the response

Current focus:
- verify that the API path behaves the same way
- evaluate output quality before changing architecture

Recommended model for current hardware:
- `qwen2.5:3b-instruct`

Recommended `.env`:
```env
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5:3b-instruct
```

Pull command:
```powershell
ollama pull qwen2.5:3b-instruct
```

## 5. Experiment Order

1. Record step 14 as a no-rerank technical pass with `basic`
2. Test `/analyze`
3. Run 5 realistic alerts and log outputs
4. Score retrieval relevance, rationale fit, and mitigation fit
5. Compare `basic`, `few_shot`, and `cot`
6. Add reranker
7. Run the experiment matrix

## 6. Target Experiment Matrix

| Config | use_rag | use_rerank | retrieve_k | final_k | Purpose |
|---|---|---|---|---|---|
| `baseline_llm_only` | No | No | - | - | Zero-shot baseline |
| `rag_top5_no_rerank` | Yes | No | 5 | 5 | Stable no-rerank baseline |
| `rag_top20_no_rerank` | Yes | No | 20 | 20 | Noise comparison |
| `rag_rerank_50to5` | Yes | Yes | 50 | 5 | Main reranked config |

## 7. Near-Term Checklist

- [x] Stabilise prompt builder and parser
- [x] Lock `service.py` to `basic`
- [x] Finish retrieval step 13
- [x] Move `alert_builder.py` into the E2E test path
- [x] Install local Ollama model
- [x] Pass step 14 technically
- [ ] Pass `/analyze` API smoke test
- [ ] Run 5-alert no-rerank baseline
- [ ] Create manual quality scoring rubric and first results table
- [ ] Compare prompt templates
- [ ] Implement reranker

## 8. Interpretation of the First Successful E2E Output

The first successful output indicates:
- the RAG pipeline is operational
- retrieval is partially relevant, but still noisy
- the rationale can drift to a broader ATT&CK narrative such as command-and-control
- the mitigation advice is still too generic for a SOC-style response

Therefore:
- step 14 should be reported as a technical milestone
- output quality should be evaluated before further architecture changes
