# Guide: What To Do After Embedding (Without Coding For You)

## Goal
Move from "embeddings are ready" to "RAG retrieval works reliably".

## 1) Infrastructure Validation
Before any application code:
- Ensure Docker Compose file is valid (no typo on top-level `volumes`).
- Bring up Qdrant and confirm it is healthy.
- Decide API key usage policy for local/dev.

Done when:
- Qdrant responds healthy on REST.
- Storage persists after container restart.

## 2) Data Contract Design (Most Important)
Decide point schema first, then implement.

Recommended fields:
- id: stable unique id per chunk.
- vector: embedding array.
- payload.source: cve or mitre.
- payload.doc_id: source document id.
- payload.chunk_index: position in document.
- payload.text: chunk content.
- payload.metadata: optional extra fields.

Decisions to make now:
- Single collection with `payload.source` filter, or separate collections.
- Distance metric (cosine usually matches sentence embeddings).
- Vector size (must match your embedding model output).

## 3) Ingest Workflow Design
Implement as 3 internal steps:
1. Load ids and vectors.
2. Build payload mapping.
3. Upsert in batches and log progress.

Good practice:
- Start with 100-500 points smoke test.
- Verify count in collection after upsert.
- Re-run ingest safely (idempotent behavior).

## 4) Retrieval Validation (Before LLM)
Test retrieval quality independently:
- Prepare 10-20 manual test queries.
- Check top-k relevance by reading returned chunks.
- Tune `k` and optional score threshold.
- Add source filter tests (CVE only, MITRE only).

Acceptance criteria:
- Most queries return context that is clearly related.
- No frequent empty/irrelevant top-k.

## 5) API Integration Plan
After retrieval is reliable:
- Build retriever module as a separate component.
- Build prompt builder module with 2-3 templates.
- Keep LLM client isolated so you can swap models.
- Add one endpoint for end-to-end test.

Return structure should include:
- retrieved context ids
- model answer
- severity + rationale
- suggested mitigation

## 6) Experiment/Evaluation Preparation
To support thesis quality:
- Save each run config (model, k, prompt template).
- Log retrieval inputs/outputs for auditability.
- Keep baseline (LLM-only) path for comparison.

Core metrics:
- Retrieval recall (manual or automated subset)
- Faithfulness
- Answer relevance
- Latency

## Common Pitfalls To Avoid
- Mismatch vector size vs collection schema.
- Using random/non-stable ids causing duplicate points.
- Mixing CVE/MITRE without source metadata.
- Evaluating LLM before retrieval is stable.

## Your Next 3 Concrete Actions
1. Fix Compose typo and confirm Qdrant healthy.
2. Freeze point schema and collection strategy.
3. Run a small ingest + manual top-k quality check.

If you want, next I can review your design decisions (collection layout + payload schema + test cases) and give feedback only, still without writing implementation code.
