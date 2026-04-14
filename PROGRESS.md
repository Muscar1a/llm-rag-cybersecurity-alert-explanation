# Progress Tracker

Updated: 2026-04-13

## Current Status
- Embedding phase: Done (CVE + MITRE).
- Ollama: Installed and ready.
- Qdrant in Docker: Added, but needs one fix before running.

## Blocking / Fix Now
- In docker-compose, `vo.lumes` should be `volumes`.
- Why this matters: Docker Compose will fail to parse the file and cannot start Qdrant volume.

## Immediate Next Milestone
- Milestone: Qdrant up + collection ready for ingest.
- Target outcome: You can upsert vectors and query top-k successfully.

## Step-by-Step Checklist
- [x] Clean + chunk data
- [x] Generate embeddings
- [x] Install Ollama
- [x] Add Qdrant service to Docker Compose
- [ ] Fix `volumes` key typo in Docker Compose
- [ ] Start Qdrant container and verify health endpoint
- [ ] Define collection strategy (1 collection or 2 collections)
- [ ] Build ingest script structure (without business logic first)
- [ ] Upsert a small sample and verify retrieval
- [ ] Connect retriever into API layer

## Suggested Order (No Code)
1. Stabilize infra first (Compose parse + container healthy).
2. Lock data contract for points (id, vector, payload fields).
3. Test ingest with a tiny sample.
4. Validate retrieval quality.
5. Only then connect prompt + LLM output.

## Notes for Next Update
- Add run result of Qdrant health check.
- Record chosen collection design.
- Record first retrieval quality observations.
