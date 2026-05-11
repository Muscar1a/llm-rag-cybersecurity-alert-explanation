"""
Verify that embed_chunks.py has successfully ingested data into Qdrant.

Checks:
  1. Qdrant is reachable and the collection exists.
  2. Each source (cve, mitre, sigma) has at least one point.
  3. Every retrieved point has the required payload fields.
  4. Semantic search returns relevant results for a known query per source.
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from qdrant_client import QdrantClient
from src.rag.settings import settings
from src.rag.service import Retriever

REQUIRED_PAYLOAD_FIELDS = {"chunk_id", "doc_id", "source", "text"}

SMOKE_QUERIES = {
    "cve":   ("Apache Log4j remote code execution", 0.1),
    "mitre": ("credential dumping LSASS memory", 0.1),
    "sigma": ("suspicious PowerShell execution", 0.1),
}

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"


def check(label: str, condition: bool, detail: str = "") -> bool:
    status = PASS if condition else FAIL
    print(f"  [{status}] {label}" + (f" — {detail}" if detail else ""))
    return condition


def main():
    failures = 0

    # ── 1. Connectivity & collection existence ────────────────────────────────
    print("\n=== 1. Qdrant connectivity & collection ===")
    try:
        client = QdrantClient(
            host=settings.qdrant_host,
            port=settings.qdrant_port,
            https=settings.qdrant_https,
            api_key=settings.qdrant_api_key,
        )
        collections = [c.name for c in client.get_collections().collections]
        ok = check("Qdrant reachable", True)
    except Exception as exc:
        check("Qdrant reachable", False, str(exc))
        print("\nCannot proceed — Qdrant is not running or misconfigured.")
        sys.exit(1)

    collection = settings.qdrant_collection
    if not check("Collection exists", collection in collections, collection):
        print(f"\nCollection '{collection}' missing — run embed_chunks.py first.")
        sys.exit(1)

    # ── 2. Per-source point counts ────────────────────────────────────────────
    print("\n=== 2. Per-source point counts ===")
    for source in SMOKE_QUERIES:
        from qdrant_client import models
        count_result = client.count(
            collection_name=collection,
            count_filter=models.Filter(
                must=[models.FieldCondition(key="source", match=models.MatchValue(value=source))]
            ),
            exact=True,
        )
        n = count_result.count
        if not check(f"{source.upper()} point count > 0", n > 0, f"{n} points"):
            failures += 1

    # ── 3. Payload schema on a sample ────────────────────────────────────────
    print("\n=== 3. Payload field integrity (sample of 10 points) ===")
    sample, _ = client.scroll(collection_name=collection, limit=10, with_payload=True)
    for point in sample:
        payload = point.payload or {}
        missing = REQUIRED_PAYLOAD_FIELDS - payload.keys()
        if not check(f"Point {point.id} has all required fields", not missing,
                     f"missing: {missing}" if missing else ""):
            failures += 1

    # ── 4. Semantic search returns plausible results ──────────────────────────
    print("\n=== 4. Semantic search smoke-test ===")
    try:
        retriever = Retriever()
    except Exception as exc:
        check("Retriever initialised", False, str(exc))
        sys.exit(1)

    for source, (query, min_score) in SMOKE_QUERIES.items():
        try:
            hits = retriever.search(query=query, k=3, source=source)
            got_hits = check(f"{source.upper()} returns ≥1 hit for '{query}'", len(hits) > 0,
                             f"{len(hits)} hits")
            if got_hits:
                top_score = hits[0]["score"]
                check(
                    f"{source.upper()} top score ≥ {min_score}",
                    top_score >= min_score,
                    f"score={top_score:.4f}",
                )
                for h in hits:
                    src_ok = h.get("source") == source
                    if not check(f"{source.upper()} result has correct source", src_ok,
                                 f"got '{h.get('source')}'"):
                        failures += 1
            else:
                failures += 1
        except Exception as exc:
            check(f"{source.upper()} search raised exception", False, str(exc))
            failures += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 50)
    if failures == 0:
        print(f"[{PASS}] All checks passed — Qdrant is ready for RAG.")
    else:
        print(f"[{FAIL}] {failures} check(s) failed — review output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
