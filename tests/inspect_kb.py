import argparse
from collections import Counter

from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue

from src.rag.qdrant_store import build_client
from src.rag.settings import settings


# ── Helpers ───────────────────────────────────────────────────────────────────

SEP = "-" * 72


def print_sep(title: str = "") -> None:
    if title:
        pad = max(0, 72 - len(title) - 4)
        print(f"\n-- {title} {'-' * pad}")
    else:
        print(SEP)


def trunc(text: str, width: int = 300) -> str:
    return text if len(text) <= width else text[:width] + " …"


# ── Collection overview ───────────────────────────────────────────────────────

def show_overview(client: QdrantClient) -> None:
    col = client.get_collection(settings.qdrant_collection)
    print_sep("Collection overview")
    print(f"  Name       : {settings.qdrant_collection}")
    print(f"  Points     : {col.points_count:,}")
    print(f"  Vector size: {col.config.params.vectors.size}")
    print(f"  Distance   : {col.config.params.vectors.distance.name}")
    print(f"  Status     : {col.status.name}")


def show_source_breakdown(client: QdrantClient, limit: int = 2000) -> None:
    """Scroll up to `limit` points and count by source."""
    print_sep("Source breakdown")
    counter: Counter = Counter()
    offset = None
    fetched = 0

    while fetched < limit:
        batch, offset = client.scroll(
            collection_name=settings.qdrant_collection,
            limit=min(250, limit - fetched),
            offset=offset,
            with_payload=["metadata"],
            with_vectors=False,
        )
        if not batch:
            break
        for pt in batch:
            src = (pt.payload or {}).get("metadata", {}).get("source", "unknown")
            counter[src] += 1
        fetched += len(batch)
        if offset is None:
            break

    total = sum(counter.values())
    print(f"  (sampled {total} points)")
    for src, cnt in counter.most_common():
        bar = "█" * min(40, int(40 * cnt / total)) if total else ""
        print(f"  {src:<12} {cnt:>6,}  {bar}")


# ── Random sample ─────────────────────────────────────────────────────────────

def show_random_sample(client: QdrantClient, n: int = 5, source_filter: str | None = None) -> None:
    print_sep(f"Random sample (n={n}{', source=' + source_filter if source_filter else ''})")

    scroll_filter = None
    if source_filter:
        scroll_filter = Filter(must=[
            FieldCondition(key="metadata.source", match=MatchValue(value=source_filter))
        ])

    points, _ = client.scroll(
        collection_name=settings.qdrant_collection,
        limit=n,
        with_payload=True,
        with_vectors=False,
        scroll_filter=scroll_filter,
    )

    if not points:
        print("  No points found.")
        return

    for i, pt in enumerate(points, 1):
        payload = pt.payload or {}
        meta = payload.get("metadata", {})
        text = payload.get("text", "")
        print(f"\n  [{i}] id={pt.id}")
        print(f"       source   : {meta.get('source', '?')}")
        print(f"       chunk_id : {meta.get('chunk_id', '?')}")
        print(f"       doc_id   : {meta.get('doc_id', '?')}")
        # print remaining meta keys
        extra = {k: v for k, v in meta.items() if k not in ("source", "chunk_id", "doc_id")}
        if extra:
            for k, v in extra.items():
                print(f"       {k:<10}: {trunc(str(v), 80)}")
        print(f"       text     : {trunc(text, 300)}")


# ── Retrieval test ─────────────────────────────────────────────────────────────

def run_retrieval_test(query: str, source_filter: str | None, k: int, min_score: float) -> None:
    print_sep(f"Retrieval test  (k={k}, min_score={min_score})")
    print(f"  Query : {query}")
    if source_filter:
        print(f"  Filter: source={source_filter}")

    # Import here so embedding model only loads when needed
    from src.rag.lc_vectorstore import get_vectorstore
    from qdrant_client.models import Filter, FieldCondition, MatchValue

    vs = get_vectorstore()

    search_kwargs: dict = {
        "k": k,
        "fetch_k": k * 10,
        "lambda_mult": 0.6,
        "score_threshold": min_score,
    }
    if source_filter:
        search_kwargs["filter"] = Filter(must=[
            FieldCondition(key="metadata.source", match=MatchValue(value=source_filter))
        ])

    docs = vs.max_marginal_relevance_search(query, **search_kwargs)

    if not docs:
        print(f"\n  ❌ Không tìm thấy chunk nào vượt qua ngưỡng score={min_score}.")
        print("     Thử hạ --score (mặc định 0.82) hoặc dùng --score 0.0 để xem top-k.")
        return

    print(f"\n  ✅ Tìm được {len(docs)} chunk(s):\n")
    for i, doc in enumerate(docs, 1):
        meta = doc.metadata
        print(f"  [{i}] source   : {meta.get('source', '?')}")
        print(f"       chunk_id : {meta.get('chunk_id', '?')}")
        print(f"       text     : {trunc(doc.page_content, 350)}")
        print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect Qdrant knowledge base")
    parser.add_argument("--query",  type=str,   default=None, help="Câu query để test retrieval")
    parser.add_argument("--source", type=str,   default=None, help="Filter theo source: cve / mitre / sigma")
    parser.add_argument("--score",  type=float, default=0.82, help="Min score ngưỡng (mặc định 0.82)")
    parser.add_argument("--k",      type=int,   default=5,    help="Số chunk trả về (mặc định 5)")
    parser.add_argument("--sample", type=int,   default=5,    help="Số chunk ngẫu nhiên in ra (mặc định 5)")
    args = parser.parse_args()

    client = build_client()

    show_overview(client)
    show_source_breakdown(client)
    show_random_sample(client, n=args.sample, source_filter=args.source)

    if args.query:
        run_retrieval_test(
            query=args.query,
            source_filter=args.source,
            k=args.k,
            min_score=args.score,
        )
    else:
        print_sep("Gợi ý")
        print("  Chạy lại với --query để test retrieval, ví dụ:")
        print('  python tests/inspect_kb.py --query "botnet C2 beaconing port 8080"')
        print('  python tests/inspect_kb.py --query "SQL injection blind" --score 0.5')

    print(f"\n{SEP}\n")


if __name__ == "__main__":
    main()
