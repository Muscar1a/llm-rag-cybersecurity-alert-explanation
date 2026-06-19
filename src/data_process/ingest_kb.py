"""
Ingest KB v2 (4 groups) into Qdrant.

No chunking: each JSONL entry is already a self-contained chunk (design doc §3),
so we embed entry["document"] whole — one entry = one vector. The chunking:
section in params.yaml is for the legacy raw-source pipeline, not this one.

Usage:
    python src/data_process/ingest_kb.py
    python src/data_process/ingest_kb.py --group port_profile
    python src/data_process/ingest_kb.py --test-only --query "port 445 SMB lateral movement"

Input:  data/kb/{port_profile,conn_state,traffic_pattern,tatic_profile}/*.jsonl
Output: upserted to Qdrant collection 'cyber_chunks', source='kb_v2'
"""

import argparse
import json
import uuid
from pathlib import Path

import torch
import yaml
from qdrant_client import QdrantClient
from qdrant_client.models import (
    PointStruct,
    Filter, FieldCondition, MatchValue, FilterSelector,
)
from sentence_transformers import SentenceTransformer

try:
    with open("params.yaml", encoding="utf-8") as f:
        _params = yaml.safe_load(f)
    EMBED_MODEL = _params["embedding"]["model_name"]
    VECTOR_SIZE = _params["embedding"]["dim"]
    BATCH_SIZE  = _params["embedding"]["batch_size"]
except Exception as e:
    print(f"Warning: could not load params.yaml ({e}), using defaults.")
    EMBED_MODEL = "BAAI/bge-base-en-v1.5"
    VECTOR_SIZE = 768
    BATCH_SIZE  = 64

COLLECTION = "cyber_chunks"
SOURCE_TAG = "kb_v2"
KB_ROOT    = Path("data/kb")

GROUPS = {
    "port_profile":    KB_ROOT / "port_profile"   / "port_profiles.jsonl",
    "conn_state":      KB_ROOT / "conn_state"      / "conn_state_profiles.jsonl",
    "traffic_pattern": KB_ROOT / "traffic_pattern" / "traffic_pattern_profiles.jsonl",
    "tactic":          KB_ROOT / "tactic_profile"  / "tactic_profiles.jsonl",
}


def load_group(path: Path) -> list[dict]:
    entries = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def build_payload(entry: dict, text: str) -> dict:
    meta    = entry.get("metadata", {})
    kb_type = meta.get("kb_type", "")

    payload = {
        "chunk_id": entry["id"],
        "doc_id":   entry["id"],
        "source":   SOURCE_TAG,
        "text":     text,
        "kb_type":  kb_type,
        "metadata": {"source": SOURCE_TAG, "kb_type": kb_type},
    }

    # Hoist filterable fields to top-level for Qdrant where-filter
    extra: dict = {}
    if kb_type == "port_profile":
        extra = {k: meta[k] for k in ("port", "protocol", "service_name", "cve_ids") if k in meta}
    elif kb_type == "conn_state":
        extra = {k: meta[k] for k in ("state_code",) if k in meta}
    elif kb_type == "traffic_pattern":
        extra = {k: meta[k] for k in ("pattern_id", "scope") if k in meta}
    elif kb_type == "tactic":
        extra = {k: meta[k] for k in ("tactic",) if k in meta}

    payload.update(extra)
    payload["metadata"].update(extra)
    return payload


def warn_truncation(model: SentenceTransformer, entries: list[dict], texts: list[str]) -> None:
    """bge truncates (not chunks) past max_seq_length — flag entries that lose their tail."""
    max_len = model.max_seq_length
    tok = model.tokenizer
    over = 0
    for entry, text in zip(entries, texts):
        n = len(tok.encode(text, add_special_tokens=True))
        if n > max_len:
            over += 1
            print(f"  [WARN] {entry['id']}: {n} tokens > {max_len} — tail will be truncated")
    if over:
        print(f"  [!] {over} entry(s) exceed {max_len} tokens. Consider trimming the entry text.")
    else:
        print(f"  [ok] All entries fit within {max_len} tokens — no truncation.")


def ensure_collection(client: QdrantClient) -> None:
    from src.rag.qdrant_store import ensure_collection as _ensure
    _ensure(client, VECTOR_SIZE)


def delete_kb_group(client: QdrantClient, kb_type: str) -> None:
    client.delete(
        collection_name=COLLECTION,
        points_selector=FilterSelector(filter=Filter(must=[
            FieldCondition(key="metadata.source",  match=MatchValue(value=SOURCE_TAG)),
            FieldCondition(key="metadata.kb_type", match=MatchValue(value=kb_type)),
        ])),
    )
    print(f"[+] Removed old '{SOURCE_TAG}' kb_type={kb_type} points.")


def ingest(groups: dict[str, Path]) -> None:
    print(f"\n[1/4] Loading KB entries from {len(groups)} group(s)...")
    all_entries: list[dict] = []
    for name, path in groups.items():
        if not path.is_file():
            print(f"  [SKIP] Not found: {path}")
            continue
        entries = load_group(path)
        print(f"  [{name}] {len(entries)} entries")
        all_entries.extend(entries)

    if not all_entries:
        print("[!] No entries loaded.")
        return
    print(f"  Total: {len(all_entries)} entries")

    print(f"\n[2/4] Loading embedding model: {EMBED_MODEL}")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"  Device: {device}")
    model = SentenceTransformer(
        EMBED_MODEL,
        device=device,
        model_kwargs={"torch_dtype": torch.float16} if torch.cuda.is_available() else {},
        trust_remote_code=True,
    )

    texts = [e["document"] for e in all_entries]

    print("  Checking token lengths (no chunking — whole entry embedded)...")
    warn_truncation(model, all_entries, texts)

    print(f"\n[3/4] Encoding {len(texts)} entries...")
    embeddings = model.encode(
        texts,
        batch_size=BATCH_SIZE,
        show_progress_bar=True,
        convert_to_numpy=True,
        normalize_embeddings=True,
    )

    print("\n[4/4] Upserting to Qdrant...")
    client = QdrantClient(host="localhost", port=6333)
    ensure_collection(client)

    for name in groups:
        delete_kb_group(client, kb_type=name)

    points = [
        PointStruct(
            id=str(uuid.uuid4()),
            vector=embeddings[i].tolist(),
            payload=build_payload(entry, texts[i]),
        )
        for i, entry in enumerate(all_entries)
    ]

    for i in range(0, len(points), 200):
        client.upsert(collection_name=COLLECTION, points=points[i:i + 200])
        print(f"  Upserted {min(i + 200, len(points))}/{len(points)}")

    print(f"\n[+] Done. {len(points)} kb_v2 points in collection '{COLLECTION}'.")


def query_test(query: str, score: float) -> None:
    model  = SentenceTransformer(EMBED_MODEL, trust_remote_code=True)
    client = QdrantClient(host="localhost", port=6333)
    vec    = model.encode(query, normalize_embeddings=True).tolist()
    result = client.query_points(
        collection_name=COLLECTION,
        query=vec,
        limit=5,
        score_threshold=score,
        query_filter=Filter(must=[
            FieldCondition(key="metadata.source", match=MatchValue(value=SOURCE_TAG))
        ]),
    )
    hits = result.points
    print(f"\n--- Query: '{query}' (min_score={score}) ---")
    if not hits:
        print("  No results above threshold.")
    for h in hits:
        print(f"  [{h.score:.4f}] [{h.payload.get('kb_type')}] {h.payload.get('text', '')[:150]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest KB v2 into Qdrant.")
    parser.add_argument("--group", choices=list(GROUPS), default=None,
                        help="Ingest only one group (default: all)")
    parser.add_argument("--query", default="port 445 SMB lateral movement brute force")
    parser.add_argument("--score", type=float, default=0.50)
    parser.add_argument("--test-only", action="store_true",
                        help="Skip ingestion, only run query test")
    args = parser.parse_args()

    groups = {args.group: GROUPS[args.group]} if args.group else GROUPS

    if not args.test_only:
        ingest(groups)

    query_test(args.query, args.score)
