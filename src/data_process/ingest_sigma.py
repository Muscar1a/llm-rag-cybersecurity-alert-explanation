"""
Ingest Sigma detection rules into Qdrant.

Only the 'network' category is loaded by default — most relevant for network
traffic analysis. Use --categories to add windows/linux/cloud if needed.

Usage:
    python src/data_process/ingest_sigma.py
    python src/data_process/ingest_sigma.py --categories network windows
    python src/data_process/ingest_sigma.py --test-only
    python src/data_process/ingest_sigma.py --query "C2 beaconing proxy connection"

Input:  data/raw/sigma/<category>/**/*.yml
Output: upserted to Qdrant collection 'cyber_chunks', source='sigma'
"""

import argparse
import json
import uuid
from glob import glob
from pathlib import Path

import torch
import yaml
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance, VectorParams, PointStruct,
    Filter, FieldCondition, MatchValue, FilterSelector,
)
from sentence_transformers import SentenceTransformer

# ---------------------------------------------------------------------------
# Config — mirrors ingest_et_rules.py
# ---------------------------------------------------------------------------
COLLECTION  = "cyber_chunks"
EMBED_MODEL = "BAAI/bge-base-en-v1.5"
VECTOR_SIZE = 768
SOURCE_TAG  = "sigma"
SIGMA_BASE  = Path("data/raw/sigma")

DEFAULT_CATEGORIES = ["network"]


# ---------------------------------------------------------------------------
# Parser + renderer
# ---------------------------------------------------------------------------

def parse_rule(filepath: str) -> dict | None:
    try:
        with open(filepath, encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        if not rule or not isinstance(rule, dict) or not rule.get("title"):
            return None
        return {
            "title":          rule.get("title", ""),
            "description":    (rule.get("description") or ""),
            "status":         rule.get("status", ""),
            "level":          rule.get("level", ""),
            "tags":           rule.get("tags") or [],
            "logsource":      str(rule.get("logsource", {})),
            "falsepositives": rule.get("falsepositives") or [],
            "detection":      str(rule.get("detection", {})),
        }
    except Exception:
        return None


def render_text(rule: dict) -> str:
    """
    Render a Sigma rule dict into human-readable text for embedding.

        Rule: <title>
        Severity Level: <level>
        Log Source: <logsource>
        Tags: <tags>
        Description: <description>
        Detection: <detection>
        False Positives: <falsepositives>
    """
    lines = [
        f"Rule: {rule['title']}",
        f"Severity Level: {rule['level']}",
        f"Log Source: {rule['logsource']}",
    ]
    if rule["tags"]:
        lines.append(f"Tags: {', '.join(rule['tags'])}")
    if rule["description"]:
        lines.append(f"Description: {rule['description'][:600]}")
    lines.append(f"Detection: {rule['detection']}")
    if rule["falsepositives"]:
        lines.append(f"False Positives: {', '.join(str(fp) for fp in rule['falsepositives'])}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_rules(categories: list[str]) -> list[tuple[str, dict]]:
    """Return list of (filepath, parsed_rule) for all valid rules in categories."""
    results = []
    for cat in categories:
        pattern = str(SIGMA_BASE / cat / "**" / "*.yml")
        for filepath in glob(pattern, recursive=True):
            rule = parse_rule(filepath)
            if rule:
                results.append((filepath, rule))
        print(f"  [{cat}] {sum(1 for p, _ in results if cat in p)} rules loaded")
    return results


# ---------------------------------------------------------------------------
# Qdrant helpers
# ---------------------------------------------------------------------------

def ensure_collection(client: QdrantClient) -> None:
    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION not in existing:
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        )
        print(f"[+] Created collection '{COLLECTION}'")


def delete_sigma(client: QdrantClient) -> None:
    client.delete(
        collection_name=COLLECTION,
        points_selector=FilterSelector(filter=Filter(must=[
            FieldCondition(key="metadata.source", match=MatchValue(value=SOURCE_TAG))
        ])),
    )
    print(f"[+] Removed old '{SOURCE_TAG}' points from collection.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def ingest(categories: list[str] = DEFAULT_CATEGORIES) -> None:
    print(f"\n[1/4] Loading Sigma rules from categories: {categories}")
    rule_pairs = load_rules(categories)
    if not rule_pairs:
        print(f"[!] No rules found under {SIGMA_BASE}. Check that data/raw/sigma/ exists.")
        return
    print(f"  Total: {len(rule_pairs)} rules.")

    print(f"\n[2/4] Loading embedding model: {EMBED_MODEL}")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"  Device: {device}")
    model = SentenceTransformer(
        EMBED_MODEL,
        device=device,
        model_kwargs={"torch_dtype": torch.float16} if torch.cuda.is_available() else {},
        trust_remote_code=True,
    )

    texts = [render_text(rule) for _, rule in rule_pairs]

    print(f"\n[3/4] Encoding {len(texts)} rules...")
    embeddings = model.encode(
        texts,
        batch_size=64,
        show_progress_bar=True,
        convert_to_numpy=True,
        normalize_embeddings=True,
    )

    print("\n[4/4] Upserting to Qdrant...")
    client = QdrantClient(host="localhost", port=6333)
    ensure_collection(client)
    delete_sigma(client)

    points = []
    for i, ((filepath, rule), text, emb) in enumerate(zip(rule_pairs, texts, embeddings)):
        safe_id  = rule["title"].lower().replace(" ", "_").replace("/", "_")[:60]
        chunk_id = f"sigma_{safe_id}_c0"
        doc_id   = f"sigma_{safe_id}"
        points.append(PointStruct(
            id=str(uuid.uuid4()),
            vector=emb.tolist(),
            payload={
                "chunk_id": chunk_id,
                "doc_id":   doc_id,
                "source":   SOURCE_TAG,
                "text":     text,
                "level":    rule["level"],
                "tags":     rule["tags"],
                "metadata": {
                    "chunk_id":  chunk_id,
                    "source":    SOURCE_TAG,
                    "level":     rule["level"],
                    "tags":      json.dumps(rule["tags"]),
                    "logsource": rule["logsource"],
                },
            },
        ))

    for i in range(0, len(points), 200):
        client.upsert(collection_name=COLLECTION, points=points[i:i + 200])
        print(f"  Upserted {min(i + 200, len(points))}/{len(points)}")

    print(f"\n[+] Done. {len(points)} sigma points in collection '{COLLECTION}'.")
    print("\n--- Sample rule text ---")
    print(texts[0] if texts else "(none)")


def query_test(query: str, score: float) -> None:
    """Quick retrieval test after ingestion."""
    model  = SentenceTransformer(EMBED_MODEL, trust_remote_code=True)
    client = QdrantClient(host="localhost", port=6333)
    vec    = model.encode(query, normalize_embeddings=True).tolist()
    hits   = client.search(
        collection_name=COLLECTION,
        query_vector=vec,
        limit=5,
        score_threshold=score,
        query_filter=Filter(must=[
            FieldCondition(key="metadata.source", match=MatchValue(value=SOURCE_TAG))
        ]),
    )
    print(f"\n--- Query: '{query}' (min_score={score}) ---")
    if not hits:
        print("  No results above threshold.")
    for h in hits:
        print(f"  [{h.score:.4f}] {h.payload.get('text', '')[:150]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest Sigma rules into Qdrant.")
    parser.add_argument(
        "--categories", nargs="+", default=DEFAULT_CATEGORIES,
        choices=["network", "windows", "linux", "cloud"],
        help="Sigma categories to ingest (default: network only)",
    )
    parser.add_argument("--query",     default="botnet C2 network connection unusual port",
                        help="Test query after ingestion")
    parser.add_argument("--score",     type=float, default=0.50,
                        help="Score threshold for test query")
    parser.add_argument("--test-only", action="store_true",
                        help="Skip ingestion, only run query test")
    args = parser.parse_args()

    if not args.test_only:
        ingest(args.categories)

    query_test(args.query, args.score)
