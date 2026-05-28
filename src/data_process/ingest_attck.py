"""
Ingest MITRE ATT&CK Enterprise techniques into Qdrant.

Usage:
    python src/data_process/ingest_attck.py
    python src/data_process/ingest_attck.py --test-only
    python src/data_process/ingest_attck.py --query "C2 beaconing proxy non-standard port"

Input:  data/raw/MITRE/enterprise-attack/enterprise-attack.json  (STIX bundle)
Output: upserted to Qdrant collection 'cyber_chunks', source='mitre_attck'
"""

import argparse
import sys
import uuid
from pathlib import Path

import torch
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance, VectorParams, PointStruct,
    Filter, FieldCondition, MatchValue, FilterSelector,
)
from sentence_transformers import SentenceTransformer

# Make project root importable regardless of working directory
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.data_process.parse_attck import load_attack_techniques

# ---------------------------------------------------------------------------
# Config — mirrors ingest_et_rules.py
# ---------------------------------------------------------------------------
COLLECTION  = "cyber_chunks"
EMBED_MODEL = "BAAI/bge-base-en-v1.5"
VECTOR_SIZE = 768
SOURCE_TAG  = "mitre_attck"


# ---------------------------------------------------------------------------
# Text renderer
# ---------------------------------------------------------------------------

def render_text(tech: dict) -> str:
    """
    Render an ATT&CK technique dict into human-readable text for embedding.

        ATT&CK Technique: T1071.001 — Application Layer Protocol: Web Protocols
        Tactics: command-and-control
        Platforms: Linux, Windows, macOS
        Description: <truncated>
        Detection: <truncated>
        Reference: https://attack.mitre.org/techniques/T1071/001/
    """
    lines = [f"ATT&CK Technique: {tech['id']} — {tech['name']}"]

    if tech.get("tactics"):
        lines.append(f"Tactics: {', '.join(tech['tactics'])}")

    if tech.get("platforms"):
        lines.append(f"Platforms: {', '.join(tech['platforms'])}")

    desc = (tech.get("description") or "").strip()
    if desc:
        lines.append(f"Description: {desc[:1200]}")

    detection = (tech.get("detection") or "").strip()
    if detection:
        lines.append(f"Detection: {detection[:600]}")

    if tech.get("url"):
        lines.append(f"Reference: {tech['url']}")

    return "\n".join(lines)


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


def delete_attck(client: QdrantClient) -> None:
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

def ingest() -> None:
    print("\n[1/4] Loading ATT&CK techniques...")
    techniques = load_attack_techniques()
    if not techniques:
        print("[!] No techniques loaded. Check data/raw/MITRE/enterprise-attack/enterprise-attack.json")
        return
    print(f"  Loaded {len(techniques)} techniques.")

    print(f"\n[2/4] Loading embedding model: {EMBED_MODEL}")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"  Device: {device}")
    model = SentenceTransformer(
        EMBED_MODEL,
        device=device,
        model_kwargs={"torch_dtype": torch.float16} if torch.cuda.is_available() else {},
        trust_remote_code=True,
    )

    texts = [render_text(t) for t in techniques]

    print(f"\n[3/4] Encoding {len(texts)} techniques...")
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
    delete_attck(client)

    points = []
    for i, (tech, text, emb) in enumerate(zip(techniques, texts, embeddings)):
        tech_id  = tech.get("id") or f"TUNK-{i:04d}"
        chunk_id = f"attck_{tech_id}_c0"
        points.append(PointStruct(
            id=str(uuid.uuid4()),
            vector=emb.tolist(),
            payload={
                "chunk_id":       chunk_id,
                "doc_id":         tech_id,
                "source":         SOURCE_TAG,
                "text":           text,
                "technique_id":   tech_id,
                "technique_name": tech.get("name", ""),
                "tactics":        tech.get("tactics", []),
                "url":            tech.get("url", ""),
                "metadata": {
                    "chunk_id":       chunk_id,
                    "source":         SOURCE_TAG,
                    "technique_id":   tech_id,
                    "technique_name": tech.get("name", ""),
                    "tactics":        tech.get("tactics", []),
                },
            },
        ))

    for i in range(0, len(points), 200):
        client.upsert(collection_name=COLLECTION, points=points[i:i + 200])
        print(f"  Upserted {min(i + 200, len(points))}/{len(points)}")

    print(f"\n[+] Done. {len(points)} mitre_attck points in collection '{COLLECTION}'.")

    print("\n--- Sample technique text ---")
    print(texts[0])


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
    parser = argparse.ArgumentParser(description="Ingest MITRE ATT&CK into Qdrant.")
    parser.add_argument("--query",     default="C2 beaconing proxy non-standard port custom TCP stack",
                        help="Test query after ingestion")
    parser.add_argument("--score",     type=float, default=0.50,
                        help="Score threshold for test query")
    parser.add_argument("--test-only", action="store_true",
                        help="Skip ingestion, only run query test")
    args = parser.parse_args()

    if not args.test_only:
        ingest()

    query_test(args.query, args.score)
