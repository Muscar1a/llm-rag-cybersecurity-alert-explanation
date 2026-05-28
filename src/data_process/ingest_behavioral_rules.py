"""
Ingest behavioral flow-level detection rules into Qdrant.

These rules describe attack patterns observable from network flow statistics
(packet counts, byte ratios, TCP flags, window sizes, timing) rather than
payload content. They complement signature-based ET/Sigma rules, which cannot
match flow-level inputs.

Usage:
    python src/data_process/ingest_behavioral_rules.py
    python src/data_process/ingest_behavioral_rules.py --test-only
    python src/data_process/ingest_behavioral_rules.py --query "botnet ACK probe proxy port"

Input:  data/raw/behavioral_rules/behavioral_rules.json
Output: upserted to Qdrant collection 'cyber_chunks', source='behavioral_rules'
"""

import argparse
import json
import uuid
from pathlib import Path

import torch
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
RULES_FILE  = Path("data/raw/behavioral_rules/behavioral_rules_v3.json")
SOURCE_TAG  = "behavioral_rules"


# ---------------------------------------------------------------------------
# Text renderer (supports v3 schema)
# ---------------------------------------------------------------------------

def render_text(rule: dict) -> str:
    """
    Render a behavioral rule dict (v3 schema) into human-readable text for
    embedding. Includes keywords, MITRE ATT&CK reference, flow profile summary,
    and differential diagnosis to improve retrieval precision.

        Behavioral Rule: <name>
        Protocol: <proto> | Ports: <ports>
        Keywords: <keywords>
        MITRE ATT&CK: <tactic> | <technique_id> — <technique>
        Detection: <indicators>
        Flow profile: <key flow characteristics>
        Classtype: <classtype>
        Severity: <severity>
        Context: <explanation>
        Differential diagnosis: <distinguishing_factor>
    """
    lines = [f"Behavioral Rule: {rule['name']}"]

    proto = rule.get("proto", "TCP")
    ports = rule.get("dst_ports", [])
    port_str = f"dst_port:{','.join(str(p) for p in ports)}" if ports else ""
    lines.append(f"Protocol: {proto}" + (f" | Ports: {port_str}" if port_str else ""))

    # Keywords — semantic anchors for embedding
    keywords = rule.get("keywords", [])
    if keywords:
        lines.append(f"Keywords: {', '.join(keywords)}")

    # MITRE ATT&CK reference
    mitre = rule.get("mitre_attack", {})
    if mitre:
        tactic       = mitre.get("tactic", "")
        technique_id = mitre.get("technique_id", "")
        technique    = mitre.get("technique", "")
        sub          = mitre.get("sub_technique") or ""
        mitre_str    = f"{technique_id} — {technique}"
        if sub:
            mitre_str += f" ({sub})"
        lines.append(f"MITRE ATT&CK: {tactic} | {mitre_str}")

    # Indicators (Detection)
    indicators = rule.get("indicators", [])
    if indicators:
        lines.append("Detection: " + "; ".join(indicators))

    # Flow profile — structured behavioral description
    fp = rule.get("flow_profile", {})
    if fp:
        fp_parts = [
            f"{k}={v}" for k, v in fp.items()
            if v and str(v).lower() not in ("varies", "")
        ]
        if fp_parts:
            lines.append("Flow profile: " + "; ".join(fp_parts))

    if rule.get("classtype"):
        lines.append(f"Classtype: {rule['classtype']}")

    if rule.get("severity"):
        lines.append(f"Severity: {rule['severity']}")

    if rule.get("context"):
        lines.append(f"Context: {rule['context']}")

    # Differential diagnosis — helps LLM distinguish similar patterns
    dd = rule.get("differential_diagnosis", {})
    if dd.get("distinguishing_factor"):
        lines.append(f"Differential diagnosis: {dd['distinguishing_factor']}")

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


def delete_behavioral_rules(client: QdrantClient) -> None:
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

def ingest(rules_file: Path = RULES_FILE) -> None:
    print(f"\n[1/4] Loading rules from {rules_file} ...")
    with open(rules_file, encoding="utf-8") as f:
        rules = json.load(f)
    print(f"  Loaded {len(rules)} behavioral rules.")

    print(f"\n[2/4] Loading embedding model: {EMBED_MODEL}")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"  Device: {device}")
    model = SentenceTransformer(
        EMBED_MODEL,
        device=device,
        model_kwargs={"torch_dtype": torch.float16} if torch.cuda.is_available() else {},
        trust_remote_code=True,
    )

    texts = [render_text(r) for r in rules]

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
    delete_behavioral_rules(client)

    points = []
    for i, (rule, text, emb) in enumerate(zip(rules, texts, embeddings)):
        rule_id = rule.get("id", f"BHR-{i:03d}")
        chunk_id = f"{rule_id}_c0"
        points.append(PointStruct(
            id=str(uuid.uuid4()),
            vector=emb.tolist(),
            payload={
                "chunk_id":  chunk_id,
                "doc_id":    rule_id,
                "source":    SOURCE_TAG,
                "text":      text,
                "classtype": rule.get("classtype", ""),
                "severity":  rule.get("severity", ""),
                "metadata": {
                    "chunk_id":  chunk_id,
                    "source":    SOURCE_TAG,
                    "rule_id":   rule_id,
                    "classtype": rule.get("classtype", ""),
                    "severity":  rule.get("severity", ""),
                },
            },
        ))

    client.upsert(collection_name=COLLECTION, points=points)
    print(f"\n[+] Done. {len(points)} behavioral_rules points in collection '{COLLECTION}'.")

    # Preview sample
    print("\n--- Sample rule text ---")
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
    parser = argparse.ArgumentParser(description="Ingest behavioral flow rules into Qdrant.")
    parser.add_argument("--rules-file", default=str(RULES_FILE),
                        help="Path to behavioral_rules.json")
    parser.add_argument("--query",     default="botnet ACK probe proxy port custom TCP stack",
                        help="Test query after ingestion")
    parser.add_argument("--score",     type=float, default=0.50,
                        help="Score threshold for test query")
    parser.add_argument("--test-only", action="store_true",
                        help="Skip ingestion, only run query test")
    args = parser.parse_args()

    if not args.test_only:
        ingest(Path(args.rules_file))

    query_test(args.query, args.score)
