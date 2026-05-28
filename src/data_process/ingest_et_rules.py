"""
Ingest Emerging Threats Suricata rules into Qdrant.

Usage:
    python src/data_process/ingest_et_rules.py
    python src/data_process/ingest_et_rules.py --files emerging-scan.rules emerging-dos.rules
    python src/data_process/ingest_et_rules.py --score 0.0  # query-test only

Mirrors the style of ingest_sigma.py but for Snort/Suricata rule format.
Embedding model: BAAI/bge-base-en-v1.5 (768-dim, same as the rest of the pipeline).
"""

import argparse
import json
import re
import uuid
from pathlib import Path

import torch
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance, VectorParams, PointStruct,
    Filter, FieldCondition, MatchValue,
)
from sentence_transformers import SentenceTransformer

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
COLLECTION  = "cyber_chunks"
EMBED_MODEL = "BAAI/bge-base-en-v1.5"
VECTOR_SIZE = 768
RAW_DIR     = Path("data/raw/emerging_threats")

DEFAULT_FILES = [
    "emerging-scan.rules",
    "emerging-dos.rules",
    "emerging-sql.rules",
    "emerging-web_specific_apps.rules",
    "emerging-policy.rules",
]

# Rules from these files are kept in full (no keyword filter)
IMPORT_ALL = {
    "emerging-scan.rules",
    "emerging-dos.rules",
    "emerging-sql.rules",
}

# Keyword filter for large files (web_specific_apps, policy)
KEEP_KEYWORDS = [
    "brute", "xss", "cross-site", "sql", "injection",
    "botnet", "c2", "beacon", "c&c", "command and control",
    "ssh", "ftp", "telnet", "rdp",
    "dos", "flood", "slowloris", "slow http",
    "scan", "sweep", "cleartext", "non-standard port",
    "infiltrat", "exfiltrat", "tunnel",
]


# ---------------------------------------------------------------------------
# Rule parser
# ---------------------------------------------------------------------------

def _extract_quoted(field: str, text: str) -> str | None:
    m = re.search(rf'{field}:"([^"]*)"', text)
    return m.group(1).strip() if m else None


def parse_rule(line: str) -> dict | None:
    """Parse a single Suricata/Snort rule line. Returns None for comments/blanks."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if not re.match(r'^(alert|drop|pass|reject|log)\s', line):
        return None

    header = re.match(
        r'^(\w+)\s+(\w+)\s+\S+\s+(\S+)\s+(?:->|<>)\s+\S+\s+(\S+)',
        line,
    )
    if not header:
        return None
    _, proto, src_port, dst_port = header.groups()

    opts_m = re.search(r'\((.+)\)\s*$', line, re.DOTALL)
    if not opts_m:
        return None
    opts = opts_m.group(1)

    msg       = _extract_quoted("msg", opts)
    classtype = _extract_quoted("classtype", opts)
    sid_m     = re.search(r'\bsid:(\d+)', opts)
    sid       = sid_m.group(1) if sid_m else ""
    contents  = re.findall(r'content:"([^"]*)"', opts)
    refs      = re.findall(r'reference:([^;]+)', opts)

    # signature_severity from metadata block
    severity = ""
    meta_m = re.search(r'metadata:([^;]+)', opts)
    if meta_m:
        sev_m = re.search(r'signature_severity\s+(\S+)', meta_m.group(1))
        if sev_m:
            severity = sev_m.group(1).strip(" ,)")

    if not msg:
        return None

    return {
        "sid":       sid,
        "msg":       msg,
        "proto":     proto.upper(),
        "src_port":  src_port,
        "dst_port":  dst_port,
        "classtype": classtype or "",
        "severity":  severity,
        "contents":  contents,
        "refs":      refs,
    }


def render_text(r: dict) -> str:
    """Render a parsed rule into human-readable text for embedding."""
    lines = [f"Rule: {r['msg']}"]

    port_parts = []
    for label, val in [("src_port", r["src_port"]), ("dst_port", r["dst_port"])]:
        if val not in ("any", "$EXTERNAL_NET", "$HTTP_SERVERS", "$HTTP_PORTS", ""):
            port_parts.append(f"{label}:{val}")
    port_str = " | ".join(port_parts)
    lines.append(f"Protocol: {r['proto']}" + (f" | Ports: {port_str}" if port_str else ""))

    if r["contents"]:
        content_str = "; ".join(repr(c) for c in r["contents"][:3])
        lines.append(f"Detection: {content_str}")

    if r["classtype"]:
        lines.append(f"Classtype: {r['classtype']}")
    if r["severity"]:
        lines.append(f"Severity: {r['severity']}")
    if r["refs"]:
        lines.append(f"Reference: {'; '.join(r['refs'][:2])}")

    return "\n".join(lines)


def _should_keep(msg: str, filename: str) -> bool:
    if filename in IMPORT_ALL:
        return True
    msg_lower = msg.lower()
    return any(kw in msg_lower for kw in KEEP_KEYWORDS)


# ---------------------------------------------------------------------------
# Load rules from files
# ---------------------------------------------------------------------------

def load_rules(rule_files: list[str]) -> list[dict]:
    all_rules = []
    for filename in rule_files:
        filepath = RAW_DIR / filename
        if not filepath.is_file():
            print(f"[SKIP] Not found: {filepath}")
            continue

        kept = 0
        filtered = 0
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = parse_rule(line)
                if parsed is None:
                    continue
                if not _should_keep(parsed["msg"], filename):
                    filtered += 1
                    continue
                parsed["source_file"] = filename
                all_rules.append(parsed)
                kept += 1

        print(f"  [{filename}] kept={kept}, filtered={filtered}")

    return all_rules


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


def delete_et_rules(client: QdrantClient) -> None:
    from qdrant_client.models import FilterSelector
    client.delete(
        collection_name=COLLECTION,
        points_selector=FilterSelector(filter=Filter(must=[
            FieldCondition(key="metadata.source", match=MatchValue(value="et_rules"))
        ])),
    )
    print("[+] Removed old et_rules points from collection.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def ingest(rule_files: list[str]) -> None:
    print(f"\n[1/4] Parsing rules from {len(rule_files)} file(s)...")
    rules = load_rules(rule_files)
    if not rules:
        print("[!] No rules loaded. Check that files exist in data/raw/emerging_threats/")
        return
    print(f"  Total rules loaded: {len(rules)}")

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
    delete_et_rules(client)

    points = []
    for i, (r, text, emb) in enumerate(zip(rules, texts, embeddings)):
        chunk_id = f"et_{r['sid']}_c0" if r["sid"] else f"et_rule_{i}_c0"
        meta = {
            "classtype":   r["classtype"],
            "severity":    r["severity"],
            "sid":         r["sid"],
            "source_file": r["source_file"],
        }
        points.append(PointStruct(
            id=str(uuid.uuid4()),
            vector=emb.tolist(),
            payload={
                "chunk_id": chunk_id,
                "doc_id":   r["sid"] or f"et_rule_{i}",
                "source":   "et_rules",
                "text":     text,
                "classtype": r["classtype"],
                "severity":  r["severity"],
                "sid":       r["sid"],
                "metadata": {
                    "chunk_id": chunk_id,
                    "source":   "et_rules",
                    **meta,
                },
            },
        ))

    for i in range(0, len(points), 200):
        client.upsert(collection_name=COLLECTION, points=points[i:i + 200])
        print(f"  Upserted {min(i + 200, len(points))}/{len(points)}")

    print(f"\n[+] Done. {len(points)} et_rules points in collection '{COLLECTION}'.")

    # Save processed rules to JSON for reference
    out_json = Path("data/processed/emerging_threats/et_rules.json")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(
            [{"sid": r["sid"], "msg": r["msg"], "classtype": r["classtype"],
              "severity": r["severity"], "source_file": r["source_file"]} for r in rules],
            f, indent=2, ensure_ascii=False,
        )
    print(f"[+] Rule index saved → {out_json}")


def query_test(query: str, score: float) -> None:
    """Quick retrieval test after ingestion."""
    from sentence_transformers import SentenceTransformer as ST
    model  = ST(EMBED_MODEL, trust_remote_code=True)
    client = QdrantClient(host="localhost", port=6333)
    vec    = model.encode(query, normalize_embeddings=True).tolist()
    hits   = client.search(
        collection_name=COLLECTION,
        query_vector=vec,
        limit=5,
        score_threshold=score,
        query_filter=Filter(must=[
            FieldCondition(key="metadata.source", match=MatchValue(value="et_rules"))
        ]),
    )
    print(f"\n--- Query: '{query}' (min_score={score}) ---")
    if not hits:
        print("  No results.")
    for h in hits:
        print(f"  [{h.score:.4f}] {h.payload.get('text', '')[:120]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", nargs="+", default=DEFAULT_FILES,
                        help="Rule files to ingest (from data/raw/emerging_threats/)")
    parser.add_argument("--query", default="port scan TCP SYN sweep reconnaissance",
                        help="Test query after ingestion")
    parser.add_argument("--score", type=float, default=0.60,
                        help="Score threshold for test query")
    parser.add_argument("--test-only", action="store_true",
                        help="Skip ingestion, only run query test")
    args = parser.parse_args()

    if not args.test_only:
        ingest(args.files)

    query_test(args.query, args.score)
