import argparse
import json
import uuid
from pathlib import Path
import pandas as pd
import torch
from sentence_transformers import SentenceTransformer
from tqdm import tqdm
import numpy as np
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchValue, FilterSelector

import yaml

try:
    with open("params.yaml", "r", encoding="utf-8") as f:
        _params = yaml.safe_load(f)
    EMBED_MODEL = _params["embedding"]["model_name"]
    VECTOR_SIZE = _params["embedding"]["dim"]
except Exception as e:
    print(f"Warning: Failed to load params.yaml, using defaults. Error: {e}")
    EMBED_MODEL = "BAAI/bge-base-en-v1.5"
    VECTOR_SIZE = 768

COLLECTION  = "cyber_chunks"
SOURCES = {
    "mitre":    Path("data/processed/MITRE/chunks.parquet"),
    "sigma":    Path("data/processed/sigma/chunks.parquet"),
    "et_rules": Path("data/processed/emerging_threats/chunks.parquet"),
}


def get_device() -> torch.device:
    if torch.cuda.is_available():
        torch.backends.cuda.matmul.allow_tf32 = True
        torch.backends.cudnn.benchmark = True
        return torch.device("cuda")
    return torch.device("cpu")


def get_model_kwargs() -> dict:
    if torch.cuda.is_available():
        return {"torch_dtype": torch.float16}
    return {}


def load_chunks(parquet_path: Path) -> pd.DataFrame:
    df = pd.read_parquet(parquet_path, columns=["chunk_id", "doc_id", "source", "text", "metadata"])
    return df.dropna(subset=["chunk_id", "doc_id", "source", "text"])


def ensure_collection(client: QdrantClient) -> None:
    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION not in existing:
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        )
        print(f"[+] Created collection '{COLLECTION}'")


def _build_points(df: pd.DataFrame, embeddings: np.ndarray) -> list[PointStruct]:
    points = []
    for i, row in df.reset_index(drop=True).iterrows():
        try:
            meta = json.loads(row["metadata"]) if row.get("metadata") else {}
        except Exception:
            meta = {}

        payload = {
            "chunk_id": row["chunk_id"],
            "doc_id":   row["doc_id"],
            "source":   row["source"],
            "text":     row["text"],
            "metadata": {
                **meta,
                "chunk_id": row["chunk_id"],
                "doc_id":   row["doc_id"],
                "source":   row["source"],
            },
        }

        source = row["source"]
        if source == "mitre":
            payload.update({
                "technique_id": row["doc_id"],
                "tactics":      meta.get("tactics", ""),
            })
        elif source == "sigma":
            payload.update({
                "level": meta.get("level", ""),
                "tags":  meta.get("tags", ""),
            })
        elif source == "et_rules":
            payload.update({
                "classtype": meta.get("classtype", ""),
                "severity":  meta.get("severity", ""),
                "sid":       meta.get("sid", ""),
            })
        points.append(PointStruct(
            id=str(uuid.uuid4()),
            vector=embeddings[i].tolist(),
            payload=payload,
        ))
    return points


def delete_source(client: QdrantClient, source: str) -> None:
    client.delete(
        collection_name=COLLECTION,
        points_selector=FilterSelector(filter=Filter(must=[
            FieldCondition(key="metadata.source", match=MatchValue(value=source))
        ])),
    )
    print(f"[{source.upper()}] Deleted existing points from collection.")


def embed_and_upsert(source: str, chunks_path: Path, model: SentenceTransformer, client: QdrantClient, batch: int) -> None:
    if not chunks_path.is_file():
        print(f"[{source.upper()}] Chunk file not found: {chunks_path} - skipping.")
        return

    print(f"\n[{source.upper()}] Loading chunks from {chunks_path}...")
    df = load_chunks(chunks_path)
    print(f"[{source.upper()}] {len(df)} chunks loaded.")

    print(f"[{source.upper()}] Encoding...")
    # texts = [f"passage: {t}" for t in df["text"].tolist()]
    texts = df["text"].tolist()
    embeddings = model.encode(
        texts,
        batch_size=batch,
        show_progress_bar=True,
        convert_to_numpy=True,
        normalize_embeddings=True,
    ).astype(np.float32)

    points = _build_points(df, embeddings)

    for i in tqdm(range(0, len(points), 200), desc=f"[{source.upper()}] Upserting"):
        client.upsert(collection_name=COLLECTION, points=points[i:i + 200])

    print(f"[{source.upper()}] Done - {len(points)} points upserted.")
    if torch.cuda.is_available():
        torch.cuda.empty_cache()


def main():
    parser = argparse.ArgumentParser(description="Embed chunks and upsert to Qdrant.")
    parser.add_argument("--source", choices=list(SOURCES), default=None,
                        help="Source to embed. Omit to run all sources.")
    parser.add_argument("--batch", type=int, default=64)
    parser.add_argument("--recreate", action="store_true",
                        help="Drop and recreate the collection (removes old incompatible vectors).")
    args = parser.parse_args()

    sources_to_run = {args.source: SOURCES[args.source]} if args.source else SOURCES

    device = get_device()
    print(f"[i] Device: {device} | Model: {EMBED_MODEL}")
    model = SentenceTransformer(
        EMBED_MODEL, 
        device=device, 
        model_kwargs=get_model_kwargs(),
        trust_remote_code=True,
    )

    client = QdrantClient(host="localhost", port=6333, timeout=120)

    if args.recreate:
        existing = [c.name for c in client.get_collections().collections]
        if COLLECTION in existing:
            client.delete_collection(COLLECTION)
            print(f"[!] Deleted old collection '{COLLECTION}'")

    ensure_collection(client)

    for source, chunks_path in sources_to_run.items():
        delete_source(client, source)
        embed_and_upsert(source, chunks_path, model, client, args.batch)

    print(f"\n[+] All done. Collection: '{COLLECTION}'")

    # Write completion file for DVC tracking
    import datetime
    out_dir = Path("data/embeddings")
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "completed.txt", "w", encoding="utf-8") as f:
        f.write(f"Completed: {datetime.datetime.now().isoformat()}\n")
        f.write(f"Model: {EMBED_MODEL}\n")
        f.write(f"Collection: {COLLECTION}\n")
        f.write(f"Vector size: {VECTOR_SIZE}\n")
        f.write(f"Sources run: {list(sources_to_run.keys())}\n")


if __name__ == "__main__":
    main()
