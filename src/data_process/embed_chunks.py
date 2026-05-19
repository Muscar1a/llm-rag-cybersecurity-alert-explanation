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
from qdrant_client.models import Distance, VectorParams, PointStruct

EMBED_MODEL = "intfloat/e5-small-v2"
COLLECTION  = "cyber_chunks"
VECTOR_SIZE = 384

SOURCES = {
    "cve":   Path("data/processed/CVE/chunks.parquet"),
    "mitre": Path("data/processed/MITRE/chunks.parquet"),
    "sigma": Path("data/processed/sigma/chunks.parquet"),
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
                "chunk_id": row["chunk_id"],
                "doc_id":   row["doc_id"],
                "source":   row["source"],
                **meta,
            },
        }

        source = row["source"]
        if source == "cve":
            payload.update({
                "cve_id":        row["doc_id"],
                "cvss_score":    meta.get("cvss_score"),
                "cvss_severity": meta.get("cvss_severity"),
            })
        elif source == "mitre":
            payload.update({
                "technique_id": row["doc_id"],
                "tactics":      meta.get("tactics", ""),
            })
        elif source == "sigma":
            payload.update({
                "level": meta.get("level", ""),
                "tags":  meta.get("tags", ""),
            })

        points.append(PointStruct(
            id=str(uuid.uuid4()),
            vector=embeddings[i].tolist(),
            payload=payload,
        ))
    return points


def embed_and_upsert(source: str, chunks_path: Path, model: SentenceTransformer, client: QdrantClient, batch: int) -> None:
    if not chunks_path.is_file():
        print(f"[{source.upper()}] Chunk file not found: {chunks_path} — skipping.")
        return

    print(f"\n[{source.upper()}] Loading chunks from {chunks_path}...")
    df = load_chunks(chunks_path)
    print(f"[{source.upper()}] {len(df)} chunks loaded.")

    print(f"[{source.upper()}] Encoding...")
    texts = [f"passage: {t}" for t in df["text"].tolist()]
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

    print(f"[{source.upper()}] Done — {len(points)} points upserted.")
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
    model = SentenceTransformer(EMBED_MODEL, device=device, model_kwargs=get_model_kwargs())

    client = QdrantClient(host="localhost", port=6333)

    if args.recreate:
        existing = [c.name for c in client.get_collections().collections]
        if COLLECTION in existing:
            client.delete_collection(COLLECTION)
            print(f"[!] Deleted old collection '{COLLECTION}'")

    ensure_collection(client)

    for source, chunks_path in sources_to_run.items():
        embed_and_upsert(source, chunks_path, model, client, args.batch)

    print(f"\n[+] All done. Collection: '{COLLECTION}'")


if __name__ == "__main__":
    main()
