import argparse
import json
import uuid
import numpy as np
import pandas as pd
from qdrant_client import models
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from src.rag.qdrant_store import build_client, ensure_collection
from src.rag.settings import settings

def load_vectors(source: str):
    ids_path = Path("data/embeddings") / source / "chunk_ids.csv"
    emb_path = Path("data/embeddings") / source / "embeddings.npy"
    
    ids = pd.read_csv(ids_path, header=None)[0].astype(str).tolist()
    vecs = np.load(emb_path)
    return ids, vecs


def load_payload_df(source: str) -> pd.DataFrame:
    source_dir = {"cve": "CVE", "mitre": "MITRE"}[source]
    path = Path("data/processed") / source_dir / "chunks.parquet"
    df = pd.read_parquet(path, columns=["chunk_id", "doc_id", "source", "text", "metadata"])
    
    def parse_meta(v):
        if isinstance(v, dict):
            return v
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return {}
        return {}
    
    df["metadata"] = df["metadata"].apply(parse_meta)
    return df


def build_points(ids, vecs, payload_df: pd.DataFrame):
    payload_map = payload_df.set_index("chunk_id").to_dict(orient="index")
    points = []
    
    for i, chunk_id in enumerate(ids):
        row = payload_map.get(chunk_id)
        if row is None:
            continue
        
        payload = {
            "chunk_id": chunk_id,
            "doc_id": row["doc_id"],
            "source": row["source"],
            "text": row["text"],
            "metadata": row["metadata"],
        }
        
        points.append(
            models.PointStruct(
                id=str(uuid.uuid5(uuid.NAMESPACE_URL, chunk_id)),
                vector=vecs[i].astype(np.float32).tolist(),
                payload=payload
            )
        )
    return points


def upsert_in_batches(client, points, batch_size: int):
    total = len(points)
    for start in range(0, total, batch_size):
        end = min(start + batch_size, total)
        client.upsert(
            collection_name=settings.qdrant_collection,
            points=points[start:end],
            wait=True,
        )
        print(f"[upsert] {end}/{total}")
        
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, choices=["cve", "mitre"])
    parser.add_argument("--batch", type=int, default=256)
    args = parser.parse_args()
    
    ids, vecs = load_vectors(args.source)
    df = load_payload_df(args.source)
    
    if len(ids) != len(vecs):
        raise ValueError(f"IDs ({len(ids)}) != vectors ({len(vecs)})")
    
    client = build_client()
    ensure_collection(client, vector_size=vecs.shape[1])
    
    points = build_points(ids, vecs, df)
    print(f"[build] points ready: {len(points)}")
    
    upsert_in_batches(client, points, batch_size=args.batch)
    
    count = client.count(collection_name=settings.qdrant_collection, exact=True).count
    print(f"[done] total points in collection: {count}")