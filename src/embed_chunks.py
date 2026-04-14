import argparse
import json
from pathlib import Path
import pandas as pd
import torch
from sentence_transformers import SentenceTransformer
from tqdm import tqdm
import numpy as np

def get_device() -> torch.device:
    if torch.cuda.is_available():
        torch.backends.cuda.matmul.allow_tf32 = True
        torch.backends.cudnn.benchmark = True
        return torch.device("cuda")
    return torch.device("cpu")


def load_chunks(parquet_path: Path) -> pd.DataFrame:
    if not parquet_path.is_file():
        raise FileNotFoundError(f"Chunk file not found: {parquet_path}")
    df = pd.read_parquet(parquet_path, columns=["chunk_id", "doc_id", "source", "text", "metadata"])
    if df.isnull().any().any():
        df = df.dropna(subset=["chunk_id", "doc_id", "source", "text", "metadata"])
    return df


def chunk_batcher(df: pd.DataFrame, batch_size: int):
    n = len(df)
    for start in range(0, n, batch_size):
        end = min(start + batch_size, n)
        batch = df.iloc[start:end]
        yield batch["chunk_id"].tolist(), batch["text"].tolist()
        

def save_embeddings(out_dir: Path, embeddings: np.ndarray, ids: list, dtype=np.float16):
    out_dir.mkdir(parents=True, exist_ok=True)
    
    emb_path = out_dir / "embeddings.npy"
    ids_path = out_dir / "chunk_ids.csv"
    
    np.save(emb_path, embeddings.astype(dtype))
    pd.Series(ids).to_csv(ids_path, index=False, header=False)
    print(f"[+] Saved embeddings to  {emb_path}")
    print(f"[+] Saved ids to         {ids_path}")

    
    
def main():
    parser = argparse.ArgumentParser(
        description="Create dense embeddings for knowledge-base chunks."
    )
    parser.add_argument("--source", required=True, choices=["cve", "mitre"])
    parser.add_argument("--model", default="intfloat/e5-small-v2")
    parser.add_argument("--batch", type=int, default=512,
        help="Batch size cho model.encode() — try 512, 1024, 2048.",
    )
    args = parser.parse_args()

    source_dir_map = {
        "cve": "CVE",
        "mitre": "MITRE",
    }
    processed_source_dir = source_dir_map[args.source]

    chunks_path = Path("data/processed") / processed_source_dir / "chunks.parquet"
    out_dir = Path("data/embeddings") / args.source
    out_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"[i] Loading chunks for source: {args.source}")
    df = load_chunks(chunks_path)
    print(f"[i] {len(df)} chunks loaded.")
    
    device = get_device()
    print(f"[i] Using device: {device}")
    
    print(f"[i] Loading model: {args.model}")
    model = SentenceTransformer(args.model, device=device)
    model.max_seq_length = 512
    
    if device.type == "cuda":
        model.half()
        
    all_ids = df["chunk_id"].tolist()
    all_texts = df["text"].tolist()
    
    print(f"[i] Encoding {len(all_texts)} chunks with batch size {args.batch}...")
    
    embeddings_arr = model.encode(
        all_texts,
        batch_size=args.batch,
        show_progress_bar=True,
        convert_to_numpy=True,
        normalize_embeddings=True,
        device=device
    )
    
    embeddings_arr = embeddings_arr.astype(np.float16)
    
    print(f"[i] Final embeddings shape: {embeddings_arr.shape}")
    save_embeddings(out_dir, embeddings_arr, all_ids, dtype=np.float16)
    
if __name__ == "__main__":
    main()