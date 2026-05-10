import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
os.chdir(PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient

from data_process.clean_data import run_pipeline as clean_pipeline
from data_process.chunk_data import SOURCES as CHUNK_SOURCES, chunk_source
from data_process.embed_chunks import (
    SOURCES as EMBED_SOURCES,
    EMBED_MODEL,
    COLLECTION,
    get_device,
    ensure_collection,
    embed_and_upsert,
)


def main():
    print("=== STEP 1: CLEAN ===")
    clean_pipeline()

    device = get_device()
    print(f"[i] Device: {device} | Model: {EMBED_MODEL} | Collection: {COLLECTION}")
    model  = SentenceTransformer(EMBED_MODEL, device=device)
    client = QdrantClient(host="localhost", port=6333)
    ensure_collection(client)

    print("\n=== STEP 2: CHUNK ===")
    for source_cfg in CHUNK_SOURCES:
        chunk_source(source_cfg, model.tokenizer)

    print("\n=== STEP 3: EMBED & UPSERT ===")
    for source, chunks_path in EMBED_SOURCES.items():
        embed_and_upsert(source, chunks_path, model, client, batch=512)

    print(f"\n[+] Pipeline complete. Data in Qdrant collection '{COLLECTION}'.")


if __name__ == "__main__":
    main()
