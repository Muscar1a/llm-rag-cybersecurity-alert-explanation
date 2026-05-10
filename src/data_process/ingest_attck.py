from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer
from parse_attck import load_attack_techniques
import uuid
import json
import os

COLLECTION = "cyber_chunks"


def ingest_attck():
    client = QdrantClient(host="localhost", port=6333)
    model  = SentenceTransformer("all-MiniLM-L6-v2")

    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION not in existing:
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=384, distance=Distance.COSINE),
        )

    techniques = load_attack_techniques()

    output_dir  = os.path.join("data", "processed", "MITRE")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "techniques.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=4)
    print(f"Techniques saved to {output_path}")

    points = []
    for tech in techniques:
        text = (
            f"Technique: {tech['id']} - {tech['name']}\n"
            f"Tactics: {', '.join(tech['tactics'])}\n"
            f"Platforms: {', '.join(tech['platforms'])}\n"
            f"Description: {tech['description'][:1000]}\n"
            f"Detection: {tech['detection'][:500]}"
        )
        vector = model.encode(text).tolist()
        points.append(PointStruct(
            id=str(uuid.uuid4()),
            vector=vector,
            payload={
                "text":           text,
                "source":         "mitre_attck",
                "technique_id":   tech["id"],
                "technique_name": tech["name"],
                "tactics":        tech["tactics"],
                "url":            tech["url"],
            },
        ))

    for i in range(0, len(points), 100):
        client.upsert(collection_name=COLLECTION, points=points[i:i + 100])
        print(f"Ingested {min(i + 100, len(points))}/{len(points)}")

    print("ATT&CK ingestion complete!")


if __name__ == "__main__":
    ingest_attck()
