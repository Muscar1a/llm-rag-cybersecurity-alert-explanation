import json
from glob import glob
import yaml
import os
import uuid
from pathlib import Path
from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct
from sentence_transformers import SentenceTransformer

COLLECTION = "cyber_chunks"


def parse_sigma_rule(file_path: str) -> dict | None:
    try:
        with open(file_path, encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        if not rule or not isinstance(rule, dict):
            return None
        detection = rule.get("detection", {})
        detection_str = str(detection)
        
        return {
            "title":          rule.get("title", ""),
            "description":    rule.get("description", ""),
            "status":         rule.get("status", ""),
            "level":          rule.get("level", ""),
            "tags":           rule.get("tags", []),
            "logsource":      str(rule.get("logsource", {})),
            "falsepositives": rule.get("falsepositives", []),
            "detection":      detection_str,
            "source":         "sigma",
        }
    except Exception:
        return None


def ingest_sigma():
    client = QdrantClient(host="localhost", port=6333)
    model  = SentenceTransformer("all-MiniLM-L6-v2")

    categories = [
        "data/raw/sigma/network/**/*.yml",
        "data/raw/sigma/windows/**/*.yml",
        "data/raw/sigma/linux/**/*.yml",
        "data/raw/sigma/cloud/**/*.yml",
    ]

    all_points      = []
    processed_rules = []

    for pattern in categories:
        for filepath in glob(pattern, recursive=True):
            rule = parse_sigma_rule(filepath)
            if not rule or not rule["title"]:
                continue

            text = (
                f"Rule: {rule['title']}\n"
                f"Severity Level: {rule['level']}\n"
                f"Log Source: {rule['logsource']}\n"
                f"Tags: {', '.join(rule['tags'])}\n"
                f"Description: {rule['description'][:600]}\n"
                f"Detection: {rule['detection']}\n"
                f"False Positives: {', '.join(str(fp) for fp in rule['falsepositives'])}"
            )

            vector = model.encode(text).tolist()
            all_points.append(PointStruct(
                id=str(uuid.uuid4()),
                vector=vector,
                payload={
                    "text":  text,
                    "title": rule["title"],
                    "level": rule["level"],
                    "tags":  rule["tags"],
                },
            ))
            processed_rules.append(rule)

    output_path = Path("data/processed/sigma/rules.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(processed_rules, f, indent=4, ensure_ascii=False)

    for i in range(0, len(all_points), 200):
        client.upsert(collection_name=COLLECTION, points=all_points[i:i + 200])

    print(f"Sigma ingestion complete! Total rules ingested: {len(processed_rules)}")
    print(f"Processed rules saved to {output_path}")


if __name__ == "__main__":
    ingest_sigma()
