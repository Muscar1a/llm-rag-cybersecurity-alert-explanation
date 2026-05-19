#!/usr/bin/env python3

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.rag.service import RagService
from src.data_process.alert_builder import build_alert_text
from src.monitoring.baseline import PortBaseline

MAX_PER_LABEL = 3

baseline = PortBaseline.from_json("baselines/cicids2018.json")


def main():
    csv_file = "data/raw/cse-cic-ids2018/combined_shorten.csv"

    if not Path(csv_file).exists():
        print(f"Error: File not found: {csv_file}")
        sys.exit(1)

    rag_service = RagService()
    results = []
    label_counts: dict[str, int] = defaultdict(int)

    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            label = row.get("Label", "Unknown").strip()

            if label_counts[label] >= MAX_PER_LABEL:
                continue
            label_counts[label] += 1

            print(f"\n{'='*80}")
            print(f"Label: {label}  [{label_counts[label]}/{MAX_PER_LABEL}]")
            print(f"{'='*80}")

            alert_text = build_alert_text(row, baseline=baseline)
            print(f"\n[INPUT]:\n{alert_text}\n")

            try:
                rag_output = rag_service.analyze(
                    alert_text=alert_text,
                    k=5,
                    source=None,
                )
                results.append({
                    "label": label,
                    "raw_packet": row,
                    "input": alert_text,
                    "output": rag_output,
                })
                print("[RAG OUTPUT]:")
                print(f"  Threat:    {rag_output.get('threat_description')}")
                print(f"  Severity:  {rag_output.get('severity')}")
                print(f"  Rationale: {rag_output.get('rationale')}")
                print("  Mitigation Steps:")
                for step in rag_output.get("mitigation_steps", []):
                    print(f"    - {step}")
                print(f"  Retrieved: {rag_output.get('retrieved_context_ids', [])}")

            except Exception as e:
                print(f"[ERROR]: {e}")
                results.append({
                    "label": label,
                    "raw_packet": row,
                    "input": alert_text,
                    "output": {"error": str(e)},
                })

    output_file = Path(__file__).resolve().parent / "rag_output_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*80}")
    print(f"Results saved to: {output_file}")
    print(f"Total records processed: {len(results)}")
    print(f"\nPer-label breakdown:")
    for lbl, cnt in sorted(label_counts.items()):
        print(f"  {lbl}: {cnt}")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()
