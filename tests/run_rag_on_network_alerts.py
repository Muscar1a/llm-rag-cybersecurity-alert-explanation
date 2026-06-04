#!/usr/bin/env python3

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import glob
import pandas as pd

from src.rag.service import RagService
from src.data_process.zeek_alert_builder import build_alert_text

MAX_PER_TACTIC = 3
DATA_DIR = "data/raw/uwf-zeekdata24"


def main():
    if not Path(DATA_DIR).exists():
        print(f"Error: Directory not found: {DATA_DIR}")
        sys.exit(1)

    # Load all tactic CSVs
    rows_by_tactic: list[tuple[str, dict]] = []
    for tactic_dir in sorted(Path(DATA_DIR).iterdir()):
        if not tactic_dir.is_dir():
            continue
        csvs = list(tactic_dir.glob("*.csv"))
        if not csvs:
            continue
        df = pd.read_csv(csvs[0], low_memory=False)
        if "label_technique" in df.columns:
            df = df[~df["label_technique"].isin({"Duplicate", ""})]
            df = df[df["label_technique"].notna()]
        for _, row in df.head(MAX_PER_TACTIC).iterrows():
            rows_by_tactic.append((tactic_dir.name, row.to_dict()))

    rag_service = RagService()
    results = []
    tactic_counts: dict[str, int] = defaultdict(int)

    for tactic, row in rows_by_tactic:
        tactic_counts[tactic] += 1

        print(f"\n{'='*80}")
        print(f"Tactic: {tactic}  [{tactic_counts[tactic]}/{MAX_PER_TACTIC}]")
        print(f"Technique: {row.get('label_technique', '')}")
        print(f"{'='*80}")

        alert_text = build_alert_text(row)
        print(f"\n[INPUT]:\n{alert_text}\n")

        try:
            rag_output = rag_service.analyze(
                alert_text=alert_text,
                k=5,
                source=None,
            )
            results.append({
                "label_tactic":    tactic,
                "label_technique": row.get("label_technique", ""),
                "input":           alert_text,
                "output":          rag_output,
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
                "label_tactic":    tactic,
                "label_technique": row.get("label_technique", ""),
                "input":           alert_text,
                "output":          {"error": str(e)},
            })

    output_file = Path(__file__).resolve().parent / "rag_output_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*80}")
    print(f"Results saved to: {output_file}")
    print(f"Total records processed: {len(results)}")
    print(f"\nPer-tactic breakdown:")
    for lbl, cnt in sorted(tactic_counts.items()):
        print(f"  {lbl}: {cnt}")
    print(f"{'='*80}")

    try:
        from src.mlops.tracking import log_rag_experiment
        log_rag_experiment(
            run_name="manual_test_run",
            params={
                "retrieval.k": 5,
                "max_per_tactic": MAX_PER_TACTIC,
                "data_source": "uwf-zeekdata24",
            },
            metrics={
                "total_records": len(results)
            },
            artifacts=[str(output_file)],
            tags={"type": "manual_test"}
        )
        print("Logged run to MLflow.")
    except Exception as e:
        print(f"Failed to log to MLflow: {e}")


if __name__ == "__main__":
    main()
