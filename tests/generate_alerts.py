"""
generate_alerts.py
------------------
Read UWF-ZeekData24 CSVs, build alert texts, save to tests/alerts.json.
No LLM calls. Run once to produce a stable, reusable evaluation dataset.

Usage:
    python tests/generate_alerts.py [--max-per-tactic N] [--out PATH]
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.data_process.zeek_alert_builder import build_alert_text, build_metadata

DATA_DIR    = project_root / "data" / "raw" / "uwf-zeekdata24"
DEFAULT_OUT = Path(__file__).parent / "alerts.json"

# Skip rows with ambiguous/duplicate technique labels
_SKIP_TECHNIQUES = {"Duplicate", "duplicate", ""}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-per-tactic", type=int, default=50,
                        help="Max rows to sample per tactic (default: 50)")
    parser.add_argument("--out", type=str, default=str(DEFAULT_OUT))
    args = parser.parse_args()

    if not DATA_DIR.exists():
        print(f"Error: data directory not found: {DATA_DIR}")
        sys.exit(1)

    records: list[dict]       = []
    tactic_counts: dict       = defaultdict(int)

    for tactic_dir in sorted(DATA_DIR.iterdir()):
        if not tactic_dir.is_dir():
            continue
        csvs = list(tactic_dir.glob("*.csv"))
        if not csvs:
            continue

        df = pd.read_csv(csvs[0], low_memory=False)

        # Filter out Duplicate technique rows
        if "label_technique" in df.columns:
            df = df[~df["label_technique"].isin(_SKIP_TECHNIQUES)]
            df = df[df["label_technique"].notna()]

        # Sample up to --max-per-tactic rows, balanced by technique if multiple
        if len(df) > args.max_per_tactic:
            if "label_technique" in df.columns and df["label_technique"].nunique() > 1:
                df = (
                    df.groupby("label_technique", group_keys=False)
                    .apply(lambda g: g.sample(min(len(g), args.max_per_tactic // df["label_technique"].nunique())))
                )
            else:
                df = df.sample(args.max_per_tactic, random_state=42)

        tactic = tactic_dir.name
        for _, row in df.iterrows():
            row_dict = row.to_dict()
            alert_text = build_alert_text(row_dict)
            meta       = build_metadata(row_dict)

            records.append({
                "label_tactic":    tactic,
                "label_technique": str(row_dict.get("label_technique", "")),
                "alert_text":      alert_text,
                "metadata":        meta,
            })
            tactic_counts[tactic] += 1

    out_path = Path(args.out)
    out_path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nDone. {len(records)} alerts written to {out_path}")
    print("\nBreakdown by tactic:")
    for tactic, count in sorted(tactic_counts.items()):
        print(f"  {tactic:<25} {count}")


if __name__ == "__main__":
    main()
