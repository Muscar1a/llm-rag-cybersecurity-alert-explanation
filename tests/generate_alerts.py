"""
generate_alerts.py
------------------
Step 1: Read CSV, build alert texts, save to tests/alerts.json.
No LLM calls. Run once to produce a stable, reusable dataset.

Usage:
    python tests/generate_alerts.py [--max-per-label N] [--out PATH]
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.data_process.alert_builder import build_alert_text
from src.monitoring.baseline import PortBaseline

CSV_FILE     = "data/raw/cse-cic-ids2018/combined_shorten.csv"
DEFAULT_OUT  = Path(__file__).parent / "alerts.json"
BASELINE_FILE = "baselines/cicids2018.json"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=str, default=str(DEFAULT_OUT),
                        help="Output JSON file path")
    args = parser.parse_args()

    if not Path(CSV_FILE).exists():
        print(f"Error: CSV not found: {CSV_FILE}")
        sys.exit(1)

    baseline = PortBaseline.from_json(BASELINE_FILE)

    records      = []
    label_counts = defaultdict(int)

    with open(CSV_FILE, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            label = row.get("Label", "Unknown").strip()
            label_counts[label] += 1

            alert_text = build_alert_text(row, baseline=baseline)
            records.append({
                "label":      label,
                "alert_text": alert_text,
                "raw_packet": dict(row),
            })
            print(f"[{label}] {label_counts[label]}")

    out_path = Path(args.out)
    out_path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nDone. {len(records)} alerts written to {out_path}")


if __name__ == "__main__":
    main()
