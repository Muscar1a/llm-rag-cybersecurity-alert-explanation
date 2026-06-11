"""
generate_alerts.py
------------------
Read UWF-ZeekData24 directory (one subdir per tactic), build alert texts,
save to tests/alerts.json.
No LLM calls. Run once to produce a stable, reusable evaluation dataset.

Usage:
    python tests/generate_alerts.py [--input-dir PATH] [--max-per-tactic N] [--max-total N] [--out PATH]
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

DEFAULT_INPUT_DIR = project_root / "data" / "test_data" / "uwf-zeekdata24"
DEFAULT_OUT       = Path(__file__).parent / "alerts.json"

_SKIP_TECHNIQUES = {"Duplicate", "duplicate", ""}


def _filter_rows(df: pd.DataFrame) -> pd.DataFrame:
    if "label_technique" not in df.columns:
        return df
    df = df[~df["label_technique"].isin(_SKIP_TECHNIQUES)]
    return df[df["label_technique"].notna()]


def _sample_rows(df: pd.DataFrame, max_rows: int) -> pd.DataFrame:
    if max_rows <= 0 or len(df) <= max_rows:
        return df.head(max(0, max_rows))

    if "label_technique" in df.columns and df["label_technique"].nunique() > 1:
        per_technique = max(1, max_rows // df["label_technique"].nunique())
        df = (
            df.groupby("label_technique", group_keys=False)
            .apply(lambda g: g.sample(min(len(g), per_technique), random_state=42))
        )
        if len(df) > max_rows:
            df = df.sample(max_rows, random_state=42)
        return df

    return df.sample(max_rows, random_state=42)


def _append_alerts(records, tactic_counts, df: pd.DataFrame, tactic_name=None, max_total=None, seen_texts: set = None):
    for _, row in df.iterrows():
        if max_total is not None and len(records) >= max_total:
            break

        row_dict = row.to_dict()
        label_tactic = tactic_name or str(row_dict.get("label_tactic", ""))
        alert_text = build_alert_text(row_dict)

        if seen_texts is not None:
            if alert_text in seen_texts:
                continue
            seen_texts.add(alert_text)

        meta = build_metadata(row_dict)

        records.append({
            "label_tactic":    label_tactic,
            "label_technique": str(row_dict.get("label_technique", "")),
            "alert_text":      alert_text,
            "metadata":        meta,
        })
        tactic_counts[label_tactic] += 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=str, default=str(DEFAULT_INPUT_DIR),
                        help=f"Directory with one subdir per tactic (default: {DEFAULT_INPUT_DIR})")
    parser.add_argument("--max-per-tactic", type=int, default=35,
                        help="Max rows to sample per tactic (default: 35)")
    parser.add_argument("--max-total", type=int, default=9999,
                        help="Max total alerts to write (default: unlimited)")
    parser.add_argument("--out", type=str, default=str(DEFAULT_OUT))
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"Error: input directory not found: {input_dir}")
        sys.exit(1)

    records: list[dict] = []
    tactic_counts: dict = defaultdict(int)
    seen_texts: set = set()

    for tactic_dir in sorted(input_dir.iterdir()):
        if len(records) >= args.max_total:
            break
        if not tactic_dir.is_dir():
            continue
        csvs = list(tactic_dir.glob("*.csv"))
        if not csvs:
            continue

        df = pd.read_csv(csvs[0], low_memory=False)
        df = _filter_rows(df)

        remaining = args.max_total - len(records)
        df = _sample_rows(df, min(args.max_per_tactic, remaining))

        tactic = tactic_dir.name
        _append_alerts(records, tactic_counts, df, tactic_name=tactic, max_total=args.max_total, seen_texts=seen_texts)

    out_path = Path(args.out)
    out_path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nDone. {len(records)} alerts written to {out_path}")
    print("\nBreakdown by tactic:")
    for tactic, count in sorted(tactic_counts.items()):
        print(f"  {tactic:<25} {count}")


if __name__ == "__main__":
    main()
