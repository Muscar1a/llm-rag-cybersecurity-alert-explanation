import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd

DEFAULT_INPUT_DIR = Path("data") / "test_data" / "uwf-zeekdata24"
DEFAULT_OUT       = Path(__file__).parent / "zeek_rows.json"

_SKIP_TECHNIQUES = {"Duplicate", "duplicate", ""}


def _safe(v):
    if v is None:
        return None
    if isinstance(v, float) and v != v:
        return None
    return v


def _to_int(v) -> int:
    try:
        f = float(v if v is not None else 0)
        return 0 if f != f else int(f)
    except (ValueError, TypeError):
        return 0


def _to_float(v) -> float:
    try:
        f = float(v if v is not None else 0)
        return 0.0 if f != f else f
    except (ValueError, TypeError):
        return 0.0


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=str, default=str(DEFAULT_INPUT_DIR))
    parser.add_argument("--max-per-tactic", type=int, default=30)
    parser.add_argument("--max-total", type=int, default=9999)
    parser.add_argument("--out", type=str, default=str(DEFAULT_OUT))
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"Error: input directory not found: {input_dir}")
        sys.exit(1)

    records: list[dict] = []
    tactic_counts: dict = defaultdict(int)
    seen: set = set()
    row_id = 0

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

        for _, row in df.iterrows():
            if len(records) >= args.max_total:
                break

            row_dict = row.to_dict()

            proto = str(_safe(row_dict.get("proto")) or "tcp").lower()
            src_ip = _safe(row_dict.get("src_ip_zeek")) or ""
            src_port = _to_int(row_dict.get("src_port_zeek", 0))
            dest_ip = _safe(row_dict.get("dest_ip_zeek")) or ""
            dest_port = _to_int(row_dict.get("dest_port_zeek", 0))
            conn_state = str(_safe(row_dict.get("conn_state")) or "")

            key = (proto, src_ip, src_port, dest_ip, dest_port, conn_state)
            if key in seen:
                continue
            seen.add(key)

            records.append({
                "id": row_id,
                "network": {
                    "proto":      proto,
                    "src_ip":     src_ip,
                    "src_port":   src_port,
                    "dest_ip":    dest_ip,
                    "dest_port":  dest_port,
                    "conn_state": conn_state,
                    "duration_s": round(_to_float(row_dict.get("duration", 0)), 6),
                    "orig_bytes": _to_int(row_dict.get("orig_bytes", 0)),
                    "resp_bytes": _to_int(row_dict.get("resp_bytes", 0)),
                    "orig_pkts":  _to_int(row_dict.get("orig_pkts", 0)),
                    "resp_pkts":  _to_int(row_dict.get("resp_pkts", 0)),
                    "service":    str(_safe(row_dict.get("service")) or ""),
                    "history":    str(_safe(row_dict.get("history")) or ""),
                },
                "_ground_truth": {
                    "label_tactic":    tactic,
                    "label_technique": str(_safe(row_dict.get("label_technique")) or ""),
                },
            })
            tactic_counts[tactic] += 1
            row_id += 1

    out_path = Path(args.out)
    out_path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nDone. {len(records)} rows written to {out_path}")
    print("\nBreakdown by tactic:")
    for tactic, count in sorted(tactic_counts.items()):
        print(f"  {tactic:<25} {count}")


if __name__ == "__main__":
    main()
