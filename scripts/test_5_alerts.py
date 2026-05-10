import sys
import json
import math
from pathlib import Path
from datetime import datetime

import pandas as pd

sys.path.append(str(Path(__file__).parent.parent))

from src.data_process.alert_builder import build_alert_text
from src.rag.service import RagService


DATA_PATH = Path("data/processed/CICIDS2017/cicids_rag_evaluation.csv")
OUTPUT_PATH = Path("REPORT_5_ALERTS_E2E.md")

TARGET_LABELS = [
    "SSH-Patator",
    "FTP-Patator",
    "PortScan",
    "DoS Hulk",
    "Bot",
]


def normalize_value(value):
    try:
        if pd.isna(value):
            return None
    except Exception:
        pass

    if hasattr(value, "item"):
        try:
            value = value.item()
        except Exception:
            pass

    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return None

    return value


def to_json_block(obj) -> str:
    return "```json\n" + json.dumps(obj, ensure_ascii=False, indent=2) + "\n```\n"


def to_text_block(text: str) -> str:
    return "```text\n" + text + "\n```\n"


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Missing data file: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)
    rag = RagService()

    lines = []
    lines.append("# E2E Report: 5 Alerts Baseline")
    lines.append("")
    lines.append(f"- Generated at: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`")
    lines.append(f"- Data source: `{DATA_PATH.as_posix()}`")
    lines.append("- Retrieval source: `mitre`")
    lines.append("- Retrieval k: `5`")
    lines.append("- Prompt template in service: `basic`")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| # | Label | Status |")
    lines.append("|---|---|---|")

    report_sections = []

    for idx, label in enumerate(TARGET_LABELS, start=1):
        sample = df[df["label"].astype(str).str.lower() == label.lower()]

        if sample.empty:
            lines.append(f"| {idx} | {label} | SKIPPED |")
            report_sections.extend([
                f"## Alert {idx}: {label}",
                "",
                "Status: `SKIPPED`",
                "",
                "No matching row found in CSV.",
                "",
            ])
            continue

        row = sample.iloc[0].to_dict()
        row = {k: normalize_value(v) for k, v in row.items()}

        alert_text = build_alert_text(row)

        response = rag.analyze(
            alert_text=alert_text,
            k=5,
            source="mitre",
        )

        response = json.loads(json.dumps(response, ensure_ascii=False, default=str))

        lines.append(f"| {idx} | {label} | OK |")

        report_sections.extend([
            f"## Alert {idx}: {label}",
            "",
            "### Raw Packet Row",
            "",
            to_json_block(row),
            "### Alert Text",
            "",
            to_text_block(alert_text),
            "### RAG Response",
            "",
            to_json_block(response),
        ])

    content = "\n".join(lines + [""] + report_sections)
    OUTPUT_PATH.write_text(content, encoding="utf-8")

    print(f"Report written to: {OUTPUT_PATH.resolve()}")


if __name__ == "__main__":
    main()
