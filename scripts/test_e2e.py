import sys
from pathlib import Path
import pandas as pd

sys.path.append(str(Path(__file__).parent.parent))

from src.data_process.alert_builder import build_alert_text
from src.rag.service import RagService

DATA_PATH = Path("data/processed/CICIDS2017/cicids_rag_evaluation.csv")


def load_sample_alert() -> tuple[str, str]:
    df = pd.read_csv(DATA_PATH)

    preferred_labels = [
        "SSH-Patator",
        "FTP-Patator",
        "PortScan",
        "DoS Hulk",
        "DDoS",
        "Bot",
    ]

    for label in preferred_labels:
        sample = df[df["label"].astype(str).str.lower() == label.lower()]
        if not sample.empty:
            row = sample.iloc[0].to_dict()
            return row["label"], build_alert_text(row)

    sample = df[df["label"].astype(str).str.upper() != "BENIGN"]
    if sample.empty:
        raise RuntimeError("No attack rows found in CICIDS evaluation CSV.")

    row = sample.iloc[0].to_dict()
    return row["label"], build_alert_text(row)

def main() -> None:
    label, alert_text = load_sample_alert()
    rag = RagService()

    result = rag.analyze(
        alert_text=alert_text,
        k=5,
        source="mitre",
    )

    print(f"Label: {label}")
    print(f"Alert text: {alert_text}\n")
    print(result)


if __name__ == "__main__":
    main()
