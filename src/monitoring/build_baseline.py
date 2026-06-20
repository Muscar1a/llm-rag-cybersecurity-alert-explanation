import glob
import sys
import pandas as pd
from pathlib import Path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
from src.monitoring.baseline import PortBaseline

CSV_DIR = "data/raw/cse-cic-ids2018"
OUTPUT = "baselines/cicids2018.json"


def main():
    pattern = f"{CSV_DIR}/*_TrafficForML_CICFlowMeter.csv"
    files = sorted(glob.glob(pattern))
    if not files:
        print(f"No CSV files found: {pattern}")
        return

    print(f"Found {len(files)} files. Processing one by one...")
    baselines = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        benign = df[df["Label"].str.strip() == "Benign"]
        print(f"  {f.split('/')[-1]}: {len(benign):,} Benign rows")
        if len(benign) == 0:
            continue
        baselines.append(PortBaseline.from_dataframe(benign))
        del df, benign  # free memory before next file

    print(f"\nMerging {len(baselines)} partial baselines...")
    final = PortBaseline.merge(baselines)
    final.save(OUTPUT)
    print(f"Saved to {OUTPUT}")


if __name__ == "__main__":
    main()
