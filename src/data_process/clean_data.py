import json
import os
import glob
import re
import sys
import pandas as pd
import numpy as np
import yaml

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
os.chdir(PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


from ingest_cve import get_cves_for_year
from parse_attck import load_attack_techniques

SIGMA_CATEGORIES = ["network", "windows", "linux", "cloud"]


def _parse_sigma_rules(sigma_base_dir: str) -> list[dict]:
    rules = []
    for category in SIGMA_CATEGORIES:
        pattern = os.path.join(sigma_base_dir, category, "**", "*.yml")
        for filepath in glob.glob(pattern, recursive=True):
            try:
                with open(filepath, encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                if not rule or not isinstance(rule, dict) or not rule.get("title"):
                    continue
                rules.append({
                    "title":          rule.get("title", ""),
                    "description":    rule.get("description", ""),
                    "status":         rule.get("status", ""),
                    "level":          rule.get("level", ""),
                    "tags":           json.dumps(rule.get("tags", [])),
                    "logsource":      str(rule.get("logsource", {})),
                    "falsepositives": json.dumps(rule.get("falsepositives", [])),
                    "source":         "sigma",
                })
            except Exception:
                continue
    return rules


def run_pipeline():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    # CVE ==================================================
    print("=== CVE ===")
    cve_out_dir = os.path.join("data", "processed", "CVE")
    os.makedirs(cve_out_dir, exist_ok=True)

    all_cves = []
    for year in range(2010, 2026):
        print(f"  Fetching {year}...")
        all_cves.extend(get_cves_for_year(year))

    cve_df = pd.DataFrame(all_cves)
    cve_df["products"] = cve_df["products"].apply(
        lambda x: json.dumps(x) if isinstance(x, list) else x
    )
    cve_df["references"] = cve_df["references"].apply(
        lambda x: json.dumps(x) if isinstance(x, list) else x
    )
    cve_out = os.path.join(cve_out_dir, "cve_cleaned.parquet")
    cve_df.to_parquet(cve_out, index=False)
    print(f"  Saved {len(cve_df)} CVE records → {cve_out}")

    # MITRE ==================================================
    print("\n=== MITRE ===")
    techniques = load_attack_techniques()
    mitre_df = pd.DataFrame(techniques)
    mitre_df["tactics"] = mitre_df["tactics"].apply(json.dumps)
    mitre_df["platforms"] = mitre_df["platforms"].apply(json.dumps)
    mitre_df = mitre_df.rename(columns={"id": "mitre_id"})

    mitre_out_dir = os.path.join("data", "processed", "MITRE")
    os.makedirs(mitre_out_dir, exist_ok=True)
    mitre_out = os.path.join(mitre_out_dir, "mitre_cleaned.parquet")
    mitre_df.to_parquet(mitre_out, index=False)
    print(f"  Saved {len(mitre_df)} MITRE techniques → {mitre_out}")

    # Sigma ==================================================
    print("\n=== Sigma ===")
    sigma_raw_dir = os.path.join(project_root, "data", "raw", "sigma")
    if not os.path.isdir(sigma_raw_dir):
        print(f"  No Sigma data at {sigma_raw_dir} — skipping.")
    else:   
        sigma_rules = _parse_sigma_rules(sigma_raw_dir)
        if not sigma_rules:
            print("  No valid Sigma rules found — skipping.")
        else:
            sigma_df = pd.DataFrame(sigma_rules)
            sigma_out_dir = os.path.join("data", "processed", "sigma")
            os.makedirs(sigma_out_dir, exist_ok=True)
            sigma_out = os.path.join(sigma_out_dir, "sigma_cleaned.parquet")
            sigma_df.to_parquet(sigma_out, index=False)
            print(f"  Saved {len(sigma_df)} Sigma rules → {sigma_out}")


if __name__ == "__main__":
    run_pipeline()
