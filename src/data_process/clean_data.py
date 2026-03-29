import pandas as pd
import re
import json
import os
import glob
import numpy as np

from CVE import get_cves_for_year
from MITRE import process_mitre 

script_dir = os.path.dirname(os.path.abspath(__file__))

def clean_text(raw_text: str) -> str:
    if not isinstance(raw_text, str) or not raw_text.strip():
        return ""

    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'[\x00-\x1F\x7f-\x9f]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()

    return text


    

def run_pipeline():
    # CVE
    target_years = [year for year in range(2010, 2026)]
    os.makedirs(os.path.join("data", "processed", "CVE"), exist_ok=True)
    
    all_cves = []
    for year in target_years:
        print(f"=== Start extraction for year {year} ===")
        cves = get_cves_for_year(year)
        all_cves.extend(cves)
        
    all_cves_df = pd.DataFrame(all_cves)
    all_cves_df.to_parquet(os.path.join("data", "processed", "CVE", "cve_cleaned.parquet"), index=False)
    print(f"Saved {len(all_cves_df)} CVE records to data/processed/CVE/cve_cleaned.parquet")
    
    # ====================================================================== #
    # MITRE
    techniques = process_mitre()
    all_mitre_df = pd.DataFrame(techniques)
    
    os.makedirs(os.path.join("data", "processed", "MITRE"), exist_ok=True)
    output_path = os.path.join("data", "processed", "MITRE", "mitre_cleaned.parquet")
    all_mitre_df.to_parquet(output_path, index=False)
    print(f"Saved {len(all_mitre_df)} mitre records to {output_path}")

    # ====================================================================== #
    # CICIDS2017
    cicids_path = os.path.join(script_dir, "..", "..", "data", "raw", "CICIDS2017")
    cicids_files = glob.glob(os.path.join(cicids_path, "*.csv"))
    
    cicids_df_list = []
    for file in cicids_files:
        df_temp = pd.read_csv(file, skipinitialspace=True)
        cicids_df_list.append(df_temp)
    
    df = pd.concat(cicids_df_list, ignore_index=True)
    print(f"Total rows: {len(df)}")
    
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('/', '_')
    
    df.rename(columns={'label': 'label'}, inplace=True)
    
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    missing_pct = df.isnull().mean() * 100
    cols_with_missing = missing_pct[missing_pct > 0]
    
    if len(cols_with_missing) > 0:
        print("\nColumns with missing values (NaN):")
        print(cols_with_missing)

        threshold = 1.0  # 1%
        for col in cols_with_missing.index:
            if cols_with_missing[col] < threshold:
                print(f" -> Column '{col}' missing < 1%. Dropping affected rows.")
                df.dropna(subset=[col], inplace=True)
            else:
                print(f" -> Column '{col}' missing >= 1%. Imputing with median.")
                df[col].fillna(df[col].median(), inplace=True)
    else:
        print("\nNo missing values detected in the dataset!")
    
    SAMPLE_SIZE = 100000
    cicids_df_sampled = pd.concat([
        group.sample(n=min(len(group), int(SAMPLE_SIZE * len(group) / len(df))), random_state=42)
        for _, group in df.groupby('label')
    ]).reset_index(drop=True)
    
    print(f"\nClass distribution in evaluation sample ({len(cicids_df_sampled)} flows):")
    print(cicids_df_sampled['label'].value_counts())

    out_dir = os.path.join("data", "processed", "CICIDS2017")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "cicids_cleaned.parquet")

    cicids_df_sampled.to_parquet(out_file, index=False)
    print(f"Saved sampled dataset to {out_file}")

if __name__ == "__main__":
    run_pipeline()
