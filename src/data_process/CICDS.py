import pandas as pd
import glob
import os
import numpy as np

print("Loading ...")
script_dir = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(script_dir, "..", "..", "data", "raw", "CICIDS2017")
all_files = glob.glob(os.path.join(path, "*.csv"))

df_list = []
for file in all_files:
    print( f"Reading file: {file}")
    df_temp = pd.read_csv(file, skipinitialspace=True)
    df_list.append(df_temp)

df = pd.concat(df_list, ignore_index=True)
print(f"Total rows: {len(df)}")

df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('/', '_')

df.rename(columns={'label': 'label'}, inplace=True)

print("\n====================")
print(df.columns[:5].tolist())


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

# Remove benign records
df = df[df['label'] != 'BENIGN']
print(f"\nAfter removing benign records: {len(df)} rows")

SAMPLE_SIZE = 10000

df_sampled = pd.concat([
    group.sample(n=min(len(group), int(SAMPLE_SIZE * len(group) / len(df))), random_state=42)
    for _, group in df.groupby('label')
]).reset_index(drop=True)

print(f"\nClass distribution in evaluation sample ({len(df_sampled)} flows):")
print(df_sampled['label'].value_counts())

out_dir = os.path.join("../../data", "processed", "CICIDS2017")
os.makedirs(out_dir, exist_ok=True)
out_file = os.path.join(out_dir, "cicids_rag_evaluation.csv")

df_sampled.to_csv(out_file, index=False)
print(f"\nEvaluation dataset exported to: {out_file}")