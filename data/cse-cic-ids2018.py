import os
import sys
import zipfile
import pandas as pd
import glob

target_days = [
    "Friday-02-03-2018",
    "Friday-16-02-2018",
    "Friday-23-02-2018",
    "Thursday-01-03-2018",
    "Thursday-15-02-2018",
    "Thursday-22-02-2018",
    "Tuesday-20-02-2018",
    "Wednesday-14-02-2018",
    "Wednesday-21-02-2018",
    "Wednesday-28-02-2018"
]

def download_logs():
    base_s3_path = "s3://cse-cic-ids2018/Original Network Traffic and Log data/"
    output_base = "data/raw/cse-cic-ids2018"

    os.makedirs(output_base, exist_ok=True)

    for day in target_days:
        print(f"--- Downloading log for day: {day} ---")
        s3_uri = f"{base_s3_path}{day}/logs.zip"
        
        day_folder = os.path.join(output_base, day)
        os.makedirs(day_folder, exist_ok=True)
        
        os.system(f'aws s3 cp "{s3_uri}" "{day_folder}/" --no-sign-request')

    print("Done!")


def download_ground_truth():
    base_s3_path = "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/"
    output_base = "data/raw/cse-cic-ids2018"
    
    os.makedirs(output_base, exist_ok=True)
    
    for day in target_days:
        print(f"--- Downloading ground truth for day: {day} (csv) ---")
        s3_uri = f"{base_s3_path}{day}_TrafficForML_CICFlowMeter.csv"
        
        day_folder = os.path.join(output_base, day)
        os.makedirs(day_folder, exist_ok=True)
        
        os.system(f'aws s3 cp "{s3_uri}" "{day_folder}/" --no-sign-request')
    
    print("Done!")
    

def extract_logs(output_base="data/raw/cse-cic-ids2018"):
    """Find and extract all .zip files (logs.zip) under output_base.

    Extracts each zip into its containing directory.
    """
    if not os.path.isdir(output_base):
        print(f"Output base not found: {output_base}")
        return

    for root, dirs, files in os.walk(output_base):
        for fname in files:
            if fname.lower().endswith('.zip'):
                zip_path = os.path.join(root, fname)
                print(f"Extracting {zip_path}...")
                try:
                    with zipfile.ZipFile(zip_path, 'r') as z:
                        z.extractall(root)
                except zipfile.BadZipFile:
                    print(f"Bad zip file: {zip_path}")

    print("Extraction complete.")


def extract_non_benign_records(output_base="data/raw/cse-cic-ids2018", num_records=40):
    """Extract non-BENIGN records from *_TrafficForML_CICFlowMeter.csv files.
    
    For each file matching the pattern, extracts the first 'num_records' 
    non-BENIGN records and saves to *_TrafficShorten.csv.
    Then combines all shortened files into combined_shorten.csv.
    """
    if not os.path.isdir(output_base):
        print(f"Output base not found: {output_base}")
        return
    
    # Find all *_TrafficForML_CICFlowMeter.csv files
    pattern = os.path.join(output_base, "*_TrafficForML_CICFlowMeter.csv")
    traffic_files = glob.glob(pattern)
    
    if not traffic_files:
        print(f"No files matching pattern {pattern} found.")
        return
    
    print(f"Found {len(traffic_files)} traffic files.")
    all_dfs = []
    
    for traffic_file in traffic_files:
        print(f"\nProcessing: {traffic_file}")
        
        # Read the CSV file
        try:
            df = pd.read_csv(traffic_file)
        except Exception as e:
            print(f"Error reading {traffic_file}: {e}")
            continue
        
        # Filter out BENIGN records (assuming 'Label' column exists)
        label_col = None
        for col in df.columns:
            if col.strip().lower() == 'label':
                label_col = col
                break
        
        if label_col is None:
            print(f"Warning: 'Label' column not found in {traffic_file}. Skipping.")
            continue
        
        # Normalize label values (strip spaces, uppercase) and filter out 'BENIGN'
        labels = df[label_col].astype(str).str.strip().str.upper()
        non_benign = df[labels != 'BENIGN']

        if len(non_benign) == 0:
            print(f"No non-BENIGN records found in {traffic_file}.")
            continue

        # If there are at least num_records, take a random sample, otherwise take all
        if len(non_benign) >= num_records:
            shortened = non_benign.sample(n=num_records, random_state=42)
        else:
            shortened = non_benign.copy()
        
        # Save to *_TrafficShorten.csv
        shorten_file = traffic_file.replace("_TrafficForML_CICFlowMeter.csv", "_TrafficShorten.csv")
        shortened.to_csv(shorten_file, index=False)
        print(f"Saved {len(shortened)} records to {shorten_file}")
        
        all_dfs.append(shortened)
    
    # Combine all shortened files into combined_shorten.csv
    if all_dfs:
        combined = pd.concat(all_dfs, ignore_index=True)
        combined_file = os.path.join(output_base, "combined_shorten.csv")
        combined.to_csv(combined_file, index=False)
        print(f"\nCombined {len(all_dfs)} files into {combined_file}")
        print(f"Total records in combined file: {len(combined)}")
    else:
        print("No data to combine.")


if __name__ == "__main__":
    # Simple CLI: python cse-cic-ids2018.py [download|extract|shorten]
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == 'download':
            download_logs()
        elif cmd == 'extract':
            extract_logs()
        elif cmd == 'download_ground_truth':
            download_ground_truth()
        elif cmd == 'shorten':
            extract_non_benign_records()
        else:
            print("Usage: python cse-cic-ids2018.py [download|extract|download_ground_truth|shorten]")
    else:
        print("Usage: python cse-cic-ids2018.py [download|extract|download_ground_truth|shorten]")