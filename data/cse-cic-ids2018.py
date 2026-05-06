import os
import sys
import zipfile

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


if __name__ == "__main__":
    # Simple CLI: python cse-cic-ids2018.py [download|extract]
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == 'download':
            download_logs()
        elif cmd == 'extract':
            extract_logs()
        elif cmd == 'download_ground_truth':
            download_ground_truth()
        else:
            print("Usage: python cse-cic-ids2018.py [download|extract]")
    else:
        print("Usage: python cse-cic-ids2018.py [download|extract]")