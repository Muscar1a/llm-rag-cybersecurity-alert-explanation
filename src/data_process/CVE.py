import os
import time
import requests
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv
import re

# Load environment variables from .env
load_dotenv()

# NVD allows 50 requests per 30 seconds with an API key, or 5 requests without one.
# We'll use a conservative sleep to ensure we don't hit the rate limit.
API_KEY = os.getenv("NVD_API_KEY")
DELAY = 0.6 if API_KEY else 6.0 

def fetch_cves_by_date_range(start_date: datetime, end_date: datetime):
    """
    Fetches CVEs for a specific date range from NVD API, handling pagination.
    Note: NVD API enforces a strict maximum of 120 days per request range.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    headers = {}
    if API_KEY:
        headers["apiKey"] = API_KEY
    
    pub_start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end_date = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    results = []
    start_index = 0
    results_per_page = 2000  # NVD max is 2000

    print(f"Fetching CVEs from {start_date.date()} to {end_date.date()}...")
    
    while True:
        params = {
            "pubStartDate": pub_start_date,
            "pubEndDate": pub_end_date,
            "resultsPerPage": results_per_page,
            "startIndex": start_index
        }
        
        try:
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code == 403:
                print("Rate limited! Retrying in 10 seconds...")
                time.sleep(10)
                continue
                
            response.raise_for_status()
            data = response.json()
            
            cves = data.get("vulnerabilities", [])
            
            for item in cves:
                processed_item = process_cve(item)

                if processed_item["description"] == "No description":
                    continue

                results.append(processed_item)
            
            total_results = data.get("totalResults", 0)
            print(f"  - Fetched {len(results)} / {total_results} records so far...")
            
            if len(results) >= total_results or len(cves) == 0:
                break
                
            start_index += results_per_page
            time.sleep(DELAY)
            
        except Exception as e:
            print(f"Error fetching CVEs at startIndex {start_index}: {e}")
            print("Retrying in 5 seconds...")
            time.sleep(5)
            
    return results

def get_cves_for_year(year: int):
    """
    Fetches all CVEs for a given year by splitting it into 3 chunks 
    (since max NVD date range per request is 120 days).
    """
    start_of_year = datetime(year, 1, 1)
    end_of_year = datetime(year, 12, 31, 23, 59, 59)
    
    current_start = start_of_year
    all_cves = []
    
    while current_start <= end_of_year:
        # Split year into intervals of 100 days to be safely under 120
        current_end = current_start + timedelta(days=100)
        if current_end > end_of_year:
            current_end = end_of_year
            
        batch_cves = fetch_cves_by_date_range(current_start, current_end)
        all_cves.extend(batch_cves)
        
        current_start = current_end + timedelta(seconds=1)
        time.sleep(DELAY)
        
    print(f"\nCompleted fetching {year}. Total CVEs found: {len(all_cves)}\n")
    return all_cves

def clean_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'[\x00-\x1F\x7f-\x9f]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def process_cve(item: dict):
    cve_info = item.get("cve", {})
    cve_id = cve_info.get("id", "Unknown ID")
    published_date = cve_info.get("published", "")
    
    descriptions = cve_info.get("descriptions", [])
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    desc = clean_text(desc)
    
    if not desc:
        desc = "No description"

    references_data = cve_info.get("references", [])
    references = [ref.get("url") for ref in references_data if "url" in ref]

    return {
        "cve_id": cve_id,
        "description": desc,
        "publishedDate": published_date,
        "references": references
    }

def main():
    # Set the years you want to fetch. For testing, you could just do [2024]
    target_years = [year for year in range(2010, 2026)] 
    
    # Ensure data directory exists
    os.makedirs(os.path.join("data", "raw", "CVE"), exist_ok=True)
    
    for year in target_years:
        print(f"=== Starting extraction for year {year} ===")
        cves = get_cves_for_year(year)
        
        # Save to JSON
        output_path = os.path.join("data", "raw", "CVE", f"nvd_cves_{year}.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(cves, f, indent=4)
        print(f"Saved {year} data to {output_path}")

if __name__ == "__main__":
    main()
