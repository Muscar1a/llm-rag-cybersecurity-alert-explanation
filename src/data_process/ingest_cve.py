import os
import time
import re
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("NVD_API_KEY")
DELAY   = 0.6 if API_KEY else 6.0


def clean_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'[\x00-\x1F\x7f-\x9f]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def process_cve(item: dict) -> dict | None:
    cve_info = item.get("cve", {})
    cve_id   = cve_info.get("id", "Unknown ID")

    desc = ""
    for d in cve_info.get("descriptions", []):
        if d.get("lang") == "en":
            desc = clean_text(d.get("value", ""))
            break
    if not desc or desc.startswith("** RESERVED"):
        return None

    cvss_score    = None
    cvss_severity = None
    cvss_vector   = None
    metrics = cve_info.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m             = metrics[key][0]
            cvss_data     = m.get("cvssData", {})
            cvss_score    = cvss_data.get("baseScore")
            cvss_severity = m.get("baseSeverity") or cvss_data.get("baseSeverity")
            cvss_vector   = cvss_data.get("vectorString")
            break

    products = []
    for cfg in cve_info.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe   = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    products.append(f"{parts[3]}/{parts[4]}")
    products = list(dict.fromkeys(products))[:10]

    references = [r.get("url") for r in cve_info.get("references", []) if "url" in r]

    return {
        "cve_id":        cve_id,
        "description":   desc,
        "publishedDate": cve_info.get("published", ""),
        "cvss_score":    cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector":   cvss_vector,
        "products":      products,
        "references":    references,
        "source":        "nvd",
    }


def fetch_cves_by_date_range(start_date: datetime, end_date: datetime) -> list[dict]:
    url     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": API_KEY} if API_KEY else {}

    pub_start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end_date   = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

    results = []
    start_index = 0
    results_per_page = 2000

    print(f"Fetching CVEs from {start_date.date()} to {end_date.date()}...")

    while True:
        params = {
            "pubStartDate":   pub_start_date,
            "pubEndDate":     pub_end_date,
            "resultsPerPage": results_per_page,
            "startIndex":     start_index,
        }
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code == 403:
                print("  Rate limited — waiting 10s...")
                time.sleep(10)
                continue
            resp.raise_for_status()
            data = resp.json()

            for item in data.get("vulnerabilities", []):
                processed = process_cve(item)
                if processed:
                    results.append(processed)

            total   = data.get("totalResults", 0)
            fetched = start_index + results_per_page
            print(f"    {min(fetched, total)}/{total} records")

            if fetched >= total or not data.get("vulnerabilities"):
                break

            start_index += results_per_page
            time.sleep(DELAY)

        except Exception as e:
            print(f"  Error at index {start_index}: {e} — retrying in 5s...")
            time.sleep(5)

    return results


def get_cves_for_year(year: int) -> list[dict]:
    start_of_year = datetime(year, 1, 1)
    end_of_year   = datetime(year, 12, 31, 23, 59, 59)

    current_start = start_of_year
    all_cves = []

    while current_start <= end_of_year:
        chunk_end = min(current_start + timedelta(days=120), end_of_year)
        all_cves.extend(fetch_cves_by_date_range(current_start, chunk_end))
        current_start = chunk_end + timedelta(seconds=1)
        time.sleep(DELAY)

    print(f"Year {year} complete — {len(all_cves)} CVEs\n")
    return all_cves
