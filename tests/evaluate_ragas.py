import csv
import os
import sys
from collections import defaultdict
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from ragas import EvaluationDataset, SingleTurnSample, evaluate
from ragas.metrics import faithfulness, answer_relevancy
from ragas.llms import LangchainLLMWrapper
from ragas.embeddings import LangchainEmbeddingsWrapper
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings

from src.rag.service import RagService
from src.rag.settings import settings
from src.data_process.alert_builder import build_alert_text
from src.monitoring.baseline import PortBaseline

# ── Ground truth tables ────────────────────────────────────────────────────

SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Unknown": -1}

SEVERITY_MIN = {
    "DDOS attack-HOIC":          "High",
    "DoS attacks-GoldenEye":     "High",
    "DoS attacks-Hulk":          "High",
    "SQL Injection":             "High",
    "Infilteration":             "High",
    "DoS attacks-Slowloris":     "Medium",
    "DoS attacks-SlowHTTPTest":  "Medium",
    "FTP-BruteForce":            "Medium",
    "SSH-Bruteforce":            "Medium",
    "Brute Force -Web":          "Medium",
    "Brute Force -XSS":          "Medium",
    "Bot":                       "Medium",
}

ATTACK_KEYWORDS = {
    "Bot":                      ["bot", "c2", "command-and-control", "malware", "beacon"],
    "Brute Force -Web":         ["brute", "force", "credential", "login", "password", "web"],
    "Brute Force -XSS":         ["xss", "cross-site", "script", "injection"],
    "DDOS attack-HOIC":         ["ddos", "dos", "flood", "denial"],
    "DoS attacks-GoldenEye":    ["dos", "denial", "flood", "goldeneye", "http"],
    "DoS attacks-Hulk":         ["dos", "denial", "flood", "hulk", "http"],
    "DoS attacks-SlowHTTPTest": ["dos", "slow", "http", "denial"],
    "DoS attacks-Slowloris":    ["slowloris", "dos", "slow", "denial", "http"],
    "FTP-BruteForce":           ["ftp", "brute", "force", "credential"],
    "Infilteration":            ["infiltr", "exfil", "lateral", "pivot", "c2", "intrusion"],
    "SQL Injection":            ["sql", "injection", "database"],
    "SSH-Bruteforce":           ["ssh", "brute", "force", "credential"],
}


HALLUCINATION_PATTERNS = [
    ("SYN flood: NOT possible", "syn flood"),
    ("Zero-byte flow",          "exfiltrat"),
    ("server did not respond",  "established connection"),
]

# ── Rule-based metrics ─────────────────────────────────────────────────────

def get_severity_verdict(output_sev: str, label: str) -> str:
    expected_min = SEVERITY_MIN.get(label)
    if not expected_min:
        return "unknown_label"
    out_rank = SEVERITY_ORDER.get(output_sev, -1)
    if out_rank == -1:
        return "unknown_severity"
    min_rank = SEVERITY_ORDER[expected_min]
    if out_rank < min_rank:
        return "underestimated"
    if out_rank > min_rank:
        return "overestimated"
    return "correct"

def get_attack_type_hit(label: str, text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in ATTACK_KEYWORDS.get(label, []))

def get_hallucination_flag(alert_text: str, output_text: str) -> bool:
    alert_lower  = alert_text.lower()
    output_lower = output_text.lower()
    return any(
        cond in alert_lower and viol in output_lower
        for cond, viol in HALLUCINATION_PATTERNS
    )

def get_context_diversity(context_ids: list) -> str:
    has_cve   = any(cid.startswith("CVE")   for cid in context_ids)
    has_mitre = any(cid.startswith("T")     for cid in context_ids)
    has_sigma = any("sigma" in cid          for cid in context_ids)
    parts = [s for s, flag in [("cve", has_cve), ("mitre", has_mitre), ("sigma", has_sigma)] if flag]
    return "+".join(parts) if parts else "none"

# ── Main ───────────────────────────────────────────────────────────────────

MAX_PER_LABEL = 3
CSV_FILE      = "data/raw/cse-cic-ids2018/combined_shorten.csv"
REPORT_FILE   = Path(__file__).parent / "evaluation_report.csv"


def main():
    if not Path(CSV_FILE).exists():
        print(f"Error: File not found: {CSV_FILE}")
        sys.exit(1)

    google_api_key = settings.google_api_key
    google_model_name = settings.google_model_name
    
    if not google_api_key:
        print("Error: google_api_key not found in .env or settings.")
        sys.exit(1)

    baseline    = PortBaseline.from_json("baselines/cicids2018.json")
    rag_service = RagService()

    judge_llm = LangchainLLMWrapper(
        ChatGoogleGenerativeAI(model=google_model_name, google_api_key=google_api_key)
    )
    judge_emb = LangchainEmbeddingsWrapper(
        GoogleGenerativeAIEmbeddings(model="models/embedding-001", google_api_key=google_api_key)
    )

    records      = []
    label_counts = defaultdict(int)

    with open(CSV_FILE, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            label = row.get("Label", "Unknown").strip()
            if label_counts[label] >= MAX_PER_LABEL:
                continue
            label_counts[label] += 1

            alert_text = build_alert_text(row, baseline=baseline)
            rag_out    = rag_service.analyze(alert_text=alert_text, k=5, source=None)

            records.append({
                "label":         label,
                "alert_text":    alert_text,
                "severity":      rag_out.get("severity", "Unknown"),
                "output_text":   rag_out.get("threat_description", "") + "\n" + rag_out.get("rationale", ""),
                "context_ids":   rag_out.get("retrieved_context_ids", []),
                "context_texts": rag_out.get("retrieved_contexts_text", []),
            })
            print(f"[{label}] {label_counts[label]}/{MAX_PER_LABEL} collected")

    # Layer 1 — RAGAs
    print(f"\nRunning RAGAs evaluation on {len(records)} records...")
    samples = [
        SingleTurnSample(
            user_input=r["alert_text"],
            response=r["output_text"],
            retrieved_contexts=r["context_texts"],
        )
        for r in records
    ]
    ragas_result = evaluate(
        EvaluationDataset(samples=samples),
        metrics=[faithfulness, answer_relevancy],
        llm=judge_llm,
        embeddings=judge_emb,
    )

    # Layer 2 — rule-based + merge with RAGAs scores
    rows = []
    for i, r in enumerate(records):
        score = ragas_result.scores[i] if i < len(ragas_result.scores) else {}
        rows.append({
            "label":              r["label"],
            "severity_output":    r["severity"],
            "severity_verdict":   get_severity_verdict(r["severity"], r["label"]),
            "attack_type_hit":    get_attack_type_hit(r["label"], r["output_text"]),
            "hallucination_flag": get_hallucination_flag(r["alert_text"], r["output_text"]),
            "sigma_2514_hit":     "sigma_2514_c0" in r["context_ids"],
            "context_diversity":  get_context_diversity(r["context_ids"]),
            "faithfulness":       round(score.get("faithfulness", 0.0), 3),
            "answer_relevancy":   round(score.get("answer_relevancy", 0.0), 3),
        })

    # Write CSV report
    with open(REPORT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    # Summary
    total = len(rows)
    under = sum(1 for r in rows if r["severity_verdict"] == "underestimated")
    over  = sum(1 for r in rows if r["severity_verdict"] == "overestimated")
    hit   = sum(1 for r in rows if r["attack_type_hit"])
    hallu = sum(1 for r in rows if r["hallucination_flag"])
    sig   = sum(1 for r in rows if r["sigma_2514_hit"])
    avg_f = sum(r["faithfulness"]     for r in rows) / total
    avg_r = sum(r["answer_relevancy"] for r in rows) / total

    print(f"\n{'='*50}")
    print(f"Evaluation Summary  ({total} records)")
    print(f"{'='*50}")
    print(f"  Severity underestimated : {under}/{total} ({100*under//total}%)")
    print(f"  Severity overestimated  : {over}/{total}  ({100*over//total}%)")
    print(f"  Attack type hit         : {hit}/{total}   ({100*hit//total}%)")
    print(f"  Hallucination flagged   : {hallu}/{total} ({100*hallu//total}%)")
    print(f"  sigma_2514_c0 hit rate  : {sig}/{total}  ({100*sig//total}%)")
    print(f"  Faithfulness (avg)      : {avg_f:.3f}")
    print(f"  Answer relevancy (avg)  : {avg_r:.3f}")
    print(f"{'='*50}")
    print(f"\nReport saved: {REPORT_FILE}")


if __name__ == "__main__":
    main()
