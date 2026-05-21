import argparse
import csv
import json
import math
import os
import sys
import time
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from ragas import EvaluationDataset, SingleTurnSample, evaluate
from ragas.metrics import (
    faithfulness,
    answer_relevancy,
    answer_correctness,
    context_precision,
    context_recall,
)
from google import genai
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings

from src.rag.service import RagService
from src.rag.settings import settings

# -- Config --------------------------------------------------

TEMPLATES = ["basic", "cot", "few_shot"]

GROUND_TRUTH_FILE = Path(__file__).parent.parent / "baselines" / "ground_truth.json"
OUTPUT_DIR = Path(__file__).parent

# -- Ground truth tables --------------------------------------------------

SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3, "Unknown": -1}

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

HALLUCINATION_PATTERNS = [
    ("SYN flood: NOT possible", "syn flood"),
    ("Zero-byte flow",          "exfiltrat"),
    ("server did not respond",  "established connection"),
]

# -- Rule-based metrics --------------------------------------------------------------

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

def get_hallucination_flag(alert_text: str, output_text: str) -> bool:
    alert_lower  = alert_text.lower()
    output_lower = output_text.lower()
    return any(
        cond in alert_lower and viol in output_lower
        for cond, viol in HALLUCINATION_PATTERNS
    )

def get_context_diversity(context_ids: list) -> str:
    has_cve   = any(cid.startswith("CVE") for cid in context_ids)
    has_mitre = any(cid.startswith("T")   for cid in context_ids)
    has_sigma = any("sigma" in cid        for cid in context_ids)
    parts = [s for s, flag in [("cve", has_cve), ("mitre", has_mitre), ("sigma", has_sigma)] if flag]
    return "+".join(parts) if parts else "none"

# -- Key Management & LLM wrappers ---------------------------------------------------

class APIKeyManager:
    def __init__(self, keys: list[str], model_name: str):
        self.keys = [k for k in keys if k]
        self.model_name = model_name
        self.current_idx = 0
        if not self.keys:
            raise ValueError("No Google API keys provided")
        self._set_env()

    def get_current_key(self) -> str:
        return self.keys[self.current_idx]

    def _set_env(self):
        os.environ["GEMINI_API_KEY"] = self.get_current_key()

    def next_key(self):
        if len(self.keys) <= 1:
            print("  [KeyManager] Only one key available. Not rotating.")
            return
        self.current_idx = (self.current_idx + 1) % len(self.keys)
        self._set_env()
        print(f"  [KeyManager] Switched to API key index {self.current_idx}")

    def get_judge_llm(self):
        return ChatGoogleGenerativeAI(
            model=self.model_name, 
            google_api_key=self.get_current_key(),
            max_retries=0 # Disable automatic internal retries to handle rate limits manually
        )

    def get_judge_emb(self):
        return GoogleGenerativeAIEmbeddings(
            model="gemini-embedding-001", 
            google_api_key=self.get_current_key()
        )

    def get_genai_client(self):
        return genai.Client(api_key=self.get_current_key())

def judge_attack_type(key_manager: APIKeyManager, label: str, output_text: str) -> bool:
    prompt = (
        f"You are an elite SOC expert. Read the threat analysis report below and answer with only True or False:\n"
        f"Does the report correctly analyze and identify signs of a [{label}] attack?\n\n"
        f"Report:\n{output_text}"
    )
    for attempt in range(10):
        try:
            client = key_manager.get_genai_client()
            response = client.models.generate_content(model=key_manager.model_name, contents=prompt)
            return response.text.strip().lower().startswith("true")
        except Exception as e:
            err_str = str(e).lower()
            if "429" in err_str or "quota" in err_str or "resourceexhausted" in err_str:
                print(f"  [Rate Limit] Gemini API rate limit hit in judge_attack_type. Rotating key...")
                key_manager.next_key()
                time.sleep(2)
            else:
                if attempt == 9:
                    raise e
                print(f"  [GenAI Error] {e} (attempt {attempt+1}). Retrying...")
                time.sleep(5)
    return False

def run_ragas_evaluate_with_retry(key_manager: APIKeyManager, sample: SingleTurnSample) -> dict:
    for attempt in range(10):
        try:
            judge_llm = key_manager.get_judge_llm()
            judge_emb = key_manager.get_judge_emb()
            
            ragas_result = evaluate(
                EvaluationDataset(samples=[sample]),
                metrics=[faithfulness, answer_relevancy, answer_correctness, context_precision, context_recall],
                llm=judge_llm,
                embeddings=judge_emb,
                show_progress=False
            )
            return ragas_result.scores[0] if len(ragas_result.scores) > 0 else {}
        except Exception as e:
            err_str = str(e).lower()
            if "429" in err_str or "quota" in err_str or "resourceexhausted" in err_str or "rate limit" in err_str:
                print(f"  [Rate Limit] Gemini API rate limit hit in RAGAS. Rotating key...")
                key_manager.next_key()
                time.sleep(2)
            else:
                if attempt == 9:
                    raise e
                print(f"  [RAGAS Error] {e} (attempt {attempt+1}). Retrying...")
                time.sleep(5)
    return {}

# -- Evaluation per template --------------------------------------------------------------

def evaluate_template(
    template_name: str,
    ground_truth: list,
    rag_service: RagService,
    key_manager: APIKeyManager,
    reset_checkpoint: bool = False,
) -> dict:
    print(f"\n{'='*60}")
    print(f"  Evaluating template: {template_name.upper()}")
    print(f"{'='*60}")

    checkpoint_file = OUTPUT_DIR / f"checkpoint_eval_{template_name}.json"
    
    if reset_checkpoint and checkpoint_file.exists():
        print(f"  [Reset] Deleting existing checkpoint: {checkpoint_file.name}")
        checkpoint_file.unlink()

    records = []
    
    # Load Checkpoint
    if checkpoint_file.exists():
        try:
            records = json.loads(checkpoint_file.read_text(encoding="utf-8"))
            print(f"  Loaded {len(records)} completed records from checkpoint.")
        except Exception as e:
            print(f"  Error reading checkpoint: {e}. Starting fresh.")
            records = []

    # Map processed labels to avoid re-evaluating
    processed_ids = {f"{r['label']}_{r['input']}" for r in records}

    for idx, entry in enumerate(ground_truth):
        label      = entry["label"]
        alert_text = entry["alert_text"]
        entry_id   = f"{label}_{alert_text}"
        
        print(f"\n  [{template_name}] Progress: {idx+1}/{len(ground_truth)} | Task: {label}")

        if entry_id in processed_ids:
            print(f"  -> Already processed. Skipping.")
            continue

        gt_output  = entry["output"]

        # 1. RAG inference
        rag_out = rag_service.analyze(
            alert_text=alert_text,
            k=5,
            source=None,
            template_name=template_name,
        )
        context_texts = rag_out.get("retrieved_contexts_text", [])
        reference = gt_output["threat_description"] + "\n" + gt_output["rationale"]

        output_text = rag_out.get("threat_description", "") + "\n" + rag_out.get("rationale", "")
        severity = rag_out.get("severity", "Unknown")

        sample = SingleTurnSample(
            user_input=alert_text,
            response=output_text,
            retrieved_contexts=context_texts,
            reference=reference,
        )

        # 2. RAGAs Evaluation
        print(f"  -> Running RAGAs evaluation...")
        score = run_ragas_evaluate_with_retry(key_manager, sample)

        # 3. SOC Domain Evaluation
        print(f"  -> Running SOC domain evaluation...")
        attack_hit = judge_attack_type(key_manager, label, output_text)
        
        severity_verdict = get_severity_verdict(severity, label)
        hallucination_flag = get_hallucination_flag(alert_text, output_text)
        context_ids = rag_out.get("retrieved_context_ids", [])
        sigma_2514_hit = "sigma_2514_c0" in context_ids
        context_diversity = get_context_diversity(context_ids)

        def _safe(val, default=None):
            if val is None or (isinstance(val, float) and math.isnan(val)):
                return default
            return round(val, 3)

        record = {
            "label":      label,
            "raw_packet": entry.get("raw_packet", {}),
            "input":      alert_text,
            "reference":  reference,
            "output": {
                "threat_description":      rag_out.get("threat_description", ""),
                "severity":                severity,
                "rationale":               rag_out.get("rationale", ""),
                "mitigation_steps":        rag_out.get("mitigation_steps", []),
                "retrieved_context_ids":   context_ids,
                "retrieved_contexts_text": context_texts,
            },
            "evaluation": {
                "severity_verdict":    severity_verdict,
                "attack_semantic_hit": attack_hit,
                "hallucination_flag":  hallucination_flag,
                "sigma_2514_hit":      sigma_2514_hit,
                "context_diversity":   context_diversity,
                "faithfulness":        _safe(score.get("faithfulness")),
                "answer_relevancy":    _safe(score.get("answer_relevancy")),
                "answer_correctness":  _safe(score.get("answer_correctness")),
                "context_precision":   _safe(score.get("context_precision")),
                "context_recall":      _safe(score.get("context_recall")),
            },
        }

        records.append(record)
        processed_ids.add(entry_id)

        # Output Intermediate Results
        print(f"  -> [Result] Answer Correctness: {record['evaluation']['answer_correctness']} | Semantic Hit: {attack_hit}")

        # Save Checkpoint
        checkpoint_file.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
        
        # Rotate Key after task completion
        print(f"  -> [Task Complete] Rotating API Key...")
        key_manager.next_key()


    # Final Write: CSV
    csv_file = OUTPUT_DIR / f"evaluation_report_{template_name}.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        if records:
            fieldnames = ["label", "severity_output", "severity_verdict", "attack_semantic_hit", "hallucination_flag", "sigma_2514_hit", "context_diversity", "faithfulness", "answer_relevancy", "answer_correctness", "context_precision", "context_recall"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in records:
                eval_data = r["evaluation"]
                writer.writerow({
                    "label": r["label"],
                    "severity_output": r["output"]["severity"],
                    "severity_verdict": eval_data["severity_verdict"],
                    "attack_semantic_hit": eval_data["attack_semantic_hit"],
                    "hallucination_flag": eval_data["hallucination_flag"],
                    "sigma_2514_hit": eval_data["sigma_2514_hit"],
                    "context_diversity": eval_data["context_diversity"],
                    "faithfulness": eval_data["faithfulness"],
                    "answer_relevancy": eval_data["answer_relevancy"],
                    "answer_correctness": eval_data["answer_correctness"],
                    "context_precision": eval_data["context_precision"],
                    "context_recall": eval_data["context_recall"],
                })

    # Final Write: JSON
    json_file = OUTPUT_DIR / f"evaluation_results_{template_name}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)

    def _nanmean(records, key):
        vals = [r["evaluation"][key] for r in records if r["evaluation"][key] is not None]
        return round(sum(vals) / len(vals), 3) if vals else None

    # Compute Summary
    total = len(records)
    summary = {
        "template":              template_name,
        "total":                 total,
        "severity_underestimated": sum(1 for r in records if r["evaluation"]["severity_verdict"] == "underestimated"),
        "severity_overestimated":  sum(1 for r in records if r["evaluation"]["severity_verdict"] == "overestimated"),
        "severity_correct":        sum(1 for r in records if r["evaluation"]["severity_verdict"] == "correct"),
        "attack_semantic_hit":     sum(1 for r in records if r["evaluation"]["attack_semantic_hit"]),
        "hallucination_flagged":   sum(1 for r in records if r["evaluation"]["hallucination_flag"]),
        "sigma_2514_hit":          sum(1 for r in records if r["evaluation"]["sigma_2514_hit"]),
        "avg_faithfulness":        _nanmean(records, "faithfulness"),
        "avg_answer_relevancy":    _nanmean(records, "answer_relevancy"),
        "avg_answer_correctness":  _nanmean(records, "answer_correctness"),
        "avg_context_precision":   _nanmean(records, "context_precision"),
        "avg_context_recall":      _nanmean(records, "context_recall"),
    }

    print(f"\n  [{template_name.upper()}] Summary:")
    print(f"    Severity correct       : {summary['severity_correct']}/{total}")
    print(f"    Attack semantic hit    : {summary['attack_semantic_hit']}/{total}")
    print(f"    Hallucination flagged  : {summary['hallucination_flagged']}/{total}")
    print(f"    Avg faithfulness       : {summary['avg_faithfulness']}")
    print(f"    Avg answer_correctness : {summary['avg_answer_correctness']}")
    print(f"  CSV : {csv_file}")
    print(f"  JSON: {json_file}")

    return summary

# -- Main --------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Run RAG evaluation with RAGAs and SOC domain metrics.")
    parser.add_argument("--reset", action="store_true", help="Delete existing checkpoints and start evaluation from scratch.")
    args = parser.parse_args()

    if not GROUND_TRUTH_FILE.exists():
        print(f"Error: ground_truth.json not found at {GROUND_TRUTH_FILE}")
        sys.exit(1)

    keys = [
        settings.google_api_key,
        settings.google_api_key_2,
        settings.google_api_key_3,
        settings.google_api_key_4,
        settings.google_api_key_5,
    ]
    google_model_name = settings.google_model_name

    try:
        key_manager = APIKeyManager(keys, google_model_name)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    rag_service = RagService()

    ground_truth = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))
    
    #* This is for tét
    ground_truth = ground_truth[:3]
    
    print(f"Loaded {len(ground_truth)} entries from {GROUND_TRUTH_FILE}")

    all_summaries = []
    for template in TEMPLATES:
        summary = evaluate_template(
            template_name=template,
            ground_truth=ground_truth,
            rag_service=rag_service,
            key_manager=key_manager,
            reset_checkpoint=args.reset,
        )
        all_summaries.append(summary)

    # Metrics to compare
    metrics = [
        ("severity_correct",       "Severity correct"),
        ("severity_underestimated","Severity underestimated"),
        ("severity_overestimated", "Severity overestimated"),
        ("attack_semantic_hit",    "Attack semantic hit"),
        ("hallucination_flagged",  "Hallucination flagged"),
        ("avg_faithfulness",       "Avg faithfulness"),
        ("avg_answer_relevancy",   "Avg answer relevancy"),
        ("avg_answer_correctness", "Avg answer correctness"),
        ("avg_context_precision",  "Avg context precision"),
        ("avg_context_recall",     "Avg context recall"),
    ]

    # Print to console
    print(f"\n{'='*80}")
    print("  COMPARISON ACROSS TEMPLATES")
    print(f"{'='*80}")
    for key, label in metrics:
        vals = [s[key] for s in all_summaries]
        print(f"  {label:<25}: basic={vals[0]:<8} cot={vals[1]:<8} few_shot={vals[2]}")
    print(f"{'='*80}")

    # Generate markdown report
    total = all_summaries[0]["total"] if all_summaries else 0
    md_lines = [
        "# Evaluation Report: Prompt Template Comparison",
        "",
        f"**Ground Truth**: `{GROUND_TRUTH_FILE.name}` ({total} samples)",
        "",
        "## Summary Table",
        "",
        "| Metric | basic | cot | few_shot |",
        "|--------|------:|----:|---------:|",
    ]
    for key, label in metrics:
        vals = [all_summaries[i][key] for i in range(3)]
        md_lines.append(f"| {label} | {vals[0]} | {vals[1]} | {vals[2]} |")

    md_lines += [
        "",
        "## Output Files",
        "",
        "| Template | CSV Report | JSON Results |",
        "|----------|------------|--------------|",
        f"| basic | `evaluation_report_basic.csv` | `evaluation_results_basic.json` |",
        f"| cot | `evaluation_report_cot.csv` | `evaluation_results_cot.json` |",
        f"| few_shot | `evaluation_report_few_shot.csv` | `evaluation_results_few_shot.json` |",
    ]

    md_file = OUTPUT_DIR / "evaluation_comparison.md"
    md_file.write_text("\n".join(md_lines), encoding="utf-8")

    # Save JSON comparison
    json_file = OUTPUT_DIR / "evaluation_comparison.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(all_summaries, f, ensure_ascii=False, indent=2)

    print(f"\nReports saved:")
    print(f"  Markdown: {md_file}")
    print(f"  JSON:     {json_file}")


if __name__ == "__main__":
    main()
