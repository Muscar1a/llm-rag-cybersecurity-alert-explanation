import argparse
import csv
import json
import math
import os
import sys
import time
from functools import lru_cache
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from ragas import EvaluationDataset, SingleTurnSample, evaluate, RunConfig
from ragas.metrics import (
    faithfulness,
    answer_relevancy,
    answer_correctness,
    context_precision,
    context_recall,
)
from langchain_ollama import ChatOllama
from langchain_huggingface import HuggingFaceEmbeddings

from src.rag.service import RagService
from src.rag.settings import settings

# -- Config --------------------------------------------------

TEMPLATES = ["basic", "cot", "few_shot"]

GROUND_TRUTH_FILE = Path(__file__).parent.parent / "baselines" / "ground_truth.json"
OUTPUT_DIR = Path(__file__).parent.parent / "results"

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

# -- LLM Helpers ---------------------------------------------------

@lru_cache(maxsize=1)
def get_judge_llm() -> ChatOllama:
    return ChatOllama(
        model=settings.ollama_judge_model,
        base_url=settings.ollama_host,
        temperature=0,
        # timeout=180,
    )

@lru_cache(maxsize=1)
def get_judge_emb() -> HuggingFaceEmbeddings:
    return HuggingFaceEmbeddings(
        model_name=settings.embedding_model,
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )

def judge_attack_type(label: str, output_text: str) -> bool:
    from langchain_core.messages import HumanMessage
    prompt = (
        f"You are an elite SOC expert. Read the threat analysis report below and answer with only True or False:\n"
        f"Does the report correctly analyze and identify signs of a [{label}] attack?\n\n"
        f"Report:\n{output_text}"
    )
    for attempt in range(5):
        try:
            llm = get_judge_llm()
            response = llm.invoke([HumanMessage(content=prompt)])
            return response.content.strip().lower().startswith("true")
        except Exception as e:
            if attempt == 4:
                raise e
            print(f"  [LLM Error] {e} (attempt {attempt+1}). Retrying...")
            time.sleep(5)
    return False

_RAGAS_RUN_CONFIG = RunConfig(timeout=180, max_retries=2, max_workers=1)

def run_ragas_evaluate_with_retry(sample: SingleTurnSample) -> dict:
    for attempt in range(3):
        try:
            ragas_result = evaluate(
                EvaluationDataset(samples=[sample]),
                metrics=[faithfulness, answer_relevancy, answer_correctness, context_precision, context_recall],
                llm=get_judge_llm(),
                embeddings=get_judge_emb(),
                run_config=_RAGAS_RUN_CONFIG,
                show_progress=False
            )
            return ragas_result.scores[0] if ragas_result.scores else {}
        except Exception as e:
            if attempt == 2:
                raise e
            print(f"  [RAGAS Error] {e} (attempt {attempt+1}). Retrying...")
            time.sleep(5)
    return {}

# -- Evaluation per template --------------------------------------------------------------

def _safe(val, default=None):
    if val is None or (isinstance(val, float) and math.isnan(val)):
        return default
    return round(val, 3)


def evaluate_template(
    template_name: str,
    ground_truth: list,
    rag_service: RagService,
    reset_checkpoint: bool = False,
    version: str = "v1",
) -> dict:
    print(f"\n{'='*60}")
    print(f"  Evaluating template: {template_name.upper()}")
    print(f"{'='*60}")

    checkpoint_dir = OUTPUT_DIR / "checkpoints"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_file = checkpoint_dir / f"checkpoint_eval_{template_name}_{version}.json"

    if reset_checkpoint and checkpoint_file.exists():
        print(f"  [Reset] Deleting existing checkpoint: {checkpoint_file.name}")
        checkpoint_file.unlink()

    records = []
    if checkpoint_file.exists():
        try:
            records = json.loads(checkpoint_file.read_text(encoding="utf-8"))
            print(f"  Loaded {len(records)} completed records from checkpoint.")
        except Exception as e:
            print(f"  Error reading checkpoint: {e}. Starting fresh.")
            records = []

    processed_ids = {f"{r['label']}_{r['input']}" for r in records}
    new_entries = [e for e in ground_truth if f"{e['label']}_{e['alert_text']}" not in processed_ids]

    if not new_entries:
        print("  All entries already processed.")
    else:
        # Pass 1: RAG inference — run all before loading judge model
        print(f"\n  [Pass 1/2] RAG inference: {len(new_entries)} entries...")
        rag_cache: dict[str, dict] = {}
        latency_cache: dict[str, float] = {}
        for i, entry in enumerate(new_entries):
            entry_id = f"{entry['label']}_{entry['alert_text']}"
            print(f"  [{template_name}] {i+1}/{len(new_entries)} | RAG | {entry['label']}")
            t0 = time.perf_counter()
            rag_cache[entry_id] = rag_service.analyze(
                alert_text=entry["alert_text"],
                k=5,
                source=None,
                template_name=template_name,
            )
            latency_cache[entry_id] = round(time.perf_counter() - t0, 3)

        # Pass 2: Judge evaluation — RAG model naturally unloads when judge first loads
        print(f"\n  [Pass 2/2] Evaluation: {len(new_entries)} entries...")
        for i, entry in enumerate(new_entries):
            label      = entry["label"]
            alert_text = entry["alert_text"]
            entry_id   = f"{label}_{alert_text}"
            gt_output  = entry["output"]
            rag_out    = rag_cache[entry_id]

            print(f"\n  [{template_name}] {i+1}/{len(new_entries)} | Eval | {label}")

            context_texts = rag_out.get("retrieved_contexts_text", [])
            reference     = gt_output["threat_description"] + "\n" + gt_output["rationale"]
            output_text   = rag_out.get("threat_description", "") + "\n" + rag_out.get("rationale", "")
            severity      = rag_out.get("severity", "Unknown")

            sample = SingleTurnSample(
                user_input=alert_text,
                response=output_text,
                retrieved_contexts=context_texts,
                reference=reference,
            )

            print(f"  -> Running RAGAs evaluation...")
            score = run_ragas_evaluate_with_retry(sample)

            print(f"  -> Running SOC domain evaluation...")
            attack_hit = judge_attack_type(label, output_text)

            context_ids       = rag_out.get("retrieved_context_ids", [])
            severity_verdict  = get_severity_verdict(severity, label)
            hallucination_flag = get_hallucination_flag(alert_text, output_text)
            context_diversity = get_context_diversity(context_ids)

            faith = _safe(score.get("faithfulness"))
            hallucination_rate = _safe(1.0 - faith) if faith is not None else None
            latency_s = latency_cache.get(entry_id)

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
                    "context_diversity":   context_diversity,
                    "hallucination_rate":  hallucination_rate,
                    "answer_relevancy":    _safe(score.get("answer_relevancy")),
                    "answer_correctness":  _safe(score.get("answer_correctness")),
                    "context_precision":   _safe(score.get("context_precision")),
                    "context_recall":      _safe(score.get("context_recall")),
                    "response_latency_s":  latency_s,
                },
            }

            records.append(record)
            processed_ids.add(entry_id)

            print(f"  -> [Result] Correctness: {record['evaluation']['answer_correctness']} | Semantic Hit: {attack_hit}")
            checkpoint_file.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")

    # Final Write: JSON
    result_dir = OUTPUT_DIR / template_name
    result_dir.mkdir(parents=True, exist_ok=True)
    json_file = result_dir / f"evaluation_results_{template_name}_{version}.json"
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
        "avg_hallucination_rate":   _nanmean(records, "hallucination_rate"),
        "avg_answer_relevancy":    _nanmean(records, "answer_relevancy"),
        "avg_answer_correctness":  _nanmean(records, "answer_correctness"),
        "avg_context_precision":   _nanmean(records, "context_precision"),
        "avg_context_recall":      _nanmean(records, "context_recall"),
        "avg_response_latency_s":  _nanmean(records, "response_latency_s"),
    }

    print(f"\n  [{template_name.upper()}] Summary:")
    print(f"    Severity correct        : {summary['severity_correct']}/{total}")
    print(f"    Attack semantic hit     : {summary['attack_semantic_hit']}/{total}")
    print(f"    Hallucination flagged   : {summary['hallucination_flagged']}/{total}")
    print(f"    Avg hallucination rate  : {summary['avg_hallucination_rate']}")
    print(f"    Avg answer_correctness  : {summary['avg_answer_correctness']}")
    print(f"    Avg response latency(s) : {summary['avg_response_latency_s']}")
    print(f"  JSON: {json_file}")

    return summary

# -- Main --------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Run RAG evaluation with RAGAs and SOC domain metrics.")
    parser.add_argument("--reset", action="store_true", help="Delete existing checkpoints and start evaluation from scratch.")
    parser.add_argument("--version", type=str, default="v1", help="Version identifier for output files (e.g., v3).")
    args = parser.parse_args()

    if not GROUND_TRUTH_FILE.exists():
        print(f"Error: ground_truth.json not found at {GROUND_TRUTH_FILE}")
        sys.exit(1)

    rag_service = RagService()

    ground_truth = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))
    
    ############
    # Sample exactly 1 record per attack type
    seen_labels = set()
    sampled_ground_truth = []
    for record in ground_truth:
        if record["label"] not in seen_labels:
            seen_labels.add(record["label"])
            sampled_ground_truth.append(record)
    ground_truth = sampled_ground_truth
    
    print(f"Loaded {len(ground_truth)} entries from {GROUND_TRUTH_FILE} (1 per category)")
    ############

    all_summaries = []
    for template in TEMPLATES:
        summary = evaluate_template(
            template_name=template,
            ground_truth=ground_truth,
            rag_service=rag_service,
            reset_checkpoint=args.reset,
            version=args.version,
        )
        all_summaries.append(summary)

    # Metrics to compare
    metrics = [
        ("severity_correct",        "Severity correct"),
        ("severity_underestimated", "Severity underestimated"),
        ("severity_overestimated",  "Severity overestimated"),
        ("attack_semantic_hit",     "Attack semantic hit"),
        ("hallucination_flagged",   "Hallucination flagged"),
        ("avg_hallucination_rate",  "Avg hallucination rate"),
        ("avg_answer_relevancy",    "Avg answer relevancy"),
        ("avg_answer_correctness",  "Avg answer correctness"),
        ("avg_context_precision",   "Avg context precision"),
        ("avg_context_recall",      "Avg context recall"),
        ("avg_response_latency_s",  "Avg response latency (s)"),
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
        f"# Evaluation Report: Prompt Template Comparison ({args.version})",
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
        "| Template | JSON Results |",
        "|----------|--------------|",
        f"| basic | `results/basic/evaluation_results_basic_{args.version}.json` |",
        f"| cot | `results/cot/evaluation_results_cot_{args.version}.json` |",
        f"| few_shot | `results/few_shot/evaluation_results_few_shot_{args.version}.json` |",
    ]

    comp_dir = OUTPUT_DIR / "comparison"
    comp_dir.mkdir(parents=True, exist_ok=True)
    md_file = comp_dir / f"evaluation_comparison_{args.version}.md"
    md_file.write_text("\n".join(md_lines), encoding="utf-8")

    # Save JSON comparison
    json_file = comp_dir / f"evaluation_comparison_{args.version}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(all_summaries, f, ensure_ascii=False, indent=2)

    print(f"\nReports saved:")
    print(f"  Markdown: {md_file}")
    print(f"  JSON:     {json_file}")


if __name__ == "__main__":
    main()
