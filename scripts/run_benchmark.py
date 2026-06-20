import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml

from src.rag.service import RagService
from src.mlops.tracking import log_rag_experiment, register_rag_pipeline
from tests.eval.eval_latency import evaluate_latency
from tests.eval.eval_retrieval import evaluate_retrieval
from tests.eval.eval_generation import evaluate_generation
from tests.eval.eval_remediation import evaluate_remediation

DEFAULT_TEMPLATES = ["basic", "cot", "few_shot"]
GROUND_TRUTH_FILE = project_root / "baselines" / "ground_truth.json"
ALERTS_FILE = project_root / "tests" / "alerts.json"
REMEDIATION_GT_FILE = project_root / "baselines" / "remediation_gt.json"
RESULTS_DIR = project_root / "results"
PARAMS_FILE = project_root / "params.yaml"


def get_git_sha():
    try:
        import subprocess
        return subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']).decode('ascii').strip()
    except Exception:
        return "unknown"


def sample_balanced(gt_data: list, n: int) -> list:
    seen = set()
    out = []
    for r in gt_data:
        if r["label_tactic"] not in seen:
            seen.add(r["label_tactic"])
            out.append(r)
            if len(out) >= n:
                return out
    for r in gt_data:
        if r not in out:
            out.append(r)
            if len(out) >= n:
                return out
    return out


def _save_ckpt(ckpt_file: Path, state: dict):
    ckpt_file.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


def run_template(
    template: str,
    sampled: list,
    rag_service: RagService,
    retrieval_k: int,
    version: str,
    reset: bool,
    alerts_by_id: dict | None = None,
    rem_gt_by_id: dict | None = None,
) -> tuple[dict, Path, bool]:
    """Run benchmark for one template. Returns (summary, json_file, was_resumed_done)."""
    ckpt_dir = RESULTS_DIR / "checkpoints"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    ckpt_file = ckpt_dir / f"checkpoint_{template}_{version}.json"

    if reset and ckpt_file.exists():
        print(f"  [Reset] Deleting checkpoint: {ckpt_file.name}")
        ckpt_file.unlink()

    state = {"samples_data": [], "phase": "inference", "next_idx": 0}
    if ckpt_file.exists():
        try:
            state = json.loads(ckpt_file.read_text(encoding="utf-8"))
            print(f"  Resumed from checkpoint: phase={state['phase']}, next_idx={state['next_idx']}/{len(sampled)}")
        except Exception as e:
            print(f"  Failed to load checkpoint: {e}. Starting fresh.")
            state = {"samples_data": [], "phase": "inference", "next_idx": 0}

    samples_data = state["samples_data"]
    already_done = state["phase"] == "done"

    # Pass 1: RAG inference
    if state["phase"] == "inference":
        print(f"\n  [Pass 1/2] RAG inference (template={template})")
        for i in range(state["next_idx"], len(sampled)):
            entry = sampled[i]
            alert_id = entry.get("id")
            print(f"  [{template}] {i+1}/{len(sampled)} | Inference | {entry['label_tactic']} / {entry.get('label_technique', '')}")

            metadata = None
            if alerts_by_id and alert_id is not None:
                alert_data = alerts_by_id.get(alert_id)
                if alert_data:
                    net = alert_data["network"]
                    metadata = {
                        "src_ip": net.get("src_ip"),
                        "dest_ip": net.get("dest_ip"),
                        "dest_port": net.get("dest_port"),
                        "proto": net.get("proto"),
                        "conn_state": net.get("conn_state"),
                    }

            t0 = time.perf_counter()
            rag_out = rag_service.analyze(
                alert_text=entry["alert_text"],
                k=retrieval_k,
                template_name=template,
                metadata=metadata,
            )
            latency = time.perf_counter() - t0

            output_text = rag_out.get("threat_description", "") + "\n" + rag_out.get("rationale", "")

            samples_data.append({
                "id": alert_id,
                "alert_text": entry["alert_text"],
                "label_tactic": entry["label_tactic"],
                "label_technique": entry.get("label_technique", ""),
                "output_text": output_text,
                "retrieved_contexts": rag_out.get("retrieved_contexts_text", []),
                "reference": entry["reference"],
                "latency_s": round(latency, 3),
                "gt_severity": entry.get("severity"),
                "llm_severity": rag_out.get("severity", "Unknown"),
                "remediation_commands": rag_out.get("remediation_commands", []),
            })
            state["next_idx"] = i + 1
            _save_ckpt(ckpt_file, state)
        state["phase"] = "eval"
        state["next_idx"] = 0
        _save_ckpt(ckpt_file, state)

    # Pass 2: Per-sample judge eval (retrieval + generation), checkpoint after each
    if state["phase"] == "eval":
        print(f"\n  [Pass 2/2] Judge evaluation (template={template})")
        for i in range(state["next_idx"], len(samples_data)):
            s = samples_data[i]
            print(f"  [{template}] {i+1}/{len(samples_data)} | Eval | {s['label_tactic']}")
            retr = evaluate_retrieval([s])[0]
            gen = evaluate_generation([s])[0]
            s.update(retr)
            s.update(gen)
            state["next_idx"] = i + 1
            _save_ckpt(ckpt_file, state)
        state["phase"] = "done"
        _save_ckpt(ckpt_file, state)

    # Compute summary
    latencies = [s["latency_s"] for s in samples_data if "latency_s" in s]
    latency_metrics = evaluate_latency(latencies)

    def nanmean(key):
        vals = [d[key] for d in samples_data if d.get(key) is not None]
        return round(sum(vals) / len(vals), 3) if vals else None

    total = len(samples_data)
    summary = {
        "template": template,
        "total": total,
        **latency_metrics,
        "avg_context_recall": nanmean("context_recall"),
        "avg_answer_relevancy": nanmean("answer_relevancy"),
        "avg_hallucination_rate": nanmean("hallucination_rate"),
    }

    # Severity + remediation evaluation
    rem_summary = evaluate_remediation(samples_data, rem_gt_by_id or {})
    summary["severity_accuracy"] = rem_summary.get("severity_accuracy")
    summary["severity_correct"] = rem_summary.get("severity_correct")
    summary["severity_total"] = rem_summary.get("severity_total")
    summary["avg_cmd_recall"] = rem_summary.get("avg_cmd_recall")
    summary["avg_cmd_precision"] = rem_summary.get("avg_cmd_precision")
    summary["remediation_per_tactic"] = rem_summary.get("per_tactic")

    # Save final per-template JSON
    out_dir = RESULTS_DIR / template
    out_dir.mkdir(parents=True, exist_ok=True)
    json_file = out_dir / f"benchmark_{template}_{version}.json"
    json_file.write_text(
        json.dumps({"summary": summary, "samples": samples_data}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"\n  [{template.upper()}] Summary:")
    print(f"    p50 / avg latency (s)       : {summary.get('p50_latency_s')} / {summary.get('avg_latency_s')}")
    print(f"    Retrieval recall            : {summary['avg_context_recall']}")
    print(f"    Answer relevancy            : {summary['avg_answer_relevancy']}")
    print(f"    Hallucination rate          : {summary['avg_hallucination_rate']}")
    sev_str = f"{rem_summary.get('severity_correct')}/{rem_summary.get('severity_total')}"
    print(f"    Severity accuracy           : {summary['severity_accuracy']} ({sev_str})")
    print(f"    Remediation cmd recall      : {summary['avg_cmd_recall']}")
    print(f"    Remediation cmd precision   : {summary['avg_cmd_precision']}")
    if rem_summary.get("per_tactic"):
        print(f"    Per-tactic:")
        for tactic, tm in rem_summary["per_tactic"].items():
            print(f"      {tactic:25s} sev={tm['severity_accuracy']}  cmd_R={tm['cmd_recall']}  cmd_P={tm['cmd_precision']}  (n={tm['n']})")
    print(f"  JSON: {json_file}")

    return summary, json_file, already_done


COMPARISON_METRICS = [
    ("p50_latency_s",        "p50 latency (s)"),
    ("avg_latency_s",        "avg latency (s)"),
    ("avg_context_recall",   "Retrieval Recall"),
    ("avg_answer_relevancy", "Answer Relevance"),
    ("avg_hallucination_rate", "Hallucination Rate"),
    ("severity_accuracy",    "Severity Accuracy"),
    ("avg_cmd_recall",       "Remediation Cmd Recall"),
    ("avg_cmd_precision",    "Remediation Cmd Precision"),
]


def write_comparison(summaries: list[dict], templates: list[str], version: str, git_sha: str, n_samples: int):
    comp_dir = RESULTS_DIR / "comparison"
    comp_dir.mkdir(parents=True, exist_ok=True)

    json_path = comp_dir / f"comparison_{version}.json"
    json_path.write_text(json.dumps(summaries, ensure_ascii=False, indent=2), encoding="utf-8")

    header = "| Metric | " + " | ".join(templates) + " |"
    sep = "|--------|" + "|".join(["-----:"] * len(templates)) + "|"
    rows = [header, sep]
    for key, label in COMPARISON_METRICS:
        vals = " | ".join(str(s.get(key)) for s in summaries)
        rows.append(f"| {label} | {vals} |")

    md = "\n".join([
        f"# Benchmark Comparison ({version})",
        "",
        f"**Git SHA**: `{git_sha}` | **Samples per template**: {n_samples} | **Templates**: {', '.join(templates)}",
        "",
        "## Summary",
        "",
        *rows,
    ])
    md_path = comp_dir / f"comparison_{version}.md"
    md_path.write_text(md, encoding="utf-8")
    print(f"\nComparison saved:")
    print(f"  JSON: {json_path}")
    print(f"  MD:   {md_path}")


def main():
    parser = argparse.ArgumentParser(description="Unified RAG benchmark — runs one or more prompt templates with checkpointing and MLflow logging.")
    parser.add_argument("--samples", type=int, default=135, help="Sample size per template (default: 135)")
    parser.add_argument("--templates", type=str, default=",".join(DEFAULT_TEMPLATES),
                        help=f"Comma-separated templates (default: {','.join(DEFAULT_TEMPLATES)})")
    parser.add_argument("--reset", action="store_true", help="Delete existing checkpoints and start fresh")
    parser.add_argument("--version", type=str, default="v1", help="Version tag (default: v1). Used in output paths and checkpoint names.")
    args = parser.parse_args()

    templates = [t.strip() for t in args.templates.split(",") if t.strip()]
    invalid = [t for t in templates if t not in DEFAULT_TEMPLATES]
    if invalid:
        print(f"Error: unknown template(s): {invalid}. Valid: {DEFAULT_TEMPLATES}")
        sys.exit(1)

    if not GROUND_TRUTH_FILE.exists():
        print(f"Error: ground truth not found at {GROUND_TRUTH_FILE}")
        sys.exit(1)
    if not PARAMS_FILE.exists():
        print(f"Error: params.yaml not found at {PARAMS_FILE}")
        sys.exit(1)

    with open(PARAMS_FILE, "r", encoding="utf-8") as f:
        params = yaml.safe_load(f)
    retrieval_k = params["retrieval"]["k"]

    gt_data = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))
    sampled = sample_balanced(gt_data, args.samples)
    print(f"Evaluating {len(sampled)} samples × {len(templates)} template(s): {templates}")

    alerts_by_id = {}
    if ALERTS_FILE.exists():
        alerts_list = json.loads(ALERTS_FILE.read_text(encoding="utf-8"))
        alerts_by_id = {a["id"]: a for a in alerts_list}

    rem_gt_by_id = {}
    if REMEDIATION_GT_FILE.exists():
        rem_list = json.loads(REMEDIATION_GT_FILE.read_text(encoding="utf-8"))
        rem_gt_by_id = {r["id"]: r for r in rem_list}

    rag_service = RagService()
    git_sha = get_git_sha()

    base_params = {
        "embed_model": params["embedding"]["model_name"],
        "embed_dim": params["embedding"]["dim"],
        "chunk_size": params["chunking"]["chunk_size"],
        "retrieval_k": retrieval_k,
        "llm_model": params["llm"]["model"],
        "llm_temp": params["llm"]["temperature"],
        "git_sha": git_sha,
        "num_samples": len(sampled),
    }

    all_summaries = []
    for template in templates:
        print(f"\n{'='*60}\n  Template: {template.upper()}\n{'='*60}")
        summary, json_file, already_done = run_template(
            template=template,
            sampled=sampled,
            rag_service=rag_service,
            retrieval_k=retrieval_k,
            version=args.version,
            reset=args.reset,
            alerts_by_id=alerts_by_id,
            rem_gt_by_id=rem_gt_by_id,
        )
        all_summaries.append(summary)

        if already_done:
            print(f"  [MLflow] Skipped (checkpoint phase=done). Use --reset to re-log.")
            continue

        mlflow_metrics = {
            k: v for k, v in summary.items()
            if isinstance(v, (int, float)) and v is not None and k != "total"
        }
        run_id = log_rag_experiment(
            run_name=f"benchmark_{template}_{args.version}",
            params={**base_params, "template": template},
            metrics=mlflow_metrics,
            artifacts=[str(json_file)],
            tags={
                "type": "benchmark",
                "template": template,
                "git_sha": git_sha,
                "version": args.version,
            },
        )
        register_rag_pipeline(run_id)

    if len(templates) > 1:
        write_comparison(all_summaries, templates, args.version, git_sha, len(sampled))

    print(f"\n[+] Benchmark completed.")


if __name__ == "__main__":
    main()
