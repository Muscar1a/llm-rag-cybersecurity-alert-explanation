import time
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from ragas import EvaluationDataset, SingleTurnSample, evaluate, RunConfig
from ragas.metrics import faithfulness, answer_relevancy, answer_correctness
from .utils import (
    get_judge_llm,
    get_judge_emb,
    safe_val,
    get_severity_verdict,
    get_hallucination_pattern_hit,
    judge_attack_type,
    _is_rate_limit,
)

_RAGAS_RUN_CONFIG = RunConfig(timeout=180, max_retries=5, max_workers=1)

# Groq API only supports n=1. Set strictness to 1 to prevent n=3 requests in answer_relevancy
answer_relevancy.strictness = 1

def evaluate_generation(samples_data: list[dict]) -> list[dict]:
    results = []

    for entry in samples_data:
        sample = SingleTurnSample(
            user_input=entry["alert_text"],
            response=entry["output_text"],
            retrieved_contexts=entry["retrieved_contexts"],
            reference=entry["reference"],
        )

        scores = {}
        for attempt in range(3):
            try:
                ragas_result = evaluate(
                    EvaluationDataset(samples=[sample]),
                    metrics=[faithfulness, answer_relevancy, answer_correctness],
                    llm=get_judge_llm(),
                    embeddings=get_judge_emb(),
                    run_config=_RAGAS_RUN_CONFIG,
                    show_progress=False
                )
                if ragas_result.scores:
                    scores = ragas_result.scores[0]
                break
            except Exception as e:
                if attempt == 2:
                    print(f"  [Error] Generation eval failed: {e}")
                    break
                wait = 5 * (2 ** attempt) if _is_rate_limit(e) else 5
                print(f"  [eval_generation] attempt {attempt+1} failed ({e}), retrying in {wait}s...")
                time.sleep(wait)

        # Courtesy delay to avoid bursting the Groq rate limit
        time.sleep(3)

        severity_verdict = get_severity_verdict(entry["severity"], entry["label"])
        pattern_hit = get_hallucination_pattern_hit(entry["alert_text"], entry["output_text"])
        attack_hit = judge_attack_type(entry["label"], entry["output_text"])

        faith = safe_val(scores.get("faithfulness"))
        correctness = safe_val(scores.get("answer_correctness"))

        results.append({
            "faithfulness": faith,
            "answer_relevancy": safe_val(scores.get("answer_relevancy")),
            "answer_correctness": correctness,
            "severity_verdict": severity_verdict,
            "hallucination_intrinsic": round(1.0 - faith, 3) if faith is not None else None,
            "hallucination_extrinsic": round(1.0 - correctness, 3) if correctness is not None else None,
            "hallucination_pattern_hit": pattern_hit,
            "attack_semantic_hit": attack_hit
        })

    return results
