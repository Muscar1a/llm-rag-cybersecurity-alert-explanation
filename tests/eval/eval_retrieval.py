import time
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from ragas import EvaluationDataset, SingleTurnSample, evaluate, RunConfig
from ragas.metrics import context_precision, context_recall
from .utils import get_judge_llm, get_judge_emb, safe_val, get_context_diversity, _is_rate_limit

_RAGAS_RUN_CONFIG = RunConfig(timeout=180, max_retries=2, max_workers=1)

def evaluate_retrieval(samples_data: list[dict]) -> list[dict]:
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
                    metrics=[context_precision, context_recall],
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
                    print(f"  [Error] Retrieval eval failed: {e}")
                    break
                wait = 5 * (2 ** attempt) if _is_rate_limit(e) else 5
                print(f"  [eval_retrieval] attempt {attempt+1} failed ({e}), retrying in {wait}s...")
                time.sleep(wait)
                
        diversity = get_context_diversity(entry["context_ids"])
        
        results.append({
            "context_precision": safe_val(scores.get("context_precision")),
            "context_recall": safe_val(scores.get("context_recall")),
            "context_diversity": diversity
        })
        
    return results
