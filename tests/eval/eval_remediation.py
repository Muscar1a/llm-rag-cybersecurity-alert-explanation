import numpy as np
from .utils import get_judge_emb

SIMILARITY_THRESHOLD = 0.7


def evaluate_remediation(samples_data: list[dict], rem_gt_by_id: dict) -> dict:
    """Evaluate remediation description quality using embedding similarity.

    Compares LLM-generated remediation descriptions against ground truth.
    Commands are excluded from evaluation.
    """
    emb_model = get_judge_emb()

    desc_recalls = []
    desc_precisions = []
    per_tactic: dict[str, dict] = {}

    for s in samples_data:
        aid = s.get("id")
        tactic = s.get("label_tactic", "Unknown")

        if tactic not in per_tactic:
            per_tactic[tactic] = {"recalls": [], "precisions": []}
        pt = per_tactic[tactic]

        if aid is None or aid not in rem_gt_by_id:
            continue
        gt_rem = rem_gt_by_id[aid].get("remediation", [])
        if not gt_rem:
            continue

        llm_descs = [
            cmd["description"]
            for cmd in s.get("remediation_commands", [])
            if isinstance(cmd, dict) and cmd.get("description")
        ]

        if not llm_descs:
            any_gt = any(step for v in gt_rem for step in v.get("steps", []))
            if any_gt:
                desc_recalls.append(0.0)
                pt["recalls"].append(0.0)
            continue

        llm_vecs = np.array(emb_model.embed_documents(llm_descs))

        # Recall: best-matching variant (LLM might follow one strategy)
        best_recall = 0.0
        for variant in gt_rem:
            v_descs = [step["description"] for step in variant.get("steps", []) if step.get("description")]
            if not v_descs:
                continue
            v_vecs = np.array(emb_model.embed_documents(v_descs))
            sim = v_vecs @ llm_vecs.T
            matched = int((sim.max(axis=1) >= SIMILARITY_THRESHOLD).sum())
            best_recall = max(best_recall, matched / len(v_descs))

        desc_recalls.append(best_recall)
        pt["recalls"].append(best_recall)

        # Precision: LLM description matches any GT description across all variants
        all_gt_descs = [
            step["description"]
            for v in gt_rem for step in v.get("steps", [])
            if step.get("description")
        ]
        if all_gt_descs:
            gt_vecs = np.array(emb_model.embed_documents(all_gt_descs))
            sim = gt_vecs @ llm_vecs.T
            llm_matched = int((sim.max(axis=0) >= SIMILARITY_THRESHOLD).sum())
            precision = llm_matched / len(llm_descs)
        else:
            precision = 0.0

        desc_precisions.append(precision)
        pt["precisions"].append(precision)

    def _avg(lst):
        return round(sum(lst) / len(lst), 3) if lst else None

    tactic_summary = {}
    for tactic, vals in sorted(per_tactic.items()):
        tactic_summary[tactic] = {
            "desc_recall": _avg(vals["recalls"]),
            "desc_precision": _avg(vals["precisions"]),
        }

    return {
        "avg_desc_recall": _avg(desc_recalls),
        "avg_desc_precision": _avg(desc_precisions),
        "per_tactic": tactic_summary,
    }
