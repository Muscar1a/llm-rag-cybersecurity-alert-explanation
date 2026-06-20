def evaluate_remediation(samples_data: list[dict], rem_gt_by_id: dict) -> dict:
    """Compare engine remediation output against ground truth.

    Returns severity accuracy + command recall/precision metrics.
    """
    sev_correct = 0
    sev_total = 0
    cmd_recalls = []
    cmd_precisions = []
    per_tactic = {}

    for s in samples_data:
        aid = s.get("id")
        tactic = s.get("label_tactic", "Unknown")

        if tactic not in per_tactic:
            per_tactic[tactic] = {"sev_correct": 0, "sev_total": 0, "recalls": [], "precisions": []}
        pt = per_tactic[tactic]

        gt_sev = s.get("gt_severity", "")
        llm_sev = s.get("llm_severity", "")
        if gt_sev:
            sev_total += 1
            pt["sev_total"] += 1
            if llm_sev and gt_sev.strip().lower() == llm_sev.strip().lower():
                sev_correct += 1
                pt["sev_correct"] += 1

        if aid is None or aid not in rem_gt_by_id:
            continue
        gt_rem = rem_gt_by_id[aid].get("remediation", [])
        if not gt_rem:
            continue

        gt_cmds = set()
        for variant in gt_rem:
            for step in variant.get("steps", []):
                gt_cmds.add(_norm(step["command"]))

        engine_cmds = set()
        for cmd in s.get("remediation_commands", []):
            if isinstance(cmd, dict) and cmd.get("command"):
                engine_cmds.add(_norm(cmd["command"]))

        if gt_cmds:
            matched = len(gt_cmds & engine_cmds)
            recall = matched / len(gt_cmds)
            cmd_recalls.append(recall)
            pt["recalls"].append(recall)
        if engine_cmds:
            matched = len(gt_cmds & engine_cmds)
            precision = matched / len(engine_cmds)
            cmd_precisions.append(precision)
            pt["precisions"].append(precision)

    def _avg(lst):
        return round(sum(lst) / len(lst), 3) if lst else None

    tactic_summary = {}
    for tactic, pt in sorted(per_tactic.items()):
        tactic_summary[tactic] = {
            "severity_accuracy": round(pt["sev_correct"] / pt["sev_total"], 3) if pt["sev_total"] else None,
            "n": pt["sev_total"],
            "cmd_recall": _avg(pt["recalls"]),
            "cmd_precision": _avg(pt["precisions"]),
        }

    return {
        "severity_correct": sev_correct,
        "severity_total": sev_total,
        "severity_accuracy": round(sev_correct / sev_total, 3) if sev_total else None,
        "avg_cmd_recall": _avg(cmd_recalls),
        "avg_cmd_precision": _avg(cmd_precisions),
        "per_tactic": tactic_summary,
    }


def _norm(cmd: str) -> str:
    return " ".join(cmd.strip().split())
