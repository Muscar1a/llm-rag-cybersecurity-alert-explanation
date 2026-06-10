import numpy as np

def evaluate_latency(latency_list: list[float]) -> dict:
    if not latency_list:
        return {}
    return {
        "p50_latency_s": round(np.percentile(latency_list, 50), 3),
        "avg_latency_s": round(np.mean(latency_list), 3),
    }
