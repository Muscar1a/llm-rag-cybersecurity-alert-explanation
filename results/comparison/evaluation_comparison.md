# Evaluation Report: Prompt Template Comparison

**Ground Truth**: `ground_truth.json` (16 samples)

## Summary Table

| Metric | basic | cot | few_shot |
|--------|------:|----:|---------:|
| Severity correct | 10 | 10 | 5 |
| Severity underestimated | 6 | 6 | 3 |
| Severity overestimated | 0 | 0 | 8 |
| Attack semantic hit | 2 | 2 | 1 |
| Hallucination flagged | 0 | 0 | 1 |
| Avg hallucination rate | 0.87 | 0.842 | 0.964 |
| Avg answer relevancy | 0.55 | 0.577 | 0.591 |
| Avg answer correctness | 0.614 | 0.601 | 0.583 |
| Avg context precision | 0.524 | 0.483 | 0.536 |
| Avg context recall | 0.635 | 0.464 | 0.438 |
| Avg response latency (s) | 40.369 | 43.838 | 44.411 |

## Output Files

| Template | CSV Report | JSON Results |
|----------|------------|--------------|
| basic | `evaluation_report_basic.csv` | `evaluation_results_basic.json` |
| cot | `evaluation_report_cot.csv` | `evaluation_results_cot.json` |
| few_shot | `evaluation_report_few_shot.csv` | `evaluation_results_few_shot.json` |