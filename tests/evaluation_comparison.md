# Evaluation Report: Prompt Template Comparison

**Ground Truth**: `ground_truth.json` (3 samples)

## Summary Table

| Metric | basic | cot | few_shot |
|--------|------:|----:|---------:|
| Severity correct | 2 | 1 | 3 |
| Severity underestimated | 1 | 2 | 0 |
| Severity overestimated | 0 | 0 | 0 |
| Attack semantic hit | 0 | 0 | 0 |
| Hallucination flagged | 0 | 0 | 0 |
| Avg faithfulness | nan | nan | nan |
| Avg answer relevancy | nan | nan | nan |
| Avg answer correctness | nan | nan | nan |
| Avg context precision | nan | nan | nan |
| Avg context recall | nan | nan | nan |

## Output Files

| Template | CSV Report | JSON Results |
|----------|------------|--------------|
| basic | `evaluation_report_basic.csv` | `evaluation_results_basic.json` |
| cot | `evaluation_report_cot.csv` | `evaluation_results_cot.json` |
| few_shot | `evaluation_report_few_shot.csv` | `evaluation_results_few_shot.json` |