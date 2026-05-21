# Evaluation Report: Prompt Template Comparison

**Ground Truth**: `ground_truth.json` (3 samples)

## Summary Table

| Metric | basic | cot | few_shot |
|--------|------:|----:|---------:|
| Severity correct | 3 | 1 | 1 |
| Severity underestimated | 0 | 2 | 0 |
| Severity overestimated | 0 | 0 | 2 |
| Attack semantic hit | 0 | 0 | 0 |
| Hallucination flagged | 0 | 0 | 0 |
| Avg faithfulness | 0.0 | 0.0 | None |
| Avg answer relevancy | 0.828 | 0.789 | None |
| Avg answer correctness | 0.504 | 0.514 | None |
| Avg context precision | 0.0 | 0.0 | None |
| Avg context recall | 0.0 | 0.0 | 0.0 |

## Output Files

| Template | CSV Report | JSON Results |
|----------|------------|--------------|
| basic | `evaluation_report_basic.csv` | `evaluation_results_basic.json` |
| cot | `evaluation_report_cot.csv` | `evaluation_results_cot.json` |
| few_shot | `evaluation_report_few_shot.csv` | `evaluation_results_few_shot.json` |