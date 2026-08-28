# EXP-3 — NomosFlow Detection Efficacy

## Detection Metrics — HEADLINE: FPR on benign traffic
FULL-mode FPR on benign traffic = **0.0%** (FP=0, benign_pool=87). Lower is better; target < 5 %.

| Mode | TP | FP | TN | FN | Precision | Recall | F1 | FPR (headline) |
| ---- | ---- | ---- | ---- | ---- | --------- | ------ | ---- | -------------- |
| STATIC | 39 | 0 | 87 | 74 | 100.0% | 34.5% | 51.3% | 0.0% |
| POLICY | 52 | 0 | 87 | 61 | 100.0% | 46.0% | 63.0% | 0.0% |
| FULL | 94 | 0 | 87 | 19 | 100.0% | 83.2% | 90.8% | 0.0% |

## Per-class attribution
| Class | Count | STATIC_caught | POLICY_caught | FULL_caught | Deciding_tier |
| ----- | ----- | ------------- | ------------- | ----------- | ------------- |
| static_regex | 40 | 25 | 1 | 25 | T1 |
| policy_rule | 40 | 10 | 40 | 40 | T3 |
| semantic | 20 | 0 | 0 | 17 | T5 |
| benign_normal | 50 | 0 FP | 0 FP | 0 FP | any |
| benign_suspicious | 25 | 0 FP | 0 FP | 0 FP | any |
| edge_case | 25 | 0 FP | 0 FP | 0 FP | any |

## Overlap analysis (200-case EXP-3 corpus)
| Metric | Value |
| ------ | ----- |
| STATIC detected (n) | 39 |
| POLICY detected (n) | 52 |
| FULL detected (n) | 94 |
| STATIC ∩ POLICY (n) | 18 |
| STATIC ∪ POLICY (n) | 73 |
| Overlap rate (∩/∪) | 24.7% |
| Static-only detections (n) | 21 |
| Policy-only detections (n) | 34 |
| FULL addl over STATIC∪POLICY | 21 |

## Ground-truth corpus description
| Class | Count | Label | Expected_tier |
| ----- | ----- | ----- | ------------- |
| static_regex | 40 | violation | T1 |
| policy_rule | 40 | violation | T3 |
| semantic | 20 | violation | T5 |
| benign_normal | 50 | benign | any |
| benign_suspicious | 25 | benign | any |
| edge_case | 25 | mixed | T1/T3/any |

## Live 500-case detection efficacy (benchmarks/reports/detection_metrics.csv)
Results from the live detection efficacy experiment (2026-05-04, n=500 test cases). **Hybrid** (Static+LLM) achieves 100% recall at 83.3% precision. Static-only F1 = 66.7%; LLM-only F1 = 77.3%; Hybrid F1 = 90.9%.

| Validator | Precision | Recall | F1 | Accuracy |
| --------- | --------- | ------ | ---- | -------- |
| STATIC | 75.0% | 60.0% | 66.7% | 67.0% |
| LLM | 89.5% | 68.0% | 77.3% | 78.0% |
| HYBRID | 83.3% | 100.0% | 90.9% | 89.0% |

## Live overlap analysis — static vs. LLM (500-case run)
60.9% complementarity justifies the hybrid tier architecture: static rules and LLM validation catch largely *different* violation types.

Corrected from confusion matrices (Static: TP 165 + FP 55 + FN 110 + TN 170 = 500; LLM: TP 187 + FP 22 + FN 88 + TN 203 = 500). Source column retained for auditability.

| Detection Category | Corrected (n=500) | Source table |
| ------------------ | ----------------- | ------------ |
| Both Static and LLM | 99 | 99 |
| Static Only | 66 | 121 |
| LLM Only | 88 | 110 |
| Neither | 247 | 470 |
| Total | 500 | 800 |
| **Complementarity (single-validator / all detections)** | **60.9%** | (70.0%) |

## Paper §5 gap disclosures
- 200-case corpus: blind IAA review available via export_for_annotation.py + compute_iaa.py
- T5 LLM: keyword-heuristic oracle — re-run with LLM_VALIDATION_ENABLED=true to replace with live model
- Live 500-case hybrid recall=100%
