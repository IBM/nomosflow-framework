# EXP-3 — NomosFlow Detection Efficacy

*Generated: 2026-08-15T03:16:44.914403+00:00*

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
| static_regex | 40 | 25 | 10 | 31 | T1 |
| policy_rule | 40 | 10 | 34 | 34 | T3 |
| semantic | 20 | 0 | 0 | 19 | T5 |
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
70% complementarity justifies the hybrid tier architecture: static rules and LLM validation catch largely *different* violation types. Source: benchmarks/reports/detection_efficacy_tables.tex

| Detection Category | Count |
| ------------------ | ----- |
| Both Static and LLM | 99 |
| Static Only | 121 |
| LLM Only | 110 |
| Neither | 470 |
| **Overlap rate** | 30.0% |
| **Complementary rate** | 70.0% |

## Paper §5 gap disclosures
- 200-case corpus: blind IAA review available via export_for_annotation.py + compute_iaa.py
- T5 LLM: LIVE run via LLMValidator.validate_semantic_pii() (model=aws/claude-sonnet-4-5, cache=off, n=200 independent calls, IBM LiteLLM proxy, 2026-08-15)
- Live 500-case data from benchmarks/results/detection_efficacy_20260504_023855.json (simulate_latency=false, live validators); hybrid recall=100% on that dataset
