# EXP-7 baseline coverage comparison

*Generated: 2026-08-28T21:40:28.681907+00:00*

## EXP-7: Coverage-vs-overhead comparison across enforcement baselines (live OPA).
| Baseline | Coverage | FPR | Mean\,(ms) | Overhead\,(ms) |
| -------- | -------- | ---- | ---------- | -------------- |
| NomosFlow | 100.0\% | 0.0\% | 1.58 | 1.56 |
| OPA gateway | 90.0\% | 0.0\% | 1.98 | 1.96 |
| App-level | 52.5\% | 0.0\% | 0.08 | 0.06 |
| No enforcement | 0.0\% | 0.0\% | 0.02 | 0.00 |
| Envoy+OPA gateway | 80.0\% | 0.0\% | 2.47 | 2.45 |
| \multicolumn{5}{l}{\textit{Live OPA P50 latency (opa\_live=true, 2026-07-10 benchmark)}} |
| $n$\,=\,100 | --- | --- | 2.17 | --- |
| $n$\,=\,1{,}000 | --- | --- | 4.84 | --- |
| $n$\,=\,10{,}000 | --- | --- | 4.93 | --- |
| $n$\,=\,100{,}000 | --- | --- | 4.91 | --- |
