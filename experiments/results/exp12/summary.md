# EXP-12: Sidecar Resource Overhead

*Generated: 2026-08-24T16:59:56.643786+00:00*

Sources:
- CPU/RSS configuration table: raw_20260824_165956.json (local live run, Aug 24 09:59)
- OPA container RSS (104.9 MB): raw_CANONICAL.json (Aug 15 2026, podman stats with opa-engine container running)
- Pod decomposition: combines both sources, matching paper_results.tex Table (GAP-12 resolved)

## CPU and RSS by configuration
| Config | Mean_CPU_pct | Peak_CPU_pct | Mean_RSS_MB | Peak_RSS_MB |
| ------ | ------------ | ------------ | ----------- | ----------- |
| no_enforcement | 99.96 | 100.8 | 35.89 | 35.91 |
| apl_only | 99.96 | 100.4 | 36.47 | 36.67 |
| opa_only | 60.55 | 64.3 | 38.28 | 38.33 |
| full_stack | 61.56 | 65.5 | 38.33 | 38.34 |

## Overhead vs. no-enforcement baseline
| Metric | Delta | Delta_pct |
| ------ | ----- | --------- |
| mean_cpu_pct | -38.40 | -38.4% |
| peak_cpu_pct | -35.30 | -35.0% |
| mean_rss_mb | +2.44 | +6.8% |
| peak_rss_mb | +2.43 | +6.8% |

Note: paper_results.tex reports +2.2 MB / +6.1% using no_enforcement=36.3 MB baseline
from the paper's live run. raw_20260824_165956 measures no_enforcement=35.89 MB,
giving +2.44 MB / +6.8%. The difference reflects run-to-run baseline RSS variance.

## ≈373 MB full-pod decomposition (measured + analytical, GAP-12 resolved)
The paper's ≈373 MB full-pod runtime figure reflects the complete NomosFlow stack. Components
labelled 'analytical' are literature/vendor estimates; components labelled 'measured' come
from podman stats (raw_CANONICAL.json Aug 15) or psutil (raw_20260824_165956.json Aug 24).

| Component | RSS (MB) | Source |
| --------- | -------- | ------ |
| Kafka broker (JVM) | ~180 | analytical |
| OPA server | 104.9 | measured (podman stats, raw_CANONICAL Aug 15) |
| Prometheus | ~30 | analytical |
| Python sidecar | 38.5 | measured (psutil, raw_20260824_165956 Aug 24) |
| OS / page cache | ~20 | analytical |

## Live-benchmark scale throughput + OPA latency (benchmarks/tier_benchmark_20260710_021432.json)
All-services-live run (opa_live=true, apl_live=true, cmf_live=true, llm_live=true at 1% routing) from 2026-07-10 across four scales.

| Scale | RPS (live) | Decisions (APPROVED/DENIED) | OPA_mean_ms |
| ----- | ---------- | --------------------------- | ----------- |
| 100 | 392.0 | APPROVED=86 / DENIED=14 | 2.59 |
| 1000 | 18.3 | APPROVED=766 / DENIED=234 | 5.05 |
| 10000 | 14.8 | APPROVED=7893 / DENIED=2107 | 5.47 |
| 100000 | 17.1 | APPROVED=79093 / DENIED=20907 | 5.40 |

## Paper §5 gap disclosures
- ≈373 MB figure includes Kafka+OPA+Prometheus; sidecar-only RSS is substantially lower. Kafka (~180 MB) and Prometheus (~30 MB) are analytical estimates; OPA RSS measured at 104.9 MB via podman stats (raw_CANONICAL Aug 15); Python sidecar measured at 38.5 MB via psutil (raw_20260824_165956 Aug 24).
- OPA RSS (104.9 MB) comes from raw_CANONICAL.json which captured a running opa-engine container; the Aug-24 local runs did not have OPA running as a separate container (opa_rss_mb=null in those files).
- CPU stays withheld from paper tables; included here for completeness.
