# EXP-12: Sidecar Resource Overhead

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

## ≈373 MB full-pod decomposition (measured + analytical, GAP-12 resolved)
The paper's ≈373 MB full-pod runtime figure reflects the complete NomosFlow stack. Components
labelled 'analytical' are literature/vendor estimates; components labelled 'measured' come
from podman stats or psutil.

| Component | RSS (MB) | Source |
| --------- | -------- | ------ |
| Kafka broker (JVM) | ~180 | analytical |
| OPA server | 104.9 | measured (podman stats) |
| Prometheus | ~30 | analytical |
| Python sidecar | 38.5 | measured (psutil) |
| OS / page cache | ~20 | analytical |

## Live-benchmark scale throughput + OPA latency
All-services-live run (opa_live=true, apl_live=true, cmf_live=true, llm_live=true at 1% routing) across four scales.

| Scale | RPS (live) | Decisions (APPROVED/DENIED) | OPA_mean_ms |
| ----- | ---------- | --------------------------- | ----------- |
| 100 | 392.0 | APPROVED=86 / DENIED=14 | 2.59 |
| 1000 | 18.3 | APPROVED=766 / DENIED=234 | 5.05 |
| 10000 | 14.8 | APPROVED=7893 / DENIED=2107 | 5.47 |
| 100000 | 17.1 | APPROVED=79093 / DENIED=20907 | 5.40 |

## Paper §5 gap disclosures
- ≈373 MB figure includes Kafka+OPA+Prometheus; sidecar-only RSS is substantially lower. Kafka (~180 MB) and Prometheus (~30 MB) are analytical estimates; OPA RSS measured at 104.9 MB via podman stats; Python sidecar measured at 38.5 MB via psutil.
- CPU included here for completeness; not reported in paper tables.
