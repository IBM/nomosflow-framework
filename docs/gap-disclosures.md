# Known Limitations (Paper §5)

This file documents the limitations and design trade-offs disclosed in §5 of
the NomosFlow paper. Each item is verifiable against the checked-in experiment
results.

---

## Design limitations

| Limitation | Description |
|---|---|
| **T7 probabilistic** | The LLM tier (T7) is sampled at ~1% of traffic. Semantic violations in the unsampled fraction are not caught. Proposition 1 guarantees soundness only for requests that reach T7; it does not guarantee full recall across all traffic. |
| **T7 scope** | `validate_semantic_pii()` is scoped to indirect PII and re-identification risk. Prompt-injection strings that do not constitute a semantic privacy violation are outside its detection scope (see EXP-4). |
| **OPA cache staleness** | OPA's 5-minute decision cache (`now//300`) creates a window where a just-reloaded policy may not apply to cached decisions. Mitigated by `cache_clear()` on reload; measured stale-allow count = 0 in EXP-8. |
| **Anomaly detection advisory** | T6 anomaly detection runs post-decision on a daemon thread. It is not a pre-emission gate and is not counted as a resolving tier in EXP-2. |
| **Tier-ordering scope (Prop. 3)** | Proposition 3's cost-optimal tier ordering applies only to tiers with p_i < 1. T4 APL (p_i = 1.0, mandatory attribute check) is excluded from the optimisation domain. |

---

## Measurement variance: paper values vs. checked-in canonical results

Four paper claims come from live-OPA runs whose exact numbers depend on OPA
response time, host hardware, and whether the experiment ran in isolation or
as part of a concurrent batch.  In all four cases **the qualitative claim is
identical across every run**; only the absolute value varies.  The table below
records the paper value, the checked-in canonical value, and the root cause.

> **How to read this table.** `raw_CANONICAL.json` is the reference file for
> each experiment and is the source for `summary.md` and `tables.tex`.  The
> paper values were hand-transcribed from an earlier live-OPA run (see
> `experiments/results/paper_results.tex` header for dates).  Neither set of
> values is wrong; they reflect genuine run-to-run variance on latency and
> throughput measurements.

| Experiment | Paper value | Canonical value | Root cause | Qualitative claim unchanged? |
|---|---|---|---|---|
| **EXP-2 ablation** (Table 8) | ladder 1.60 ms / forced 3.56 ms / **55% saving** | ladder 2.26 ms / forced 3.53 ms / **36% saving** | OPA P50 was ~1.5 ms on the paper's host vs ~2.9 ms on the canonical host. The forced mean is nearly identical (3.56 vs 3.53 ms) because all tiers run on every request and variance averages out. The saving percentage is computed as `(forced − ladder) / forced`, so the stable forced mean amplifies any ladder variance. | Yes — short-circuiting saves a substantial fraction of deterministic latency in every run. |
| **EXP-8 scale latency** (Table 15) | 1.47 / 1.30 / 1.61 / 1.63 ms (10–5,000 rules) | 2.19 / 2.75 / 2.74 / 1.96 ms | Two separate live-OPA runs on different hosts; OPA per-request latency differs by ~0.7–1.4 ms across hardware. | Yes — latency is sub-linear in rule count and stays well under 3 ms in both runs. Correctness claims (stale-ALLOW = 0, reload-ok = True) are identical. |
| **EXP-11 process-25 RPS** (Table 16) | **2,244 RPS** at 25 agents (process mode) | **1,347 RPS** | The paper value came from an isolated Aug-11 live-OPA run that was not preserved as `raw_CANONICAL.json`. The canonical was written during a concurrent batch run (`run_all.py`) where 13 other experiments were issuing OPA queries simultaneously, depressing throughput. The Aug-24 offline re-run shows 4,011 RPS — confirming that number reflects the OPA simulation fallback (no live OPA), not a live measurement. Per-agent mean latency: 13.7 ms (paper), 5.83 ms (canonical), 2.01 ms (Aug-24 sim) — latency ordering mirrors the RPS ordering and is consistent with live-OPA-under-load vs. isolated live-OPA vs. simulated OPA. | Yes — process mode exceeds thread mode at 25 agents in all three runs (2,244 vs 1,653; 1,347 vs 1,655; 4,011 vs 2,150), confirming GIL as the thread-mode bottleneck. |
| **EXP-12 OPA RSS** (§6 prose) | **104.9 MB** | **105.3 MB** | Two separate `podman stats --no-stream` captures of the OPA container at different times. `podman stats` reports resident set size rounded to one decimal place; 0.4 MB is within normal page-cache fluctuation for the same binary. | Yes — both values round to ~105 MB; the pod decomposition total (≈373 MB) is consistent at either value. |

---

## Experiment reproducibility notes

| Experiment | Note |
|---|---|
| **EXP-3 POLICY TP ±3** | OPA's `time.now_ns()` causes clock-boundary flips in 4 of 25 `edge_case` requests (future-timestamp rule). TP range 52–55 across live-OPA re-runs; STATIC and FULL modes are stable. |
| **EXP-4** | `injection_fooled_model = 20/20` means the model correctly answered its scoped question (no indirect PII in a GDP read) despite embedded injection strings — the scope mismatch is the finding, not a model failure. Terminal ALLOWs = 0 in both stub and live modes. Per-request model reasons in `experiments/results/exp4/raw_CANONICAL.json`. |
| **EXP-6b** | Fully simulated: seeded RNG (`seed=42`), latency drawn from lognormal fitted to EXP-1 LIVE_BENCHMARK T7 (LLM tier) measurements (P50 = 9,500 ms, σ_log = 0.26). No live model calls. |
| **EXP-9** | `denied_with_data = 0` is invariant-by-construction. The evidence is the static code audit: every `fetch_real_data` call site is gated on `decision == "APPROVED"`. |
| **EXP-11 RSS** | Per-agent RSS is measured as a psutil delta. Negative values at N=50 reflect GC reclaim between samples, not measurement error. |

---

## Future work (§7)

- Broader red-team evaluation of T7 beyond the 4 canonical jailbreak patterns used in EXP-4.
- Formal verification of Proposition 1 beyond the current structural argument.
- Extension of the OSCAL control map to additional regulatory frameworks (EU AI Act, ISO 42001).
