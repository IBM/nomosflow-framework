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
