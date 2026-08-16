# Gap Disclosures (Paper §5)

This file consolidates all gap disclosures from the NomosFlow paper's §5 and
from the individual experiment `summary.md` files.

---

## Resolved gaps (fixed before submission)

| Gap | Description | Fix |
|-----|-------------|-----|
| **GAP-8** | Audit durability: `flush_audit_batch()` dropped records on SQLite failure | Store-and-forward WAL (`_spill_to_wal` / `_drain_wal`) added to `sidecar_optimized.py`; hash-chain (`prev_hash` SHA-256) added to `S3AuditWriter`. EXP-6 `AUDIT_PARTITION` row: `lost_records=0`, `chain_ok=True`. |
| **GAP-10** | T5 fail-open: LLM outage allowed requests through | `process_llm_tier` now returns DENIED when LLM is unavailable. Set `FAIL_OPEN_LLM=true` to restore previous behaviour (used only in escalation demo). |
| **GAP-12** | Pod RSS underestimate (claimed 310 MB) | OPA measured at 104.9 MB via `podman stats`; full pod ≈ 373 MB. |
| **GAP-13** | Interceptor hook surfaces incomplete | `attach`/`detach` added to `compliance_interceptor`; `handle_request` to `mcp_interceptor`; `create_app` to `compliance_proxy_server`. All 3/3 pass. |
| **GAP-25b** | IAA: original κ=0.888 used a *simulated* Annotator B (circular) | Retracted. Genuine blind run with `aws/claude-sonnet-4-5` (corpus labels withheld) yielded κ=0.681 ("substantial"). Raw per-item reasoning in `experiments/results/exp3/iaa_blind_raw.json`. |
| **GAP-30** | Paper figures missing | `fig1_tier_histogram.svg` (EXP-2) and `fig2_coverage_frontier.svg` (EXP-7) generated; `figures.tex` provides `\includesvg` stubs. |
| **GAP-32** | OPA ↔ Python OSCAL map drift | Zero drift confirmed; 5 new REQ mappings added; non-standard `ZT-1` replaced by `IA-5` and `IA-11`. |
| **GAP-35** | T5 payload sent raw (PII exposure) | `redact_for_llm()` scrubs SSN, email, phone, credit-card before model call; base compose defaults to local Ollama (`granite3.2:2b`). |
| **EXP-3 corpus** | 80-case corpus had 16 mislabelled benign items; FPR was 44% | Corpus expanded to 200 cases with corrected labels; FPR = 0.0% (FP=0/87). |
| **EXP-8 hot-reload** | `hot_reload()` used wrong policy ID | Fixed to use `bank_authz` ID; `reload_ok=True`, `stale_allow_count=0`. |
| **EXP-3 T5 (GAP-3c)** | Semantic class used keyword-heuristic oracle | Re-run with live `aws/claude-sonnet-4-5` via `validate_semantic_pii()`; semantic recall 85% → 95%; FULL F1 90.3% → 90.8%; FPR remains 0.0%. |

---

## Open gaps / Proposition 3 disclosures

| Gap | Description |
|-----|-------------|
| **GAP-2** | Prop. 3 tier ordering applies only to tiers with p_i < 1; T1 (p_i=1.0, mandatory) is excluded from the optimisation domain. |
| **GAP-4** | Red-team evaluation of T5 with adversarial prompt-injection sequences beyond EXP-4 is future work (§7). |
| **GAP-11** | Per-agent RSS (EXP-11) is measured as psutil delta; negative values at N=50 reflect GC reclaim between samples, not measurement error. |
| **OPA cache staleness** | OPA's 5-minute decision cache (`now//300`) creates a stale-ALLOW window during hot-reload (EXP-8). This is a sidecar-layer artefact, not OPA-level; mitigated by `cache_clear()` on policy reload. |
| **Anomaly detection advisory** | T4 anomaly detection runs post-decision on a daemon thread; it is not a pre-emission gate and is not counted as a resolving tier in EXP-2. |

---

## Provenance notes (documented variances)

| Experiment | Note |
|------------|------|
| **EXP-3 POLICY TP ±3** | OPA's `time.now_ns()` causes clock-boundary flips in 4 of the 25 `edge_case` requests (REQ-14 future-timestamp rule). Observed range 52–55 TP across live-OPA re-runs. STATIC and FULL are stable. |
| **EXP-6b** | Fully simulated: deterministic oracle + seeded RNG (`seed=42`) + hardcoded latency constants. No live model calls. Table quantifies structural recall–throughput trade-off shape. |
| **EXP-9 runtime check** | `denied_with_data=0` is invariant-by-construction (`data_emitted = allowed` uses the same boolean). The genuine evidence is the static code audit (1/1 `fetch_real_data` call sites inside `if decision == "APPROVED"`). |
| **EXP-3 overlap counts** | The 500-case source overlap table summed to 800, not 500. Corrected from confusion matrices: Both=99, Static-only=66, LLM-only=88, Neither=247 (sum=500). Complementarity = 60.9% (not 70%). |
