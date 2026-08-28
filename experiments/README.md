# NomosFlow — Experiments

Self-contained experiment suite for the NomosFlow paper. Every experiment writes:
- `results/<EXP_ID>/raw_CANONICAL.json` — reference numbers (checked in; **do not modify**)
- `results/<EXP_ID>/raw_<timestamp>.json` — fresh run output
- `results/<EXP_ID>/summary.md` — human-readable results (**overwritten on every run**)
- `results/<EXP_ID>/tables.tex` — LaTeX table snippets (**overwritten on every run**)
- `results/<EXP_ID>/corpus.json` — labeled corpus (EXP-3/4/6b/7 only)

> **`summary.md` and `tables.tex` are regenerated on every run** by
> `experiments/shared/report.py:write_summary()`. Re-running locally overwrites
> them with values from that run. The authoritative ground truth is always
> `raw_CANONICAL.json` (per-experiment) and
> `results/paper_results.tex` (paper tables).

> **Tier-naming note:** The paper labels tiers T3–T7. Internal code and JSON
> keys use T1\_APL, T2\_CMF, T3\_OPA, T4\_RATE, T5\_LLM. The mapping is
> documented in [`exp2_resolution/run.py`](exp2_resolution/run.py) lines 17–22.
> All `summary.md` and `tables.tex` files use the paper labels (T3–T7).

## Running

```bash
# All experiments, no services needed (~90 s):
python experiments/run_all.py

# Single experiment:
python -m experiments.exp3_detection.run

# Validate paper invariants:
python experiments/compare_results.py

# Strict canonical comparison (same hardware):
python experiments/compare_results.py --compare-canonical

# Verify every numeric paper claim against the checked-in canonical files:
python experiments/verify_paper_claims.py        # table view
python experiments/verify_paper_claims.py -v     # + matched text snippet per row
```

> **`verify_paper_claims.py`:** checks all 65 numeric claims in
> `results/paper_results.tex` against `raw_CANONICAL.json` files.
> No services, no re-running. `p.tex` is optional — if absent all p.tex
> checks are silently skipped and the script still exits 0 on full alignment.
> This is also run in CI on every push/PR.
>
> **`compare_results.py` modes:**
> - *Default* (no flags): checks structural invariants (counts, verdict
>   distributions, zero false-ALLOWs) against the most-recently-written
>   `raw_*.json` per experiment. Passes on any hardware.
> - *`--compare-canonical`*: byte-for-byte JSON equality against
>   `raw_CANONICAL.json`. Requires the same hardware and services as the
>   original canonical run — use only for like-for-like environments.
>
> EXP-1, EXP-11, EXP-12 measure real latency/RSS and are sensitive to hardware
> and system load. Use the default invariant check as the primary portability
> test; `--compare-canonical` is for like-for-like environments only.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `OPA_URL` | `http://localhost:8181` | OPA endpoint (set to live OPA for measured latency) |
| `LLM_VALIDATION_ENABLED` | `false` | `true` to enable live LLM tier in EXP-3 and EXP-4 |
| `LITELLM_BASE_URL` | — | LiteLLM proxy or provider base URL (e.g. `https://api.openai.com/v1`) |
| `LLM_API_KEY` | — | API key for the LLM provider |
| `LLM_MODEL` | `gpt-3.5-turbo` | Model identifier passed to LiteLLM |
| `LLM_VALIDATION_TIMEOUT` | `10.0` | Per-call timeout (seconds) for T7 (LLM tier) |
| `FRED_API_KEY` | — | FRED macro-data API key (EXP-4 live data-lake; free) |
| `BENCHMARK_SCALES` | `100,1000,10000` | Request scales for EXP-1/EXP-11 |
| `AGENT_COUNTS` | `1,5,10,25,50,100` | Agent counts for EXP-11 |
| `LLM_RATES` | `0.0,0.05,0.2,0.5,1.0` | Routing fractions for EXP-6b |
| `RESULTS_DIR` | `experiments/results` | Output directory |

### Which experiments need credentials?

| Experiment | Variable(s) required | Notes |
|---|---|---|
| **All (default)** | none | Full stub/offline mode; all paper invariants pass |
| **EXP-3** live T7 | `LLM_VALIDATION_ENABLED=true` + `LITELLM_BASE_URL` + `LLM_API_KEY` + `LLM_MODEL` | Calls LLM for semantic PII check |
| **EXP-4** live injection | `LLM_VALIDATION_ENABLED=true` + `LITELLM_BASE_URL` + `LLM_API_KEY` + `LLM_MODEL` | Calls LLM for each adversarial probe |
| **EXP-4** live FRED data | `FRED_API_KEY` | Optional; fetches live macro-economic data (free key) |
| **EXP-1/EXP-3** live OPA | OPA running at `OPA_URL` | `podman-compose up -d opa` or `docker compose up -d opa` |

Copy [`.env.local.example`](../.env.local.example) to `.env.local`, fill in
the relevant values, then `source .env.local` before running. The file is
`.gitignore`-listed and will never be committed. Without it every experiment
runs in deterministic stub mode.

## Paper section mapping

| Experiment | Paper § | Paper tables | Key claim | Mode | Corpus |
|---|---|---|---|---|---|
| EXP-1 | §6.1 | Table 7 | Per-tier P50/P95/P99; in-pod vs gateway overhead | Synthetic; live OPA for measured latency | synthetic |
| EXP-2 | §6.1 | Table 8, Figure 3 | `resolved_at_tier` histogram; empirical p_i, c_i | Synthetic | synthetic |
| EXP-3 | §6.2 | Tables 9, 10, 11 | Detection F1 = 90.8%; FPR = 0.0% on benign traffic | All tiers live (T3–T7 active in canonical run) | **200-case labeled** → `corpus.json` |
| EXP-4 | §6.2 | Table 12 | Proposition 1: 0 terminal ALLOWs under injected payloads; model answered correctly within its evaluation scope | Live model for `adversarial_deny` class (20 probes); stub for `clean_escalated` and `true_violation` | **60-case labeled** → `corpus.json` |
| EXP-6 | §6.3 | Table 13 | Zero false-ALLOWs under OPA kill / LLM timeout | Synthetic (mock injection) | synthetic |
| EXP-6b | §6.3 | Table 14 | Recall/throughput Pareto; T7 P50 = 9,500 ms (Table 7) | Simulation (seeded RNG, lognormal latency) | **80-case labeled** → `corpus.json` |
| EXP-7 | §6.4 | Tables 2, Figure 2 | NomosFlow vs Envoy+OPA vs app-level coverage/overhead | Synthetic; live Envoy probe optional | **80-case labeled** → `corpus.json` |
| EXP-8 | §6.5 | Table 15 | Policy scale latency; hot-reload correctness | Synthetic; live OPA optional | synthetic |
| EXP-9 | §6.6 | — | Buffer-then-release invariant (atomic RB) | Static audit + runtime OPA probe | static audit |
| EXP-11 | §6.7 | Table 16 | Per-agent resource curve (1–100 agents) | Synthetic | synthetic |
| EXP-12 | §6.7 | — | Sidecar CPU/RSS overhead; ≈373 MB full-pod figure with measured and analytical components | Synthetic (psutil); measured OPA via podman stats | synthetic |
| EXP-GAP-13 | §5 | — | Interceptor hook inventory (3/3 pass) | Static inventory | static audit |
| EXP-GAP-32 | §5 | Table 6 | OSCAL control-mapping drift = 0 | Static parse | static parse |
| EXP-GAP-35 | §5 | Table 5 | PII redacted before model call | Static + 5 inline cases | static + inline |

## Corpus files (EXP-3/4/6b/7)

These four experiments have labeled corpora written inline in code. Each run
serialises the corpus to `results/<EXP_ID>/corpus.json` for reviewer inspection:

**EXP-3** (`200 requests`): fields `id`, `class`, `label`, `deciding_tier`,
`content`. Classes: `static_regex` (40), `policy_rule` (40), `semantic` (20),
`benign_normal` (50), `benign_suspicious` (25), `edge_case` (25).

**EXP-4** (`60 requests`): two representations — `annotated` (includes
`_semantic_class`, `_violation_type`) and `public` (T1/T3 and harness annotation
fields stripped — exact payload the live model receives). Classes:
`clean_escalated` (20), `adversarial_deny` (20), `true_violation` (20).

**EXP-6b** (`80 requests`): fields `_label`, `_vclass`. 40 benign + 40
violations: `rbac_write`, `purpose_mismatch`, `bad_token`, `future_timestamp`,
`purpose_bypass_fred` (8 each).

**EXP-7** (`80 requests`): fields `label`, `violation_type`. 40 benign + 40
violations cycling through 7 violation types.

## Known limitations

See [`docs/gap-disclosures.md`](../docs/gap-disclosures.md) for the full list.
Reproducibility-relevant notes:

- **EXP-3 POLICY TP ±3**: OPA's `time.now_ns()` causes clock-boundary flips in 4
  `edge_case` requests. Range 52–55 TP across live-OPA re-runs; STATIC and FULL stable.
- **EXP-6b fully simulated**: seeded RNG (`seed=42`), no live model calls. The
  latency model is fitted to measured EXP-1 data, not live calls.
- **EXP-4 adversarial strings**: 4 canonical jailbreak patterns cycled across 20
  requests. Broader red-team evaluation is future work (§7).
- **EXP-9**: `denied_with_data=0` is invariant-by-construction; static code audit
  is the evidence (1/1 `fetch_real_data` call sites gated on `decision == "APPROVED"`).
