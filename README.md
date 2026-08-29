# NomosFlow

[![CI](https://github.com/IBM/nomosflow-framework/actions/workflows/experiments.yml/badge.svg)](https://github.com/IBM/nomosflow-framework/actions/workflows/experiments.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **Supplementary material:** [`supplement.pdf`](supplement.pdf) — proofs, pre-registration protocol, artifact audits, and full result tables.
> `p.tex` (main paper file) and `supplement.tex` are the LaTeX source and are read by `verify_paper_claims.py` when present.

**NomosFlow** is an event-driven compliance sidecar for AI agents. It intercepts every data-access event and passes it through a five-tier validation pipeline before allowing it to proceed:

| Tier | Component | Latency | Purpose |
|------|-----------|---------|---------|
| T3 | CMF | µs | CDM v2 context enrichment |
| T4 | APL | µs | Token / RBAC / attestation |
| T5 | OPA | ~2–5 ms | Rego policy evaluation |
| T6 | Rate-limit | µs | Per-agent token-bucket |
| T7 | LLM validator | ~9,500 ms P50 | Semantic / indirect-PII check (sampled) |

Fails **secure** at every tier: any failure defaults to DENY, not ALLOW (Proposition 1).

> **Tier-naming note:** The paper labels tiers T3–T7. The source code and JSON
> keys use an internal numbering (T1\_APL, T2\_CMF, T3\_OPA, T4\_RATE, T5\_LLM).
> The mapping is documented in
> [`experiments/exp2_resolution/run.py`](experiments/exp2_resolution/run.py)
> lines 17–22. All `summary.md` and `tables.tex` files use the paper labels
> (T3–T7).

## Verifying results without re-running

If you prefer to check the canonical numbers directly rather than re-running the full suite, all checked-in artifacts are in [`experiments/results/`](experiments/results/):

| Artifact | Location | What it contains |
|---|---|---|
| **Master paper tables** | [`experiments/results/paper_results.tex`](experiments/results/paper_results.tex) | Every table and figure that appears in the paper, with full provenance comments at the top |
| **Per-experiment raw data** | `experiments/results/<EXP_ID>/raw_CANONICAL.json` | Exact numbers from the canonical live-service runs (Aug 9–14 2026); used by `compare_results.py --compare-canonical` |
| **Per-experiment summaries** | `experiments/results/<EXP_ID>/summary.md` | Human-readable results in Markdown; reflect the canonical run until overwritten by a local re-run |
| **Figures** | [`experiments/results/figures/fig1_tier_histogram.svg`](experiments/results/figures/fig1_tier_histogram.svg) | Resolved-at-tier histogram (Figure 3 / EXP-2) |
| | [`experiments/results/figures/fig2_coverage_frontier.svg`](experiments/results/figures/fig2_coverage_frontier.svg) | Coverage frontier (Figure 2 / EXP-7) |
| **LaTeX figure stubs** | [`experiments/results/figures/figures.tex`](experiments/results/figures/figures.tex) | `\includesvg` stubs for both figures |
| **Labelled corpora** | `experiments/results/<EXP_ID>/corpus.json` | EXP-3 (200 cases), EXP-4 (60), EXP-6b (80), EXP-7 (80) — see [Corpus files](#corpus-files) below |

> **`summary.md` and `tables.tex` are regenerated on every run.** The checked-in copies are the canonical reference. If you re-run locally the files will be overwritten with values from that run; the authoritative ground truth is always `raw_CANONICAL.json` (per-experiment) and `paper_results.tex` (paper tables).

## Reproducing the paper experiments

```bash
git clone https://github.com/IBM/nomosflow-framework && cd nomosflow-framework
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python experiments/run_all.py            # all experiments, ~90 s, no services needed
python experiments/compare_results.py    # validates paper invariants against your run

# Verify every numeric paper claim against the checked-in canonical files
# (no services, no re-running — exits 0 if all 65 checks pass)
python experiments/verify_paper_claims.py        # table view
python experiments/verify_paper_claims.py -v     # + matched text snippet per row
```

> **`compare_results.py` modes:**
> - *Default* (no flags): checks structural invariants (counts, verdict
>   distributions, zero false-ALLOWs) against the most-recently-written
>   `raw_*.json` per experiment. Passes on any hardware.
> - *`--compare-canonical`*: byte-for-byte JSON equality against
>   `raw_CANONICAL.json`. Requires the same hardware and services as the
>   original canonical run — use only for like-for-like environments.
>
> **`summary.md` / `tables.tex` are regenerated on every run** by
> `experiments/shared/report.py:write_summary()` and will be overwritten with
> the values from that run. The checked-in copies in `experiments/results/`
> reflect the canonical live-service runs (Aug 9–14 2026). If you re-run offline
> the files will show simulated values; the canonical ground truth is always
> `raw_CANONICAL.json` and `experiments/results/paper_results.tex`.

**With live OPA** (reproduces measured latency):
```bash
podman-compose up -d opa   # or: docker compose up -d opa
OPA_URL=http://localhost:8181 python experiments/run_all.py
```

**With live LLM** (EXP-3 T7 tier, EXP-4 injection robustness):
```bash
cp .env.local.example .env.local
# Edit .env.local — set LITELLM_BASE_URL, LLM_API_KEY, LLM_MODEL, then:
export LLM_VALIDATION_ENABLED=true
source .env.local
python -m experiments.exp3_detection.run
python -m experiments.exp4_semantic.run
```
Without `.env.local` both experiments fall back to deterministic stub validators — all paper invariants still pass.

### Which experiments need which keys?

| Experiment | Needs keys? | What for |
|---|---|---|
| EXP-1 through EXP-12 (stub mode) | **No** | All run offline with seeded RNG and simulated latency |
| EXP-3 (live T7) | `LITELLM_BASE_URL` + `LLM_API_KEY` + `LLM_MODEL` | Actual LLM call for semantic PII check |
| EXP-4 (live injection) | `LITELLM_BASE_URL` + `LLM_API_KEY` + `LLM_MODEL` | Actual LLM call per adversarial probe |
| EXP-4 (FRED data-lake) | `FRED_API_KEY` | Live FRED macro-economic data fetch (free key) |
| OPA live mode | OPA running at `OPA_URL` | `podman-compose up -d opa` or `docker compose up -d opa` |

`FRED_API_KEY` is free — register at <https://fred.stlouisfed.org/docs/api/api_key.html>.

## Paper table and figure map

The `Canonical file` column points to the checked-in artifact that contains the numbers for that item.

| Paper item | Experiment | Description | Canonical file |
|---|---|---|---|
| Table 1 | — | Observation function (body) | [`paper_results.tex`](experiments/results/paper_results.tex) |
| Table 2 | EXP-7 | Coverage vs. overhead comparison matrix (body) | [`exp7/raw_CANONICAL.json`](experiments/results/exp7/raw_CANONICAL.json) |
| Figure 1 | — | Architecture diagram (body) | [`experiments/nomosflow-architecture.png`](experiments/nomosflow-architecture.png) |
| Figure 2 | EXP-7 | Coverage frontier (body) | [`figures/fig2_coverage_frontier.svg`](experiments/results/figures/fig2_coverage_frontier.svg) |
| Table 3 | — | Coverage predicates (appendix) | [`paper_results.tex`](experiments/results/paper_results.tex) |
| Table 4 | — | Isolation discharge (appendix) | [`paper_results.tex`](experiments/results/paper_results.tex) |
| Table 5 | EXP-GAP-35 | Egress / redaction checks (appendix) | [`exp_gap35/raw_CANONICAL.json`](experiments/results/exp_gap35/raw_CANONICAL.json) |
| Table 6 | EXP-GAP-32 | OSCAL control mapping (appendix) | [`exp_gap32/raw_CANONICAL.json`](experiments/results/exp_gap32/raw_CANONICAL.json) |
| Table 7 | EXP-1 | Per-tier latency microbenchmark (appendix) | [`exp1/raw_CANONICAL.json`](experiments/results/exp1/raw_CANONICAL.json) |
| Table 8 | EXP-2 | Short-circuit ablation / tier resolution (appendix) | [`exp2/raw_CANONICAL.json`](experiments/results/exp2/raw_CANONICAL.json) |
| Tables 9–11 | EXP-3 | Detection 200-case, 500-case, overlap (appendix) | [`exp3/raw_CANONICAL.json`](experiments/results/exp3/raw_CANONICAL.json) |
| Table 12 | EXP-4 | Verdict-lattice robustness under injected payloads (appendix) | [`exp4/raw_CANONICAL.json`](experiments/results/exp4/raw_CANONICAL.json) |
| Table 13 | EXP-6 | Fault injection — zero false-ALLOWs (appendix) | [`exp6/raw_CANONICAL.json`](experiments/results/exp6/raw_CANONICAL.json) |
| Table 14 | EXP-6b | Selective screening Pareto frontier (appendix) | [`exp6b/raw_CANONICAL.json`](experiments/results/exp6b/raw_CANONICAL.json) |
| Table 15 | EXP-8 | Policy scale latency (appendix) | [`exp8/raw_CANONICAL.json`](experiments/results/exp8/raw_CANONICAL.json) |
| Table 16 | EXP-11 | Multi-agent scalability (appendix) | [`exp11/raw_CANONICAL.json`](experiments/results/exp11/raw_CANONICAL.json) |
| Figure 3 | EXP-2 | Resolved-at-tier histogram (appendix) | [`figures/fig1_tier_histogram.svg`](experiments/results/figures/fig1_tier_histogram.svg) |
| — | EXP-GAP-13 | Interceptor hook inventory — `tab:gap13-interceptors` in `paper_results.tex` | [`exp_gap13/raw_CANONICAL.json`](experiments/results/exp_gap13/raw_CANONICAL.json) |
| — | EXP-9 | Buffer-then-release invariant (static code audit + runtime check) | [`exp9/raw_CANONICAL.json`](experiments/results/exp9/raw_CANONICAL.json) |
| — | EXP-12 | Sidecar CPU / RSS overhead; full-pod decomposition | [`exp12/raw_CANONICAL.json`](experiments/results/exp12/raw_CANONICAL.json) |

## Corpus files

EXP-3, EXP-4, EXP-6b, and EXP-7 write their labeled corpora to `experiments/results/<EXP_ID>/corpus.json` on every run. Reviewers can inspect individual cases without re-running anything:

| File | N | Contents |
|------|---|----------|
| [`results/exp3/corpus.json`](experiments/results/exp3/corpus.json) | 200 | `id`, `class`, `label`, `deciding_tier`, `content` |
| [`results/exp4/corpus.json`](experiments/results/exp4/corpus.json) | 60 | `annotated` (harness tags) + `public` (exact model input) |
| [`results/exp6b/corpus.json`](experiments/results/exp6b/corpus.json) | 80 | `_label`, `_vclass` per request |
| [`results/exp7/corpus.json`](experiments/results/exp7/corpus.json) | 80 | `label`, `violation_type` per request |

## Repository layout

```
nomosflow-framework/
├── src/                   Sidecar source (validators, core, interceptors)
├── policies/              OPA Rego policies + OSCAL control map
├── benchmarks/            Canonical live-service measurement files
├── experiments/           Self-contained experiment suite (see experiments/README.md)
│   ├── run_all.py
│   ├── compare_results.py
│   ├── shared/
│   └── results/           Canonical outputs (checked in)
│       ├── paper_results.tex   ← master paper tables (all experiments)
│       ├── figures/            ← fig1_tier_histogram.svg, fig2_coverage_frontier.svg
│       └── <EXP_ID>/           ← raw_CANONICAL.json, summary.md, tables.tex, corpus.json
├── docs/                  Architecture and gap-disclosure docs
└── docker-compose.yml     OPA + Redpanda + Prometheus
```

See [`experiments/README.md`](experiments/README.md) for per-experiment details, environment variables, and the paper section mapping.

## License

Apache 2.0 — see [`LICENSE`](LICENSE). Contributions require the IBM CLA; see [`CONTRIBUTING.md`](CONTRIBUTING.md).
