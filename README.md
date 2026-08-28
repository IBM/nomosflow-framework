# NomosFlow

[![CI](https://github.com/IBM/nomosflow/actions/workflows/experiments.yml/badge.svg)](https://github.com/IBM/nomosflow/actions/workflows/experiments.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

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

## Reproducing the paper experiments

```bash
git clone https://github.com/IBM/nomosflow && cd nomosflow
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python experiments/run_all.py            # all experiments, ~90 s, no services needed
python experiments/compare_results.py    # validates paper invariants against your run
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
> reflect the canonical live-service run (Aug 15 2026). If you re-run offline
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

| Paper item | Experiment | Description |
|---|---|---|
| Table 1 | — | Observation function (body) |
| Table 2 | EXP-7 | Coverage vs. overhead comparison matrix (body) |
| Figure 1 | — | Architecture diagram (body) |
| Figure 2 | EXP-7 | Coverage frontier (body) |
| Table 3 | — | Coverage predicates (appendix) |
| Table 4 | — | Isolation discharge (appendix) |
| Table 5 | EXP-GAP-35 | Egress / redaction checks (appendix) |
| Table 6 | EXP-GAP-32 | OSCAL control mapping (appendix) |
| Table 7 | EXP-1 | Per-tier latency microbenchmark (appendix) |
| Table 8 | EXP-2 | Short-circuit ablation / tier resolution (appendix) |
| Tables 9–11 | EXP-3 | Detection 200-case, 500-case, overlap (appendix) |
| Table 12 | EXP-4 | Verdict-lattice robustness under injected payloads (appendix) |
| Table 13 | EXP-6 | Fault injection — zero false-ALLOWs (appendix) |
| Table 14 | EXP-6b | Selective screening Pareto frontier (appendix) |
| Table 15 | EXP-8 | Policy scale latency (appendix) |
| Table 16 | EXP-11 | Multi-agent scalability (appendix) |
| Figure 3 | EXP-2 | Resolved-at-tier histogram (appendix) |

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
nomosflow/
├── src/                   Sidecar source (validators, core, interceptors)
├── policies/              OPA Rego policies + OSCAL control map
├── benchmarks/            Canonical live-service measurement files
├── experiments/           Self-contained experiment suite (see experiments/README.md)
│   ├── run_all.py
│   ├── compare_results.py
│   ├── shared/
│   └── results/           Canonical outputs (checked in)
├── docs/                  Architecture and gap-disclosure docs
└── docker-compose.yml     OPA + Redpanda + Prometheus
```

See [`experiments/README.md`](experiments/README.md) for per-experiment details, environment variables, and the paper section mapping.

## License

Apache 2.0 — see [`LICENSE`](LICENSE). Contributions require the IBM CLA; see [`CONTRIBUTING.md`](CONTRIBUTING.md).
