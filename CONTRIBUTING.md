# Contributing to NomosFlow

Thank you for your interest in contributing!

## IBM Contributor License Agreement

All contributors must sign the [IBM CLA](https://cla-assistant.io/IBM/nomosflow-framework)
before a pull request can be merged.  The CLA bot will prompt you automatically
on your first PR.

## Developer Certificate of Origin (DCO)

Every commit must be signed off with your real name and email:

```bash
git commit -s -m "Your commit message"
```

This certifies that you wrote the code or have the right to submit it under the
Apache 2.0 licence.

## Branching model

| Branch | Purpose |
|--------|---------|
| `main` | Stable, always passes CI |
| `dev/*` | Feature branches; PRs target `main` |

## Running the experiment suite locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Fully simulated (no services, no API keys):
python experiments/run_all.py

# Check paper invariants:
python experiments/compare_results.py
```

## Adding a new experiment

1. Create `experiments/exp<N>_<name>/run.py` with a `main()` function.
2. Add `experiments/exp<N>_<name>/__init__.py` (empty).
3. Register the experiment name in `experiments/run_all.py` `_EXPERIMENTS` list.
4. Run it: `python experiments/run_all.py --exp exp<N>`.
5. Add invariant checks to `experiments/compare_results.py`.

## Code style

- Python 3.12+, `from __future__ import annotations`
- No external dependencies beyond `requirements.txt`
- All experiment results written to `experiments/results/<exp_id>/`

## Reporting issues

Please open a GitHub issue with the experiment name, Python version, and
the full traceback.
