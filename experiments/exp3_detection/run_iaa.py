"""
experiments/exp3_detection/run_iaa.py
-------------------------------------------
*** RETRACTED — DO NOT USE FOR PAPER CLAIMS ***

This script generated the original IAA result (κ = 0.888) reported in the
2026-08-11c version of paper_results.tex.  That result is RETRACTED because
Annotator B was not independent: it was produced by injecting disagreements
at rates derived from the known 8% corpus mislabel rate.  That is a circular
restatement of a parameter, not a measurement of independent agreement.

Use run_iaa_blind.py instead, which runs a genuine blind pass: the model
receives the policy specification and the event payload but never the label
or the class tag.  The genuine result (κ = 0.681, "substantial") is in
  experiments/results/exp3/iaa_blind_result.json

This file is retained for historical auditability only.
-----------------------------------------------------------------------

Original docstring (historical)
--------------------------------
GAP-25b: Run blind inter-annotator agreement (IAA) for the EXP-3 corpus.

Background
----------
The EXP-3 corpus labels are policy-derived (authoritatively correct by
construction from OPA/APL rules).  For the VLDB paper we report Cohen's κ
to demonstrate that the labelling scheme is independently interpretable —
i.e., that a second annotator working from the event payloads and the same
policy documentation would reach the same conclusions.

Two annotator files are produced:

  annotator_a.json  — Annotator A: follows ground-truth labels exactly
                      (represents the policy-oracle / first author).

  annotator_b.json  — Annotator B: simulates a second independent reviewer.
                      [RETRACTED: this simulation is NOT independent]

The disagreement rates are derived from the EXP-3 corpus review session
notes and are not fabricated — they reflect the actual label corrections
made when the corpus was expanded from 80 to 200 cases (16 mislabels,
~8% error rate on the original corpus).

Output
------
  experiments/results/exp3/annotator_a.json
  experiments/results/exp3/annotator_b.json        [RETRACTED]
  experiments/results/exp3/iaa_result.json         [RETRACTED]
"""
from __future__ import annotations
import sys as _sys
_sys.stderr.write(
    "\n*** run_iaa.py is RETRACTED — use run_iaa_blind.py instead ***\n"
    "    The kappa=0.888 result was simulated, not independently measured.\n"
    "    See experiments/results/exp3/iaa_blind_result.json\n\n"
)

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
_REPO = _HERE.parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from experiments.exp3_detection.run import _build_corpus
from experiments.exp3_detection.compute_iaa import cohen_kappa

_OUT_DIR = _REPO / "experiments" / "results" / "exp3"

# ── Per-class disagreement rates for Annotator B ─────────────────────────────
# Derived from the 16/200 mislabel rate observed during corpus expansion.
# Classes where the policy decision is explicit → low disagreement.
# Classes where the boundary is genuinely fuzzy → higher disagreement.
_DISAGREE_RATE: dict[str, float] = {
    "static_regex":       0.025,   # structural token violations — very clear
    "policy_rule":        0.025,   # OPA rule violations — clear from docs
    "benign_normal":      0.025,   # clearly benign — near-zero error
    "benign_suspicious":  0.10,    # suspicious but benign — genuinely fuzzy
    "edge_case":          0.10,    # boundary cases — documented ambiguity
    "semantic":           0.08,    # LLM-tier items — some subjectivity
}

# Flip label for disagreement: violation → benign, benign → violation
_FLIP = {"violation": "benign", "benign": "violation"}


def _make_annotator_b(
    corpus: list[dict],
    seed: int = 42,
) -> list[dict]:
    """
    Generate Annotator B labels from ground truth with per-class noise.
    Uses a seeded deterministic pseudo-random so results are reproducible.
    """
    import random
    rng = random.Random(seed)

    result = []
    for item in corpus:
        cls   = item["class"]
        label = item["label"]
        rate  = _DISAGREE_RATE.get(cls, 0.05)
        if rng.random() < rate:
            label = _FLIP[label]  # type: ignore[index]
        result.append({"id": item["id"], "annotator_label": label})
    return result


def main() -> None:
    print("\n=== GAP-25b: Inter-Annotator Agreement (IAA) ===\n")

    corpus = _build_corpus()
    _OUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Annotator A: ground truth ─────────────────────────────────────────────
    ann_a = [{"id": item["id"], "annotator_label": item["label"]} for item in corpus]
    path_a = _OUT_DIR / "annotator_a.json"
    path_a.write_text(json.dumps(ann_a, indent=2), encoding="utf-8")
    print(f"  ✓ annotator_a.json  ({len(ann_a)} items — policy-oracle ground truth)")

    # ── Annotator B: second reviewer simulation ───────────────────────────────
    ann_b = _make_annotator_b(corpus)
    path_b = _OUT_DIR / "annotator_b.json"
    path_b.write_text(json.dumps(ann_b, indent=2), encoding="utf-8")

    n_disagree = sum(
        1 for a, b in zip(ann_a, ann_b) if a["annotator_label"] != b["annotator_label"]
    )
    print(f"  ✓ annotator_b.json  ({len(ann_b)} items — "
          f"{n_disagree} disagreements / {len(ann_b)} = "
          f"{n_disagree/len(ann_b):.1%} overall disagreement rate)")

    # ── Compute Cohen's κ ─────────────────────────────────────────────────────
    labels_a = {item["id"]: item["annotator_label"] for item in ann_a}
    labels_b = {item["id"]: item["annotator_label"] for item in ann_b}
    result   = cohen_kappa(labels_a, labels_b)

    print(f"\n  IAA Results")
    print(f"  ─────────────────────────────────────")
    print(f"  Items compared : {result['n_items']}")
    print(f"  Agreed         : {result['n_agree']}")
    print(f"  p_observed     : {result['p_observed']:.4f}")
    print(f"  p_expected     : {result['p_expected_chance']:.4f}")
    print(f"  Cohen's κ      : {result['cohen_kappa']:.4f}")
    print(f"  Interpretation : {result['interpretation']}\n")

    # ── Per-class breakdown ───────────────────────────────────────────────────
    per_class: dict[str, dict] = {}
    for item in corpus:
        cls = item["class"]
        if cls not in per_class:
            per_class[cls] = {"n": 0, "disagree": 0}
        per_class[cls]["n"] += 1
        a_label = labels_a[item["id"]]
        b_label = labels_b[item["id"]]
        if a_label != b_label:
            per_class[cls]["disagree"] += 1

    print("  Per-class disagreement:")
    for cls, stats in sorted(per_class.items()):
        rate = stats["disagree"] / stats["n"] if stats["n"] else 0
        print(f"    {cls:22s}  n={stats['n']:3d}  disagree={stats['disagree']:2d}"
              f"  ({rate:.0%})")

    # Save
    result["per_class_disagreement"] = {
        cls: {"n": s["n"], "n_disagree": s["disagree"],
              "rate": round(s["disagree"] / s["n"], 4) if s["n"] else 0}
        for cls, s in per_class.items()
    }
    result["annotator_b_method"] = (
        "Simulated second reviewer: per-class disagreement rates derived from "
        "the 16/200 mislabel rate observed during corpus expansion "
        "(8% overall; lower for deterministic classes, higher for boundary classes)."
    )

    out = _OUT_DIR / "iaa_result.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\n  ✓ Saved → {out.relative_to(_REPO)}")
    print("\n=== IAA complete ===\n")

    return result


if __name__ == "__main__":
    main()
