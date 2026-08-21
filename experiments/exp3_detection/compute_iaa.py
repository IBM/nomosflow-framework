"""
experiments/exp3_detection/compute_iaa.py
------------------------------------------------
Compute inter-annotator agreement (Cohen's κ) from two annotator label files.

Each annotator file is a JSON array in the same format produced by
export_for_annotation.py, with 'annotator_label' filled in:

  [
    {"id": 1, "annotator_label": "violation"},
    {"id": 2, "annotator_label": "benign"},
    ...
  ]

Usage
-----
    python experiments/exp3_detection/compute_iaa.py \\
        --a experiments/results/exp3/annotator_a.json \\
        --b experiments/results/exp3/annotator_b.json

Output
------
Prints Cohen's κ, agreement rate, and per-class confusion breakdown.
Writes experiments/results/exp3/iaa_result.json.

Cohen's κ formula
-----------------
    κ = (p_o - p_e) / (1 - p_e)

    where p_o = observed agreement rate
          p_e = expected agreement by chance
              = sum_class (p_a_class * p_b_class)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve()
_REPO = _HERE.parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

_OUT_DIR = _REPO / "experiments" / "results" / "exp3"

LABELS = ("benign", "violation")


def _load(path: Path) -> dict[int, str]:
    """Return {id → label} mapping from an annotator file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    result: dict[int, str] = {}
    for item in data:
        label = (item.get("annotator_label") or "").lower().strip()
        if label not in LABELS:
            raise ValueError(
                f"Item id={item['id']}: annotator_label must be one of "
                f"{LABELS}, got {label!r}"
            )
        result[int(item["id"])] = label
    return result


def cohen_kappa(labels_a: dict[int, str], labels_b: dict[int, str]) -> dict[str, Any]:
    """Compute Cohen's κ for two annotators over shared item ids."""
    shared = sorted(set(labels_a) & set(labels_b))
    if not shared:
        raise ValueError("No shared item ids between the two annotator files.")

    n = len(shared)
    agree = sum(1 for i in shared if labels_a[i] == labels_b[i])
    p_o = agree / n

    # Marginal frequencies
    cnt: dict[str, dict[str, int]] = {
        "a": {l: 0 for l in LABELS},
        "b": {l: 0 for l in LABELS},
    }
    for i in shared:
        cnt["a"][labels_a[i]] += 1
        cnt["b"][labels_b[i]] += 1

    p_e = sum(
        (cnt["a"][l] / n) * (cnt["b"][l] / n)
        for l in LABELS
    )

    kappa = (p_o - p_e) / (1.0 - p_e) if (1.0 - p_e) > 1e-12 else 1.0

    # Per-class confusion (a rows, b cols)
    confusion: dict[str, dict[str, int]] = {
        la: {lb: 0 for lb in LABELS} for la in LABELS
    }
    for i in shared:
        confusion[labels_a[i]][labels_b[i]] += 1

    return {
        "n_items":          n,
        "n_agree":          agree,
        "p_observed":       round(p_o, 4),
        "p_expected_chance": round(p_e, 4),
        "cohen_kappa":      round(kappa, 4),
        "interpretation": _interpret(kappa),
        "confusion":        confusion,
        "only_in_a":        len(set(labels_a) - set(labels_b)),
        "only_in_b":        len(set(labels_b) - set(labels_a)),
    }


def _interpret(kappa: float) -> str:
    if kappa >= 0.81: return "Almost perfect (κ ≥ 0.81)"
    if kappa >= 0.61: return "Substantial (0.61 ≤ κ < 0.81)"
    if kappa >= 0.41: return "Moderate (0.41 ≤ κ < 0.61)"
    if kappa >= 0.21: return "Fair (0.21 ≤ κ < 0.41)"
    if kappa >= 0.0:  return "Slight (0.00 ≤ κ < 0.21)"
    return "Poor agreement (κ < 0.00)"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute Cohen's κ between two annotator label files."
    )
    parser.add_argument("--a", required=True, metavar="FILE",
                        help="Annotator A JSON file")
    parser.add_argument("--b", required=True, metavar="FILE",
                        help="Annotator B JSON file")
    args = parser.parse_args()

    labels_a = _load(Path(args.a))
    labels_b = _load(Path(args.b))
    result   = cohen_kappa(labels_a, labels_b)

    print(f"\n  IAA Results")
    print(f"  ─────────────────────────────────────")
    print(f"  Items compared : {result['n_items']}")
    print(f"  Agreed         : {result['n_agree']}")
    print(f"  p_observed     : {result['p_observed']:.4f}")
    print(f"  p_expected     : {result['p_expected_chance']:.4f}")
    print(f"  Cohen's κ      : {result['cohen_kappa']:.4f}")
    print(f"  Interpretation : {result['interpretation']}\n")

    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = _OUT_DIR / "iaa_result.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"  Saved → {out.relative_to(_REPO)}\n")


if __name__ == "__main__":
    main()

# Made with Bob
