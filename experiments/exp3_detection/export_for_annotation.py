"""
experiments/exp3_detection/export_for_annotation.py
----------------------------------------------------------
Export a stripped copy of the EXP-3 corpus for blind inter-annotator
agreement (IAA) labeling.

The export removes the ground-truth 'label' and 'deciding_tier' fields so
that human annotators cannot see the expected answer.  Each item retains
only its numeric id and the raw event payload.

Usage
-----
    python experiments/exp3_detection/export_for_annotation.py
    # → experiments/results/exp3/annotation_batch.json

Annotators fill in 'annotator_label' (benign | violation) for each item,
then pass their completed files to compute_iaa.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
_REPO = _HERE.parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from experiments.exp3_detection.run import _build_corpus  # noqa: E402


_OUT_DIR = _REPO / "experiments" / "results" / "exp3"
_OUT_FILE = _OUT_DIR / "annotation_batch.json"


def export() -> Path:
    """Build corpus and write stripped annotation batch to disk."""
    corpus = _build_corpus()
    _OUT_DIR.mkdir(parents=True, exist_ok=True)

    batch = []
    for item in corpus:
        batch.append({
            "id":    item["id"],
            "class": item["class"],   # kept so annotators can stratify
            "event": item["content"],
            # Annotators fill this in:
            "annotator_label": None,  # "benign" | "violation"
        })

    _OUT_FILE.write_text(json.dumps(batch, indent=2), encoding="utf-8")

    violations = sum(1 for i in corpus if i["label"] == "violation")
    benigns    = sum(1 for i in corpus if i["label"] == "benign")
    print(f"  Exported {len(batch)} items → {_OUT_FILE.relative_to(_REPO)}")
    print(f"  Ground truth: {violations} violations, {benigns} benign "
          f"(labels NOT included in export)")
    return _OUT_FILE


if __name__ == "__main__":
    export()

# Made with Bob
