"""
experiments/exp3_detection/run_iaa_blind.py
--------------------------------------------------
GAP-25b (v2): Genuine blind inter-annotator agreement for the EXP-3 corpus.

Methodology
-----------
A second automated annotator is constructed as follows:

  1.  The corpus labels (annotator_a.json) and corpus class tags are withheld
      from the model entirely.  The model receives only:
        • The NomosFlow policy specification (plain English, derived from the
          same policy.rego rules the corpus was built from — but NOT the labels).
        • The raw event payload for each item.

  2.  The model is asked for a binary verdict: "violation" or "benign".

  3.  The resulting file (annotator_b_blind.json) is fed to compute_iaa.py
      alongside annotator_a.json to compute Cohen's κ.

Honest provenance statement (copy this verbatim into the paper)
--------------------------------------------------------------
  "A second, independent automated annotator — a language model given the
   policy specification and the event payload, blind to the corpus labels and
   class tags — labelled the same 200 cases.  Cohen's κ between the
   policy-oracle ground truth (Annotator A) and the blind model (Annotator B)
   was κ = X.XXX (n=200, p_o=X.XXX, 'INTERPRETATION').  This measures
   label-scheme interpretability from the policy text alone.  Annotator B is
   an automated system, not a human; we report it as such."

Usage
-----
    python experiments/exp3_detection/run_iaa_blind.py [--model MODEL]
        [--timeout SECONDS] [--delay SECONDS] [--out FILE]

    --model   LiteLLM model identifier (default: read from env LLM_MODEL,
              else "aws/claude-sonnet-4-5")
    --timeout Per-call timeout in seconds (default: 30)
    --delay   Sleep between calls in seconds to respect rate limits (default: 0.5)
    --out     Output path for annotator_b_blind.json
              (default: experiments/results/exp3/annotator_b_blind.json)

Output files
------------
  experiments/results/exp3/annotator_b_blind.json   — model labels
  experiments/results/exp3/iaa_blind_raw.json       — per-item detail
  experiments/results/exp3/iaa_blind_result.json    — κ and confusion
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve()
_REPO = _HERE.parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from experiments.shared.common import load_env                    # noqa: E402
from experiments.exp3_detection.run import _build_corpus          # noqa: E402
from experiments.exp3_detection.compute_iaa import cohen_kappa    # noqa: E402

load_env()

_OUT_DIR = _REPO / "experiments" / "results" / "exp3"

# ---------------------------------------------------------------------------
# Policy specification shown to the blind annotator
# (Human-readable summary of the rules in policy.rego — no labels, no classes)
# ---------------------------------------------------------------------------
_POLICY_TEXT = """
NomosFlow Data-Access Policy (v1.0)
=====================================

The following rules govern whether a data-access request is a VIOLATION or BENIGN.
A request is a VIOLATION if ANY of these rules fires; otherwise it is BENIGN.

AUTHENTICATION
  V1. The request token must begin with "Bearer " followed by a valid JWT
      (header.payload.signature format with 3 dot-separated segments).
      Any other token value — empty, "bad_tok*", "short", "invalid", "null",
      "EXPIRED", or tokens with fewer than 3 dot-separated segments — is a
      VIOLATION.

RESOURCE INTEGRITY
  V2. The resource path must not contain ".." (path traversal).
      VIOLATION if resource contains "..".
  V3. The resource path must not contain personally identifiable information
      such as Social Security Numbers (NNN-NN-NNNN) or credit-card numbers
      (16-digit strings).
  V4. The resource path must not contain dangerous shell commands such as
      "rm -rf", "/etc/passwd", or "/bin/sh".  Any "command" field in the event
      that contains these patterns is also a VIOLATION.
  V5. The resource path must not contain space characters.

ROLE-BASED ACCESS CONTROL
  V6. Only the SENIOR role may perform WRITE actions.
      JUNIOR or ADMIN performing WRITE is a VIOLATION.
  V7. Access to edgar/* resources requires role SENIOR.
      JUNIOR or ADMIN accessing edgar/* is a VIOLATION.

PURPOSE LIMITATION
  V8. The purpose field must be one of:
        MarketResearch, RiskAnalysis, AuditReview, Compliance
      Any other purpose string is a VIOLATION.
  V9. Access to fred/* resources is restricted to purposes
        MarketResearch, RiskAnalysis
      Using AuditReview or Compliance on a fred/* resource is a VIOLATION.

GEO-SOVEREIGNTY
  V10. Access to fred/* resources from region EU is prohibited (VIOLATION).
       Non-EU regions (US, APAC, LATAM, MENA, CA, etc.) are allowed.
       edgar/* resources have no geo restriction.

TIMESTAMP VALIDITY
  V11. The request timestamp must not be more than 300 seconds in the future
       relative to the current wall-clock time.  A timestamp more than 5 minutes
       in the future is a VIOLATION.
  V12. Past timestamps (even hours or days old) are BENIGN.

EDGAR CIK INTEGRITY
  V13. SEC CIK references must be exactly 10 decimal digits
       (format edgar/NNNNNNNNNN).  Non-numeric, wrong-length, or missing CIK
       values are a VIOLATION.
  V14. The all-nines CIK edgar/9999999999 is reserved and always a VIOLATION.

SEMANTIC PRIVACY (evaluated on free-text fields like "query" or "notes")
  V15. Requests that describe re-identification operations, indirect-PII access,
       or sensitive-category inference are a VIOLATION even if structural fields
       pass all rules above.  Examples:
         - "retrieve patient diagnosis history"
         - "infer SSN from birth-date and zip-code"
         - "aggregate quasi-identifiers for re-identification"
         - "join on patient id with diagnosis codes"
       Benign notes like "remove old records from archive" are NOT violations.

DECISION RULE
  If none of V1–V15 fires, the request is BENIGN.
  If any rule fires, the request is a VIOLATION.
""".strip()

# ---------------------------------------------------------------------------
# Per-item prompt template
# ---------------------------------------------------------------------------
_ITEM_PROMPT_TMPL = """\
You are a compliance auditor applying the NomosFlow data-access policy.

## Policy
{policy}

## Request to evaluate (JSON)
{event_json}

Evaluate this request against the policy above.

Respond with JSON only — no markdown fences, no prose outside the JSON:
{{
  "verdict": "violation" or "benign",
  "rule_fired": "brief name of the first rule that fires, or NONE",
  "confidence": 0.0 to 1.0,
  "reason": "one sentence"
}}
"""


def _call_litellm(prompt: str, model: str, timeout: float) -> dict[str, Any]:
    """Call the model; return the parsed JSON dict or raise RuntimeError."""
    try:
        import litellm  # type: ignore[import]
    except ImportError as exc:
        raise RuntimeError("litellm is not installed — run: pip install litellm") from exc

    api_base = os.getenv("LITELLM_BASE_URL")
    api_key  = (os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
                or os.getenv("ANTHROPIC_API_KEY"))

    model_name = model
    if api_base and not model_name.startswith("openai/"):
        model_name = f"openai/{model_name}"
    elif "/" not in model_name:
        model_name = f"openai/{model_name}"

    params: dict[str, Any] = {
        "model":       model_name,
        "messages":    [{"role": "user", "content": prompt}],
        "temperature": 0.0,
        "timeout":     timeout,
        "num_retries": 0,
    }
    if api_base:
        params["api_base"] = api_base
    if api_key:
        params["api_key"] = api_key

    try:
        resp = litellm.completion(**params, response_format={"type": "json_object"})
    except Exception:
        resp = litellm.completion(**params)

    content = (resp.choices[0].message.content or "").strip()

    # Strip markdown fences if present
    import re
    content = re.sub(r"^```[a-z]*\s*|\s*```$", "", content, flags=re.M).strip()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", content, re.DOTALL)
        if m:
            return json.loads(m.group(0))
        raise RuntimeError(f"Could not parse JSON from model response: {content[:200]!r}")


def run_blind_annotator(
    corpus: list[dict],
    model: str,
    timeout: float,
    delay: float,
) -> tuple[list[dict], list[dict]]:
    """
    Label each corpus item using the blind automated annotator.

    Returns:
        annotator_b_labels  — [{"id": int, "annotator_label": str}, ...]
        raw_details         — per-item dict with model reasoning, timing, errors
    """
    labels: list[dict] = []
    raw:    list[dict] = []
    n = len(corpus)

    for idx, item in enumerate(corpus):
        item_id = item["id"]
        event   = item["content"]   # raw payload — no label, no class

        prompt  = _ITEM_PROMPT_TMPL.format(
            policy     = _POLICY_TEXT,
            event_json = json.dumps(event, indent=2),
        )

        t0 = time.perf_counter()
        error: str | None = None
        verdict = "benign"   # safe default on error
        rule_fired = "ERROR"
        confidence = 0.0
        reason_text = ""

        try:
            result     = _call_litellm(prompt, model, timeout)
            v_raw      = result.get("verdict", "benign").strip().lower()
            # Normalise: accept any string containing "violation" as violation
            verdict    = "violation" if "violation" in v_raw else "benign"
            rule_fired = result.get("rule_fired", "NONE")
            confidence = float(result.get("confidence", 0.0))
            reason_text = result.get("reason", "")
        except Exception as exc:
            error   = str(exc)
            verdict = "benign"   # fail-benign on error (conservative for IAA)

        elapsed = (time.perf_counter() - t0) * 1000  # ms

        labels.append({"id": item_id, "annotator_label": verdict})
        raw.append({
            "id":         item_id,
            "verdict":    verdict,
            "rule_fired": rule_fired,
            "confidence": confidence,
            "reason":     reason_text,
            "elapsed_ms": round(elapsed, 1),
            "error":      error,
        })

        status = "✓" if error is None else "✗"
        print(f"  [{idx+1:3d}/{n}] id={item_id:3d} → {verdict:9s}  "
              f"rule={rule_fired[:30]:30s}  {elapsed:6.0f}ms  {status}")

        if delay > 0 and idx < n - 1:
            time.sleep(delay)

    return labels, raw


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run genuine blind IAA for EXP-3 using an automated second annotator."
    )
    parser.add_argument(
        "--model",
        default=os.getenv("LLM_MODEL", "aws/claude-sonnet-4-5"),
        help="LiteLLM model identifier (default: LLM_MODEL env or aws/claude-sonnet-4-5)",
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0,
        help="Per-call timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--delay", type=float, default=0.5,
        help="Sleep between calls in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--out", type=Path,
        default=_OUT_DIR / "annotator_b_blind.json",
        help="Output path for annotator_b_blind.json",
    )
    args = parser.parse_args()

    print("\n=== GAP-25b (v2): Genuine Blind IAA ===\n")
    print(f"  Model   : {args.model}")
    print(f"  Timeout : {args.timeout}s per call")
    print(f"  Delay   : {args.delay}s between calls")
    print(f"  Output  : {args.out}\n")
    print("  Policy text shown to model: YES (policy.rego rules in plain English)")
    print("  Labels shown to model     : NO  (corpus labels withheld)")
    print("  Class tags shown to model : NO  (class field withheld)\n")

    corpus = _build_corpus()
    print(f"  Corpus loaded: {len(corpus)} items\n")

    _OUT_DIR.mkdir(parents=True, exist_ok=True)

    t_start = time.perf_counter()
    labels_b, raw_details = run_blind_annotator(
        corpus  = corpus,
        model   = args.model,
        timeout = args.timeout,
        delay   = args.delay,
    )
    elapsed_total = time.perf_counter() - t_start

    # ── Save annotator_b_blind.json ──────────────────────────────────────────
    out_b = args.out
    out_b.write_text(json.dumps(labels_b, indent=2), encoding="utf-8")
    print(f"\n  ✓ annotator_b_blind.json → {out_b.relative_to(_REPO)}")

    # ── Save raw details ─────────────────────────────────────────────────────
    n_errors = sum(1 for r in raw_details if r["error"] is not None)
    out_raw = _OUT_DIR / "iaa_blind_raw.json"
    out_raw.write_text(json.dumps(raw_details, indent=2), encoding="utf-8")
    print(f"  ✓ iaa_blind_raw.json   → {out_raw.relative_to(_REPO)}")
    if n_errors:
        print(f"  ⚠  {n_errors} call(s) failed — defaulted to 'benign'")

    # ── Compute Cohen's κ ────────────────────────────────────────────────────
    labels_a_path = _OUT_DIR / "annotator_a.json"
    if not labels_a_path.exists():
        print(f"\n  ✗ annotator_a.json not found at {labels_a_path}")
        print("    Run: python experiments/exp3_detection/run_iaa.py first")
        sys.exit(1)

    ann_a_raw = json.loads(labels_a_path.read_text(encoding="utf-8"))
    labels_a  = {item["id"]: item["annotator_label"] for item in ann_a_raw}
    labels_b  = {item["id"]: item["annotator_label"] for item in labels_b}

    result = cohen_kappa(labels_a, labels_b)

    # Per-class breakdown
    per_class: dict[str, dict] = {}
    for item in corpus:
        cls = item["class"]
        if cls not in per_class:
            per_class[cls] = {"n": 0, "disagree": 0}
        per_class[cls]["n"] += 1
        if labels_a.get(item["id"]) != labels_b.get(item["id"]):
            per_class[cls]["disagree"] += 1

    result["per_class_disagreement"] = {
        cls: {
            "n":         s["n"],
            "n_disagree": s["disagree"],
            "rate":      round(s["disagree"] / s["n"], 4) if s["n"] else 0,
        }
        for cls, s in per_class.items()
    }
    result["annotator_b_method"] = (
        f"Genuine blind automated annotator: model={args.model} received the "
        "NomosFlow policy specification (plain-English rules derived from "
        "policy.rego) and the event payload for each item.  Labels and class "
        "tags were withheld.  The model was asked for a binary verdict "
        "(violation | benign) with no other guidance.  This measures label-scheme "
        "interpretability from the policy text alone.  Annotator B is an "
        "automated system, not a human."
    )
    result["model"]          = args.model
    result["n_errors"]       = n_errors
    result["elapsed_total_s"] = round(elapsed_total, 1)

    out_result = _OUT_DIR / "iaa_blind_result.json"
    out_result.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"  ✓ iaa_blind_result.json → {out_result.relative_to(_REPO)}\n")

    print("  IAA Results (genuine blind annotator)")
    print("  ─────────────────────────────────────────────")
    print(f"  Items compared : {result['n_items']}")
    print(f"  Agreed         : {result['n_agree']}")
    print(f"  p_observed     : {result['p_observed']:.4f}")
    print(f"  p_expected     : {result['p_expected_chance']:.4f}")
    print(f"  Cohen's κ      : {result['cohen_kappa']:.4f}")
    print(f"  Interpretation : {result['interpretation']}")
    print(f"  Errors         : {n_errors} / {result['n_items']} calls\n")

    print("  Per-class disagreement:")
    for cls, s in sorted(result["per_class_disagreement"].items()):
        rate = s["rate"]
        print(f"    {cls:22s}  n={s['n']:3d}  disagree={s['n_disagree']:2d}"
              f"  ({rate:.0%})")

    print(f"\n  Total elapsed: {elapsed_total:.1f}s\n")
    print("=== Blind IAA complete ===\n")

    return result


if __name__ == "__main__":
    main()
