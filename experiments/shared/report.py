"""
shared/report.py — summary → markdown + LaTeX table emitter.

Each experiment calls write_summary(exp_id, title, sections) where
sections is a list of dicts:
  {"heading": str, "table": [[col,...], [row,...], ...], "text": str}
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import result_dir, _REPO_ROOT


def _md_table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    header = rows[0]
    sep    = ["-" * max(4, len(h)) for h in header]
    lines  = ["| " + " | ".join(header) + " |",
              "| " + " | ".join(sep)    + " |"]
    for row in rows[1:]:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


def _latex_table(rows: list[list[str]], caption: str, label: str) -> str:
    if not rows:
        return ""
    ncols   = len(rows[0])
    col_fmt = "l" + "r" * (ncols - 1)
    lines   = [
        r"\begin{table}[t]",
        r"  \centering",
        f"  \\caption{{{caption}}}",
        f"  \\label{{{label}}}",
        f"  \\begin{{tabular}}{{{col_fmt}}}",
        r"    \toprule",
        "    " + " & ".join(f"\\textbf{{{h}}}" for h in rows[0]) + r" \\",
        r"    \midrule",
    ]
    for row in rows[1:]:
        lines.append("    " + " & ".join(str(c) for c in row) + r" \\")
    lines += [r"    \bottomrule", r"  \end{tabular}", r"\end{table}"]
    return "\n".join(lines)


def write_summary(
    exp_id:   str,
    title:    str,
    sections: list[dict[str, Any]],
    gaps:     list[str] | None = None,
) -> Path:
    d   = result_dir(exp_id)
    ts  = datetime.now(timezone.utc).isoformat()

    # ── Markdown summary ──────────────────────────────────────────────────
    md_lines = [
        f"# {title}",
        f"",
        f"*Generated: {ts}*",
        f"",
    ]
    for sec in sections:
        md_lines.append(f"## {sec.get('heading', 'Results')}")
        if "text" in sec:
            md_lines.append(sec["text"])
            md_lines.append("")
        if "table" in sec and sec["table"]:
            md_lines.append(_md_table(sec["table"]))
            md_lines.append("")

    if gaps:
        md_lines.append("## Paper §5 gap disclosures")
        for g in gaps:
            md_lines.append(f"- {g}")
        md_lines.append("")

    summary_path = d / "summary.md"
    summary_path.write_text("\n".join(md_lines))
    print(f"  ✓ summary → {summary_path.relative_to(_REPO_ROOT)}")

    # ── LaTeX snippets ────────────────────────────────────────────────────
    latex_lines: list[str] = [f"% Auto-generated LaTeX for {title}", f"% {ts}", ""]
    for i, sec in enumerate(sections):
        if "table" in sec and sec["table"]:
            latex_lines.append(
                _latex_table(
                    sec["table"],
                    caption=sec.get("heading", title),
                    label=f"tab:{exp_id}_{i}",
                )
            )
            latex_lines.append("")

    latex_path = d / "tables.tex"
    latex_path.write_text("\n".join(latex_lines))
    print(f"  ✓ LaTeX   → {latex_path.relative_to(_REPO_ROOT)}")

    return summary_path


def fmt_ms(v: float, decimals: int = 2) -> str:
    return f"{v:.{decimals}f}"

def fmt_pct(v: float) -> str:
    return f"{v*100:.1f}%"
