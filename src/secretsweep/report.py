"""Text and JSON rendering."""

from __future__ import annotations

import json

from .model import SEVERITY_ORDER, Finding

# ANSI colors. Disabled when --no-color or when stdout is not a terminal.
COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
    "rule": "\033[36m",
    "path": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def _c(name: str, text: str, color: bool) -> str:
    if not color:
        return text
    return f"{COLORS.get(name, '')}{text}{COLORS['reset']}"


def render_text(
    findings: list[Finding],
    *,
    color: bool = False,
    show_evidence: bool = True,
    stats: dict | None = None,
) -> str:
    if not findings:
        return "secretsweep: no findings\n"
    out: list[str] = []
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.path, []).append(f)

    for path in sorted(grouped):
        out.append(_c("path", path, color))
        for finding in grouped[path]:
            sev = finding.severity.upper().ljust(8)
            head = f"  {_c(finding.severity, sev, color)} {finding.line:>5}:{finding.column:<3} "
            head += f"{_c('rule', finding.rule, color)}  {finding.masked}"
            if finding.suppressed:
                head += f"  {_c('dim', '[placeholder]', color)}"
            out.append(head)
            detail = f"          {finding.rule_name} | confidence={finding.confidence} entropy={finding.entropy:.2f}"
            if finding.bucket != "source":
                detail += f" | bucket={finding.bucket}"
            out.append(_c("dim", detail, color))
            if finding.reasons:
                out.append(_c("dim", "          " + "; ".join(finding.reasons), color))
            if show_evidence and finding.evidence:
                out.append(_c("dim", f"          > {finding.evidence}", color))
        out.append("")

    if stats:
        parts = " ".join(f"{k}={v}" for k, v in stats.items() if v)
        out.append(_c("dim", f"-- {parts}", color))
    return "\n".join(out) + "\n"


def render_json(findings: list[Finding], stats: dict | None = None) -> str:
    payload = {
        "tool": "secretsweep",
        "stats": stats or {},
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2) + "\n"


def summary_line(findings: list[Finding]) -> str:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    return (
        f"{len(findings)} finding(s): "
        f"critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']} info={counts['info']}"
    )
