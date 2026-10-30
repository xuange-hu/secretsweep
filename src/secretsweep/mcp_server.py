"""MCP server: exposes secretsweep as tools for agent runtimes.

Optional extra: `pip install "secretsweep[mcp]"` (pinned to mcp>=1.2,<2 because
2.x renames FastMCP).
"""

from __future__ import annotations

import json
import os

from . import __version__
from . import baseline as baseline_mod
from . import demo as demo_mod
from . import sarif as sarif_mod
from .entropy import charset_of, is_random_looking, shannon_entropy
from .model import SEVERITIES
from .patterns import RULES, rules_for_tag
from .scanner import Options, scan_path, scan_text

_SYSTEM_ERROR = None
try:  # pragma: no cover - exercised only where the extra is installed
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("secretsweep")
except Exception as exc:  # pragma: no cover
    mcp = None
    _SYSTEM_ERROR = str(exc)

MAX_FINDINGS = 200


def _require_server():
    if mcp is None:
        raise RuntimeError(
            "the MCP extra is not installed; run: pip install \"secretsweep[mcp]\""
            + (f" (import error: {_SYSTEM_ERROR})" if _SYSTEM_ERROR else "")
        )
    return mcp


def _options(min_severity: str = "info", include_placeholders: bool = False, entropy_min: float | None = None) -> Options:
    return Options(
        include_placeholders=include_placeholders,
        min_severity=min_severity if min_severity in SEVERITIES else "info",
        entropy_min=entropy_min,
    )


def _summarize(findings) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {"total": len(findings), "by_severity": counts}


def tool_scan(
    path: str,
    min_severity: str = "info",
    include_placeholders: bool = False,
    fail_on: str = "high",
    baseline: str | None = None,
    limit: int = 50,
) -> str:
    """Scan a directory or file for leaked credentials.

    Returns a JSON summary plus the top findings (masked, never the raw secret).
    """
    if not os.path.exists(path):
        return json.dumps({"error": f"no such path: {path}"})
    result = scan_path(path, options=_options(min_severity, include_placeholders))
    findings = result.findings
    payload: dict = {
        "path": path,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "summary": _summarize(findings),
    }
    if baseline and os.path.exists(baseline):
        diff = baseline_mod.compare(findings, baseline_mod.load(baseline))
        payload["baseline"] = {"new": len(diff.new), "resolved": len(diff.resolved), "persisted": len(diff.persisted)}
        findings = diff.new
    payload["findings"] = [f.to_dict() for f in findings[: max(1, min(limit, MAX_FINDINGS))]]
    payload["truncated"] = len(findings) > limit
    return json.dumps(payload, indent=2)


def tool_scan_text(text: str, filename: str = "snippet.txt", min_severity: str = "info") -> str:
    """Scan a pasted snippet (log line, config block, diff) for credentials."""
    findings = scan_text(text, path=filename, options=_options(min_severity))
    return json.dumps({"summary": _summarize(findings), "findings": [f.to_dict() for f in findings]}, indent=2)


def tool_baseline(path: str, include_placeholders: bool = False) -> str:
    """Build a baseline for a path: the set of findings to stop reporting."""
    if not os.path.exists(path):
        return json.dumps({"error": f"no such path: {path}"})
    result = scan_path(path, options=_options(include_placeholders=include_placeholders))
    return json.dumps(baseline_mod.build(result.findings), indent=2)


def tool_diff(path: str, baseline_json: str) -> str:
    """Diff a scan against a baseline document (the JSON from tool_baseline)."""
    if not os.path.exists(path):
        return json.dumps({"error": f"no such path: {path}"})
    try:
        base = json.loads(baseline_json)
    except ValueError as exc:
        return json.dumps({"error": f"invalid baseline json: {exc}"})
    result = scan_path(path, options=_options())
    diff = baseline_mod.compare(result.findings, base)
    return json.dumps(
        {
            "new": [f.to_dict() for f in diff.new],
            "resolved": diff.resolved,
            "persisted": len(diff.persisted),
        },
        indent=2,
    )


def tool_rules(tag: str | None = None) -> str:
    """List detection rules, optionally filtered by tag."""
    rows = rules_for_tag(tag) if tag else list(RULES)
    return json.dumps(
        [
            {
                "id": r.rid,
                "name": r.name,
                "severity": r.severity,
                "entropy_min": r.entropy_min,
                "keywords": list(r.keywords),
                "tags": list(r.tags),
            }
            for r in rows
        ],
        indent=2,
    )


def tool_entropy(value: str) -> str:
    """Explain whether a string looks like random credential material."""
    return json.dumps(
        {
            "length": len(value),
            "charset": charset_of(value),
            "entropy": round(shannon_entropy(value), 3),
            "random_looking": is_random_looking(value),
        },
        indent=2,
    )


def tool_sarif(path: str) -> str:
    """Render findings as SARIF 2.1.0 for code scanning dashboards."""
    if not os.path.exists(path):
        return json.dumps({"error": f"no such path: {path}"})
    result = scan_path(path, options=_options())
    root = path if os.path.isdir(path) else os.path.dirname(path) or "."
    return json.dumps(sarif_mod.build_sarif(result.findings, root=root), indent=2)


def tool_demo() -> str:
    """Scan the built-in leaky demo repo - the fastest way to see output shape."""
    result = demo_mod.run(options=Options(include_placeholders=True))
    return json.dumps(
        {"root": result.root, "summary": _summarize(result.findings), "findings": [f.to_dict() for f in result.findings]},
        indent=2,
    )


TOOLS = (
    ("secretsweep_scan", tool_scan),
    ("secretsweep_scan_text", tool_scan_text),
    ("secretsweep_baseline", tool_baseline),
    ("secretsweep_diff", tool_diff),
    ("secretsweep_rules", tool_rules),
    ("secretsweep_entropy", tool_entropy),
    ("secretsweep_sarif", tool_sarif),
    ("secretsweep_demo", tool_demo),
)


def register(server=None) -> int:
    """Register every tool. Returns the number registered."""
    target = server or _require_server()
    for name, fn in TOOLS:
        target.tool(name=name)(fn)
    return len(TOOLS)


def tool_manifest() -> list[dict]:
    """Describe the tools without importing the MCP SDK."""
    out = []
    for name, fn in TOOLS:
        doc = (fn.__doc__ or "").strip().splitlines()
        out.append({"name": name, "summary": doc[0] if doc else ""})
    return out


def create_server():
    server = _require_server()
    register(server)
    return server


def main() -> None:
    server = create_server()
    server.run()


if __name__ == "__main__":  # pragma: no cover
    main()


__all__ = [
    "TOOLS",
    "__version__",
    "create_server",
    "register",
    "tool_manifest",
]
