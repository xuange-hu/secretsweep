#!/usr/bin/env python3
"""GitHub Action entrypoint for secretsweep.

Deliberately thin: the action reuses `secretsweep.cli`'s own argparse tree to
build its options, so a flag can never mean one thing in the CLI and another
in CI. It then calls the library directly instead of going through
`cmd_scan`, because the action needs structured results (counts, max severity,
SARIF, a report for the step summary) rather than a printed blob.

No third-party imports: the action runs the checked-out source, so a CI run
that uses it installs nothing at all. That matters for a credential scanner -
the thing that is supposed to be watching your supply chain should not be
adding to it.
"""

from __future__ import annotations

import json
import os
import shlex
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from secretsweep import baseline as baseline_mod  # noqa: E402
from secretsweep import cli  # noqa: E402
from secretsweep import sarif as sarif_mod  # noqa: E402
from secretsweep.model import SEVERITY_ORDER  # noqa: E402
from secretsweep.report import render_json, render_text  # noqa: E402

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

# A step output that is 4000 lines long makes the job log unusable; cap it.
MAX_REPORT_BYTES = 64 * 1024


def _input(name: str, default: str = "") -> str:
    value = os.environ.get("INPUT_" + name.upper().replace("-", "_"), "")
    return value if value.strip() else default


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get("INPUT_" + name.upper().replace("-", "_"), "")
    if not raw.strip():
        return default
    return raw.strip().lower() in ("true", "1", "yes", "on")


def _list(name: str) -> list[str]:
    """Action inputs have no repeat syntax, so accept comma or newline lists."""
    raw = os.environ.get("INPUT_" + name.upper().replace("-", "_"), "")
    return [part.strip() for part in raw.replace("\n", ",").split(",") if part.strip()]


def _argv() -> list[str]:
    argv = ["--no-color", "scan", _input("path", "."), "--fail-on", _input("fail-on", "high")]
    if _input("min-severity", "info") != "info":
        argv += ["--min-severity", _input("min-severity")]
    if _input("baseline"):
        argv += ["--baseline", _input("baseline")]
    if _input("sarif"):
        argv += ["--sarif", _input("sarif")]
    if _flag("json"):
        argv.append("--json")
    if _flag("show-placeholders"):
        argv.append("--show-placeholders")
    if _flag("no-ignore-file"):
        argv.append("--no-ignore-file")
    if _flag("no-inline-ignore"):
        argv.append("--no-inline-ignore")
    if _flag("history"):
        argv += ["--history", "--max-commits", _input("max-commits", "500")]
    if _input("entropy-min"):
        argv += ["--entropy-min", _input("entropy-min")]
    if _input("max-bytes"):
        argv += ["--max-bytes", _input("max-bytes")]
    for value in _list("tag"):
        argv += ["--tag", value]
    for value in _list("exclude-rule"):
        argv += ["--exclude-rule", value]
    for value in _list("skip-dir"):
        argv += ["--skip-dir", value]
    for value in _list("ignore-glob"):
        argv += ["--ignore-glob", value]
    # `extra-args` is the escape hatch: anything not modelled as an input yet.
    argv += shlex.split(_input("extra-args"))
    return argv


def _max_severity(findings) -> str:
    best = None
    for finding in findings:
        rank = SEVERITY_ORDER.get(finding.severity)
        if rank is None:
            continue
        if best is None or rank > best[0]:
            best = (rank, finding.severity)
    return best[1] if best else "none"


def _write_output(handle, name: str, value: str) -> None:
    """GITHUB_OUTPUT uses heredoc syntax for anything that may be multiline."""
    if any(char in value for char in ("\n", "\r")):
        delimiter = "secretsweep_" + name.replace("-", "_")
        handle.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
    else:
        handle.write(f"{name}={value}\n")


def _write_summary(text: str, stats: dict) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("## secretsweep\n\n")
        fh.write(f"**{stats['findings']} finding(s)** — highest severity `{stats['max-severity']}`\n\n")
        if text.strip():
            fh.write("```\n")
            fh.write(text if text.endswith("\n") else text + "\n")
            fh.write("```\n")


def _truncate(text: str) -> str:
    raw = text.encode("utf-8", "replace")
    if len(raw) <= MAX_REPORT_BYTES:
        return text
    return raw[:MAX_REPORT_BYTES].decode("utf-8", "ignore") + "\n... (truncated)\n"


def main() -> int:
    args = cli.build_parser().parse_args(_argv())
    if not os.path.exists(args.path):
        print(f"secretsweep: no such path: {args.path}", file=sys.stderr)
        return EXIT_ERROR

    options = cli._options_from_args(args)
    result = cli._collect(args.path, options, args)
    findings = result.findings

    stats = cli._stats(result)
    if args.baseline and os.path.exists(args.baseline):
        diff = baseline_mod.compare(findings, baseline_mod.load(args.baseline))
        stats["baseline_persisted"] = len(diff.persisted)
        stats["baseline_resolved"] = len(diff.resolved)
        reported = diff.new
    else:
        reported = findings

    for err in result.errors:
        print(f"secretsweep: {err}", file=sys.stderr)

    stats["findings"] = len(reported)
    stats["max-severity"] = _max_severity(reported)
    root = args.path if os.path.isdir(args.path) else os.path.dirname(args.path) or "."

    if args.sarif:
        payload = sarif_mod.build_sarif(reported, root=root)
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        print(f"secretsweep: wrote {args.sarif} ({len(reported)} results)")

    if args.json:
        sys.stdout.write(render_json(reported, stats))
        body = ""
    else:
        body = render_text(reported, color=False, show_evidence=not args.no_evidence, stats=stats)
        sys.stdout.write(body)

    _write_summary(_truncate(body) if body else "", stats)

    out_path = os.environ.get("GITHUB_OUTPUT")
    if out_path:
        with open(out_path, "a", encoding="utf-8") as fh:
            _write_output(fh, "findings", str(len(reported)))
            _write_output(fh, "max-severity", stats["max-severity"])
            _write_output(fh, "files-scanned", str(result.files_scanned))
            _write_output(fh, "report", _truncate(body))
            _write_output(fh, "sarif", args.sarif or "")

    failed = cli._exceeds(reported, cli._fail_threshold(args.fail_on))
    exit_code = EXIT_FINDINGS if failed else EXIT_CLEAN
    if out_path:
        with open(out_path, "a", encoding="utf-8") as fh:
            _write_output(fh, "exit-code", str(exit_code))
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
