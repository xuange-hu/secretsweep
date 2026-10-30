"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from . import baseline as baseline_mod
from . import demo as demo_mod
from . import sarif as sarif_mod
from .entropy import charset_of, is_random_looking, shannon_entropy
from .model import SEVERITIES, Finding, normalize_severity
from .patterns import RULES, rules_for_tag
from .report import render_json, render_text
from .scanner import DEFAULT_MAX_BYTES, Options, ScanResult, scan_path

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    # `--no-color` lives on a shared parent so it works before *and* after the
    # subcommand: argparse only accepts global flags before it.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", help="disable ANSI color")

    parser = argparse.ArgumentParser(
        prog="secretsweep",
        description="Zero-dependency credential leak scanner.",
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"secretsweep {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- scan
    scan = sub.add_parser("scan", help="scan a path or a single file", parents=[common])
    scan.add_argument("path", nargs="?", default=".", help="path to scan (default: .)")
    scan.add_argument("--baseline", help="baseline file; only report findings not in it")
    scan.add_argument("--fail-on", default="high", help="severity that fails the run (default: high; 'none' disables)")
    scan.add_argument("--min-severity", default="info", choices=SEVERITIES, help="hide findings below this level")
    scan.add_argument("--entropy-min", type=float, default=None, help="raise every rule's entropy gate")
    scan.add_argument("--tag", action="append", default=[], help="only run rules carrying this tag (repeatable)")
    scan.add_argument("--exclude-rule", action="append", default=[], help="skip a rule id (repeatable)")
    scan.add_argument("--skip-dir", action="append", default=[], help="extra directory name to skip (repeatable)")
    scan.add_argument("--ignore-glob", action="append", default=[], help="extra path glob to skip (repeatable)")
    scan.add_argument(
        "--no-ignore-file",
        action="store_true",
        help="do not read .secretsweepignore from the scan root",
    )
    scan.add_argument("--show-placeholders", action="store_true", help="also report documented example values")
    scan.add_argument("--no-inline-ignore", action="store_true", help="ignore `secretsweep:ignore` directives")
    scan.add_argument("--history", action="store_true", help="scan git history instead of the working tree")
    scan.add_argument("--max-commits", type=int, default=500, help="history depth (default: 500)")
    scan.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="skip files larger than this")
    scan.add_argument("--json", action="store_true", help="JSON output")
    scan.add_argument("--sarif", help="write SARIF 2.1.0 to this path (implies no text report)")
    scan.add_argument("--no-evidence", action="store_true", help="hide the source line in the text report")

    # ---- baseline
    bl = sub.add_parser("baseline", help="snapshot current findings so only new leaks fail CI", parents=[common])
    bl.add_argument("path", nargs="?", default=".", help="path to scan")
    bl.add_argument("-o", "--output", default=baseline_mod.DEFAULT_NAME, help="baseline file path")
    bl.add_argument("--prune", action="store_true", help="drop baseline entries that no longer exist")
    bl.add_argument("--min-severity", default="info", choices=SEVERITIES)
    bl.add_argument("--show-placeholders", action="store_true")

    # ---- diff
    df = sub.add_parser("diff", help="compare a scan against a baseline without writing anything", parents=[common])
    df.add_argument("path", nargs="?", default=".", help="path to scan")
    df.add_argument("--baseline", default=baseline_mod.DEFAULT_NAME)
    df.add_argument("--json", action="store_true")

    # ---- rules
    rl = sub.add_parser("rules", help="list rules")
    rl.add_argument("--tag", help="filter by tag")
    rl.add_argument("--json", action="store_true")

    # ---- entropy
    en = sub.add_parser("entropy", help="explain a single string")
    en.add_argument("value", help="the string to analyse")

    # ---- demo
    dm = sub.add_parser("demo", help="write a leaky demo repo and scan it", parents=[common])
    dm.add_argument("--dir", help="where to write it (default: temp dir)")
    dm.add_argument("--json", action="store_true")

    return parser


def _options_from_args(args) -> Options:
    return Options(
        include_placeholders=getattr(args, "show_placeholders", False),
        min_severity=getattr(args, "min_severity", "info"),
        entropy_min=getattr(args, "entropy_min", None),
        only_tags=tuple(getattr(args, "tag", []) or []),
        exclude_rules=tuple(getattr(args, "exclude_rule", []) or []),
        max_bytes=getattr(args, "max_bytes", DEFAULT_MAX_BYTES),
        respect_inline_ignore=not getattr(args, "no_inline_ignore", False),
        ignore_globs=tuple(getattr(args, "ignore_glob", []) or ()),
        use_ignore_file=not getattr(args, "no_ignore_file", False),
    )


def _collect(path: str, options: Options, args) -> ScanResult:
    if getattr(args, "history", False):
        from . import history as history_mod

        return history_mod.scan_history(path, options=options, max_commits=getattr(args, "max_commits", 500))
    return scan_path(path, options=options, extra_skip=tuple(getattr(args, "skip_dir", []) or []))


def _stats(result: ScanResult) -> dict:
    return {
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "errors": len(result.errors),
        "duration_ms": result.duration_ms,
    }


def _fail_threshold(value: str) -> str | None:
    if not value or value.lower() in ("none", "never", "off"):
        return None
    return normalize_severity(value)


def _exceeds(findings: list[Finding], threshold: str | None) -> bool:
    if threshold is None:
        return False
    from .model import at_least

    return any(at_least(f.severity, threshold) for f in findings)


def cmd_scan(args) -> int:
    options = _options_from_args(args)
    if not os.path.exists(args.path):
        print(f"secretsweep: no such path: {args.path}", file=sys.stderr)
        return EXIT_ERROR

    result = _collect(args.path, options, args)
    findings = result.findings
    stats = _stats(result)

    if args.baseline and os.path.exists(args.baseline):
        data = baseline_mod.load(args.baseline)
        diff = baseline_mod.compare(findings, data)
        stats["baseline_persisted"] = len(diff.persisted)
        stats["baseline_resolved"] = len(diff.resolved)
        reported = diff.new
    else:
        reported = findings

    for err in result.errors:
        print(f"secretsweep: {err}", file=sys.stderr)

    stats["findings"] = len(reported)
    root = args.path if os.path.isdir(args.path) else os.path.dirname(args.path) or "."

    if args.sarif:
        payload = sarif_mod.build_sarif(reported, root=root)
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        print(f"secretsweep: wrote {args.sarif} ({len(reported)} results)")
    elif args.json:
        sys.stdout.write(render_json(reported, stats))
    else:
        color = not args.no_color and sys.stdout.isatty()
        sys.stdout.write(
            render_text(reported, color=color, show_evidence=not args.no_evidence, stats=stats)
        )
        if not reported:
            return EXIT_CLEAN

    return EXIT_FINDINGS if _exceeds(reported, _fail_threshold(args.fail_on)) else EXIT_CLEAN


def cmd_baseline(args) -> int:
    options = _options_from_args(args)
    result = _collect(args.path, options, args)
    findings = result.findings
    stats = _stats(result)
    data = baseline_mod.build(findings)
    if args.prune:
        data = baseline_mod.prune(data, findings)
    baseline_mod.save(args.output, data)
    print(f"secretsweep: wrote {args.output} ({data['count']} entries, scanned {stats['files_scanned']} files)")
    return EXIT_CLEAN


def cmd_diff(args) -> int:
    options = _options_from_args(args)
    result = _collect(args.path, options, args)
    findings = result.findings
    stats = _stats(result)
    if not os.path.exists(args.baseline):
        print(f"secretsweep: no baseline at {args.baseline}", file=sys.stderr)
        return EXIT_ERROR
    diff = baseline_mod.compare(findings, baseline_mod.load(args.baseline))
    stats.update({"new": len(diff.new), "resolved": len(diff.resolved), "persisted": len(diff.persisted)})
    if args.json:
        sys.stdout.write(render_json(diff.new, stats))
    else:
        color = not args.no_color and sys.stdout.isatty()
        sys.stdout.write(render_text(diff.new, color=color, stats=stats))
        for key in diff.resolved:
            print(f"resolved: {key}")
    return EXIT_FINDINGS if diff.new else EXIT_CLEAN


def cmd_rules(args) -> int:
    rows = rules_for_tag(args.tag) if args.tag else list(RULES)
    if args.json:
        payload = [
            {
                "id": r.rid,
                "name": r.name,
                "severity": r.severity,
                "entropy_min": r.entropy_min,
                "keywords": list(r.keywords),
                "tags": list(r.tags),
            }
            for r in rows
        ]
        print(json.dumps(payload, indent=2))
        return EXIT_CLEAN
    print(f"{len(rows)} rule(s)" + (f" tagged {args.tag}" if args.tag else ""))
    for r in rows:
        extra = f" entropy>={r.entropy_min}" if r.entropy_min else ""
        kws = f" keywords={','.join(r.keywords)}" if r.keywords else ""
        print(f"  {r.severity:<8} {r.rid:<34} {r.name}{extra}{kws}")
    return EXIT_CLEAN


def cmd_entropy(args) -> int:
    value = args.value
    ent = shannon_entropy(value)
    print(f"length      : {len(value)}")
    print(f"charset     : {charset_of(value)}")
    print(f"entropy     : {ent:.3f} bits/char")
    print(f"random      : {is_random_looking(value)}")
    return EXIT_CLEAN


def cmd_demo(args) -> int:
    options = Options(include_placeholders=True)
    result = demo_mod.run(args.dir, options=options)
    stats = {
        "files_scanned": result.files_scanned,
        "findings": len(result.findings),
        "duration_ms": result.duration_ms,
    }
    if args.json:
        sys.stdout.write(render_json(result.findings, stats))
    else:
        color = not args.no_color and sys.stdout.isatty()
        print(f"demo tree: {result.root}")
        sys.stdout.write(render_text(result.findings, color=color, stats=stats))
    return EXIT_CLEAN


HANDLERS = {
    "scan": cmd_scan,
    "baseline": cmd_baseline,
    "diff": cmd_diff,
    "rules": cmd_rules,
    "entropy": cmd_entropy,
    "demo": cmd_demo,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = HANDLERS.get(args.command)
    if handler is None:  # pragma: no cover - argparse enforces choices
        parser.print_help()
        return EXIT_ERROR
    try:
        return handler(args)
    except ValueError as exc:
        print(f"secretsweep: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
