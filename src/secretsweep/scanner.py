"""The scan engine.

Pipeline per line:
  regex match -> entropy gate -> placeholder triage -> capability inference
  -> bucket adjustment -> overlap suppression -> dedupe
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field

from . import capability
from .context import DOWNGRADE_BY_BUCKET, classify_path, is_binary, looks_generated
from .entropy import shannon_entropy
from .ignore import DEFAULT_PATTERNS, is_ignored
from .ignore import load as load_ignore
from .model import (
    SEVERITY_ORDER,
    Finding,
    downgrade,
    fingerprint,
    mask,
    sort_findings,
)
from .patterns import RULES, Rule
from .placeholders import triage

IGNORE_TOKEN = "secretsweep:ignore"
IGNORE_RE = re.compile(r"secretsweep:ignore(?:\[([^\]]*)\])?")

SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "site-packages",
        "vendor",
        "third_party",
        ".idea",
        "coverage",
        ".next",
        ".nuxt",
        "target",
    }
)

DEFAULT_MAX_BYTES = 2 * 1024 * 1024

# Rules carrying these tags lose an overlap contest against a provider rule.
GENERIC_TAGS = frozenset({"generic", "entropy"})


@dataclass
class Options:
    rules: tuple[Rule, ...] = RULES
    include_placeholders: bool = False
    min_severity: str = "info"
    entropy_min: float | None = None
    only_tags: tuple[str, ...] = ()
    exclude_rules: tuple[str, ...] = ()
    max_bytes: int = DEFAULT_MAX_BYTES
    respect_inline_ignore: bool = True
    ignore_globs: tuple[str, ...] = ()
    use_ignore_file: bool = True

    def active_rules(self) -> list[Rule]:
        out = []
        for r in self.rules:
            if r.rid in self.exclude_rules:
                continue
            if self.only_tags and not set(r.tags) & set(self.only_tags):
                continue
            out.append(r)
        return out


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    root: str = ""

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "duration_ms": self.duration_ms,
            "errors": self.errors,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
        }

    def counts(self) -> dict[str, int]:
        out = {"total": len(self.findings)}
        for sev in SEVERITY_ORDER:
            out[sev] = sum(1 for f in self.findings if f.severity == sev)
        return out


def _ignored_rule_ids(line: str) -> set[str] | None:
    """Return the set of rule ids ignored on this line.

    `None` means "no ignore directive". An empty set means "ignore everything".
    """
    match = IGNORE_RE.search(line)
    if not match:
        return None
    raw = match.group(1)
    if not raw:
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def _collect_ignores(lines: list[str]) -> dict[int, set[str]]:
    """Map 1-based line number -> ignored rule ids (empty set = all)."""
    ignores: dict[int, set[str]] = {}
    for idx, line in enumerate(lines, start=1):
        ids = _ignored_rule_ids(line)
        if ids is None:
            continue
        # A directive on its own comment line applies to the next code line too.
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
            ignores[idx] = ids
            if idx + 1 <= len(lines) and not lines[idx].strip().startswith(("#", "//", "/*")):
                ignores[idx + 1] = ids
        else:
            ignores[idx] = ids
    return ignores


def _specificity(rule: Rule) -> int:
    return 0 if set(rule.tags) & GENERIC_TAGS else 1


def scan_text(text: str, path: str = "<stdin>", options: Options | None = None) -> list[Finding]:
    """Scan a text blob. `path` is only used for bucketing and reporting."""
    opts = options or Options()
    rules = opts.active_rules()
    lines = text.splitlines()
    ignores = _collect_ignores(lines) if opts.respect_inline_ignore else {}
    bucket = classify_path(path)

    candidates: list[tuple[int, int, int, Rule, str, float]] = []  # line, start, end, rule, value, entropy
    for lineno, line in enumerate(lines, start=1):
        ignored = ignores.get(lineno)
        if ignored is not None and not ignored:
            continue
        if not line.strip():
            continue
        for rule in rules:
            if ignored is not None and rule.rid in ignored:
                continue
            if not rule.matches_line(line):
                continue
            for match in rule.pattern.finditer(line):
                value = match.group(rule.value_group)
                if not value:
                    continue
                ent = shannon_entropy(value)
                gate = rule.entropy_min if opts.entropy_min is None else max(rule.entropy_min, opts.entropy_min)
                if gate and ent < gate:
                    continue
                if rule.validate is not None and not rule.validate(value):
                    continue
                start, end = match.span(rule.value_group)
                candidates.append((lineno, start, end, rule, value, ent))

    # Overlap resolution: a provider rule wins over a generic one on the same span.
    candidates.sort(key=lambda c: (-c[3].priority, -_specificity(c[3]), -(c[2] - c[1]), c[0], c[1]))
    kept: list[tuple[int, int, int, Rule, str, float]] = []
    taken: dict[int, list[tuple[int, int]]] = {}
    for cand in candidates:
        lineno, start, end, _rule, _value, _ent = cand
        spans = taken.setdefault(lineno, [])
        if any(start < e and s < end for s, e in spans):
            continue
        spans.append((start, end))
        kept.append(cand)

    findings: list[Finding] = []
    seen: set[tuple[str, int, str, str]] = set()
    for lineno, start, _end, rule, value, ent in kept:
        line = lines[lineno - 1]
        confidence, reasons = triage(value, line)
        if confidence == "placeholder" and not opts.include_placeholders:
            continue
        base = rule.severity
        sev = base
        extra_reasons = list(reasons)
        tags = list(rule.tags)

        notes = capability.infer(rule.rid, value)
        if notes:
            extra_reasons.extend(notes)
        if any(n.endswith("(already expired)") for n in notes):
            sev = downgrade(sev, 1)
            extra_reasons.append("expired-token")

        steps = DOWNGRADE_BY_BUCKET.get(bucket, 0)
        if steps:
            sev = downgrade(sev, steps)
            extra_reasons.append(f"bucket:{bucket}")

        suppressed = confidence == "placeholder"
        if suppressed:
            sev = "info"

        fp = fingerprint(rule.rid, value)
        key = (path, lineno, rule.rid, fp)
        if key in seen:
            continue
        seen.add(key)

        if SEVERITY_ORDER[sev] < SEVERITY_ORDER[opts.min_severity]:
            continue

        # Evidence is shown to humans and forwarded to agents: the secret itself
        # must never survive into it.
        masked = mask(value)
        evidence = line.strip()[:200].replace(value, masked)

        findings.append(
            Finding(
                path=path,
                line=lineno,
                column=start + 1,
                rule=rule.rid,
                rule_name=rule.name,
                severity=sev,
                confidence=confidence,
                masked=masked,
                fingerprint=fp,
                entropy=ent,
                bucket=bucket,
                reasons=tuple(extra_reasons),
                evidence=evidence,
                suppressed=suppressed,
                base_severity=base,
                tags=tuple(tags),
            )
        )

    return sort_findings(findings)


def scan_file(path: str, options: Options | None = None) -> list[Finding]:
    opts = options or Options()
    try:
        if os.path.getsize(path) > opts.max_bytes:
            return []
    except OSError:
        return []
    if is_binary(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    return scan_text(text, path=path, options=opts)


def iter_files(root: str, options: Options | None = None, extra_skip: tuple[str, ...] = ()):
    """Yield files worth scanning. Prunes known-noisy directories while walking."""
    skip = frozenset(SKIP_DIRS | set(extra_skip))
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if looks_generated(full):
                continue
            yield full


def scan_path(root: str, options: Options | None = None, extra_skip: tuple[str, ...] = ()) -> ScanResult:
    opts = options or Options()
    started = time.time()
    result = ScanResult(root=root)
    seen_files: set[str] = set()
    scan_root = root if os.path.isdir(root) else (os.path.dirname(root) or ".")
    patterns = tuple(opts.ignore_globs) + DEFAULT_PATTERNS
    if opts.use_ignore_file:
        patterns += load_ignore(scan_root)
    for path in iter_files(root, options=opts, extra_skip=extra_skip):
        real = os.path.normcase(os.path.abspath(path))
        if real in seen_files:
            continue
        seen_files.add(real)
        if is_ignored(path, patterns, scan_root):
            result.files_skipped += 1
            continue
        if is_binary(path):
            result.files_skipped += 1
            continue
        try:
            if os.path.getsize(path) > opts.max_bytes:
                result.files_skipped += 1
                continue
        except OSError:
            result.files_skipped += 1
            result.errors.append(f"{path}: unreadable")
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            result.files_skipped += 1
            result.errors.append(f"{path}: {exc}")
            continue
        result.files_scanned += 1
        result.findings.extend(scan_text(text, path=path, options=opts))
    result.findings = sort_findings(result.findings)
    result.duration_ms = int((time.time() - started) * 1000)
    return result
