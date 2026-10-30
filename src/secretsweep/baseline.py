"""Baselines: the only way a secret scanner survives contact with an old repo.

Most repositories committing secrets today committed them years ago. A scanner
that fails the build on day one gets deleted on day one. The workflow this
module supports is:

    secretsweep baseline .            # snapshot what is already there
    secretsweep scan . --baseline .secretsweep-baseline.json   # only new leaks

Fingerprints are (path, rule, value-hash) triples so line drift does not
invalidate a baseline, but a *new* secret in the same file does.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .model import Finding

BASELINE_VERSION = 1
DEFAULT_NAME = ".secretsweep-baseline.json"


def _key(finding: Finding) -> str:
    return f"{finding.path}|{finding.rule}|{finding.fingerprint}"


def build(findings: list[Finding]) -> dict:
    entries = sorted({_key(f) for f in findings})
    return {
        "version": BASELINE_VERSION,
        "tool": "secretsweep",
        "count": len(entries),
        "entries": entries,
    }


def save(path: str, baseline: dict) -> None:
    payload = json.dumps(baseline, indent=2, sort_keys=False) + "\n"
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(payload)


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "entries" not in data:
        raise ValueError(f"{path}: not a secretsweep baseline (missing 'entries')")
    version = data.get("version", 1)
    if version != BASELINE_VERSION:
        raise ValueError(f"{path}: baseline version {version} != {BASELINE_VERSION}")
    return data


def entry_set(baseline: dict) -> set[str]:
    return set(baseline.get("entries") or [])


@dataclass
class Diff:
    new: list[Finding] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    persisted: list[Finding] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.new


def compare(findings: list[Finding], baseline: dict) -> Diff:
    known = entry_set(baseline)
    current = {_key(f): f for f in findings}
    diff = Diff()
    for key, finding in current.items():
        if key in known:
            diff.persisted.append(finding)
        else:
            diff.new.append(finding)
    diff.resolved = sorted(known - set(current))
    diff.new.sort(key=lambda f: (f.path, f.line, f.rule))
    diff.persisted.sort(key=lambda f: (f.path, f.line, f.rule))
    return diff


def prune(baseline: dict, findings: list[Finding]) -> dict:
    """Drop baseline entries that no longer exist - a baseline should shrink."""
    current = {_key(f) for f in findings}
    kept = sorted(entry_set(baseline) & current)
    out = dict(baseline)
    out["entries"] = kept
    out["count"] = len(kept)
    return out
