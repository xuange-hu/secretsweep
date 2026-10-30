"""Core data model: severities, confidences, findings."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER = {name: i for i, name in enumerate(SEVERITIES)}

# "real"      -> structural evidence says this is a live credential
# "likely"    -> looks like a credential, no placeholder markers
# "placeholder" -> documented example / template / dummy value
CONFIDENCES = ("placeholder", "likely", "real")
CONFIDENCE_ORDER = {name: i for i, name in enumerate(CONFIDENCES)}


def normalize_severity(value: str) -> str:
    v = (value or "").strip().lower()
    if v not in SEVERITY_ORDER:
        raise ValueError(f"unknown severity: {value!r} (expected one of {SEVERITIES})")
    return v


def at_least(severity: str, threshold: str) -> bool:
    """True when `severity` is at or above `threshold`."""
    return SEVERITY_ORDER[normalize_severity(severity)] >= SEVERITY_ORDER[normalize_severity(threshold)]


def downgrade(severity: str, steps: int = 1) -> str:
    idx = max(0, SEVERITY_ORDER[normalize_severity(severity)] - steps)
    return SEVERITIES[idx]


def upgrade(severity: str, steps: int = 1) -> str:
    idx = min(len(SEVERITIES) - 1, SEVERITY_ORDER[normalize_severity(severity)] + steps)
    return SEVERITIES[idx]


def fingerprint(rule_id: str, value: str) -> str:
    """Stable 16-hex id for a (rule, secret) pair.

    Deliberately independent of file/line: a finding keeps its identity when the
    file moves or the line number shifts, which is what makes baselines usable.
    """
    digest = hashlib.sha256(f"{rule_id}:{value}".encode("utf-8", "replace")).hexdigest()
    return digest[:16]


def mask(value: str, keep_head: int = 4, keep_tail: int = 2) -> str:
    """Mask a secret for display. Short values are masked completely."""
    if len(value) <= keep_head + keep_tail + 1:
        return "*" * len(value)
    return f"{value[:keep_head]}{'*' * min(12, len(value) - keep_head - keep_tail)}{value[-keep_tail:]}"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    column: int
    rule: str
    rule_name: str
    severity: str
    confidence: str
    masked: str
    fingerprint: str
    entropy: float
    bucket: str
    reasons: tuple[str, ...] = ()
    evidence: str = ""
    suppressed: bool = False
    base_severity: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "rule": self.rule,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "base_severity": self.base_severity or self.severity,
            "confidence": self.confidence,
            "masked": self.masked,
            "fingerprint": self.fingerprint,
            "entropy": round(self.entropy, 3),
            "bucket": self.bucket,
            "suppressed": self.suppressed,
            "reasons": list(self.reasons),
            "tags": list(self.tags),
            "evidence": self.evidence,
        }

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}:{self.column}"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_ORDER[f.severity],
            -CONFIDENCE_ORDER[f.confidence],
            f.path,
            f.line,
            f.rule,
        ),
    )
