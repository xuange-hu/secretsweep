"""SARIF 2.1.0 output so findings land in GitHub code scanning."""

from __future__ import annotations

import os

from .model import SEVERITY_ORDER, Finding
from .patterns import RULES_BY_ID

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

# SARIF level vocabulary is narrower than ours.
LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SEVERITY_SCORE = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "info": 1.0,
}


def _rule_descriptor(finding: Finding) -> dict:
    rule = RULES_BY_ID.get(finding.rule)
    descriptor = {
        "id": finding.rule,
        "name": finding.rule.replace("-", "_"),
        "shortDescription": {"text": finding.rule_name},
        "fullDescription": {"text": (rule.note if rule and rule.note else finding.rule_name)},
        "help": {
            "text": (
                "Rotate this credential, then remove it from the file and from git history. "
                "See https://docs.github.com/en/code-security/secret-scanning"
            )
        },
        "defaultConfiguration": {"level": LEVEL_BY_SEVERITY.get(finding.severity, "warning")},
        "properties": {
            "security-severity": str(SEVERITY_SCORE.get(finding.severity, 5.0)),
            "tags": sorted(set(finding.tags) | {"security", "secret"}),
        },
    }
    return descriptor


def build_sarif(findings: list[Finding], root: str = "") -> dict:
    rules_seen: dict[str, dict] = {}
    results = []
    for finding in findings:
        rules_seen.setdefault(finding.rule, _rule_descriptor(finding))
        uri = finding.path.replace("\\", "/")
        if root:
            uri = os.path.relpath(finding.path, root).replace("\\", "/")
        results.append(
            {
                "ruleId": finding.rule,
                "level": LEVEL_BY_SEVERITY.get(finding.severity, "warning"),
                "message": {
                    "text": (
                        f"{finding.rule_name} (confidence={finding.confidence}, "
                        f"entropy={finding.entropy:.2f}, masked={finding.masked})"
                        + (f"; {'; '.join(finding.reasons)}" if finding.reasons else "")
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": finding.line, "startColumn": finding.column},
                        }
                    }
                ],
                "partialFingerprints": {"secretsweepFingerprint": finding.fingerprint},
                "properties": {
                    "confidence": finding.confidence,
                    "bucket": finding.bucket,
                    "suppressed": finding.suppressed,
                    "baseSeverity": finding.base_severity or finding.severity,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secretsweep",
                        "informationUri": "https://github.com/xuange-hu/secretsweep",
                        "rules": [rules_seen[k] for k in sorted(rules_seen)],
                    }
                },
                "results": results,
            }
        ],
    }


def severity_rank(finding: Finding) -> int:
    return SEVERITY_ORDER[finding.severity]
