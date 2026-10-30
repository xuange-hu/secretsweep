import pytest

from secretsweep.model import (
    CONFIDENCE_ORDER,
    SEVERITIES,
    SEVERITY_ORDER,
    Finding,
    at_least,
    downgrade,
    fingerprint,
    mask,
    normalize_severity,
    sort_findings,
    upgrade,
)


def test_severity_order_is_total():
    assert list(SEVERITY_ORDER) == list(SEVERITIES)
    assert SEVERITY_ORDER["critical"] > SEVERITY_ORDER["high"] > SEVERITY_ORDER["medium"]
    assert SEVERITY_ORDER["medium"] > SEVERITY_ORDER["low"] > SEVERITY_ORDER["info"]


def test_normalize_severity_accepts_known_values():
    assert normalize_severity(" HIGH ") == "high"


def test_normalize_severity_rejects_unknown():
    with pytest.raises(ValueError):
        normalize_severity("catastrophic")


def test_at_least_comparisons():
    assert at_least("critical", "high")
    assert at_least("high", "high")
    assert not at_least("medium", "high")
    assert not at_least("info", "low")


def test_downgrade_and_upgrade_clamp():
    assert downgrade("critical") == "high"
    assert downgrade("info", 3) == "info"
    assert upgrade("info") == "low"
    assert upgrade("critical", 2) == "critical"


def test_fingerprint_is_stable_and_unique():
    a = fingerprint("github-pat", "ghp_abc")
    b = fingerprint("github-pat", "ghp_abc")
    c = fingerprint("github-pat", "ghp_abd")
    d = fingerprint("aws-access-key-id", "ghp_abc")
    assert a == b
    assert len(a) == 16
    assert a != c and a != d


def test_mask_keeps_head_and_tail():
    assert mask("abcdefghijklmnop") == "abcd**********op"
    assert mask("short") == "*****"
    assert mask("abcdef") == "******"


def _finding(severity="high", path="a.py", line=1, confidence="likely"):
    return Finding(
        path=path,
        line=line,
        column=1,
        rule="r",
        rule_name="Rule",
        severity=severity,
        confidence=confidence,
        masked="***",
        fingerprint="fp",
        entropy=4.0,
        bucket="source",
    )


def test_finding_to_dict_roundtrips_the_important_parts():
    data = _finding().to_dict()
    assert data["severity"] == "high"
    assert data["base_severity"] == "high"
    assert data["reasons"] == []
    assert data["tags"] == []


def test_finding_location():
    assert _finding(path="src/a.py", line=12).location == "src/a.py:12:1"


def test_sort_findings_puts_critical_first():
    findings = [_finding("low"), _finding("critical"), _finding("high", path="b.py")]
    ordered = sort_findings(findings)
    assert [f.severity for f in ordered] == ["critical", "high", "low"]


def test_sort_findings_breaks_ties_by_confidence_then_path():
    findings = [
        _finding("high", path="z.py", confidence="placeholder"),
        _finding("high", path="a.py", confidence="real"),
        _finding("high", path="a.py", confidence="likely"),
    ]
    ordered = sort_findings(findings)
    assert [(f.path, f.confidence) for f in ordered] == [
        ("a.py", "real"),
        ("a.py", "likely"),
        ("z.py", "placeholder"),
    ]


def test_confidence_order():
    assert CONFIDENCE_ORDER["real"] > CONFIDENCE_ORDER["likely"] > CONFIDENCE_ORDER["placeholder"]
