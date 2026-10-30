"""Every rule must fire on its own sample.

This is the guard against a rule library that looks impressive in `rules` and
silently matches nothing.
"""

import pytest

from secretsweep.patterns import RULES, rule_ids
from secretsweep.samples import RULE_SAMPLES, extra_samples, missing_samples
from secretsweep.scanner import Options, scan_text

OPTIONS = Options(include_placeholders=True, min_severity="info")


def test_no_missing_or_orphaned_samples():
    assert missing_samples(rule_ids()) == []
    assert extra_samples(rule_ids()) == []


@pytest.mark.parametrize("rule_id", rule_ids())
def test_sample_triggers_its_rule(rule_id):
    line = RULE_SAMPLES[rule_id]
    found = scan_text(line, path="src/app.py", options=OPTIONS)
    assert rule_id in {f.rule for f in found}, f"{rule_id}: sample did not match: {line!r}"


@pytest.mark.parametrize("rule_id", rule_ids())
def test_sample_survives_the_default_options(rule_id):
    """A rule is only useful if its sample shows up without debug flags."""
    line = RULE_SAMPLES[rule_id]
    found = scan_text(line, path="src/app.py")
    rules_hit = {f.rule for f in found}
    assert rules_hit, f"{rule_id}: nothing reported by default: {line!r}"


def test_samples_are_single_line():
    for rule_id, line in RULE_SAMPLES.items():
        assert "\n" not in line, rule_id


def test_every_sample_produces_at_least_one_finding():
    for rule in RULES:
        found = scan_text(RULE_SAMPLES[rule.rid], path="src/app.py", options=OPTIONS)
        assert found, rule.rid
        assert all(f.evidence for f in found), rule.rid
