import pytest

from secretsweep.model import SEVERITY_ORDER
from secretsweep.patterns import RULES, RULES_BY_ID, rule_ids, rules_for_tag, tags
from secretsweep.samples import RULE_SAMPLES


def test_rule_ids_are_unique():
    ids = rule_ids()
    assert len(ids) == len(set(ids))


def test_rules_by_id_is_consistent():
    assert len(RULES_BY_ID) == len(RULES)
    for rule in RULES:
        assert RULES_BY_ID[rule.rid] is rule


def test_every_rule_has_a_valid_severity():
    for rule in RULES:
        assert rule.severity in SEVERITY_ORDER, rule.rid


def test_every_rule_declares_tags_and_a_name():
    for rule in RULES:
        assert rule.tags, rule.rid
        assert rule.name and not rule.name.isspace(), rule.rid


def test_value_group_never_points_past_the_pattern():
    for rule in RULES:
        assert rule.value_group <= rule.pattern.groups, rule.rid


def test_entropy_gates_are_sane():
    for rule in RULES:
        assert 0.0 <= rule.entropy_min <= 6.0, rule.rid


def test_keywords_are_lowercase():
    for rule in RULES:
        for kw in rule.keywords:
            assert kw == kw.lower(), (rule.rid, kw)


def test_there_is_a_sample_for_every_rule():
    assert set(RULE_SAMPLES) == set(rule_ids())


def test_tags_are_discoverable():
    all_tags = tags()
    assert "aws" in all_tags
    assert "generic" in all_tags
    assert len(all_tags) == len(set(all_tags))


def test_rules_for_tag_filters():
    aws = rules_for_tag("aws")
    assert aws and all("aws" in r.tags for r in aws)
    assert rules_for_tag("definitely-not-a-tag") == []


def test_priority_defaults_to_zero():
    assert all(r.priority >= 0 for r in RULES)
    flagged = [r.rid for r in RULES if r.priority > 0]
    assert flagged, "at least one rule should disambiguate an overlap"


def test_rule_is_hashable_and_frozen():
    rule = RULES[0]
    with pytest.raises(AttributeError):
        rule.rid = "mutated"
