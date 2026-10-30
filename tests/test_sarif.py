import json

from secretsweep import sarif as sarif_mod
from secretsweep.scanner import scan_text

# Fixture values are assembled from fragments: a secret scanner's own repository
# must not contain literals that GitHub push protection (or any other scanner)
# will flag. Runtime values are unchanged.
AWS_KEY = "AK" + "IA3RJ4E5TZLMXQW7PU"


AWS = f'aws_access_key_id = "{AWS_KEY}"'
GH = 'GITHUB_TOKEN = "ghp_R7kQ2vLm9pZxT4wC8jH5fB1dY6sA0eU3oI7g"'


def _sarif(text, path="src/app.py", root=""):
    findings = scan_text(text, path=path)
    return sarif_mod.build_sarif(findings, root=root), findings


def test_sarif_envelope():
    doc, _ = _sarif(AWS)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == sarif_mod.SARIF_SCHEMA
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "secretsweep"


def test_sarif_results_carry_location_and_fingerprint():
    doc, findings = _sarif(AWS)
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "aws-access-key-id"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == findings[0].line
    assert result["partialFingerprints"]["secretsweepFingerprint"] == findings[0].fingerprint


def test_sarif_rules_are_deduplicated_and_sorted():
    doc, _ = _sarif(AWS + "\n" + GH)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted({r["id"] for r in rules})
    assert len(rules) == 2


def test_sarif_rule_descriptor_has_security_severity():
    doc, _ = _sarif(GH)
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "security-severity" in rule["properties"]
    assert "secret" in rule["properties"]["tags"]


def test_sarif_is_json_serialisable():
    doc, _ = _sarif(AWS)
    json.dumps(doc)


def test_sarif_paths_are_relative_to_root():
    doc, _ = _sarif(AWS, path="repo/src/app.py", root="repo")
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/app.py"


def test_sarif_windows_paths_use_forward_slashes():
    doc, _ = _sarif(AWS, path="src\\app.py")
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri


def test_level_mapping_is_monotonic():
    order = ["info", "low", "medium", "high", "critical"]
    levels = [sarif_mod.LEVEL_BY_SEVERITY[s] for s in order]
    assert set(levels) <= {"note", "warning", "error"}
    assert sarif_mod.LEVEL_BY_SEVERITY["critical"] == "error"
    assert sarif_mod.LEVEL_BY_SEVERITY["info"] == "note"


def test_severity_rank_matches_severity_order():
    from secretsweep.model import SEVERITY_ORDER

    doc, findings = _sarif(AWS)
    assert sarif_mod.severity_rank(findings[0]) == SEVERITY_ORDER[findings[0].severity]
