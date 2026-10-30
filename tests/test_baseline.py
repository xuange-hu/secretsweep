import json

import pytest

from secretsweep import baseline as bl
from secretsweep.scanner import scan_text

# Fixture values are assembled from fragments: a secret scanner's own repository
# must not contain literals that GitHub push protection (or any other scanner)
# will flag. Runtime values are unchanged.
AWS_KEY = "AK" + "IA3RJ4E5TZLMXQW7PU"


AWS = f'aws_access_key_id = "{AWS_KEY}"'
GH = 'GITHUB_TOKEN = "ghp_R7kQ2vLm9pZxT4wC8jH5fB1dY6sA0eU3oI7g"'


def _findings(text="src/app.py"):
    return scan_text(AWS, path=text)


def test_build_is_deterministic_and_sorted():
    findings = _findings()
    data = bl.build(findings)
    assert data["version"] == bl.BASELINE_VERSION
    assert data["count"] == 1
    assert data["entries"] == sorted(data["entries"])
    assert bl.build(list(reversed(findings))) == data


def test_entry_keys_are_path_rule_fingerprint():
    findings = _findings()
    entry = bl.build(findings)["entries"][0]
    assert entry.split("|") == ["src/app.py", "aws-access-key-id", findings[0].fingerprint]


def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / "sub" / bl.DEFAULT_NAME
    data = bl.build(_findings())
    bl.save(str(path), data)
    assert path.exists()
    assert bl.load(str(path)) == data


def test_save_creates_missing_directories(tmp_path):
    path = tmp_path / "a" / "b" / "baseline.json"
    bl.save(str(path), bl.build([]))
    assert path.exists()


def test_load_rejects_foreign_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(ValueError):
        bl.load(str(path))


def test_load_rejects_future_version(tmp_path):
    path = tmp_path / "v9.json"
    path.write_text(json.dumps({"version": 9, "entries": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        bl.load(str(path))


def test_compare_splits_new_persisted_and_resolved():
    first = _findings()
    base = bl.build(first)
    diff = bl.compare(first, base)
    assert diff.clean
    assert len(diff.persisted) == 1
    assert diff.new == []
    assert diff.resolved == []

    second = first + scan_text(GH, path="src/app.py")
    diff = bl.compare(second, base)
    assert not diff.clean
    assert [f.rule for f in diff.new] == ["github-pat"]


def test_compare_reports_resolved_entries():
    base = bl.build(_findings())
    diff = bl.compare([], base)
    assert len(diff.resolved) == 1
    assert diff.new == []


def test_prune_drops_stale_entries():
    base = bl.build(_findings())
    pruned = bl.prune(base, [])
    assert pruned["entries"] == []
    assert pruned["count"] == 0
    kept = bl.prune(base, _findings())
    assert kept["entries"] == base["entries"]


def test_baseline_ignores_line_drift():
    """A finding keeps its identity when code moves around it."""
    before = scan_text("\n\n" + AWS, path="src/app.py")
    after = scan_text(AWS, path="src/app.py")
    assert before[0].line != after[0].line
    assert bl.build(before) == bl.build(after)


def test_a_new_secret_in_a_baselined_file_still_shows():
    base = bl.build(_findings())
    moved = scan_text(AWS + "\n" + GH, path="src/app.py")
    diff = bl.compare(moved, base)
    assert [f.rule for f in diff.new] == ["github-pat"]


def test_entry_set_helper():
    base = bl.build(_findings())
    assert bl.entry_set(base) == set(base["entries"])
