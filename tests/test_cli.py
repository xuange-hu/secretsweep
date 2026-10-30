import json
import os

import pytest

from secretsweep import demo as demo_mod
from secretsweep.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, build_parser, main

# Fixture values are assembled from fragments: a secret scanner's own repository
# must not contain literals that GitHub push protection (or any other scanner)
# will flag. Runtime values are unchanged.
AWS_KEY = "AK" + "IA3RJ4E5TZLMXQW7PU"
S40 = "qN3xT7vLm2pR9wZ4cK8jH5fB1dY6sA0eU3o" + "I7gXz"



@pytest.fixture
def leaky(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        f'aws_access_key_id = "{AWS_KEY}"\n'
        'GITHUB_TOKEN = "ghp_R7kQ2vLm9pZxT4wC8jH5fB1dY6sA0eU3oI7g"\n',
        encoding="utf-8",
    )
    return tmp_path


def test_parser_has_every_subcommand():
    parser = build_parser()
    actions = [a for a in parser._actions if a.dest == "command"]
    assert actions
    assert set(actions[0].choices) == {"scan", "baseline", "diff", "rules", "entropy", "demo"}


def test_scan_reports_and_fails(leaky, capsys):
    code = main(["scan", str(leaky), "--no-color"])
    out = capsys.readouterr().out
    assert code == EXIT_FINDINGS
    assert "aws-access-key-id" in out
    assert "github-pat" in out


def test_scan_fail_on_none_is_clean(leaky):
    assert main(["scan", str(leaky), "--fail-on", "none"]) == EXIT_CLEAN


def test_scan_fail_on_critical_ignores_high(leaky, tmp_path):
    only_high = tmp_path / "high.py"
    only_high.write_text(f'aws_access_key_id = "{AWS_KEY}"\n', encoding="utf-8")
    assert main(["scan", str(only_high), "--fail-on", "critical"]) == EXIT_CLEAN


def test_scan_missing_path_is_an_error(tmp_path):
    assert main(["scan", str(tmp_path / "nope")]) == EXIT_ERROR


def test_scan_min_severity_filters(leaky, capsys):
    main(["scan", str(leaky), "--min-severity", "critical", "--no-color"])
    assert "aws-access-key-id" not in capsys.readouterr().out


def test_scan_json_output(leaky, capsys):
    main(["scan", str(leaky), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "secretsweep"
    assert payload["stats"]["findings"] >= 2


def test_scan_sarif_output(leaky, tmp_path, capsys):
    out = tmp_path / "out.sarif.json"
    assert main(["scan", str(leaky), "--sarif", str(out)]) == EXIT_FINDINGS
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["runs"][0]["results"]


def test_scan_with_baseline_is_clean(leaky, tmp_path):
    baseline = tmp_path / "bl.json"
    assert main(["baseline", str(leaky), "-o", str(baseline)]) == EXIT_CLEAN
    assert json.loads(baseline.read_text(encoding="utf-8"))["count"] >= 2
    assert main(["scan", str(leaky), "--baseline", str(baseline)]) == EXIT_CLEAN


def test_scan_reports_new_leaks_against_baseline(leaky, tmp_path):
    baseline = tmp_path / "bl.json"
    main(["baseline", str(leaky), "-o", str(baseline)])
    (leaky / "src" / "app.py").write_text(
        'GITHUB_TOKEN = "ghp_T4wC8jH5fB1dY6sA0eU3oI7gR7kQ2vLm9pZx"\n', encoding="utf-8"
    )
    assert main(["scan", str(leaky), "--baseline", str(baseline)]) == EXIT_FINDINGS


def test_baseline_prune_removes_stale_entries(leaky, tmp_path):
    baseline = tmp_path / "bl.json"
    main(["baseline", str(leaky), "-o", str(baseline)])
    for path in leaky.rglob("*.py"):
        os.remove(path)
    assert main(["baseline", str(leaky), "-o", str(baseline), "--prune"]) == EXIT_CLEAN
    assert json.loads(baseline.read_text(encoding="utf-8"))["count"] == 0


def test_diff_without_baseline_is_an_error(leaky, tmp_path):
    assert main(["diff", str(leaky), "--baseline", str(tmp_path / "missing.json")]) == EXIT_ERROR


def test_diff_against_fresh_baseline_is_clean(leaky, tmp_path, capsys):
    baseline = tmp_path / "bl.json"
    main(["baseline", str(leaky), "-o", str(baseline)])
    assert main(["diff", str(leaky), "--baseline", str(baseline), "--no-color"]) == EXIT_CLEAN
    assert "no findings" in capsys.readouterr().out


def test_diff_json_output(leaky, tmp_path, capsys):
    baseline = tmp_path / "bl.json"
    main(["baseline", str(leaky), "-o", str(baseline)])
    capsys.readouterr()  # drop the baseline command's own output
    main(["diff", str(leaky), "--baseline", str(baseline), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["new"] == 0


def test_rules_lists_everything(capsys):
    assert main(["rules"]) == EXIT_CLEAN
    assert "rule(s)" in capsys.readouterr().out


def test_rules_tag_filter(capsys):
    assert main(["rules", "--tag", "aws"]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "aws-access-key-id" in out
    assert "github-pat" not in out


def test_rules_json(capsys):
    assert main(["rules", "--json"]) == EXIT_CLEAN
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list)
    assert {"id", "severity", "tags"} <= set(payload[0])


def test_entropy_explains_a_string(capsys):
    assert main(["entropy", S40]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "entropy" in out
    assert "random" in out


def test_demo_runs_and_scans(tmp_path, capsys):
    assert main(["demo", "--dir", str(tmp_path), "--no-color"]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "demo tree" in out
    assert "github-pat" in out


def test_demo_json(tmp_path, capsys):
    assert main(["demo", "--dir", str(tmp_path), "--json"]) == EXIT_CLEAN
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"]


def test_no_color_works_before_and_after_the_subcommand(leaky):
    assert main(["--no-color", "scan", str(leaky)]) == EXIT_FINDINGS
    assert main(["scan", str(leaky), "--no-color"]) == EXIT_FINDINGS


def test_scan_history_flag_is_accepted(leaky):
    # not a git repo in tmp: the history scan must degrade, not crash
    assert main(["scan", str(leaky), "--history"]) in (EXIT_CLEAN, EXIT_FINDINGS)


def test_demo_never_writes_outside_its_dir(tmp_path):
    demo_mod.run(str(tmp_path))
    assert {p.name for p in tmp_path.iterdir()} <= {".secretsweepignore", "src", ".env", ".github", "docs", "tests", "README.md"}
