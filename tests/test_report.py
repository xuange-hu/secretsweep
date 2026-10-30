import json

from secretsweep.model import Finding
from secretsweep.report import render_json, render_text, summary_line
from secretsweep.scanner import scan_text

# Fixture values are assembled from fragments: a secret scanner's own repository
# must not contain literals that GitHub push protection (or any other scanner)
# will flag. Runtime values are unchanged.
AWS_KEY = "AK" + "IA3RJ4E5TZLMXQW7PU"


AWS = f'aws_access_key_id = "{AWS_KEY}"'


def _finding(**kw):
    base = dict(
        path="src/app.py",
        line=3,
        column=9,
        rule="aws-access-key-id",
        rule_name="AWS access key id",
        severity="high",
        confidence="likely",
        masked="AKIA****PU",
        fingerprint="abc123",
        entropy=4.2,
        bucket="source",
        evidence=AWS,
        tags=("aws",),
    )
    base.update(kw)
    return Finding(**base)


def test_empty_report_says_so():
    assert "no findings" in render_text([])


def test_text_report_groups_by_path():
    text = render_text([_finding(), _finding(path="src/other.py", line=1)])
    assert text.count("src/app.py") == 1
    assert "src/other.py" in text


def test_text_report_includes_severity_rule_and_mask():
    text = render_text([_finding()], color=False)
    assert "HIGH" in text
    assert "aws-access-key-id" in text
    assert "AKIA****PU" in text


def test_text_report_marks_placeholders():
    text = render_text([_finding(suppressed=True, confidence="placeholder", severity="info")])
    assert "[placeholder]" in text


def test_text_report_can_hide_evidence():
    assert AWS in render_text([_finding()])
    assert AWS not in render_text([_finding()], show_evidence=False)


def test_text_report_color_wraps_but_keeps_content():
    plain = render_text([_finding()], color=False)
    colored = render_text([_finding()], color=True)
    assert "\033[" in colored
    assert "\033[" not in plain
    assert "aws-access-key-id" in colored.replace("\033[0m", "")


def test_text_report_appends_stats():
    text = render_text([_finding()], stats={"files_scanned": 4, "findings": 1})
    assert "files_scanned=4" in text


def test_json_report_is_parseable():
    payload = json.loads(render_json([_finding()], {"findings": 1}))
    assert payload["tool"] == "secretsweep"
    assert payload["findings"][0]["rule"] == "aws-access-key-id"
    assert payload["stats"]["findings"] == 1


def test_summary_line_counts_every_severity():
    findings = [_finding(severity="critical"), _finding(severity="low"), _finding(severity="low")]
    line = summary_line(findings)
    assert "3 finding(s)" in line
    assert "critical=1" in line
    assert "low=2" in line
    assert "high=0" in line


def test_report_roundtrips_real_findings():
    findings = scan_text(AWS, path="src/app.py")
    payload = json.loads(render_json(findings))
    assert payload["findings"][0]["fingerprint"] == findings[0].fingerprint
    assert findings[0].masked in render_text(findings)
    assert AWS_KEY not in render_text(findings)
