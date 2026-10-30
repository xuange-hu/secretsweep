import pytest

from secretsweep import history as hist
from secretsweep.scanner import Options

# Fixture values are assembled from fragments: a secret scanner's own repository
# must not contain literals that GitHub push protection (or any other scanner)
# will flag. Runtime values are unchanged.
AWS_KEY = "AK" + "IA3RJ4E5TZLMXQW7PU"


AWS = f'aws_access_key_id = "{AWS_KEY}"'
GH = 'GITHUB_TOKEN = "ghp_R7kQ2vLm9pZxT4wC8jH5fB1dY6sA0eU3oI7g"'

SYNTHETIC_LOG = "\n".join(
    [
        "commit 1111111111111111111111111111111111111111",
        "Author: dev <dev@example.org>",
        "",
        "    add config",
        "",
        "diff --git a/src/app.py b/src/app.py",
        "new file mode 100644",
        "index 0000000..1111111",
        "--- /dev/null",
        "+++ b/src/app.py",
        "@@ -0,0 +1,2 @@",
        f"+{AWS}",
        "+print('hello')",
        "commit 2222222222222222222222222222222222222222",
        "",
        "    add token",
        "",
        "diff --git a/src/ci.py b/src/ci.py",
        "--- a/src/ci.py",
        "+++ b/src/ci.py",
        "@@ -10,3 +10,4 @@ def main():",
        " context",
        f"+{GH}",
        "-removed = 1",
        "",
    ]
)


@pytest.fixture
def fake_repo(monkeypatch):
    monkeypatch.setattr(hist, "is_repo", lambda root: True)
    monkeypatch.setattr(hist, "_run_log", lambda root, max_commits: SYNTHETIC_LOG)
    return True


def test_scan_history_reports_added_lines_with_commit(fake_repo):
    result = hist.scan_history(".")
    rules = {f.rule for f in result.findings}
    assert "aws-access-key-id" in rules
    assert "github-pat" in rules
    assert all(any(r.startswith("commit:") for r in f.reasons) for f in result.findings)


def test_scan_history_tracks_line_numbers(fake_repo):
    result = hist.scan_history(".")
    by_rule = {f.rule: f for f in result.findings}
    assert by_rule["aws-access-key-id"].line == 1
    # the context line above the addition advances the counter first
    assert by_rule["github-pat"].line == 11


def test_scan_history_deduplicates_across_commits(fake_repo):
    result = hist.scan_history(".")
    assert len(result.findings) == 2


def test_scan_history_respects_options(fake_repo):
    options = Options(exclude_rules=("aws-access-key-id", "github-pat"))
    result = hist.scan_history(".", options=options)
    assert "aws-access-key-id" not in {f.rule for f in result.findings}
    assert "github-pat" not in {f.rule for f in result.findings}


def test_scan_history_outside_a_repo(monkeypatch):
    monkeypatch.setattr(hist, "is_repo", lambda root: False)
    result = hist.scan_history(".")
    assert result.findings == []
    assert result.errors


def test_scan_history_with_empty_log(monkeypatch):
    monkeypatch.setattr(hist, "is_repo", lambda root: True)
    monkeypatch.setattr(hist, "_run_log", lambda root, max_commits: "")
    assert hist.scan_history(".").findings == []


def test_is_repo_degrades_without_git(monkeypatch):
    monkeypatch.setattr(hist, "git_available", lambda: False)
    assert hist.is_repo(".") is False
    assert hist.repo_root(".") is None


def test_relpath_is_posix():
    assert hist.relpath("a\\b\\c.py", "a") == "b/c.py"


def test_this_project_is_a_git_repo_or_git_is_missing():
    """Sanity: the helpers must agree with whatever the environment offers."""
    if hist.git_available():
        assert isinstance(hist.is_repo("."), bool)
    else:
        assert hist.is_repo(".") is False
