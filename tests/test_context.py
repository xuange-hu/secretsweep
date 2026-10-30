import pytest

from secretsweep.context import (
    BUCKETS,
    DOWNGRADE_BY_BUCKET,
    classify_path,
    is_binary,
    looks_generated,
)


@pytest.mark.parametrize(
    "path,expected",
    [
        ("src/app.py", "source"),
        ("Makefile", "source"),
        (".env", "config"),
        ("config/settings.ini", "config"),
        ("tests/test_api.py", "test"),
        ("api/__tests__/thing.spec.ts", "test"),
        ("tests/fixtures/tokens.json", "test"),
        ("docs/example.env", "example"),
        ("deploy/app.env.example", "example"),
        ("docs/guide.md", "docs"),
        ("README.md", "docs"),
        ("node_modules/left-pad/index.js", "vendor"),
        ("vendor/bundle/gem.rb", "vendor"),
        (".github/workflows/deploy.yml", "ci"),
        ("Jenkinsfile", "ci"),
        (".gitlab-ci.yml", "ci"),
        ("package-lock.json", "lockfile"),
        ("poetry.lock", "lockfile"),
    ],
)
def test_classify_path(path, expected):
    assert classify_path(path) == expected


def test_every_bucket_has_a_downgrade_rule():
    assert set(DOWNGRADE_BY_BUCKET) == set(BUCKETS)


def test_vendor_is_suppressed_hardest():
    assert DOWNGRADE_BY_BUCKET["vendor"] >= DOWNGRADE_BY_BUCKET["test"]
    assert DOWNGRADE_BY_BUCKET["source"] == 0


def test_is_binary_detects_null_bytes(tmp_path):
    text = tmp_path / "a.txt"
    text.write_text("hello", encoding="utf-8")
    assert not is_binary(str(text))
    blob = tmp_path / "b.txt"
    blob.write_bytes(b"hello\x00world")
    assert is_binary(str(blob))


def test_is_binary_short_circuits_on_extension(tmp_path):
    png = tmp_path / "logo.png"
    png.write_bytes(b"")
    assert is_binary(str(png))


def test_is_binary_of_missing_file_is_true(tmp_path):
    assert is_binary(str(tmp_path / "nope.txt"))


def test_looks_generated_does_not_eat_dot_github():
    # `/.git` as a substring would also match `.github`, which is where CI
    # secrets actually live.
    assert not looks_generated(".github/workflows/deploy.yml")
    assert not looks_generated("src/app.py")
    assert looks_generated(".git/config")
    assert looks_generated("bundle.min.js")
    assert looks_generated("app.js.map")
