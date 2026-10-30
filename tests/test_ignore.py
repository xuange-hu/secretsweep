from secretsweep.ignore import IGNORE_FILE, load, match, normalize, parse


def test_parse_skips_comments_and_blanks():
    assert parse("# comment\n\napp.py\n  spaced.py  \n") == ("app.py", "spaced.py")


def test_load_returns_empty_when_absent(tmp_path):
    assert load(str(tmp_path)) == ()


def test_load_reads_the_file(tmp_path):
    (tmp_path / IGNORE_FILE).write_text("secrets.env\n", encoding="utf-8")
    assert load(str(tmp_path)) == ("secrets.env",)


def test_normalize_strips_leading_cur_dir():
    assert normalize("./src/app.py") == "src/app.py"
    assert normalize("src\\app.py") == "src/app.py"


def test_match_by_basename():
    assert match("a/b/token.json", ("token.json",)) == "token.json"
    assert match("a/b/other.json", ("token.json",)) is None


def test_match_by_extension_glob():
    assert match("a/b/secrets.env", ("*.env",)) == "*.env"
    assert match("a/b/app.py", ("*.env",)) is None


def test_match_by_path_glob():
    assert match("tests/fixtures/tokens.json", ("tests/**",)) == "tests/**"
    assert match("src/tests/tokens.json", ("tests/**",)) is None


def test_match_directory_pattern():
    # gitignore semantics: a bare `docs/` matches at any depth
    assert match("docs/generated/x.py", ("docs/",)) == "docs/"
    assert match("src/docs/x.py", ("docs/",)) == "docs/"
    assert match("src/document.txt", ("docs/",)) is None


def test_match_is_relative_to_root():
    patterns = ("src/app.py",)
    assert match("repo/src/app.py", patterns, root="repo") == "src/app.py"
    assert match("other/src/app.py", patterns, root="repo") is None


def test_normalize_handles_absolute_paths(tmp_path):
    path = tmp_path / "app.py"
    assert normalize(str(path), str(tmp_path)) == "app.py"
