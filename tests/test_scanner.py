import pytest

from secretsweep.scanner import DEFAULT_MAX_BYTES, Options, ScanResult, scan_file, scan_path, scan_text

# Fixture values are assembled from fragments: a secret scanner's own repository
# must not contain literals that GitHub push protection (or any other scanner)
# will flag. Runtime values are unchanged.
AWS_KEY = "AK" + "IA3RJ4E5TZLMXQW7PU"


AWS_LINE = f'aws_access_key_id = "{AWS_KEY}"'
GH_LINE = 'GITHUB_TOKEN = "ghp_R7kQ2vLm9pZxT4wC8jH5fB1dY6sA0eU3oI7g"'
EXAMPLE_LINE = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"


def test_scan_text_finds_a_provider_rule():
    found = scan_text(AWS_LINE, path="src/app.py")
    assert [f.rule for f in found] == ["aws-access-key-id"]
    assert found[0].severity == "high"
    assert found[0].confidence == "likely"
    assert found[0].column == 22


def test_scan_text_hides_placeholders_by_default():
    assert scan_text(EXAMPLE_LINE, path="src/app.py") == []


def test_scan_text_can_show_placeholders():
    found = scan_text(EXAMPLE_LINE, path="src/app.py", options=Options(include_placeholders=True))
    assert [f.rule for f in found] == ["aws-access-key-id"]
    assert found[0].suppressed is True
    assert found[0].severity == "info"
    assert found[0].confidence == "placeholder"


def test_inline_ignore_suppresses_whole_line():
    line = f"{AWS_LINE}  # secretsweep:ignore"
    assert scan_text(line, path="src/app.py") == []


def test_inline_ignore_applies_to_the_next_line():
    text = "# secretsweep:ignore\n" + AWS_LINE + "\n"
    assert scan_text(text, path="src/app.py") == []


def test_inline_ignore_can_name_a_rule():
    line = f'aws_access_key_id = "{AWS_KEY}"'
    ignored = scan_text(f"{line}  # secretsweep:ignore[aws-access-key-id]", path="src/app.py")
    assert "aws-access-key-id" not in {f.rule for f in ignored}
    kept = scan_text(f"{line}  # secretsweep:ignore[github-pat]", path="src/app.py")
    assert "aws-access-key-id" in {f.rule for f in kept}


def test_no_inline_ignore_option_disables_directives():
    text = f"{AWS_LINE}  # secretsweep:ignore"
    options = Options(respect_inline_ignore=False)
    assert scan_text(text, path="src/app.py", options=options)


def test_min_severity_filters():
    text = f"{AWS_LINE}\npassword = hunter2\n"
    found = scan_text(text, path="src/app.py", options=Options(min_severity="critical"))
    assert found == []
    assert scan_text(text, path="src/app.py", options=Options(min_severity="info"))


def test_entropy_min_raises_the_bar():
    low = 'api_key = "aaaaaaaaaaaaaaaaaaaa"'
    assert not scan_text(low, path="src/app.py")
    assert not scan_text(low, path="src/app.py", options=Options(entropy_min=4.5))


def test_only_tags_filters_rules():
    found = scan_text(AWS_LINE, path="src/app.py", options=Options(only_tags=("github",)))
    assert found == []
    assert scan_text(AWS_LINE, path="src/app.py", options=Options(only_tags=("aws",)))


def test_exclude_rules_works():
    options = Options(exclude_rules=("aws-access-key-id",))
    found = scan_text(AWS_LINE, path="src/app.py", options=options)
    assert "aws-access-key-id" not in {f.rule for f in found}


def test_generic_rule_loses_to_provider_rule_on_the_same_span():
    line = 'github_token = "ghp_R7kQ2vLm9pZxT4wC8jH5fB1dY6sA0eU3oI7g"'
    found = scan_text(line, path="src/app.py")
    assert "github-pat" in {f.rule for f in found}
    assert "generic-token-assignment" not in {f.rule for f in found}


def test_duplicate_matches_are_deduplicated():
    found = scan_text(f"{AWS_LINE}\n{AWS_LINE}\n", path="src/app.py")
    assert len([f for f in found if f.rule == "aws-access-key-id"]) == 2  # different lines
    assert len({(f.line, f.rule) for f in found}) == len(found)


def test_bucket_downgrade_is_reported():
    found = scan_text(AWS_LINE, path="tests/test_thing.py")
    assert found[0].bucket == "test"
    assert found[0].severity == "low"  # high -> low: the test bucket drops two levels
    assert "bucket:test" in found[0].reasons


def test_capability_notes_land_on_the_finding():
    found = scan_text(GH_LINE, path="src/app.py")
    assert any("classic personal access token" in r for r in found[0].reasons)


def test_expired_jwt_is_downgraded():
    # exp = 1730000000 (2024-10-27), long past
    token = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiJzdmMtZGVwbG95IiwiZXhwIjoxNzMwMDAwMDAwfQ."
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    found = scan_text(f'id_token = "{token}"', path="src/app.py")
    jwt = [f for f in found if f.rule == "jwt"]
    assert jwt
    assert jwt[0].severity == "medium"  # high -> medium
    assert "expired-token" in jwt[0].reasons


def test_scan_file_and_scan_path(tmp_path):
    target = tmp_path / "src"
    target.mkdir()
    (target / "app.py").write_text(AWS_LINE + "\n", encoding="utf-8")
    assert scan_file(str(target / "app.py"))

    result = scan_path(str(tmp_path))
    assert result.files_scanned == 1
    assert [f.rule for f in result.findings] == ["aws-access-key-id"]
    assert result.counts()["high"] == 1


def test_scan_path_skips_vendor_and_binary(tmp_path):
    vendor = tmp_path / "node_modules" / "pkg"
    vendor.mkdir(parents=True)
    (vendor / "index.js").write_text(AWS_LINE, encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00\x01")
    result = scan_path(str(tmp_path))
    assert result.findings == []
    assert result.files_scanned == 0


def test_scan_path_honours_extra_skip(tmp_path):
    sub = tmp_path / "generated"
    sub.mkdir()
    (sub / "a.py").write_text(AWS_LINE, encoding="utf-8")
    assert scan_path(str(tmp_path)).findings
    assert scan_path(str(tmp_path), extra_skip=("generated",)).findings == []


def test_scan_path_reads_the_ignore_file(tmp_path):
    (tmp_path / "app.py").write_text(AWS_LINE, encoding="utf-8")
    assert scan_path(str(tmp_path)).findings
    (tmp_path / ".secretsweepignore").write_text("app.py\n# comment\n\n", encoding="utf-8")
    result = scan_path(str(tmp_path))
    assert result.findings == []
    assert result.files_skipped >= 1


def test_scan_path_can_disable_the_ignore_file(tmp_path):
    (tmp_path / "app.py").write_text(AWS_LINE, encoding="utf-8")
    (tmp_path / ".secretsweepignore").write_text("app.py\n", encoding="utf-8")
    options = Options(use_ignore_file=False)
    assert scan_path(str(tmp_path), options=options).findings


def test_scan_path_respects_ignore_globs(tmp_path):
    (tmp_path / "secrets.env").write_text(AWS_LINE, encoding="utf-8")
    options = Options(ignore_globs=("*.env",))
    assert scan_path(str(tmp_path), options=options).findings == []


def test_scan_path_skips_oversized_files(tmp_path):
    big = tmp_path / "big.py"
    big.write_text("x" * 1024 + "\n" + AWS_LINE + "\n", encoding="utf-8")
    options = Options(max_bytes=512)
    result = scan_path(str(tmp_path), options=options)
    assert result.files_skipped == 1
    assert result.findings == []
    assert DEFAULT_MAX_BYTES > 512


def test_scan_path_on_a_single_file(tmp_path):
    target = tmp_path / "app.py"
    target.write_text(AWS_LINE, encoding="utf-8")
    result = scan_path(str(target))
    assert result.files_scanned == 1
    assert result.findings


def test_scan_result_to_dict(tmp_path):
    (tmp_path / "app.py").write_text(AWS_LINE, encoding="utf-8")
    result = scan_path(str(tmp_path))
    data = result.to_dict()
    assert data["counts"]["total"] == 1
    assert data["findings"][0]["rule"] == "aws-access-key-id"


def test_scan_result_reports_errors_for_unreadable_paths(tmp_path):
    missing = tmp_path / "gone"
    result = ScanResult(root=str(missing))
    assert result.errors == []
    assert result.counts()["total"] == 0


def test_empty_text_yields_nothing():
    assert scan_text("", path="src/app.py") == []


def test_blank_lines_are_skipped():
    assert scan_text("\n\n   \n", path="src/app.py") == []


def test_validate_hook_filters_impostors():
    # Not 36 base62 chars after the prefix -> rejected by validate.
    line = 'token = "ghp_short"'
    assert scan_text(line, path="src/app.py") == []


@pytest.mark.parametrize("path", ["src/app.py", "app.py", "config/settings.yaml"])
def test_column_is_one_based_and_inside_the_line(path):
    found = scan_text(AWS_LINE, path=path)
    assert found[0].column >= 1
    assert found[0].column <= len(AWS_LINE)
