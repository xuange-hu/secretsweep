import os

from secretsweep import demo as demo_mod
from secretsweep.scanner import Options


def test_demo_tree_is_written(tmp_path):
    paths = demo_mod.write_tree(str(tmp_path))
    assert len(paths) == len(demo_mod.FILES)
    for path in paths:
        assert os.path.isfile(path)


def test_demo_run_finds_the_planted_leaks(tmp_path):
    result = demo_mod.run(str(tmp_path))
    assert result.files_scanned >= 6
    rules = {f.rule for f in result.findings}
    assert "aws-access-key-id" in rules
    assert "github-pat" in rules
    assert "stripe-live-key" in rules
    assert "postgres-uri" in rules


def test_demo_shows_every_confidence_tier(tmp_path):
    result = demo_mod.run(str(tmp_path), options=Options(include_placeholders=True))
    confidences = {f.confidence for f in result.findings}
    assert "placeholder" in confidences
    assert "likely" in confidences


def test_demo_bucket_downgrade_is_visible(tmp_path):
    result = demo_mod.run(str(tmp_path))
    fixture = [f for f in result.findings if f.bucket == "test"]
    assert fixture
    assert fixture[0].severity in ("low", "info")


def test_demo_inline_ignore_is_respected(tmp_path):
    result = demo_mod.run(str(tmp_path))
    assert not [f for f in result.findings if f.path.endswith("ok.py")]


def test_demo_reset_rewrites_files(tmp_path):
    demo_mod.reset(str(tmp_path))
    target = tmp_path / "src" / "config.py"
    target.write_text("clean = True\n", encoding="utf-8")
    demo_mod.reset(str(tmp_path))
    assert "AKIA" in target.read_text(encoding="utf-8")


def test_demo_default_root_is_outside_the_repo():
    assert "secretsweep-demo" in demo_mod.default_root()


def test_demo_files_are_deterministic():
    assert demo_mod.FILES == demo_mod.FILES
    assert all(isinstance(v, str) for v in demo_mod.FILES.values())
