"""Dogfooding: secretsweep must be clean on its own source.

If the tool cannot pass its own gate, nobody should wire it into theirs.
"""

from pathlib import Path

from secretsweep.scanner import Options, scan_path

ROOT = Path(__file__).resolve().parent.parent


def test_self_scan_is_clean():
    result = scan_path(str(ROOT))
    assert result.findings == [], [f.to_dict() for f in result.findings[:5]]


def test_self_scan_actually_scans_files():
    result = scan_path(str(ROOT))
    assert result.files_scanned >= 10


def test_self_scan_includes_placeholders_and_stays_clean():
    """Even with placeholders shown, nothing here should rank above info."""
    result = scan_path(str(ROOT), options=Options(include_placeholders=True))
    assert all(f.severity == "info" for f in result.findings), [f.to_dict() for f in result.findings[:5]]


def test_ignore_file_is_present_and_parses():
    text = (ROOT / ".secretsweepignore").read_text(encoding="utf-8")
    assert "samples.py" in text
