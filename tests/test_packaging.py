"""Packaging contract tests.

CI installs `.[all]` so it can never catch the failure these tests exist for:
a console script whose module imports a package that is only in an extra.
"""

import re
from pathlib import Path

import pytest

try:  # 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 has no tomllib
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
SRC = ROOT / "src"

NEEDS_TOML = pytest.mark.skipif(tomllib is None, reason="tomllib requires Python 3.11+")


def _load_pyproject():
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


@NEEDS_TOML
def test_pyproject_declares_the_console_scripts():
    scripts = _load_pyproject()["project"]["scripts"]
    assert scripts["secretsweep"] == "secretsweep.cli:main"
    assert scripts["secretsweep-mcp"] == "secretsweep.mcp_server:main"


@NEEDS_TOML
def test_package_has_zero_runtime_dependencies():
    assert _load_pyproject()["project"]["dependencies"] == []


@NEEDS_TOML
def test_mcp_is_an_optional_extra():
    extras = _load_pyproject()["project"]["optional-dependencies"]
    assert "mcp" in extras
    assert any(dep.startswith("mcp>=") for dep in extras["mcp"])


@NEEDS_TOML
def test_mcp_pin_excludes_2x():
    """mcp 2.x renames FastMCP; importing it the 1.x way breaks."""
    spec = next(d for d in _load_pyproject()["project"]["optional-dependencies"]["mcp"] if d.startswith("mcp"))
    assert "<2" in spec


def test_cli_module_imports_only_stdlib_and_own_packages():
    text = (SRC / "secretsweep" / "cli.py").read_text(encoding="utf-8")
    external = [
        name
        for name in re.findall(r"^(?:from|import)\s+([A-Za-z_][\w.]*)", text, re.M)
        if not name.startswith(("secretsweep", "__"))
    ]
    allowed = {
        "argparse",
        "json",
        "os",
        "sys",
        "from",
        "import",
    }
    unexpected = [n for n in external if n.split(".")[0] not in allowed]
    assert unexpected == [], unexpected


@NEEDS_TOML
def test_version_agrees_with_pyproject():
    import secretsweep

    assert secretsweep.__version__ == _load_pyproject()["project"]["version"]


def test_package_directory_contains_the_modules_we_ship():
    names = {p.stem for p in (SRC / "secretsweep").glob("*.py")}
    for expected in ("cli", "scanner", "patterns", "baseline", "sarif", "mcp_server", "demo", "history", "ignore"):
        assert expected in names


def test_readme_exists_and_mentions_the_install_command():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "secretsweep" in readme
    assert "pip install" in readme or "uvx" in readme
