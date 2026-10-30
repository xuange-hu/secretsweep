"""Path context.

The same string means different things in `docs/example.env` and in
`.github/workflows/deploy.yml`. Instead of pretending otherwise, every finding
carries the bucket it was found in and the severity is adjusted from there.
"""

from __future__ import annotations

import os
import re

TEST_DIR_RE = re.compile(r"(^|[\\/])(tests?|__tests__|spec|fixtures?|testdata)([\\/]|$)")
TEST_FILE_RE = re.compile(r"(^|[\\/])(test_[^\\/]*|[^\\/]*_test|[^\\/]*\.test|[^\\/]*\.spec)\.[a-z0-9]+$")
EXAMPLE_RE = re.compile(r"(\.example|\.sample|\.template|\.dist|\.default)$|^example|^sample", re.IGNORECASE)
DOC_RE = re.compile(r"\.(md|rst|txt|adoc|pdf)$|(^|[\\/])(docs?|examples?|samples?)([\\/]|$)", re.IGNORECASE)
VENDOR_DIR_RE = re.compile(
    r"(^|[\\/])(node_modules|vendor|third_party|site-packages|dist|build|\.venv|venv|\.tox|\.mypy_cache"
    r"|\.ruff_cache|\.pytest_cache|__pycache__|target)([\\/]|$)"
)
CI_PATH_RE = re.compile(
    r"(^|[\\/])(\.github|workflows|\.gitlab-ci\.yml|Jenkinsfile|\.circleci|\.buildkite|azure-pipelines\.yml"
    r"|\.drone\.yml|bitbucket-pipelines\.yml)$|(^|[\\/])\.github[\\/]workflows[\\/]"
)
LOCKFILE_RE = re.compile(r"(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|go\.sum|composer\.lock)$")

BINARY_EXT = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svgz", ".pdf", ".zip", ".gz", ".tgz",
        ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".class", ".so", ".dll", ".dylib", ".exe", ".bin",
        ".pyc", ".pyo", ".wasm", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".mov", ".avi",
        ".sqlite", ".db", ".parquet", ".pickle", ".npy", ".npz", ".pyd", ".egg", ".whl",
    }
)

BUCKETS = ("source", "config", "ci", "test", "example", "docs", "vendor", "lockfile")

# How far a finding drops when it lives in a bucket where secrets are illustrative.
DOWNGRADE_BY_BUCKET = {
    "test": 2,
    "example": 2,
    "docs": 1,
    "vendor": 3,
    "source": 0,
    "config": 0,
    "ci": 0,
    "lockfile": 1,
}


def classify_path(path: str) -> str:
    """Bucket a path. Order matters: tests before docs, CI before config."""
    norm = path.replace("\\", "/")
    base = os.path.basename(norm)
    if VENDOR_DIR_RE.search(norm):
        return "vendor"
    if TEST_DIR_RE.search(norm) or TEST_FILE_RE.search(norm):
        return "test"
    if EXAMPLE_RE.search(base):
        return "example"
    if CI_PATH_RE.search(norm):
        return "ci"
    if LOCKFILE_RE.search(base):
        return "lockfile"
    if DOC_RE.search(norm):
        return "docs"
    if base.startswith(".env") or base.endswith((".ini", ".cfg", ".conf", ".properties", ".yaml", ".yml", ".toml", ".json")):
        return "config"
    return "source"


def is_binary(path: str) -> bool:
    _, ext = os.path.splitext(path.lower())
    if ext in BINARY_EXT:
        return True
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(4096)
    except OSError:
        return True
    return b"\x00" in chunk


def looks_generated(path: str) -> bool:
    """Skip minified/generated files.

    Path *segments* are compared, not substrings: `/.git` as a substring would
    also match `.github`, which is where CI secrets actually live.
    """
    norm = path.replace("\\", "/")
    segments = norm.split("/")
    if ".git" in segments:
        return True
    return norm.endswith(".min.js") or norm.endswith(".map")
