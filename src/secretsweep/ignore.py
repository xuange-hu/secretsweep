"""`.secretsweepignore` support.

Every scanner needs a way to say "this file is a test fixture, stop telling me
about it". Globs follow .gitignore conventions closely enough: `*` and `?`,
a trailing `/` matches a directory, a leading `/` anchors to the scan root, and
`#` starts a comment.
"""

from __future__ import annotations

import contextlib
import fnmatch
import os

IGNORE_FILE = ".secretsweepignore"

DEFAULT_PATTERNS = (
    ".secretsweepignore",
    ".git/**",
    "*.lock",
)


def parse(text: str) -> tuple[str, ...]:
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return tuple(out)


def load(root: str) -> tuple[str, ...]:
    path = os.path.join(root, IGNORE_FILE)
    if not os.path.isfile(path):
        return ()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return parse(fh.read())
    except OSError:
        return ()


def normalize(path: str, root: str = "") -> str:
    norm = path.replace("\\", "/")
    if root:
        with contextlib.suppress(ValueError):  # different drives on Windows
            norm = os.path.relpath(path, root).replace("\\", "/")
    return norm.lstrip("./")


def match(path: str, patterns: tuple[str, ...], root: str = "") -> str | None:
    """Return the pattern that excludes `path`, or None."""
    rel = normalize(path, root)
    base = os.path.basename(rel)
    for pattern in patterns:
        candidate = pattern.lstrip("/")
        if candidate.endswith("/"):
            # Directory pattern: matches the directory and everything under it.
            if rel == candidate.rstrip("/") or rel.startswith(candidate) or f"/{candidate}" in f"/{rel}":
                return pattern
            continue
        if "/" in candidate:
            if fnmatch.fnmatch(rel, candidate):
                return pattern
            continue
        if fnmatch.fnmatch(base, candidate) or fnmatch.fnmatch(rel, candidate):
            return pattern
    return None


def is_ignored(path: str, patterns: tuple[str, ...], root: str = "") -> bool:
    return match(path, patterns, root) is not None
