"""Git history scanning.

Deleting a secret from the working tree does not remove it from the object
database. `secretsweep scan --history` walks `git log -p` and reports leaks that
still exist in history.

No git bindings: `git` is invoked as a subprocess and everything degrades
gracefully (empty result) when it is missing or the path is not a repository.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import replace

from .model import Finding, sort_findings
from .scanner import Options, ScanResult, scan_text

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def git_available() -> bool:
    return shutil.which("git") is not None


def is_repo(root: str) -> bool:
    if not git_available():
        return False
    try:
        proc = subprocess.run(
            ["git", "-C", root, "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def _run_log(root: str, max_commits: int | None) -> str:
    cmd = ["git", "-C", root, "log", "-p", "--no-color", "--no-textconv", "-U0", "--all"]
    if max_commits:
        cmd.append(f"--max-count={max_commits}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout


def scan_history(root: str, options: Options | None = None, max_commits: int | None = 500) -> ScanResult:
    """Scan every line ever added in git history under `root`."""
    opts = options or Options()
    result = ScanResult(root=root)
    if not is_repo(root):
        result.errors.append("not a git repository (or git unavailable)")
        return result

    log = _run_log(root, max_commits)
    if not log:
        return result

    sha = ""
    path = ""
    new_line = 0
    seen: set[tuple[str, str, str]] = set()
    commits_seen = 0

    for raw in log.splitlines():
        if raw.startswith("commit "):
            sha = raw.split(None, 1)[1].strip()[:8]
            commits_seen += 1
            continue
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            path = "" if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            continue
        if raw.startswith("--- "):
            continue
        match = HUNK_RE.match(raw)
        if match:
            new_line = int(match.group(1))
            continue
        if not path:
            continue
        if raw.startswith("+"):
            content = raw[1:]
            for finding in scan_text(content, path=path, options=opts):
                key = (path, finding.rule, finding.fingerprint)
                if key in seen:
                    continue
                seen.add(key)
                result.findings.append(
                    replace(
                        finding,
                        line=new_line,
                        reasons=(*finding.reasons, f"commit:{sha}", "history"),
                    )
                )
            new_line += 1
        elif raw.startswith("-") or raw.startswith("diff ") or raw.startswith("index ") or raw.startswith("new file"):
            continue
        else:
            new_line += 1

    result.files_scanned = commits_seen
    result.findings = sort_findings(result.findings)
    return result


def history_findings(root: str, options: Options | None = None) -> list[Finding]:
    return scan_history(root, options=options).findings


def repo_root(path: str) -> str | None:
    if not git_available():
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", path, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def relpath(path: str, root: str) -> str:
    """Return `path` relative to `root`, always with forward slashes.

    Separators are normalized *before* the relative computation, not after.
    git always emits posix paths, and a scanner that reports `b/c.py` on Linux
    but `../a/b/c.py` on Windows for the same input is not reporting the same
    scan - the finding path is what baselines and diffs are keyed on.
    """
    posix_path = path.replace("\\", "/")
    posix_root = root.replace("\\", "/")
    try:
        return os.path.relpath(posix_path, posix_root).replace("\\", "/")
    except ValueError:  # pragma: no cover - different drives on Windows
        return posix_path
