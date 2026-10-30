"""A throwaway repository that leaks on purpose.

`secretsweep demo` writes it and scans it, so the first thing a visitor sees is
the tool doing its job instead of a wall of options.
"""

from __future__ import annotations

import os
import tempfile

from . import samples
from .scanner import Options, ScanResult, scan_path

# assembled so the demo tree never ships a live-looking literal
STRIPE_TEST = "sk" + "_test_" + "0" * 24

S = samples.RULE_SAMPLES

FILES: dict[str, str] = {
    "README.md": (
        "# demo\n\n"
        "A synthetic repository with planted credentials. Nothing here is real.\n"
        "Run `secretsweep scan .` to see what it finds.\n"
    ),
    "src/config.py": (
        "# application configuration (planted leaks)\n"
        f"{S['aws-access-key-id']}\n"
        f"{S['stripe-live-key']}\n"
        f"{S['github-pat']}\n"
        f"{S['postgres-uri']}\n"
        f"{S['generic-secret-assignment']}\n"
    ),
    ".env": (
        "# environment file: secrets belong in a secret manager, not here\n"
        f"{S['env-file-secret']}\n"
        f"{S['sendgrid-api-key']}\n"
        f"{S['db-password-assignment']}\n"
    ),
    ".github/workflows/deploy.yml": (
        "name: deploy\n"
        "on: [push]\n"
        "jobs:\n"
        "  ship:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo deploy\n"
        "        env:\n"
        f"          {S['npm-token']}\n"
        f"          {S['gitlab-pat']}\n"
    ),
    "docs/example.env": (
        "# copy this file to .env and fill it in - everything here is a documented example\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        f"STRIPE_SECRET_KEY={STRIPE_TEST}\n"
        "GITHUB_TOKEN=ghp_0000000000000000000000000000000000\n"
    ),
    "tests/fixtures/tokens.json": (
        "{\n"
        f'  "token": "{samples.S36}",\n'
        '  "comment": "test fixture, downgraded because of where it lives"\n'
        "}\n"
    ),
    "src/ok.py": (
        "# this file is clean and shows the inline ignore directive\n"
        "PUBLIC_URL = 'https://api.internal.corp/v1/status'\n"
        f"{S['generic-api-key-assignment']}  # secretsweep:ignore\n"
    ),
}


def write_tree(root: str) -> list[str]:
    """Write the demo tree. Returns the written paths."""
    written: list[str] = []
    for rel, content in FILES.items():
        target = os.path.join(root, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        written.append(target)
    return written


def default_root() -> str:
    return os.path.join(tempfile.gettempdir(), "secretsweep-demo")


def run(root: str | None = None, options: Options | None = None) -> ScanResult:
    target = root or default_root()
    os.makedirs(target, exist_ok=True)
    write_tree(target)
    result = scan_path(target, options=options)
    result.root = target
    return result


def reset(root: str | None = None) -> str:
    target = root or default_root()
    write_tree(target)
    return target
