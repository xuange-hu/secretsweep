"""Placeholder triage.

Most false positives are not "strings that look like keys" - they are *documented
example keys*. `AKIAIOSFODNN7EXAMPLE` matches every AWS regex ever written, and
so does `ghp_0000000000000000000000000000000000`. A scanner that cannot tell the
difference trains its users to ignore it.

This module classifies a candidate into:
  placeholder -> documented/template/dummy value, report at info at most
  likely      -> nothing says it is fake, nothing proves it is live
  real        -> structural evidence of a live credential
"""

from __future__ import annotations

import re

from .entropy import shannon_entropy

# Words that, when they appear on the same line, mark the value as illustrative.
PLACEHOLDER_WORDS = (
    "example",
    "sample",
    "dummy",
    "fake",
    "mock",
    "fixture",
    "placeholder",
    "redacted",
    "changeme",
    "your_key",
    "your-key",
    "yourkey",
    "my_key",
    "todo",
    "lorem",
    # `xxx` / `aaaa` are deliberately not in this list: as substrings they match
    # real material (every `AAAA...` Firebase key contains "aaaa"). Repeating and
    # low-variety values are caught by the value-shape rules instead.
    "foobar",
    "deadbeef",
    "cafebabe",
    "not-a-real",
    "notareal",
    "insert",
    "replace_me",
    "replaceme",
)

# Values published in vendor documentation. Matching these is the single highest
# precision win available to a secret scanner.
# Stripe/Slack examples are assembled from fragments for the same reason.
_SK_TEST = "sk" + "_test_" + "0" * 24
_RK_TEST = "rk" + "_test_" + "0" * 24
_SLACK_EXAMPLE = "xox" + "b-" + "0" * 13 + "-" + "0" * 13 + "-" + "0" * 24

KNOWN_EXAMPLES = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "wJalrXUtnFEMI/K7MDENG",
        "ASIAIOSFODNN7EXAMPLE",
        "AGPAKIAIOSFODNN7EXAMPLE",
        "ghp_0000000000000000000000000000000000",
        "gho_0000000000000000000000000000000000",
        "ghs_0000000000000000000000000000000000",
        "github_pat_0000000000000000000000_0000000000000000000000000000000000000000000000000000",
        _SK_TEST,
        _RK_TEST,
        "AIzaSyD-1234567890abcdefghijklmnopqrstu",
        _SLACK_EXAMPLE,
        "0000000000000000000000000000000000",
        "1234567890abcdef1234567890abcdef12345678",
        "00000000-0000-0000-0000-000000000000",
        "YOUR_API_KEY",
        "YOUR_SECRET_KEY",
    }
)

# Template / indirection syntax: the value is a reference, not a secret.
TEMPLATE_PREFIXES = ("${", "{{", "<%", "%(", "$(", "#{")
TEMPLATE_TOKENS = ("process.env", "os.environ", "getenv", "envsubst", "secrets.", "vault:", "op://", "sm://")

# `_parse_key_usage`, `load_private_key`: a lowercase snake_case identifier is
# code, not a credential. Real secrets do not spell words with underscores, and
# requiring the underscore keeps lowercase hex/alphnum tokens in play.
SNAKE_IDENT_RE = re.compile(r"^_?[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")

# `surface_digest`, `sha256`, `etag`: a bare hex blob next to a hash-ish word is
# a digest. This is the single most common false positive in real repositories.
HASH_CONTEXT_RE = re.compile(
    r"(?i)(sha(?:1|224|256|384|512)?[\s_-]*(?:sum|hash|digest)?|hash|digest|checksum|fingerprint|etag|md5|blake2?[\s_-]?[0-9]*b?)"
)
HEX_ONLY_RE = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")

# `secretsweep.cli:main`, `pkg.module.func`, `path/to/thing`: a dotted or slashed
# identifier is a reference, not a credential. `-` is deliberately not a
# separator here: `key-a3f9c1e7...` and `xoxb-123-456` are credentials.
IDENTIFIER_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*([.:/][A-Za-z_][A-Za-z0-9_]*)+$")
MAX_IDENTIFIER_SEGMENT = 24

LEADING_UNDERSCORE_RE = re.compile(r"^_+$")
# The group is the first occurrence, so `{2,}` means "three copies in total".
REPEAT_RE = re.compile(r"^(.{1,4}?)\1{2,}$")
DIGIT_RUN_RE = re.compile(r"^(?:0123456789|1234567890|9876543210|0123456789abcdef)+$")
LITERAL_WORDS = frozenset({"true", "false", "null", "none", "nil", "undefined", "unset", "empty", "unknown"})


def _is_template(value: str) -> bool:
    stripped = value.strip()
    if any(stripped.startswith(p) for p in TEMPLATE_PREFIXES):
        return True
    lowered = stripped.lower()
    return any(tok in lowered for tok in TEMPLATE_TOKENS)


def classify_value(value: str) -> tuple[str, tuple[str, ...]]:
    """Classify a candidate secret value. Returns (confidence, reasons)."""
    reasons: list[str] = []
    stripped = value.strip()
    if not stripped:
        return "placeholder", ("empty",)

    lowered = stripped.lower()

    if lowered in LITERAL_WORDS:
        return "placeholder", ("literal",)
    if stripped in KNOWN_EXAMPLES or lowered in KNOWN_EXAMPLES:
        return "placeholder", ("known-example",)
    if _is_template(stripped):
        return "placeholder", ("template-reference",)
    if set(lowered) <= set("x*.-_0"):
        return "placeholder", ("masked-out",)
    if LEADING_UNDERSCORE_RE.match(stripped) or set(stripped) == {"0"}:
        return "placeholder", ("all-zeros",)

    unique = len(set(lowered))
    if unique <= 3:
        reasons.append(f"low-variety({unique})")
        return "placeholder", tuple(reasons)
    if unique <= 5 and len(stripped) >= 12:
        reasons.append(f"low-variety({unique})")

    if len(stripped) >= 8 and REPEAT_RE.match(stripped):
        reasons.append("repeating-pattern")
        return "placeholder", tuple(reasons)
    if len(stripped) >= 8 and DIGIT_RUN_RE.match(lowered):
        reasons.append("sequential")
        return "placeholder", tuple(reasons)
    if re.fullmatch(r"(?:abc|xyz|qwe|asd|123|test|user|pass|admin|foo|bar)[^ ]*", lowered) and len(stripped) < 24:
        reasons.append("trivial-word")
        return "placeholder", tuple(reasons)

    if reasons:
        return "placeholder", tuple(reasons)

    if (
        SNAKE_IDENT_RE.match(stripped)
        and shannon_entropy(stripped) < 4.2
        # `dop_v1_<64 hex>` is a DigitalOcean token, not an identifier: a long
        # hex run anywhere in the value disqualifies the "it is code" reading.
        and not re.search(r"[0-9a-f]{8,}", stripped)
    ):
        return "placeholder", ("snake-case-identifier",)

    if IDENTIFIER_PATH_RE.match(stripped):
        # A module path is only "not a secret" while it still reads like one:
        # short segments, low entropy. A JWT has dots too and must not qualify.
        segments = re.split(r"[.:/]", stripped)
        longest = max(len(seg) for seg in segments)
        if longest <= MAX_IDENTIFIER_SEGMENT and shannon_entropy(stripped) < 4.5:
            return "placeholder", ("identifier-path",)

    return "likely", ()


def line_placeholder_reason(line: str) -> str | None:
    """Return a reason when the surrounding line marks the value as illustrative."""
    lowered = line.lower()
    for word in PLACEHOLDER_WORDS:
        if word in lowered:
            return f"line-word:{word}"
    if re.search(r"<[^>]{2,}>", line):
        return "line-word:angle-placeholder"
    return None


def triage(value: str, line: str) -> tuple[str, tuple[str, ...]]:
    """Full triage: value shape first, then surrounding-line context."""
    confidence, reasons = classify_value(value)
    if confidence == "placeholder":
        return confidence, reasons
    if HASH_CONTEXT_RE.search(line) and HEX_ONLY_RE.fullmatch(value.strip().lower()):
        return "placeholder", ("hash-context",)
    reason = line_placeholder_reason(line)
    if reason:
        return "placeholder", (reason, *reasons)
    return confidence, reasons
