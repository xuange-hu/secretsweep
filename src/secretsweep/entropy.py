"""Shannon entropy and charset classification.

Entropy is what catches credentials no regex knows about: a 40-char base64 blob
assigned to `token =` has no provider prefix, but it is not a word either.
"""

from __future__ import annotations

import math
import re

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
B62_RE = re.compile(r"^[A-Za-z0-9]+$")
DIGITS_RE = re.compile(r"^[0-9]+$")

# Delimiters used to split a line into candidate tokens. Any of these ends a
# value: keep it in sync with what real config strings look like.
TOKEN_SPLIT_RE = re.compile(r"[\s\"'`;,(){}\[\]<>|&\\\x00]+")

# Character sets considered "high signal" for random-looking material.
CHARSET_THRESHOLDS = {
    "hex": 3.0,  # 16 symbols -> max 4.0 bits
    "base64": 3.5,  # 64 symbols -> max 6.0 bits
    "base62": 3.8,
    "digits": 2.0,
    "mixed": 3.5,
}


def shannon_entropy(value: str) -> float:
    """Bits per character. Empty or single-symbol strings score 0.0."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    ent = 0.0
    for n in counts.values():
        p = n / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def charset_of(value: str) -> str:
    if not value:
        return "empty"
    if DIGITS_RE.match(value):
        return "digits"
    if HEX_RE.match(value):
        return "hex"
    if B62_RE.match(value):
        return "base62"
    if B64_RE.match(value):
        return "base64"
    return "mixed"


def is_random_looking(value: str, entropy_min: float | None = None) -> bool:
    """True when the value's entropy is high for the charset it is drawn from."""
    if len(value) < 12:
        return False
    cs = charset_of(value)
    if cs == "empty":
        return False
    threshold = CHARSET_THRESHOLDS.get(cs, CHARSET_THRESHOLDS["mixed"])
    if entropy_min is not None:
        threshold = max(threshold, entropy_min)
    return shannon_entropy(value) >= threshold


TOKEN_RE = re.compile(r"[^\s\"'`;,(){}\[\]<>|&\\\x00]+")


def iter_tokens(line: str):
    """Yield (token, start_offset) for every delimiter-separated token in a line.

    Offsets come from match positions, not from adding up chunk lengths: a
    multi-character separator (` = `) would drift the reported column.
    """
    for match in TOKEN_RE.finditer(line):
        yield match.group(0), match.start()


def high_entropy_tokens(
    line: str,
    min_length: int = 20,
    entropy_min: float | None = None,
):
    """Yield (token, start_offset, entropy) for random-looking tokens.

    Tokens shorter than `min_length` are ignored: `password = "hunter2"` is a bad
    password but it is not what a scanner should page a human for.
    """
    for token, start in iter_tokens(line):
        if len(token) < min_length:
            continue
        # Strip surrounding punctuation that survived the split.
        core = token.strip(".,:;!?")
        offset = start + (len(token) - len(core.lstrip(".,:;!?")))
        if len(core) < min_length:
            continue
        ent = shannon_entropy(core)
        if is_random_looking(core, entropy_min=entropy_min):
            yield core, offset, ent
