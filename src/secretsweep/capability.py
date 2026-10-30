"""Offline capability inference.

A finding that says "this is an AWS key" tells you what to rotate.
A finding that says "this is an *ASIA* key, i.e. a temporary STS session, and the
JWT next to it expired in 2021" tells you what to do first.

Everything here is derived from the shape of the value - no network calls.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import json

AWS_PREFIX_MEANING = {
    "AKIA": "long-lived IAM user key",
    "ASIA": "temporary STS session key (expires on its own)",
    "ABIA": "AWS STS service bearer token",
    "ACCA": "context-specific credential",
    "AGPA": "IAM group key (cannot sign requests)",
    "ANPA": "managed policy key (cannot sign requests)",
    "ANVA": "managed policy version key",
    "APKA": "IAM public key",
    "A3T": "AWS X.509/legacy credential",
}

GITHUB_PREFIX_MEANING = {
    "ghp": "classic personal access token (repo + org scopes possible)",
    "gho": "OAuth access token",
    "ghu": "OAuth user-to-server token",
    "ghs": "server-to-server (GitHub App installation) token",
    "ghr": "refresh token",
}

SLACK_PREFIX_MEANING = {
    "xoxb": "bot token - can post and read in installed channels",
    "xoxp": "user token - acts as the authorising user",
    "xoxa": "app-level token",
    "xoxr": "refresh token",
    "xoxs": "app-level session token",
}

STRIPE_PREFIX_MEANING = {
    "sk_live": "live secret key - can move real money",
    "rk_live": "restricted live key - scoped subset of the API",
    "sk_test": "test-mode secret key - no real charges",
    "rk_test": "test-mode restricted key",
}


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def jwt_facts(value: str) -> dict | None:
    """Decode a JWT without verifying it. Returns header/payload facts."""
    parts = value.split(".")
    if len(parts) != 3:
        return None
    facts: dict = {}
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    facts["alg"] = header.get("alg")
    facts["typ"] = header.get("typ")
    facts["kid"] = header.get("kid")
    for key in ("sub", "iss", "aud", "azp", "scope", "scopes"):
        if key in payload:
            facts[key] = payload[key]
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        try:
            when = _dt.datetime.fromtimestamp(float(exp), tz=_dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            when = None
        if when is not None:
            facts["exp"] = when.isoformat()
            facts["expired"] = when < _dt.datetime.now(tz=_dt.timezone.utc)
    return facts


def infer(rule_id: str, value: str) -> tuple[str, ...]:
    """Return human-readable capability notes for a matched value."""
    notes: list[str] = []

    if rule_id == "aws-access-key-id":
        prefix = value[:4]
        notes.append(AWS_PREFIX_MEANING.get(prefix, f"AWS credential (prefix {prefix})"))
        if prefix == "ASIA":
            notes.append("temporary: rotation may be unnecessary, but the issuing role matters")

    elif rule_id == "github-pat":
        if value.startswith("github_pat_"):
            notes.append("fine-grained token: scoped to specific repos and permissions")
        else:
            prefix = value[:3]
            notes.append(GITHUB_PREFIX_MEANING.get(prefix, "GitHub token"))
            if prefix == "ghp":
                notes.append("classic tokens cannot be scoped to a single repo - treat as full account access")

    elif rule_id == "slack-bot-token":
        prefix = value[:4]
        notes.append(SLACK_PREFIX_MEANING.get(prefix, "Slack token"))

    elif rule_id in ("stripe-live-key", "stripe-test-key"):
        prefix = "_".join(value.split("_")[:2])
        notes.append(STRIPE_PREFIX_MEANING.get(prefix, "Stripe key"))
        if prefix.endswith("live"):
            notes.append("live mode: charges are real")

    elif rule_id in ("jwt", "kubernetes-service-account-token"):
        facts = jwt_facts(value)
        if facts:
            if facts.get("alg") == "none":
                notes.append("alg=none: signature is not verified at all")
            elif facts.get("alg"):
                notes.append(f"alg={facts['alg']}")
            if facts.get("typ"):
                notes.append(f"typ={facts['typ']}")
            if facts.get("sub"):
                notes.append(f"sub={str(facts['sub'])[:48]}")
            if facts.get("scope"):
                notes.append(f"scope={str(facts['scope'])[:64]}")
            if facts.get("exp"):
                notes.append(f"exp={facts['exp']}" + (" (already expired)" if facts.get("expired") else " (still valid)"))
        if rule_id == "kubernetes-service-account-token":
            notes.append("bound to a ServiceAccount: grants API access inside the cluster")

    elif rule_id == "private-key-block":
        notes.append("offline-signing material: rotate the key pair, not just the file")

    elif rule_id == "gcp-api-key":
        notes.append("project-scoped API key, often unrestricted by referrer in practice")

    elif rule_id == "basic-auth-url":
        notes.append("credentials travel in the URL - also leaks via referrer and logs")

    return tuple(notes)
