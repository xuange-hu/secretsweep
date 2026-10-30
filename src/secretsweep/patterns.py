"""Provider rule library.

Rules are line-based; multi-line formats (PEM blocks) are handled by
`scanner.scan_text` separately. Every rule carries:
  - `entropy_min`: gate so `password: password` cannot trip a generic rule
  - `keywords`: optional words that must appear on the line (cheap precision)
  - `tags`: used by the report and by `--only-tag`
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

# ---------------------------------------------------------------- helpers


def _b62(lo: int, hi: int | None = None) -> str:
    return rf"[A-Za-z0-9]{{{lo}}}" if hi is None else rf"[A-Za-z0-9]{{{lo},{hi}}}"


def _b64(lo: int, hi: int | None = None) -> str:
    return rf"[A-Za-z0-9+/=_-]{{{lo}}}" if hi is None else rf"[A-Za-z0-9+/=_-]{{{lo},{hi}}}"


def _hex(lo: int, hi: int | None = None) -> str:
    return rf"[0-9a-fA-F]{{{lo}}}" if hi is None else rf"[0-9a-fA-F]{{{lo},{hi}}}"


def valid_github_pat(value: str) -> bool:
    """ghp_/gho_/ghu_/ghs_/ghr_ + 36 base62, or the new fine-grained form."""
    if value.startswith("github_pat_"):
        body = value[len("github_pat_") :]
        return len(body) >= 50 and all(ch.isalnum() or ch == "_" for ch in body)
    body = value[4:]
    return len(body) == 36 and re.fullmatch(r"[A-Za-z0-9]{36}", body) is not None


def valid_jwt(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    return all(len(p) >= 8 and re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts)


def valid_slack(value: str) -> bool:
    parts = value.split("-")
    return len(parts) >= 3 and all(p.isalnum() for p in parts)


# ---------------------------------------------------------------- rule model


@dataclass(frozen=True)
class Rule:
    rid: str
    name: str
    severity: str
    pattern: re.Pattern[str]
    # None means "take the first capture group": rules that read
    # `key = (value)` want the value, not the assignment around it.
    group: int | None = None
    entropy_min: float = 0.0
    keywords: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    note: str = ""
    priority: int = 0
    validate: Callable[[str], bool] | None = None

    @property
    def value_group(self) -> int:
        if self.group is not None:
            return self.group
        return 1 if self.pattern.groups >= 1 else 0

    def matches_line(self, line: str) -> bool:
        if not self.keywords:
            return True
        lowered = line.lower()
        return any(k in lowered for k in self.keywords)


def _rule(
    rid: str,
    name: str,
    severity: str,
    pattern: str,
    **kw,
) -> Rule:
    return Rule(rid=rid, name=name, severity=severity, pattern=re.compile(pattern), **kw)


# ---------------------------------------------------------------- rules

RULES: tuple[Rule, ...] = (
    # --- cloud: AWS
    _rule(
        "aws-access-key-id",
        "AWS access key id",
        "high",
        r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|ANPA|ANVA|APKA)[A-Z0-9]{12,20})\b",
        tags=("aws", "cloud"),
        note="ASIA/ASIA-prefixed ids are temporary session credentials.",
    ),
    _rule(
        "aws-secret-access-key",
        "AWS secret access key",
        "critical",
        r"(?i)aws(.{0,20})?(?:secret|private)(.{0,20})?['\"][ \t]*([A-Za-z0-9/+=]{40})['\"]",
        group=3,
        entropy_min=3.5,
        keywords=("aws",),
        tags=("aws", "cloud"),
    ),
    _rule(
        "aws-session-token",
        "AWS session token",
        "high",
        r"\b(FwoGZXIvYXdz[A-Za-z0-9+/=]{16,})\b",
        entropy_min=3.5,
        tags=("aws", "cloud"),
    ),
    # --- cloud: GCP
    _rule(
        "gcp-api-key",
        "Google API key",
        "high",
        r"\b(AIza[0-9A-Za-z_-]{35})\b",
        tags=("gcp", "cloud"),
    ),
    _rule(
        "gcp-service-account",
        "GCP service account private key id",
        "critical",
        r"\"private_key_id\"\s*:\s*\"(" + _b64(20, 40) + r")\"",
        keywords=("private_key_id",),
        tags=("gcp", "cloud"),
    ),
    _rule(
        "firebase-cloud-messaging",
        "Firebase Cloud Messaging server key",
        "high",
        r"\b(AAAA[A-Za-z0-9_-]{7,}:[A-Za-z0-9_-]{100,})\b",
        entropy_min=3.5,
        tags=("gcp", "firebase"),
    ),
    # --- cloud: Azure
    _rule(
        "azure-storage-key",
        "Azure storage account key",
        "critical",
        r"(?i)AccountKey=([A-Za-z0-9+/=]{40,88})",
        keywords=("accountkey",),
        entropy_min=3.0,
        tags=("azure", "cloud"),
    ),
    _rule(
        "azure-client-secret",
        "Azure AD client secret",
        "high",
        r"(?i)(?:client[_-]?secret|azure[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9._~_-]{32,44})['\"]?",
        entropy_min=3.4,
        keywords=("secret",),
        tags=("azure", "cloud"),
    ),
    # --- git hosting
    _rule(
        "github-pat",
        "GitHub personal access token",
        "critical",
        r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})\b",
        validate=valid_github_pat,
        tags=("github", "vcs"),
    ),
    _rule(
        "gitlab-pat",
        "GitLab personal access token",
        "critical",
        r"\b(glpat-[A-Za-z0-9_-]{20,})\b",
        tags=("gitlab", "vcs"),
    ),
    _rule(
        "gitlab-runner-token",
        "GitLab runner registration token",
        "high",
        r"\b(GR1348941[A-Za-z0-9_-]{20,})\b",
        tags=("gitlab", "vcs", "ci"),
    ),
    _rule(
        "bitbucket-app-password",
        "Bitbucket app password",
        "high",
        r"(?i)bitbucket[^\n]{0,24}?(ATBB[A-Za-z0-9]{24,})",
        keywords=("bitbucket",),
        tags=("bitbucket", "vcs"),
    ),
    # --- package registries
    _rule(
        "npm-token",
        "npm access token",
        "critical",
        r"\b(npm_[A-Za-z0-9]{36})\b",
        tags=("npm", "registry"),
    ),
    _rule(
        "npmrc-auth-token",
        "npmrc _authToken",
        "critical",
        r"(?i)_auth(?:Token)?\s*=\s*([A-Za-z0-9._-]{20,})",
        keywords=("_auth", "npmrc"),
        entropy_min=2.5,
        tags=("npm", "registry"),
    ),
    _rule(
        "pypi-token",
        "PyPI upload token",
        "critical",
        r"\b(pypi-[A-Za-z0-9_-]{40,})\b",
        tags=("pypi", "registry"),
    ),
    _rule(
        "docker-hub-pat",
        "Docker Hub personal access token",
        "high",
        r"\b(dckr_pat_[A-Za-z0-9_-]{20,})\b",
        tags=("docker", "registry"),
    ),
    _rule(
        "nuget-api-key",
        "NuGet API key",
        "medium",
        r"(?i)api[_-]?key[ \t]*[:=][ \t]*['\"]?([a-z0-9]{32,64})",
        keywords=("nuget",),
        entropy_min=3.0,
        tags=("nuget", "registry"),
    ),
    # --- comms
    _rule(
        "slack-bot-token",
        "Slack bot/user token",
        "critical",
        r"\b(xox[abprs]-[A-Za-z0-9-]{10,72})\b",
        validate=valid_slack,
        tags=("slack", "chat"),
    ),
    _rule(
        "slack-webhook",
        "Slack incoming webhook",
        "high",
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{20,}",
        tags=("slack", "chat", "webhook"),
    ),
    _rule(
        "discord-bot-token",
        "Discord bot token",
        "high",
        r"\b([MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b",
        tags=("discord", "chat"),
    ),
    _rule(
        "discord-webhook",
        "Discord webhook",
        "medium",
        r"https://discord(?:app)?\.com/api/webhooks/[0-9]{15,25}/[A-Za-z0-9_-]{40,}",
        tags=("discord", "chat", "webhook"),
    ),
    _rule(
        "telegram-bot-token",
        "Telegram bot token",
        "high",
        r"\b([0-9]{8,12}:[A-Za-z0-9_-]{35})\b",
        tags=("telegram", "chat"),
    ),
    _rule(
        "twilio-account-sid",
        "Twilio account SID",
        "medium",
        r"\b(AC[0-9a-fA-F]{32})\b",
        tags=("twilio", "sms"),
    ),
    _rule(
        "twilio-api-key",
        "Twilio API key",
        "high",
        r"\b(SK[0-9a-fA-F]{32})\b",
        tags=("twilio", "sms"),
    ),
    _rule(
        "sendgrid-api-key",
        "SendGrid API key",
        "critical",
        r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b",
        tags=("sendgrid", "email"),
    ),
    _rule(
        "mailgun-api-key",
        "Mailgun API key",
        "high",
        r"\b(key-[0-9a-fA-F]{32})\b",
        tags=("mailgun", "email"),
    ),
    _rule(
        "mailchimp-api-key",
        "Mailchimp API key",
        "high",
        r"\b([0-9a-f]{32}-us[0-9]{1,2})\b",
        tags=("mailchimp", "email"),
    ),
    # --- payments
    _rule(
        "stripe-live-key",
        "Stripe live secret key",
        "critical",
        r"\b([sr]k_live_[A-Za-z0-9]{20,247})\b",
        tags=("stripe", "payment"),
    ),
    _rule(
        "stripe-test-key",
        "Stripe test secret key",
        "low",
        r"\b([sr]k_test_[A-Za-z0-9]{20,247})\b",
        tags=("stripe", "payment"),
    ),
    _rule(
        "square-access-token",
        "Square access token",
        "critical",
        r"\b(sq0atp-[A-Za-z0-9_-]{22,}|EAAA[A-Za-z0-9+/=]{40,})\b",
        tags=("square", "payment"),
    ),
    _rule(
        "paypal-braintree",
        "Braintree/PayPal access token",
        "critical",
        r"\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b",
        tags=("paypal", "payment"),
    ),
    _rule(
        "shopify-token",
        "Shopify access token",
        "high",
        r"\b(shp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32})\b",
        tags=("shopify", "payment"),
    ),
    # --- LLM / AI
    _rule(
        "openai-api-key",
        "OpenAI API key",
        "critical",
        r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})T3BlbkFJ[A-Za-z0-9_-]{20,}\b",
        tags=("openai", "llm"),
        # The full form beats `openai-key-short` on the same token.
        priority=1,
    ),
    _rule(
        "openai-key-short",
        "OpenAI API key (compact form)",
        "critical",
        r"\b(sk-proj-[A-Za-z0-9_-]{40,})\b",
        tags=("openai", "llm"),
    ),
    _rule(
        "anthropic-api-key",
        "Anthropic API key",
        "critical",
        r"\b(sk-ant-[A-Za-z0-9_-]{24,})\b",
        tags=("anthropic", "llm"),
    ),
    _rule(
        "huggingface-token",
        "Hugging Face token",
        "high",
        r"\b(hf_[A-Za-z0-9]{30,})\b",
        tags=("huggingface", "llm"),
    ),
    _rule(
        "replicate-token",
        "Replicate API token",
        "high",
        r"\b(r8_[A-Za-z0-9]{30,})\b",
        tags=("replicate", "llm"),
    ),
    # --- infra / CI / observability
    _rule(
        "digitalocean-token",
        "DigitalOcean token",
        "critical",
        r"\b(dop_v1_[a-f0-9]{64})\b",
        tags=("digitalocean", "cloud"),
    ),
    _rule(
        "digitalocean-legacy",
        "DigitalOcean legacy token",
        "high",
        r"(?i)do[_-]?token\s*[:=]\s*['\"]?([a-f0-9]{64})",
        keywords=("do_token", "digitalocean"),
        tags=("digitalocean", "cloud"),
    ),
    _rule(
        "heroku-api-key",
        "Heroku API key",
        "high",
        r"(?i)heroku(.{0,12})?api[_-]?key\s*[:=]\s*['\"]?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})",
        group=2,
        keywords=("heroku",),
        tags=("heroku", "cloud"),
    ),
    _rule(
        "datadog-api-key",
        "Datadog API key",
        "high",
        r"(?i)datadog(.{0,20})?['\"]([0-9a-f]{32})['\"]",
        group=2,
        keywords=("datadog",),
        tags=("datadog", "observability"),
    ),
    _rule(
        "newrelic-key",
        "New Relic key",
        "high",
        r"\b(NRAK-[A-Z0-9]{27})\b",
        tags=("newrelic", "observability"),
    ),
    _rule(
        "grafana-api-key",
        "Grafana API key / service account token",
        "high",
        r"\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})\b",
        tags=("grafana", "observability"),
    ),
    _rule(
        "grafana-legacy-key",
        "Grafana legacy API key",
        "medium",
        r"(?i)grafana(.{0,20})?['\"](eyJ[A-Za-z0-9_/+-]{20,})['\"]",
        group=2,
        keywords=("grafana",),
        tags=("grafana", "observability"),
    ),
    _rule(
        "jfrog-token",
        "JFrog API key / identity token",
        "high",
        r"\b((?:AKC|AP)[0-9a-zA-Z]{10,})\b|\b(?:cmVmdGtu)[A-Za-z0-9=]{8,}",
        entropy_min=3.0,
        keywords=("jfrog", "artifactory", "xray"),
        tags=("jfrog", "registry"),
    ),
    _rule(
        "hashicorp-vault-token",
        "HashiCorp Vault token",
        "critical",
        r"\b((?:hvs|hvr|hvb)\.[A-Za-z0-9_-]{24,})\b",
        tags=("vault", "secret-manager"),
    ),
    _rule(
        "terraform-cloud-token",
        "Terraform Cloud/Enterprise token",
        "critical",
        r"\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,})\b",
        tags=("terraform", "iac"),
    ),
    _rule(
        "cloudflare-api-token",
        "Cloudflare API token",
        "high",
        r"(?i)cloudflare(.{0,24})?['\"]([A-Za-z0-9_-]{40})['\"]",
        group=2,
        entropy_min=3.5,
        keywords=("cloudflare",),
        tags=("cloudflare", "cdn"),
    ),
    _rule(
        "cloudflare-global-key",
        "Cloudflare global API key",
        "critical",
        r"(?i)cloudflare(.{0,24})?['\"]([0-9a-f]{37})['\"]",
        group=2,
        keywords=("cloudflare",),
        tags=("cloudflare", "cdn"),
    ),
    # --- project management / SaaS
    _rule(
        "linear-api-key",
        "Linear API key",
        "high",
        r"\b(lin_api_[A-Za-z0-9]{40,})\b",
        tags=("linear", "saas"),
    ),
    _rule(
        "asana-token",
        "Asana personal access token",
        "medium",
        r"(?i)asana(.{0,24})?['\"](\d{16})['\"]",
        group=2,
        keywords=("asana",),
        tags=("asana", "saas"),
    ),
    _rule(
        "jira-api-token",
        "Jira/Atlassian API token",
        "high",
        r"(?i)(?:jira|atlassian)(.{0,24})?['\"](ATATT[A-Za-z0-9_=-]{20,})['\"]",
        group=2,
        keywords=("jira", "atlassian"),
        tags=("atlassian", "saas"),
    ),
    _rule(
        "sentry-token",
        "Sentry auth token",
        "high",
        r"\b(sntrys_[A-Za-z0-9]{32,})\b",
        tags=("sentry", "observability"),
    ),
    _rule(
        "snyk-token",
        "Snyk API token",
        "high",
        r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
        entropy_min=3.0,
        keywords=("snyk",),
        tags=("snyk", "security"),
    ),
    _rule(
        "sonar-token",
        "SonarQube token",
        "medium",
        r"\b(squ_[0-9a-f]{40})\b",
        tags=("sonar", "ci"),
    ),
    _rule(
        "codecov-token",
        "Codecov upload token",
        "medium",
        r"(?i)codecov[_-]?token\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        keywords=("codecov",),
        tags=("codecov", "ci"),
    ),
    _rule(
        "algolia-api-key",
        "Algolia API key",
        "medium",
        r"(?i)algolia(.{0,20})?['\"]([0-9a-f]{32})['\"]",
        group=2,
        keywords=("algolia",),
        tags=("algolia", "saas"),
    ),
    _rule(
        "mapbox-token",
        "Mapbox access token",
        "medium",
        r"\b(pk\.eyJ1[A-Za-z0-9_-]{20,})\b",
        tags=("mapbox", "saas"),
    ),
    _rule(
        "segment-write-key",
        "Segment write key",
        "medium",
        r"(?i)segment(.{0,20})?['\"]([A-Za-z0-9]{32})['\"]",
        group=2,
        entropy_min=3.4,
        keywords=("segment",),
        tags=("segment", "analytics"),
    ),
    _rule(
        "postman-api-key",
        "Postman API key",
        "medium",
        r"\b(PMAK-[0-9a-f]{24}-[0-9a-f]{34})\b",
        tags=("postman", "saas"),
    ),
    _rule(
        "shodan-api-key",
        "Shodan API key",
        "low",
        r"(?i)shodan(.{0,20})?['\"]([A-Za-z0-9]{32})['\"]",
        group=2,
        entropy_min=3.4,
        keywords=("shodan",),
        tags=("shodan", "osint"),
    ),
    _rule(
        "auth0-client-secret",
        "Auth0 client secret",
        "critical",
        r"(?i)auth0(.{0,24})?['\"]([A-Za-z0-9_-]{32,64})['\"]",
        group=2,
        entropy_min=3.6,
        keywords=("auth0",),
        tags=("auth0", "identity"),
    ),
    _rule(
        "okta-token",
        "Okta API token",
        "critical",
        r"\b(00[A-Za-z0-9_-]{40})\b",
        entropy_min=3.6,
        keywords=("okta",),
        tags=("okta", "identity"),
    ),
    _rule(
        "dropbox-token",
        "Dropbox access token",
        "high",
        r"\b(sl\.[A-Za-z0-9_-]{40,})\b",
        tags=("dropbox", "storage"),
    ),
    _rule(
        "twitter-bearer",
        "Twitter/X bearer token",
        "high",
        r"(?i)twitter.{0,24}bearer.{0,8}?(AAAAAAAAAAAAAAAAAAAAAA%2F[A-Za-z0-9%]{20,}|[A-Za-z0-9%_-]{40,})",
        keywords=("twitter",),
        tags=("twitter", "social"),
    ),
    _rule(
        "facebook-access-token",
        "Facebook/Instagram access token",
        "high",
        r"\b(EAAG[A-Za-z0-9]{20,})\b",
        tags=("facebook", "social"),
    ),
    # --- databases and connection strings
    _rule(
        "postgres-uri",
        "PostgreSQL URI with password",
        "critical",
        r"(?i)postgres(?:ql)?://[^\s:@/]+:([^\s@/]{6,})@",
        keywords=("postgres",),
        tags=("database", "uri"),
    ),
    _rule(
        "mysql-uri",
        "MySQL URI with password",
        "critical",
        r"(?i)mysql://[^\s:@/]+:([^\s@/]{6,})@",
        keywords=("mysql",),
        tags=("database", "uri"),
    ),
    _rule(
        "mongodb-uri",
        "MongoDB URI with password",
        "critical",
        r"(?i)mongodb(?:\+srv)?://[^\s:@/]+:([^\s@/]{6,})@",
        keywords=("mongo",),
        tags=("database", "uri"),
    ),
    _rule(
        "redis-uri",
        "Redis URI with password",
        "high",
        r"(?i)rediss?://[^\s:@/]*:([^\s@/]{6,})@",
        keywords=("redis",),
        tags=("database", "uri"),
    ),
    _rule(
        "amqp-uri",
        "AMQP URI with password",
        "high",
        r"(?i)amqps?://[^\s:@/]+:([^\s@/]{6,})@",
        keywords=("amqp",),
        tags=("database", "uri"),
    ),
    _rule(
        "basic-auth-url",
        "HTTP basic-auth credentials in URL",
        "high",
        r"https?://[^\s:@/]{2,}:([^\s@/]{4,})@[^\s/]+",
        tags=("url", "auth"),
    ),
    _rule(
        "db-password-assignment",
        "Database password assignment",
        "high",
        r"(?i)\b(?:db|database|sql|pg|mysql|mongo|redis)[_-]?(?:password|passwd|pwd)\b\s*['\"]?\s*[:=]\s*['\"]?([^\s'\"]{6,})",
        entropy_min=2.0,
        keywords=("password",),
        tags=("database", "assignment"),
    ),
    # --- keys and tokens
    _rule(
        "private-key-block",
        "Private key block",
        "critical",
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        tags=("key", "crypto"),
    ),
    _rule(
        "jwt",
        "JSON Web Token",
        "high",
        r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b",
        validate=valid_jwt,
        tags=("jwt", "token"),
    ),
    _rule(
        "bearer-token",
        "Bearer token literal",
        "medium",
        r"(?i)\bauthorization\b[^\n]{0,20}\bbearer\s+([A-Za-z0-9._~+/=-]{20,})",
        entropy_min=3.0,
        keywords=("bearer",),
        tags=("token", "auth"),
    ),
    _rule(
        "basic-authorization-header",
        "Basic auth header literal",
        "medium",
        r"(?i)\bauthorization\b[^\n]{0,20}\bbasic\s+([A-Za-z0-9+/=]{16,})",
        entropy_min=3.0,
        keywords=("basic",),
        tags=("token", "auth"),
    ),
    _rule(
        "kubernetes-service-account-token",
        "Kubernetes service account token",
        "critical",
        r"\b(eyJhbGciOiJSUzI1NiIs[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b",
        tags=("kubernetes", "token"),
        # Beats the generic `jwt` rule when both match the same span.
        priority=1,
    ),
    _rule(
        "ssh-private-key-inline",
        "SSH private key inline",
        "critical",
        r"ssh-rsa\s+(AAAAB3NzaC1yc2E[A-Za-z0-9+/=]{100,})",
        tags=("key", "ssh"),
    ),
    # --- generic assignments (entropy-gated)
    _rule(
        "generic-api-key-assignment",
        "Generic api key assignment",
        "medium",
        r"(?i)\b(?:api[_-]?key|apikey|access[_-]?key)\b\s*['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
        entropy_min=3.2,
        tags=("generic", "assignment"),
    ),
    _rule(
        "generic-secret-assignment",
        "Generic secret assignment",
        "medium",
        r"(?i)\b(?:client[_-]?secret|app[_-]?secret|[a-z0-9_]*secret[_-]?key|secret)\b\s*['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
        entropy_min=3.2,
        keywords=("secret",),
        tags=("generic", "assignment"),
    ),
    _rule(
        "generic-token-assignment",
        "Generic token assignment",
        "medium",
        r"(?i)\b(?:auth[_-]?token|access[_-]?token|refresh[_-]?token|[a-z0-9_]*[_-]?token)\b\s*['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?",
        entropy_min=3.4,
        keywords=("token",),
        tags=("generic", "assignment"),
    ),
    _rule(
        "generic-password-assignment",
        "Generic password assignment",
        "low",
        r"(?i)\b(?:password|passwd|pwd)\b\s*['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
        entropy_min=3.0,
        keywords=("password",),
        tags=("generic", "assignment"),
    ),
    _rule(
        "env-file-secret",
        "Environment file secret assignment",
        "medium",
        # The value charset is deliberately narrow: `*_TOKEN_* = re.compile(...)`
        # in a Python source file is not a credential.
        r"(?i)^[ \t]*(?:export[ \t]+)?([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)[ \t]*=[ \t]*['\"]?([A-Za-z0-9_\-.=+/]{16,})",
        group=2,
        entropy_min=2.8,
        tags=("generic", "env"),
    ),
    # --- high-entropy material with no provider prefix
    _rule(
        "hex-secret-64",
        "64-char hex secret",
        "low",
        r"\b([0-9a-f]{64})\b",
        entropy_min=3.2,
        tags=("entropy", "hex"),
    ),
    _rule(
        "base64-secret-40",
        "40+ char base64 blob",
        "low",
        r"\b([A-Za-z0-9+/]{40,}={0,2})\b",
        entropy_min=4.0,
        keywords=("secret", "token", "key", "password", "auth", "sign", "hash"),
        tags=("entropy", "base64"),
    ),
)

RULES_BY_ID: dict[str, Rule] = {r.rid: r for r in RULES}


def rule_ids() -> list[str]:
    return [r.rid for r in RULES]


def tags() -> list[str]:
    seen: list[str] = []
    for r in RULES:
        for t in r.tags:
            if t not in seen:
                seen.append(t)
    return seen


def rules_for_tag(tag: str) -> list[Rule]:
    return [r for r in RULES if tag in r.tags]
