"""One realistic sample line per rule.

This exists because a rule library that is never exercised is a rule library
that silently rots: `tests/test_samples.py` asserts that every rule id has a
sample and that scanning the sample actually produces that rule id.
`demo.py` writes these into a throwaway tree so `secretsweep demo` has something
real to find.
"""

from __future__ import annotations

# --- reusable fragments (each block below is exactly 10 characters) ---------
_B1 = "qN3xT7vLm2"
_B2 = "pR9wZ4cK8j"
_B3 = "H5fB1dY6sA"
_B4 = "0eU3oI7gXz"

S40 = _B1 + _B2 + _B3 + _B4  # 40, mixed case
S30 = _B1 + _B2 + _B3  # 30
S20 = _B1 + _B2  # 20

_C1 = "R7kQ2vLm9pZx"  # 12
_C2 = "T4wC8jH5fB1d"  # 12
_C3 = "Y6sA0eU3oI7g"  # 12
S36 = _C1 + _C2 + _C3  # 36, base62
S51 = S36 + "Xz2mP8nQ4tR7vLb"  # 51
S22 = _C2 + "Y6sA0eU3oI"  # 22
S43 = S40 + "P2m"  # 43

_H1 = "a3f9c1e7"  # 8
_H2 = "5b2d8406"
_H3 = "e91c47af"
_H4 = "3d6b25f8"
_H5 = "7ac018be"
_H6 = "2f5e93d4"
_H7 = "b6407c19"
_H8 = "8e1d4a52"
HEX16 = _H1 + _H2
HEX24 = HEX16 + _H3
HEX32 = HEX24 + _H4
HEX37 = HEX32 + "5c2e1"
HEX40 = HEX32 + _H5
HEX64 = HEX40 + _H6 + _H7 + _H8

UUID = f"{_H1}-{_H2[:4]}-{_H2[4:]}-{_H3[:4]}-{_H3[4:]}{_H4}"
UPPER27 = "R7KQ2VLM9PZXT4WC8JH5FB1DY6S"  # 27 chars, [A-Z0-9]

JWT_HS256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtZGVwbG95IiwiaWF0IjoxNzMwMDAwMDAwLCJleHAiOjE3MzAwMDAwMDB9.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
JWT_RS256 = "eyJhbGciOiJSUzI1NiIsImtpZCI6InN2Yy1rZXktMDEifQ.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpkZXBsb3kifQ.T3BlbkFJc2lnbmF0dXJlYmxvYmZvcnRoZXJlYWRlcjEyMzQ1"

PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"

RULE_SAMPLES: dict[str, str] = {
    # --- AWS
    "aws-access-key-id": 'aws_access_key_id = "AKIA3RJ4E5TZLMXQW7PU"',
    "aws-secret-access-key": f'aws_secret_access_key = "{S40}"',
    "aws-session-token": f'aws_session_token = "FwoGZXIvYXdz{S30}"',
    # --- GCP
    "gcp-api-key": f'gcp_key = "AIza{_C1 + _C2 + _C3[:11]}"',
    "gcp-service-account": f'"private_key_id": "{_B1 + _B2}"',
    "firebase-cloud-messaging": f'fcm_key = "AAAApR9wZ4c:{S40 + S40 + _B1 + _B2 + "Kj8"}"',
    # --- Azure
    "azure-storage-key": f"AccountKey={S40}{_B1}{_B2}",
    "azure-client-secret": f'client_secret = "{S40}"',
    # --- git hosting
    "github-pat": f'GITHUB_TOKEN = "ghp_{S36}"',
    "gitlab-pat": f'gitlab_token = "glpat-{_C1}{_C2}{_C3[:4]}"',
    "gitlab-runner-token": f'registration_token = "GR1348941{_C1}{_C2}"',
    "bitbucket-app-password": f'bitbucket_pwd = "ATBB{_B1}{_B2}{_B3[:4]}"',
    # --- registries
    "npm-token": f'NPM_TOKEN = "npm_{S36}"',
    "npmrc-auth-token": f'_authToken={_C1}{_C2[:8]}',
    "pypi-token": f'pypi_token = "pypi-{S40}"',
    "docker-hub-pat": f'docker_pat = "dckr_pat_{_C1}{_C2}"',
    "nuget-api-key": f'nuget api_key = "{_H1}{_H2}{_H3}{_H4}"',
    # --- comms
    "slack-bot-token": f'slack = "xoxb-3827461590238-3847561029384-{_C1}{_C2[:4]}"',
    "slack-webhook": "https://hooks.slack.com/services/T02K4N7QL/B05P2X9WZQD/" + _C1 + _C2,
    "discord-bot-token": f'discord = "M{_C1}{_C2[:11]}.{_B1[:6]}.{_C2}{_C3}{_B1[:3]}"',
    "discord-webhook": "https://discord.com/api/webhooks/104739201948612345/" + _C1 + _C2 + _C3 + _B1[:4],
    "telegram-bot-token": f'telegram = "7236184561:{_C1}{_C2}{_C3[:11]}"',
    "twilio-account-sid": f'twilio_sid = "AC{HEX32}"',
    "twilio-api-key": f'twilio_key = "SK{HEX32}"',
    "sendgrid-api-key": f'sendgrid = "SG.{S22}.{S43}"',
    "mailgun-api-key": f'mailgun = "key-{HEX32}"',
    "mailchimp-api-key": f'mailchimp = "{HEX32}-us12"',
    # --- payments
    "stripe-live-key": f'stripe = "sk_live_{S40}"',
    "stripe-test-key": f'stripe = "sk_test_{S40}"',
    "square-access-token": f'square = "sq0atp-{_C1}{_C2}"',
    "paypal-braintree": f'braintree = "access_token$production${_H1}{_H2[:8]}${HEX32}"',
    "shopify-token": f'shopify = "shpat_{HEX32}"',
    # --- LLM
    "openai-api-key": f'openai = "sk-proj-{_C1}{_C2[:8]}T3BlbkFJ{_C2}{_C3}"',
    "openai-key-short": f'openai = "sk-proj-{_C1}{_C2}{_C3}{_B1}"',
    "anthropic-api-key": f'anthropic = "sk-ant-{_C1}{_C2}"',
    "huggingface-token": f'hf = "hf_{_C1}{_C2}{_C3}"',
    "replicate-token": f'replicate = "r8_{_C1}{_C2}{_C3}"',
    # --- infra / CI / observability
    "digitalocean-token": f'do = "dop_v1_{HEX64}"',
    "digitalocean-legacy": f'do_token = "{HEX64}"',
    "heroku-api-key": f'heroku_api_key = "{UUID}"',
    "datadog-api-key": f'datadog api = "{HEX32}"',
    "newrelic-key": f'newrelic = "NRAK-{UPPER27}"',
    "grafana-api-key": f'grafana = "glsa_{_C1}{_C2}{_C3[:8]}_{_H1}"',
    "grafana-legacy-key": f'grafana key = "eyJ{_C1}{_C2}"',
    "jfrog-token": f'artifactory = "AKC{_C1}{_C2}"',
    "hashicorp-vault-token": f'vault = "hvs.{_C1}{_C2}"',
    "terraform-cloud-token": f'tfc = "{_C1[:2]}{_C2[:12]}.atlasv1.{S40}{_B1}{_B2}"',
    "cloudflare-api-token": f'cloudflare token = "{S40}"',
    "cloudflare-global-key": f'cloudflare key = "{HEX37}"',
    # --- SaaS
    "linear-api-key": f'linear = "lin_api_{S40}"',
    "asana-token": 'asana = "4820913572615048"',
    "jira-api-token": f'jira token = "ATATT{_C1}{_C2}"',
    "sentry-token": f'sentry = "sntrys_{S40}"',
    "snyk-token": f'snyk_token = "{UUID}"',
    "sonar-token": f'sonar = "squ_{HEX40}"',
    "codecov-token": f'codecov_token = "{UUID}"',
    "algolia-api-key": f'algolia = "{HEX32}"',
    "mapbox-token": f'mapbox = "pk.eyJ1{_C1}{_C2}"',
    "segment-write-key": f'segment = "{S20}{_B3}{_C1[:2]}"',
    "postman-api-key": f'postman = "PMAK-{HEX24}-{HEX32}{_H5[:2]}"',
    "shodan-api-key": f'shodan = "{_C1}{_C2}{_C3[:8]}"',
    "auth0-client-secret": f'auth0 = "{S40}"',
    "okta-token": f'okta = "00{_C1}{_C2}{_C3}{_B1[:4]}"',
    "dropbox-token": f'dropbox = "sl.{S40}"',
    "twitter-bearer": f'twitter bearer = "AAAAAAAAAAAAAAAAAAAAAA%2F{_C1}{_C2}{_C3[:4]}"',
    "facebook-access-token": f'facebook = "EAAG{_C1}{_C2}"',
    # --- databases
    "postgres-uri": f"DATABASE_URL = postgres://svc:{_C1}@db.internal.corp:5432/app",
    "mysql-uri": f"MYSQL_URL = mysql://root:{_C2}@mysql.internal.corp/app",
    "mongodb-uri": f"MONGO_URI = mongodb+srv://app:{_C3}@cluster0.mongodb.net/app",
    "redis-uri": f"REDIS_URL = rediss://default:{_B1}@cache.internal.corp:6380",
    "amqp-uri": f"AMQP_URL = amqp://guest:{_B2}@rabbit.internal.corp:5672",
    "basic-auth-url": f"PULL_URL = https://ci-bot:{_C1}@artifacts.internal.corp/builds",
    "db-password-assignment": 'db_password = "Xk9#mQ2vL"',
    # --- keys and tokens
    "private-key-block": PEM_HEADER,
    "jwt": f'id_token = "{JWT_HS256}"',
    "bearer-token": f"authorization: bearer {S40}",
    "basic-authorization-header": "Authorization: Basic ZHJhZnQ6cGFzc3dvcmQxMjM0NQ==",
    "kubernetes-service-account-token": f'k8s_token = "{JWT_RS256}"',
    "ssh-private-key-inline": f"ssh-rsa AAAAB3NzaC1yc2E{S40}{S40}{_B1}{_B2}{_B3[:4]} svc@deploy",
    # --- generic
    "generic-api-key-assignment": f'api_key = "{S40}"',
    "generic-secret-assignment": f'app_secret = "{S40}"',
    "generic-token-assignment": f'access_token = "{S40}"',
    "generic-password-assignment": 'password = "Xk9#mQ2vLpR7wZ"',
    "env-file-secret": f'export DEPLOY_WEBHOOK_SECRET = "{_C1}{_C2[:4]}"',
    # --- entropy
    "hex-secret-64": f'blob = "{HEX64}"',
    "base64-secret-40": f'hmac_signing blob = "{S40}"',
}


def sample_for(rule_id: str) -> str:
    """Return the sample line for a rule. Raises KeyError when missing."""
    return RULE_SAMPLES[rule_id]


def missing_samples(rule_ids: list[str]) -> list[str]:
    return [rid for rid in rule_ids if rid not in RULE_SAMPLES]


def extra_samples(rule_ids: list[str]) -> list[str]:
    return [rid for rid in RULE_SAMPLES if rid not in rule_ids]
