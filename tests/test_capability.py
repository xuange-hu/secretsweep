import time

from secretsweep import capability

# Fixture values are assembled from fragments: a secret scanner's own repository
# must not contain literals that GitHub push protection (or any other scanner)
# will flag. Runtime values are unchanged.
AWS_KEY = "AK" + "IA3RJ4E5TZLMXQW7PU"



def test_aws_prefixes_explain_what_the_key_is():
    assert "long-lived" in " ".join(capability.infer("aws-access-key-id", AWS_KEY))
    notes = capability.infer("aws-access-key-id", "ASIA3RJ4E5TZLMXQW7PU")
    assert any("temporary" in n for n in notes)
    assert any("cannot sign" in n for n in capability.infer("aws-access-key-id", "AGPA3RJ4E5TZLMXQW7PU"))


def test_github_prefixes_explain_scope():
    assert any("fine-grained" in n for n in capability.infer("github-pat", "github_pat_" + "a" * 60))
    notes = capability.infer("github-pat", "ghp_" + "A" * 36)
    assert any("classic" in n for n in notes)
    assert any("full account access" in n for n in notes)


def test_stripe_live_is_called_out():
    notes = capability.infer("stripe-live-key", "sk_live_" + "a" * 24)
    assert any("live mode" in n for n in notes)


def test_unknown_rule_yields_no_notes():
    assert capability.infer("hex-secret-64", "a" * 64) == ()


def test_jwt_facts_decode_without_verifying():
    import base64
    import json

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    future = int(time.time()) + 86400
    token = f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg({'sub': 'svc', 'exp': future})}.{'x' * 20}"
    facts = capability.jwt_facts(token)
    assert facts["alg"] == "HS256"
    assert facts["sub"] == "svc"
    assert facts["expired"] is False


def test_jwt_facts_detect_expiry():
    import base64
    import json

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    token = f"{seg({'alg': 'HS256'})}.{seg({'sub': 'svc', 'exp': 1730000000})}.{'x' * 20}"
    facts = capability.jwt_facts(token)
    assert facts["expired"] is True
    notes = capability.infer("jwt", token)
    assert any("already expired" in n for n in notes)


def test_jwt_facts_reject_non_jwt():
    assert capability.jwt_facts("not-a-jwt") is None
    assert capability.jwt_facts("a.b") is None


def test_jwt_alg_none_is_flagged():
    import base64
    import json

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    token = f"{seg({'alg': 'none'})}.{seg({'sub': 'x'})}.{'y' * 10}"
    assert any("alg=none" in n for n in capability.infer("jwt", token))


def test_private_key_note_points_at_rotation():
    assert any("rotate" in n for n in capability.infer("private-key-block", "-----BEGIN RSA PRIVATE KEY-----"))


def test_kubernetes_token_mentions_the_cluster():
    import base64
    import json

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    token = f"{seg({'alg': 'RS256', 'kid': 'k'})}.{seg({'sub': 'system:serviceaccount:default:deploy'})}.{'z' * 20}"
    assert any("ServiceAccount" in n for n in capability.infer("kubernetes-service-account-token", token))


def test_basic_auth_url_mentions_referrer_leak():
    assert any("referrer" in n for n in capability.infer("basic-auth-url", "https://u:p@host"))
