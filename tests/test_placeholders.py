from secretsweep.placeholders import classify_value, line_placeholder_reason, triage

# Fixture values are assembled from fragments: a secret scanner's own repository
# must not contain literals that GitHub push protection (or any other scanner)
# will flag. Runtime values are unchanged.
SK_TEST = "sk" + "_test_" + "0" * 24


RANDOM = "qN3xT7vLm2pR9wZ4cK8jH"


def test_known_examples_are_placeholders():
    for value in (
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "ghp_0000000000000000000000000000000000",
        SK_TEST,
    ):
        confidence, reasons = classify_value(value)
        assert confidence == "placeholder", value
        assert "known-example" in reasons


def test_template_references_are_placeholders():
    for value in ("${AWS_KEY}", "{{ secrets.TOKEN }}", "process.env.API_KEY", "vault:secret/data/token"):
        confidence, reasons = classify_value(value)
        assert confidence == "placeholder", value
        assert "template-reference" in reasons


def test_literals_are_placeholders():
    for value in ("true", "None", "undefined"):
        confidence, _ = classify_value(value)
        assert confidence == "placeholder"


def test_masked_and_low_variety_values():
    assert classify_value("xxxx")[0] == "placeholder"
    assert classify_value("00000000")[0] == "placeholder"
    assert classify_value("abab")[0] == "placeholder"  # too short for the repeat rule
    assert classify_value("aaaaaaaaaaaa")[0] == "placeholder"


def test_sequential_runs_are_placeholders():
    confidence, reasons = classify_value("1234567890")
    assert confidence == "placeholder"
    assert "sequential" in reasons
    assert classify_value("abcdefgh")[0] == "placeholder"


def test_trivial_words_are_placeholders():
    assert classify_value("password")[0] == "placeholder"
    assert classify_value("testtoken")[0] == "placeholder"


def test_repeated_pattern_is_placeholder():
    confidence, reasons = classify_value("abcdabcdabcd")
    assert confidence == "placeholder"
    assert "repeating-pattern" in reasons
    # fewer distinct characters trip the low-variety rule first
    assert classify_value("abababababab")[0] == "placeholder"


def test_low_variety_long_value_is_placeholder():
    confidence, reasons = classify_value("aaaabbbbcccc")
    assert confidence == "placeholder"
    assert any(r.startswith("low-variety") for r in reasons)


def test_identifier_paths_are_placeholders():
    for value in ("secretsweep.cli:main", "pkg.module.func", "src/secretsweep/cli.py"):
        assert classify_value(value)[0] == "placeholder", value


def test_snake_case_identifiers_are_placeholders():
    """Found by dogfooding on vehsec: `elif oid == _EXT_KEY_USAGE` is not a leak."""
    for value in ("_parse_key_usage", "load_private_key", "get_secret_name"):
        assert classify_value(value)[0] == "placeholder", value


def test_snake_case_rule_does_not_swallow_hex_bearing_tokens():
    # dop_v1_<64 hex> is a DigitalOcean token, not a Python identifier
    assert classify_value("dop_v1_" + "a3f9c1e7" * 8)[0] == "likely"


def test_hex_digests_next_to_hash_words_are_placeholders():
    """Found by dogfooding on mcplock: `surface_digest` is a hash, not a secret."""
    value = "a3f9c1e75b2d8406e91c47af3d6b25f87ac018be2f5e93d4b6407c198e1d4a52"
    for line in (
        f'"surface_digest": "{value}"',
        f"sha256sum = {value}",
        f"expected_fingerprint = {value}",
        f"etag: {value}",
    ):
        confidence, reasons = triage(value, line)
        assert confidence == "placeholder", line
        assert "hash-context" in reasons


def test_hex_blobs_without_hash_context_stay_likely():
    value = "a3f9c1e75b2d8406e91c47af3d6b25f87ac018be2f5e93d4b6407c198e1d4a52"
    confidence, _ = triage(value, f'blob = "{value}"')
    assert confidence == "likely"


def test_random_material_is_likely():
    confidence, reasons = classify_value(RANDOM)
    assert confidence == "likely"
    assert reasons == ()


def test_line_words_mark_placeholder():
    assert line_placeholder_reason(f'api_key = "{RANDOM}"') is None
    assert line_placeholder_reason("token = ${TOKEN}") is None
    assert line_placeholder_reason("token = <your-token-here>") == "line-word:angle-placeholder"
    assert line_placeholder_reason("api_key = SAMPLEKEY") == "line-word:sample"


def test_triage_applies_line_context():
    confidence, reasons = triage(RANDOM, 'api_key = "RANDOMVALUEHERE"  # example')
    assert confidence == "placeholder"
    assert any(r.startswith("line-word:") for r in reasons)


def test_triage_keeps_likely_values():
    confidence, _reasons = triage(RANDOM, f'api_key = "{RANDOM}"')
    assert confidence == "likely"


def test_empty_value_is_placeholder():
    assert classify_value("   ")[0] == "placeholder"
