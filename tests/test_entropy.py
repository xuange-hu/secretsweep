import math

import pytest

from secretsweep.entropy import (
    charset_of,
    high_entropy_tokens,
    is_random_looking,
    iter_tokens,
    shannon_entropy,
)

# Fixture values are assembled from fragments: a secret scanner's own repository
# must not contain literals that GitHub push protection (or any other scanner)
# will flag. Runtime values are unchanged.
S40 = "qN3xT7vLm2pR9wZ4cK8jH5fB1dY6sA0eU3o" + "I7gXz"


def test_entropy_of_empty_and_uniform():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("a") == 0.0


def test_entropy_of_two_symbols_is_one_bit():
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy("abababab") == pytest.approx(1.0)


def test_entropy_grows_with_alphabet():
    assert shannon_entropy("abcd") == pytest.approx(2.0)
    assert math.isclose(shannon_entropy("abcdefgh"), 3.0)


def test_charset_classification():
    assert charset_of("") == "empty"
    assert charset_of("1234567") == "digits"
    assert charset_of("deadbeef") == "hex"
    assert charset_of("qN3xT7vLm2") == "base62"
    assert charset_of("abc+/=_-") == "base64"
    assert charset_of("abc-#$%") == "mixed"


def test_is_random_looking_requires_length():
    assert not is_random_looking("qN3xT7vLm2")  # 10 chars, too short
    assert is_random_looking("qN3xT7vLm2pR9wZ4cK8jH")
    assert not is_random_looking("aaaaaaaaaaaaaaaaaaaaaa")


def test_is_random_looking_respects_explicit_threshold():
    value = "qN3xT7vLm2pR9wZ4cK8jH"
    assert is_random_looking(value)
    assert not is_random_looking(value, entropy_min=5.0)


def test_iter_tokens_reports_offsets():
    line = 'key = "value" other'
    tokens = list(iter_tokens(line))
    values = [t[0] for t in tokens]
    assert "key" in values and "value" in values and "other" in values
    _token, offset = [t for t in tokens if t[0] == "value"][0]
    assert line[offset : offset + 5] == "value"


def test_high_entropy_tokens_skips_short_and_common():
    assert list(high_entropy_tokens("token = hunter2")) == []
    found = list(high_entropy_tokens('token = "qN3xT7vLm2pR9wZ4cK8jH5fB"'))
    assert len(found) == 1
    token, _offset, ent = found[0]
    assert token == "qN3xT7vLm2pR9wZ4cK8jH5fB"
    assert ent > 4.0


def test_high_entropy_tokens_honours_min_length():
    value = S40  # 40 random-looking chars
    assert len(list(high_entropy_tokens(value))) == 1
    assert list(high_entropy_tokens(value, min_length=64)) == []
