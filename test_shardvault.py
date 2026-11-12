import itertools, secrets
import pytest
from shardvault import P, split_secret, combine_shares, seal, open_vault, Share


def test_any_t_subset_recovers():
    s = secrets.randbelow(P)
    pts = split_secret(s, 3, 5)
    for combo in itertools.combinations(pts, 3):
        assert combine_shares(list(combo)) == s


def test_t_minus_1_is_wrong():
    s = secrets.randbelow(P)
    pts = split_secret(s, 3, 5)
    assert combine_shares(pts[:2]) != s  # holds with overwhelming probability


def test_roundtrip_file():
    data = secrets.token_bytes(10_000)
    blob, toks = seal(data, 2, 4)
    assert open_vault(blob, [toks[3], toks[0]]) == data


def test_too_few_shares():
    blob, toks = seal(b"x", 3, 5)
    with pytest.raises(ValueError):
        open_vault(blob, toks[:2])


def test_tampered_share_detected():
    blob, toks = seal(b"secret", 2, 3)
    s = Share.decode(toks[0]); s.y = (s.y + 1) % P
    with pytest.raises(ValueError):
        open_vault(blob, [s.encode(), toks[1]])


def test_tampered_ciphertext_detected():
    blob, toks = seal(b"secret", 2, 3)
    bad = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(Exception):
        open_vault(bad, toks[:2])


def test_shares_from_other_file_ignored():
    blob, toks = seal(b"a", 2, 3)
    _, other = seal(b"b", 2, 3)
    with pytest.raises(ValueError):
        open_vault(blob, [toks[0], other[1]])
