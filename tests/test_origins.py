import pytest

from asgi_cross_origin_protection.origins import (
    host_authority,
    normalize_origin,
    origin_authority,
    parse_trusted_origin,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://example.com", ("https", "example.com", None)),
        ("http://example.com", ("http", "example.com", None)),
        ("https://example.com:8443", ("https", "example.com", 8443)),
        ("HTTP://Example.COM", ("http", "example.com", None)),
        ("https://example.com:bogus", None),
        ("http://[::1", None),
        ("https://", None),  # scheme but no host
        ("not-a-url", None),
        ("null", None),
        ("", None),
    ],
)
def test_normalize_origin(value, expected):
    assert normalize_origin(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://example.com:8443", ("example.com", 8443)),
        ("http://example.com", ("example.com", None)),
        ("not-a-url", None),
        ("null", None),
    ],
)
def test_origin_authority(value, expected):
    assert origin_authority(value) == expected


def test_origin_authority_is_scheme_blind():
    assert origin_authority("https://example.com") == origin_authority("http://example.com")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com:8443", ("example.com", 8443)),
        ("example.com", ("example.com", None)),
        ("Example.COM", ("example.com", None)),
        ("example.com:bogus", ("example.com", None)),
        ("[::1", None),
        ("", None),
    ],
)
def test_host_authority(value, expected):
    assert host_authority(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://example.com", ("https", "example.com", None)),
        ("https://example.com:8443", ("https", "example.com", 8443)),
        ("HTTPS://Example.COM", ("https", "example.com", None)),
    ],
)
def test_parse_trusted_origin_accepts_bare_origins(value, expected):
    assert parse_trusted_origin(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "example.com",  # no scheme
        "https://",  # no host
        "https://example.com/path",  # path
        "https://example.com/",  # trailing slash
        "https://example.com?q=1",  # query
        "https://example.com#f",  # fragment
        "https://example.com:bogus",  # non-numeric port
        "https://[::1",  # unbalanced IPv6 bracket (urlsplit raises)
        "",
    ],
)
def test_parse_trusted_origin_rejects_non_origins(value):
    with pytest.raises(ValueError, match="invalid trusted origin"):
        parse_trusted_origin(value)
