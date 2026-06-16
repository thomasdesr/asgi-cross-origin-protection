import pytest

from asgi_cross_origin_protection.origins import normalize_origin, origin_tuple


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://example.com", ("https", "example.com", 443)),
        ("http://example.com", ("http", "example.com", 80)),
        ("https://example.com:8443", ("https", "example.com", 8443)),
        ("HTTP://Example.COM", ("http", "example.com", 80)),
        ("not-a-url", None),
        ("null", None),
        ("", None),
    ],
)
def test_normalize_origin(value, expected):
    assert normalize_origin(value) == expected


def test_origin_tuple_requires_scheme_and_host():
    assert origin_tuple("https", None, None) is None
    assert origin_tuple(None, "example.com", None) is None
    assert origin_tuple("", "", None) is None


def test_origin_tuple_defaults_unknown_scheme_port_to_80():
    assert origin_tuple("ftp", "example.com", None) == ("ftp", "example.com", 80)
