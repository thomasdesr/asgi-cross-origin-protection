"""Origin parsing and comparison (pure: no I/O, no framework types).

Origins reach this module in two shapes, so there are two builders.
``normalize_origin`` parses a full URL string, the form found in an ``Origin``
request header. ``origin_tuple`` builds from already-split scheme/host/port
components, the form the middleware has after reading the ``Host`` header or the
ASGI ``server`` field. Both return the same normalized ``Origin`` (lowercased
scheme and host, port defaulted from the scheme), so an origin parsed from a
header compares equal to one built from request components.

Neither is part of the package's public API; the protection middleware imports
them internally.
"""

from urllib.parse import urlparse

# (scheme, host, port), with scheme and host lowercased and the port defaulted.
Origin = tuple[str, str, int]


def normalize_origin(value: str) -> Origin | None:
    """Parse an Origin header value (a URL string) into a normalized origin, or None."""
    parsed = urlparse(value)
    return origin_tuple(parsed.scheme, parsed.hostname, parsed.port)


def origin_tuple(scheme: str | None, host: str | None, port: int | None) -> Origin | None:
    """Build a normalized origin from components, defaulting the port from the scheme.

    Returns None when scheme or host is missing.
    """
    if not scheme or not host:
        return None
    scheme_lower = scheme.lower()
    port_value = port if port is not None else _DEFAULT_PORTS.get(scheme_lower, 80)
    return scheme_lower, host.lower(), port_value


_DEFAULT_PORTS = {"https": 443, "http": 80}
