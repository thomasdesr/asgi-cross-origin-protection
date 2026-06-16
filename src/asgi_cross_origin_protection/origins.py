"""Origin and authority parsing (pure: no I/O, no framework types).

Two comparisons need two shapes:

- Trusted-origin matching (``allowed_origins``) is scheme-sensitive: trusting
  ``https://partner.example`` does not trust plaintext ``http://``. It compares
  full ``Origin`` tuples (scheme, host, port).
- Same-origin self-matching is scheme-blind. The request's own scheme is not
  reliably known behind a TLS-terminating proxy, so comparing it would reject
  legitimate requests; this matches Go's ``net/http`` and relies on HSTS to
  prevent http/https confusion. It compares ``Authority`` tuples (host, port).

Ports are kept verbatim (the explicit value or None), never defaulted from the
scheme: a browser omits the default port in both ``Origin`` and ``Host``, so the
two compare equal without defaulting, while defaulting would fold the scheme back
into the port (https->443 vs http->80) and defeat scheme-blind matching.
"""

from urllib.parse import urlsplit

# (scheme, host, port), with scheme and host lowercased and the port verbatim.
Origin = tuple[str, str, int | None]
# (host, port), scheme dropped, host lowercased and the port verbatim.
Authority = tuple[str, int | None]


def normalize_origin(value: str) -> Origin | None:
    """Parse an Origin header value (a URL string) into a normalized origin, or None.

    Returns None when the scheme or host is missing, or the port is non-numeric:
    a full origin must be well-formed to be trusted.
    """
    try:
        split = urlsplit(value)
    except ValueError:
        return None
    if not split.scheme or not split.hostname:
        return None
    try:
        port = split.port
    except ValueError:
        return None
    return split.scheme.lower(), split.hostname.lower(), port


class InvalidTrustedOriginError(ValueError):
    """A configured trusted origin is not a bare ``scheme://host[:port]``.

    Raised at construction. It signals a misconfiguration to fix, not a runtime
    condition to catch and recover from; it subclasses ``ValueError`` so config
    loaders that validate untrusted input can still handle it.
    """

    def __init__(self, value: str, reason: str) -> None:
        super().__init__(f"invalid trusted origin {value!r}: {reason}")


def parse_trusted_origin(value: str) -> Origin:
    """Validate and normalize a configured trusted origin (``scheme://host[:port]``).

    Raises InvalidTrustedOriginError (a ValueError) on anything that is not a bare
    origin. Configuration errors are loud, unlike malformed request headers
    (normalize_origin returns None and the request is simply not trusted).
    Matches Go's ``AddTrustedOrigin``, which rejects a missing scheme/host and
    any path, query, or fragment.
    """
    try:
        split = urlsplit(value)
    except ValueError as exc:
        raise InvalidTrustedOriginError(value, str(exc)) from exc
    if not split.scheme:
        raise InvalidTrustedOriginError(value, "scheme is required")
    if not split.hostname:
        raise InvalidTrustedOriginError(value, "host is required")
    if split.path or split.query or split.fragment:
        raise InvalidTrustedOriginError(value, "path, query, and fragment are not allowed")
    try:
        port = split.port
    except ValueError as exc:
        raise InvalidTrustedOriginError(value, "port must be numeric") from exc
    return split.scheme.lower(), split.hostname.lower(), port


def origin_authority(value: str) -> Authority | None:
    """Scheme-blind (host, port) of an Origin header value, or None if unusable."""
    origin = normalize_origin(value)
    if origin is None:
        return None
    _, host, port = origin
    return host, port


def host_authority(value: str) -> Authority | None:
    """Parse a Host-header authority ('host' or 'host:port') into (host, port), or None.

    The Host header is best-effort: a non-numeric port leaves a usable hostname,
    so the port falls back to None rather than discarding the whole authority. An
    unbalanced IPv6 bracket makes ``urlsplit`` raise and is unrecoverable.
    """
    try:
        split = urlsplit(f"//{value}")
    except ValueError:
        return None
    if not split.hostname:
        return None
    try:
        port = split.port
    except ValueError:
        port = None
    return split.hostname.lower(), port
