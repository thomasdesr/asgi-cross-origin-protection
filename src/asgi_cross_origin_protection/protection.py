"""Cross-origin request protection (CSRF defense) as raw ASGI middleware.

Depends only on the standard library; works with any ASGI framework (Starlette,
FastAPI, Litestar, Quart, Django-ASGI, ...).
"""

import json
from collections.abc import Sequence

from asgi_cross_origin_protection._types import ASGIApp, Receive, Scope, Send
from asgi_cross_origin_protection.origins import (
    Authority,
    Origin,
    host_authority,
    normalize_origin,
    parse_trusted_origin,
)


class InvalidExemptPathError(ValueError):
    """An ``exempt_paths`` entry is not an absolute path.

    Raised at construction. It signals a misconfiguration to fix, not a runtime
    condition to catch and recover from; it subclasses ``ValueError`` so config
    loaders that validate untrusted input can still handle it.
    """

    def __init__(self, value: str) -> None:
        super().__init__(
            f"invalid exempt_paths entry {value!r}: must be an absolute path starting "
            "with '/' (an empty prefix would match every path)"
        )


class CrossOriginProtection:
    """Deny cross-site state-changing requests (CSRF defense).

    A plain ASGI middleware: ``app = CrossOriginProtection(app, ...)``. The
    default policy is safe for most apps with no configuration.

    Decision order (first conclusive signal wins):

    1. ``allowed_origins``: an ``Origin`` in this set is allowed regardless of
       Fetch Metadata, so a trusted partner's cross-site request passes.
    2. Fetch Metadata (``Sec-Fetch-Site``): only ``same-origin``/``none`` are
       allowed; ``same-site``, ``cross-site``, and any unrecognized value are
       rejected (a present header is conclusive — the Origin step is skipped).
    3. ``Origin`` compared (scheme-blind, by authority) against the request's
       own host; ``Origin: null`` and unparseable values are rejected.
    4. Neither header present: allowed unless ``allow_unverifiable_requests``
       is cleared.

    Safe methods (GET/HEAD/OPTIONS) are always allowed; rejection applies
    to state-changing methods. Rejections invoke ``deny_app`` (default: a 403
    JSON response). Because Starlette/FastAPI ``Response`` instances are
    themselves ASGI apps, you can pass one directly.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_origins: Sequence[str] = (),
        exempt_paths: Sequence[str] = (),
        deny_app: ASGIApp | None = None,
        allow_unverifiable_requests: bool = True,
    ) -> None:
        self.app = app
        self.allowed_origins: set[Origin] = {
            parse_trusted_origin(value) for value in allowed_origins
        }
        for prefix in exempt_paths:
            if not prefix.startswith("/"):
                raise InvalidExemptPathError(prefix)
        self.exempt_paths = tuple(exempt_paths)
        self.deny_app = deny_app or _default_deny
        self.allow_unverifiable_requests = allow_unverifiable_requests

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if not self._is_exempt(scope) and self._is_blocked(scope):
            await self.deny_app(scope, receive, send)
            return

        await self.app(scope, receive, send)

    def _is_exempt(self, scope: Scope) -> bool:
        path = scope.get("path", "")
        return any(_path_within(path, prefix) for prefix in self.exempt_paths)

    def _is_blocked(self, scope: Scope) -> bool:
        # Method first: safe methods are always allowed, so skip the header
        # inspection entirely for them (the common GET path does no parsing).
        method = scope["method"].upper()
        return method not in SAFE_METHODS and self._is_cross_origin(scope)

    def _is_cross_origin(self, scope: Scope) -> bool:
        origin_header = _get_header(scope["headers"], b"origin")
        # Parsed once and reused below. An empty Origin carries nothing to check
        # and is treated as absent (allowed by default); a present but
        # unparseable or opaque ("null") Origin parses to None and matches nothing.
        origin = normalize_origin(origin_header) if origin_header else None

        # Trusted origins override Fetch Metadata: a configured partner is allowed
        # even when the browser reports the request as cross-site.
        if origin is not None and origin in self.allowed_origins:
            return False

        metadata_verdict = self._allows_via_fetch_metadata(scope)
        if metadata_verdict is not None:
            return not metadata_verdict

        if origin_header:
            # Present Origin: same-origin only when its authority matches the
            # request's own. Scheme-blind (scope["scheme"] is unreliable behind a
            # TLS-terminating proxy). A None parse (unparseable/null) never matches.
            if origin is None:
                return True
            _, host, port = origin
            return (host, port) != _request_authority(scope)

        # Origin absent: can't be verified, allow unless the caller opted out.
        return not self.allow_unverifiable_requests

    def _allows_via_fetch_metadata(self, scope: Scope) -> bool | None:
        site = _get_header(scope["headers"], b"sec-fetch-site")
        if not site:
            return None
        # Only first-party values are allowed. same-site, cross-site, and any
        # unrecognized value are rejected: a present Sec-Fetch-Site is conclusive
        # and the Origin step is not consulted. Matches Go's net/http, which
        # allows only same-origin/none and rejects every other non-empty value.
        return site.lower() in _FETCH_METADATA_ALLOWED


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_FETCH_METADATA_ALLOWED = frozenset({"same-origin", "none"})


def _path_within(path: str, prefix: str) -> bool:
    """True when path equals prefix or lies under it at a path-segment boundary.

    ``/health`` exempts ``/health`` and ``/health/status`` but not
    ``/healthcheck``: matching is on segment boundaries, not a bare string prefix.
    """
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _get_header(headers: Sequence[tuple[bytes, bytes]], name: bytes) -> str | None:
    """First value for a lowercased header name, decoded as latin-1, or None."""
    for key, value in headers:
        if key == name:
            return value.decode("latin-1")
    return None


def _request_authority(scope: Scope) -> Authority | None:
    """(host, port) the request was served on, from the Host header or ASGI server.

    Scheme-blind: the self-check compares authority alone, so the scheme is not
    derived here. Returns None when no host can be determined.
    """
    host_header = _get_header(scope["headers"], b"host")
    if host_header:
        authority = host_authority(host_header)
        if authority is not None:
            return authority

    server = scope.get("server")
    if server:
        host, port = server
        if host:
            return host.lower(), port

    return None


async def _default_deny(_scope: Scope, _receive: Receive, send: Send) -> None:
    body = json.dumps({"detail": "Cross-origin request rejected by middleware."}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
