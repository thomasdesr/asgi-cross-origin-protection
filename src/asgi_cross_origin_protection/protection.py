"""Cross-origin request protection (CSRF defense) as raw ASGI middleware.

Depends only on the standard library; works with any ASGI framework (Starlette,
FastAPI, Litestar, Quart, Django-ASGI, ...).
"""

import json
from collections.abc import Sequence
from urllib.parse import urlsplit

from asgi_cross_origin_protection._types import ASGIApp, Receive, Scope, Send
from asgi_cross_origin_protection.origins import Origin, normalize_origin, origin_tuple


class CrossOriginProtection:
    """Deny cross-site state-changing requests (CSRF defense).

    A plain ASGI middleware: ``app = CrossOriginProtection(app, ...)``. The
    default policy is safe for most apps with no configuration.

    Decision order (first conclusive signal wins):

    1. Fetch Metadata (``Sec-Fetch-Site``): ``same-origin``/``same-site``/
       ``none`` allowed, ``cross-site`` rejected.
    2. ``Origin`` compared against the request's own origin and
       ``allowed_origins``; ``Origin: null`` is rejected.
    3. Neither header present: allowed unless ``allow_unverifiable_requests``
       is cleared.

    Safe methods (GET/HEAD/OPTIONS/TRACE) are always allowed; rejection applies
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
            origin for value in allowed_origins if (origin := normalize_origin(value)) is not None
        }
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
        return any(path.startswith(prefix) for prefix in self.exempt_paths)

    def _is_blocked(self, scope: Scope) -> bool:
        method = scope["method"].upper()
        return self._is_cross_origin(scope) and method not in SAFE_METHODS

    def _is_cross_origin(self, scope: Scope) -> bool:
        metadata_verdict = self._allows_via_fetch_metadata(scope)
        if metadata_verdict is not None:
            return not metadata_verdict

        header_verdict = self._allows_via_origin_headers(scope)
        if header_verdict is not None:
            return not header_verdict

        # Origin can't be verified: allow unless the caller opted out.
        return not self.allow_unverifiable_requests

    def _allows_via_fetch_metadata(self, scope: Scope) -> bool | None:
        site = _get_header(scope["headers"], b"sec-fetch-site")
        if not site:
            return None
        site = site.lower()

        if site in {"same-origin", "same-site", "none"}:
            return True
        if site == "cross-site":
            return False
        return None

    def _allows_via_origin_headers(self, scope: Scope) -> bool | None:
        origin_header = _get_header(scope["headers"], b"origin")
        if not origin_header:
            return None
        if origin_header == "null":
            # The opaque origin (sandboxed iframes, file://, some redirects) is
            # never trusted. normalize_origin also maps "null" to None today, so
            # this is currently redundant, but it keeps the rejection explicit
            # and independent of how the parser treats non-URL tokens.
            return False
        origin = normalize_origin(origin_header)
        if origin is None:
            return False
        return origin in self.allowed_origins or origin == _request_origin(scope)


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def _get_header(headers: Sequence[tuple[bytes, bytes]], name: bytes) -> str | None:
    """First value for a lowercased header name, decoded as latin-1, or None."""
    for key, value in headers:
        if key == name:
            return value.decode("latin-1")
    return None


def _request_origin(scope: Scope) -> Origin:
    """Origin the request was served from, from the Host header or the ASGI server."""
    scheme = scope.get("scheme", "http")

    host_header = _get_header(scope["headers"], b"host")
    if host_header:
        origin = _origin_from_authority(scheme, host_header)
        if origin is not None:
            return origin

    server = scope.get("server")
    if server:
        host, port = server
        origin = origin_tuple(scheme, host, port)
        if origin is not None:
            return origin

    return (scheme.lower(), "", 80)


def _origin_from_authority(scheme: str, authority: str) -> Origin | None:
    """Parse a Host-header authority into an origin, or None if unusable.

    An unbalanced IPv6 bracket makes ``urlsplit`` raise; a non-numeric port
    makes ``.port`` raise. The first is unrecoverable; the second still leaves a
    usable hostname, so the port falls back to the scheme default.
    """
    try:
        split = urlsplit(f"//{authority}")
    except ValueError:
        return None
    try:
        port = split.port
    except ValueError:
        port = None
    return origin_tuple(scheme, split.hostname, port)


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
