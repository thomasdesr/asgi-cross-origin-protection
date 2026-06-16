import httpx
import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from asgi_cross_origin_protection import CrossOriginProtection
from asgi_cross_origin_protection._types import Receive, Scope, Send
from asgi_cross_origin_protection.origins import origin_authority
from asgi_cross_origin_protection.protection import _path_within, _request_authority


async def echo_app(scope: Scope, receive: Receive, send: Send) -> None:
    """Minimal raw-ASGI app: 200 OK with a text body, regardless of path."""
    assert scope["type"] == "http"
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
    await send({"type": "http.response.body", "body": b"ok"})


def client(**kwargs) -> httpx.AsyncClient:
    app = CrossOriginProtection(echo_app, **kwargs)
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def status_for_scope(method: str, raw_headers: list[tuple[bytes, bytes]], **kwargs) -> int:
    """Drive the middleware with hand-built raw ASGI headers; return the response status.

    Goes below the HTTP client so header values an HTTP client would normalize or
    drop (e.g. an empty Origin) reach the middleware verbatim.
    """
    app = CrossOriginProtection(echo_app, **kwargs)
    scope = {
        "type": "http",
        "method": method,
        "path": "/echo",
        "scheme": "http",
        "headers": [(b"host", b"testserver"), *raw_headers],
        "server": ("testserver", 80),
    }
    sent: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


# --- Fetch Metadata ---------------------------------------------------------


@pytest.mark.parametrize(
    ("site", "status"),
    [
        pytest.param("same-origin", 200, id="same-origin"),
        pytest.param("same-site", 403, id="same-site"),
        pytest.param("none", 200, id="none"),
        pytest.param("cross-site", 403, id="cross-site"),
    ],
)
async def test_fetch_metadata_decides_regardless_of_origin(site, status):
    # A conclusive Sec-Fetch-Site wins over the Origin header. The cross-origin
    # Origin would flip the verdict if Sec-Fetch-Site were ignored, so this pins
    # both the token mapping and its precedence over the Origin step.
    async with client() as c:
        response = await c.post(
            "/echo",
            headers={"Sec-Fetch-Site": site, "Origin": "http://evil.test"},
        )
    assert response.status_code == status


async def test_fetch_site_value_is_case_insensitive():
    async with client() as c:
        response = await c.post("/echo", headers={"Sec-Fetch-Site": "Cross-Site"})
    assert response.status_code == 403


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
async def test_cross_site_safe_method_always_allowed(method):
    async with client() as c:
        response = await c.request(method, "/echo", headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 200


async def test_cross_site_trace_blocked():
    # TRACE is not a safe method (matching Go net/http, which only exempts
    # GET/HEAD/OPTIONS); a cross-origin TRACE is a state-changing request here.
    async with client() as c:
        response = await c.request("TRACE", "/echo", headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403


async def test_unknown_fetch_site_rejected_even_for_same_origin():
    # A present-but-unrecognized Sec-Fetch-Site is conclusive and rejects: it is
    # never sent by a real browser, so a matching Origin does not rescue it. This
    # matches Go's net/http, which treats every non-empty value other than
    # same-origin/none as cross-origin without consulting the Origin header.
    async with client() as c:
        response = await c.post(
            "/echo",
            headers={"Sec-Fetch-Site": "garbage", "Origin": "http://testserver"},
        )
    assert response.status_code == 403


# --- Origin header ----------------------------------------------------------


async def test_origin_header_same_origin_allowed():
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "http://testserver"})
    assert response.status_code == 200


async def test_origin_header_cross_origin_blocked():
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "http://evil.test"})
    assert response.status_code == 403


async def test_cross_scheme_same_host_origin_allowed():
    # The request's own scheme is not reliable behind a TLS-terminating proxy
    # (scope["scheme"] stays "http"), so the self-check is scheme-blind and
    # matches on authority alone. An https Origin against the http test request
    # is treated as same-origin (matching Go; relies on HSTS).
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "https://testserver"})
    assert response.status_code == 200


async def test_malformed_origin_blocked():
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "not-a-url"})
    assert response.status_code == 403


async def test_null_origin_blocked():
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "null"})
    assert response.status_code == 403


async def test_empty_origin_header_treated_as_unverifiable():
    # An empty Origin value carries no origin to check, so it is treated like an
    # absent header (allowed by default), not like a mismatching origin. Go's
    # net/http does the same: `if origin == "" { return nil }`.
    assert await status_for_scope("POST", [(b"origin", b"")]) == 200


async def test_empty_origin_header_blocked_when_unverifiable_opt_out():
    assert (
        await status_for_scope("POST", [(b"origin", b"")], allow_unverifiable_requests=False) == 403
    )


async def test_allowed_origins_whitelist_overrides_cross_origin_block():
    async with client(allowed_origins=["https://allowed.example", "http://testserver"]) as c:
        response = await c.post("/echo", headers={"Origin": "https://allowed.example"})
    assert response.status_code == 200


async def test_allowed_origin_trusted_even_when_cross_site():
    # A configured partner origin is honored regardless of Fetch Metadata. Modern
    # browsers label a genuine cross-origin request "cross-site", and a trusted
    # origin must still pass (Go checks trusted origins in the cross-site branch).
    async with client(allowed_origins=["https://partner.example"]) as c:
        response = await c.post(
            "/echo",
            headers={"Sec-Fetch-Site": "cross-site", "Origin": "https://partner.example"},
        )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "bad",
    [
        "not-a-url",  # no scheme
        "https://",  # no host
        "https://x.example/path",  # path not allowed
        "https://x.example/",  # trailing slash is a path
        "https://x.example?q=1",  # query not allowed
        "https://x.example#frag",  # fragment not allowed
        "https://x.example:bogus",  # non-numeric port
    ],
)
def test_invalid_allowed_origin_raises(bad):
    # Configuration errors are loud (unlike malformed request headers, which are
    # simply not trusted). Raised as a ValueError at construction; the consumer
    # who validates dynamic config catches ValueError, not a specific subclass.
    with pytest.raises(ValueError, match="invalid trusted origin"):
        CrossOriginProtection(echo_app, allowed_origins=[bad])


# --- Unverifiable requests (allowed by default, matching Go) ----------------


async def test_unverifiable_request_allowed_by_default():
    async with client() as c:
        response = await c.post("/echo")
    assert response.status_code == 200


async def test_unverifiable_request_denied_when_opted_out():
    async with client(allow_unverifiable_requests=False) as c:
        response = await c.post("/echo")
    assert response.status_code == 403


async def test_unverifiable_opt_out_still_allows_safe_methods():
    async with client(allow_unverifiable_requests=False) as c:
        response = await c.get("/echo")
    assert response.status_code == 200


# --- Exemptions and custom deny ---------------------------------------------


@pytest.mark.parametrize("bad", ["", "health", "health/live"])
def test_invalid_exempt_path_rejected(bad):
    # An empty or non-absolute exempt path is a configuration error. An empty
    # entry is the dangerous case: it would match every path and disable all
    # protection. Reject loudly at construction, like allowed_origins.
    with pytest.raises(ValueError, match="exempt_paths"):
        CrossOriginProtection(echo_app, exempt_paths=[bad])


async def test_exempt_path_bypasses_checks():
    async with client(exempt_paths=("/health",)) as c:
        response = await c.post("/health/status", headers={"Origin": "http://evil.test"})
    assert response.status_code == 200


async def test_exempt_path_exact_match():
    async with client(exempt_paths=("/health",)) as c:
        response = await c.post("/health", headers={"Origin": "http://evil.test"})
    assert response.status_code == 200


async def test_exempt_path_matches_on_segment_boundary_only():
    # "/health" exempts "/health" and "/health/..." but NOT "/healthcheck":
    # matching is on a path-segment boundary, not a bare string prefix, so a
    # sibling path sharing a prefix is not accidentally exempted.
    async with client(exempt_paths=("/health",)) as c:
        response = await c.post("/healthcheck", headers={"Origin": "http://evil.test"})
    assert response.status_code == 403


@given(
    prefix=st.text(st.characters(blacklist_characters="/"), min_size=1).map(lambda s: "/" + s),
    suffix=st.text(st.characters(blacklist_characters="/"), min_size=1),
)
def test_path_within_never_matches_partial_segment(prefix, suffix):
    # A child only counts when the extra characters begin a new segment, so a
    # path that merely shares `prefix` as a character-prefix is never exempt.
    assert _path_within(prefix, prefix)
    assert _path_within(prefix + "/" + suffix, prefix)
    assert not _path_within(prefix + suffix, prefix)


async def test_default_deny_response_is_json():
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "http://evil.test"})
    assert response.status_code == 403
    assert response.headers["content-type"] == "application/json"
    assert int(response.headers["content-length"]) == len(response.content)
    assert response.json() == {"detail": "Cross-origin request rejected by middleware."}


async def test_custom_deny_app():
    async def deny(scope: Scope, receive: Receive, send: Send) -> None:
        body = b'{"why": "nope"}'
        await send(
            {
                "type": "http.response.start",
                "status": 418,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async with client(deny_app=deny) as c:
        response = await c.post("/echo", headers={"Origin": "http://evil.test"})
    assert response.status_code == 418
    assert response.json() == {"why": "nope"}


async def test_non_http_scope_passes_through_untouched():
    seen: dict[str, str] = {}

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        seen["type"] = scope["type"]

    async def receive() -> dict[str, str]:
        return {}

    async def send(message: dict[str, str]) -> None:
        return

    middleware = CrossOriginProtection(app)
    await middleware({"type": "lifespan"}, receive, send)
    assert seen["type"] == "lifespan"


# --- _request_authority -----------------------------------------------------


def test_request_authority_from_host_header():
    scope = {"type": "http", "headers": [(b"host", b"example.com:8443")]}
    assert _request_authority(scope) == ("example.com", 8443)


def test_request_authority_falls_back_to_server():
    scope = {"type": "http", "headers": [], "server": ("example.com", 8080)}
    assert _request_authority(scope) == ("example.com", 8080)


def test_request_authority_invalid_port_in_host_drops_port():
    # A non-numeric port leaves a usable hostname; the port falls back to None
    # rather than discarding the whole authority.
    scope = {"type": "http", "headers": [(b"host", b"example.com:bogus")]}
    assert _request_authority(scope) == ("example.com", None)


def test_request_authority_no_host_no_server():
    scope = {"type": "http", "headers": []}
    assert _request_authority(scope) is None


def test_request_authority_malformed_host_does_not_raise():
    # An unbalanced IPv6 bracket makes urlsplit raise ValueError; the Host
    # header is client-controlled, so this must not crash the middleware.
    scope = {"type": "http", "headers": [(b"host", b"[::1")]}
    assert _request_authority(scope) is None


@given(host=st.binary(max_size=64))
def test_request_authority_never_raises_on_arbitrary_host_bytes(host):
    # Any client-supplied Host bytes must yield an authority or None, never raise.
    scope = {"type": "http", "headers": [(b"host", host)]}
    result = _request_authority(scope)
    assert result is None or (
        isinstance(result[0], str) and (result[1] is None or isinstance(result[1], int))
    )


# The Host header (parsed by host_authority) and the Origin header (parsed by
# origin_authority) must produce the same authority for the same input, or
# same-origin requests would be wrongly rejected. The match is scheme-blind, so
# the Origin's scheme must not affect the result.
_hostnames = st.from_regex(
    r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,15})(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,15})){0,2}",
    fullmatch=True,
)


@given(
    scheme=st.sampled_from(["http", "https"]),
    host=_hostnames,
    port=st.none() | st.integers(min_value=1, max_value=65535),
)
@example(scheme="http", host="[::1]", port=8080)
@example(scheme="https", host="Example.COM", port=None)
def test_request_authority_agrees_with_origin_authority(scheme, host, port):
    authority = host if port is None else f"{host}:{port}"
    scope = {"type": "http", "headers": [(b"host", authority.encode())]}
    assert _request_authority(scope) == origin_authority(f"{scheme}://{authority}")
