import httpx
import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from asgi_cross_origin_protection import CrossOriginProtection
from asgi_cross_origin_protection._types import Receive, Scope, Send
from asgi_cross_origin_protection.origins import normalize_origin
from asgi_cross_origin_protection.protection import _request_origin


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


# --- Fetch Metadata ---------------------------------------------------------


@pytest.mark.parametrize(
    ("site", "status"),
    [
        pytest.param("same-origin", 200, id="same-origin"),
        pytest.param("same-site", 200, id="same-site"),
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


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "TRACE"])
async def test_cross_site_safe_method_always_allowed(method):
    async with client() as c:
        response = await c.request(method, "/echo", headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 200


async def test_unknown_fetch_site_falls_back_to_origin():
    async with client() as c:
        response = await c.post(
            "/echo",
            headers={"Sec-Fetch-Site": "garbage", "Origin": "http://testserver"},
        )
    assert response.status_code == 200


# --- Origin header ----------------------------------------------------------


async def test_origin_header_same_origin_allowed():
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "http://testserver"})
    assert response.status_code == 200


async def test_origin_header_cross_origin_blocked():
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "http://evil.test"})
    assert response.status_code == 403


async def test_cross_scheme_same_host_origin_blocked():
    # https://testserver is a different origin from the http://testserver request.
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "https://testserver"})
    assert response.status_code == 403


async def test_malformed_origin_blocked():
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "not-a-url"})
    assert response.status_code == 403


async def test_null_origin_blocked():
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "null"})
    assert response.status_code == 403


async def test_allowed_origins_whitelist_overrides_cross_origin_block():
    async with client(allowed_origins=["https://allowed.example", "http://testserver"]) as c:
        response = await c.post("/echo", headers={"Origin": "https://allowed.example"})
    assert response.status_code == 200


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


async def test_exempt_path_bypasses_checks():
    async with client(exempt_paths=("/health",)) as c:
        response = await c.post("/health/status", headers={"Origin": "http://evil.test"})
    assert response.status_code == 200


async def test_exempt_path_matches_by_prefix_not_segment():
    # "/health" also exempts "/healthcheck": this is a prefix match, not a
    # path-segment match. Documented here because it can surprise.
    async with client(exempt_paths=("/health",)) as c:
        response = await c.post("/healthcheck", headers={"Origin": "http://evil.test"})
    assert response.status_code == 200


async def test_default_deny_response_is_json():
    async with client() as c:
        response = await c.post("/echo", headers={"Origin": "http://evil.test"})
    assert response.status_code == 403
    assert response.headers["content-type"] == "application/json"
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


# --- _request_origin --------------------------------------------------------


def test_request_origin_from_host_header():
    scope = {"type": "http", "scheme": "https", "headers": [(b"host", b"example.com:8443")]}
    assert _request_origin(scope) == ("https", "example.com", 8443)


def test_request_origin_falls_back_to_server():
    scope = {"type": "http", "scheme": "https", "headers": [], "server": ("example.com", 8080)}
    assert _request_origin(scope) == ("https", "example.com", 8080)


def test_request_origin_invalid_port_in_host_defaults_port():
    scope = {"type": "http", "scheme": "http", "headers": [(b"host", b"example.com:bogus")]}
    assert _request_origin(scope) == ("http", "example.com", 80)


def test_request_origin_no_host_no_server():
    scope = {"type": "http", "scheme": "http", "headers": []}
    assert _request_origin(scope) == ("http", "", 80)


def test_request_origin_malformed_host_does_not_raise():
    # An unbalanced IPv6 bracket makes urlsplit raise ValueError; the Host
    # header is client-controlled, so this must not crash the middleware.
    scope = {"type": "http", "scheme": "http", "headers": [(b"host", b"[::1")]}
    assert _request_origin(scope) == ("http", "", 80)


@given(host=st.binary(max_size=64), scheme=st.sampled_from(["http", "https"]))
def test_request_origin_never_raises_on_arbitrary_host_bytes(host, scheme):
    # Any client-supplied Host bytes must yield a well-formed origin, never raise.
    scope = {"type": "http", "scheme": scheme, "headers": [(b"host", host)]}
    sch, hostname, port = _request_origin(scope)
    assert isinstance(sch, str)
    assert isinstance(hostname, str)
    assert isinstance(port, int)


# The Host header (parsed by urlsplit) and the Origin header (parsed by
# normalize_origin via urlparse) must produce the same origin for the same
# authority, or same-origin requests would be wrongly rejected.
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
def test_request_origin_agrees_with_normalize_origin(scheme, host, port):
    authority = host if port is None else f"{host}:{port}"
    scope = {"type": "http", "scheme": scheme, "headers": [(b"host", authority.encode())]}
    assert _request_origin(scope) == normalize_origin(f"{scheme}://{authority}")
