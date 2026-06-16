import httpx

from asgi_cross_origin_protection._types import Receive, Scope, Send
from asgi_cross_origin_protection.isolation import CrossOriginIsolation


async def echo_app(scope: Scope, receive: Receive, send: Send) -> None:
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
    app = CrossOriginIsolation(echo_app, **kwargs)
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def test_default_isolation_headers_applied():
    async with client() as c:
        response = await c.get("/echo")
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-embedder-policy"] == "require-corp"
    assert response.headers["cross-origin-resource-policy"] == "same-site"


async def test_policy_values_are_configurable():
    async with client(
        opener_policy="same-origin-allow-popups", resource_policy="cross-origin"
    ) as c:
        response = await c.get("/echo")
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["cross-origin-resource-policy"] == "cross-origin"


async def test_none_policy_omits_that_header():
    async with client(embedder_policy=None) as c:
        response = await c.get("/echo")
    assert "cross-origin-embedder-policy" not in response.headers
    assert response.headers["cross-origin-opener-policy"] == "same-origin"


async def test_all_none_passes_through_without_wrapping():
    async with client(opener_policy=None, embedder_policy=None, resource_policy=None) as c:
        response = await c.get("/echo")
    assert "cross-origin-opener-policy" not in response.headers
    assert response.status_code == 200


async def test_does_not_override_existing_header():
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"cross-origin-opener-policy", b"unsafe-none")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    transport = httpx.ASGITransport(app=CrossOriginIsolation(app))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        response = await c.get("/echo")
    assert response.headers["cross-origin-opener-policy"] == "unsafe-none"
    assert response.headers["cross-origin-embedder-policy"] == "require-corp"


async def test_existing_header_not_duplicated_case_insensitively():
    # App sets a capitalized COOP; the middleware lowercases when checking
    # presence, so it must not emit a second cross-origin-opener-policy.
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"Cross-Origin-Opener-Policy", b"unsafe-none")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    transport = httpx.ASGITransport(app=CrossOriginIsolation(app))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        response = await c.get("/echo")
    assert response.headers.get_list("cross-origin-opener-policy") == ["unsafe-none"]


async def test_non_http_scope_passes_through_untouched():
    seen: dict[str, str] = {}

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        seen["type"] = scope["type"]

    async def receive() -> dict[str, str]:
        return {}

    async def send(message: dict[str, str]) -> None:
        return

    middleware = CrossOriginIsolation(app)
    await middleware({"type": "lifespan"}, receive, send)
    assert seen["type"] == "lifespan"
