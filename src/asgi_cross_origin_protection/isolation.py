"""Cross-origin isolation response headers (COOP/COEP/CORP) as ASGI middleware.

Separate from request protection: this only adds response headers that ask the
browser to isolate the document. It performs no request gating. Most apps do
not need it; reach for it when you specifically want cross-origin isolation
(for example, to enable ``crossOriginIsolated`` and powerful APIs like
``SharedArrayBuffer``).
"""

from asgi_cross_origin_protection._types import ASGIApp, Message, Receive, Scope, Send


class CrossOriginIsolation:
    """Add COOP/COEP/CORP headers to responses, without overriding existing ones.

    A plain ASGI middleware: ``app = CrossOriginIsolation(app, ...)``.

    Each policy is added only when the wrapped app did not already set that
    header. Pass ``None`` for a policy to leave that header alone.

    ``require-corp`` (the ``embedder_policy`` default) is breaking: a document
    carrying it can only load cross-origin subresources that themselves send
    ``Cross-Origin-Resource-Policy`` or CORS headers. That is inherent to
    cross-origin isolation; pass ``embedder_policy=None`` to opt out.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        opener_policy: str | None = "same-origin",
        embedder_policy: str | None = "require-corp",
        resource_policy: str | None = "same-site",
    ) -> None:
        self.app = app
        # Lowercased per the ASGI spec.
        policies = (
            (b"cross-origin-opener-policy", opener_policy),
            (b"cross-origin-embedder-policy", embedder_policy),
            (b"cross-origin-resource-policy", resource_policy),
        )
        self.headers: tuple[tuple[bytes, bytes], ...] = tuple(
            (name, value.encode("latin-1")) for name, value in policies if value is not None
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.headers:
            await self.app(scope, receive, send)
            return

        await self.app(scope, receive, self._wrap_send(send))

    def _wrap_send(self, send: Send) -> Send:
        async def send_with_isolation(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers: list[tuple[bytes, bytes]] = list(message.get("headers") or [])
                present = {name.lower() for name, _ in headers}
                headers.extend((name, value) for name, value in self.headers if name not in present)
                message = {**message, "headers": headers}
            await send(message)

        return send_with_isolation
