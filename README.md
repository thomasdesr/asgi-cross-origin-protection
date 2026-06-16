# asgi-cross-origin-protection

Cross-origin request protection ASGI middleware. It rejects cross-site
state-changing requests (CSRF defense) by inspecting Fetch Metadata headers,
with an Origin fallback. It needs no CSRF tokens or session state. The defaults
are safe for most apps without configuration.

Pure ASGI with no dependencies: works with Starlette, FastAPI,
Litestar, Quart, Django-ASGI, or any other ASGI app.

## Install

```bash
uv add asgi-cross-origin-protection
```

## Usage

Wrap your app. For most apps this is all you need:

```python
from asgi_cross_origin_protection import CrossOriginProtection

app = CrossOriginProtection(app)
```

With Starlette/FastAPI's `add_middleware`:

```python
from fastapi import FastAPI
from asgi_cross_origin_protection import CrossOriginProtection

app = FastAPI()
app.add_middleware(CrossOriginProtection)
```

The default policy rejects cross-site requests that change state, while
allowing same-origin requests, non-browser clients (mobile apps, CLIs,
server-to-server), and inbound links. A cross-site attacker cannot forge the
`Sec-Fetch-Site` header or strip `Origin` from a browser request, so the CSRF
vector is still closed.

## When to change the defaults

You only need to touch configuration if one of these applies:

| If your app… | Set |
|--------------|-----|
| trusts specific partner origins | `allowed_origins=("https://partner.example",)` |
| has paths that must skip the check (health probes, webhooks) | `exempt_paths=("/healthz",)` |
| should return something other than the default 403 JSON | `deny_app=...` (see below) |

```python
app = CrossOriginProtection(
    app,
    allowed_origins=("https://app.example.com",),
    exempt_paths=("/healthz",),
)
```

### Custom rejection response

`deny_app` is any ASGI app. Starlette/FastAPI `Response` instances are
themselves ASGI apps, so you can pass one directly:

```python
from starlette.responses import PlainTextResponse

app = CrossOriginProtection(
    app,
    deny_app=PlainTextResponse("forbidden", status_code=403),
)
```

## How it decides

A request is evaluated in this order; the first conclusive signal wins:

1. **Fetch Metadata**: `Sec-Fetch-Site` of `same-origin`, `same-site`, or
   `none` is allowed; `cross-site` is rejected.
2. **Origin header**: compared against the request's own origin and any
   `allowed_origins`. `Origin: null` is rejected.
3. **Neither header present**: allowed unless `allow_unverifiable_requests`
   is cleared.

Safe methods (GET/HEAD/OPTIONS/TRACE) are always allowed; rejection applies to
state-changing methods.

### Hardening

`allow_unverifiable_requests` (default `True`) governs requests that carry
neither `Sec-Fetch-Site` nor `Origin`, so their origin cannot be checked. These
are typically non-browser clients (mobile apps, CLIs, server-to-server). They
are allowed by default because a browser CSRF attempt always carries one of
those headers. Set it to `False` only if your app serves browsers exclusively
and you want to reject everything else:

```python
app = CrossOriginProtection(app, allow_unverifiable_requests=False)
```

## Cross-origin isolation headers

COOP/COEP/CORP isolation headers are a separate, optional middleware. Most apps
do not need them. Reach for `CrossOriginIsolation` when you specifically want
cross-origin isolation, for example to enable `crossOriginIsolated` and APIs
like `SharedArrayBuffer`:

```python
from asgi_cross_origin_protection.isolation import CrossOriginIsolation

app = CrossOriginIsolation(app)
```

Each policy is added only when the wrapped app did not already set that header.
Pass `None` for a policy to leave its header alone. Defaults: COOP `same-origin`,
COEP `require-corp`, CORP `same-site`.

Compose both middlewares when you want protection and isolation together.

## Development

```bash
make dev     # sync dependencies and install the prek git hook
make lint    # run all checks via prek (ruff, ty, zizmor)
make test    # pytest (100% coverage gate)
```

The same prek hooks run automatically on every commit; `make lint` runs them
across all files on demand.

## Influences

- Go's [`net/http.CrossOriginProtection`](https://pkg.go.dev/net/http#CrossOriginProtection),
  whose API and safe-by-default policy this package mirrors.
- Filippo Valsorda's [Cross-Site Request Forgery](https://words.filippo.io/csrf/),
  the reasoning behind that design.
- [XS-Leaks Wiki](https://xsleaks.dev/), background on the cross-site leak
  classes the isolation headers help defend against.
