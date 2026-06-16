# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `allowed_origins` is now honored regardless of Fetch Metadata. A trusted
  origin was only consulted in the Origin fallback, so a configured partner's
  cross-site request (which modern browsers label `Sec-Fetch-Site: cross-site`)
  was rejected.
- An empty `Origin` header is treated as absent (allowed by default) rather than
  as a mismatching origin that gets rejected.
- An empty or non-absolute `exempt_paths` entry now raises at construction; an
  empty entry previously matched every path and silently disabled all protection.

### Changed

- The same-origin self-check is now scheme-blind, comparing authority (host and
  port) rather than the full origin. The request's own scheme is unreliable
  behind a TLS-terminating proxy, so comparing it falsely rejected legitimate
  requests; this matches Go's `net/http` and relies on HSTS.
- A present `Sec-Fetch-Site` is conclusive: only `same-origin`/`none` are
  allowed, and `same-site`, `cross-site`, and unrecognized values are rejected
  without falling through to the Origin check. Matches Go's `net/http`.
- Safe methods are `GET`/`HEAD`/`OPTIONS` (`TRACE` dropped), matching Go's
  `net/http`.
- `exempt_paths` match on path-segment boundaries rather than a bare string
  prefix, so `/health` does not also exempt `/healthcheck`.
- Invalid `allowed_origins` entries raise `InvalidTrustedOriginError` (a
  `ValueError`) at construction rather than being silently dropped; entries
  carrying a path, query, or fragment are rejected.

## [0.1.0]

### Added

- `CrossOriginProtection` ASGI middleware: rejects cross-site state-changing
  requests (CSRF defense) via Fetch Metadata with an Origin fallback. Safe by
  default with no configuration; `allowed_origins`, `exempt_paths`, `deny_app`,
  and `allow_unverifiable_requests` adjust the policy.
- `CrossOriginIsolation` ASGI middleware: sets COOP/COEP/CORP response headers,
  each configurable and skippable.
- Pure ASGI with no dependencies.
