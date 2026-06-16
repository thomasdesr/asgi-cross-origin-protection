# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

### Added

- `CrossOriginProtection` ASGI middleware: rejects cross-site state-changing
  requests (CSRF defense) via Fetch Metadata with an Origin fallback. Safe by
  default with no configuration; `allowed_origins`, `exempt_paths`, `deny_app`,
  and `allow_unverifiable_requests` adjust the policy.
- `CrossOriginIsolation` ASGI middleware: sets COOP/COEP/CORP response headers,
  each configurable and skippable.
- Pure ASGI with no dependencies.
