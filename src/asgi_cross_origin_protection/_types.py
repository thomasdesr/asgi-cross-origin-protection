"""Shared ASGI type aliases (no logic, no I/O)."""

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, TypeAlias

Scope: TypeAlias = MutableMapping[str, Any]
Message: TypeAlias = MutableMapping[str, Any]
Receive: TypeAlias = Callable[[], Awaitable[Message]]
Send: TypeAlias = Callable[[Message], Awaitable[None]]
ASGIApp: TypeAlias = Callable[[Scope, Receive, Send], Awaitable[None]]
