"""Cross-origin request protection ASGI middleware.

Rejects cross-site state-changing requests (CSRF defense) using Fetch Metadata
(``Sec-Fetch-Site``) with an Origin fallback. Depends only on the standard
library.

For most apps, the zero-config default is all you need::

    from asgi_cross_origin_protection import CrossOriginProtection

    app = CrossOriginProtection(app)
"""

from asgi_cross_origin_protection._types import ASGIApp
from asgi_cross_origin_protection.protection import CrossOriginProtection

__all__ = ["ASGIApp", "CrossOriginProtection"]
