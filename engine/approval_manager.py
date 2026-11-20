"""Fail-closed adapter for an externally trusted change-approval provider.

No production provider is bundled. This manager only delegates verification to
an explicitly injected provider or verification callable; policy enforcement
still validates every returned claim against the exact request and diff.
"""
from __future__ import annotations

from typing import Any, Callable, Optional


class ApprovalManager:
    def __init__(self, provider: Optional[Any] = None, verifier: Optional[Callable[..., Any]] = None):
        if provider is not None and verifier is not None:
            raise ValueError("Configure either an approval provider or verifier, not both.")
        if provider is not None and not callable(getattr(provider, "verify", None)):
            raise TypeError("Approval provider must expose a callable verify(**claims) method.")
        if verifier is not None and not callable(verifier):
            raise TypeError("Approval verifier must be callable.")
        self.provider = provider
        self.verifier = verifier

    @property
    def is_configured(self) -> bool:
        return self.provider is not None or self.verifier is not None

    def verify(self, **claims: Any) -> Any:
        """Return provider evidence; missing provider or provider errors fail closed."""
        if self.provider is not None:
            return self.provider.verify(**claims)
        if self.verifier is not None:
            return self.verifier(**claims)
        return None
