"""Trusted approval provider contract. No concrete production provider is bundled."""
from typing import Any, Protocol


class ApprovalProvider(Protocol):
    def verify(self, **claims: Any) -> Any:
        """Verify requester, canonical target, exact diff, approval threshold and expiry."""
        ...
