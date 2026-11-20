"""Credential provider contract. No concrete production provider is bundled."""
from typing import Any, Dict, Protocol


class CredentialProvider(Protocol):
    def get_credentials(self, credentials_ref: str, canonical_device: Any) -> Dict[str, Any]:
        """Resolve a credential reference from an external trusted secret store."""
        ...
