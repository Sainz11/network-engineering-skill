"""Authentication provider for the AI Network Operations Assistant.

Design principles:
- Identity is NEVER sourced from user-controllable CLI arguments.
- Development mode requires explicit AGY_ENV=dev opt-in; it never grants WRITE or CRITICAL.
- Production mode fails closed: it raises NotImplementedError until a real trusted provider
  (LDAP, OAuth2, service-account token, etc.) is integrated.
- AGY_USER is treated ONLY as a development identity selector, NOT as proof of identity.
- UserContext produced here is immutable (frozen dataclass); callers cannot mutate scope.
"""

import os
import hmac
import hashlib
import secrets
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import FrozenSet, Optional, Any

# Issuer verifiers are stored as verification-only closures. Signing capability
# lives only on an instantiated LocalDevAuthProvider and can issue fixed-scope
# development contexts; no module-level signing key/API exists.
_ISSUER_VERIFIERS = {}

# Development and production allowed scopes
_DEV_DEFAULT_SCOPES: FrozenSet[str] = frozenset({"READ_ONLY"})
_DEV_DIAGNOSTIC_SCOPES: FrozenSet[str] = frozenset({"READ_ONLY", "DIAGNOSTIC"})
_PROD_READ_SCOPES: FrozenSet[str] = frozenset({"READ_ONLY"})
_PROD_NOC_SCOPES: FrozenSet[str] = frozenset({"READ_ONLY", "DIAGNOSTIC"})
_PROD_WRITE_SCOPES: FrozenSet[str] = frozenset({"READ_ONLY", "DIAGNOSTIC", "WRITE"})
_PROD_ADMIN_SCOPES: FrozenSet[str] = frozenset({"READ_ONLY", "DIAGNOSTIC", "WRITE", "CRITICAL"})

# ---------------------------------------------------------------------------
# Immutable UserContext
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UserContext:
    """Immutable, authenticated user context.

    Fields are set once by the AuthProvider and cannot be modified by callers.
    'authorized_scopes' is a frozenset so it cannot be mutated after construction.
    '_signature' cryptographically binds the context to the internal authentication provider.
    """
    username: str
    role: str
    authorized_scopes: FrozenSet[str]
    session_id: Optional[str] = None
    is_dev_mode: bool = False
    authorized_devices: FrozenSet[str] = frozenset()
    issuer_id: str = ""
    _signature: str = ""

    def has_scope(self, scope: str) -> bool:
        return scope in self.authorized_scopes

    def can_access_device(self, device_id: str) -> bool:
        """Device-level authorization check.

        If authorized_devices contains '*', access to all authorized inventory devices is allowed.
        Otherwise, device_id must be in authorized_devices.
        """
        if "*" in self.authorized_devices:
            return True
        return device_id.upper() in {d.upper() for d in self.authorized_devices}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _canonical_context_payload(
    username: str,
    role: str,
    scopes: FrozenSet[str],
    is_dev_mode: bool,
    session_id: Optional[str],
    authorized_devices: FrozenSet[str],
    issuer_id: str,
) -> bytes:
    """Serialize signed identity fields without coercing distinct values.

    None, empty strings, booleans, and other JSON types remain distinct. Set-like
    fields are sorted deterministically before serialization.
    """
    payload = {
        "username": username,
        "role": role,
        "authorized_scopes": sorted(scopes),
        "is_dev_mode": is_dev_mode,
        "session_id": session_id,
        "authorized_devices": sorted(authorized_devices),
        "issuer_id": issuer_id,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def verify_issued_context(user_ctx: Any) -> bool:
    """Verify that user_ctx is a genuine, tamper‑free UserContext issued by a trusted AuthProvider.

    Direct instantiation by an unauthorized caller will fail because the secret key
    is not accessible.
    """
    if not isinstance(user_ctx, UserContext):
        return False
    sig = getattr(user_ctx, "_signature", None)
    if not sig:
        return False
    try:
        payload = _canonical_context_payload(
            user_ctx.username,
            user_ctx.role,
            user_ctx.authorized_scopes,
            user_ctx.is_dev_mode,
            user_ctx.session_id,
            user_ctx.authorized_devices,
            user_ctx.issuer_id,
        )
        verifier = _ISSUER_VERIFIERS.get(user_ctx.issuer_id)
    except (TypeError, ValueError, AttributeError):
        return False
    return verifier is not None and verifier(payload, sig)

# ---------------------------------------------------------------------------
# AuthProvider interface
# ---------------------------------------------------------------------------

class AuthProvider(ABC):
    """Abstract authentication provider.

    Implementers must resolve the caller's identity from a trusted source
    (not from user‑supplied arguments) and return an immutable UserContext.
    """

    @abstractmethod
    def authenticate(self) -> UserContext:
        """Authenticate the current caller.

        Returns an immutable UserContext on success.
        Raises AuthenticationError on failure.
        """
        ...

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AuthenticationError(RuntimeError):
    """Raised when authentication fails or no trusted identity is available."""

class AuthorizationError(RuntimeError):
    """Raised when an authenticated user lacks the required scope."""

# ---------------------------------------------------------------------------
# LocalDevAuthProvider  (DEVELOPMENT ONLY)
# ---------------------------------------------------------------------------

class LocalDevAuthProvider(AuthProvider):
    """Development‑mode authentication provider.

    Active ONLY when AGY_ENV=dev is explicitly set.
    Reads AGY_USER as a development identity selector.
    Never grants WRITE or CRITICAL scopes.
    Must never be used in production.
    """

    def __init__(self):
        self.__issuer_id = secrets.token_hex(16)
        secret = secrets.token_bytes(32)

        # Signing capability is confined to this provider instance. The global
        # registry stores verification-only closures, never keys or signers.
        def sign(payload: bytes) -> str:
            return hmac.new(secret, payload, hashlib.sha256).hexdigest()

        def verify(payload: bytes, signature: str) -> bool:
            expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
            return isinstance(signature, str) and hmac.compare_digest(signature, expected)

        _ISSUER_VERIFIERS[self.__issuer_id] = verify
        self.__sign = sign

    def authenticate(self) -> UserContext:
        env = os.environ.get("AGY_ENV", "").strip().lower()
        if env != "dev":
            raise AuthenticationError(
                "LocalDevAuthProvider requires AGY_ENV=dev. "
                "Do not use development authentication in production."
            )

        username = os.environ.get("AGY_USER", "").strip()
        if not username:
            raise AuthenticationError(
                "AGY_USER must be set to a non‑empty development identity "
                "when using LocalDevAuthProvider (AGY_ENV=dev)."
            )

        # Reject obviously unsafe values
        if any(c in username for c in ("/", "\\", "..", "\x00", "@", " ")):
            raise AuthenticationError(
                f"AGY_USER contains disallowed characters: '{username}'."
            )

        role = "dev-read-only"

        # Explicit device authorization from AGY_DEV_DEVICES if set, otherwise default to inventory wildcard
        dev_devices_env = os.environ.get("AGY_DEV_DEVICES", "*").strip()
        dev_devices = frozenset([d.strip() for d in dev_devices_env.split(",") if d.strip()]) or frozenset({"*"})

        # Development defaults to READ_ONLY. DIAGNOSTIC is an explicit opt-in;
        # development mode can never escalate to WRITE/CRITICAL.
        diagnostic_opt_in = os.environ.get("AGY_DEV_DIAGNOSTIC", "").strip().casefold() in {"1", "true", "yes"}
        scopes = _DEV_DIAGNOSTIC_SCOPES if diagnostic_opt_in else _DEV_DEFAULT_SCOPES
        payload = _canonical_context_payload(username, role, scopes, True, None, dev_devices, self.__issuer_id)
        sig = self.__sign(payload)
        return UserContext(
            username=username,
            role=role,
            authorized_scopes=scopes,
            session_id=None,
            is_dev_mode=True,
            authorized_devices=dev_devices,
            issuer_id=self.__issuer_id,
            _signature=sig,
        )

# ---------------------------------------------------------------------------
# ProdAuthProvider  (PRODUCTION)
# ---------------------------------------------------------------------------

class ProdAuthProvider(AuthProvider):
    """Production authentication provider — FAIL CLOSED.

    This class acts as a mandatory placeholder until a real trusted provider
    (OAuth2 token introspection, LDAP, service‑account key, etc.) is integrated.
    It always raises NotImplementedError so that production deployments fail
    visibly rather than silently falling back to insecure development auth.
    """

    def authenticate(self) -> UserContext:
        raise NotImplementedError(
            "ProdAuthProvider is not yet implemented. "
            "Integrate a trusted authentication source (OAuth2, LDAP, service-account "
            "token, etc.) before deploying to production. "
            "The system cannot proceed without a verified identity."
        )

# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------

def get_auth_provider() -> AuthProvider:
    """Return the appropriate AuthProvider for the current environment.

    Uses AGY_ENV to select:
      - 'dev'  → LocalDevAuthProvider (requires AGY_USER)
      - anything else → ProdAuthProvider (fails closed)
    """
    env = os.environ.get("AGY_ENV", "").strip().lower()
    if env == "dev":
        return LocalDevAuthProvider()
    return ProdAuthProvider()

def authenticate_current_user() -> UserContext:
    """Authenticate the caller using the environment‑appropriate provider.

    This is the single entry point for identity resolution in the execution
    pipeline. Identity obtained here is immutable for the lifetime of the call.
    """
    provider = get_auth_provider()
    return provider.authenticate()
