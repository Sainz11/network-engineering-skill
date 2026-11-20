"""Policy types for the AI Network Operations Assistant.

UserContext here is a compatibility shim that accepts both:
- the immutable auth_provider.UserContext (frozen dataclass with FrozenSet scopes), and
- plain dicts / legacy dataclasses used in existing tests.

OperationRequest accepts any object that exposes `.username`, `.role`, and `.authorized_scopes`.
Callers that use the CLI always receive the auth_provider.UserContext.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union, FrozenSet
import datetime

# Imported only for identity-type discrimination; auth_provider does not import
# from this module, so there is no circular-import risk.
from engine.auth_provider import UserContext as _AuthUserContext, verify_issued_context


class OperationClassification(str, Enum):
    READ_ONLY = "READ_ONLY"
    DIAGNOSTIC = "DIAGNOSTIC"
    WRITE = "WRITE"
    CRITICAL = "CRITICAL"


class ExecutionMode(str, Enum):
    LIVE = "LIVE"
    SIMULATED = "SIMULATED"
    DRY_RUN = "DRY_RUN"


@dataclass
class UserContext:
    """Mutable UserContext for internal policy engine use.

    When the CLI is used, an immutable auth_provider.UserContext is supplied instead.
    Both expose the same interface: .username, .role, .authorized_scopes, .has_scope().

    PRODUCTION IDENTITY REQUIREMENT:
    - In production (non-dev environments), only the immutable
      auth_provider.UserContext (frozen dataclass) is trusted as an authenticated
      identity.
    - This mutable shim is acceptable only in development mode (is_dev_mode=True)
      and MUST NOT be used as proof of authentication in production.
    - Callers must verify is_dev_mode == True before accepting this context as an
      authenticated identity; otherwise reject it as unauthenticated.
    """
    username: str
    role: str
    authorized_scopes: Union[List[str], FrozenSet[str]] = field(
        default_factory=lambda: ["READ_ONLY"]
    )
    session_id: Optional[str] = None
    is_dev_mode: bool = False
    authorized_devices: Union[List[str], FrozenSet[str]] = field(
        default_factory=lambda: ["*"]
    )

    def has_scope(self, scope: str) -> bool:
        return scope in self.authorized_scopes

    def can_access_device(self, device_id: str) -> bool:
        if "*" in self.authorized_devices:
            return True
        return device_id.upper() in {d.upper() for d in self.authorized_devices}


def is_production_identity(user_ctx: Any) -> bool:
    """Return True only if *user_ctx* is a genuine authenticated identity issued by AuthProvider.

    A forged UserContext or directly instantiated dataclass without valid cryptographic
    issuer proof will be rejected.
    """
    if isinstance(user_ctx, _AuthUserContext):
        return verify_issued_context(user_ctx)
    return False


@dataclass
class TargetDevice:
    device_id: str
    hostname: str
    ip_address: str
    vendor: str
    model: str
    device_category: str = "UNKNOWN"
    port: int = 22
    protocol: str = "ssh"       # ssh, rest, snmp
    credentials_ref: Optional[str] = None
    firmware_version: Optional[str] = None
    environment: str = "PRODUCTION"  # PRODUCTION, STAGING, LAB


@dataclass
class OperationRequest:
    request_id: str
    user: Any          # accepts auth_provider.UserContext or policy.types.UserContext
    device: TargetDevice
    classification: OperationClassification
    action: str
    command: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    execution_mode: ExecutionMode = ExecutionMode.LIVE
    approved: bool = False
    approval_token: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())


@dataclass
class ExecutionResult:
    request_id: str
    success: bool
    classification: OperationClassification
    mode: ExecutionMode
    output: Any
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    redacted: bool = True
    rollback_plan: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    status: str = "COMPLETED"
