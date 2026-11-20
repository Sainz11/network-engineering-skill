"""engine.policy public API."""

from .types import (
    OperationClassification,
    ExecutionMode,
    UserContext,
    TargetDevice,
    OperationRequest,
    ExecutionResult,
    is_production_identity,
)
from .security_policy import SecurityPolicyEngine
from .audit import AuditLogger


def check_permission(user_ctx: UserContext, device_id: str, operation: str,
                     classification: OperationClassification = OperationClassification.DIAGNOSTIC) -> None:
    """Authorization check based on a genuine authenticated UserContext.

    Validates:
    1. Authenticated UserContext issued by trusted AuthProvider (fails on forged or raw context).
    2. Operation classification scope (e.g. DIAGNOSTIC).
    3. Device existence in inventory (rejects unknown devices).
    4. Explicit device-level authorization for the user (can_access_device).
    """
    # 1. Identity check
    if not hasattr(user_ctx, "has_scope") or not hasattr(user_ctx, "username"):
        raise TypeError(
            "check_permission requires an authenticated UserContext with "
            ".username and .has_scope() — a raw username string is not "
            "proof of authentication. Received: " + repr(user_ctx)
        )

    if not is_production_identity(user_ctx):
        raise PermissionError(
            f"User '{getattr(user_ctx, 'username', 'UNKNOWN')}' is not an "
            f"authenticated identity issued by a trusted AuthProvider. Forged or unverified contexts are rejected."
        )

    # 2. Scope check
    required_scope = classification.value
    if not user_ctx.has_scope(required_scope):
        raise PermissionError(
            f"User '{user_ctx.username}' lacks required scope '{required_scope}' "
            f"for '{operation}' on device '{device_id}' "
            f"(classification={classification.value})."
        )

    # 3. Target device inventory validation (deny unknown devices). Import
    # lazily to avoid a policy.types <-> inventory initialization cycle.
    from ..inventory.inventory_manager import DeviceInventoryManager
    inv_mgr = DeviceInventoryManager()
    dev = inv_mgr.get_device(device_id)
    if not dev:
        raise PermissionError(
            f"Device '{device_id}' is not a registered inventory device. Out-of-scope/unknown device access denied."
        )

    # 4. Device-level user authorization
    if hasattr(user_ctx, "can_access_device") and not user_ctx.can_access_device(device_id):
        raise PermissionError(
            f"User '{user_ctx.username}' is not authorized to access device '{device_id}'."
        )


__all__ = [
    "OperationClassification",
    "ExecutionMode",
    "UserContext",
    "TargetDevice",
    "OperationRequest",
    "ExecutionResult",
    "SecurityPolicyEngine",
    "AuditLogger",
    "check_permission",
]
