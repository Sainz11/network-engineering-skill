"""Test-only identity helper that delegates issuance to the real dev provider.

This helper does not possess a signing key and cannot mint production identities.
"""
import os
from unittest.mock import patch
from engine.auth_provider import LocalDevAuthProvider, AuthenticationError

_ALLOWED_DEV_SCOPES = frozenset({"READ_ONLY", "DIAGNOSTIC"})

def create_test_context(username, role, scopes, is_dev_mode=True, session_id=None, authorized_devices=frozenset({"*"})):
    requested_scopes = frozenset(scopes)
    requested_devices = frozenset(authorized_devices)
    if not is_dev_mode:
        raise ValueError("Test helper may issue development-mode contexts only")
    if not requested_scopes.issubset(_ALLOWED_DEV_SCOPES):
        raise ValueError("Test helper cannot grant WRITE or CRITICAL scopes")
    if session_id not in (None, ""):
        raise ValueError("Local development provider does not issue caller-selected session IDs")
    if not username or any(c in username for c in ("/", "\\", "..", "\x00", "@", " ")):
        raise ValueError("Invalid development username")
    # Caller-supplied role is intentionally ignored; the provider issues only
    # the fixed dev-read-only role.
    devices_env = ",".join(sorted(requested_devices)) or "*"
    env = {"AGY_ENV": "dev", "AGY_USER": username, "AGY_DEV_DEVICES": devices_env}
    env["AGY_DEV_DIAGNOSTIC"] = "1" if "DIAGNOSTIC" in requested_scopes else "0"
    with patch.dict(os.environ, env, clear=False):
        context = LocalDevAuthProvider().authenticate()
    if not requested_scopes.issubset(context.authorized_scopes):
        raise AuthenticationError("Requested scopes are not issued by the development provider")
    return context
