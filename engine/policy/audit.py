"""Restrictive, redacting audit log writer for network operations."""
import json
import os
import datetime
import stat
from typing import Dict, Any, Optional
from scripts.redact import redact_sensitive_data

# Operational logs must never be written into the installed source tree. Operators
# may choose a dedicated state directory, otherwise use a private per-user path.
_DEFAULT_AUDIT_DIR = os.environ.get(
    "NETWORK_SKILL_AUDIT_DIR",
    os.path.join(os.path.expanduser("~"), ".network-engineering-skill", "audit"),
)
DEFAULT_AUDIT_LOG_FILE = os.path.join(_DEFAULT_AUDIT_DIR, "audit_trail.jsonl")
_SENSITIVE_KEYS = {"password", "passwd", "passphrase", "secret", "community", "community_string", "snmp_community", "token", "api_key", "api_token", "apikey", "credential", "authorization", "cookie", "private_key", "key"}


class AuditLogger:
    def __init__(self, log_file: Optional[str] = None):
        self.log_file = os.path.abspath(log_file or DEFAULT_AUDIT_LOG_FILE)
        parent = os.path.dirname(self.log_file)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        # Reject symlinked path components to prevent redirection outside the
        # intended audit directory. A race-resistant Windows handle is not
        # verified in this Linux test environment.
        current = os.path.abspath(parent)
        while current and current != os.path.dirname(current):
            if os.path.islink(current):
                raise PermissionError("Audit log parent path must not contain symlinks")
            current = os.path.dirname(current)
        if os.path.islink(self.log_file):
            raise PermissionError("Audit log path must not be a symlink")
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass

    def log_event(self, event_type: str, user: str, device_id: str, action: str, details: Dict[str, Any], status: str):
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type": self._sanitize(event_type),
            "user": self._sanitize(user),
            "device_id": self._sanitize(device_id),
            "action": self._sanitize(action),
            "status": self._sanitize(status),
            "details": self._sanitize(details),
        }
        payload = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.log_file, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
        finally:
            os.close(fd)

    def _sanitize(self, data: Any) -> Any:
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                key_text = str(key)
                if key_text.lower().replace("-", "_") in _SENSITIVE_KEYS:
                    sanitized[key_text] = "***REDACTED***"
                else:
                    sanitized[key_text] = self._sanitize(value)
            return sanitized
        if isinstance(data, (list, tuple)):
            return [self._sanitize(v) for v in data]
        if isinstance(data, str):
            return redact_sensitive_data(data)
        return data
