import re

# Redaction patterns for sensitive network engineering data
SENSITIVE_PATTERNS = [
    # Passwords and secrets
    (re.compile(r'(?i)(password|secret|key|pass|auth-password|wpa-key|preshared-key|pre-shared-key)\s*(=|:|\s+)\s*["\']?([^"\'\s]+)["\']?'), r'\1\2"***REDACTED***"'),
    (re.compile(r'(?i)(set\s+user\s+\S+\s+password\s+)(\S+)'), r'\1***REDACTED***'),
    (re.compile(r'(?i)(user\s+name\s+\S+\s+password\s+)(\S+)'), r'\1***REDACTED***'),
    (re.compile(r'(?i)(snmp-server\s+community\s+)(\S+)'), r'\1***REDACTED***'),
    (re.compile(r'(?i)(community\s*(?:=|:|\s)\s*)(\S+)'), r'\1***REDACTED***'),
    # Authorization headers & tokens
    (re.compile(r'(?i)(bearer\s+)([A-Za-z0-9_\-\.]+)'), r'\1***REDACTED***'),
    (re.compile(r'(?i)(api[-_]?key\s*[:=]\s*["\']?)([^"\'\s]+)(["\']?)'), r'\1***REDACTED***\3'),
    (re.compile(r'(?i)(token\s*[:=]\s*["\']?)([^"\'\s]+)(["\']?)'), r'\1***REDACTED***\3'),
    # Private keys
    (re.compile(r'-----BEGIN\s+[\w\s]+PRIVATE\s+KEY-----[\s\S]+?-----END\s+[\w\s]+PRIVATE\s+KEY-----'), '-----BEGIN PRIVATE KEY-----\n***REDACTED PRIVATE KEY***\n-----END PRIVATE KEY-----'),
]

def redact_sensitive_data(text: str) -> str:
    """Redacts passwords, secrets, community strings, tokens, and private keys from configuration or logs."""
    if not text:
        return ""
    redacted = str(text)
    for pattern, replacement in SENSITIVE_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted
