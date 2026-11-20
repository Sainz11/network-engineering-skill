# Security

## Controls present
- Inventory-backed canonical device resolution.
- Fail-closed authorization and classification.
- External approval claim validation for WRITE/CRITICAL; critical dual-approver rules.
- Caller-supplied live credentials rejected; credential provider required.
- SSH unknown host keys rejected; shell-control characters rejected.
- REST TLS validation and endpoint constraints.
- Secure evidence handling/redaction and audit logger.
- Scoped discovery, timeouts, bounded diagnostic output.
- Live mode rejects simulated targets and development identity.

## Remediation in this release
- Unknown vendor adapter no longer silently falls back to Cisco.
- Ping target/count validation blocks common option and command-injection patterns.

## Unavailable / unverified
Production identity provider, credential provider, approval verifier, live SNMP, external ACS, Windows DPAPI/ACL integration, and physical network validation are not bundled or verified. Operations relying on them remain unavailable or fail closed.

## Operational policy
READ_ONLY default. DIAGNOSTIC requires scope. WRITE requires exact target/diff approval. CRITICAL requires exact approval and independent approvers. Dry-run is not execution. Mock evidence is not hardware evidence. Secrets must not enter source, archive, reports, or user-facing logs.
