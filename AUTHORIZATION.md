# Authorization Model

Classifications: READ_ONLY, DIAGNOSTIC, WRITE, CRITICAL.

- READ_ONLY is the default.
- DIAGNOSTIC requires the authorized diagnostic scope.
- WRITE requires a trusted external approval verifier bound to requester, canonical inventory device, request/classification, exact diff hash, expiration and approver claims.
- CRITICAL requires independent dual approvers and cannot be self-approved.
- Unknown devices, caller-supplied identity overrides, caller-provided live credentials, expired/mismatched approvals, development identity live access, and LIVE access to simulated devices are rejected.
- Connector initialization follows authorization checks.

Development identity is intentionally constrained. Production identity/approval integration is not present; the production path rejects requests rather than trusting a placeholder.


## Development scope defaults

Development identities default to `READ_ONLY`. Granting `DIAGNOSTIC` requires explicit local opt-in with `AGY_DEV_DIAGNOSTIC=1`; development identities never receive `WRITE` or `CRITICAL`. Production identity remains unavailable until a genuine provider is integrated.
