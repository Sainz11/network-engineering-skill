# Operations Guide

## Safe on-demand workflow
1. Describe objective, target, and impact.
2. Resolve target from trusted inventory; confirm canonical identity/model/firmware.
3. Select READ_ONLY, DIAGNOSTIC, WRITE, or CRITICAL classification.
4. Present plan, expected evidence, risk, and diff for changes.
5. Obtain scope/approval before connector creation or execution.
6. Execute only through Operations Engine and validated connector/adapters.
7. Collect timestamped evidence, redact secrets, and log the operation.
8. Verify returned state, report findings/limitations, and offer rollback only if supported.

## Module use
- Troubleshooting: use catalog-defined commands, evidence, and RCA confidence statuses.
- Provisioning: follow vendor/model/firmware-specific SOPs; no production ACS is bundled.
- QC: load a matching profile; unsupported features are N/A/UNKNOWN, never assumed failed; preserve history.
- Discovery: explicit authorized scope only; neighbor evidence is classified, not fabricated.

## Not in scope
Continuous monitoring, polling, scheduled tasks, telemetry services, and automatic alerting are excluded.
