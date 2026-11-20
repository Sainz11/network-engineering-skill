# Architecture

The project retains its two-layer design: Skill knowledge and instructions are the Brain; Python modules/connectors are the Hands. The execution boundary is the Operations Engine and shared policy.

## Flow
1. Skill interprets request and proposes an operation.
2. Resolve device through trusted inventory; reject unknown or conflicting identity.
3. Determine classification and required scope.
4. Validate authorization/approval before connector construction.
5. Use connector and vendor adapter to execute bounded operation.
6. Collect structured result/evidence, redact secrets, audit, and report.

## Shared packages
- `engine/policy`: types, authorization, classification, approval validation.
- `engine/auth_provider.py`: identity context; production provider deliberately unavailable until integration.
- `engine/inventory`: canonical inventory identity resolution.
- `engine/execution`: operation orchestration.
- `engine/connectors`: SSH, REST, SNMP interface and mock.
- `engine/adapters`: vendor-specific operations.
- `engine/troubleshoot`: on-demand diagnostics, parsers, secure evidence and RCA.
- `engine/discovery`, `engine/topology`: scoped collection, normalization, graph and visualization.
- `scripts/qc_engine`: QC profiles, tests, decision engine, history and reports.
- `scripts/acs_integration`: ACS interface and mock.

No background polling, monitoring daemon, scheduler, or alert service is included.
