# Module capability and integration matrix

Status labels distinguish software-path tests from hardware verification. `SIMULATED` means no live device/provisioning operation was performed.

| Module | Software capabilities retained | Shared lifecycle | Operational status | Limits |
|---|---|---|---|---|
| 1 Advanced Network Operations | Operations Engine, troubleshooting catalog, RCA, vendor adapters, on-demand diagnostics | Diagnostic/RCA workflows use canonical inventory, signed context, scope policy, audit and structured results | Software/mock paths tested; live connector use remains gated | Production auth, credential and approval providers absent; vendor/model/hardware support not certified |
| 2 ISP Provisioning & Remote Management | PPPoE/IPoE, DHCP, VLAN/QinQ, PON and ONT/ONU request model; ACS interface/mock | ACS mock workflows and provisioning simulation route through shared authorization/audit gateway | `MOCK_ONLY` / `SIMULATED_NOT_APPLIED` | No production ACS, CWMP/TR-069, USP/TR-369, or live provisioning transport |
| 3 Advanced Device Quality Control | Model/profile catalog, evidence manager, decision engine, history, JSON/CSV/PDF/XLSX reports | Optional shared canonical inventory, auth/policy workflow, evidence provenance and QC history | Software-tested; manual and file-backed evidence only | No instrument/physical hardware validation; openpyxl is optional for XLSX |
| 4 Network Discovery & Topology | LLDP/CDP/MNDP parser paths, neighbor correlation, topology graph, HTML/SVG output | Authorized ingestion and topology-build workflows use shared inventory/context/policy/audit when configured | Imported evidence/offline and mock seed paths | No live collector; no physical link is inferred from subnet similarity; port mismatch lowers confidence |

## Shared operational foundation

```text
Canonical Device Inventory
        |
Verified Authentication Context
        |
Permission / Scope Policy ---- Approval Manager (external provider required for WRITE/CRITICAL)
        |
OperationsEngine ---- CredentialProvider interface (no production provider bundled)
        |
Vendor Capability Registry / Connector Selection
        |
Audit Logger + Evidence Manager + Structured ExecutionResult
        |
+----------------+----------------+----------------+----------------+
| Module 1        | Module 2       | Module 3       | Module 4       |
| Diagnostics/RCA| ACS/Provision  | Device QC      | Discovery/Topo |
+----------------+----------------+----------------+----------------+
```

Local module-workflow handlers are recorded as `SIMULATED`; live device operations must use the separate OperationsEngine execution path and its provider gates. There is no continuous monitoring, background polling, scheduled telemetry or alerting.

## Connector status
| Connector | Status | Security/limits |
|---|---|---|
| SSH | Connector code present; mock/security-tested | RejectUnknown host-key policy; Paramiko is not installed in the audit environment; live access not verified |
| REST | Connector code present; software-tested | HTTPS certificate validation; no vendor API endpoint validated |
| SNMP | Interface only | Live transport disabled/fail-closed |
| Mock | Implemented | Explicit simulation/test only; not hardware evidence |
| Winbox | Guarded Windows integration | Requires verified identity, canonical target, shared audit, trusted credential provider and device-enforced READ_ONLY account; Windows/live behavior NOT VERIFIED |
| ACS | Interface + mock | No real ACS endpoint or CWMP/USP implementation |

## Vendor registry
See `VENDOR_SUPPORT.md` and `engine/vendors/registry.py`. An adapter or alias is not a certification of all models or firmware for a vendor.
