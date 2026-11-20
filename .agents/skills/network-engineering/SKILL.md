---
name: network-engineering
description: Vendor-aware network engineering skill for router/switch/access equipment troubleshooting, ISP provisioning guidance and simulated requests, device QC, guarded Winbox workflows, imported network discovery, topology analysis, and policy-controlled operations. Live production functions require separately integrated trusted providers.
---

# Network Engineering Operations Assistant (The Brain & The Hands)

## Architecture Overview
This skill operates on a dual-layer architectural model:
1. **THE BRAIN — Network Engineering Skill (Knowledge, Reasoning & SOPs)**:
   - Device capability awareness, vendor syntax resolution, diagnostic workflow planning, fault domain isolation, optical/RF budget validation, model-specific QC decision logic, network discovery methodologies, and topology corroboration rules.
2. **THE HANDS — Executable Operations Engine (`engine/`)**:
   - Python-based execution connectors (SSH via Paramiko, REST API via Requests, SNMP, Mock Connector, and security-hardened Winbox GUI adapter).
   - Network Discovery and Topology Engine (`engine/discovery/`, `engine/topology/`, `engine/health/`) supporting scoped discovery, LLDP/CDP/MNDP neighbor parsing, interactive SVG/HTML visualization, and telemetry health analysis.
   - Vendor Adapters for **MikroTik RouterOS** (API/SSH/Winbox), **Cisco IOS/IOS-XE**, **Huawei VRP/SmartAX**, **Ruijie/Reyee**, **Cambium Networks**, **Ubiquiti**, and **TP-Link**.
   - Security Policy Engine governing operation classifications (`READ_ONLY`, `DIAGNOSTIC`, `WRITE`, `CRITICAL`), shell-control rejection, exact-diff approval binding, and fail-closed approval-provider integration.
   - Comprehensive audit logging with automated credential redaction.

---

## Executable Security Status

- Production identity provider: **NOT INTEGRATED** (production authentication fails closed).
- Development identities default to **READ_ONLY**; `DIAGNOSTIC` requires explicit `AGY_DEV_DIAGNOSTIC=1` opt-in. Development identities never receive `WRITE` or `CRITICAL`.
- Trusted credential provider: **NOT INTEGRATED** (live connector operations fail closed).
- External approval verifier: **NOT INTEGRATED** (WRITE/CRITICAL cannot execute live).
- Live SNMP transport: **NOT IMPLEMENTED**.
- Live Winbox: requires trusted identity, canonical inventory, and credential-provider integration; not verified on Windows.
- Real network hardware: **NOT VERIFIED**.
- Continuous monitoring/background polling/automatic alerts: **OUT OF SCOPE**.

---

## 1. First Classify the Task
Determine the technical scope:
- **Network Discovery & Topology Mapping**: Authorized imported-evidence ingestion, multi-source neighbor parsing (LLDP/CDP/MNDP/ARP), topology graph construction, link confidence evaluation (`VERIFIED`, `INFERRED`, `UNKNOWN`), and escaped SVG/HTML rendering. No live collector is bundled; subnet similarity alone never proves a physical link.
- **ISP Provisioning & Remote Management**: PPPoE/IPoE, C-VLAN/S-VLAN/QinQ, GPON/EPON/XGS-PON, ONT/ONU provisioning request guidance and explicitly simulated requests. ACS is mock-only; no live TR-069 CWMP or TR-369 USP transport is implemented.
- **Advanced Device QC & Automation**: Model/profile-aware assessment, validated file-backed evidence or clearly separate manual attestation, decision logic and JSON/CSV/PDF/XLSX reports. Physical/optical/radio hardware measurements require external instruments and have not been validated here.
- **MikroTik Winbox Desktop Integration**: Windows Winbox detection, process management, session launching, GUI menu navigation, evidence screenshot capture, and intelligent connector selection (API vs. SSH vs. Winbox).
- **Network Operations & Execution**: On-demand diagnostic and simulated device workflows. Live operations require trusted production identity and credentials; live WRITE/CRITICAL also require the external exact-diff approval service, which is not bundled and therefore remains fail-closed.
- **Design / Topology / Addressing**: IPAM, subnets, IPv4/IPv6 allocation, routing protocols (BGP/OSPF).
- **Troubleshooting & Incident Triage**: Root-cause analysis, MTU/VLAN mismatch detection, link health verification.
- **Wireless RF & Microwave Backhaul**: Link planning, Fresnel clearance, path budget, tower safety.

---

## 2. Discovery & Topology Corroboration Rules
- **No Unrestricted Port Scanning**: Discovery requires an explicit authorized CIDR subnet, inventory source, or seed router.
- **Evidence-Backed Topology**: Never infer physical connectivity from IP subnet similarity alone.
- **Link Confidence Standards**:
  - `VERIFIED`: Bidirectional LLDP/CDP/MNDP confirmation from both endpoints.
  - `INFERRED`: Unidirectional neighbor observation or switch MAC forwarding table lookup.
  - `UNKNOWN`: Uncorroborated single host hint or conflicting bridge port records.
- **Telemetry Health Checks**: Analyzes CPU load (>70% WARN, >85% CRIT), free memory (<32MB CRIT), GPON optical levels (<-27dBm CRIT attenuation, >-8dBm WARN overload), and wireless RF metrics (RSSI <-78dBm, SNR <18dB).

---

## 3. Permission and Execution Policy (Non-Negotiable)

### 3.1 Default Mode: READ-ONLY
All user queries and AI plans must default to read-only diagnostics and passive telemetry retrieval.

### 3.2 Operation Classifications:
1. **`READ_ONLY`**:
   - Operations: `show ...`, `display ...`, `get ...`, `/system resource print`, `/interface print`, Winbox menu inspection, LLDP neighbor interrogation.
   - Access: Available to all operators; no changes made.
2. **`DIAGNOSTIC`**:
   - Operations: `ping`, `traceroute`, `mtr`, `/tool torch`, `/tool sniffer quick`, Winbox spectral scan.
   - Access: Requires Diagnostic scope; on-demand diagnostics only.
3. **`WRITE`**:
   - Operations: `set ...`, `add ...`, `/interface set`, `/ip address add`, `/ppp secret add`.
   - Access: Requires a trusted external approval verifier bound to the canonical device and exact proposed diff. The CLI `--approve` boolean is not authorization evidence. This provider is not yet integrated, so live WRITE remains disabled.
4. **`CRITICAL`**:
   - Operations: `reload`, `reboot`, `/system reboot`, `factory-reset`, `/system reset-configuration`, firmware upgrade.
   - Access: Requires a trusted external approval verifier with two distinct approvers (separate from the requester), exact target/diff binding, and unexpired evidence. This provider is not yet integrated, so live CRITICAL remains disabled.

---

## 4. Standard Execution Workflow
When executing or recommending network operations, follow this 14-step sequence:
1. **Understand** the user's objective and operational context.
2. **Identify** target devices and roles (Core, Aggregation, Distribution, Access, CPE).
3. **Discover** device vendor, exact model, hardware revision, and firmware version.
4. **Determine** required access level and operation classification (`READ_ONLY`, `DIAGNOSTIC`, `WRITE`, `CRITICAL`).
5. **Validate** user authorization against role scopes.
6. **Select** an appropriate connector (SSH, REST, SNMP, Winbox, or Mock).
7. **Build** an execution plan with explicit pre-checks and rollback steps.
8. **Validate** commands against vendor OS syntax and safety allowlists.
9. **Request approval** when `WRITE` or `CRITICAL` changes are required.
10. **Execute** strictly within authorized boundaries (utilizing Dry-Run mode where appropriate).
11. **Collect and validate** command outputs, GUI states, and telemetry.
12. **Analyze** findings, error counters, and optical/RF thresholds.
13. **Generate** a clean technical report (with credentials fully redacted).
14. **Record** the operation in the restrictive append-oriented audit log (`audit_trail.jsonl`).

---

## 5. Repository Reference Modules
- **`engine/`**:
  - `discovery/`: Neighbor parsing (LLDP/CDP/MNDP), scoped collector, and device identification models.
  - `topology/`: Topology graph engine, evidence corroboration, and SVG/HTML visualizers.
  - `health/`: Telemetry analysis and incident threshold evaluations.
  - `winbox/`: Windows Winbox desktop locator, UI automation wrapper, adapter, and connector selector.
  - `connectors/`: SSH (Paramiko), REST (Requests), SNMP, and Mock connectors.
  - `adapters/`: Device adapters for MikroTik, Cisco, Huawei, Ruijie, Cambium, Ubiquiti, TP-Link.
  - `policy/`: Classification detection, authorization checks, and audit logging.
  - `execution/`: Central `OperationsEngine` orchestrator.
  - `cli/`: NetOps CLI tool.
- **`provisioning/`**:
  - `pppoe/`: BNG provisioning workflows and QinQ configuration.
  - `ont-onu/`: GPON/EPON/XGS-PON optical profiles and multi-vendor OLT commands.
  - `tr-069/` & `tr-369/`: CWMP & USP architectures, data models, and mock ACS provider.
  - `playbooks/`: Standardized operational SOPs.
- **`quality-control/`**:
  - `framework/` & `profiles/`: Model-aware hardware profiles and threshold validation.
  - `reports/` & `history/`: Multi-format reporting (JSON/CSV/PDF) and retest tracking.
- **`scripts/`**:
  - `qc_engine/`: QC evaluation and decision engine.
  - `acs_integration/`: Mock ACS connector and CWMP simulator.
  - `redact.py`: Regex-based secret sanitization engine.

## Capability and Evidence Honesty
- Resolve the target only through trusted inventory; never treat caller-provided identifiers as canonical.
- Before operations, explain objective, target, classification, plan and approval requirements. Connector creation/execution must occur only after policy authorization.
- Unsupported vendor/model/firmware or unknown capability must be explicitly reported as UNKNOWN/NOT SUPPORTED; never use an unrelated adapter as fallback.
- Distinguish observed evidence, inference, hypotheses and confirmed root cause. Attach source and timestamp; stale/future/contradictory evidence lowers confidence.
- Never claim live configuration, QC, provisioning, discovery, or physical tests succeeded without returned execution/evidence. Label mock/simulated results.
- Any write requires external approval bound to canonical device and exact diff; critical requires independent approvals. In the current distribution, these providers are unavailable and live changes remain fail-closed.
- Use on-demand operations only. Continuous monitoring, polling, scheduled telemetry and automatic alerting are excluded.
