# AI Network Operations Assistant (The Brain & The Hands)

[![CI](https://github.com/network-engineering-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/network-engineering-skill/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

An enterprise-grade, vendor-aware AI Network Operations Assistant built on a strict **Two-Layer Architecture**:

1. **THE BRAIN — Network Engineering Skill (`SKILL.md`, `provisioning/`, `quality-control/`, `references/`)**:
   - The knowledge base, reasoning framework, technical SOPs, vendor syntax guides, troubleshooting methodology, model-aware QC thresholds, network discovery methodology, and security policies governing AI actions.
2. **THE HANDS — Executable Tools and Operations Engine (`engine/`, `scripts/`)**:
   - Executable software paths for SSH/REST connector handling, vendor adapters, policy enforcement, on-demand diagnostics, QC, discovery/topology, and report generation. Several integrations are simulation-only or disabled pending trusted providers; see the module and connector status tables before any operational use.

---

## Current security / execution status (all modules)

This distribution is intentionally fail-closed and is **not production-ready for live network changes**:

- `ProdAuthProvider` is a placeholder and rejects authentication until a genuine external identity provider is integrated.
- Development identities default to `READ_ONLY`; `DIAGNOSTIC` requires explicit `AGY_DEV_DIAGNOSTIC=1` opt-in. Development identities can never receive `WRITE` or `CRITICAL`.
- Live device operations require an inventory-backed target and a trusted credential provider. No credential provider is bundled.
- `WRITE` / `CRITICAL` operations require an external approval verifier returning claims bound to requester, target, request, classification, exact configuration diff, expiry, and approvers. No verifier is bundled; `CRITICAL` requires two approvers separate from requester.
- SSH rejects unknown host keys and blocks shell operators. REST requires HTTPS certificate validation and same-host relative endpoints. SNMP live transport is not implemented and fails closed.
- Winbox live sessions require a verified context, canonical inventory target, and trusted credential provider. Simulated targets cannot be opened as live sessions.
- `SIMULATED` / `DRY_RUN` workflows are supported; real-router/hardware validation has not been performed.
- Troubleshooting evidence encryption uses AES-GCM. Windows DPAPI/ACL integration is not verified here; non-Windows development key protection is explicitly insecure and production storage fails closed.
- All four module workflows now use the shared `OperationsEngine` workflow gateway when configured; these module-level workflows are explicitly `SIMULATED` and do not imply a live device operation.
- Module 1 troubleshooting uses the shared authorization and audit lifecycle; live troubleshooting connectors remain disabled until trusted production providers are available.
- Module 2 ACS and ISP provisioning are mock/simulation only. No TR-069/CWMP, TR-369/USP, or live provisioning transport is bundled.
- Module 3 QC validates evidence references and retains provenance; PASS for mandatory checks requires validated evidence or a distinct manual attestation. XLSX output is available when optional `openpyxl` is installed.
- Module 4 discovery ingestion accepts authorized imported evidence or explicit mock data; no live LLDP/CDP/MNDP/SNMP collector or physical-link validation is claimed.
- Continuous monitoring, background polling, scheduled telemetry, and automatic alerting are out of scope.

## 🏛 Architectural Overview

```
                      +---------------------------------------+
                      |         NATURAL LANGUAGE REQUEST      |
                      +---------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| THE BRAIN (Network Engineering Skill)                                             |
|  * Identify device category, capabilities, & firmware constraints                 |
|  * Scoped Discovery Planning & Adjacency Corroboration Engine                     |
|  * Intelligent Connector Selection (RouterOS API vs. SSH vs. Winbox GUI)          |
|  * Formulate multi-stage execution plan (Pre-checks -> Change -> Rollback)        |
|  * Determine Operation Classification (READ_ONLY, DIAGNOSTIC, WRITE, CRITICAL)    |
|  * Enforce safety guidelines, optical/RF budgets, & credential redaction rules    |
+-----------------------------------------------------------------------------------+
                                          |
                        Validates Authorization & Approval
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| THE HANDS (Operations Engine & Automation)                                        |
|  * Imported-evidence discovery/topology parsers and SVG/HTML visualizer          |
|  * On-demand health analysis over supplied/mock measurements                     |
|  * Guarded Winbox integration wrapper (Windows/live behavior unverified)         |
|  * Security policy engine, signed identity context and external approval gate    |
|  * Connectors: SSH/REST code paths, fail-closed SNMP interface, Mock connector   |
|  * Vendor adapters and conservative capability registry                         |
|  * QC evidence, decision, history and report engine (JSON / CSV / PDF / XLSX)     |
|  * Restrictive Audit Logger (JSONL with secret redaction)                           |
+-----------------------------------------------------------------------------------+
```

---

## 🌐 Network Discovery & Topology Mapping (`engine/discovery/` & `engine/topology/`)

The discovery engine parses imported/mock multi-vendor layer-2 and layer-3 neighbor evidence and models confidence-labelled network graphs:
- **Scoped Collector (`DiscoveryCollector`)**: Enforces configured authorized IP ranges for imported evidence. It does not perform live subnet scanning or collect live neighbor telemetry in this release.
- **Multi-Source Neighbor Parsing (`NeighborParser`)**:
  - MikroTik RouterOS MNDP / LLDP (`/ip neighbor print`)
  - Cisco IOS / IOS-XE CDP (`show cdp neighbors detail`)
  - IEEE 802.1AB LLDP (Huawei, Ruijie, Linux, Ubiquiti)
  - Bridge Host / FDB forwarding tables and DHCP leases
- **Topology Graph Engine (`TopologyEngine`)**:
  - **`VERIFIED`**: Bidirectional adjacency corroborated from both endpoints.
  - **`INFERRED`**: Unidirectional neighbor observation or switch access port correlation.
  - **`UNKNOWN`**: Uncorroborated single host hint or conflicting bridge port records.
  - **No IP Fabrications**: Never creates links based solely on shared subnets.
- **Visualization (`TopologyVisualizer`)**:
  - Export to scalable vector graphics (**SVG**) and a static, self-contained **HTML** evidence viewer. Network-derived text is escaped.
- **On-demand Health Analyzer (`NetworkHealthAnalyzer`)**:
  - Evaluates supplied/mock CPU, memory, optical and RF measurements using configurable sample thresholds. It is not a telemetry collector or monitoring service; thresholds require model/vendor validation before operational use.

---

## 🖥 MikroTik Winbox Desktop Integration & Hardening (`engine/winbox/`)

- **Security Hardening (Eliminated CLI Credential Leakage)**: Avoids passing passwords in command-line arguments, preventing exposure to process enumeration (`tasklist`, WMI `Win32_Process`, Process Hacker, and ETW Event ID 4688).
- **Windows UI Control Automation (`WindowsUIAWrapper`)**: Windows-specific wrapper and selector code are present; live login/session behavior and security properties have not been validated on Windows.
- **Connector Selector (`ConnectorSelector`)**: Provides selection logic, but live routing through RouterOS API, SSH CLI, and Winbox must be validated in an authorized lab.

---

## 🔒 Permission & Execution Policy

Every operation must declare its classification before execution:

| Classification | Permitted Actions | Approval Requirement | Environment Safeguards |
| :--- | :--- | :--- | :--- |
| **`READ_ONLY`** | Explicitly allowlisted reads and offline evidence inspection | Authenticated context and device scope | Live use still requires production identity and credentials |
| **`DIAGNOSTIC`** | Scoped, bounded on-demand diagnostics | Diagnostic scope | Live use requires trusted production identity and credentials |
| **`WRITE`** | Configuration changes | External verifier bound to requester, canonical target, exact diff and expiry | Disabled until trusted providers are integrated |
| **`CRITICAL`** | High-impact changes | External exact-diff approval with two distinct approvers | Disabled until trusted providers are integrated |

---

## 📁 Repository Organization

```text
network-engineering/
├── SKILL.md                               # Canonical Skill instructions (The Brain)
├── README.md                              # Main documentation and operational guide
├── .agents/skills/network-engineering/    # OpenAI Codex skill mirror
├── .claude/skills/network-engineering/    # Claude Code skill mirror
├── engine/                                # The Hands: Executable Operations Engine
│   ├── discovery/                         # Scoped discovery & neighbor parsers (LLDP/CDP/MNDP)
│   ├── topology/                          # Topology graph engine & SVG/HTML visualizers
│   ├── health/                            # Network telemetry health analyzer
│   ├── winbox/                            # Winbox desktop automation & UI adapter
│   ├── connectors/                        # SSH, REST, SNMP, Mock connectors
│   ├── adapters/                          # Vendor adapters (MikroTik, Cisco, Huawei, etc.)
│   ├── policy/                            # Policy engine, RBAC, types, audit logging
│   ├── execution/                         # OperationsEngine orchestrator
│   ├── inventory/                         # Device inventory management
│   └── cli/                               # NetOps CLI tool (`netops_cli.py`)
├── provisioning/                          # ISP Provisioning & Remote Management
│   ├── pppoe/                             # PPPoE / IPoE / BNG workflows & QinQ
│   ├── ont-onu/                           # GPON / EPON / XGS-PON optical guide
│   ├── tr-069/                            # CWMP protocol reference & data models
│   ├── tr-369/                            # USP protocol reference & Protobuf
│   ├── remote-management/                 # RBAC, encryption, & credential hygiene
│   └── playbooks/                         # 10 Operational SOPs
├── quality-control/                       # Advanced Device Quality Control
│   ├── profiles/                          # Model-specific hardware profiles (JSON)
│   ├── vendor-checklists/                 # 8 Inspection categories & criteria
│   ├── history/                           # QC session history & retest records
│   └── reports/                           # Output directory for QC reports
├── scripts/                               # Automation & Helper Utilities
│   ├── qc_engine/                         # Data-driven QC execution & scoring engine
│   ├── acs_integration/                   # ACS Connector Interface & Mock ACS
│   └── redact.py                          # Regex secret & credential redaction
└── tests/                                 # Complete Unit and Integration Test Suite
```

---

## 🚀 Hands-On Usage

### 1. Discovering Scoped Network Topology
```python
from engine.discovery import DiscoveryCollector
from engine.topology import TopologyEngine, TopologyVisualizer
from engine.health import NetworkHealthAnalyzer

# Collect devices within authorized management subnet
collector = DiscoveryCollector(authorized_subnets=["10.0.0.0/16"])
discovered_devices = collector.discover_from_mock_environment()

# Build evidence-backed topology graph
top_engine = TopologyEngine()
devices, links = top_engine.build_topology(discovered_devices)

# Generate interactive SVG and HTML visualizations
topology_data = top_engine.export_topology_data()
visualizer = TopologyVisualizer(topology_data)
visualizer.generate_svg("quality-control/reports/topology.svg")
visualizer.generate_html_viewer("quality-control/reports/topology.html")

# Evaluate network telemetry health
health_summary = NetworkHealthAnalyzer.generate_health_summary(discovered_devices)
print(f"Overall Network Health: {health_summary['overall_health']}")
```

### 2. Interrogating Device Inventory via CLI
```bash
python engine/cli/netops_cli.py inventory
```

### 3. Inspecting Device System Info (Read-Only)
```bash
python engine/cli/netops_cli.py exec --device RTR-CORE-01 --action system_info --mode SIMULATED
```

### 4. Running Automated Device QC Inspection
```python
from scripts.qc_engine import QCTestEngine, DeviceIdentity, QCReportGenerator

engine = QCTestEngine()
dev = DeviceIdentity(manufacturer="MikroTik", model="RB750Gr3", serial_number="HE0912837")

measurements = {
    "PHYS-01": {"value": "PASS", "evidence_ref": "photo_bench.jpg"},
    "PHYS-02": {"value": "PASS", "evidence_ref": "ports_checked.jpg"},
    "PHYS-03": {"value": "PASS", "evidence_ref": "label.jpg"},
    "PWR-01": {"value": "PASS", "evidence_ref": "boot.log"},
    "PWR-02": {"value": "PASS", "evidence_ref": "leds.jpg"},
    "ETH-01": {"value": "1000M", "evidence_ref": "negotiation.txt"},
    "ETH-02": {"value": "PASS", "evidence_ref": "counters.txt"}
}

report = engine.run_qc_session(dev, measurements, technician="NOC_Tech_01")
print(f"Final QC Status: {report.final_status.value}")
```

---

## 🧪 Testing and Acceptance Results

Install the tested dependencies and run the full offline test suite:
```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q -rs
python -m compileall -q engine scripts tests
```
The test suite validates:
- **Network Discovery & Topology**: Imported/mock evidence parsing, multi-vendor neighbor parsers (MikroTik MNDP, Cisco CDP, IEEE LLDP), bidirectional link corroboration, SVG/HTML escaping, and on-demand health analysis. No live collector is included.
- **Winbox Desktop Integration (Hardened)**: Process detection, installation path resolution, GUI session launching, in-memory control text setting, menu navigation simulation, evidence screenshot recording, and connector selection.
- **Real Router Hardware Readiness**: Dedicated read-only test suite in `tests/test_real_router_validation.py`. When no physical router is configured in the environment (`LAB_MIKROTIK_IP`), status is reported as **`SKIPPED (NOT VERIFIED)`**.
- **Operations Engine & Policy**: Security classification, fail-closed external approval checks, exact-diff binding, shared simulated module workflows, and structured audit trail writing.
- **Device QC Engine**: Model-aware hardware thresholds (e.g. hAP lite 100M PHY vs. hEX 1G PHY; GPON Class B+ optical power limits), mandatory fail blocking, missing evidence detection, and PDF/CSV/JSON report generation.
- **ACS / CWMP Integration**: Mock-only ACS workflows and explicit provisioning simulations. No production ACS/CWMP/USP transport or live device provisioning is included.
- **Security & Secret Redaction**: Regex sanitization of passwords, private keys, bearer tokens, and SNMP communities.

## Incremental audit release

This release preserves the existing architecture and features. See `AUDIT_AND_IMPLEMENTATION_PLAN.md` for audit status, `MODULES.md` for module coverage, and the required operational/security documentation set.

Recent hardening: unsupported vendor adapters now fail closed rather than defaulting to a Cisco-like adapter; adapter ping input targets and counts are validated. These behaviors have regression tests.

**Verification boundaries:** production identity/credential/approval providers, live SNMP, production ACS/CWMP/USP, Windows-specific security and Winbox flows, and physical hardware have not been verified. Mock tests are not hardware tests. This project is not declared production-ready.


## Release candidate verification

The current release-candidate test record is maintained in `FINAL_VERIFICATION.md`. The verified Linux clean-extraction run recorded **202 passed, 5 skipped, and 45 subtests passed**. Skips are Windows-only checks, an optional live-router check, and the initial packaging-inspection check before a distribution archive is present.

`requirements.txt` records tested runtime dependencies; `requirements-dev.txt` adds pytest. Optional live integrations and platform-specific dependencies are not implied to be installed or verified.

**Operational boundary:** this is a software release candidate for controlled development/lab evaluation, not a production provisioning or network-management system. Do not enable live writes or critical changes until trusted production identity, credential and approval providers are integrated and validated.
