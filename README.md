








<div align="center">
⚡ AI Network Operations Assistant
THE BRAIN × THE HANDS
One network-engineering brain. One controlled execution layer.

A vendor-aware Agent Skill and Python Operations Engine for structured troubleshooting, ISP workflows, device quality control, and evidence-backed network discovery. Plan with engineering knowledge; execute only within explicit authorization and safety boundaries.

<p> <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+"/></a> <a href="https://github.com/Sainz11/network-engineering-skill/actions"><img src="https://img.shields.io/github/actions/workflow/status/Sainz11/network-engineering-skill/ci.yml?branch=main&style=for-the-badge&label=CI" alt="CI status"/></a> <img src="https://img.shields.io/badge/AI%20Skill-Codex%20%7C%20Claude-8B5CF6?style=for-the-badge" alt="Codex and Claude skills"/> <img src="https://img.shields.io/badge/Execution-Simulated%20%2F%20Dry--Run-orange?style=for-the-badge" alt="Simulated and dry-run"/> <img src="https://img.shields.io/badge/Live%20Writes-Disabled-red?style=for-the-badge" alt="Live writes disabled"/> </p>
Overview · Modules · Install with NPX · Quick start · Security · Tests

</div>
🧭 Overview
AI Network Operations Assistant is a two-layer network engineering project. It separates the AI's operational knowledge from the software that enforces execution rules.

THE BRAIN decides what should happen. THE HANDS enforce what is allowed to happen.

Layer	What it contains	What it does
🧠 THE BRAIN	SKILL.md, provisioning/, quality-control/, references and playbooks	Vendor-aware reasoning, technical SOPs, troubleshooting, QC criteria, discovery methodology, and safety rules
🛠️ THE HANDS	engine/, scripts/	Operations gateway, policy enforcement, connector code paths, adapters, simulated workflows, evidence handling, and reports
The repository includes Skill mirrors for OpenAI Codex and Claude Code. Install the Skill into an agent to make its network-engineering instructions available. The Operations Engine is a separate software component: installing the Skill does not automatically connect an AI agent to routers, credentials, or local execution tools.

[!IMPORTANT]
Release readiness: This is a controlled development/lab release, not a production-ready live network-change platform. Production identity, trusted credential storage, and the external approval verifier are not bundled; live WRITE / CRITICAL operations remain unavailable. Hardware and live Winbox behavior have not been verified.

Fastest setup: npx skills add https://github.com/Sainz11/network-engineering-skill/tree/main/.claude/skills/network-engineering -g -a claude-code

See Install in under a minute for Codex, project-level installation, verification, updates, and private-repository setup.

✨ Core modules
<table> <tr> <td width="50%" valign="top">
01 · Advanced Network Operations
Vendor-aware troubleshooting guidance
Scoped, on-demand diagnostics
Connector-selection logic
Configuration planning
Pre-check and rollback considerations
</td> <td width="50%" valign="top">
02 · ISP Provisioning & Remote Management
PPPoE / IPoE, BNG, VLAN and QinQ references
GPON / EPON / XGS-PON ONT/ONU guidance
TR-069 / CWMP and TR-369 / USP references
Remote-management security and credential hygiene
Simulated provisioning workflows
</td> </tr> <tr> <td width="50%" valign="top">
03 · Advanced Device Quality Control
Model-aware device profiles
Physical, power, Ethernet, wireless and optical checks
Evidence references and provenance
Mandatory-check blocking
QC history and retest records
JSON, CSV, PDF and optional XLSX reports
</td> <td width="50%" valign="top">
04 · Network Discovery & Topology Mapping
Imported/mock LLDP, CDP and MNDP evidence
Layer 2 / Layer 3 neighbor parsing
VERIFIED, INFERRED, UNKNOWN confidence labels
Evidence-backed topology graph
SVG and self-contained HTML exports
No link creation from shared subnet alone
</td> </tr> </table>
🏗️ Architecture
Operation lifecycle
Understand the request and identify the target scope.
Determine the required operation classification.
Validate identity, permissions, target, and any required approval.
Execute only through the configured and permitted workflow.
Record results and evidence in the audit lifecycle.
⚡ Install in under a minute
The easiest way to install this repository as an Agent Skill is the Vercel Skills CLI. You do not need to manually clone the repository or copy folders. The CLI downloads the Skill from GitHub and installs it into the agent directory you select.

Requirements: Node.js 22.20.0 or newer. Check with node --version.

Claude Code — global install
Run this in PowerShell, Command Prompt, or a terminal:

npx skills add https://github.com/Sainz11/network-engineering-skill/tree/main/.claude/skills/network-engineering -g -a claude-code
OpenAI Codex — global install
npx skills add https://github.com/Sainz11/network-engineering-skill/tree/main/.agents/skills/network-engineering -g -a codex
Install into the current project instead
Remove -g from either command. The Skill will be installed in the current project's agent-specific skills directory, rather than your user-wide directory.

Install for both agents
Run the Claude Code and Codex commands above separately. This makes the target explicit and avoids installing an unintended Skill mirror.

Verify installation
npx skills list -g
For Claude Code, restart the app and run /skills; then invoke /network-engineering if the Skill is listed. For Codex, restart/reload the app and inspect /skills or the Skill picker.

Update or remove the Skill
# Check for updates
npx skills check

# Update globally installed Skills
npx skills update -g

# Remove this Skill from Claude Code (global)
npx skills remove --global --agent claude-code network-engineering

# Remove this Skill from Codex (global)
npx skills remove --global --agent codex network-engineering
If the GitHub repository is private
The CLI uses your existing Git/GitHub authentication. Sign in with GitHub CLI first if needed, then retry the install:

gh auth login
Do not paste access tokens into chat or commit them to the repository.

🧰 Manual installation (fallback)
Use this only if you prefer not to use the Skills CLI. First clone the repository:

git clone https://github.com/Sainz11/network-engineering-skill.git
cd network-engineering-skill
Codex — Windows PowerShell, global:

$destination = Join-Path $HOME ".agents\skills\network-engineering"
New-Item -ItemType Directory -Force -Path (Split-Path $destination) | Out-Null
Copy-Item ".agents\skills\network-engineering" $destination -Recurse -Force
Claude Code — Windows PowerShell, global:

$destination = Join-Path $HOME ".claude\skills\network-engineering"
New-Item -ItemType Directory -Force -Path (Split-Path $destination) | Out-Null
Copy-Item ".claude\skills\network-engineering" $destination -Recurse -Force
For project-level installation, keep the Skill in the repository's existing .agents/skills/ (Codex) or .claude/skills/ (Claude Code) directory and open that repository as your project.

Install the Python Operations Engine (optional)
Installing the Agent Skill and installing the Python project are separate. The Skill provides instructions; Python dependencies are only needed if you intend to run the repository's local Operations Engine, scripts, or tests.

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
Linux / macOS:

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
PowerShell note: If activation is blocked by your machine's execution policy, use Command Prompt or an approved local Python environment workflow. Avoid changing system-wide security settings just to activate the environment.

Installation layout
Claude Code:  ~/.claude/skills/network-engineering/SKILL.md
Codex:        ~/.agents/skills/network-engineering/SKILL.md
A successful file installation does not prove that a Skill has loaded correctly, nor does it connect the agent to routers or grant device permissions. See What installation does — and does not do.

🚀 Quick start
These examples use the current simulated/offline workflows. They do not establish live-device connectivity.

Inspect inventory
python engine/cli/netops_cli.py inventory
Run a simulated read-only system-info action
python engine/cli/netops_cli.py exec --device RTR-CORE-01 --action system_info --mode SIMULATED
Build a topology from mock evidence
from engine.discovery import DiscoveryCollector
from engine.topology import TopologyEngine, TopologyVisualizer

collector = DiscoveryCollector(
    authorized_subnets=["10.0.0.0/16"]
)

discovered_devices = collector.discover_from_mock_environment()

topology = TopologyEngine()
devices, links = topology.build_topology(discovered_devices)

visualizer = TopologyVisualizer(topology.export_topology_data())
visualizer.generate_svg("quality-control/reports/topology.svg")
visualizer.generate_html_viewer("quality-control/reports/topology.html")
Run a QC session
from scripts.qc_engine import QCTestEngine, DeviceIdentity

engine = QCTestEngine()

device = DeviceIdentity(
    manufacturer="MikroTik",
    model="RB750Gr3",
    serial_number="HE0912837",
)

measurements = {
    "PHYS-01": {"value": "PASS", "evidence_ref": "photo_bench.jpg"},
    "PHYS-02": {"value": "PASS", "evidence_ref": "ports_checked.jpg"},
    "PHYS-03": {"value": "PASS", "evidence_ref": "label.jpg"},
    "PWR-01": {"value": "PASS", "evidence_ref": "boot.log"},
    "PWR-02": {"value": "PASS", "evidence_ref": "leds.jpg"},
    "ETH-01": {"value": "1000M", "evidence_ref": "negotiation.txt"},
    "ETH-02": {"value": "PASS", "evidence_ref": "counters.txt"},
}

report = engine.run_qc_session(
    device,
    measurements,
    technician="NOC_Tech_01",
)

print(report.final_status.value)
🔐 Security model
Every operation declares its classification before execution.

Classification	Scope	Required safeguards
READ_ONLY	Allowlisted reads and offline evidence inspection	Authenticated context and device scope; live use also needs production identity and credentials
DIAGNOSTIC	Scoped, bounded, on-demand diagnostics	Explicit diagnostic scope; live use needs trusted production identity and credentials
WRITE	Configuration changes	External approval bound to requester, canonical target, exact diff, and expiry
CRITICAL	High-impact changes	External exact-diff approval from two distinct approvers, separate from requester
Current security boundaries
ProdAuthProvider is a placeholder and rejects authentication.
Development identities default to READ_ONLY.
DIAGNOSTIC requires explicit AGY_DEV_DIAGNOSTIC=1 opt-in.
Development identities cannot receive WRITE or CRITICAL.
No trusted production credential provider is bundled.
No external approval verifier is bundled; live WRITE and CRITICAL operations are therefore unavailable.
SSH rejects unknown host keys and blocks shell operators.
REST requires HTTPS certificate validation and same-host relative endpoints.
Live SNMP transport is not implemented and fails closed.
Winbox live behavior and Windows-specific security integration are not verified.
AES-GCM is used for troubleshooting evidence encryption; Windows DPAPI/ACL integration is not verified. Non-Windows development key protection is explicitly insecure, and production storage fails closed.
📁 Repository structure
network-engineering-skill/
├── SKILL.md
├── README.md
├── .agents/
│   └── skills/network-engineering/    # Codex Skill mirror
├── .claude/
│   └── skills/network-engineering/    # Claude Code Skill mirror
├── engine/
│   ├── discovery/
│   ├── topology/
│   ├── health/
│   ├── winbox/
│   ├── connectors/
│   ├── adapters/
│   ├── policy/
│   ├── execution/
│   ├── inventory/
│   └── cli/
├── provisioning/
│   ├── pppoe/
│   ├── ont-onu/
│   ├── tr-069/
│   ├── tr-369/
│   ├── remote-management/
│   └── playbooks/
├── quality-control/
│   ├── profiles/
│   ├── vendor-checklists/
│   ├── history/
│   └── reports/
├── scripts/
│   ├── qc_engine/
│   ├── acs_integration/
│   └── redact.py
└── tests/
🧪 Testing
Install the development dependencies first, then run:

python -m compileall -q engine scripts tests
python -m pytest -q -rs
The automated suite covers imported/mock discovery evidence, topology parsing and exports, Winbox wrapper logic, Operations Engine policy workflows, QC validation and reports, mock ACS workflows, and security/secret-redaction behavior.

The optional real-router test is skipped when LAB_MIKROTIK_IP is not configured. A skipped hardware test means NOT VERIFIED, not passed hardware validation.

For the release-specific record, see `FINAL_VERIFICATION.md`.

🧩 What installation does — and does not do
Installing the Skill gives the agent…	It does not automatically give the agent…
Network-engineering instructions and SOPs	Router credentials
Vendor-aware troubleshooting guidance	Access to your local network
QC and discovery methodology	A live SSH / API / SNMP connection
Permission and safety rules	Permission to change device configuration
References to project workflows	A running Operations Engine or MCP server
The Skill is the knowledge layer. The Operations Engine and any trusted connector/provider are the execution layer. They must be configured and authorized separately.

🧯 Troubleshooting
<details> <summary><strong>Codex does not show the Skill</strong></summary>
Confirm the folder is under .agents/skills/network-engineering/.
Confirm SKILL.md exists directly inside that folder.
Open Codex from the repository root for project-level discovery.
Run /skills and restart Codex if necessary.
For global installation, confirm the destination is $HOME/.agents/skills/network-engineering/.
</details><details> <summary><strong>Claude Code does not show /network-engineering</strong></summary>
Confirm the folder is under .claude/skills/network-engineering/.
Confirm SKILL.md exists directly inside that folder.
Confirm the Skill's frontmatter and directory name are valid.
Restart Claude Code.
For global installation, confirm the destination is $HOME/.claude/skills/network-engineering/.
</details><details> <summary><strong>The agent knows the Skill but cannot connect to a router</strong></summary>
That is expected with the current release configuration. Installing a Skill does not install credentials, a production identity provider, an approval verifier, or a live connector. Current workflows are simulation/offline unless a separately validated integration is configured.

</details><details> <summary><strong>Python reports a missing module</strong></summary>
Activate the project's virtual environment and install the dependencies:

python -m pip install -r requirements-dev.txt
</details>
📚 Documentation
`SKILL.md` — canonical Skill instructions.
`MODULES.md` — module coverage and status.
`AUDIT_AND_IMPLEMENTATION_PLAN.md` — audit and implementation tracking.
`FINAL_VERIFICATION.md` — release-candidate verification record.
🚧 Scope and roadmap boundaries
This project focuses on on-demand network engineering workflows. Continuous monitoring, background polling, scheduled telemetry, and automatic alerting are intentionally out of scope.

The following integrations remain unverified or unavailable in this release:

Production authentication, credential-vault, and external approval providers.
Live SNMP transport.
Production ACS / CWMP / USP and subscriber provisioning transport.
Live device discovery and physical-link validation.
Windows-specific security behavior and live Winbox sessions.
Physical-router and hardware validation.
🤝 Contributing
Contributions should preserve the Brain/Hands separation and fail-closed security model.

Keep README claims aligned with implemented and verified behavior.
Add regression tests for changes to authorization, connectors, evidence handling, and execution workflows.
Run the compile and test commands above.
Document any integration or hardware validation that remains outstanding.
📄 License
No license file was identified in the supplied README. Add a LICENSE file before presenting this repository as open source or granting reuse rights.

<div align="center">
THE BRAIN plans. THE HANDS enforce. Every operation stays within its authorization boundary.

</div>




