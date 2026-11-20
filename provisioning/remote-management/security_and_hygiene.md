# Remote Management Security & Credential Hygiene

This guide defines non-negotiable security requirements, encryption standards, role-based access controls, and credential redaction procedures for network engineering operations.

---

## 1. Zero-Trust Access & Channel Security

### 1.1 Out-of-Band & Dedicated Management Networks
- Remote management traffic (SSH, SNMPv3, TR-069, Netconf/RESTCONF) must **never** traverse customer data VLANs unsegmented.
- Dedicate isolated Management VLANs (e.g. VLAN 99 / 999) or physically isolated Out-Of-Band (OOB) Ethernet networks terminated on firewalled bastion hosts.

### 1.2 Encrypted Management Channels
- **SSHv2 Only**: Disable Telnet and SSHv1. Use modern ciphers (`chacha20-poly1305`, `aes256-gcm`) and key exchange (`curve25519-sha256`).
- **HTTPS / TLS 1.3**: WebGUIs and CWMP/USP endpoints must enforce TLS 1.2 or TLS 1.3. Plain HTTP and deprecated TLS 1.0/1.1 are strictly prohibited.
- **SNMPv3 with AuthPriv**: Disable SNMPv1/v2c. Enforce SHA-256 / SHA-512 authentication and AES-256 encryption.

---

## 2. Role-Based Access Control (RBAC) & Least Privilege

| Role | Access Scope | Allowed Operations |
| :--- | :--- | :--- |
| **NOC Tier 1 / Helpdesk** | Read-Only | Ping, traceroute, display optical levels, check PPPoE session state |
| **NOC Tier 2 / Field Tech** | Staged Write | CPE Wi-Fi credential changes, port reset, ONT reprovisioning |
| **NOC Tier 3 / Core Eng** | Full Access | BNG routing changes, OLT profile modification, firmware distribution |
| **Auditor / Compliance** | Read-Only Audit | Inspection of configuration changes, session history, and AAA logs |

---

## 3. Credential Redaction & Sanitization Standards

> [!CAUTION]
> Never expose passwords, pre-shared keys, SNMP communities, or private keys in documentation, test logs, bug trackers, or AI prompts.

### Automatic Redaction Rules:
The included `scripts/redact.py` utility enforces regex-based redaction:
- `password="..."` -> `password="***REDACTED***"`
- `snmp-server community <secret>` -> `snmp-server community ***REDACTED***`
- `wpa-pre-shared-key` / `preshared-key` -> `***REDACTED***`
- `-----BEGIN RSA/OPENSSH PRIVATE KEY-----` -> `***REDACTED PRIVATE KEY***`

---

## 4. Change Control & Audit Logging

Every production device modification must:
1. Associate with an approved **Change Request (CR)** or **Trouble Ticket**.
2. Run in **Dry-Run / Safe Check** mode prior to commitment (e.g. MikroTik `safe mode`, Juniper `commit confirmed 5`, Cisco archive rollback).
3. Generate immutable AAA syslog records:
   - Timestamp (NTP synchronized).
   - Source IP and authenticated operator username.
   - Command executed and result code.
