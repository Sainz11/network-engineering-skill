# MikroTik Winbox Desktop Integration Reference & Security Hardening

This guide details the architecture, automation methods, menu structures, and security considerations for integrating the official MikroTik Winbox desktop application on Windows.

---

## 1. Role of Winbox in Network Operations

While the **RouterOS API** and **SSH CLI** serve as the primary mechanisms for programmatic configuration, the **Winbox Desktop Application** plays a distinct operational role:
- **Neighbor Discovery**: L2 MNDP / CDP discovery when IP addressing is unconfigured or misconfigured.
- **Visual Diagnostics**: Real-time traffic graphing, interface utilization meters, and wireless spectral scans.
- **Evidence Capture**: High-resolution GUI screenshots for change records, client handover, and QC audits.
- **Familiar Operator Handover**: Bridging automated changes with on-screen visual verification for NOC technicians.

---

## 2. Intelligent Connector Selection Strategy

```
                                [Task Request]
                                      |
                     +----------------+----------------+
                     |                                 |
         Needs Visual/GUI/L2             Structured Config / Bulk Telemetry
                     |                                 |
           [Winbox Installed?]                         v
             /              \                 [RouterOS API / SSH]
          YES                NO                        |
           |                  |                        v
           v                  v                 [Standard Engine]
      [Winbox GUI]     [Fallback to SSH]
```

| Connector | Best Used For | Protocol / Port | Execution Model |
| :--- | :--- | :--- | :--- |
| **RouterOS API** | Programmatic automation, bulk provisioning, JSON telemetry | TCP 8728 (plain) / 8729 (TLS) | Structured API |
| **SSH Connector** | Command-line diagnostics, batch script export, RouterBOARD upgrades | TCP 22 | Terminal stream |
| **Winbox GUI** | Live technician sessions, visual inspections, UI screenshot evidence | TCP 8291 / Windows Desktop | Windows UI Automation |

---

## 3. Supported Menu Hierarchies & Mappings

The Winbox Adapter supports programmatic navigation across standard RouterOS submenus:

| Winbox Menu | RouterOS CLI Equivalent | Typical Operational Purpose |
| :--- | :--- | :--- |
| **System → Resources** | `/system resource print` | CPU load, memory usage, uptime, RouterOS version |
| **System → Identity** | `/system identity print` | Hostname verification and site naming |
| **System → RouterBOARD**| `/system routerboard print` | Model, firmware version, serial number, bootloader |
| **Interfaces** | `/interface print` | Port statuses, running flags, link negotiation, errors |
| **IP → Addresses** | `/ip address print` | Assigned IPv4 subnets, interfaces, network addresses |
| **IP → Routes** | `/ip route print` | Default gateway, static routes, BGP/OSPF entries |
| **IP → DHCP Server** | `/ip dhcp-server print` | Active leases, lease pools, Option 82 configuration |
| **IP → Firewall** | `/ip firewall filter/nat/mangle` | Security rules, NAT translation, connection tracking |
| **IP → DNS** | `/ip dns print` | Cache size, static DNS records, upstream servers |
| **PPP** | `/ppp active/profile/secret` | PPPoE servers, active customer sessions, secrets |
| **Bridge** | `/interface bridge print` | STP/RSTP state, VLAN filtering, hardware offload |
| **Wireless / WiFi** | `/interface wireless / /interface wifi` | Radio bands, SSIDs, registration table, noise floor |
| **Queues** | `/queue simple print` | Bandwidth limits, traffic shaping, rate limits |
| **Log** | `/log print` | System events, authentication failures, link flaps |

---

## 4. Security Hardening & Credential Protection

> [!CAUTION]
> Never pass plaintext passwords as command-line arguments to Windows desktop applications. Command line arguments are globally readable by non-admin users via `WMI`, PowerShell `Get-CimInstance Win32_Process`, Task Manager, Process Hacker, and Windows Event Tracing (ETW Event ID 4688).

### 4.1 CLI Argument Vulnerability & Elimination
- **Previous Vulnerability**: Invoking `winbox.exe <target> <user> <password>` exposed passwords to process enumeration tools.
- **Hardened Implementation**: The hardened `WinboxAdapter` invokes Winbox with **target and username only** (`winbox.exe <target> <username>`).
- **In-Memory Window Message Injection**: Passwords are sent directly to the Winbox password `Edit` control via `WM_SETTEXT` without command-line exposure or clipboard leakage.
- **Password Redaction**: Any password passed into memory structures is scrubbed and marked `***REDACTED***` in audit logs and internal objects.

### 4.2 Error Dialog & Authentication Failure Detection
- The `WindowsUIAWrapper` monitors child control text and error banners.
- When an authentication failure, timeout, or connection error dialog appears (e.g. `ERROR: could not connect`, `Login failed`), the adapter immediately captures the error message, terminates the hung process, and raises a classified exception instead of freezing.

---

## 5. Laboratory & Real Hardware Verification Status

- **Simulated & Unit Tests**: Fully validated (35 test cases passing with mock connectors and Win32 UI automation wrappers).
- **Desktop Process & Control Automation**: Verified via `WindowsUIAWrapper` using native Win32/ctypes APIs.
- **Physical Router Hardware Integration**:
  - Live hardware tests are contained in [tests/test_real_router_validation.py](file:///c:/Users/dell/OneDrive/ドキュメント/codingan/network-engineering-skill/tests/test_real_router_validation.py).
  - Status without lab environment variables (`LAB_MIKROTIK_IP`): **`NOT VERIFIED (SKIPPED)`**.
  - All test logic executes in **strictly `READ_ONLY` mode** without destructive commands.
