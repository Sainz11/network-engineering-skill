# TR-069 / CWMP Architecture & Protocol Engineering Reference

This document provides a comprehensive technical reference for Broadband Forum **TR-069** (CPE WAN Management Protocol - CWMP) and the TR-098 / TR-181 data models.

---

## 1. CWMP Architecture & Ecosystem

```
+----------------------------------------------------+
| Auto Configuration Server (ACS)                   |
| (e.g. GenieACS, Axiros AXESS, Nokia Motive)       |
+----------------------------------------------------+
        ^                                  |
        | SOAP over HTTPS                  | HTTP / XMPP
        | (Inform, Get/Set, Transfer)      | Connection Request
        v                                  v
+----------------------------------------------------+
| Customer Premises Equipment (CPE / ONT Router)     |
| Embedded CWMP Client                               |
+----------------------------------------------------+
```

### Protocol Components:
- **Transport**: HTTP 1.1 over TLS/SSL (HTTPS) on default port 7547 (or 443).
- **Messaging Format**: XML-RPC / SOAP 1.1 envelopes.
- **RPC Methods**:
  - `Inform`: CPE sends status, hardware info, event codes to ACS.
  - `GetParameterValues`: ACS inspects device settings.
  - `SetParameterValues`: ACS provisions parameters.
  - `Download`: ACS triggers firmware upgrades or configuration file restoration.
  - `Upload`: ACS backs up CPE configuration.
  - `Reboot` / `FactoryReset`: Remote maintenance commands.
  - `GetRPCMethods`: Capabilities negotiation.

---

## 2. Session Lifecycle & Inform Events

### Session Sequence Flow:
1. **Trigger**: CPE boots, periodic timer expires, parameter changes, or CPE receives an active **Connection Request** from ACS.
2. **TLS Handshake**: CPE verifies ACS server certificate using embedded CA root bundle.
3. **HTTP Authentication**: Basic or Digest authentication (RFC 2617).
4. **CPE Inform**: CPE transmits `Inform` containing Device ID and Event codes.
5. **ACS InformResponse**: ACS acknowledges the session.
6. **ACS Requests**: ACS sends pending RPCs (e.g., `GetParameterValues`, `SetParameterValues`).
7. **CPE Responses**: CPE returns results or SOAP Faults.
8. **Empty HTTP Post**: Sent by ACS/CPE to indicate end of transmission and close HTTP connection.

### Standard Inform Event Codes:
- `0 BOOTSTRAP`: First time CPE contacts ACS after factory default or initial provisioning.
- `1 BOOT`: Normal power-on or reboot sequence.
- `2 PERIODIC`: Periodic Inform timer elapsed (e.g., every 86400 seconds).
- `4 VALUE CHANGE`: Monitored parameter modified (e.g., IP address changed).
- `6 CONNECTION REQUEST`: CPE responding to incoming HTTP GET on its ConnectionRequestURL.
- `7 TRANSFER COMPLETE`: Firmware download or config upload completed.
- `8 DIAGNOSTICS COMPLETE`: Ping, Traceroute, or Speedtest diagnostics finished.

---

## 3. Data Model Hierarchy: TR-098 vs. TR-181

Broadband Forum defines two primary root data models:

### 3.1 TR-098 (`InternetGatewayDevice.`)
Legacy root model used on older ONTs, ADSL/VDSL modems, and early Wi-Fi routers.

Key Subtrees:
- `InternetGatewayDevice.DeviceInfo.`: Hardware, software version, uptime, serial.
- `InternetGatewayDevice.ManagementServer.`: URL, periodic inform interval, connection request credentials.
- `InternetGatewayDevice.WANDevice.{i}.`: WAN connection instances, DSL/Ethernet/PON physical link stats.
- `InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{j}.WANPPPConnection.{k}.`: PPPoE username, password, IP.
- `InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{j}.`: SSID, WPA pre-shared key, beacon stats.

### 3.2 TR-181 Issue 2 (`Device.`)
Modern, modular device data model used in current GPON/XGS-PON ONTs, Wi-Fi 6/7 gateways, and TR-369 USP devices.

Key Subtrees:
- `Device.DeviceInfo.`: Vendor, serial, firmware, memory usage.
- `Device.ManagementServer.`: CWMP / USP controller bindings.
- `Device.Ethernet.Interface.{i}.`: Physical Ethernet port speeds, duplex, packet counters.
- `Device.WiFi.Radio.{i}.` / `Device.WiFi.SSID.{i}.`: Frequency bands, channel widths, multi-SSID.
- `Device.IP.Interface.{i}.`: L3 IP addresses, subnets, IPv6 SLAAC/DHCPv6.
- `Device.Optical.Interface.{i}.`: RX/TX optical power, transceiver temperature, bias current.

---

## 4. Common TR-069 Fault Codes

| SOAP Fault Code | Fault String | Description / Cause |
| :--- | :--- | :--- |
| **9000** | Method not supported | RPC not implemented by CPE firmware |
| **9001** | Request denied | CPE rejected command (e.g. invalid state) |
| **9002** | Internal error | Firmware crash, memory allocation failure |
| **9003** | Invalid arguments | Syntax error or schema mismatch |
| **9005** | Invalid parameter name | Parameter does not exist on this specific device model |
| **9006** | Invalid parameter type | Data type mismatch (e.g. string passed to integer) |
| **9007** | Invalid parameter value | Value outside allowed range (e.g. VLAN > 4094) |
| **9010** | Download failure | Firmware URL unreachable, checksum mismatch, or HTTP 404 |

---

## 5. Security & Best Practices
1. **TLS / HTTPS Mandatory**: Never operate CWMP over plain HTTP. Ensure strict CA certificate verification to prevent MITM attacks.
2. **Connection Request Security**:
   - Connection Request URL must reside on a dedicated private management VLAN.
   - Utilize HTTP Digest authentication with strong, randomized per-device credentials.
3. **Secret Redaction**: ACS logs and operator interfaces must mask passwords (`InternetGatewayDevice...WANPPPConnection.*.Password`).
