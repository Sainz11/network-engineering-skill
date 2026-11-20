# TR-369 / USP (User Services Platform) Engineering Reference

This document details Broadband Forum **TR-369** (User Services Platform - USP), the next-generation management and telemetry architecture replacing traditional TR-069.

---

## 1. USP Architecture & Roles

TR-369 USP is designed for IoT, cloud-native telemetry, multi-controller environments, and low-latency smart home networks.

```
+--------------------+        +--------------------+
| Cloud Controller   |        | Mobile / Local App |
| (ISP Operations)   |        | (Customer Control) |
+--------------------+        +--------------------+
          \                          /
           \   Message Broker (MTP) /
            \  (MQTT / STOMP / WS) /
             v                    v
      +----------------------------------+
      | USP Agent                        |
      | (ONT / Home Gateway / Wi-Fi AP)  |
      +----------------------------------+
```

### Key Architectural Concepts:
- **USP Agent**: The managed endpoint (CPE, ONT, Wi-Fi Extender, Smart Device) executing operations.
- **USP Controller**: The management entity (ISP NMS, Cloud ACS, Smart Home mobile app). An Agent can connect simultaneously to **multiple controllers** with fine-grained access control permissions.
- **MTP (Message Transfer Protocol)**: Unlike TR-069 which relies solely on HTTP POST, USP supports multiple modern, asynchronous transports:
  - **MQTT**: Lightweight publish/subscribe.
  - **WebSocket**: Bidirectional persistent connection.
  - **STOMP**: Streaming text-oriented messaging over TCP/TLS.
  - **CoAP / UDS**: Constrained application protocol for embedded IoT.

---

## 2. TR-069 vs. TR-369 USP Comparison

| Feature | TR-069 (CWMP) | TR-369 (USP) |
| :--- | :--- | :--- |
| **Architecture** | Single ACS per CPE (1-to-1) | Multi-Controller (Cloud NMS + Local App) |
| **Transport** | SOAP 1.1 over HTTP/HTTPS | Protocol Buffers (Protobuf) over MQTT/WebSocket/STOMP |
| **Connection Wakeup**| HTTP Connection Request or XMPP | Always-on persistent broker connection (MQTT/WS) |
| **Telemetry** | Periodic Inform polling (minutes/hours) | Real-time streaming telemetry & event subscriptions |
| **Payload Efficiency**| Verbose XML/SOAP envelopes | Compact binary Protocol Buffers |
| **Root Data Model** | TR-098 / TR-181 | TR-181 Issue 2 (Modular Device.) |
| **Access Control** | Global ACS credentials | Role-Based Access Control (RBAC) per Controller |

---

## 3. Protocol Buffers & USP Record Structure

USP messages are serialized using Google Protocol Buffers (protobuf v3).

### USP Record Envelope:
- `version`: Protocol version (e.g., "1.2").
- `to_id`: USP Endpoint Identifier (e.g., `proto::agent-00123456`).
- `from_id`: Originating USP Endpoint (e.g., `proto::controller-noc`).
- `payload_security`: `PLAINTEXT` or `TLS12` application layer payload encryption.
- `mac_signature`: Cryptographic integrity signature.

### Core USP Request Types:
- **`Get`**: Retrieves parameter values and object schemas.
- **`Set`**: Modifies parameter values transactionally.
- **`Add`**: Creates instances in multi-instance tables (e.g., adding a new Wi-Fi SSID).
- **`Delete`**: Removes object instances.
- **`Operate`**: Invokes native asynchronous actions (e.g., `Device.IP.Diagnostics.IPPing()`, `Device.DeviceInfo.Reboot()`).
- **`Notify`**: Telemetry events, threshold alerts, or value changes pushed to subscribed controllers.

---

## 4. USP Implementation Considerations & Vendor Status
- **Standardized Implementations**: Open-source stacks such as Broadband Forum's **OB-USP-Agent** provide standard compliant client implementations.
- **Carrier Gateways**: Modern Wi-Fi 6/7 gateways and carrier ONTs (e.g., Nokia WiFi, CommScope, Sagemcom) are deploying dual-stack TR-069 + USP agents.
- **Controller Infrastructure**: Platforms like Axiros, Friendly Technologies, and Incognito now support hybrid CWMP/USP controller endpoints.
